//! `citadel-svc` — привилегированная Windows-служба CitadelPQVPN (модель W2).
//!
//! Аналог Linux-`citadel-helper`, но для Windows: владеет WinTUN-адаптером + WFP-kill-switch +
//! маршрутами/DNS и гоняет **packet-pump** ↔ неприв. приложение по **named pipe** `\\.\pipe\citadel-svc`.
//! Движок (QUIC/obfs) остаётся в приложении (`WindowsTunProvider`), как на Linux. Служба линкует
//! только `citadel-winnet` (кадры пайпа + WFP-план + маршруты), НЕ движок — меньше attack surface.
//!
//! Реализовано целиком: named-pipe сервер + config-handshake (`TunSetup` → READY), чистая
//! оркестрация [`plan`], WinTUN-адаптер и packet-pump (`windows_svc::Session`/`bring_up`),
//! WFP-фильтры (`crate::wfp`) — IPv4-kill-switch и fail-closed блок IPv6-утечки (W1). Открытый остаток —
//! не заглушки, а известные ограничения: L-9 (опознание клиента пайпа по PID→путь образа, без
//! проверки подписи) и L-12 (фильтры стоят на `ALE_AUTH_CONNECT`, поэтому армирование не рвёт уже
//! установленные потоки); оба — в `docs/SECURITY-AUDIT-4-2026-08.md §20.3`.

#[cfg_attr(not(windows), allow(dead_code))]
mod plan;
#[cfg(windows)]
mod log;
#[cfg(windows)]
mod wfp;

#[cfg(not(windows))]
fn main() {
    eprintln!("citadel-svc — служба только для Windows (WinTUN/WFP). На этой ОС не запускается.");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    // install/uninstall — из инсталлятора приложения (elevated); --console — dev; без аргументов —
    // запуск диспетчером SCM (как система стартует службу).
    match std::env::args().nth(1).as_deref() {
        Some("install") => windows_svc::install(),
        Some("uninstall") => windows_svc::uninstall(),
        Some("--console") => windows_svc::run_console(),
        _ => windows_svc::dispatch(),
    }
}

#[cfg(windows)]
mod windows_svc {
    use std::ffi::OsString;
    use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;

    use citadel_winnet::{
        decode_config, encode_packet, encode_ready_err, encode_ready_ok, TunReady, TunSetup,
        WfpFamily, TAG_CONFIG, TAG_QUIT,
    };
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{define_windows_service, service_dispatcher};
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, ERROR_IO_PENDING, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::NetworkManagement::IpHelper::GetBestInterface;
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile, FILE_FLAG_OVERLAPPED};
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    };
    use windows_sys::Win32::System::Threading::{CreateEventW, ResetEvent};
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

    use crate::plan::{bypass_route_add, bypass_route_del, plan_session, SessionPlan, ADAPTER_NAME};

    /// Имя службы в SCM.
    const SERVICE_NAME: &str = "CitadelPQVPN";
    /// Флаг остановки (ставит control-handler на Stop/Shutdown); serve-цикл его опрашивает.
    static SHUTDOWN: AtomicBool = AtomicBool::new(false);
    /// Хэндл СЛУШАЮЩЕГО инстанса пайпа (для `cancel_accept` → CancelIoEx прерывает `ConnectNamedPipe`).
    /// Инстанс сессии сюда НЕ попадает: он живёт в [`SessionSlot`] своего рабочего потока.
    static LISTENING_PIPE: AtomicIsize = AtomicIsize::new(0);

    /// Сколько ждать сворачивания ВЫТЕСНЯЕМОЙ сессии, прежде чем отказать новому клиенту. Teardown —
    /// это `route delete` + удаление WinTUN-адаптера (device removal на Windows штатно занимает
    /// единицы секунд), поэтому запас щедрый; смысл границы — не зависнуть навсегда, а ответить
    /// клиенту внятной ошибкой.
    const PREEMPT_TIMEOUT: Duration = Duration::from_secs(20);
    /// Сколько ждать окончания уже идущей сессии, прежде чем отклонить `TAG_QUIT` (выход приложения
    /// приходит сразу после `disconnect`, и сессия в этот момент ещё может доворачивать teardown).
    const QUIT_GRACE: Duration = Duration::from_secs(5);
    /// Сколько ждать завершения рабочих потоков на остановке службы (SCM Stop не должен висеть).
    const WORKERS_JOIN_TIMEOUT: Duration = Duration::from_secs(15);
    /// Сколько ждать запрос от подключившегося клиента (фаза handshake, локальный пайп).
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

    /// Слот активной сессии туннеля: служба владеет ОДНИМ WinTUN-адаптером, поэтому сессия
    /// одновременно ровно одна, и новый аутентифицированный клиент (реконнект приложения, повторный
    /// запуск) **вытесняет** прежнюю.
    ///
    /// Так закрывается корень «Все копии канала заняты (os error 231)»: раньше serve-цикл держал
    /// ЕДИНСТВЕННЫЙ инстанс пайпа на всю сессию и создавал следующий только после полного teardown.
    /// Пока сессия жива, новый `CreateFileW` получал `ERROR_PIPE_BUSY`, а в окне между инстансами —
    /// `ERROR_FILE_NOT_FOUND`. Если же сессия зависала (writer-поток в `WriteFile` на пайпе клиента,
    /// который перестал читать, но хэндл ещё не закрыл), служба оставалась занятой НАВСЕГДА: туннель
    /// не поднимался ни по одной ссылке, и `TAG_QUIT` не доходил — `citadel-svc.exe` висел в задачах
    /// после выхода из приложения. Теперь акцептор всегда держит свободный инстанс, а сессию
    /// вытесняет явно.
    ///
    /// Хэндл пайпа сессии закрывает САМ слот ([`SessionSlot::finish`]) под тем же мьютексом, под
    /// которым вытесняющий поток зовёт `CancelIoEx` — иначе была бы гонка «отмена по уже закрытому
    /// (и, возможно, переиспользованному ядром) хэндлу».
    struct SessionSlot {
        /// Хэндл пайпа этой сессии (`isize`, чтобы структура была `Send`/`Sync`).
        pipe: isize,
        /// M-5 (аудит-4): строковый SID пользователя, которому принадлежит сессия. Вытеснить её
        /// вправе только он сам (см. [`crate::plan::session_owner_may_preempt`]). `None` —
        /// dev-console, где аутентификации клиента нет вовсе.
        owner: Option<String>,
        /// `true` — сессия свёрнута полностью и хэндл закрыт.
        done: Mutex<bool>,
        done_cv: Condvar,
    }
    // SAFETY: хэндл трогают только под `done`-мьютексом (закрытие) либо его владелец-поток.
    unsafe impl Send for SessionSlot {}
    unsafe impl Sync for SessionSlot {}

    impl SessionSlot {
        fn new(pipe: HANDLE, owner: Option<String>) -> Arc<Self> {
            Arc::new(SessionSlot {
                pipe: pipe as isize,
                owner,
                done: Mutex::new(false),
                done_cv: Condvar::new(),
            })
        }

        /// Завершить обслуживание: отключить и закрыть пайп, разбудить ожидающего вытеснителя.
        /// Закрытие идёт ПОД мьютексом — вытесняющий поток зовёт `CancelIoEx` под ним же.
        fn finish(&self) {
            let mut done = self.done.lock().unwrap();
            // SAFETY: pipe — валидный хэндл этой сессии, закрывается ровно один раз (флаг `done`).
            unsafe {
                DisconnectNamedPipe(self.pipe as HANDLE);
                CloseHandle(self.pipe as HANDLE);
            }
            *done = true;
            self.done_cv.notify_all();
        }

        /// Прервать I/O сессии и дождаться её сворачивания. `false` — не уложилась в `timeout`.
        fn cancel_and_wait(&self, timeout: Duration) -> bool {
            let done = self.done.lock().unwrap();
            if !*done {
                // SAFETY: под мьютексом хэндл ещё не закрыт (его закрывает `finish` под ним же).
                unsafe { CancelIoEx(self.pipe as HANDLE, std::ptr::null()) };
            }
            let (done, _) =
                self.done_cv.wait_timeout_while(done, timeout, |d| !*d).unwrap();
            *done
        }
    }

    /// Текущая сессия туннеля (если поднята). Вытеснение — [`claim_session_slot`].
    static SESSION: Mutex<Option<Arc<SessionSlot>>> = Mutex::new(None);

    /// Занять слот сессии под нового клиента, свернув прежнюю. `false` — прежняя не свернулась за
    /// [`PREEMPT_TIMEOUT`]: поднимать туннель НЕЛЬЗЯ (два WinTUN-адаптера с одним именем + гонка за
    /// маршруты), клиент получит READY-err с причиной.
    fn claim_session_slot(slot: &Arc<SessionSlot>) -> Result<(), String> {
        let old = {
            let mut g = SESSION.lock().unwrap();
            // M-5: чужую сессию не трогаем ВООБЩЕ — ни свернуть, ни занять слот. Сверка идёт под
            // тем же мьютексом, что и замена, иначе два клиента разошлись бы в гонке.
            if let Some(cur) = g.as_ref() {
                if !crate::plan::session_owner_may_preempt(cur.owner.as_deref(), slot.owner.as_deref())
                {
                    eprintln!(
                        "[svc] M-5: клиент {} пытается вытеснить сессию пользователя {} — отказ",
                        slot.owner.as_deref().unwrap_or("?"),
                        cur.owner.as_deref().unwrap_or("?")
                    );
                    return Err("туннель уже поднят другим пользователем этого компьютера — \
                                отключите его сеанс или войдите под ним"
                        .into());
                }
            }
            g.replace(slot.clone())
        };
        let Some(old) = old else { return Ok(()) };
        eprintln!("[svc] новый клиент вытесняет прежнюю сессию — сворачиваю её");
        if old.cancel_and_wait(PREEMPT_TIMEOUT) {
            eprintln!("[svc] прежняя сессия свёрнута — поднимаю новую");
            return Ok(());
        }
        // Сюда попадать не должны (сворачивание разбужено и CancelIoEx'ом, и shutdown'ом WinTUN-
        // сессии), но если случилось — поднимать туннель поверх нельзя: второй WinTUN-адаптер с тем
        // же именем сделает `netsh name=Citadel` неоднозначным и разнесёт маршруты. Возвращаем в слот
        // ПРЕЖНЮЮ сессию (состояние службы должно оставаться правдивым) и просим службу завершиться:
        // на следующей попытке приложение поднимет её заново через SCM и получит чистое состояние.
        // Ценой временного fail-open по WFP — те же семантики, что при любом падении службы, и
        // единственная альтернатива вечно неработающему туннелю.
        eprintln!(
            "[svc] прежняя сессия НЕ свернулась за {PREEMPT_TIMEOUT:?} — отказываю клиенту и \
             завершаю службу (следующая попытка поднимет её заново)"
        );
        {
            let mut g = SESSION.lock().unwrap();
            if g.as_ref().is_some_and(|cur| Arc::ptr_eq(cur, slot)) {
                *g = Some(old);
            }
        }
        SHUTDOWN.store(true, Ordering::Release);
        cancel_accept();
        Err("прежняя сессия туннеля не свернулась вовремя — повторите попытку \
             (или перезапустите службу CitadelPQVPN)"
            .into())
    }

    /// Освободить слот, если он всё ещё наш (нас могли уже вытеснить — тогда слот принадлежит новому
    /// клиенту и трогать его нельзя).
    fn release_session_slot(slot: &Arc<SessionSlot>) {
        let mut g = SESSION.lock().unwrap();
        if g.as_ref().is_some_and(|cur| Arc::ptr_eq(cur, slot)) {
            *g = None;
        }
    }

    /// Есть ли сейчас активная сессия туннеля (для `TAG_QUIT`: не гасим службу под живым туннелем).
    fn session_active() -> bool {
        SESSION.lock().unwrap().is_some()
    }

    /// HANDLE (`*mut c_void`) не `Send` — обёртка для передачи пайпа в поток WinTUN→пайп. Пайп
    /// OVERLAPPED-режима: одновременные WriteFile (этот поток) и ReadFile (поток пайп→WinTUN) на одном
    /// хэндле идут независимо (каждый со своим OVERLAPPED). В СИНХРОННОМ режиме ядро сериализовало бы
    /// их (FO_SYNCHRONOUS_IO) — блокирующий ReadFile повиснув глушил бы WriteFile → pump вставал.
    struct SendHandle(HANDLE);
    unsafe impl Send for SendHandle {}

    /// Пер-поточный контекст overlapped-I/O: manual-reset событие для блокирующего завершения одной
    /// операции. Дуплексный пайп открыт с `FILE_FLAG_OVERLAPPED`, поэтому конкурентные Read/Write НЕ
    /// сериализуются на file-object'е (в отличие от синхронного режима). Блокируемся через
    /// `GetOverlappedResult(wait=TRUE)`. КАЖДАЯ одновременная операция обязана иметь СВОЙ `Ov` (своё
    /// событие+OVERLAPPED): reader-поток и writer-поток pump'а держат по одному.
    struct Ov {
        event: HANDLE,
    }
    // SAFETY: событие используется одним потоком-владельцем; HANDLE переносится в поток pump'а.
    unsafe impl Send for Ov {}

    impl Ov {
        fn new() -> anyhow::Result<Self> {
            // manual-reset (TRUE), начально несигнальное; без имени.
            let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
            if event.is_null() {
                anyhow::bail!("CreateEventW: err={}", unsafe { GetLastError() });
            }
            Ok(Ov { event })
        }

        /// Одна overlapped Read/Write → число переданных байт. `write=false` → ReadFile.
        fn one(&self, h: HANDLE, ptr: *mut u8, len: u32, write: bool) -> anyhow::Result<u32> {
            self.one_within(h, ptr, len, write, None)
        }

        /// Как [`one`], но с необязательной границей ожидания: `Some(d)` — не дождались за `d`,
        /// отменяем операцию и возвращаем ошибку. Нужно на фазе handshake: подключившийся клиент
        /// обязан сразу прислать `TAG_CONFIG`/`TAG_QUIT`, и молчун не должен держать рабочий поток
        /// службы (и инстанс пайпа) бесконечно.
        fn one_within(
            &self,
            h: HANDLE,
            ptr: *mut u8,
            len: u32,
            write: bool,
            limit: Option<Duration>,
        ) -> anyhow::Result<u32> {
            use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
            use windows_sys::Win32::System::Threading::WaitForSingleObject;
            // SAFETY: h — валидный overlapped-хэндл пайпа; ptr/len — валидный буфер; ov живёт до
            // конца GetOverlappedResult (он зовётся на ВСЕХ путях выхода, в т.ч. после отмены по
            // таймауту — иначе ядро писало бы в освобождённый стек), self.event — валидное событие.
            unsafe {
                let mut ov: OVERLAPPED = std::mem::zeroed();
                ov.hEvent = self.event;
                ResetEvent(self.event);
                let ok = if write {
                    WriteFile(h, ptr, len, std::ptr::null_mut(), &mut ov)
                } else {
                    ReadFile(h, ptr, len, std::ptr::null_mut(), &mut ov)
                };
                if ok == 0 {
                    let e = GetLastError();
                    if e != ERROR_IO_PENDING {
                        anyhow::bail!("{} err={e}", if write { "WriteFile" } else { "ReadFile" });
                    }
                }
                let mut timed_out = false;
                if let Some(d) = limit {
                    let ms = d.as_millis().min(u32::MAX as u128 - 1) as u32;
                    if WaitForSingleObject(self.event, ms) != WAIT_OBJECT_0 {
                        CancelIoEx(h, &ov);
                        timed_out = true;
                    }
                }
                let mut done = 0u32;
                // bWait=TRUE: ждём на ov.hEvent; отмена через CancelIoEx завершит с ошибкой (Err).
                let got = GetOverlappedResult(h, &ov, &mut done, 1);
                if timed_out {
                    anyhow::bail!("клиент молчит дольше {limit:?} — обрываю");
                }
                if got == 0 {
                    anyhow::bail!("GetOverlappedResult err={}", GetLastError());
                }
                Ok(done)
            }
        }

        fn read_exact(&self, h: HANDLE, buf: &mut [u8]) -> anyhow::Result<()> {
            self.read_exact_within(h, buf, None)
        }

        /// [`read_exact`] с общей границей на всё чтение (см. [`one_within`]).
        fn read_exact_within(
            &self,
            h: HANDLE,
            buf: &mut [u8],
            limit: Option<Duration>,
        ) -> anyhow::Result<()> {
            let deadline = limit.map(|d| std::time::Instant::now() + d);
            let mut off = 0;
            while off < buf.len() {
                let left = deadline.map(|dl| dl.saturating_duration_since(std::time::Instant::now()));
                let n =
                    self.one_within(h, buf[off..].as_mut_ptr(), (buf.len() - off) as u32, false, left)?;
                if n == 0 {
                    anyhow::bail!("пайп закрыт (EOF) при чтении");
                }
                off += n as usize;
            }
            Ok(())
        }

        fn write_all(&self, h: HANDLE, buf: &[u8]) -> anyhow::Result<()> {
            let mut off = 0;
            while off < buf.len() {
                let n =
                    self.one(h, buf[off..].as_ptr() as *mut u8, (buf.len() - off) as u32, true)?;
                if n == 0 {
                    anyhow::bail!("пайп закрыт (EOF) при записи");
                }
                off += n as usize;
            }
            Ok(())
        }

        /// Прочитать один кадр пакета: `u16(len,BE) ‖ payload`. `len==0` → `Ok(None)` (чистый
        /// disconnect); EOF/ошибка → `Err`.
        fn read_frame(&self, h: HANDLE) -> anyhow::Result<Option<Vec<u8>>> {
            let mut lenb = [0u8; 2];
            self.read_exact(h, &mut lenb)?;
            let len = u16::from_be_bytes(lenb) as usize;
            if len == 0 {
                return Ok(None);
            }
            let mut pkt = vec![0u8; len];
            self.read_exact(h, &mut pkt)?;
            Ok(Some(pkt))
        }
    }

    impl Drop for Ov {
        fn drop(&mut self) {
            // SAFETY: event — валидный хэндл, созданный CreateEventW, больше не используется.
            unsafe { CloseHandle(self.event) };
        }
    }

    /// Overlapped-`ConnectNamedPipe`: дождаться подключения клиента. `true` — подключён (или уже был
    /// до вызова, `ERROR_PIPE_CONNECTED`); `false` — ошибка/отмена (CancelIoEx на Stop → aborted).
    fn overlapped_connect(h: HANDLE, ov: &Ov) -> bool {
        // SAFETY: h — валидный overlapped-хэндл пайпа; o живёт до GetOverlappedResult.
        unsafe {
            let mut o: OVERLAPPED = std::mem::zeroed();
            o.hEvent = ov.event;
            ResetEvent(ov.event);
            if ConnectNamedPipe(h, &mut o) != 0 {
                return true; // overlapped: обычно 0; ненулевой — тоже успех
            }
            let e = GetLastError();
            if e == ERROR_PIPE_CONNECTED {
                return true; // клиент успел до ConnectNamedPipe
            }
            if e != ERROR_IO_PENDING {
                eprintln!("[svc] ConnectNamedPipe err={e}");
                return false;
            }
            let mut done = 0u32;
            GetOverlappedResult(h, &o, &mut done, 1) != 0
        }
    }

    // Win32-константы CreateNamedPipeW (ABI-стабильны; локально — чтобы не гадать модуль в windows-sys).
    const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
    const PIPE_TYPE_BYTE: u32 = 0x0000_0000;
    const PIPE_READMODE_BYTE: u32 = 0x0000_0000;
    const PIPE_WAIT: u32 = 0x0000_0000;
    const PIPE_UNLIMITED_INSTANCES: u32 = 255;

    const PIPE_NAME: &str = r"\\.\pipe\citadel-svc";
    /// ACL пайпа (SDDL): SYSTEM/Builtin-Admins — полный доступ (GA); интерактивные пользователи (IU) —
    /// read+write (desktop-app коннектится под юзером). Сеть/аноним/сервисы — нет доступа. `P` —
    /// protected DACL (без наследования). W3 (аудит-3): SACL с mandatory-label `(ML;;NW;;;ME)` —
    /// no-write-up ниже Medium ⇒ low-integrity/AppContainer-процессы (типовой sandbox малвари) НЕ
    /// могут писать в пайп, даже будучи IU. Легитимный app (Medium) не затронут. Дополняется
    /// per-connection проверкой образа клиента (`verify_client_is_installed_app`, W3).
    const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)S:(ML;;NW;;;ME)";
    /// Верхняя граница config-кадра (анти-DoS при чтении из пайпа).
    const MAX_CONFIG: usize = 64 * 1024;
    /// `ERROR_PIPE_CONNECTED` — клиент успел подключиться до `ConnectNamedPipe` (не ошибка).
    const ERROR_PIPE_CONNECTED: u32 = 535;

    /// UTF-16 нуль-терминированная строка для *W-API.
    fn wide(s: &str) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    /// Запуск диспетчером SCM (служба стартует системой без аргументов). Блокирует поток до остановки.
    pub fn dispatch() -> anyhow::Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
        Ok(())
    }

    /// Консольный dev-режим: тот же serve-цикл без SCM (работает до kill / Ctrl-C).
    pub fn run_console() -> anyhow::Result<()> {
        eprintln!("[svc] citadel-svc: dev-console режим");
        serve(false) // dev: служба под юзером, клиент из build-дерева → client-auth выкл
    }

    // SCM-boilerplate: ffi_service_main парсит аргументы и зовёт service_main на фоновом потоке.
    define_windows_service!(ffi_service_main, service_main);

    fn service_main(_args: Vec<OsString>) {
        if let Err(e) = run_service() {
            eprintln!("[svc] служба завершилась с ошибкой: {e:#}");
        }
    }

    fn status(state: ServiceState, accepted: ServiceControlAccept) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accepted,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        }
    }

    fn run_service() -> anyhow::Result<()> {
        // Перенаправить stderr службы в файл (%ProgramData%\CitadelPQVPN\logs) — у SCM-службы нет
        // консоли, иначе весь eprintln! bring_up/netsh/WFP теряется и туннель не диагностируется.
        crate::log::redirect_stderr_to_file();
        // control-handler: Stop/Shutdown → флаг + прервать блокирующий accept/pump (CancelIoEx).
        let handler = move |control| -> ServiceControlHandlerResult {
            match control {
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    SHUTDOWN.store(true, Ordering::Release);
                    cancel_accept();
                    cancel_active_session();
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };
        let status_handle = service_control_handler::register(SERVICE_NAME, handler)?;
        status_handle.set_service_status(status(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ))?;
        // Само-лечение прав на КАЖДОМ старте (LocalSystem имеет WRITE_DAC на свою запись в SCM):
        // дескриптор мог остаться дефолтным, если при установке `sc sdset` не отработал (инсталлятор
        // код возврата не проверяет), а установки прежних сборок про него не знали вовсе. Симптом
        // ровно один и труднодиагностируемый: приложение без прав администратора не поднимает
        // туннель («OpenService: Отказано в доступе», os 5), причём ломается ОТЛОЖЕННО — пока службу
        // не остановят при выходе из приложения, всё работает. Служба AutoStart ⇒ ближайшая
        // перезагрузка (или `net start` из инсталлятора) чинит установку сама.
        grant_start_to_interactive_users();
        let _ = serve(true); // SCM/LocalSystem → W3 client-auth enforce
        status_handle
            .set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty()))?;
        Ok(())
    }

    /// Установить службу в SCM (нужна elevation). Запускается вручную инсталлятором приложения.
    pub fn install() -> anyhow::Result<()> {
        use std::time::Duration;
        use windows_service::service::{
            ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl,
            ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType,
        };
        use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )?;
        let info = ServiceInfo {
            name: SERVICE_NAME.into(),
            display_name: "CitadelPQVPN Service".into(),
            service_type: ServiceType::OWN_PROCESS,
            // AutoStart: служба всегда слушает пайп (неприв. desktop-app сам её не стартанёт — нет
            // прав SERVICE_START). Пока туннель не поднят — только слушает пайп (адаптера/WFP нет).
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: std::env::current_exe()?,
            launch_arguments: vec![],
            dependencies: vec![],
            account_name: None, // LocalSystem
            account_password: None,
        };
        // Идемпотентность: при АПГРЕЙДЕ служба уже есть (инсталлятор зовёт `install` всегда) —
        // create_service вернёт ERROR_SERVICE_EXISTS. Тогда открываем существующую и обновляем
        // конфиг (путь к exe мог смениться), иначе новые настройки (SDDL/recovery) не доехали бы
        // до тех, кто обновляется, а не ставит с нуля.
        let service = match manager.create_service(&info, ServiceAccess::CHANGE_CONFIG) {
            Ok(s) => s,
            Err(e) => {
                let s = manager
                    .open_service(SERVICE_NAME, ServiceAccess::CHANGE_CONFIG)
                    .map_err(|e2| anyhow::anyhow!("служба не создана ({e}) и не открыта ({e2})"))?;
                s.change_config(&info)?;
                eprintln!("[svc] служба '{SERVICE_NAME}' уже была — конфиг обновлён");
                s
            }
        };
        // ПЕРВЫМ делом — право запуска интерактивному пользователю: без него неприв. приложение не
        // поднимет службу, и туннель не встанет вовсе («OpenService: Отказано в доступе», os 5).
        // Раньше этот вызов стоял последним, за двумя `?`-шагами: любая их осечка (а инсталлятор код
        // возврата `citadel-svc install` не проверяет) оставляла службу с дефолтным дескриптором —
        // молча и навсегда. Косметика (описание, recovery) ниже уже не критична: логируем и живём.
        grant_start_to_interactive_users();
        if let Err(e) = service.set_description(
            "CitadelPQVPN — постквантовый VPN: WinTUN + WFP kill-switch (модель W2)",
        ) {
            eprintln!("[svc] описание службы не задано (не критично): {e}");
        }
        // SCM-recovery: авто-рестарт при КРАШЕ (не чистом стопе) — смягчает окно fail-closed, если
        // служба упадёт с активным туннелем; после рестарта WFP переармируется на следующем connect.
        let restart = |secs| ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: Duration::from_secs(secs),
        };
        if let Err(e) = service.update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![restart(5), restart(5), restart(30)]),
        }) {
            eprintln!("[svc] авто-рестарт при краше не настроен (не критично): {e}");
        }
        eprintln!("[svc] служба '{SERVICE_NAME}' установлена (авто-рестарт при краше)");
        Ok(())
    }

    /// Дать интерактивному пользователю право ЗАПУСКА службы (`RP` = SERVICE_START) + чтения статуса.
    ///
    /// Нужно, потому что приложение при выходе гасит службу (`TAG_QUIT`, п.2 — не держать
    /// elevated-процесс без клиента), а поднять её обратно на следующем запуске неприв. процесс без
    /// этого права не может (дефолтный дескриптор службы даёт IU только чтение).
    ///
    /// Умышленно НЕ даём `WP` (SERVICE_STOP): остановка идёт ТОЛЬКО через аутентифицированный пайп
    /// (W3) и только когда сессии нет — иначе любой локальный пользователь мог бы снять службу с
    /// активным туннелем, а вместе с ней и WFP-kill-switch (fail-open = деанон). Старт же поднимает
    /// лишь слушателя пайпа, который сам аутентифицирует клиента ⇒ прироста поверхности почти нет.
    ///
    /// Через `sc.exe sdset` (абсолютный путь из %SystemRoot%, аргументы — константы, без ввода
    /// снаружи): SetServiceObjectSecurity потребовал бы ручной сборки SD в unsafe-коде внутри
    /// привилегированного бинаря. Ошибка не фатальна — служба остаётся AutoStart и переживёт
    /// перезагрузку, просто «оживёт» не сразу (пользователю подскажет текст ошибки в приложении).
    fn grant_start_to_interactive_users() {
        // SY — LocalSystem (полный набор служебных прав), BA — администраторы (полный + смена ACL),
        // IU — интерактивные: CC/LC/SW/LO/RC (чтение конфига/статуса) + RP (SERVICE_START),
        // SU — служебные аккаунты (чтение), как в дефолтном дескрипторе служб.
        const SDDL: &str = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)\
                            (A;;CCLCSWRPLORC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";
        let sc = std::path::Path::new(&std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()))
            .join("System32")
            .join("sc.exe");
        match std::process::Command::new(&sc).args(["sdset", SERVICE_NAME, SDDL]).output() {
            Ok(o) if o.status.success() => {
                eprintln!("[svc] SDDL службы: интерактивному пользователю разрешён SERVICE_START")
            }
            Ok(o) => eprintln!(
                "[svc] ⚠ sc sdset не удался ({}) — неприв. приложение НЕ сможет запустить службу \
                 («OpenService: Отказано в доступе»): {} {}",
                o.status,
                String::from_utf8_lossy(&o.stdout).trim(),
                String::from_utf8_lossy(&o.stderr).trim()
            ),
            Err(e) => eprintln!(
                "[svc] ⚠ sc sdset не запущен ({e}) — неприв. приложение НЕ сможет запустить службу"
            ),
        }
    }

    /// Удалить службу из SCM (нужна elevation).
    pub fn uninstall() -> anyhow::Result<()> {
        use windows_service::service::ServiceAccess;
        use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
        let manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let service = manager.open_service(SERVICE_NAME, ServiceAccess::DELETE)?;
        service.delete()?;
        eprintln!("[svc] служба '{SERVICE_NAME}' удалена");
        Ok(())
    }

    /// Акцептор: держит СВОБОДНЫЙ слушающий инстанс пайпа и отдаёт каждое соединение рабочему потоку,
    /// сам немедленно возвращаясь к `ConnectNamedPipe`. Ключевой инвариант: **подключиться к службе
    /// можно всегда** — и во время активной сессии (реконнект вытеснит её, см. [`claim_session_slot`]),
    /// и во время её сворачивания. Раньше цикл обслуживал клиента сам, поэтому единственный инстанс
    /// был занят всю сессию → `ERROR_PIPE_BUSY` (231) на реконнекте, `ERROR_FILE_NOT_FOUND` (2) в окне
    /// пересоздания и вечная блокировка службы при зависшей сессии.
    ///
    /// Прерывается на Stop через `cancel_accept` (CancelIoEx на слушающем инстансе + отмена сессии);
    /// флаг остановки — общий [`SHUTDOWN`], его же ставит рабочий поток на `TAG_QUIT`.
    fn serve(enforce_client_auth: bool) -> anyhow::Result<()> {
        eprintln!("[svc] слушаю {PIPE_NAME} (client-auth W3: {})", if enforce_client_auth { "вкл" } else { "выкл (dev-console)" });
        // Overlapped-контекст акцептора: только ConnectNamedPipe. Каждый рабочий поток заводит свой Ov.
        let ov = Ov::new()?;
        let mut workers: Vec<std::thread::JoinHandle<()>> = Vec::new();
        while !SHUTDOWN.load(Ordering::Acquire) {
            let h = create_pipe_instance()?;
            LISTENING_PIPE.store(h as isize, Ordering::Release);
            let connected = overlapped_connect(h, &ov);
            LISTENING_PIPE.store(0, Ordering::Release);
            if SHUTDOWN.load(Ordering::Acquire) {
                unsafe { CloseHandle(h) };
                break;
            }
            if !connected {
                unsafe { CloseHandle(h) };
                continue;
            }
            // W3: аутентифицировать клиента ДО чтения config (это недоверенный ввод, управляющий
            // привилегированной реконфигурацией сети). SCM-режим (LocalSystem) → enforce; dev-console
            // (служба под юзером, клиент из build-дерева) → пропускаем. Проверка быстрая (OpenProcess
            // + QueryFullProcessImageNameW), поэтому остаётся на акцепторе: отсев чужого процесса не
            // должен стоить рабочего потока.
            // W3 — образ клиента из install-dir; M-5 — SID его пользователя (владелец сессии).
            let owner = if enforce_client_auth {
                match authenticate_client(h) {
                    Ok(sid) => Some(sid),
                    Err(e) => {
                        eprintln!("[svc] отклонён клиент пайпа (W3/M-5): {e:#}");
                        unsafe {
                            DisconnectNamedPipe(h);
                            CloseHandle(h);
                        }
                        continue;
                    }
                }
            } else {
                None // dev-console: аутентификации клиента нет вовсе
            };
            // Соединение уходит рабочему потоку вместе с владением хэндлом (закроет его `slot.finish`).
            let slot = SessionSlot::new(h, owner);
            workers.retain(|w| !w.is_finished());
            workers.push(std::thread::spawn(move || {
                let quit = handle_client(&slot);
                slot.finish();
                if quit {
                    // TAG_QUIT: приложение закрылось → служба больше не нужна. Флаг + отмена accept'а
                    // (в SCM-режиме run_service выставит Stopped и процесс уйдёт из списка задач).
                    SHUTDOWN.store(true, Ordering::Release);
                    cancel_accept();
                }
            }));
        }
        // Дождаться рабочих потоков: у активной сессии внутри — teardown (маршруты/адаптер/WFP), его
        // нельзя обрывать выходом процесса. Но и висеть на Stop нельзя (SCM убьёт службу жёстко),
        // поэтому ожидание ограничено.
        cancel_active_session();
        let deadline = std::time::Instant::now() + WORKERS_JOIN_TIMEOUT;
        while workers.iter().any(|w| !w.is_finished()) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        for w in workers.into_iter().filter(|w| w.is_finished()) {
            let _ = w.join();
        }
        eprintln!("[svc] serve остановлен");
        Ok(())
    }

    /// W3 (аудит-3): аутентификация клиента пайпа. ACL даёт доступ любому интерактивному юзеру (IU),
    /// но служба (LocalSystem) выполняет привилегированную реконфигурацию сети — доверять ЛЮБОМУ
    /// процессу нельзя. Проверяем, что подключившийся процесс — установленное приложение Citadel: его
    /// образ в ТОМ ЖЕ каталоге, что и служба (Inno ставит app.exe и citadel-svc.exe в один
    /// `%ProgramFiles%\CitadelPQVPN`; Program Files пишет только админ ⇒ медиум-малварь туда бинарь
    /// не положит). SYSTEM открывает клиента (≤ integrity) — OpenProcess надёжен. Дополняет
    /// mandatory-label в SDDL (блок low-integrity). Err → клиент не из install-dir (отклонить).
    fn verify_client_is_installed_app(pipe: HANDLE) -> anyhow::Result<()> {
        let install_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
            .ok_or_else(|| anyhow::anyhow!("не определить install-dir службы (current_exe)"))?;
        let mut pid: u32 = 0;
        // SAFETY: pipe — валидный серверный хэндл подключённого клиента; pid — out-указатель.
        if unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) } == 0 {
            anyhow::bail!("GetNamedPipeClientProcessId err={}", unsafe { GetLastError() });
        }
        let image = client_image_path(pid)?;
        if !crate::plan::same_dir(&image, &install_dir) {
            anyhow::bail!(
                "образ клиента {image:?} не в install-dir службы {install_dir:?} — не приложение Citadel"
            );
        }
        eprintln!("[svc] W3: клиент пайпа аутентифицирован (образ из install-dir, pid={pid})");
        Ok(())
    }

    /// Полный путь образа процесса `pid` (QueryFullProcessImageNameW). SYSTEM открывает любой процесс
    /// правом PROCESS_QUERY_LIMITED_INFORMATION (кросс-integrity вниз всегда разрешён).
    fn client_image_path(pid: u32) -> anyhow::Result<std::path::PathBuf> {
        use windows_sys::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        // SAFETY: OpenProcess лимитированным правом; хэндл закрываем; буфер фикс. под MAX_PATH,
        // len — in/out (ёмкость буфера → фактическая длина, символы UTF-16).
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                anyhow::bail!("OpenProcess(pid={pid}) err={}", GetLastError());
            }
            let mut buf = [0u16; 260]; // MAX_PATH
            let mut len = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len);
            CloseHandle(h);
            if ok == 0 {
                anyhow::bail!("QueryFullProcessImageNameW(pid={pid}) err={}", GetLastError());
            }
            Ok(std::path::PathBuf::from(String::from_utf16_lossy(&buf[..len as usize])))
        }
    }

    /// M-5 (аудит-4): строковый SID пользователя, под которым работает процесс `pid` (`S-1-5-21-…`).
    /// По нему служба решает, кому принадлежит активная сессия туннеля и кто вправе её вытеснить.
    fn client_user_sid(pid: u32) -> anyhow::Result<String> {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
        use windows_sys::Win32::System::Threading::{
            OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        // SAFETY: стандартный путь «процесс → токен → TokenUser → строковый SID». Каждый успешно
        // полученный хэндл закрывается; буфер выделяется по размеру, который вернул сам
        // GetTokenInformation; строку SID освобождает LocalFree (её выделил ConvertSidToStringSidW).
        unsafe {
            let proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if proc.is_null() {
                anyhow::bail!("OpenProcess(pid={pid}) err={}", GetLastError());
            }
            let mut token: HANDLE = std::ptr::null_mut();
            let ok = OpenProcessToken(proc, TOKEN_QUERY, &mut token);
            CloseHandle(proc);
            if ok == 0 {
                anyhow::bail!("OpenProcessToken(pid={pid}) err={}", GetLastError());
            }
            // Первый вызов — только за размером буфера (вернёт FALSE + ERROR_INSUFFICIENT_BUFFER).
            let mut need: u32 = 0;
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut need);
            if need == 0 {
                CloseHandle(token);
                anyhow::bail!("GetTokenInformation(размер) err={}", GetLastError());
            }
            let mut buf = vec![0u8; need as usize];
            let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), need, &mut need);
            CloseHandle(token);
            if ok == 0 {
                anyhow::bail!("GetTokenInformation(TokenUser) err={}", GetLastError());
            }
            let user: *const TOKEN_USER = buf.as_ptr().cast();
            let mut wide: *mut u16 = std::ptr::null_mut();
            if ConvertSidToStringSidW((*user).User.Sid, &mut wide) == 0 {
                anyhow::bail!("ConvertSidToStringSidW err={}", GetLastError());
            }
            let mut len = 0usize;
            while *wide.add(len) != 0 {
                len += 1;
            }
            let sid = String::from_utf16_lossy(std::slice::from_raw_parts(wide, len));
            LocalFree(wide.cast());
            Ok(sid)
        }
    }

    /// Аутентифицировать подключившегося клиента и вернуть **владельца** соединения (строковый SID).
    /// W3 — образ из install-dir; M-5 — пользователь, которому будет принадлежать сессия.
    ///
    /// Не смогли определить владельца — отказ (fail-closed): иначе противник, умеющий сорвать эту
    /// проверку, получал бы `None`, который «совпадает» с dev-режимом и вытеснял бы любую сессию.
    fn authenticate_client(pipe: HANDLE) -> anyhow::Result<String> {
        verify_client_is_installed_app(pipe)?;
        let mut pid: u32 = 0;
        // SAFETY: pipe — валидный серверный хэндл подключённого клиента; pid — out-указатель.
        if unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) } == 0 {
            anyhow::bail!("GetNamedPipeClientProcessId err={}", unsafe { GetLastError() });
        }
        let sid = client_user_sid(pid)
            .map_err(|e| anyhow::anyhow!("M-5: не определить владельца сессии: {e:#}"))?;
        eprintln!("[svc] M-5: владелец соединения — {sid} (pid={pid})");
        Ok(sid)
    }

    /// Прервать блокирующий `ConnectNamedPipe` на слушающем инстансе (control-handler на Stop,
    /// рабочий поток после `TAG_QUIT`). Сессию это не трогает — её сворачивает [`cancel_active_session`].
    fn cancel_accept() {
        let h = LISTENING_PIPE.load(Ordering::Acquire);
        if h != 0 {
            // SAFETY: h — текущий слушающий хэндл пайпа; CancelIoEx безопасен из другого потока и на
            // хэндле без активного I/O (вернёт FALSE — игнорируем).
            unsafe { CancelIoEx(h as HANDLE, std::ptr::null()) };
        }
    }

    /// Прервать I/O активной сессии, чтобы её рабочий поток вышел в teardown (остановка службы).
    fn cancel_active_session() {
        let slot = SESSION.lock().unwrap().clone();
        if let Some(slot) = slot {
            // Не ждём здесь: ожидание рабочих потоков (с общей границей) делает вызывающий.
            let done = slot.done.lock().unwrap();
            if !*done {
                // SAFETY: под мьютексом хэндл ещё не закрыт (`finish` закрывает его под ним же).
                unsafe { CancelIoEx(slot.pipe as HANDLE, std::ptr::null()) };
            }
        }
    }

    /// Создать новый инстанс named pipe (дуплекс, байт-поток) с ACL из [`PIPE_SDDL`]. Инстансов
    /// одновременно несколько: один слушающий (акцептор) + по одному на обслуживаемое соединение.
    fn create_pipe_instance() -> anyhow::Result<HANDLE> {
        let name = wide(PIPE_NAME);
        // ACL пайпа из SDDL (см. PIPE_SDDL). При неудаче построения — предупреждаем и НЕ падаем
        // (дефолтный SD слабее, но служба работает).
        let sddl = wide(PIPE_SDDL);
        let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: sddl — валидная UTF-16 строка; psd пишется API при успехе (LocalAlloc).
        let sd_ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1, // SDDL_REVISION_1
                &mut psd,
                std::ptr::null_mut(),
            )
        };
        if sd_ok == 0 {
            eprintln!(
                "[svc] ⚠ SD пайпа не построен (err={}) — дефолтный ACL",
                unsafe { GetLastError() }
            );
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: if sd_ok != 0 { psd } else { std::ptr::null_mut() },
            bInheritHandle: 0,
        };
        let sa_ptr: *const SECURITY_ATTRIBUTES = if sd_ok != 0 { &sa } else { std::ptr::null() };
        // SAFETY: name/sa валидны; SD (если построен) копируется внутрь объекта пайпа.
        let h = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                // OVERLAPPED: конкурентные Read (pipe→WinTUN) и Write (WinTUN→pipe) на одном хэндле
                // НЕ сериализуются ядром (иначе packet-pump встаёт — блокирующий Read глушит Write).
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                64 * 1024,
                64 * 1024,
                0,
                sa_ptr,
            )
        };
        // SD скопирован в объект пайпа → освобождаем нашу копию (ConvertString аллоцирует LocalAlloc).
        if sd_ok != 0 {
            unsafe { LocalFree(psd) };
        }
        if h == INVALID_HANDLE_VALUE {
            anyhow::bail!("CreateNamedPipeW failed: err={}", unsafe { GetLastError() });
        }
        Ok(h)
    }

    /// Что запросил клиент в фазе конфигурации.
    enum Request {
        /// Поднять туннель по этому конфигу (`TAG_CONFIG`).
        Config(Box<TunSetup>),
        /// Остановить службу (`TAG_QUIT`) — приложение выходит.
        Quit,
    }

    /// Обслужить одного клиента (на своём рабочем потоке): config-handshake → вытеснение прежней
    /// сессии → оркестрация → READY → pump. При ошибке отвечаем READY-err (приложение покажет
    /// причину). `true` — клиент попросил остановить службу.
    fn handle_client(slot: &Arc<SessionSlot>) -> bool {
        let h = slot.pipe as HANDLE;
        let ov = match Ov::new() {
            Ok(o) => o,
            Err(e) => {
                eprintln!("[svc] Ov рабочего потока не создан: {e:#}");
                return false;
            }
        };
        let setup = match read_request(&ov, h) {
            Ok(Request::Quit) => return handle_quit(),
            Ok(Request::Config(s)) => *s,
            Err(e) => {
                eprintln!("[svc] чтение config: {e:#}");
                return false;
            }
        };
        // Слот занимаем ДО bring_up: адаптер один, и прежняя сессия (реконнект приложения, повторный
        // запуск) должна быть свёрнута полностью, иначе получим второй WinTUN с тем же именем и
        // гонку за маршруты. Не свернулась за отведённое время — честно отказываем.
        if let Err(why) = claim_session_slot(slot) {
            let _ = ov.write_all(h, &encode_ready_err(&why));
            return false;
        }
        let plan = plan_session(&setup, ADAPTER_NAME);
        eprintln!(
            "[svc] сессия: {} netsh-команд, bypass={:?}, wfp-фильтров={} (KS и/или IPv6-блок)",
            plan.netsh.len(),
            plan.bypass,
            plan.wfp.as_ref().map_or(0, |w| w.len())
        );
        match bring_up(&plan) {
            Ok(session) => {
                let _ = ov.write_all(h, &encode_ready_ok(&TunReady { adapter_luid: session.luid }));
                let clean = pump(h, &session, &ov);
                teardown(session, clean);
            }
            Err(e) => {
                eprintln!("[svc] bring_up: {e:#}");
                let _ = ov.write_all(h, &encode_ready_err(&format!("{e:#}")));
            }
        }
        release_session_slot(slot);
        false
    }

    /// `TAG_QUIT` — приложение выходит и просит погасить службу (не держать elevated-процесс без
    /// клиента). Гасим ТОЛЬКО без активного туннеля: иначе любой процесс, прошедший W3, снял бы
    /// вместе со службой WinTUN-адаптер и WFP-kill-switch у работающей сессии (fail-open = деанон).
    /// Короткая отсрочка — под штатную гонку: приложение шлёт QUIT сразу после `disconnect`, и
    /// прежняя сессия в этот момент ещё доворачивает teardown.
    fn handle_quit() -> bool {
        let deadline = std::time::Instant::now() + QUIT_GRACE;
        while session_active() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        if session_active() {
            eprintln!("[svc] TAG_QUIT отклонён: туннель активен — службу не гашу (fail-closed)");
            return false;
        }
        eprintln!("[svc] клиент запросил остановку службы (выход приложения) — завершаюсь");
        true
    }

    /// Прочитать управляющий кадр фазы конфигурации: `TAG_CONFIG ‖ u32(len,BE) ‖ cbor(TunSetup)`
    /// либо `TAG_QUIT` (без тела).
    fn read_request(ov: &Ov, h: HANDLE) -> anyhow::Result<Request> {
        // Клиент шлёт запрос сразу после подключения; молчун не должен вечно держать рабочий поток
        // и инстанс пайпа (данные фазы handshake коротки, сеть не участвует — секунды с запасом).
        let limit = Some(HANDSHAKE_TIMEOUT);
        let mut tag = [0u8; 1];
        ov.read_exact_within(h, &mut tag, limit)?;
        match tag[0] {
            TAG_QUIT => Ok(Request::Quit),
            TAG_CONFIG => {
                let mut lenb = [0u8; 4];
                ov.read_exact_within(h, &mut lenb, limit)?;
                let len = u32::from_be_bytes(lenb) as usize;
                if len > MAX_CONFIG {
                    anyhow::bail!("config-кадр слишком большой: {len} > {MAX_CONFIG}");
                }
                let mut body = vec![0u8; len];
                ov.read_exact_within(h, &mut body, limit)?;
                Ok(Request::Config(Box::new(decode_config(&body)?)))
            }
            other => anyhow::bail!("ожидался TAG_CONFIG/TAG_QUIT, получен 0x{other:02x}"),
        }
    }

    /// Поднятая сессия: владеет WinTUN-адаптером + пакетной сессией (в `Arc` — делится между потоками
    /// pump'а) + список применённых bypass-маршрутов (для отката). Порядок полей = порядок drop.
    struct Session {
        session: Arc<wintun::Session>,
        _adapter: Arc<wintun::Adapter>,
        luid: u64,
        /// Успешно добавленные bypass-назначения (`route add …`) — откатываются в teardown.
        bypass: Vec<String>,
        /// W1: армирован ли РЕАЛЬНЫЙ kill-switch (V4-фильтры), а не только IPv6-блок утечки. От этого
        /// зависит fail-closed-удержание WFP при аварийном разрыве (teardown): KS держим, чистый
        /// IPv6-блок (full-tunnel без KS) — снимаем (пользователь fail-closed не выбирал).
        killswitch: bool,
    }

    /// Поднять туннель: WinTUN-адаптер → bypass-маршруты (мимо туннеля) → адрес/MTU/маршруты/DNS
    /// → WFP (kill-switch и/или блок IPv6-утечки, если они есть в плане).
    fn bring_up(plan: &SessionPlan) -> anyhow::Result<Session> {
        // Грузим wintun.dll (кладётся рядом со службой при упаковке). SAFETY: доверенная DLL WireGuard.
        let wintun =
            unsafe { wintun::load() }.map_err(|e| anyhow::anyhow!("загрузить wintun.dll: {e}"))?;
        let adapter = wintun::Adapter::create(&wintun, ADAPTER_NAME, ADAPTER_NAME, None)
            .map_err(|e| anyhow::anyhow!("создать WinTUN-адаптер '{ADAPTER_NAME}': {e}"))?;
        // get_luid() → NET_LUID_LH (union); .Value = u64-представление. SAFETY: чтение u64-поля union.
        let luid = unsafe { adapter.get_luid().Value };

        // Стартуем сессию ДО применения IP/маршрутов: WinTUN-адаптер репортит media «connected»
        // только с активной сессией. Если настроить адрес/маршруты, пока адаптер «disconnected»,
        // Windows считает интерфейс неактивным и НЕ маршрутизирует через него → «туннель поднят, а
        // интернета нет». Порядок как у wireguard-windows (сессия → конфиг).
        let session = Arc::new(
            adapter
                .start_session(wintun::MAX_RING_CAPACITY)
                .map_err(|e| anyhow::anyhow!("WinTUN start_session: {e}"))?,
        );
        eprintln!("[svc] WinTUN сессия открыта (luid={luid}) — настраиваю сеть");

        // Физический шлюз ДО подмены маршрутов туннелем — для bypass (анти-петля + Q5 split).
        let gw = default_gateway();
        eprintln!("[svc] физический default-gw: {gw:?}");
        // bypass ПЕРЕД tunnel-маршрутами: физический default ещё цел (шлюз on-link → route add к exit
        // не падает «Сетевая папка недоступна»), а GetBestInterface даёт ФИЗИЧЕСКИЙ интерфейс, не
        // Citadel. Ровно как Linux-helper ставит bypass ДО подмены routes. Без него трафик клиента к
        // exit'у заворачивается в туннель (петля) → QUIC-носитель дохнет → реконнект/нет интернета.
        let bypass = apply_bypass(&plan.bypass, gw.as_deref());
        // адрес/MTU/маршруты-в-туннель/DNS на адаптере (по имени ADAPTER_NAME). Сбой → откат bypass.
        if let Err(e) = apply_netsh(&plan.netsh) {
            for dest in &bypass {
                let _ = std::process::Command::new("route").args(bypass_route_del(dest)).status();
            }
            return Err(e);
        }

        // WFP fail-closed: IPv4 kill-switch (permit'ы плана) и/или IPv6-блок утечки (W1). Оба слоя —
        // в одной dynamic-сессии. `killswitch_armed` = есть ли РЕАЛЬНЫЙ KS (V4-фильтры) → от него
        // зависит удержание WFP при аварийном разрыве (teardown). Ошибка армирования = не поднимаем
        // туннель без запрошенной защиты (откат bypass перед выходом).
        let mut killswitch_armed = false;
        if let Some(wfp_filters) = &plan.wfp {
            if let Err(e) = crate::wfp::arm(wfp_filters, luid) {
                for dest in &bypass {
                    let _ = std::process::Command::new("route").args(bypass_route_del(dest)).status();
                }
                return Err(anyhow::anyhow!("армировать WFP: {e}"));
            }
            killswitch_armed = wfp_filters.iter().any(|f| f.family == WfpFamily::V4);
            eprintln!(
                "[svc] WFP армирован: {} фильтров (IPv4 kill-switch и/или IPv6-блок утечки, W1)",
                wfp_filters.len()
            );
        } else {
            // KS выключен в ЭТОЙ сессии → снять осиротевший WFP от прошлой аварийно-разорванной
            // KS-сессии (служба persistent/AutoStart → dynamic-фильтры живут, пока жив процесс). Иначе
            // он молча блокировал бы не-туннельный трафик вопреки выбору «без kill-switch» И мог бы
            // резать issuer при добыче токена. disarm идемпотентен (нет engine → no-op).
            crate::wfp::disarm();
        }

        eprintln!("[svc] WinTUN '{ADAPTER_NAME}' поднят (luid={luid}); bypass={bypass:?}");
        Ok(Session { session, _adapter: adapter, luid, bypass, killswitch: killswitch_armed })
    }

    /// Применить список netsh-команд (argv без ведущего `netsh`). Ошибка любой — прерывает bring_up.
    /// Захватываем вывод (`.output()`), т.к. дочерний netsh НЕ наследует перенаправленный в файл
    /// stderr службы — иначе причина сбоя (напр. «Element not found») не попала бы в лог/UI.
    fn apply_netsh(cmds: &[Vec<String>]) -> anyhow::Result<()> {
        for c in cmds {
            let out = std::process::Command::new("netsh")
                .args(c)
                .output()
                .map_err(|e| anyhow::anyhow!("запустить netsh {c:?}: {e}"))?;
            if !out.status.success() {
                anyhow::bail!(
                    "netsh {c:?} → код {:?}: {} {}",
                    out.status.code(),
                    String::from_utf8_lossy(&out.stdout).trim(),
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
            eprintln!("[svc] netsh ok: {}", c.join(" "));
        }
        Ok(())
    }

    /// Физический default-gateway из `route print -4` (чистый парсер [`crate::plan::parse_default_gateway`]).
    fn default_gateway() -> Option<String> {
        let out = std::process::Command::new("route").args(["print", "-4"]).output().ok()?;
        crate::plan::parse_default_gateway(&String::from_utf8_lossy(&out.stdout))
    }

    /// Индекс физического интерфейса, которым СЕЙЧАС достигается `probe` (IPv4), через IP Helper
    /// `GetBestInterface`. Зовётся ДО подмены routes туннелем → возвращает физический интерфейс
    /// (а не Citadel). Нужен, чтобы `route add ... IF <idx>` НЕ гадал интерфейс по шлюзу (иначе
    /// route.exe падает «Сетевая папка недоступна» при p2p-шлюзе / после /1-маршрутов).
    fn best_iface_index(probe: &str) -> Option<u32> {
        let ip: std::net::Ipv4Addr = probe.parse().ok()?;
        // GetBestInterface ждёт IPAddr в СЕТЕВОМ порядке байт (a.b.c.d в памяти) = from_le_bytes на
        // Windows (LE): 127.0.0.1 → 0x0100007F.
        let dw = u32::from_le_bytes(ip.octets());
        let mut idx: u32 = 0;
        // SAFETY: idx — валидный out-указатель; функция без побочных эффектов на память.
        let rc = unsafe { GetBestInterface(dw, &mut idx) };
        if rc == 0 {
            Some(idx)
        } else {
            None
        }
    }

    /// Добавить bypass-маршруты мимо туннеля через физический шлюз (`route add <dst> mask <m> <gw>
    /// [IF <idx>]`). Возвращает добавленные (для отката). Зовётся ДО подмены routes туннелем, чтобы
    /// физический default был цел (шлюз on-link) и `GetBestInterface` дал физический интерфейс.
    /// Без gw — предупреждаем (риск петли при full-tunnel), ничего не ставим.
    fn apply_bypass(dests: &[String], gw: Option<&str>) -> Vec<String> {
        let Some(gw) = gw else {
            if !dests.is_empty() {
                eprintln!("[svc] WARN: default-gw не найден — bypass не добавлен (риск петли)");
            }
            return Vec::new();
        };
        let mut done = Vec::new();
        for dest in dests {
            let mut args = bypass_route_add(dest, gw); // ["add", net, "mask", m, gw]
            // явный интерфейс (индекс) — по IP назначения (host-часть CIDR), пока routes физические.
            let probe = dest.split('/').next().unwrap_or(dest);
            let ifidx = best_iface_index(probe);
            if let Some(idx) = ifidx {
                args.push("IF".into());
                args.push(idx.to_string());
            }
            // .output(): route.exe возвращает 0 даже при сбое → судим по тексту (лог для диагностики).
            let out = std::process::Command::new("route").args(&args).output();
            match out {
                Ok(o) => {
                    let so = String::from_utf8_lossy(&o.stdout);
                    let se = String::from_utf8_lossy(&o.stderr);
                    let failed = so.contains("Сбой") || so.contains("failed") || se.contains("Сбой")
                        || se.contains("failed") || !o.status.success();
                    if failed {
                        eprintln!(
                            "[svc] route add {dest} via {gw} IF {ifidx:?} НЕ УДАЛСЯ: {} {}",
                            so.trim(),
                            se.trim()
                        );
                    } else {
                        eprintln!("[svc] bypass ok: {dest} via {gw} IF {ifidx:?}");
                        done.push(dest.clone());
                    }
                }
                Err(e) => eprintln!("[svc] route add {dest} не запущен: {e}"),
            }
        }
        done
    }

    /// Packet-pump: два потока поверх одного OVERLAPPED-пайпа (полнодуплекс, БЕЗ сериализации).
    /// `ov_main` (serve-поток) читает пайп→WinTUN; writer-поток держит СВОЙ `Ov` для WinTUN→пайп.
    /// Возвращает `true`, если получен маркер чистого disconnect (len==0) — teardown снимет WFP;
    /// иначе (краш/реконнект) WFP держим (fail-closed).
    fn pump(pipe: HANDLE, s: &Session, ov_main: &Ov) -> bool {
        let stop = Arc::new(AtomicBool::new(false));
        let clean = Arc::new(AtomicBool::new(false));

        // Поток WinTUN → пайп: блокирующее чтение из адаптера, кадрирование, overlapped-запись в пайп.
        let t1 = {
            let session = s.session.clone();
            let pipe = SendHandle(pipe);
            let stop = stop.clone();
            std::thread::spawn(move || {
                let pipe = pipe; // move обёртки в поток
                let ov = match Ov::new() {
                    Ok(o) => o, // свой OVERLAPPED-контекст writer'а (не делится с reader-потоком)
                    Err(e) => {
                        eprintln!("[svc] pump: writer Ov не создан: {e:#}");
                        stop.store(true, Ordering::Relaxed);
                        return;
                    }
                };
                while !stop.load(Ordering::Relaxed) {
                    match session.receive_blocking() {
                        Ok(packet) => {
                            if ov.write_all(pipe.0, &encode_packet(packet.bytes())).is_err() {
                                break; // пайп закрыт
                            }
                        }
                        Err(_) => break, // сессия закрыта (shutdown)
                    }
                }
                stop.store(true, Ordering::Relaxed);
            })
        };

        // Поток пайп → WinTUN (текущий/serve): читаем кадры (overlapped), отправляем в адаптер.
        while !stop.load(Ordering::Relaxed) {
            match ov_main.read_frame(pipe) {
                Ok(Some(pkt)) => {
                    if let Ok(mut sp) = s.session.allocate_send_packet(pkt.len() as u16) {
                        sp.bytes_mut().copy_from_slice(&pkt);
                        s.session.send_packet(sp);
                    }
                }
                Ok(None) => {
                    clean.store(true, Ordering::Relaxed); // маркер чистого disconnect (len==0)
                    break;
                }
                Err(_) => break, // пайп закрыт/ошибка/отмена (CancelIoEx на Stop)
            }
        }
        stop.store(true, Ordering::Relaxed);
        // Разбудить t1 ОБОИМИ способами, иначе join висит вечно вместе со всей службой:
        //  • `session.shutdown()` — если поток стоит в `receive_blocking` (пакетов из WinTUN нет);
        //  • `CancelIoEx` — если он стоит в overlapped-`WriteFile` (клиент перестал читать пайп, но
        //    хэндл ещё держит: 64 КБ буфера пайпа заполнены, запись «в ожидании» навсегда). Именно
        //    этот случай раньше замораживал serve-цикл — пайп оставался занят, туннель больше не
        //    поднимался ни по одной ссылке, а `TAG_QUIT` не доходил (citadel-svc.exe висел в задачах).
        let _ = s.session.shutdown();
        // SAFETY: pipe — валидный хэндл этой сессии (закрывает его владеющий SessionSlot после pump);
        // CancelIoEx безопасен из любого потока и на хэндле без активного I/O.
        unsafe { CancelIoEx(pipe, std::ptr::null()) };
        let _ = t1.join();
        clean.load(Ordering::Relaxed)
    }

    /// Свернуть сессию: откат bypass-маршрутов + drop адаптера (маршруты/DNS `store=active` исчезают
    /// с ним). WFP при чистом disconnect снимаем ВСЕГДА. При аварийном разрыве держим fail-closed
    /// ТОЛЬКО если был РЕАЛЬНЫЙ kill-switch (`s.killswitch`); если WFP был лишь IPv6-блоком утечки
    /// (full-tunnel без KS — пользователь fail-closed не выбирал), снимаем, чтобы после падения
    /// движка IPv6-связность восстановилась (как Linux-helper снимает CITADEL_KS6 без killswitch, W1).
    fn teardown(s: Session, clean: bool) {
        for dest in &s.bypass {
            let _ = std::process::Command::new("route").args(bypass_route_del(dest)).status();
        }
        if clean {
            crate::wfp::disarm();
        } else if s.killswitch {
            eprintln!("[svc] аварийный разрыв — WFP kill-switch ОСТАВЛЕН (fail-closed)");
        } else {
            // WFP был только IPv6-блоком (full-tunnel без KS) → снимаем: IPv6 восстановится, как IPv4.
            crate::wfp::disarm();
            eprintln!("[svc] аварийный разрыв — IPv6-блок снят (kill-switch не запрашивался)");
        }
        // drop(s) закрывает WinTUN-сессию и адаптер.
    }
}
