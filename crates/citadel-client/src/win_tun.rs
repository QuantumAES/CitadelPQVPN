//! `WindowsTunProvider` — `TunProvider` для Windows-desktop (модель W2: служба-плумбер + пакет-пайп).
//!
//! Windows-аналог `GuiTunProvider` (Linux). Привилегированную часть (создание WinTUN-адаптера +
//! маршруты/DNS/WFP-kill-switch) делает служба **`citadel-svc`** (ставится elevated при установке
//! приложения); адаптер и её I/O-петля живут В СЛУЖБЕ, а неприв. приложение общается с ней по
//! **named pipe** `\\.\pipe\citadel-svc`. Пайп играет роль fd из Linux-SCM_RIGHTS: конфиг → служба
//! поднимает адаптер → дальше двунаправленный поток IP-пакетов (кадры `winnet`), движок крутится в
//! приложении, как на Linux.
//!
//! **Overlapped (асинхронный) I/O.** Пайп открывается с `FILE_FLAG_OVERLAPPED`, и recv/send идут
//! overlapped-операциями (блокируемся через `GetOverlappedResult`). Это КРИТИЧНО: в СИНХРОННОМ режиме
//! ядро сериализует все операции на file-object'е (`FO_SYNCHRONOUS_IO`), поэтому блокирующий `recv`
//! (reader-поток data-plane ждёт пакет из туннеля) повиснув держал бы лок и глушил `send`
//! (writer-поток) — pump вставал, через туннель не шло НИ ОДНОГО пакета (QUIC idle-timeout).
//! `try_clone`/дубль хэндла НЕ спасает: сериализация идёт по file-object'у, а не по хэндлу. Overlapped
//! этого не делает: recv и send с раздельными OVERLAPPED идут независимо. reader и writer держат по
//! своему [`OvIo`] (событие+OVERLAPPED); пайп-хэндл общий.
//!
//! Fail-closed (C6/M9): чистый disconnect шлёт службе маркер `len==0` (аналог байта `'Q'` Linux) →
//! служба снимает WFP-kill-switch. Реконнект/краш = пайп рвётся БЕЗ маркера → служба видит EOF без
//! маркера → kill-switch ОСТАЁТСЯ (не утекает), ровно как helper держит iptables при EOF-без-'Q'.

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_IO_PENDING, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
};
use windows_sys::Win32::System::Threading::{CreateEventW, ResetEvent};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

use citadel_quic::vpn::{TunParams, TunProvider};
use citadel_tun::TunIo;

use crate::winnet::{self, TunReady, TunSetup};

/// Named pipe, на котором слушает привилегированная служба `citadel-svc`.
pub const PIPE_PATH: &str = r"\\.\pipe\citadel-svc";

/// UTF-16 нуль-терминированная строка для *W-API.
fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

/// Владеющий overlapped-хэндл пайпа (закрывается на `Drop`). `isize` (а не `HANDLE=*mut c_void`),
/// чтобы структура была `Send`+`Sync` (движок клонирует `Arc<dyn TunIo>` между потоками).
struct PipeHandle(isize);
// SAFETY: named pipe допускает конкурентный overlapped Read/Write из разных потоков; хэндл валиден,
// пока жив self (закрывается один раз в Drop).
unsafe impl Send for PipeHandle {}
unsafe impl Sync for PipeHandle {}
impl Drop for PipeHandle {
    fn drop(&mut self) {
        // SAFETY: self.0 — валидный хэндл пайпа, больше не используется.
        unsafe { CloseHandle(self.0 as HANDLE) };
    }
}

/// Пер-направленческий overlapped-контекст: manual-reset событие для блокирующего завершения ОДНОЙ
/// операции. Reader и writer держат по своему `OvIo` — иначе конкурентные операции делили бы одно
/// событие. `event` как `isize` для `Send`.
struct OvIo {
    event: isize,
}
// SAFETY: каждый OvIo используется под своим Mutex одним потоком за раз.
unsafe impl Send for OvIo {}
impl OvIo {
    fn new() -> io::Result<Self> {
        // manual-reset (TRUE), начально несигнальное, без имени.
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(OvIo { event: event as isize })
    }

    /// Одна overlapped Read/Write → число переданных байт. `write=false` → ReadFile.
    fn one(&self, h: isize, ptr: *mut u8, len: u32, write: bool) -> io::Result<u32> {
        self.one_within(h, ptr, len, write, None)
    }

    /// Как [`one`], но с необязательной границей ожидания. `Some(d)` — ждём завершения не дольше `d`,
    /// затем ОТМЕНЯЕМ операцию и возвращаем `TimedOut`. Нужно на фазе конфигурации: там ответ даёт
    /// привилегированная служба, и если она встанет (создание адаптера, `netsh`, вытеснение прежней
    /// сессии), приложение без границы висело бы в «подключение» бесконечно, без единой строки в UI.
    /// Data-path границы не имеет (пакета можно ждать сколько угодно) — там пробуждение через `cancel`.
    fn one_within(
        &self,
        h: isize,
        ptr: *mut u8,
        len: u32,
        write: bool,
        limit: Option<std::time::Duration>,
    ) -> io::Result<u32> {
        use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
        use windows_sys::Win32::System::Threading::WaitForSingleObject;
        // SAFETY: h — валидный overlapped-хэндл пайпа; ptr/len — валидный буфер; ov живёт до конца
        // GetOverlappedResult (он вызывается на ВСЕХ путях выхода, в т.ч. после отмены по таймауту —
        // иначе ядро писало бы в освобождённый стек); event — валидное событие OvIo.
        unsafe {
            let mut ov: OVERLAPPED = std::mem::zeroed();
            ov.hEvent = self.event as HANDLE;
            ResetEvent(self.event as HANDLE);
            let ok = if write {
                WriteFile(h as HANDLE, ptr as *const u8, len, std::ptr::null_mut(), &mut ov)
            } else {
                ReadFile(h as HANDLE, ptr, len, std::ptr::null_mut(), &mut ov)
            };
            if ok == 0 {
                let e = windows_sys::Win32::Foundation::GetLastError();
                if e != ERROR_IO_PENDING {
                    return Err(io::Error::from_raw_os_error(e as i32));
                }
            }
            let mut timed_out = false;
            if let Some(d) = limit {
                let ms = d.as_millis().min(u32::MAX as u128 - 1) as u32;
                if WaitForSingleObject(self.event as HANDLE, ms) != WAIT_OBJECT_0 {
                    // Не дождались — снимаем ИМЕННО эту операцию и всё равно забираем результат ниже
                    // (GetOverlappedResult с bWait=TRUE вернётся сразу после её отмены ядром).
                    CancelIoEx(h as HANDLE, &ov);
                    timed_out = true;
                }
            }
            let mut done = 0u32;
            // bWait=TRUE: ждём на ov.hEvent; CancelIoEx (реконнект/disconnect/таймаут) завершит с ошибкой.
            let got = GetOverlappedResult(h as HANDLE, &ov, &mut done, 1);
            if timed_out {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "служба citadel-svc не ответила вовремя",
                ));
            }
            if got == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(done)
        }
    }

    fn read_exact(&self, h: isize, buf: &mut [u8]) -> io::Result<()> {
        self.read_exact_within(h, buf, None)
    }

    /// [`read_exact`] с общей границей на всё чтение (см. [`one_within`]).
    fn read_exact_within(
        &self,
        h: isize,
        buf: &mut [u8],
        limit: Option<std::time::Duration>,
    ) -> io::Result<()> {
        let deadline = limit.map(|d| std::time::Instant::now() + d);
        let mut off = 0;
        while off < buf.len() {
            let left = deadline.map(|dl| dl.saturating_duration_since(std::time::Instant::now()));
            let n = self.one_within(
                h,
                buf[off..].as_mut_ptr(),
                (buf.len() - off) as u32,
                false,
                left,
            )?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "пайп закрыт (EOF)"));
            }
            off += n as usize;
        }
        Ok(())
    }

    fn write_all(&self, h: isize, buf: &[u8]) -> io::Result<()> {
        let mut off = 0;
        while off < buf.len() {
            let n =
                self.one(h, buf[off..].as_ptr() as *mut u8, (buf.len() - off) as u32, true)?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "пайп закрыт при записи"));
            }
            off += n as usize;
        }
        Ok(())
    }
}
impl Drop for OvIo {
    fn drop(&mut self) {
        // SAFETY: event — валидный хэндл события, больше не используется.
        unsafe { CloseHandle(self.event as HANDLE) };
    }
}

/// Сколько ждать доступности пайпа при подключении сессии. Служба может в этот момент сворачивать
/// прежнюю сессию (удаление WinTUN-адаптера — единицы секунд) или только что стартовать по SCM.
const PIPE_OPEN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
/// То же для служебных запросов на выходе из приложения (`TAG_QUIT`): выход важнее гарантии.
const PIPE_QUIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Открыть named pipe службы в overlapped-режиме, ретраясь до `timeout` на ДВУХ переходных отказах:
///
/// * `ERROR_PIPE_BUSY` (231, «Все копии канала заняты») — свободного инстанса сейчас нет; ждём
///   `WaitNamedPipe`;
/// * `ERROR_FILE_NOT_FOUND` (2) — слушающего инстанса нет ВОВСЕ: служба перезапускается по SCM
///   (recovery/`StartService` только что вернул управление) либо пересоздаёт инстанс. Раньше этот
///   код выходил сразу, и реконнект, попавший в окно, падал с «Не удается найти указанный файл»,
///   хотя через долю секунды всё было готово.
///
/// Прочие ошибки (отказано в доступе и т.п.) — сразу наверх: ретраить их бессмысленно.
fn open_overlapped_pipe_within(path: &str, timeout: std::time::Duration) -> io::Result<PipeHandle> {
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY};
    use windows_sys::Win32::System::Pipes::WaitNamedPipeW;
    let name = wide(path);
    let deadline = std::time::Instant::now() + timeout;
    loop {
        // SAFETY: name — валидная UTF-16 строка; прочие аргументы — константы/null.
        let h = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                std::ptr::null_mut(),
            )
        };
        if h != INVALID_HANDLE_VALUE {
            return Ok(PipeHandle(h as isize));
        }
        // SAFETY: читаем код сразу после неудачного CreateFileW.
        let err = unsafe { GetLastError() };
        let transient = err == ERROR_PIPE_BUSY || err == ERROR_FILE_NOT_FOUND;
        if !transient || std::time::Instant::now() >= deadline {
            return Err(io::Error::from_raw_os_error(err as i32));
        }
        if err == ERROR_PIPE_BUSY {
            // Ждём освобождения инстанса (до 500мс), затем ретрай CreateFileW.
            // SAFETY: name валиден; таймаут в мс.
            unsafe { WaitNamedPipeW(name.as_ptr(), 500) };
        } else {
            std::thread::sleep(std::time::Duration::from_millis(150));
        }
    }
}

/// W4 (аудит-3): анти-сквоттинг named pipe. Клиент ОБЯЗАН убедиться, что серверный конец пайпа создан
/// привилегированным процессом (владелец объекта = SYSTEM или Administrators), а не подставным
/// процессом под тем же юзером. Иначе сквоттер, успевший создать `\\.\pipe\citadel-svc` в окне гонки
/// (или до старта службы), выдал бы себя за службу → получил бы РАСШИФРОВАННЫЙ входящий туннельный
/// трафик и инъектировал бы пакеты в аутентифицированный туннель жертвы. Медиум-юзер НЕ может создать
/// объект во владении SYSTEM/Administrators (deny-only Administrators SID в токене) ⇒ owner-SID —
/// надёжный дискриминатор. Dev-обход: env `Citadel_INSECURE_PIPE` (служба под юзером в console-режиме).
fn verify_pipe_server_privileged(pipe: isize) -> Result<()> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
    use windows_sys::Win32::Security::{
        IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID,
    };
    if std::env::var_os("Citadel_INSECURE_PIPE").is_some() {
        eprintln!("[win_tun] ⚠ Citadel_INSECURE_PIPE — проверка владельца пайпа отключена (dev)");
        return Ok(());
    }
    // SAFETY: pipe — валидный хэндл с READ_CONTROL (GENERIC_READ его включает). owner указывает ВНУТРЬ
    // sd (LocalAlloc'нут GetSecurityInfo) → валиден до LocalFree(sd); ppsidgroup/ppdacl/ppsacl = null.
    unsafe {
        let mut owner: PSID = std::ptr::null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let rc = GetSecurityInfo(
            pipe as HANDLE,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        );
        if rc != 0 {
            bail!("не прочитать владельца пайпа службы (GetSecurityInfo err={rc}) — не доверяю каналу (W4)");
        }
        let privileged = IsWellKnownSid(owner, WinLocalSystemSid) != 0
            || IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0;
        LocalFree(sd);
        if !privileged {
            bail!("сервер пайпа citadel-svc НЕ привилегирован (владелец ≠ SYSTEM/Administrators) — возможен сквоттинг, отказ (W4)");
        }
    }
    Ok(())
}

/// `TunProvider` для Windows-desktop: привилегии — в службе `citadel-svc`, связь по named pipe.
pub struct WindowsTunProvider {
    /// Путь named pipe службы (по умолчанию [`PIPE_PATH`]; переопределяемо для dev/тестов).
    pub pipe_path: String,
}

impl Default for WindowsTunProvider {
    fn default() -> Self {
        Self { pipe_path: PIPE_PATH.into() }
    }
}

impl TunProvider for WindowsTunProvider {
    fn configure(&self, p: &TunParams) -> Result<Arc<dyn TunIo>> {
        // C8.3 split → (маршруты_в_туннель, CIDR_в_обход): та же winnet::split_routes, что на Linux
        // (единая split-семантика, включая Q5 kill-switch⇄split).
        let (routes, bypass) = winnet::split_routes(p.dest_mode, &p.routes, &p.dest_routes, (p.addr, p.prefix));
        let setup = TunSetup {
            addr: p.addr,
            prefix: p.prefix,
            mtu: p.mtu.parse().unwrap_or(1400),
            routes,
            dns: p.dns.clone(),
            exit_ips: p.exit_ips.clone(),
            bypass,
            killswitch: p.killswitch,
        };

        // Приложение гасит службу при выходе (см. [`service_request_quit`]) → к моменту коннекта её
        // может не быть в памяти. Поднимаем через SCM (право SERVICE_START выдано инсталлятором
        // интерактивному пользователю). Best-effort: если не вышло — ниже понятная ошибка пайпа.
        let svc_hint = match service_ensure_running() {
            Ok(()) => None,
            Err(e) => {
                eprintln!("[win] служба citadel-svc не запущена и не стартовала: {e:#}");
                Some(format!("{e:#}"))
            }
        };
        // Подключиться к службе (overlapped-хэндл). Отсутствие пайпа = служба не установлена/не
        // запущена — тогда в причину подставляем диагноз SCM (он объясняет, ЧТО чинить), а не
        // безликое «Не удается найти указанный файл».
        let pipe = open_overlapped_pipe_within(&self.pipe_path, PIPE_OPEN_TIMEOUT).map_err(|e| {
            let base = anyhow::Error::new(e);
            match &svc_hint {
                Some(h) => base.context(format!(
                    "служба citadel-svc недоступна ({}): {h}",
                    self.pipe_path
                )),
                None => base.context(format!(
                    "служба citadel-svc недоступна ({}) — установлена и запущена?",
                    self.pipe_path
                )),
            }
        })?;
        // W4: сервер пайпа обязан быть привилегированным (SYSTEM/Admins), а не сквоттером под юзером —
        // проверяем ДО отправки конфига/доверия каналу (анти-impersonation туннельного data-path).
        verify_pipe_server_privileged(pipe.0)
            .context("проверка подлинности службы citadel-svc (W4)")?;
        // Раздельные overlapped-контексты recv/send (общий хэндл, независимые OVERLAPPED).
        let read_io = OvIo::new().context("создать read-событие пайпа")?;
        let write_io = OvIo::new().context("создать write-событие пайпа")?;

        // Фаза конфигурации: шлём TunSetup → ждём READY (служба подняла адаптер/маршруты/WFP).
        write_io
            .write_all(pipe.0, &winnet::encode_config(&setup))
            .context("отправить конфиг службе")?;
        let ready = read_ready(&read_io, pipe.0).context("служба не подтвердила поднятие адаптера")?;
        let _ = ready.adapter_luid; // диагностический LUID (пока не используется)

        Ok(Arc::new(WindowsTun {
            pipe,
            read: Mutex::new(read_io),
            write: Mutex::new(write_io),
            cancelled: AtomicBool::new(false),
        }))
    }
}

// ─────────────────────────── жизненный цикл службы (п.2: не висеть без приложения) ───────────────────────────

/// Имя службы в SCM (= `SERVICE_NAME` в `citadel-svc`).
const SERVICE_NAME: &str = "CitadelPQVPN";

/// Выполнить `f` над открытой в SCM службой (хэндлы закрываются в любом случае).
/// `access` — требуемые права (`SERVICE_QUERY_STATUS`, `SERVICE_START`, …).
fn with_service<T>(access: u32, f: impl FnOnce(*mut std::ffi::c_void) -> Result<T>) -> Result<T> {
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT,
    };
    let name = wide(SERVICE_NAME);
    // SAFETY: name — валидная UTF-16 строка; оба SC-хэндла закрываются ровно один раз на всех путях.
    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            bail!("OpenSCManager: {}", io::Error::last_os_error());
        }
        let svc = OpenServiceW(scm, name.as_ptr(), access);
        if svc.is_null() {
            let e = io::Error::last_os_error();
            CloseServiceHandle(scm);
            bail!("OpenService({SERVICE_NAME}): {e} — служба установлена?");
        }
        let out = f(svc);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        out
    }
}

/// Текущее состояние службы (`SERVICE_RUNNING`/`SERVICE_STOPPED`/…) или ошибка (не установлена/нет прав).
fn service_state(svc: *mut std::ffi::c_void) -> Result<u32> {
    use windows_sys::Win32::System::Services::{QueryServiceStatus, SERVICE_STATUS};
    // SAFETY: svc — валидный хэндл с правом SERVICE_QUERY_STATUS; st — out-структура.
    unsafe {
        let mut st: SERVICE_STATUS = std::mem::zeroed();
        if QueryServiceStatus(svc, &mut st) == 0 {
            bail!("QueryServiceStatus: {}", io::Error::last_os_error());
        }
        Ok(st.dwCurrentState)
    }
}

/// Запущена ли служба (только право `SERVICE_QUERY_STATUS` — оно есть у любого пользователя даже с
/// дефолтным дескриптором службы). `Err` — служба не установлена / SCM недоступен.
fn service_is_running() -> Result<bool> {
    use windows_sys::Win32::System::Services::{SERVICE_QUERY_STATUS, SERVICE_RUNNING};
    with_service(SERVICE_QUERY_STATUS, |svc| Ok(service_state(svc)? == SERVICE_RUNNING))
}

/// Есть ли у ТЕКУЩЕГО пользователя право запустить службу (`SERVICE_START`). Его выдаёт установка
/// (`citadel-svc install` → `sc sdset`) и подтверждает сама служба на каждом старте; на установках,
/// где этого не случилось, право отсутствует — и приложение не должно гасить службу при выходе,
/// иначе поднять её обратно уже не сможет (ловушка «работает только от имени администратора»).
pub fn service_can_start() -> bool {
    use windows_sys::Win32::System::Services::SERVICE_START;
    with_service(SERVICE_START, |_| Ok(())).is_ok()
}

/// Убедиться, что служба `citadel-svc` запущена; если нет — стартовать через SCM и подождать
/// перехода в Running (до ~5 с). Право `SERVICE_START` интерактивному пользователю выдаёт
/// инсталлятор (`citadel-svc install` → `sc sdset`) и подтверждает служба на каждом старте, UAC не
/// требуется.
///
/// Статус спрашиваем ОТДЕЛЬНЫМ, минимальным доступом: `OpenService` с `SERVICE_START` отказывает
/// целиком, если права нет, — и раньше уже РАБОТАЮЩАЯ служба выглядела как «Отказано в доступе»,
/// хотя делать было нечего и туннель поднялся бы. Теперь нехватка прав всплывает только там, где
/// она действительно мешает: службу надо стартовать, а нечем.
pub fn service_ensure_running() -> Result<()> {
    use windows_sys::Win32::System::Services::{
        StartServiceW, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_START_PENDING,
    };
    if service_is_running()? {
        return Ok(());
    }
    with_service(SERVICE_QUERY_STATUS | SERVICE_START, |svc| {
        let state = service_state(svc)?;
        if state == SERVICE_RUNNING {
            return Ok(());
        }
        // SAFETY: svc — валидный хэндл с правом SERVICE_START; аргументов у службы нет.
        if state != SERVICE_START_PENDING && unsafe { StartServiceW(svc, 0, std::ptr::null()) } == 0
        {
            // SAFETY: код ошибки читаем сразу после неудачного вызова.
            let e = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            // 1056 = ERROR_SERVICE_ALREADY_RUNNING (гонка с другим стартом) — это успех.
            if e != 1056 {
                bail!(
                    "StartService({SERVICE_NAME}): {} (нет права SERVICE_START? переустановите приложение)",
                    io::Error::from_raw_os_error(e as i32)
                );
            }
        }
        // Дождаться Running: сразу после StartService пайпа ещё нет (иначе первый connect падает).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if service_state(svc)? == SERVICE_RUNNING {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        bail!("служба {SERVICE_NAME} не перешла в Running за 5 с")
    })
    .map_err(|e| {
        // Отказ в доступе на СТАРТЕ службы — это не «сломался Windows», а незавершённая установка.
        // Даём человеку ровно тот текст, по которому понятно, что делать (и почему «от имени
        // администратора» — обходной путь, а не решение).
        if format!("{e:#}").contains("os error 5") {
            anyhow::anyhow!(
                "служба CitadelPQVPN остановлена, а прав на её запуск у пользователя нет \
                 (установка не выдала SERVICE_START). Перезагрузите компьютер — служба стартует \
                 автоматически, либо переустановите приложение: {e:#}"
            )
        } else {
            e
        }
    })
}

/// Попросить службу завершиться (`TAG_QUIT` по пайпу) — зовётся при ВЫХОДЕ из приложения, чтобы
/// привилегированный `citadel-svc.exe` не оставался в процессах без клиента. Best-effort: службы
/// может уже не быть, а если идёт чужая сессия — serve-цикл занят и коннект не пройдёт (и не должен:
/// активный туннель этим не рвём). Ошибку зовущий вправе игнорировать — выход не блокируем.
pub fn service_request_quit() -> Result<()> {
    // Гасить нечего (не установлена / уже остановлена) → мгновенный выход БЕЗ ретраев ниже:
    // иначе каждый выход из приложения стоил бы пользователю лишних секунд ожидания.
    if !service_is_running()? {
        return Ok(());
    }
    // Не гасим службу, если поднять её обратно не сможем: без права SERVICE_START следующий запуск
    // приложения (без прав администратора) упрётся в «OpenService: Отказано в доступе» и туннель не
    // встанет вовсе. Лишний процесс в задачах — меньшее зло, чем неработающий VPN; сама служба
    // выдаёт это право себе на каждом старте, так что состояние временное.
    if !service_can_start() {
        eprintln!(
            "[win] служба citadel-svc оставлена работать: у пользователя нет права SERVICE_START, \
             обратно её было бы не поднять (переустановка/перезагрузка выдаст право)"
        );
        return Ok(());
    }
    // Служба всегда держит свободный слушающий инстанс, но могла как раз перезапускаться — короткий
    // ретрай внутри open (≤3с). Дольше не ждём: выход из приложения важнее гарантии остановки.
    let pipe = open_overlapped_pipe_within(PIPE_PATH, PIPE_QUIT_TIMEOUT)
        .map_err(anyhow::Error::new)
        .with_context(|| format!("служба citadel-svc недоступна ({PIPE_PATH})"))?;
    // W4-проверку владельца намеренно не делаем: кадр из одного байта без секретов, максимум
    // сквоттер его «съест» (служба тогда просто продолжит работать — не деградация безопасности).
    let io = OvIo::new().context("создать write-событие пайпа")?;
    io.write_all(pipe.0, &[winnet::TAG_QUIT]).context("отправить TAG_QUIT службе")?;
    Ok(())
}

/// Сколько ждать READY от службы. Внутри у неё: вытеснение прежней сессии (до 20с), создание
/// WinTUN-адаптера, `netsh`, WFP. Граница нужна, чтобы приложение не висело в «подключение»
/// бесконечно, если служба встанет: движок получит ошибку и уйдёт в обычный реконнект-backoff.
const READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Прочитать управляющий кадр READY от службы: `TAG_READY ‖ status ‖ u32(len) ‖ body`.
/// status==0 → body=CBOR(TunReady); ≠0 → body=UTF-8 причина (пробрасываем как ошибку).
fn read_ready(io: &OvIo, h: isize) -> Result<TunReady> {
    let mut hdr = [0u8; 6]; // TAG_READY(1) + status(1) + len(4, BE)
    io.read_exact_within(h, &mut hdr, Some(READY_TIMEOUT))
        .context("читать READY-заголовок от службы")?;
    if hdr[0] != winnet::TAG_READY {
        bail!("неожиданный тег ответа службы: 0x{:02x}", hdr[0]);
    }
    let status = hdr[1];
    let len = u32::from_be_bytes([hdr[2], hdr[3], hdr[4], hdr[5]]) as usize;
    if len > winnet::MAX_READY_BODY {
        bail!("READY-тело от службы слишком длинное: {len} > {}", winnet::MAX_READY_BODY);
    }
    let mut body = vec![0u8; len];
    io.read_exact_within(h, &mut body, Some(READY_TIMEOUT)).context("читать READY-тело")?;
    if status != 0 {
        bail!("служба отклонила поднятие адаптера: {}", String::from_utf8_lossy(&body));
    }
    winnet::decode_ready(&body)
}

/// Туннель поверх overlapped named pipe к службе. `read`/`write` — раздельные OVERLAPPED-контексты
/// (recv не блокирует send). На `Drop` пайп закрывается → служба ловит EOF; без предшествующего
/// маркера чистого disconnect (`clean_shutdown`) → WFP-kill-switch остаётся (fail-closed).
struct WindowsTun {
    pipe: PipeHandle,
    read: Mutex<OvIo>,
    write: Mutex<OvIo>,
    /// Флаг отмены: recv проверяет ПЕРЕД чтением — закрывает гонку «cancel до входа в ReadFile»
    /// (тогда CancelIoEx ничего не прерывает, но следующий recv увидит флаг и вернёт Err).
    cancelled: AtomicBool,
}

impl TunIo for WindowsTun {
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "recv отменён (disconnect)"));
        }
        let io = self.read.lock().unwrap();
        let h = self.pipe.0;
        let mut lenb = [0u8; 2];
        io.read_exact(h, &mut lenb)?;
        let len = u16::from_be_bytes(lenb) as usize;
        if len == 0 {
            return Ok(0); // служба закрывает поток данных
        }
        if len > buf.len() {
            // Кадр больше буфера recv — вычитываем его целиком, чтобы не рассинхронить поток, и
            // сигналим ошибку (штатно не бывает: пакеты ≤ MTU ≤ buf).
            let mut skip = vec![0u8; len];
            io.read_exact(h, &mut skip)?;
            return Err(io::Error::new(io::ErrorKind::InvalidData, "кадр пакета больше буфера recv"));
        }
        io.read_exact(h, &mut buf[..len])?;
        Ok(len)
    }

    fn send(&self, pkt: &[u8]) -> io::Result<usize> {
        if pkt.len() > winnet::MAX_PACKET {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "пакет больше MAX_PACKET"));
        }
        let frame = winnet::encode_packet(pkt);
        let io = self.write.lock().unwrap();
        io.write_all(self.pipe.0, &frame)?;
        Ok(pkt.len())
    }

    /// C6/M9: чистый disconnect → маркер `len==0` службе ПЕРЕД закрытием пайпа → она снимает
    /// WFP-kill-switch. Реконнект/краш этот метод не зовёт → служба видит EOF без маркера → KS держится.
    fn clean_shutdown(&self) {
        if let Ok(io) = self.write.lock() {
            let _ = io.write_all(self.pipe.0, &winnet::clean_disconnect_marker());
        }
    }

    /// Прервать блокирующий overlapped-ReadFile reader-потока (реконнект/disconnect). Сначала флаг
    /// (recv, ещё не вошедший в ReadFile, увидит его и выйдет), затем `CancelIoEx` (прерывает уже
    /// идущий overlapped-ReadFile → GetOverlappedResult вернёт ошибку). Вместе закрывают гонку →
    /// reader гарантированно получает Err и отпускает `Arc`. `CancelIoEx` с null отменяет ВСЕ
    /// операции на хэндле (в т.ч. send) — при disconnect это и нужно.
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        // SAFETY: pipe.0 — валидный HANDLE, живёт пока жив self; CancelIoEx безопасен из другого
        // потока и на handle без активного I/O (тогда просто вернёт FALSE — игнорируем).
        unsafe {
            CancelIoEx(self.pipe.0 as HANDLE, std::ptr::null());
        }
    }
}
