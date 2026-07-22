//! `citadel-svc` — привилегированная Windows-служба CitadelPQVPN (модель W2).
//!
//! Аналог Linux-`citadel-helper`, но для Windows: владеет WinTUN-адаптером + WFP-kill-switch +
//! маршрутами/DNS и гоняет **packet-pump** ↔ неприв. приложение по **named pipe** `\\.\pipe\citadel-svc`.
//! Движок (QUIC/obfs) остаётся в приложении (`WindowsTunProvider`), как на Linux. Служба линкует
//! только `citadel-winnet` (кадры пайпа + WFP-план + маршруты), НЕ движок — меньше attack surface.
//!
//! Инкремент 3a (этот файл): named-pipe сервер + config-handshake (получить `TunSetup`, ответить
//! READY) + чистая оркестрация [`plan`]. WinTUN-адаптер, WFP, packet-pump — заглушки за `TODO(3b/3c)`.

#[cfg_attr(not(windows), allow(dead_code))]
mod plan;
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
    use std::sync::Arc;

    use citadel_winnet::{
        decode_config, encode_packet, encode_ready_err, encode_ready_ok, TunReady, TunSetup,
        TAG_CONFIG,
    };
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{define_windows_service, service_dispatcher};
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
    use windows_sys::Win32::System::Pipes::{ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe};
    use windows_sys::Win32::System::IO::CancelIoEx;

    use crate::plan::{bypass_route_add, bypass_route_del, plan_session, SessionPlan, ADAPTER_NAME};

    /// Имя службы в SCM.
    const SERVICE_NAME: &str = "CitadelPQVPN";
    /// Флаг остановки (ставит control-handler на Stop/Shutdown); serve-цикл его опрашивает.
    static SHUTDOWN: AtomicBool = AtomicBool::new(false);
    /// Текущий хэндл пайпа (для `cancel_accept` → CancelIoEx прерывает блокирующий accept/pump).
    static CURRENT_PIPE: AtomicIsize = AtomicIsize::new(0);

    /// HANDLE (`*mut c_void`) не `Send` — обёртка для передачи пайпа в поток WinTUN→пайп. Named pipe
    /// полнодуплексный: одновременные WriteFile (этот поток) и ReadFile (поток пайп→WinTUN) корректны.
    struct SendHandle(HANDLE);
    unsafe impl Send for SendHandle {}

    // Win32-константы CreateNamedPipeW (ABI-стабильны; локально — чтобы не гадать модуль в windows-sys).
    const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
    const PIPE_TYPE_BYTE: u32 = 0x0000_0000;
    const PIPE_READMODE_BYTE: u32 = 0x0000_0000;
    const PIPE_WAIT: u32 = 0x0000_0000;
    const PIPE_UNLIMITED_INSTANCES: u32 = 255;

    const PIPE_NAME: &str = r"\\.\pipe\citadel-svc";
    /// ACL пайпа (SDDL): SYSTEM/Builtin-Admins — полный доступ (GA); интерактивные пользователи (IU) —
    /// read+write (desktop-app коннектится под юзером). Сеть/аноним/сервисы — нет доступа. `P` —
    /// protected DACL (без наследования). Закрывает: любой локальный процесс поднимал бы туннель.
    const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";
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
        serve(&SHUTDOWN)
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
        // control-handler: Stop/Shutdown → флаг + прервать блокирующий accept/pump (CancelIoEx).
        let handler = move |control| -> ServiceControlHandlerResult {
            match control {
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    SHUTDOWN.store(true, Ordering::Release);
                    cancel_accept();
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
        let _ = serve(&SHUTDOWN);
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
        let service = manager.create_service(&info, ServiceAccess::CHANGE_CONFIG)?;
        service.set_description(
            "CitadelPQVPN — постквантовый VPN: WinTUN + WFP kill-switch (модель W2)",
        )?;
        // SCM-recovery: авто-рестарт при КРАШЕ (не чистом стопе) — смягчает окно fail-closed, если
        // служба упадёт с активным туннелем; после рестарта WFP переармируется на следующем connect.
        let restart = |secs| ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: Duration::from_secs(secs),
        };
        service.update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![restart(5), restart(5), restart(30)]),
        })?;
        eprintln!("[svc] служба '{SERVICE_NAME}' установлена (авто-рестарт при краше)");
        Ok(())
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

    /// serve-цикл: принимать клиентов по одному, пока не выставлен `shutdown`. Прерывается на Stop
    /// через `cancel_accept` (CancelIoEx на текущем пайпе разбудит блокирующий ConnectNamedPipe/pump).
    fn serve(shutdown: &AtomicBool) -> anyhow::Result<()> {
        eprintln!("[svc] слушаю {PIPE_NAME}");
        while !shutdown.load(Ordering::Acquire) {
            let h = create_pipe_instance()?;
            CURRENT_PIPE.store(h as isize, Ordering::Release);
            let ok = unsafe { ConnectNamedPipe(h, std::ptr::null_mut()) };
            if shutdown.load(Ordering::Acquire) {
                unsafe { CloseHandle(h) };
                break;
            }
            if ok == 0 {
                let e = unsafe { GetLastError() };
                if e != ERROR_PIPE_CONNECTED {
                    eprintln!("[svc] ConnectNamedPipe err={e}");
                    unsafe { CloseHandle(h) };
                    continue;
                }
            }
            handle_client(h);
            CURRENT_PIPE.store(0, Ordering::Release);
            unsafe {
                DisconnectNamedPipe(h);
                CloseHandle(h);
            }
        }
        eprintln!("[svc] serve остановлен");
        Ok(())
    }

    /// Прервать блокирующий ConnectNamedPipe/ReadFile на текущем пайпе (control-handler на Stop).
    fn cancel_accept() {
        let h = CURRENT_PIPE.load(Ordering::Acquire);
        if h != 0 {
            // SAFETY: h — текущий валидный хэндл пайпа; CancelIoEx безопасен из другого потока.
            unsafe { CancelIoEx(h as HANDLE, std::ptr::null()) };
        }
    }

    /// Создать новый инстанс named pipe (полудуплекс байт-поток). TODO(3c): SECURITY_ATTRIBUTES —
    /// сузить ACL до SYSTEM+администраторов (сейчас дефолтный дескриптор).
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
                PIPE_ACCESS_DUPLEX,
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

    /// Обслужить одного клиента: config-handshake → оркестрация → READY → (pump). При ошибке
    /// bring_up отвечаем READY-err (приложение покажет причину).
    fn handle_client(h: HANDLE) {
        let setup = match read_config(h) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[svc] чтение config: {e:#}");
                return;
            }
        };
        let plan = plan_session(&setup, ADAPTER_NAME);
        eprintln!(
            "[svc] сессия: {} netsh-команд, bypass={:?}, killswitch={}",
            plan.netsh.len(),
            plan.bypass,
            plan.wfp.is_some()
        );
        match bring_up(&plan) {
            Ok(session) => {
                let _ = write_all(h, &encode_ready_ok(&TunReady { adapter_luid: session.luid }));
                let clean = pump(h, &session);
                teardown(session, clean);
            }
            Err(e) => {
                eprintln!("[svc] bring_up: {e:#}");
                let _ = write_all(h, &encode_ready_err(&format!("{e:#}")));
            }
        }
    }

    /// Прочитать config-кадр: `TAG_CONFIG ‖ u32(len,BE) ‖ cbor(TunSetup)`.
    fn read_config(h: HANDLE) -> anyhow::Result<TunSetup> {
        let mut tag = [0u8; 1];
        read_exact(h, &mut tag)?;
        if tag[0] != TAG_CONFIG {
            anyhow::bail!("ожидался TAG_CONFIG, получен 0x{:02x}", tag[0]);
        }
        let mut lenb = [0u8; 4];
        read_exact(h, &mut lenb)?;
        let len = u32::from_be_bytes(lenb) as usize;
        if len > MAX_CONFIG {
            anyhow::bail!("config-кадр слишком большой: {len} > {MAX_CONFIG}");
        }
        let mut body = vec![0u8; len];
        read_exact(h, &mut body)?;
        decode_config(&body)
    }

    fn read_exact(h: HANDLE, buf: &mut [u8]) -> anyhow::Result<()> {
        let mut off = 0;
        while off < buf.len() {
            let mut read = 0u32;
            // SAFETY: h — валидный хэндл пайпа; буфер валиден на [off..].
            let ok = unsafe {
                ReadFile(
                    h,
                    buf[off..].as_mut_ptr(),
                    (buf.len() - off) as u32,
                    &mut read,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                anyhow::bail!("ReadFile err={}", unsafe { GetLastError() });
            }
            if read == 0 {
                anyhow::bail!("пайп закрыт (EOF) при чтении");
            }
            off += read as usize;
        }
        Ok(())
    }

    fn write_all(h: HANDLE, buf: &[u8]) -> anyhow::Result<()> {
        let mut off = 0;
        while off < buf.len() {
            let mut wrote = 0u32;
            // SAFETY: h — валидный хэндл пайпа; буфер валиден на [off..].
            let ok = unsafe {
                WriteFile(
                    h,
                    buf[off..].as_ptr(),
                    (buf.len() - off) as u32,
                    &mut wrote,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                anyhow::bail!("WriteFile err={}", unsafe { GetLastError() });
            }
            off += wrote as usize;
        }
        Ok(())
    }

    /// Поднятая сессия: владеет WinTUN-адаптером + пакетной сессией (в `Arc` — делится между потоками
    /// pump'а) + список применённых bypass-маршрутов (для отката). Порядок полей = порядок drop.
    struct Session {
        session: Arc<wintun::Session>,
        _adapter: Arc<wintun::Adapter>,
        luid: u64,
        /// Успешно добавленные bypass-назначения (`route add …`) — откатываются в teardown.
        bypass: Vec<String>,
    }

    /// Поднять туннель: WinTUN-адаптер → bypass-маршруты (мимо туннеля) → адрес/MTU/маршруты/DNS.
    /// TODO(3c-2): WFP kill-switch (`plan.wfp`).
    fn bring_up(plan: &SessionPlan) -> anyhow::Result<Session> {
        // Грузим wintun.dll (кладётся рядом со службой при упаковке). SAFETY: доверенная DLL WireGuard.
        let wintun =
            unsafe { wintun::load() }.map_err(|e| anyhow::anyhow!("загрузить wintun.dll: {e}"))?;
        let adapter = wintun::Adapter::create(&wintun, ADAPTER_NAME, ADAPTER_NAME, None)
            .map_err(|e| anyhow::anyhow!("создать WinTUN-адаптер '{ADAPTER_NAME}': {e}"))?;
        // get_luid() → NET_LUID_LH (union); .Value = u64-представление. SAFETY: чтение u64-поля union.
        let luid = unsafe { adapter.get_luid().Value };

        // Физический шлюз ДО подмены маршрутов туннелем — для bypass (анти-петля + Q5 split).
        let gw = default_gateway();
        // адрес/MTU/маршруты-в-туннель/DNS на адаптере (по имени ADAPTER_NAME)
        apply_netsh(&plan.netsh)?;
        // bypass: exit-IP + split-Exclude мимо туннеля через физический шлюз (host-route специфичнее /1)
        let bypass = apply_bypass(&plan.bypass, gw.as_deref());

        let session = Arc::new(
            adapter
                .start_session(wintun::MAX_RING_CAPACITY)
                .map_err(|e| anyhow::anyhow!("WinTUN start_session: {e}"))?,
        );

        // WFP kill-switch (fail-closed): блокируем не-туннельный трафик, кроме permit'ов плана.
        // Ошибка армирования = не поднимаем туннель без запрошенного KS (откат bypass перед выходом).
        if let Some(wfp_filters) = &plan.wfp {
            if let Err(e) = crate::wfp::arm(wfp_filters, luid) {
                for dest in &bypass {
                    let _ = std::process::Command::new("route").args(bypass_route_del(dest)).status();
                }
                return Err(anyhow::anyhow!("армировать WFP kill-switch: {e}"));
            }
            eprintln!("[svc] WFP kill-switch армирован ({} фильтров)", wfp_filters.len());
        }

        eprintln!("[svc] WinTUN '{ADAPTER_NAME}' поднят (luid={luid}); bypass={bypass:?}");
        Ok(Session { session, _adapter: adapter, luid, bypass })
    }

    /// Применить список netsh-команд (argv без ведущего `netsh`). Ошибка любой — прерывает bring_up.
    fn apply_netsh(cmds: &[Vec<String>]) -> anyhow::Result<()> {
        for c in cmds {
            let status = std::process::Command::new("netsh")
                .args(c)
                .status()
                .map_err(|e| anyhow::anyhow!("запустить netsh {c:?}: {e}"))?;
            if !status.success() {
                anyhow::bail!("netsh {c:?} → код {:?}", status.code());
            }
        }
        Ok(())
    }

    /// Физический default-gateway из `route print -4` (чистый парсер [`crate::plan::parse_default_gateway`]).
    fn default_gateway() -> Option<String> {
        let out = std::process::Command::new("route").args(["print", "-4"]).output().ok()?;
        crate::plan::parse_default_gateway(&String::from_utf8_lossy(&out.stdout))
    }

    /// Добавить bypass-маршруты (`route add <dst> mask <m> <gw>`). Возвращает УСПЕШНО добавленные
    /// (для отката). Без gw — предупреждаем (риск петли при full-tunnel), ничего не ставим.
    fn apply_bypass(dests: &[String], gw: Option<&str>) -> Vec<String> {
        let Some(gw) = gw else {
            if !dests.is_empty() {
                eprintln!("[svc] WARN: default-gw не найден — bypass не добавлен (риск петли)");
            }
            return Vec::new();
        };
        let mut done = Vec::new();
        for dest in dests {
            let ok = std::process::Command::new("route")
                .args(bypass_route_add(dest, gw))
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if ok {
                done.push(dest.clone());
            } else {
                eprintln!("[svc] route add {dest} via {gw} не удался");
            }
        }
        done
    }

    /// Packet-pump: два потока поверх одного пайпа (полнодуплекс). Возвращает `true`, если получен
    /// маркер чистого disconnect (len==0) — teardown снимет WFP; иначе (краш/реконнект) WFP держим.
    fn pump(pipe: HANDLE, s: &Session) -> bool {
        let stop = Arc::new(AtomicBool::new(false));
        let clean = Arc::new(AtomicBool::new(false));

        // Поток WinTUN → пайп: блокирующее чтение из адаптера, кадрирование, запись в пайп.
        let t1 = {
            let session = s.session.clone();
            let pipe = SendHandle(pipe);
            let stop = stop.clone();
            std::thread::spawn(move || {
                let pipe = pipe; // move обёртки в поток
                while !stop.load(Ordering::Relaxed) {
                    match session.receive_blocking() {
                        Ok(packet) => {
                            if write_all(pipe.0, &encode_packet(packet.bytes())).is_err() {
                                break; // пайп закрыт
                            }
                        }
                        Err(_) => break, // сессия закрыта (shutdown)
                    }
                }
                stop.store(true, Ordering::Relaxed);
            })
        };

        // Поток пайп → WinTUN (текущий): читаем кадры, отправляем в адаптер.
        while !stop.load(Ordering::Relaxed) {
            match read_frame(pipe) {
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
                Err(_) => break, // пайп закрыт/ошибка
            }
        }
        stop.store(true, Ordering::Relaxed);
        let _ = s.session.shutdown(); // разбудить receive_blocking в t1 (иначе висит без пакетов)
        let _ = t1.join();
        clean.load(Ordering::Relaxed)
    }

    /// Прочитать один кадр пакета из пайпа: `u16(len,BE) ‖ payload`. `len==0` → `Ok(None)` (чистый
    /// disconnect). EOF/ошибка → `Err`.
    fn read_frame(h: HANDLE) -> anyhow::Result<Option<Vec<u8>>> {
        let mut lenb = [0u8; 2];
        read_exact(h, &mut lenb)?;
        let len = u16::from_be_bytes(lenb) as usize;
        if len == 0 {
            return Ok(None);
        }
        let mut pkt = vec![0u8; len];
        read_exact(h, &mut pkt)?;
        Ok(Some(pkt))
    }

    /// Свернуть сессию: откат bypass-маршрутов + drop адаптера (маршруты/DNS `store=active` исчезают
    /// с ним). WFP kill-switch снимаем ТОЛЬКО при чистом disconnect (`clean`); при аварийном разрыве
    /// держим (fail-closed) — следующий `arm`/перезапуск службы его переармирует/снимет.
    fn teardown(s: Session, clean: bool) {
        for dest in &s.bypass {
            let _ = std::process::Command::new("route").args(bypass_route_del(dest)).status();
        }
        if clean {
            crate::wfp::disarm();
        } else {
            eprintln!("[svc] аварийный разрыв — WFP kill-switch ОСТАВЛЕН (fail-closed)");
        }
        // drop(s) закрывает WinTUN-сессию и адаптер.
    }
}
