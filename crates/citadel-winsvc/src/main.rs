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

#[cfg(not(windows))]
fn main() {
    eprintln!("citadel-svc — служба только для Windows (WinTUN/WFP). На этой ОС не запускается.");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    windows_svc::run()
}

#[cfg(windows)]
mod windows_svc {
    use citadel_winnet::{
        decode_config, encode_ready_err, encode_ready_ok, TunReady, TunSetup, TAG_CONFIG,
    };
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
    use windows_sys::Win32::System::Pipes::{ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe};

    use crate::plan::{plan_session, SessionPlan, ADAPTER_NAME};

    // Win32-константы CreateNamedPipeW (ABI-стабильны; локально — чтобы не гадать модуль в windows-sys).
    const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
    const PIPE_TYPE_BYTE: u32 = 0x0000_0000;
    const PIPE_READMODE_BYTE: u32 = 0x0000_0000;
    const PIPE_WAIT: u32 = 0x0000_0000;
    const PIPE_UNLIMITED_INSTANCES: u32 = 255;

    const PIPE_NAME: &str = r"\\.\pipe\citadel-svc";
    /// Верхняя граница config-кадра (анти-DoS при чтении из пайпа).
    const MAX_CONFIG: usize = 64 * 1024;
    /// `ERROR_PIPE_CONNECTED` — клиент успел подключиться до `ConnectNamedPipe` (не ошибка).
    const ERROR_PIPE_CONNECTED: u32 = 535;

    /// UTF-16 нуль-терминированная строка для *W-API.
    fn wide(s: &str) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    /// Консольный dev-режим: слушать пайп и обслуживать сессии по одной. TODO(3c): регистрация как
    /// SCM-служба (`windows-service`) + запуск диспетчером вместо этого цикла.
    pub fn run() -> anyhow::Result<()> {
        eprintln!("[svc] citadel-svc: слушаю {PIPE_NAME} (dev-console; SCM — TODO 3c)");
        loop {
            let h = create_pipe_instance()?;
            // ждём подключения приложения
            let ok = unsafe { ConnectNamedPipe(h, std::ptr::null_mut()) };
            if ok == 0 {
                let e = unsafe { GetLastError() };
                if e != ERROR_PIPE_CONNECTED {
                    eprintln!("[svc] ConnectNamedPipe err={e}");
                    unsafe { CloseHandle(h) };
                    continue;
                }
            }
            handle_client(h);
            unsafe {
                DisconnectNamedPipe(h);
                CloseHandle(h);
            }
        }
    }

    /// Создать новый инстанс named pipe (полудуплекс байт-поток). TODO(3c): SECURITY_ATTRIBUTES —
    /// сузить ACL до SYSTEM+администраторов (сейчас дефолтный дескриптор).
    fn create_pipe_instance() -> anyhow::Result<HANDLE> {
        let name = wide(PIPE_NAME);
        // SAFETY: name — валидная нуль-терминированная UTF-16 строка; параметры по докам CreateNamedPipeW.
        let h = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                64 * 1024,
                64 * 1024,
                0,
                std::ptr::null(),
            )
        };
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
                pump(h, &session);
                teardown(session);
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

    /// Поднятая сессия (владеет адаптером/маршрутами/WFP). TODO(3b): реальные ресурсы WinTUN/WFP.
    struct Session {
        luid: u64,
    }

    /// TODO(3b): создать WinTUN-адаптер (крейт `wintun` + wintun.dll), применить `plan.netsh`
    /// (`Command::new("netsh")`), bypass-маршруты через физический шлюз (default-route lookup),
    /// WFP-фильтры из `plan.wfp` (windows-crate FWPM). Пока не реализовано → READY-err.
    fn bring_up(_plan: &SessionPlan) -> anyhow::Result<Session> {
        anyhow::bail!("TODO(3b): WinTUN-адаптер / маршруты / WFP ещё не реализованы")
    }

    /// TODO(3c): два потока — WinTUN.recv → `encode_packet` → пайп; пайп → `parse_stream` →
    /// WinTUN.send. Маркер `clean_disconnect` (len==0) → снять WFP (иначе держим — fail-closed).
    fn pump(_h: HANDLE, _s: &Session) {}

    /// TODO(3b): drop WinTUN-адаптера + откат маршрутов/DNS. WFP держим при аварийном разрыве.
    fn teardown(_s: Session) {}
}
