//! Файловый лог службы `citadel-svc`. У Windows-службы, запущенной SCM, НЕТ консоли — весь
//! диагностический `eprintln!` (bring_up, netsh, WFP kill-switch, pump) уходит в никуда, и причину
//! сбоя туннеля не видно. Здесь мы ОДИН раз перенаправляем process-stderr в файл под `%ProgramData%`:
//! Rust-`std` перечитывает `STD_ERROR_HANDLE` через `GetStdHandle` на КАЖДЫЙ write, поэтому после
//! `SetStdHandle` все существующие `eprintln!` службы пишутся в файл БЕЗ правки call-site'ов.
//!
//! Только для SCM-пути (`run_service`). Dev-консоль (`--console`) НЕ трогаем — там stderr нужен в окне.
//! Дочерние `netsh`/`route` сюда не наследуются (handle не-inheritable) → их вывод ловим отдельно
//! (`apply_netsh` через `.output()`).

#[cfg(windows)]
pub fn redirect_stderr_to_file() {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Console::{SetStdHandle, STD_ERROR_HANDLE};

    let Some(path) = log_path() else { return };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // Примитивная ротация: если лог вырос > 4 MiB — обрезаем (объём логов сессии скромный).
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() > 4 * 1024 * 1024 {
            let _ = std::fs::write(&path, b"");
        }
    }
    let file = match std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        Ok(f) => f,
        Err(_) => return, // не удалось открыть — работаем без файла (stderr в никуда, как раньше)
    };
    // Handle должен жить весь процесс (SetStdHandle НЕ дублирует — хранит значение). Утечём File
    // намеренно, чтобы дескриптор не закрылся при drop.
    let file: &'static std::fs::File = Box::leak(Box::new(file));
    // SAFETY: raw handle валиден и живёт весь процесс (leak); STD_ERROR_HANDLE — стандартный id.
    unsafe {
        SetStdHandle(STD_ERROR_HANDLE, file.as_raw_handle() as _);
    }
    eprintln!("\r\n──────── citadel-svc: старт лога ({}) ────────", local_stamp());
}

/// `%ProgramData%\CitadelPQVPN\logs\citadel-svc.log` (служба = LocalSystem → ProgramData доступен).
#[cfg(windows)]
fn log_path() -> Option<std::path::PathBuf> {
    let base = std::env::var_os("ProgramData")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\ProgramData"));
    Some(base.join("CitadelPQVPN").join("logs").join("citadel-svc.log"))
}

/// Локальное время `YYYY-MM-DD HH:MM:SS` для баннера начала сессии (без внешних крейтов).
#[cfg(windows)]
fn local_stamp() -> String {
    use windows_sys::Win32::System::SystemInformation::GetLocalTime;
    // SAFETY: out-структура заполняется API целиком.
    let st = unsafe {
        let mut st = std::mem::zeroed();
        GetLocalTime(&mut st);
        st
    };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
    )
}
