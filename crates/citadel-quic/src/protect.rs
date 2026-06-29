//! Защита исходящих сокетов движка от заворачивания в собственный туннель (анти-петля).
//!
//! На Android `VpnService` создаёт TUN, в который по умолчанию попадает ВЕСЬ трафик процесса —
//! включая исходящий UDP/TCP самого движка к exit. Без исключения он зациклится (туннель-в-себя).
//! Android даёт `VpnService.protect(fd)` — пометить сокет «мимо туннеля». Движок зовёт
//! [`protect_socket`] сразу после bind каждого исходящего сокета (initial + rebind при миграции);
//! платформа (Android, через FFI) один раз ставит протектор глобально [`set_socket_protector`].
//! На desktop/сервере протектор не установлен → [`protect_socket`] — no-op.

use std::os::fd::RawFd;
use std::sync::{Arc, Mutex};

/// Платформенный протектор сокета (Android: обёртка над `VpnService.protect`).
pub trait SocketProtector: Send + Sync {
    /// Исключить сокет `fd` из VPN-маршрутизации. Возвращает `true` при успехе.
    fn protect(&self, fd: RawFd) -> bool;
}

static PROTECTOR: Mutex<Option<Arc<dyn SocketProtector>>> = Mutex::new(None);

/// Установить глобальный протектор (один раз при старте VPN на Android). Перезапись допустима.
pub fn set_socket_protector(p: Arc<dyn SocketProtector>) {
    *PROTECTOR.lock().unwrap() = Some(p);
}

/// Снять протектор (при остановке VPN-сервиса).
pub fn clear_socket_protector() {
    *PROTECTOR.lock().unwrap() = None;
}

/// Применить протектор к свежесозданному исходящему сокету. No-op, если не установлен (desktop).
/// Вызывать ДО connect/первой отправки — иначе первые пакеты уйдут в туннель.
pub fn protect_socket(fd: RawFd) {
    if let Some(p) = PROTECTOR.lock().unwrap().as_ref() {
        if !p.protect(fd) {
            eprintln!("[protect] VpnService.protect(fd={fd}) вернул false — возможна маршрутная петля");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Counter(Arc<AtomicUsize>);
    impl SocketProtector for Counter {
        fn protect(&self, _fd: RawFd) -> bool {
            self.0.fetch_add(1, Ordering::SeqCst);
            true
        }
    }

    #[test]
    fn noop_without_protector_then_invoked_after_set() {
        clear_socket_protector();
        protect_socket(7); // без протектора — просто no-op, не паникует

        let n = Arc::new(AtomicUsize::new(0));
        set_socket_protector(Arc::new(Counter(n.clone())));
        protect_socket(7);
        protect_socket(8);
        assert_eq!(n.load(Ordering::SeqCst), 2);

        clear_socket_protector();
        protect_socket(9); // снова no-op
        assert_eq!(n.load(Ordering::SeqCst), 2);
    }
}
