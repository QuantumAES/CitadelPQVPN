//! Защита исходящих сокетов движка от заворачивания в собственный туннель (анти-петля).
//!
//! Сам реестр протектора живёт в крейте [`citadel_protect`] — им пользуется и `citadel-token`
//! (канал к издателю), который на `citadel-quic` зависеть не может (цикл). Здесь — реэкспорт
//! (чтобы `citadel_quic::protect::*` остался прежним адресом для FFI/приложения) плюс
//! асинхронный TCP-connect для транспортных путей движка.

pub use citadel_protect::{
    clear_socket_protector, connect_tcp_route, connect_tcp_str, connect_tcp_str_route,
    connect_tcp_timeout, handle_of, protect_socket, protector_active, set_socket_protector, Route,
    SocketHandle, SocketProtector,
};

/// Асинхронный TCP-connect с защитой сокета ДО соединения (Android) — obfs-TCP транспорт и
/// TCP-пробы диагностики.
///
/// Именно здесь была дыра: `TcpStream::connect` создаёт и соединяет сокет одним вызовом, вклиниться
/// с `protect()` некуда. `TcpSocket` даёт несоединённый сокет, который мы помечаем «мимо туннеля»,
/// и только потом соединяем — иначе на Android obfs-TCP сессия заворачивалась в собственный TUN
/// (её пакеты приходили на exit с «чужим» src и дропались анти-спуфингом → разрыв за секунды).
pub async fn connect_tcp(addr: std::net::SocketAddr) -> std::io::Result<tokio::net::TcpStream> {
    let sock = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    protect_socket(handle_of(&sock));
    sock.connect(addr).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct Peeker(Arc<Mutex<Vec<SocketHandle>>>);
    impl SocketProtector for Peeker {
        fn protect(&self, sock: SocketHandle) -> bool {
            self.0.lock().unwrap().push(sock);
            true
        }
    }

    /// Транспортный obfs-TCP сокет обязан быть защищён ДО connect — иначе на Android туннель
    /// заворачивает собственный транспорт в себя (сессия живёт секунды). Проверяем сам helper,
    /// через который ходят `quic_over_tcp_connect` и TCP-проба диагностики.
    #[tokio::test]
    async fn tcp_transport_socket_goes_through_protector() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let srv = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = srv.local_addr().unwrap();

        set_socket_protector(Arc::new(Peeker(seen.clone())));
        let s = connect_tcp(addr).await.unwrap();
        clear_socket_protector();

        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1, "протектор вызван ровно один раз");
        assert_eq!(seen[0], handle_of(&s), "защищали тот сокет, который соединили");
    }
}
