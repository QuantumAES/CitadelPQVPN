//! Защита исходящих сокетов движка от заворачивания в собственный туннель (анти-петля).
//!
//! Сам реестр протектора живёт в крейте [`citadel_protect`] — им пользуется и `citadel-token`
//! (канал к издателю), который на `citadel-quic` зависеть не может (цикл). Здесь — реэкспорт
//! (чтобы `citadel_quic::protect::*` остался прежним адресом для FFI/приложения) плюс
//! асинхронный TCP-connect для транспортных путей движка.

pub use citadel_protect::{
    apply_route, bind_udp_ephemeral, bind_udp_listen, bind_udp_route, clear_socket_protector,
    connect_tcp_route, connect_tcp_str, connect_tcp_str_route, connect_tcp_timeout, handle_of,
    protect_socket, protector_active, set_socket_protector, Route, SocketHandle, SocketProtector,
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
    apply_route(handle_of(&sock), Route::Bypass, "obfs-TCP");
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

    /// Транспортные сокеты движка обязаны проходить через протектор ДО соединения — иначе на
    /// Android туннель заворачивает собственный транспорт в себя.
    ///
    /// Проверяются ОБА транспорта в одном тесте намеренно: реестр протектора глобален на процесс,
    /// и два теста, ставящих его параллельно, мешали бы друг другу.
    ///
    /// UDP-половина — регрессионная. Строку `protect_socket` в `build_endpoint` однажды уже
    /// потеряли при рефакторинге (заход 7, перенос `pacing` в параметр), и на Android это дало
    /// самый неприятный вид поломки: хендшейк проходит (туннеля ещё нет), а данные после подъёма
    /// TUN встают намертво — наши же пакеты к exit'у уходят в наш же туннель. Симптом при этом
    /// выглядит как «сеть плохая», и разбор уезжает в MTU/оператора.
    #[tokio::test]
    async fn transport_sockets_go_through_protector() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let srv = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = srv.local_addr().unwrap();

        set_socket_protector(Arc::new(Peeker(seen.clone())));
        let s = connect_tcp(addr).await.unwrap();
        let tcp_seen = seen.lock().unwrap().clone();
        assert_eq!(tcp_seen.len(), 1, "obfs-TCP: протектор вызван ровно один раз");
        assert_eq!(tcp_seen[0], handle_of(&s), "защищали тот сокет, который соединили");

        // QUIC/UDP: и обфусцированный endpoint, и «голый» (token-less деплой) — оба обязаны
        // защитить свой сокет при создании.
        seen.lock().unwrap().clear();
        let obfs = crate::client_endpoint_obfs([7u8; 32], crate::Pacing::None).unwrap();
        assert_eq!(seen.lock().unwrap().len(), 1, "QUIC/UDP obfs: сокет не прошёл протектор");
        let plain = crate::client_endpoint_plain().unwrap();
        assert_eq!(seen.lock().unwrap().len(), 2, "QUIC/UDP без obfs: сокет не прошёл протектор");
        clear_socket_protector();
        drop((obfs, plain));
    }
}
