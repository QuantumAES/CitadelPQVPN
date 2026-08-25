//! Защита исходящих сокетов движка от заворачивания в собственный туннель (анти-петля).
//!
//! На Android `VpnService` создаёт TUN, в который по умолчанию попадает ВЕСЬ трафик процесса —
//! включая исходящий трафик самого движка к exit'у и к издателю. Приложение-владелец VPN не
//! исключение: его собственные пакеты тоже уходят в его же туннель. Android даёт
//! `VpnService.protect(fd)` — пометить сокет «мимо туннеля». Движок зовёт [`protect_socket`]
//! на КАЖДЫЙ исходящий сокет **до** connect; платформа (Android, через FFI) один раз ставит
//! протектор глобально [`set_socket_protector`]. На desktop/сервере протектор не установлен →
//! всё здесь — no-op.
//!
//! **Инвариант (нарушение = петля):** каждый сокет движка к ПУБЛИЧНОМУ адресу (exit по UDP/QUIC,
//! exit по obfs-TCP, издатель Layer-1, диагностические пробы) обязан пройти через протектор.
//! Осознанных исключений два, и оба выражены типом [`Route`], а не умолчанием:
//!  * admin-плоскость (`citadel_token::admin`) ходит к ADMIN_VIP *внутри* туннеля — защищать её
//!    нельзя, иначе «Абоненты» перестанут работать;
//!  * фоновая дозаправка кошелька токенов при ПОДНЯТОМ туннеле (§7.1(в) аудита-4): она идёт
//!    сквозь туннель, чтобы издатель видел адрес exit'а, а не абонента. Перед establish и при
//!    опущенном туннеле — по-прежнему [`Route::Bypass`], иначе токен вообще не добыть.
//!
//! Почему «до connect», а не после: (а) с системным always-on VPN + «блокировать без VPN»
//! (lockdown) незащищённый сокет вообще не имеет права выйти — connect упадёт; (б) TCP выбирает
//! исходящий адрес и маршрут в момент connect, и защита постфактум оставляет соединение на старом
//! пути; (в) при поднятии туннеля система рвёт незащищённые сокеты процесса.

use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Сырой хэндл сокета для протектора: `RawFd` (Unix) / `RawSocket` (Windows). Абстрагирует
/// платформу, чтобы движок кроссился и под Windows (там протектор — no-op: анти-петлю к exit
/// держит WFP/маршрут-bypass, VpnService-аналога нет).
#[cfg(unix)]
pub type SocketHandle = std::os::fd::RawFd;
#[cfg(windows)]
pub type SocketHandle = std::os::windows::io::RawSocket;

/// Сырой хэндл любого сокета (UDP/TCP, std/tokio/socket2) для [`protect_socket`].
#[cfg(unix)]
pub fn handle_of<S: std::os::fd::AsRawFd>(s: &S) -> SocketHandle {
    s.as_raw_fd()
}
#[cfg(windows)]
pub fn handle_of<S: std::os::windows::io::AsRawSocket>(s: &S) -> SocketHandle {
    s.as_raw_socket()
}

/// Платформенный протектор сокета (Android: обёртка над `VpnService.protect`).
pub trait SocketProtector: Send + Sync {
    /// Исключить сокет из VPN-маршрутизации. Возвращает `true` при успехе.
    fn protect(&self, sock: SocketHandle) -> bool;
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

/// Установлен ли протектор (Android с живым `VpnService`). Нужен вызывающим, которые обязаны
/// СОЗНАТЕЛЬНО решить, идёт сокет мимо туннеля или сквозь него.
pub fn protector_active() -> bool {
    PROTECTOR.lock().unwrap().is_some()
}

/// Применить протектор к свежесозданному исходящему сокету. No-op, если не установлен (desktop).
/// Вызывать ДО connect/первой отправки — иначе первые пакеты уйдут в туннель (см. модульный док).
///
/// Возвращает `true`, только если сокет ДЕЙСТВИТЕЛЬНО защищён. `false` — либо протектора нет,
/// либо платформа отказала. Различать это обязан вызывающий: на desktop `false` штатен (анти-петлю
/// там держит bypass-маршрут), а на Android он означает, что транспорт сейчас уйдёт в собственный
/// туннель. Раньше функция ничего не возвращала, и отсутствие протектора было НЕОТЛИЧИМО от успеха —
/// из-за этого гонка «сервис ещё не зарегистрировался» выглядела в журнале как исправная работа.
pub fn protect_socket(sock: SocketHandle) -> bool {
    let Some(p) = PROTECTOR.lock().unwrap().as_ref().cloned() else {
        return false;
    };
    if !p.protect(sock) {
        eprintln!("[protect] VpnService.protect({sock}) вернул false — возможна маршрутная петля");
        return false;
    }
    true
}

/// Куда именно должен уйти сокет относительно СОБСТВЕННОГО туннеля.
///
/// До аудита-4/§7.1 выбора не было: всё, что не admin-плоскость, шло [`Route::Bypass`] — мимо
/// туннеля. Для транспорта к exit'у это единственный правильный ответ (иначе петля). Но обращение
/// к **издателю** — другой случай: пока туннель поднят, его выгодно пустить СКВОЗЬ туннель, тогда
/// издатель видит адрес exit'а, а не абонента (§7.1(в)). Поэтому маршрут стал явным параметром —
/// чтобы вызывающий выбирал его сознательно, а не наследовал по умолчанию.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Мимо туннеля (Android: `VpnService.protect`). Обязателен для транспорта к exit'у.
    Bypass,
    /// Сквозь собственный туннель: сокет НЕ защищаем. Осмысленно только при поднятом туннеле —
    /// иначе на Android с lockdown соединение просто не выпустят, а без lockdown оно уйдёт напрямую.
    Tunnel,
}

/// Применить решение о маршруте к свежесозданному сокету — и **сказать об этом в журнал**.
///
/// Одна точка на все транспорты движка (UDP/QUIC, obfs-TCP, канал издателя), потому что
/// диагностика здесь важнее самой строки `protect`: на Android «защищён» и «не защищён» дают
/// ОДИНАКОВО успешный хендшейк (туннеля в этот момент ещё нет) и расходятся только позже, когда
/// поднимается TUN. Пока сообщения не было, гонка «VpnService ещё не зарегистрировался» выглядела
/// в журнале как исправная работа, и разбор дважды уезжал в MTU/оператора.
///
/// `what` — короткое имя пути для журнала («QUIC/UDP», «obfs-TCP», «издатель»).
pub fn apply_route(sock: SocketHandle, route: Route, what: &str) {
    if route == Route::Tunnel {
        return; // сознательный отказ от защиты (admin-плоскость, дозаправка при поднятом туннеле)
    }
    let ok = protect_socket(sock);
    // Сообщение имеет смысл только там, где протектор вообще бывает: на desktop/сервере `false` —
    // норма (анти-петлю держит bypass-маршрут), и предупреждение было бы ложью.
    if cfg!(target_os = "android") {
        if ok {
            eprintln!("[protect] {what}: сокет исключён из туннеля ✔");
        } else {
            eprintln!(
                "[protect] ⚠ {what}: сокет НЕ защищён (VpnService не зарегистрирован либо protect() \
                 отказал) — как только поднимется TUN, транспорт замкнётся сам на себя"
            );
        }
    }
}

/// **P-1 (единственная фабрика).** Исходящий UDP-сокет движка: маршрут относительно собственного
/// туннеля выбирается ЗДЕСЬ — параметром, до первой отправки, — а не наследуется по умолчанию.
///
/// Зачем отдельная функция там, где раньше стоял `UdpSocket::bind` + строчка `protect_socket`
/// рядом: инвариант «сокет движка идёт мимо своего туннеля» ломался **дважды** (obfs-TCP
/// 2026-08-06, QUIC/UDP 2026-08-12 — строку потеряли при переносе `pacing` в параметр), и оба раза
/// поломка выглядела как «плохая сеть»: хендшейк проходит, данные встают при подъёме TUN. Пара
/// «bind + не забыть protect» — это дисциплина; функция, у которой маршрут в сигнатуре, —
/// конструкция. Прямые `UdpSocket::bind`/`TcpStream::connect` в движковых крейтах запрещены
/// линтом (`clippy.toml`, `disallowed-methods`), поэтому забыть маршрут больше нельзя: код с
/// голым `bind` не собирается под `-D warnings`.
///
/// Возврат — `std::net::UdpSocket` (не tokio): quinn принимает именно его, а `set_nonblocking`
/// и оборачивание в tokio делает вызывающий, когда ему нужно.
pub fn bind_udp_route(local: SocketAddr, route: Route) -> io::Result<UdpSocket> {
    // Та самая единственная точка bind в движке — ей исключение и полагается.
    #[allow(clippy::disallowed_methods)]
    let sock = UdpSocket::bind(local)?;
    // Локальный адрес в метке не косметика: по нему строка сходится с журналом миграции пути
    // («rebind сокета X → Y»), иначе при реконнекте непонятно, о каком из сокетов речь.
    // format! на каждый bind ничтожен — сокеты создаются считаные разы за сессию.
    let what = match sock.local_addr() {
        Ok(a) => format!("QUIC/UDP {a}"),
        Err(_) => "QUIC/UDP".to_string(),
    };
    apply_route(handle_of(&sock), route, &what);
    Ok(sock)
}

/// То же на эфемерном порту (`0.0.0.0:0`) — обычный случай клиентского транспорта и реконнекта.
pub fn bind_udp_ephemeral(route: Route) -> io::Result<UdpSocket> {
    bind_udp_route(SocketAddr::from(([0, 0, 0, 0], 0)), route)
}

/// Слушающий UDP-сокет сервера (exit). [`Route`] неприменим **по построению**, и это не поблажка:
/// сокет ничего не инициирует, а на серверной стороне VpnService-протектора нет вовсе. Отдельное
/// имя нужно, чтобы «серверный listen» не выглядел в коде как «исходящий сокет, которому забыли
/// маршрут» — и чтобы линт не приходилось глушить в чужом файле.
pub fn bind_udp_listen(local: SocketAddr) -> io::Result<UdpSocket> {
    #[allow(clippy::disallowed_methods)]
    let sock = UdpSocket::bind(local)?;
    Ok(sock)
}

/// Синхронный TCP-connect с защитой сокета ДО соединения и таймаутом.
///
/// Таймаут здесь не косметика: раньше на этом месте стоял голый `TcpStream::connect`, и
/// недоступный издатель подвешивал попытку реконнекта на минуты (стек ретраит SYN сам).
pub fn connect_tcp_timeout(addr: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    connect_tcp_route(addr, timeout, Route::Bypass)
}

/// То же, но с явным выбором маршрута ([`Route`]).
pub fn connect_tcp_route(addr: SocketAddr, timeout: Duration, route: Route) -> io::Result<TcpStream> {
    let sock = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    apply_route(handle_of(&sock), route, "TCP (издатель/транспорт)");
    sock.connect_timeout(&addr.into(), timeout)?;
    Ok(sock.into())
}

/// То же по `host:port`: резолвим и пробуем адреса по порядку (первый успешный — победил).
///
/// NB: сам резолв (getaddrinfo) мимо протектора не проходит — это системный вызов, а не наш
/// сокет. На Android с включённым lockdown при опущенном туннеле резолв может не пройти; поэтому
/// адреса издателя/exit'а в ссылке лучше держать литералами (ссылка их и несёт).
pub fn connect_tcp_str(target: &str, timeout: Duration) -> io::Result<TcpStream> {
    connect_tcp_str_route(target, timeout, Route::Bypass)
}

/// То же по `host:port` с явным маршрутом ([`Route`]).
pub fn connect_tcp_str_route(
    target: &str,
    timeout: Duration,
    route: Route,
) -> io::Result<TcpStream> {
    let mut last = None;
    for addr in target.to_socket_addrs()? {
        match connect_tcp_route(addr, timeout, route) {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "адрес не разрезолвился")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Протектор — процессный синглтон, поэтому тесты, которые его ставят и снимают, обязаны идти
    /// по одному (иначе один тест снимает протектор у другого и падение зависит от расписания).
    static SERIAL: Mutex<()> = Mutex::new(());
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|p| p.into_inner())
    }

    struct Counter(Arc<AtomicUsize>);
    impl SocketProtector for Counter {
        fn protect(&self, _sock: SocketHandle) -> bool {
            self.0.fetch_add(1, Ordering::SeqCst);
            true
        }
    }

    /// Запоминает хэндлы, которые видел протектор, — чтобы проверить, что защищали ИМЕННО тот
    /// сокет, который потом соединяется (а не какой-то временный).
    struct Peeker(Arc<Mutex<Vec<SocketHandle>>>);
    impl SocketProtector for Peeker {
        fn protect(&self, sock: SocketHandle) -> bool {
            self.0.lock().unwrap().push(sock);
            true
        }
    }

    #[test]
    fn noop_without_protector_then_invoked_after_set() {
        let _g = serial();
        clear_socket_protector();
        // Без протектора — no-op, не паникует, и ЧЕСТНО отвечает «не защищено»: на Android это
        // означает, что сервис ещё не зарегистрировался, и транспорт уйдёт в свой же туннель.
        assert!(!protect_socket(7), "нет протектора — сокет не защищён, и это должно быть видно");
        assert!(!protector_active());

        let n = Arc::new(AtomicUsize::new(0));
        set_socket_protector(Arc::new(Counter(n.clone())));
        assert!(protector_active());
        assert!(protect_socket(7));
        assert!(protect_socket(8));
        assert_eq!(n.load(Ordering::SeqCst), 2);

        clear_socket_protector();
        assert!(!protect_socket(9)); // снова no-op
        assert_eq!(n.load(Ordering::SeqCst), 2);
    }

    /// Гвоздь регрессии: TCP-путь (obfs-fallback, канал издателя) ДОЛЖЕН проходить через
    /// протектор — до этого он шёл голым `TcpStream::connect`, и на Android туннель заворачивал
    /// собственный транспорт в себя (пакеты с «чужим» src на exit'е → сессия умирала за секунды).
    #[test]
    fn tcp_connect_protects_before_connecting() {
        let _g = serial();
        use std::net::TcpListener;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let srv = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = srv.local_addr().unwrap();

        set_socket_protector(Arc::new(Peeker(seen.clone())));
        let s = connect_tcp_timeout(addr, Duration::from_secs(3)).unwrap();
        clear_socket_protector();

        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1, "протектор вызван ровно один раз");
        assert_eq!(seen[0], handle_of(&s), "защищали тот же сокет, который потом соединили");
        assert_eq!(s.peer_addr().unwrap(), addr, "соединение поднялось после защиты");
        drop(srv);
    }

    /// §7.1(в): `Route::Tunnel` — сознательный отказ от защиты. Сокет к издателю, поднятый при
    /// живом туннеле, обязан уйти В туннель (издатель тогда видит адрес exit'а, а не абонента),
    /// поэтому протектор на нём не вызывается ни разу — при том же установленном протекторе.
    #[test]
    fn tunnel_route_does_not_protect() {
        let _g = serial();
        use std::net::TcpListener;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let srv = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = srv.local_addr().unwrap();

        set_socket_protector(Arc::new(Peeker(seen.clone())));
        let s = connect_tcp_route(addr, Duration::from_secs(3), Route::Tunnel).unwrap();
        assert!(seen.lock().unwrap().is_empty(), "Route::Tunnel не должен звать протектор");
        assert_eq!(s.peer_addr().unwrap(), addr);
        // ...а Bypass на том же протекторе — должен (иначе тест ничего не доказывал бы).
        let _s2 = connect_tcp_route(addr, Duration::from_secs(3), Route::Bypass).unwrap();
        assert_eq!(seen.lock().unwrap().len(), 1);
        clear_socket_protector();
        drop(srv);
    }

    /// Сокет обязан вернуться в БЛОКИРУЮЩЕМ режиме: канал к издателю (PQ-TLS + кадры) читает
    /// синхронно, и «забытый» non-blocking после connect_timeout сломал бы выдачу токенов на всех
    /// платформах сразу — с диагнозом вида «издатель не прислал hello».
    #[test]
    fn connected_socket_stays_blocking() {
        let _g = serial();
        use std::io::{Read, Write};
        use std::net::TcpListener;
        clear_socket_protector();
        let srv = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = srv.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut c, _) = srv.accept().unwrap();
            std::thread::sleep(Duration::from_millis(120)); // читателю придётся ПОДОЖДАТЬ
            let _ = c.write_all(b"hi");
        });

        let mut s = connect_tcp_timeout(addr, Duration::from_secs(3)).unwrap();
        let mut buf = [0u8; 2];
        s.read_exact(&mut buf).expect("read обязан заблокироваться и дождаться, а не вернуть WouldBlock");
        assert_eq!(&buf, b"hi");
    }

    /// P-1: у UDP-фабрики маршрут — параметр, и оба его значения обязаны наблюдаться на
    /// протекторе. Проверяется в одном тесте, потому что доказательство здесь парное: «Bypass
    /// защитил» без «Tunnel не защитил» одинаково проходило бы и с безусловным `protect_socket`.
    #[test]
    fn udp_factory_routes_are_observable_on_protector() {
        let _g = serial();
        let seen = Arc::new(Mutex::new(Vec::new()));
        set_socket_protector(Arc::new(Peeker(seen.clone())));

        let bypass = bind_udp_ephemeral(Route::Bypass).unwrap();
        assert_eq!(seen.lock().unwrap().len(), 1, "Bypass обязан пройти через протектор");
        assert_eq!(seen.lock().unwrap()[0], handle_of(&bypass), "защищали ИМЕННО этот сокет");

        let tunnel = bind_udp_ephemeral(Route::Tunnel).unwrap();
        assert_eq!(seen.lock().unwrap().len(), 1, "Route::Tunnel не должен звать протектор");

        // Серверный listen — тоже мимо протектора, и это не «забыли», а отдельное имя в API.
        let srv = bind_udp_listen(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        assert_eq!(seen.lock().unwrap().len(), 1, "listen не проходит через протектор");

        clear_socket_protector();
        // Сокеты живые и разные: фабрика не подсунула один и тот же и не отдала полудохлый.
        for s in [&bypass, &tunnel, &srv] {
            assert!(s.local_addr().is_ok(), "сокет фабрики обязан быть привязан");
        }
    }

    #[test]
    fn tcp_connect_str_resolves_and_protects() {
        let _g = serial();
        use std::net::TcpListener;
        let n = Arc::new(AtomicUsize::new(0));
        let srv = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = format!("127.0.0.1:{}", srv.local_addr().unwrap().port());

        set_socket_protector(Arc::new(Counter(n.clone())));
        let s = connect_tcp_str(&target, Duration::from_secs(3)).unwrap();
        clear_socket_protector();

        assert!(n.load(Ordering::SeqCst) >= 1);
        assert!(s.peer_addr().is_ok());
    }
}
