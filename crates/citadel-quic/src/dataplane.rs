//! CitadelPQVPN — data plane (L3): транспортная абстракция `Tunnel{Quic,Tcp}`,
//! обработка входящего трафика `Inbound` (egress-фильтр F2 + rate-limit F7) и
//! `pump` — двунаправленная перекачка TUN ⇄ транспорт.
//!
//! Вынесено из `bin/citadel-m1` (трек C0.2): движок работает поверх
//! `Arc<dyn TunIo>` (citadel-tun) и не знает конкретной платформы туннеля —
//! это и есть граница, через которую ОС отдаёт туннель в движок (Linux
//! `/dev/net/tun`, Android `VpnService` fd, …). См. docs/CLIENT-ARCH.md §3–4.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Result;
use citadel_masque::{datagram, ip};
use citadel_tun::TunIo;

use crate::ratelimit::{RateCfg, TokenBucket};

/// Транспорт туннеля: **всегда** PQ-QUIC (TLS 1.3 + гибридный KEX). Обычно поверх UDP; при
/// заблокированном UDP — поверх obfs-TCP (S0.3/H1), но крипта/control/data-plane идентичны.
/// `over_tcp` — только лейбл для логов (само соединение о транспорте под ним не знает).
pub struct Tunnel {
    conn: quinn::Connection,
    over_tcp: bool,
}

impl Tunnel {
    pub fn new(conn: quinn::Connection, over_tcp: bool) -> Self {
        Self { conn, over_tcp }
    }

    /// Доступ к QUIC-соединению (датаграммы/стримы) для вызывающих вне этого модуля.
    pub fn conn(&self) -> &quinn::Connection {
        &self.conn
    }

    pub fn peer(&self) -> SocketAddr {
        self.conn.remote_address()
    }

    /// S2.6/A3: TLS keying-material exporter (RFC 5705) соединения — channel-binding для ML-DSA
    /// подписи (M7). Уникален на TLS-сессию: relay-MITM держит ДВЕ разные сессии ⇒ значения на его
    /// плечах не совпадут, поэтому подпись сервера не пройдёт на клиенте. Оба конца ОДНОЙ сессии
    /// выводят одинаковые байты. Работает и над obfs-TCP (там тот же quinn+TLS).
    pub fn exporter(&self) -> Result<[u8; crate::pqauth::EXPORTER_LEN]> {
        let mut out = [0u8; crate::pqauth::EXPORTER_LEN];
        self.conn
            .export_keying_material(&mut out, crate::pqauth::EXPORTER_LABEL, b"")
            .map_err(|_| anyhow::anyhow!("TLS exporter (export_keying_material) недоступен"))?;
        Ok(out)
    }

    pub fn kind(&self) -> &'static str {
        if self.over_tcp {
            "QUIC/obfs-TCP"
        } else {
            "QUIC/UDP"
        }
    }

    pub fn close(&self, code: u32, reason: &[u8]) {
        self.conn.close(code.into(), reason);
    }

    /// Клиент: послать один control-запрос и получить ответ (reliable QUIC bi-stream).
    /// Лимит 8192 — ответ несёт ML-DSA-65 pub(1952)+sig(3309) для commitment-fetch (§S3) ⇒ ~5.3 КБ.
    pub async fn control_client(&mut self, req: &[u8]) -> Result<Vec<u8>> {
        let (mut send, mut recv) = self.conn.open_bi().await?;
        send.write_all(req).await?;
        send.finish()?;
        Ok(recv.read_to_end(8192).await?)
    }

    /// Сервер: принять один control-запрос, обработать `handle` и ответить.
    pub async fn control_server<F>(&mut self, handle: F) -> Result<()>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>>,
    {
        let (mut send, mut recv) = self.conn.accept_bi().await?;
        let req = recv.read_to_end(8192).await?;
        let resp = handle(&req)?;
        send.write_all(&resp).await?;
        send.finish()?;
        Ok(())
    }
}

/// Обработка входящего (от клиента) пакета на exit: анти-спуфинг + egress-фильтр (S0.2/F2) +
/// rate-limit (F7). `accept` → `true` пропустить в TUN, `false` дропнуть. Per-connection.
pub struct Inbound {
    /// `Some(назначенный клиенту адрес)` → exit-режим (анти-спуфинг+egress); `None` → клиент.
    egress: Option<[u8; 4]>,
    /// C7.2: `Some((admin_vip, admin_port))` → TCP к этому dst:port на exit'е пропускается мимо
    /// egress-фильтра (ядро DNAT'ит его на issuer, admin-плоскость по туннелю). Прочее — как раньше.
    admin_dst: Option<([u8; 4], u16)>,
    bucket: Option<TokenBucket>,
    dropped: u64,
    dropped_bytes: u64,
}

impl Inbound {
    pub fn new(egress: Option<[u8; 4]>, rate_limit: Option<RateCfg>) -> Self {
        Self::with_admin(egress, rate_limit, None)
    }

    /// Как [`Inbound::new`], но с точечным разрешением admin-VIP:порта (C7.2). Только exit-режим
    /// (`egress = Some`) его использует; на клиенте (`egress = None`) фильтр не активен вовсе.
    pub fn with_admin(
        egress: Option<[u8; 4]>,
        rate_limit: Option<RateCfg>,
        admin_dst: Option<([u8; 4], u16)>,
    ) -> Self {
        Self {
            egress,
            admin_dst,
            bucket: rate_limit.map(|c| TokenBucket::new(c, Instant::now())),
            dropped: 0,
            dropped_bytes: 0,
        }
    }

    pub fn accept(&mut self, pkt: &[u8]) -> bool {
        if let Some(expected_src) = self.egress {
            match ip::parse_ipv4(pkt) {
                Some(v) => {
                    // S0.2/H3: анти-спуфинг — inner-src обязан быть адресом, назначенным ЭТОМУ
                    // клиенту (легитимный стек ОС ставит src = адрес TUN). Иначе exit форвардил
                    // бы пакет со спуфнутым источником (DoS-reflection / подмена другого клиента).
                    if v.src != expected_src {
                        eprintln!(
                            "[exit] S0.2: дроп спуфинг inner-src {}.{}.{}.{} (ожидался {}.{}.{}.{})",
                            v.src[0], v.src[1], v.src[2], v.src[3],
                            expected_src[0], expected_src[1], expected_src[2], expected_src[3]
                        );
                        return false;
                    }
                    // C7.2: admin-плоскость — TCP к назначенному admin-VIP:порту разрешён мимо
                    // egress-фильтра (ядро DNAT'ит его на issuer). Анти-спуфинг src уже пройден,
                    // так что доступ имеет только легитимно подключённый клиент; сам доступ к
                    // управлению реестром отсекается admin-подписью на issuer (citadel-token::admin).
                    let is_admin = self.admin_dst.is_some_and(|(vip, port)| {
                        v.dst == vip && ip::tcp_dport(&v) == Some(port)
                    });
                    // F2: не форвардить во внутренние/служебные сети (metadata/RFC1918/loopback/…)
                    if !is_admin && ip::is_blocked_dst(v.dst) {
                        eprintln!(
                            "[exit] F2: заблокирован inner-dst {}.{}.{}.{}",
                            v.dst[0], v.dst[1], v.dst[2], v.dst[3]
                        );
                        return false;
                    }
                }
                None => {
                    // S0.2/H3: не-IPv4 (IPv6/мусор) is_blocked_dst не покрывает → default-deny
                    // (не fail-open). Туннель назначает только IPv4; v6 внутри пока не поддержан.
                    eprintln!("[exit] S0.2: дроп не-IPv4 inner-пакета (default-deny)");
                    return false;
                }
            }
        }
        if let Some(b) = self.bucket.as_mut() {
            if !b.allow(TokenBucket::packet_cost(pkt.len()), Instant::now()) {
                self.dropped += 1;
                self.dropped_bytes += pkt.len() as u64;
                if self.dropped == 1 || self.dropped.is_multiple_of(50) {
                    eprintln!(
                        "[exit] F7: rate-limit — дропнуто {} пакетов / {} б (клиент превысил лимит)",
                        self.dropped, self.dropped_bytes
                    );
                }
                return false;
            }
        }
        true
    }
}

/// Окно pump-watchdog и минимум отправленных датаграмм в окне, при котором «0 принятых»
/// трактуется как мёртвый путь. Окно > keep-alive-интервала (5с), чтобы здоровый простой и
/// одиночные потери не срабатывали; порог tx отсекает простой (мало шлём — путь не трогаем).
const WATCHDOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(8);
const WATCHDOG_TX_MIN: u64 = 12;

/// Решение watchdog по дельте счётчиков датаграмм за окно: путь считаем мёртвым, если за окно
/// отправлено ≥ порога, а принято 0 (шлём под нагрузкой, но обратно НИЧЕГО — MTU-чёрная-дыра или
/// NAT-rebind после смены сети; quinn idle-timeout это НЕ ловит, т.к. keep-alive проходит).
fn watchdog_trips(sent: u64, recvd: u64) -> bool {
    sent >= WATCHDOG_TX_MIN && recvd == 0
}

/// Двунаправленная перекачка TUN ⇄ транспорт (QUIC DATAGRAM либо obfs-TCP record).
/// `egress = Some(назначенный клиенту адрес)` включает egress-политику exit: анти-спуфинг
/// inner-src (S0.2/H3), default-deny не-IPv4 и F2 (дроп во внутренние/служебные сети); `None`
/// (клиент) — без фильтра. `rate_limit` (на exit) ограничивает входящее token-bucket'ом (F7/D3).
/// `admin_dst` (C7.2, только exit) — `Some((vip, port))` пропускает TCP к admin-VIP мимо F2
/// (ядро DNAT'ит на issuer); `None` — admin-плоскость по туннелю выключена.
///
/// TUN читается/пишется через `TunIo` — блокирующие recv/send изолированы в отдельных
/// потоках и мостятся в async каналами (платформа туннеля движку не важна).
pub async fn pump(
    tunnel: Tunnel,
    tun: Arc<dyn TunIo>,
    egress: Option<[u8; 4]>,
    rate_limit: Option<RateCfg>,
    admin_dst: Option<([u8; 4], u16)>,
    // Источник return-пакетов (TUN→сеть). На КЛИЕНТЕ — `None`: pump сам читает свой TUN. На EXIT —
    // `Some(rx)` из [`ExitTunRouter`]: единый reader общего exit-TUN демультиплексирует пакеты по
    // inner-dst нужному клиенту. Без этого N pump'ов на общем TUN воровали бы друг у друга return-
    // трафик (гонка multi-client → потеря/медленно/watchdog-шторм при >1 клиента).
    return_rx: Option<tokio::sync::mpsc::Receiver<Vec<u8>>>,
) -> Result<()> {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use tokio::sync::mpsc;
    let (net_to_tun_tx, mut net_to_tun_rx) = mpsc::channel::<Vec<u8>>(1024);

    // Watchdog-счётчики датаграмм: tx — успешно отправленных в транспорт, rx — принятых из него.
    // По дельте за окно (см. watchdog-задачу ниже) ловим односторонне мёртвый data-path, который
    // quinn idle-timeout не ловит (keep-alive проходит → соединение «живо», а датаграммы теряются).
    let tx_count = Arc::new(AtomicU64::new(0));
    let rx_count = Arc::new(AtomicU64::new(0));

    // Сигнал остановки reader-потока TUN. Ставится при отмене pump (disconnect: future
    // дропается → CancelGuard) ИЛИ при закрытии транспорта (receiver-задача). Без него
    // блокирующий reader зависал бы в recv, держа клон Arc<dyn TunIo> → TUN-fd не
    // закрывается (утечка реконнекта на клиенте + гонка multi-client на exit).
    let stop = Arc::new(AtomicBool::new(false));

    // TUN → сеть: КЛИЕНТ читает свой TUN сам (свой reader-поток); EXIT берёт return-пакеты из
    // демукса (return_rx), т.к. общий exit-TUN обслуживает всех клиентов — читать его должен ОДИН
    // reader (ExitTunRouter), иначе несколько pump'ов воруют пакеты друг у друга (multi-client гонка).
    let mut tun_to_net_rx = match return_rx {
        Some(rx) => rx,
        None => {
            let (tun_to_net_tx, rx) = mpsc::channel::<Vec<u8>>(1024);
            let tun = tun.clone();
            let stop = stop.clone();
            std::thread::spawn(move || tun_reader_loop(tun, stop, tun_to_net_tx));
            rx
        }
    };
    // сеть → TUN
    {
        let tun = tun.clone();
        std::thread::spawn(move || {
            while let Some(pkt) = net_to_tun_rx.blocking_recv() {
                let _ = tun.send(&pkt);
            }
        });
    }

    // Гард: при дропе future pump (отмена через select! в VpnController) ставит stop
    // (reader выйдет ≤ poll-таймаута) и аборт async-задач (освобождают conn и
    // net_to_tun_tx → writer-поток выходит) → все клоны Arc<dyn TunIo> отпускаются →
    // TUN закрывается, helper ловит EOF и сворачивает сеть.
    struct CancelGuard {
        stop: Arc<AtomicBool>,
        aborts: Vec<tokio::task::AbortHandle>,
        /// Клон TUN — чтобы прервать блокирующий reader-recv, не прерываемый через `raw_fd`-poll
        /// (Windows named pipe: `cancel` → CancelIoEx). На fd-туннелях `cancel` — no-op (будит poll).
        tun: Arc<dyn TunIo>,
    }
    impl Drop for CancelGuard {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::Release);
            // Прервать reader, висящий в блокирующем recv без раскрытия по stop-poll (Windows).
            self.tun.cancel();
            for a in &self.aborts {
                a.abort();
            }
        }
    }

    // S0.3/H1: единый транспорт — всегда quinn::Connection (поверх UDP или obfs-TCP). Раньше
    // здесь была вторая ветка «голого» obfs-TCP datagram-протокола; теперь TCP несёт тот же QUIC.
    let Tunnel { conn, .. } = tunnel;
    let send_conn = conn.clone();
    let send_tx = tx_count.clone();
    let sender = tokio::spawn(async move {
        while let Some(pkt) = tun_to_net_rx.recv().await {
            let dg = datagram::encode(datagram::CTX_RAW_IP, &pkt);
            match send_conn.send_datagram(bytes::Bytes::from(dg)) {
                Ok(()) => {
                    send_tx.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => eprintln!("[pump] датаграмма отброшена ({} б): {e}", pkt.len()),
            }
        }
    });
    let recv_conn = conn.clone();
    let recv_stop = stop.clone();
    let recv_rx = rx_count.clone();
    let receiver = tokio::spawn(async move {
        let mut inb = Inbound::with_admin(egress, rate_limit, admin_dst);
        loop {
            match recv_conn.read_datagram().await {
                Ok(dg) => {
                    // любой принятый датаграм = обратный путь жив (для watchdog); фильтр — дальше
                    recv_rx.fetch_add(1, Ordering::Relaxed);
                    if let Some((datagram::CTX_RAW_IP, pkt)) = datagram::decode(&dg) {
                        if inb.accept(pkt) && net_to_tun_tx.send(pkt.to_vec()).await.is_err() {
                            break;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[pump] соединение закрыто: {e}");
                    break;
                }
            }
        }
        // транспорт закрыт → разбудить reader, чтобы pump завершился (важно на exit, где future
        // pump ждётся до конца — иначе reader-поток зависал бы в recv на общем TUN).
        recv_stop.store(true, std::sync::atomic::Ordering::Release);
    });

    // pump-watchdog: если за окно отправили ≥ порога датаграмм, а приняли 0 — путь односторонне
    // мёртв (MTU-чёрная-дыра/NAT-rebind после смены сети): quinn idle-timeout молчит (keep-alive
    // проходит), read_datagram висел бы вечно → pump не завершается → реконнекта нет. Закрываем
    // conn → receiver ловит Err → pump выходит → цикл реконнекта (Android) / VpnController (desktop)
    // поднимает сессию над живым путём. На живом пути под нагрузкой rx растёт → не срабатывает;
    // на простое tx мал → не срабатывает.
    let wd_conn = conn.clone();
    let wd_tx = tx_count.clone();
    let wd_rx = rx_count.clone();
    let wd_stop = stop.clone();
    let watchdog = tokio::spawn(async move {
        let (mut seen_tx, mut seen_rx) = (0u64, 0u64);
        loop {
            tokio::time::sleep(WATCHDOG_INTERVAL).await;
            if wd_stop.load(Ordering::Acquire) {
                break;
            }
            let (tx, rx) = (wd_tx.load(Ordering::Relaxed), wd_rx.load(Ordering::Relaxed));
            let (sent, recvd) = (tx.wrapping_sub(seen_tx), rx.wrapping_sub(seen_rx));
            seen_tx = tx;
            seen_rx = rx;
            if watchdog_trips(sent, recvd) {
                eprintln!(
                    "[pump] watchdog: {sent} датаграмм отправлено, 0 принято за {}с — путь мёртв, рву транспорт",
                    WATCHDOG_INTERVAL.as_secs()
                );
                wd_conn.close(0u32.into(), b"citadel: data-path watchdog");
                break;
            }
        }
    });

    let _guard = CancelGuard {
        stop,
        aborts: vec![
            sender.abort_handle(),
            receiver.abort_handle(),
            watchdog.abort_handle(),
        ],
        tun: tun.clone(),
    };
    // pump живёт, пока жив ТРАНСПОРТ: ждём завершения receiver (закрытие conn watchdog'ом/peer'ом
    // или отмену). sender и watchdog оборвёт CancelGuard при выходе (drop _guard). Важно НЕ ждать
    // sender: на EXIT он читает return_rx из демукса, а tx там держится до unregister (ПОСЛЕ pump) —
    // при закрытии транспорта его некому закрыть, try_join завис бы и pump не снял бы регистрацию.
    let _ = receiver.await;
    Ok(())
}

/// EXIT: демультиплексор общего TUN. На сервере один TUN обслуживает ВСЕХ клиентов; читать его
/// должен ОДИН reader, иначе несколько pump'ов (по одному на клиента) наперегонки забирают пакеты
/// из общего fd и шлют их СВОЕМУ клиенту независимо от настоящего dst → return-трафик уходит не
/// туда (при >1 клиента: потеря, низкая скорость, ложные срабатывания data-path watchdog →
/// реконнект-шторм). Здесь единый reader парсит inner-dst IPv4 и кладёт пакет в канал ИМЕННО того
/// клиента (кому адрес назначен). Клиент регистрирует свой адрес на время сессии.
/// Таблица маршрутов демукса: назначенный клиенту адрес → канал его return-пакетов.
type ClientRoutes = Arc<Mutex<HashMap<[u8; 4], tokio::sync::mpsc::Sender<Vec<u8>>>>>;

#[derive(Clone)]
pub struct ExitTunRouter {
    routes: ClientRoutes,
}

impl ExitTunRouter {
    /// Создать роутер над общим exit-TUN и запустить единый reader-поток демукса.
    pub fn new(tun: Arc<dyn TunIo>) -> Self {
        let routes: ClientRoutes = Arc::new(Mutex::new(HashMap::new()));
        let r = routes.clone();
        std::thread::spawn(move || exit_tun_demux_loop(tun, r));
        Self { routes }
    }

    /// Зарегистрировать клиента (его назначенный адрес) → получить приёмник его return-пакетов
    /// для передачи в [`pump`] (аргумент `return_rx`). Повторная регистрация адреса вытесняет старую.
    pub fn register(&self, addr: [u8; 4]) -> tokio::sync::mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
        self.routes.lock().unwrap().insert(addr, tx);
        rx
    }

    /// Снять регистрацию клиента (сессия завершилась) — пакеты на его адрес больше не маршрутизируем.
    pub fn unregister(&self, addr: [u8; 4]) {
        self.routes.lock().unwrap().remove(&addr);
    }
}

/// Единый reader общего exit-TUN: читает return-пакет, парсит inner-dst IPv4 и кладёт его в канал
/// зарегистрированного клиента с этим адресом. `try_send` (не blocking): переполненный канал одного
/// (медленного) клиента НЕ должен стопорить весь демукс → его пакет дропается (как потеря UDP,
/// транспорт ретрансмитит). Нет маршрута (клиент отключился) / не-IPv4 → дроп.
fn exit_tun_demux_loop(tun: Arc<dyn TunIo>, routes: ClientRoutes) {
    let mut buf = vec![0u8; 65536];
    loop {
        match tun.recv(&mut buf) {
            Ok(n) if n > 0 => {
                route_packet(&routes, &buf[..n]);
            }
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break, // fd закрыт (exit завершается)
        }
    }
}

/// Маршрутный шаг демукса: по inner-dst IPv4 выбрать канал клиента и попытаться доставить (`try_send`
/// — не блокируем весь демукс на медленном клиенте). `false`, если пакет не-IPv4, нет маршрута
/// (клиент отключился) или канал полон/закрыт. Вынесено для юнит-теста.
fn route_packet(routes: &ClientRoutes, pkt: &[u8]) -> bool {
    let Some(v) = ip::parse_ipv4(pkt) else { return false };
    let Some(tx) = routes.lock().unwrap().get(&v.dst).cloned() else { return false };
    tx.try_send(pkt.to_vec()).is_ok()
}

/// Reader-петля TUN→сеть: прерываемое блокирующее чтение. На Unix — `poll` с коротким
/// таймаутом, чтобы периодически проверять `stop` (отмена pump / закрытие транспорта) и
/// выходить, освобождая `Arc<dyn TunIo>` — иначе поток завис бы в `recv`, удерживая TUN-fd
/// открытым (утечка интерфейса). Без fd (`raw_fd()==None`) — обычное блокирующее чтение
/// (прервётся по ошибке recv или закрытию канала-приёмника).
fn tun_reader_loop(
    tun: Arc<dyn TunIo>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
) {
    let mut buf = vec![0u8; 65536];

    #[cfg(unix)]
    if let Some(fd) = tun.raw_fd() {
        use std::sync::atomic::Ordering;
        // неблокирующий fd + poll(timeout): просыпаемся на пакет ИЛИ каждые 200мс на stop.
        // SAFETY: fd валиден, пока жив tun (держим Arc); fcntl/poll без side-effects на память.
        unsafe {
            let fl = libc::fcntl(fd, libc::F_GETFL);
            if fl >= 0 {
                libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
            }
        }
        let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        while !stop.load(Ordering::Acquire) {
            // SAFETY: &mut на один валидный pollfd; таймаут 200мс.
            let r = unsafe { libc::poll(&mut pfd, 1, 200) };
            if r < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            if r == 0 {
                continue; // таймаут → перепроверить stop
            }
            if pfd.revents & libc::POLLIN != 0 {
                match tun.recv(&mut buf) {
                    Ok(n) if n > 0 => {
                        if tx.blocking_send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => break,
                }
            }
            if pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                break; // fd закрыт/ошибка
            }
        }
        return;
    }

    // Windows/без-fd (named pipe, raw_fd()==None): reader выходит по Err из recv. Отмена на
    // реконнект/disconnect — через `TunIo::cancel` (CancelGuard зовёт его → WindowsTun делает
    // CancelIoEx + флаг), после чего recv возвращает Err и петля завершается. `stop` здесь не
    // опрашивается (нет poll-таймаута); раскрытие идёт через cancel/ошибку recv/закрытие канала.
    // Device-тест reconnect на Windows-боксе — за пользователем.
    #[cfg(not(unix))]
    let _ = &stop;

    // fallback: без fd — блокирующее чтение; прерывается Err из recv (в т.ч. по cancel) / закрытием канала.
    loop {
        match tun.recv(&mut buf) {
            Ok(n) if n > 0 => {
                if tx.blocking_send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_masque::ip;

    fn ipv4(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        ip::build_ipv4(17, src, dst, &[0u8; 4]) // UDP, тело неважно для фильтра
    }

    /// TCP-пакет src→dst с заданным dst-портом (мин. TCP-заголовок: src_port|dst_port|…).
    fn tcp(src: [u8; 4], dst: [u8; 4], dport: u16) -> Vec<u8> {
        let mut seg = vec![0u8; 20];
        seg[2..4].copy_from_slice(&dport.to_be_bytes()); // dst-порт
        ip::build_ipv4(6, src, dst, &seg)
    }

    /// EXIT-демукс: return-пакет уходит ИМЕННО клиенту с этим dst, а не «первому попавшемуся»
    /// pump'у (корень multi-client бага). Разные dst → разные каналы; неизвестный dst / не-IPv4 → дроп.
    #[test]
    fn exit_demux_routes_by_inner_dst() {
        let a = [10, 7, 0, 109];
        let b = [10, 7, 0, 110];
        let routes: ClientRoutes = Arc::new(Mutex::new(HashMap::new()));
        let (tx_a, mut rx_a) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        let (tx_b, mut rx_b) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        routes.lock().unwrap().insert(a, tx_a);
        routes.lock().unwrap().insert(b, tx_b);

        let pkt_to_a = ipv4([1, 1, 1, 1], a); // return-трафик клиенту A
        let pkt_to_b = ipv4([8, 8, 8, 8], b);
        let pkt_to_c = ipv4([1, 1, 1, 1], [10, 7, 0, 200]); // никто не зарегистрирован
        assert!(route_packet(&routes, &pkt_to_a));
        assert!(route_packet(&routes, &pkt_to_b));
        assert!(!route_packet(&routes, &pkt_to_c)); // нет маршрута → дроп
        assert!(!route_packet(&routes, &[0x60, 0, 0, 0])); // не-IPv4 → дроп

        // A получил ТОЛЬКО свой пакет (не B), и наоборот — трафик не перепутан
        assert_eq!(rx_a.try_recv().unwrap(), pkt_to_a);
        assert!(rx_a.try_recv().is_err());
        assert_eq!(rx_b.try_recv().unwrap(), pkt_to_b);
        assert!(rx_b.try_recv().is_err());
    }

    /// S0.2/H3: exit-режим (`Some(assigned)`) — пропускает только src==назначенный на публичный
    /// dst; дропает спуфнутый src, приватный dst (F2) и не-IPv4 (default-deny). Клиент (`None`) — без фильтра.
    #[test]
    fn inbound_antispoof_egress_and_ipv6_deny() {
        let assigned = [10, 7, 0, 5];
        let mut exit = Inbound::new(Some(assigned), None);
        assert!(exit.accept(&ipv4(assigned, [1, 1, 1, 1])), "легитимный src+публичный dst — пропуск");
        assert!(!exit.accept(&ipv4([9, 9, 9, 9], [1, 1, 1, 1])), "спуфнутый src — дроп");
        assert!(!exit.accept(&ipv4(assigned, [10, 0, 0, 1])), "приватный dst (F2) — дроп");
        assert!(!exit.accept(&[0x60, 0, 0, 0, 0, 0]), "IPv6 (версия 6) — default-deny");
        assert!(!exit.accept(&[0xff]), "мусор/обрезок — default-deny");

        // клиентский режим: фильтра нет — пропускаем даже «спуфнутый» и приватный
        let mut client = Inbound::new(None, None);
        assert!(client.accept(&ipv4([9, 9, 9, 9], [10, 0, 0, 1])));
    }

    /// C7.2: admin-VIP:порт (приватный dst, обычно дропнулся бы F2) пропускается ТОЛЬКО для TCP на
    /// точный порт и только с назначенного src; другой порт/протокол/VIP на том же приватном dst —
    /// дроп; спуфнутый src к admin-VIP — дроп (анти-спуфинг раньше исключения).
    #[test]
    fn inbound_admin_dst_exception() {
        let assigned = [10, 7, 0, 5];
        let vip = [10, 7, 0, 1];
        let mut exit = Inbound::with_admin(Some(assigned), None, Some((vip, 7001)));
        // TCP к admin-VIP:7001 с легитимным src — пропуск, хотя dst приватный
        assert!(exit.accept(&tcp(assigned, vip, 7001)), "admin TCP → VIP:порт пропущен мимо F2");
        // тот же VIP, другой порт — F2 дропает (не admin)
        assert!(!exit.accept(&tcp(assigned, vip, 22)), "другой порт на VIP — дроп");
        // UDP на VIP:7001 — не TCP, tcp_dport=None → F2 дропает
        assert!(!exit.accept(&ipv4(assigned, vip)), "UDP на VIP — дроп (только TCP-исключение)");
        // admin-порт, но другой приватный dst (не VIP) — дроп
        assert!(!exit.accept(&tcp(assigned, [10, 0, 0, 9], 7001)), "порт тот же, dst не VIP — дроп");
        // спуфнутый src к admin-VIP — дроп (анти-спуфинг срабатывает до исключения)
        assert!(!exit.accept(&tcp([9, 9, 9, 9], vip, 7001)), "спуфнутый src к VIP — дроп");
        // публичный dst по-прежнему проходит
        assert!(exit.accept(&tcp(assigned, [1, 1, 1, 1], 443)), "публичный dst — пропуск");

        // без admin_dst (None) VIP:7001 снова дропается (базовое поведение F2)
        let mut plain = Inbound::with_admin(Some(assigned), None, None);
        assert!(!plain.accept(&tcp(assigned, vip, 7001)), "нет admin-исключения → F2 дропает");
    }

    /// pump-watchdog: рвём путь только если под нагрузкой (tx ≥ порога) обратно 0 датаграмм.
    /// Хоть один принятый — путь жив; мало отправленных — это простой, не трогаем.
    #[test]
    fn watchdog_trips_only_on_dead_path_under_load() {
        assert!(watchdog_trips(WATCHDOG_TX_MIN, 0), "ровно порог tx, 0 принято — путь мёртв");
        assert!(watchdog_trips(WATCHDOG_TX_MIN + 500, 0), "много шлём, 0 принято — путь мёртв");
        assert!(!watchdog_trips(WATCHDOG_TX_MIN, 1), "хоть 1 принят — путь жив");
        assert!(!watchdog_trips(WATCHDOG_TX_MIN - 1, 0), "мало отправили (простой) — не трогаем");
        assert!(!watchdog_trips(0, 0), "полный простой — не трогаем");
    }
}
