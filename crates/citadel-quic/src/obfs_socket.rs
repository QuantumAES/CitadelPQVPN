//! CitadelPQVPN — L1-обфускация как `AsyncUdpSocket` под QUIC (M3 + тайминг-шейпинг).
//!
//! Каждая исходящая UDP-датаграмма QUIC заворачивается `citadel_obfs::seal` (probe-resistance
//! и анти-DPI: на проводе — псевдослучайный поток, не QUIC); каждая входящая — `open`.
//! Пакеты без знания PSK не открываются и молча отбрасываются (квин их не видит) → F3/F5.
//!
//! Сессия — per-socket: свой случайный `sid` + монотонный счётчик packet_id.
//! Демультиплексирование соединений делает сам QUIC (по Connection ID внутри).
//!
//! **Тайминг-шейпинг (вторая ось I5, DAITA-стиль):** при `Pacing::Slotted` исходящие пакеты
//! не пишутся сразу, а буферизуются и выпускаются фоновым pacer'ом по слот-сетке; в пустые
//! слоты подмешивается chaff (`TYPE_PAD`), маскируя паузы/хвосты потока. Приёмник chaff дропает.
//! По умолчанию выключено (пейсинг торгует латентностью) — включается env `Citadel_PACING`.

use std::collections::VecDeque;
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use arc_swap::ArcSwap;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rand::RngCore;
use tokio::io::ReadBuf;

/// Потолок очереди отправки при пейсинге: переполнение → дроп пакета (= потеря UDP,
/// QUIC ретрансмитит). Защита от OOM (STRIDE D2), как у datagram-каналов.
const SEND_QUEUE_CAP: usize = 1024;

/// Политика тайминг-шейпинга исходящих пакетов (анти-корреляция по времени, вторая ось I5).
/// DAITA-стиль: выпуск по слот-сетке + adaptive chaff, а не constant-rate (тот убил бы throughput).
#[derive(Clone, Copy, Debug)]
pub enum Pacing {
    /// Выключено: синхронная отправка как есть (дефолт; пейсинг торгует латентностью).
    None,
    /// Пакеты выпускаются на тиках сетки `slot`; за тик — до `burst` реальных пакетов;
    /// в пустой слот подмешивается dummy по политике `chaff`.
    Slotted { slot: Duration, burst: usize, chaff: Chaff },
}

#[derive(Clone, Copy, Debug)]
pub enum Chaff {
    /// Без dummy-трафика — пейсинг только квантует тайминги реальных пакетов.
    Off,
    /// Dummy в пустой слот, только если реальный трафик был в пределах `window` (WTF-PAD-стиль):
    /// маскирует паузы/хвосты потока, не гоня вечный chaff в простаивающем туннеле.
    Adaptive { window: Duration },
    /// Dummy в каждый пустой слот (constant-rate; дороже по трафику, для high-threat).
    Always,
}

/// Чистое решение «слать ли chaff в этот пустой слот» — вынесено для детерминированных юнит-тестов.
fn chaff_decision(chaff: Chaff, had_real_traffic: bool, idle: Duration) -> bool {
    if !had_real_traffic {
        return false; // до первого реального пакета молчим (некуда и незачем)
    }
    match chaff {
        Chaff::Off => false,
        Chaff::Always => true,
        Chaff::Adaptive { window } => idle <= window,
    }
}

/// Разбор политики из строки: `off`(дефолт) | `on` | `<slot_ms>:<burst>:<off|adaptive|always>`.
/// Чистая функция (от `&str`) — тестируется без глобального env.
fn parse_pacing(raw: &str) -> Pacing {
    let default_window = Duration::from_millis(500);
    match raw.trim() {
        "" | "off" | "none" | "0" => Pacing::None,
        "on" => Pacing::Slotted {
            slot: Duration::from_millis(5),
            burst: 32,
            chaff: Chaff::Adaptive { window: default_window },
        },
        s => {
            let mut it = s.split(':');
            let slot_ms: u64 = it.next().and_then(|x| x.parse().ok()).unwrap_or(5);
            let burst: usize = it.next().and_then(|x| x.parse().ok()).unwrap_or(32);
            let chaff = match it.next().unwrap_or("adaptive") {
                "off" => Chaff::Off,
                "always" => Chaff::Always,
                _ => Chaff::Adaptive { window: default_window },
            };
            Pacing::Slotted {
                slot: Duration::from_millis(slot_ms.max(1)),
                burst: burst.max(1),
                chaff,
            }
        }
    }
}

fn pacing_from_env() -> Pacing {
    parse_pacing(&std::env::var("Citadel_PACING").unwrap_or_default())
}

/// C3/аудит-3: анти-реплей для obfs-приёма. Дубликат `nonce_pkt` (12 случайных байт, уникальных у
/// каждого легит-пакета) = реплей — молча дропаем (анти replay-probing: цензор реплеит перехваченный
/// пакет и смотрит, ответит ли сервер → фингерпринт). Двух-поколенное окно (~последних `[cap, 2·cap]`
/// nonce) — O(1) амортизированно, память ≤ 2·cap. QUIC-ретрансмит несёт НОВЫЙ nonce (свежий seal на
/// каждый пакет) → не режется; UDP-дубль сети режется (QUIC его всё равно бы отбросил).
const REPLAY_CAP: usize = 100_000;

struct ReplayGuard {
    cur: std::collections::HashSet<[u8; 12]>,
    prev: std::collections::HashSet<[u8; 12]>,
    cap: usize,
}

impl ReplayGuard {
    fn new(cap: usize) -> Self {
        Self {
            cur: std::collections::HashSet::new(),
            prev: std::collections::HashSet::new(),
            cap,
        }
    }

    /// `true` — nonce свежий (не реплей); `false` — видели недавно (реплей → дроп).
    fn check(&mut self, nonce: [u8; 12]) -> bool {
        if self.cur.contains(&nonce) || self.prev.contains(&nonce) {
            return false;
        }
        if self.cur.len() >= self.cap {
            self.prev = std::mem::take(&mut self.cur); // ротация поколения (сдвиг окна)
        }
        self.cur.insert(nonce);
        true
    }
}

pub struct ObfsUdpSocket {
    /// Внутренний UDP-сокет, атомарно сменяемый при миграции пути (rebind) — lock-free на hot path.
    inner: ArcSwap<tokio::net::UdpSocket>,
    /// Кешированный отправитель (k_hdr/k_sess/cipher деривятся раз на сессию, не на пакет — M6).
    sealer: citadel_obfs::Sealer,
    /// Кешированный приёмник (под Mutex, т.к. open берёт &mut для кеша cipher по sid).
    opener: Mutex<citadel_obfs::Opener>,
    /// C3: анти-реплей окно (по `nonce_pkt`) — дубликат = реплей, дропаем в `poll_recv`.
    replay: Mutex<ReplayGuard>,
    send_ctr: AtomicU64,
    /// Политика паддинга исходящих пакетов (анти-fingerprint по длине, I5-размер).
    padding: citadel_obfs::Padding,
    /// Политика тайминг-шейпинга (I5-тайминг). `None` → синхронная отправка.
    pacing: Pacing,
    /// Очередь отправки при пейсинге: сырой quic-payload + назначение (seal — в момент выпуска).
    queue: Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
    /// Последнее назначение реального пакета — куда слать chaff.
    last_dst: Mutex<Option<SocketAddr>>,
    /// Момент последней реальной отправки — для adaptive chaff (окно активности).
    last_real: Mutex<Instant>,
    /// Waker задачи poll_recv — при rebind будим её, чтобы перерегистрировалась на новом сокете.
    recv_waker: Mutex<Option<Waker>>,
}

impl fmt::Debug for ObfsUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObfsUdpSocket")
    }
}

impl ObfsUdpSocket {
    fn new(std_sock: std::net::UdpSocket, psk: [u8; 32], pacing: Pacing) -> io::Result<Self> {
        std_sock.set_nonblocking(true)?;
        let inner = tokio::net::UdpSocket::from_std(std_sock)?;
        let mut sid = [0u8; citadel_obfs::SID_LEN];
        rand::thread_rng().fill_bytes(&mut sid);
        Ok(Self {
            inner: ArcSwap::from_pointee(inner),
            sealer: citadel_obfs::Sealer::new(&psk, &sid),
            opener: Mutex::new(citadel_obfs::Opener::new(&psk)),
            replay: Mutex::new(ReplayGuard::new(REPLAY_CAP)), // C3: анти-реплей окно

            // M2-full (obfs v2): 16-байтный случайный sid — 128-битная per-session соль в k_sess
            // → per-session ключ уникален (коллизия 2^-128), body-AEAD nonce-reuse под общим PSK
            // закрыт by-construction. Старт packet_id со случайного u64 сохраняем (доп. запас).
            send_ctr: AtomicU64::new(rand::random()),
            padding: citadel_obfs::DEFAULT_RANDOM_PAD, // C2: случайный паддинг (анти-fingerprint длин)
            pacing,
            queue: Mutex::new(VecDeque::new()),
            last_dst: Mutex::new(None),
            last_real: Mutex::new(Instant::now()),
            recv_waker: Mutex::new(None),
        })
    }

    /// Миграция пути (M4): заменить исходящий UDP-сокет на новый (новый локальный порт/адрес).
    /// QUIC-соединение по Connection ID переживает смену src (как WiFi↔LTE / NAT-rebind): сервер
    /// видит пакеты с нового пути, валидирует его (PATH_CHALLENGE) и продолжает. obfs-keystream
    /// скоупится на сессию (sid/psk), не на путь — миграция совместима с обфускацией.
    fn rebind(&self) -> io::Result<()> {
        let std_sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
        // после миграции новый сокет тоже исключаем из туннеля (Android); desktop — no-op
        crate::protect::protect_socket(crate::protect::handle_of(&std_sock));
        std_sock.set_nonblocking(true)?;
        let new = tokio::net::UdpSocket::from_std(std_sock)?;
        let old = self.inner.load().local_addr().ok();
        let now = new.local_addr().ok();
        self.inner.store(Arc::new(new));
        // КЛЮЧЕВОЕ: разбудить poll_recv — она спит с waker'ом на СТАРОМ сокете; без этого
        // входящие с нового сокета никто не прочитает и миграция зависнет.
        if let Some(w) = self.recv_waker.lock().unwrap().take() {
            w.wake();
        }
        eprintln!("[obfs] rebind сокета {old:?} → {now:?} (миграция пути, M4)");
        Ok(())
    }

    /// Заворачивает реальную quic-нагрузку в DATA-пакет со случайным паддингом (C2).
    fn seal(&self, quic: &[u8]) -> Vec<u8> {
        let pid = self.send_ctr.fetch_add(1, Ordering::Relaxed);
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        // C2: случайный добор длины (анти-fingerprint). Содержимое padding — нули: оно внутри AEAD,
        // на проводе всё равно псевдослучайный шифртекст.
        let padding = vec![0u8; self.pad_len(quic.len())];
        let inner = citadel_obfs::build_inner(citadel_obfs::TYPE_DATA, None, None, &padding, quic);
        self.sealer.seal(pid, &nonce, &inner)
    }

    /// C2: длина паддинга DATA-пакета. `Random` → случайно (RNG здесь, чтобы `pad_len_random`
    /// оставалась pure/тестируемой); прочие политики — delegate в `pad_len_for`.
    fn pad_len(&self, quic_len: usize) -> usize {
        match self.padding {
            citadel_obfs::Padding::Random { floor, jitter, cap } => citadel_obfs::pad_len_random(
                floor,
                jitter,
                cap,
                quic_len,
                rand::thread_rng().next_u32() as usize,
            ),
            other => citadel_obfs::pad_len_for(other, quic_len),
        }
    }

    /// Chaff-пакет (`TYPE_PAD`): случайный размер на проводе в `[floor, cap]` (совпадает с
    /// распределением DATA при Random-паддинге, C2) → на проводе неотличим от реального трафика.
    fn seal_chaff(&self) -> Vec<u8> {
        let pid = self.send_ctr.fetch_add(1, Ordering::Relaxed);
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let (floor, cap) = match self.padding {
            citadel_obfs::Padding::Random { floor, cap, .. } => (floor, cap),
            _ => (256, citadel_obfs::WIRE_CAP), // не выше того, что мог бы отправить сам QUIC (MTU)
        };
        let wire = floor + (rand::thread_rng().next_u32() as usize) % (cap - floor + 1);
        let pad = wire.saturating_sub(citadel_obfs::FRAMING_OVERHEAD);
        let inner = citadel_obfs::build_chaff(&vec![0u8; pad]);
        self.sealer.seal(pid, &nonce, &inner)
    }

    /// Кладёт пакет в очередь пейсинга; при переполнении дропает (= потеря UDP, QUIC ретрансмитит).
    fn enqueue(&self, quic: &[u8], dst: SocketAddr) {
        let mut q = self.queue.lock().unwrap();
        if q.len() < SEND_QUEUE_CAP {
            q.push_back((quic.to_vec(), dst));
        }
    }

    /// Один тик pacer'а: слить из очереди до `burst` реальных пакетов; если очередь была пуста —
    /// при разрешении политикой подмешать один chaff на последнее назначение.
    fn pace_tick(&self) {
        let (burst, chaff) = match self.pacing {
            Pacing::Slotted { burst, chaff, .. } => (burst, chaff),
            Pacing::None => return,
        };
        let mut sent_real = 0usize;
        while sent_real < burst {
            let item = self.queue.lock().unwrap().pop_front();
            let Some((quic, dst)) = item else { break };
            let sealed = self.seal(&quic);
            let _ = self.inner.load().try_send_to(&sealed, dst);
            *self.last_dst.lock().unwrap() = Some(dst);
            *self.last_real.lock().unwrap() = Instant::now();
            sent_real += 1;
        }
        if sent_real == 0 {
            let dst = *self.last_dst.lock().unwrap();
            let idle = self.last_real.lock().unwrap().elapsed();
            if let Some(dst) = dst {
                if chaff_decision(chaff, true, idle) {
                    let sealed = self.seal_chaff();
                    let _ = self.inner.load().try_send_to(&sealed, dst);
                }
            }
        }
    }
}

/// Фоновый pacer: на тиках слот-сетки выпускает накопленные пакеты + chaff.
/// Держит `Weak` — когда endpoint (и его `Arc<ObfsUdpSocket>`) дропнут, задача сама завершается.
async fn pace_loop(weak: Weak<ObfsUdpSocket>) {
    let slot = match weak.upgrade().map(|s| s.pacing) {
        Some(Pacing::Slotted { slot, .. }) => slot,
        _ => return,
    };
    let mut iv = tokio::time::interval(slot);
    iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        iv.tick().await;
        match weak.upgrade() {
            Some(s) => s.pace_tick(),
            None => break, // сокет дропнут → выходим
        }
    }
}

#[derive(Debug)]
struct ObfsPoller(Arc<ObfsUdpSocket>);

impl UdpPoller for ObfsPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.0.inner.load().poll_send_ready(cx)
    }
}

impl AsyncUdpSocket for ObfsUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(ObfsPoller(self))
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // max_transmit_segments()==1 → transmit.contents — одна датаграмма
        match self.pacing {
            Pacing::None => {
                let sealed = self.seal(transmit.contents);
                self.inner.load().try_send_to(&sealed, transmit.destination).map(|_| ())
            }
            Pacing::Slotted { .. } => {
                // Буферизуем; фоновый pacer выпустит по слот-сетке. Переполнение → дроп (потеря UDP).
                self.enqueue(transmit.contents, transmit.destination);
                Ok(())
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut tmp = [0u8; 2048];
        loop {
            let mut rb = ReadBuf::new(&mut tmp);
            match self.inner.load().poll_recv_from(cx, &mut rb) {
                Poll::Ready(Ok(addr)) => {
                    let filled = rb.filled();
                    // C3: nonce_pkt (первые 12 байт, в клере) — ключ анти-реплея.
                    let nonce_pkt: Option<[u8; 12]> = filled.get(..12).map(|s| s.try_into().unwrap());
                    if let Ok(opened) = self.opener.lock().unwrap().open(filled) {
                        // C3: реплей валидного пакета (дубликат nonce) → молча дропаем (анти
                        // replay-probing: не даём серверу «ответить» на перехваченный и переигранный
                        // пакет). Проверяем ПОСЛЕ open — мусор/проба с чужим nonce не засоряет окно.
                        if let Some(np) = nonce_pkt {
                            if !self.replay.lock().unwrap().check(np) {
                                continue;
                            }
                        }
                        if let Some((t, quic)) = citadel_obfs::parse_inner(&opened.inner) {
                            if t == citadel_obfs::TYPE_PAD {
                                continue; // chaff (тайминг-шейпинг) — отбрасываем, не отдаём в QUIC
                            }
                            let n = quic.len().min(bufs[0].len());
                            bufs[0][..n].copy_from_slice(&quic[..n]);
                            meta[0] = RecvMeta {
                                addr,
                                len: n,
                                stride: n,
                                ecn: None,
                                dst_ip: None,
                            };
                            return Poll::Ready(Ok(1));
                        }
                    }
                    // не открылось (проба/мусор/чужой PSK) → дропаем, читаем следующий
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    // запомнить waker: при rebind разбудим эту задачу, чтобы она перечитала
                    // (перерегистрировалась) уже на НОВОМ сокете — иначе миграция зависнет.
                    *self.recv_waker.lock().unwrap() = Some(cx.waker().clone());
                    return Poll::Pending;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.load().local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        1
    }
    fn max_receive_segments(&self) -> usize {
        1
    }
    fn may_fragment(&self) -> bool {
        false
    }
}

fn build_endpoint(
    std_sock: std::net::UdpSocket,
    server_config: Option<quinn::ServerConfig>,
    psk: [u8; 32],
) -> Result<quinn::Endpoint> {
    // Android: исключить исходящий сокет движка из собственного туннеля (анти-петля).
    // На desktop/сервере протектор не установлен → no-op. Должно быть ДО connect.
    crate::protect::protect_socket(crate::protect::handle_of(&std_sock));
    let pacing = pacing_from_env();
    let sock = Arc::new(ObfsUdpSocket::new(std_sock, psk, pacing)?);
    // Pacer спавним только при включённом пейсинге; держит Weak → не мешает дропу сокета.
    if matches!(pacing, Pacing::Slotted { .. }) {
        tokio::spawn(pace_loop(Arc::downgrade(&sock)));
    }
    // Миграция пути (M4, демо/тест): через Citadel_MIGRATE_AFTER_MS мс сменить исходящий сокет —
    // эмулирует смену сети WiFi↔LTE / NAT-rebind. Туннель должен пережить (QUIC по Connection ID).
    if let Some(ms) = std::env::var("Citadel_MIGRATE_AFTER_MS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
    {
        let weak = Arc::downgrade(&sock);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(ms)).await;
            if let Some(s) = weak.upgrade() {
                if let Err(e) = s.rebind() {
                    eprintln!("[obfs] rebind не удался: {e}");
                }
            }
        });
    }
    let socket: Arc<dyn AsyncUdpSocket> = sock;
    let runtime = quinn::default_runtime().ok_or_else(|| anyhow!("нет async runtime (tokio)"))?;
    let ep = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        server_config,
        socket,
        runtime,
    )?;
    Ok(ep)
}

pub fn server_endpoint_obfs(
    listen: SocketAddr,
    server_config: quinn::ServerConfig,
    psk: [u8; 32],
) -> Result<quinn::Endpoint> {
    build_endpoint(std::net::UdpSocket::bind(listen)?, Some(server_config), psk)
}

pub fn client_endpoint_obfs(psk: [u8; 32]) -> Result<quinn::Endpoint> {
    build_endpoint(std::net::UdpSocket::bind("0.0.0.0:0")?, None, psk)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C3: анти-реплей — свежий nonce проходит, повтор режется; скользящее двух-поколенное окно.
    #[test]
    fn replay_guard_detects_and_windows() {
        let mut g = ReplayGuard::new(4); // маленькое окно для теста
        let n = |i: u8| [i; 12];
        assert!(g.check(n(1)), "свежий nonce проходит");
        assert!(!g.check(n(1)), "повтор режется");
        assert!(g.check(n(2)) && g.check(n(3)) && g.check(n(4)));
        // cur заполнен (1,2,3,4) → следующий (5) ротирует: prev={1..4}, cur={5}
        assert!(g.check(n(5)));
        assert!(!g.check(n(1)), "1 ещё в prev — режется");
        assert!(!g.check(n(5)), "5 в cur — режется");
        // добиваем cur (6,7,8) и ротируем на 9 → prev={5,6,7,8}; 1..4 выпадают из окна
        for i in 6..=9u8 {
            assert!(g.check(n(i)));
        }
        assert!(g.check(n(1)), "1 давно вне окна → снова свежий (скользящее окно — ок для probing)");
    }

    #[test]
    fn chaff_decision_table() {
        let w = Duration::from_millis(500);
        // нет реального трафика → никогда (даже Always)
        assert!(!chaff_decision(Chaff::Always, false, Duration::ZERO));
        assert!(!chaff_decision(Chaff::Adaptive { window: w }, false, Duration::ZERO));
        // Off → никогда
        assert!(!chaff_decision(Chaff::Off, true, Duration::ZERO));
        // Always → всегда (когда трафик был)
        assert!(chaff_decision(Chaff::Always, true, Duration::from_secs(10)));
        // Adaptive → в окне да, вне окна нет
        assert!(chaff_decision(Chaff::Adaptive { window: w }, true, Duration::from_millis(100)));
        assert!(!chaff_decision(Chaff::Adaptive { window: w }, true, Duration::from_millis(600)));
    }

    #[test]
    fn parse_pacing_cases() {
        assert!(matches!(parse_pacing(""), Pacing::None));
        assert!(matches!(parse_pacing("off"), Pacing::None));
        assert!(matches!(parse_pacing("on"), Pacing::Slotted { .. }));
        match parse_pacing("10:8:always") {
            Pacing::Slotted { slot, burst, chaff } => {
                assert_eq!(slot, Duration::from_millis(10));
                assert_eq!(burst, 8);
                assert!(matches!(chaff, Chaff::Always));
            }
            _ => panic!("ожидался Slotted"),
        }
        match parse_pacing("3:16:off") {
            Pacing::Slotted { chaff, .. } => assert!(matches!(chaff, Chaff::Off)),
            _ => panic!("ожидался Slotted"),
        }
        // мусорные/частичные значения → дефолты, не паника
        assert!(matches!(parse_pacing("xyz"), Pacing::Slotted { .. }));
    }

    /// Интеграционный: фоновый pacer на loopback реально выпускает очередь и подмешивает chaff.
    /// Покрывает async-путь (interval-дрейн, seal, отправка, приём, дроп TYPE_PAD), который
    /// нельзя проверить чистыми юнит-тестами и который недоступен локально через QUIC/туннель.
    #[tokio::test]
    async fn pacer_delivers_real_and_chaff_over_loopback() {
        let psk = [7u8; 32];
        let rx = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rx_addr = rx.local_addr().unwrap();

        let tx_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let pacing = Pacing::Slotted {
            slot: Duration::from_millis(5),
            burst: 8,
            chaff: Chaff::Always,
        };
        let sock = Arc::new(ObfsUdpSocket::new(tx_std, psk, pacing).unwrap());
        tokio::spawn(pace_loop(Arc::downgrade(&sock)));

        sock.enqueue(b"hello-quic", rx_addr);

        let mut got_real = false;
        let mut got_chaff = false;
        let mut buf = [0u8; 2048];
        for _ in 0..50 {
            match tokio::time::timeout(Duration::from_secs(1), rx.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    let opened = citadel_obfs::open(&psk, &buf[..n]).unwrap();
                    match citadel_obfs::parse_inner(&opened.inner) {
                        Some((citadel_obfs::TYPE_PAD, _)) => got_chaff = true,
                        Some((citadel_obfs::TYPE_DATA, q)) => {
                            assert_eq!(q, b"hello-quic");
                            got_real = true;
                        }
                        _ => {}
                    }
                    if got_real && got_chaff {
                        break;
                    }
                }
                _ => break, // таймаут/ошибка приёма
            }
        }
        assert!(got_real, "pacer не доставил реальный пакет");
        assert!(got_chaff, "pacer не сгенерировал chaff");
    }

    /// Миграция (M4): rebind атомарно меняет внутренний сокет на новый порт (механика ArcSwap).
    #[tokio::test]
    async fn rebind_swaps_socket_to_new_port() {
        let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let sock = ObfsUdpSocket::new(std_sock, [9u8; 32], Pacing::None).unwrap();
        let before = sock.inner.load().local_addr().unwrap();
        sock.rebind().unwrap();
        let after = sock.inner.load().local_addr().unwrap();
        assert_ne!(before.port(), after.port(), "rebind должен дать новый локальный порт");
    }
}
