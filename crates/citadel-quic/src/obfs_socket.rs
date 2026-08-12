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

/// Потолок таблицы «адрес пира → каким ключом он говорит» (H-3). Записи вытесняются по LRU;
/// вытеснение легитимного пира стоит ему ровно одной лишней пробы ключа на следующем пакете,
/// поэтому потолок можно держать скромным и не бояться флуда с подменённых адресов.
const PEER_KEY_CAP: usize = 4096;

/// **H-3/аудит-4: чем сокет шифрует L1.**
///
/// `Fixed` — один PSK на всё время (клиент; token-less деплой; канал издателя). `Epoch` — ключ
/// выводится из мастер-секрета сервера на номер эпохи и меняется вместе с ней; принимающая сторона
/// держит **две** соседние эпохи (current и prev), потому что клиент мог получить ключ за секунду
/// до смены эпохи, а сессия живёт дольше.
#[derive(Clone, Copy, Debug)]
pub enum PskSource {
    Fixed([u8; 32]),
    /// Мастер-секрет сервера + длина эпохи (та же, что у токенов Layer-2).
    Epoch { master: [u8; 32], epoch_secs: u64 },
}

impl PskSource {
    /// Номер эпохи «сейчас» (для `Fixed` — константа 0: ключ не меняется никогда).
    fn epoch_now(&self) -> u64 {
        match self {
            PskSource::Fixed(_) => 0,
            PskSource::Epoch { epoch_secs, .. } => citadel_token::current_epoch(*epoch_secs),
        }
    }

    /// Эпохи, ключами которых принимаем СЕЙЧАС — свежайшая первой.
    fn accepted(&self, cur: u64) -> Vec<u64> {
        match self {
            PskSource::Fixed(_) => vec![0],
            PskSource::Epoch { .. } => vec![cur, cur.wrapping_sub(1)],
        }
    }

    /// H-3: ключи, которыми принимаем сейчас (для obfs-TCP, где кольцо не нужно — соединение
    /// фиксируется на подошедшем ключе с первого record'а).
    pub fn accepted_keys(&self) -> Vec<[u8; 32]> {
        let cur = self.epoch_now();
        self.accepted(cur).into_iter().map(|e| self.key_for(e)).collect()
    }

    fn key_for(&self, epoch: u64) -> [u8; 32] {
        match self {
            PskSource::Fixed(k) => *k,
            PskSource::Epoch { master, .. } => citadel_obfs::psk_epoch(master, epoch),
        }
    }
}

/// Сколько ключей эпох держим одновременно (анти-OOM: см. вытеснение в [`EpochCache::sweep`]).
const EPOCH_CACHE_CAP: usize = 32;
/// Сколько ключ прошлой эпохи живёт после последнего использования. Держать его дольше окна
/// «current ± prev» приходится намеренно: сессия, поднятая под ключом эпохи `e`, при дефолтной
/// часовой эпохе иначе умирала бы через 1–2 часа на ровном месте — а десктопные сессии живут
/// сутками. Пока по ключу идёт трафик, он не вытесняется; замолчал — уходит через это окно.
const EPOCH_KEY_IDLE: Duration = Duration::from_secs(180);

/// Кеш «эпоха → криптоматериал» с вытеснением по простою.
struct EpochCache<T> {
    items: Vec<(u64, T, Instant)>,
}

impl<T> EpochCache<T> {
    fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Материал для эпохи; отсутствующий создаётся `make` (BLAKE3-derive + key schedule).
    /// Возвращает индекс, а не ссылку: вызывающему обычно нужно ещё и «потрогать» запись.
    fn slot(&mut self, epoch: u64, make: impl FnOnce() -> T) -> usize {
        match self.items.iter().position(|(e, _, _)| *e == epoch) {
            Some(i) => i,
            None => {
                self.items.push((epoch, make(), Instant::now()));
                self.items.len() - 1
            }
        }
    }

    fn touch(&mut self, i: usize) {
        self.items[i].2 = Instant::now();
    }

    /// Убрать ключи вне окна `keep`, по которым давно нет трафика; при переполнении — самые
    /// давние независимо от активности (иначе абонент, собравший ключи многих эпох, мог бы
    /// заставить нас держать их все).
    fn sweep(&mut self, keep: &[u64]) {
        let now = Instant::now();
        self.items
            .retain(|(e, _, used)| keep.contains(e) || now.duration_since(*used) < EPOCH_KEY_IDLE);
        while self.items.len() > EPOCH_CACHE_CAP {
            let oldest = self
                .items
                .iter()
                .enumerate()
                .filter(|(_, (e, _, _))| !keep.contains(e))
                .min_by_key(|(_, (_, _, used))| *used)
                .map(|(i, _)| i);
            match oldest {
                Some(i) => {
                    self.items.remove(i);
                }
                None => break,
            }
        }
    }
}

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

/// M-8 (остаток): политика шейпинга для клиентского эндпоинта. `Some(профиль)` — настройка
/// пользователя (GUI-тумблер «маскировка таймингов» → `ClientConfig::pacing`); `None` — как
/// раньше, из `Citadel_PACING` (сервер, консольные роли, стенды).
pub fn pacing_profile(profile: Option<&str>) -> Pacing {
    match profile {
        Some(p) => parse_pacing(p),
        None => pacing_from_env(),
    }
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
    /// H-3: чем шифруем L1 — фиксированный PSK либо ключ эпохи из мастер-секрета сервера.
    psk: PskSource,
    /// Наш `sid` (общий для всех ключей: `k_sess` и так разный, т.к. разный PSK).
    sid: [u8; citadel_obfs::SID_LEN],
    /// Отправители по эпохам. `Arc` — чтобы AEAD считался ВНЕ замка: иначе на exit'е с многими
    /// клиентами отправка сериализовалась бы на одном мьютексе (было параллельно — стало бы нет).
    sealers: Mutex<EpochCache<Arc<citadel_obfs::Sealer>>>,
    /// Приёмники по эпохам (под Mutex: `open` берёт `&mut` ради кеша cipher по sid).
    openers: Mutex<EpochCache<citadel_obfs::Opener>>,
    /// Какой эпохой говорит пир: ответ обязан уйти тем же ключом, которым он к нам обратился.
    /// Промах (новый адрес, NAT-rebind, вытеснение) стоит одной лишней пробы ключа.
    peer_epoch: Mutex<std::collections::HashMap<SocketAddr, u64>>,
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
    fn new(std_sock: std::net::UdpSocket, psk: PskSource, pacing: Pacing) -> io::Result<Self> {
        std_sock.set_nonblocking(true)?;
        let inner = tokio::net::UdpSocket::from_std(std_sock)?;
        let mut sid = [0u8; citadel_obfs::SID_LEN];
        rand::thread_rng().fill_bytes(&mut sid);
        Ok(Self {
            inner: ArcSwap::from_pointee(inner),
            psk,
            sid,
            sealers: Mutex::new(EpochCache::new()),
            openers: Mutex::new(EpochCache::new()),
            peer_epoch: Mutex::new(std::collections::HashMap::new()),
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

    /// H-3: отправитель для пира — тем ключом, которым он с нами говорит. Неизвестный пир (мы
    /// инициатор либо адрес ещё не привязан) → ключ текущей эпохи. Замок держится только на
    /// поиск/создание, сам AEAD считается снаружи.
    fn sealer_for(&self, dst: SocketAddr) -> Arc<citadel_obfs::Sealer> {
        let cur = self.psk.epoch_now();
        let epoch = self.peer_epoch.lock().unwrap().get(&dst).copied().unwrap_or(cur);
        let mut cache = self.sealers.lock().unwrap();
        let i = cache.slot(epoch, || {
            Arc::new(citadel_obfs::Sealer::new(&self.psk.key_for(epoch), &self.sid))
        });
        cache.touch(i);
        let s = cache.items[i].1.clone();
        cache.sweep(&self.psk.accepted(cur));
        s
    }

    /// Заворачивает реальную quic-нагрузку в DATA-пакет со случайным паддингом (C2).
    fn seal(&self, quic: &[u8], dst: SocketAddr) -> Vec<u8> {
        let pid = self.send_ctr.fetch_add(1, Ordering::Relaxed);
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        // C2: случайный добор длины (анти-fingerprint). Содержимое padding — нули: оно внутри AEAD,
        // на проводе всё равно псевдослучайный шифртекст.
        let padding = vec![0u8; self.pad_len(quic.len())];
        let inner = citadel_obfs::build_inner(citadel_obfs::TYPE_DATA, None, None, &padding, quic);
        self.sealer_for(dst).seal(pid, &nonce, &inner)
    }

    /// H-3: попытка открыть пакет ключами принимаемых эпох (свежайшая первой) плюс теми, по
    /// которым ещё идёт трафик. Успех запоминает эпоху пира — ответ уйдёт тем же ключом.
    fn open_any(&self, addr: SocketAddr, packet: &[u8]) -> Option<citadel_obfs::Opened> {
        let cur = self.psk.epoch_now();
        let accepted = self.psk.accepted(cur);
        let mut cache = self.openers.lock().unwrap();
        for &e in &accepted {
            cache.slot(e, || citadel_obfs::Opener::new(&self.psk.key_for(e)));
        }
        // Порядок проб: сначала эпоха, которой этот пир говорил в прошлый раз (обычный случай —
        // одна проба), затем остальные от свежей к старой.
        let known = self.peer_epoch.lock().unwrap().get(&addr).copied();
        let mut order: Vec<u64> = cache.items.iter().map(|(e, _, _)| *e).collect();
        order.sort_unstable_by(|a, b| b.cmp(a));
        if let Some(k) = known {
            order.retain(|e| *e != k);
            order.insert(0, k);
        }
        for e in order {
            let Some(i) = cache.items.iter().position(|(x, _, _)| *x == e) else { continue };
            if let Ok(opened) = cache.items[i].1.open(packet) {
                cache.touch(i);
                cache.sweep(&accepted);
                drop(cache);
                if known != Some(e) {
                    let mut peers = self.peer_epoch.lock().unwrap();
                    // Анти-OOM: таблица адресов не растёт бесконечно от флуда с подменённых src.
                    if peers.len() >= PEER_KEY_CAP {
                        peers.clear();
                    }
                    peers.insert(addr, e);
                }
                return Some(opened);
            }
        }
        cache.sweep(&accepted);
        None
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
    fn seal_chaff(&self, dst: SocketAddr) -> Vec<u8> {
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
        self.sealer_for(dst).seal(pid, &nonce, &inner)
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
            let sealed = self.seal(&quic, dst);
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
                    let sealed = self.seal_chaff(dst);
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
                let sealed = self.seal(transmit.contents, transmit.destination);
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
                    if let Some(opened) = self.open_any(addr, filled) {
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
    psk: PskSource,
    pacing: Pacing,
) -> Result<quinn::Endpoint> {
    // Android: исключить исходящий сокет движка из собственного туннеля (анти-петля).
    // На desktop/сервере протектор не установлен → no-op. Должно быть ДО connect.
    //
    // Без этой строки хендшейк проходит (он идёт ДО `VpnService.Builder.establish`, туннеля ещё
    // нет), а в момент подъёма TUN с маршрутом по умолчанию наши же UDP-пакеты к exit'у уходят
    // В СОБСТВЕННЫЙ туннель: данные встают намертво, ACK'и не возвращаются, cwnd не открывается —
    // «на провод ушло 2 из 113, потерь 0». Ровно это и наблюдалось на Android (см. регрессию из
    // захода 7, где строку потеряли при переносе `pacing` в параметр). Тест
    // `udp_transport_socket_goes_through_protector` держит инвариант.
    crate::protect::protect_socket(crate::protect::handle_of(&std_sock));
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

/// EXIT: слушающий endpoint под obfs. `psk` — [`PskSource::Epoch`] при включённой ротации (H-3)
/// либо [`PskSource::Fixed`] в token-less деплое, где раздавать ключ эпохи некому.
pub fn server_endpoint_obfs(
    listen: SocketAddr,
    server_config: quinn::ServerConfig,
    psk: PskSource,
) -> Result<quinn::Endpoint> {
    // Сервер шейпит по своему `Citadel_PACING`: клиентский тумблер маскирует только ОТПРАВКУ
    // абонента, ответное направление — забота оператора exit'а (M-8, §17.2).
    build_endpoint(std::net::UdpSocket::bind(listen)?, Some(server_config), psk, pacing_from_env())
}

/// КЛИЕНТ: ключ всегда один — тот, что он получил у издателя на текущую эпоху (или бутстрапный
/// в token-less деплое). Перебирать эпохи клиенту незачем: он знает, чем говорит.
pub fn client_endpoint_obfs(psk: [u8; 32], pacing: Pacing) -> Result<quinn::Endpoint> {
    build_endpoint(std::net::UdpSocket::bind("0.0.0.0:0")?, None, PskSource::Fixed(psk), pacing)
}

/// КЛИЕНТ без obfs (token-less деплой/проба, где транспортного PSK нет): обычный QUIC-endpoint,
/// но с той же защитой сокета от заворачивания в собственный туннель, что и у obfs-пути.
///
/// Своя функция нужна ровно из-за этого: `quinn::Endpoint::client` создаёт UDP-сокет ВНУТРИ себя,
/// и вклиниться между `bind` и `connect` с `protect()` там негде — на Android такой endpoint
/// работал бы только до подъёма TUN (та же беда, что описана в [`build_endpoint`]).
pub fn client_endpoint_plain() -> Result<quinn::Endpoint> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
    crate::protect::protect_socket(crate::protect::handle_of(&sock));
    let runtime = quinn::default_runtime().ok_or_else(|| anyhow!("нет async runtime (tokio)"))?;
    Ok(quinn::Endpoint::new(quinn::EndpointConfig::default(), None, sock, runtime)?)
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

    /// M-8: явный профиль клиента (GUI-тумблер) обязан побеждать env — иначе тумблер «маскировка
    /// таймингов» ничего не значил бы на машине, где оператор когда-то выставил `Citadel_PACING`.
    #[test]
    fn explicit_profile_wins_over_env() {
        assert!(matches!(pacing_profile(Some("off")), Pacing::None));
        match pacing_profile(Some("on")) {
            Pacing::Slotted { burst, .. } => assert_eq!(burst, 32),
            Pacing::None => panic!("явный профиль `on` обязан включать шейпинг"),
        }
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
        let sock = Arc::new(ObfsUdpSocket::new(tx_std, PskSource::Fixed(psk), pacing).unwrap());
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

    /// **H-3, главное свойство:** exit принимает ТОЛЬКО ключи эпохи (текущей и прошлой), а
    /// бутстрапный PSK из ссылки канал данных больше не открывает. Именно поэтому утёкшая ссылка
    /// перестаёт быть бессрочным пропуском в L1 и классификатором трафика деплоя.
    #[tokio::test]
    async fn epoch_ring_takes_current_and_prev_but_not_the_link_psk() {
        let master = [0x5cu8; 32];
        let epoch_secs = 3600;
        let link_psk = [0xAAu8; 32]; // «тот самый» PSK из citadel:// — к мастеру отношения не имеет
        let sock = ObfsUdpSocket::new(
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
            PskSource::Epoch { master, epoch_secs },
            Pacing::None,
        )
        .unwrap();
        let cur = citadel_token::current_epoch(epoch_secs);
        let peer: SocketAddr = "127.0.0.1:40000".parse().unwrap();

        let pkt = |psk: [u8; 32]| {
            let inner = citadel_obfs::build_inner(citadel_obfs::TYPE_DATA, None, None, &[], b"quic");
            let mut sid = [0u8; citadel_obfs::SID_LEN];
            sid[0] = 1;
            citadel_obfs::seal(&psk, &sid, 1, &[9u8; 12], &inner)
        };

        // ключ текущей эпохи — открывается
        assert!(sock.open_any(peer, &pkt(citadel_obfs::psk_epoch(&master, cur))).is_some());
        // ключ прошлой эпохи — тоже (grace: клиент взял его за секунду до смены эпохи)
        let prev_peer: SocketAddr = "127.0.0.1:40001".parse().unwrap();
        assert!(sock
            .open_any(prev_peer, &pkt(citadel_obfs::psk_epoch(&master, cur - 1)))
            .is_some());
        // позапрошлая — уже нет (иначе «ротация» ничего не отзывала бы)
        let old_peer: SocketAddr = "127.0.0.1:40002".parse().unwrap();
        assert!(sock.open_any(old_peer, &pkt(citadel_obfs::psk_epoch(&master, cur - 2))).is_none());
        // и, главное, PSK из ссылки не открывает канал данных ВООБЩЕ
        assert!(sock.open_any(old_peer, &pkt(link_psk)).is_none(), "утёкшая ссылка не даёт L1");

        // Ответ уходит тем же ключом, которым говорил пир: иначе клиент на прошлом ключе оглох бы
        // ровно в момент смены эпохи.
        let back = sock.seal(b"answer", prev_peer);
        assert!(
            citadel_obfs::open(&citadel_obfs::psk_epoch(&master, cur - 1), &back).is_ok(),
            "пиру прошлой эпохи обязаны отвечать его ключом"
        );
        let fresh = sock.seal(b"answer", "127.0.0.1:40009".parse().unwrap());
        assert!(
            citadel_obfs::open(&citadel_obfs::psk_epoch(&master, cur), &fresh).is_ok(),
            "незнакомому пиру — ключ текущей эпохи"
        );
    }

    /// `Fixed` (клиент, token-less деплой) ведёт себя ровно как раньше: один ключ, без эпох.
    #[tokio::test]
    async fn fixed_psk_source_is_single_key() {
        let psk = [0x11u8; 32];
        let sock = ObfsUdpSocket::new(
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
            PskSource::Fixed(psk),
            Pacing::None,
        )
        .unwrap();
        let peer: SocketAddr = "127.0.0.1:41000".parse().unwrap();
        let inner = citadel_obfs::build_inner(citadel_obfs::TYPE_DATA, None, None, &[], b"quic");
        let sealed = citadel_obfs::seal(&psk, &[2u8; citadel_obfs::SID_LEN], 1, &[3u8; 12], &inner);
        assert!(sock.open_any(peer, &sealed).is_some());
        assert!(citadel_obfs::open(&psk, &sock.seal(b"x", peer)).is_ok());
        // чужой ключ не открывается (probe-resistance на месте)
        let alien = citadel_obfs::seal(&[0xFFu8; 32], &[2u8; citadel_obfs::SID_LEN], 1, &[3u8; 12], &inner);
        assert!(sock.open_any(peer, &alien).is_none());
    }

    /// Миграция (M4): rebind атомарно меняет внутренний сокет на новый порт (механика ArcSwap).
    #[tokio::test]
    async fn rebind_swaps_socket_to_new_port() {
        let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let sock = ObfsUdpSocket::new(std_sock, PskSource::Fixed([9u8; 32]), Pacing::None).unwrap();
        let before = sock.inner.load().local_addr().unwrap();
        sock.rebind().unwrap();
        let after = sock.inner.load().local_addr().unwrap();
        assert_ne!(before.port(), after.port(), "rebind должен дать новый локальный порт");
    }
}
