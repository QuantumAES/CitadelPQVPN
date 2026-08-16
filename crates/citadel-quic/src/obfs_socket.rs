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
//!
//! **Батарея (заход «маскировка/батарея», см. `docs/COVER-TRAFFIC-BATTERY-2026-08.md`).** В первой
//! редакции chaff взводился ЛЮБОЙ выпущенной датаграммой, включая собственный keep-alive: маячок
//! раз в 2–4 с сам себе открывал окно, и простаивающий туннель гнал ~2.2 ГБ мусора в сутки,
//! маскируя ничто. Здесь это исправлено четырьмя связанными вещами:
//!   * **П1** — окно chaff взводит только ПОЛЬЗОВАТЕЛЬСКИЙ трафик ([`crate::dataplane::user_packets`]);
//!   * **П2** — pacer не тикает в простое (спит на [`tokio::sync::Notify`], а не 200 раз/с);
//!   * **П3** — у chaff есть байтовый бюджет (token bucket), т.е. предсказуемый потолок расхода;
//!   * **П4** — хвост chaff затухает геометрически (5→10→…→320 мс), а не льёт 200 пак/с ровным окном;
//!   * **П6** — длины chaff берутся из эмпирических длин реального провода, а не из своего
//!     распределения (иначе chaff — собственная сигнатура: см. §2.4 того же документа).

use std::collections::VecDeque;
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use arc_swap::ArcSwap;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rand::RngCore;
use tokio::io::ReadBuf;

use crate::ratelimit::{RateCfg, TokenBucket};

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
    /// в пустой слот подмешивается dummy по политике `chaff`, но не быстрее, чем позволяет
    /// `budget` (П3: у маскировки обязан быть предсказуемый потолок расхода).
    Slotted { slot: Duration, burst: usize, chaff: Chaff, budget: Option<RateCfg> },
}

#[derive(Clone, Copy, Debug)]
pub enum Chaff {
    /// Без dummy-трафика — пейсинг только квантует тайминги реальных пакетов.
    Off,
    /// Dummy после пользовательского трафика, затухающим хвостом длиной `window` (WTF-PAD-стиль):
    /// маскирует паузы/хвосты потока, не гоня вечный chaff в простаивающем туннеле.
    Adaptive { window: Duration },
    /// Dummy в каждый пустой слот (constant-rate; дороже по трафику, для high-threat).
    Always,
}

/// П4: потолок шага затухания хвоста. Ценность chaff максимальна сразу после всплеска (он прячет,
/// где всплеск кончился); дальше плотность можно ронять почти без потери неопределённости.
const CHAFF_STEP_MAX: Duration = Duration::from_millis(320);

/// П4: длина хвоста chaff по умолчанию. Больше прежних 500 мс — при геометрическом затухании
/// хвост в 2 с стоит ~11 пакетов вместо 100, то есть длиннее и при этом в разы дешевле.
const CHAFF_WINDOW: Duration = Duration::from_millis(2_000);

/// П3: бюджеты профилей в КиБ/мин. «Экономно» — примерно один затухающий хвост на всплеск раз в
/// полминуты; «строго» — вчетверо больше. Всплеск разрешаем на полминуты бюджета вперёд
/// (`burst`), иначе первый же хвост упёрся бы в потолок и маскировка не состоялась бы.
const BUDGET_LITE_KIB_MIN: f64 = 32.0;
const BUDGET_STRICT_KIB_MIN: f64 = 128.0;

fn budget(kib_per_min: f64) -> RateCfg {
    let rate = kib_per_min * 1024.0 / 60.0;
    RateCfg { rate, burst: rate * 30.0 }
}

/// Чистое решение «слать ли chaff в этот пустой слот» + новый шаг затухания (П4).
/// `Some(step)` — слать, следующий chaff не раньше чем через `step`. Вынесено из состояния
/// сокета ради детерминированных юнит-тестов.
///
/// `saw_user` — был ли за жизнь сокета хоть один пользовательский пакет (до этого маскировать
/// нечего и некуда); `tail` — сколько прошло с последнего пользовательского трафика (**П1**:
/// собственный keep-alive сюда не входит); `due` — истёк ли текущий шаг затухания.
fn chaff_step_decision(
    chaff: Chaff,
    saw_user: bool,
    tail: Duration,
    due: bool,
    step: Duration,
    slot: Duration,
) -> Option<Duration> {
    if !saw_user {
        return None; // до первого пользовательского пакета молчим (некуда и незачем)
    }
    match chaff {
        Chaff::Off => None,
        Chaff::Always => due.then_some(slot), // constant-rate: каждый пустой слот
        Chaff::Adaptive { window } => {
            if tail > window || !due {
                return None;
            }
            Some((step * 2).min(CHAFF_STEP_MAX))
        }
    }
}

/// Разбор политики из строки. Профили: `off`(дефолт) | `lite` | `on` | `max`; ручная форма —
/// `<slot_ms>:<burst>:<off|adaptive|always>[:<КиБ/мин|none>]` (для стендов и операторов exit'а:
/// бюджет там по умолчанию НЕ навязывается — раз задают вручную, значит знают цену).
/// Чистая функция (от `&str`) — тестируется без глобального env.
fn parse_pacing(raw: &str) -> Pacing {
    let profile = |chaff, budget| Pacing::Slotted {
        slot: Duration::from_millis(5),
        burst: 32,
        chaff,
        budget,
    };
    let adaptive = Chaff::Adaptive { window: CHAFF_WINDOW };
    match raw.trim() {
        "" | "off" | "none" | "0" => Pacing::None,
        // «Экономно»: тот же алгоритм, вчетверо меньший потолок расхода.
        "lite" => profile(adaptive, Some(budget(BUDGET_LITE_KIB_MIN))),
        // «Строго» (историческое имя `on` — его пишет прежний GUI-тумблер и стенды).
        "on" | "strict" => profile(adaptive, Some(budget(BUDGET_STRICT_KIB_MIN))),
        // Constant-rate: только явным выбором и без бюджета — это осознанные ~13 ГБ/сутки.
        "max" | "always" => profile(Chaff::Always, None),
        s => {
            let mut it = s.split(':');
            let slot_ms: u64 = it.next().and_then(|x| x.parse().ok()).unwrap_or(5);
            let burst: usize = it.next().and_then(|x| x.parse().ok()).unwrap_or(32);
            let chaff = match it.next().unwrap_or("adaptive") {
                "off" => Chaff::Off,
                "always" => Chaff::Always,
                _ => adaptive,
            };
            let budget = it
                .next()
                .and_then(|x| x.trim().parse::<f64>().ok())
                .filter(|k| *k > 0.0)
                .map(budget);
            Pacing::Slotted {
                slot: Duration::from_millis(slot_ms.max(1)),
                burst: burst.max(1),
                chaff,
                budget,
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

/// П6: сколько последних размеров РЕАЛЬНОГО провода помним, чтобы chaff брал длины оттуда.
/// 64 хватает, чтобы догнать смену режима (пошла закачка — длины подтянулись за доли секунды),
/// и мало, чтобы не тащить историю прошлой активности в текущую маскировку.
const WIRE_HIST: usize = 64;

/// Кольцо последних длин реального провода (П6). `u16` — потолок провода 1255 Б (`WIRE_CAP`).
#[derive(Debug)]
struct WireHist {
    buf: [u16; WIRE_HIST],
    len: usize,
    pos: usize,
}

impl Default for WireHist {
    fn default() -> Self {
        Self { buf: [0; WIRE_HIST], len: 0, pos: 0 }
    }
}

impl WireHist {
    fn push(&mut self, wire: usize) {
        self.buf[self.pos] = wire.min(u16::MAX as usize) as u16;
        self.pos = (self.pos + 1) % WIRE_HIST;
        self.len = (self.len + 1).min(WIRE_HIST);
    }

    /// Случайная запомненная длина; `None` — истории ещё нет (chaff до первых данных).
    fn pick(&self, rnd: usize) -> Option<usize> {
        (self.len > 0).then(|| self.buf[rnd % self.len] as usize)
    }
}

/// П4: состояние затухающего хвоста chaff. Живёт под одним замком — читается и правится
/// исключительно в `pace_tick` (одна задача), так что конкуренции здесь нет.
#[derive(Debug)]
struct ChaffTail {
    /// Текущий шаг затухания (удваивается на каждом выпущенном chaff до [`CHAFF_STEP_MAX`]).
    step: Duration,
    /// Раньше этого момента следующий chaff не выпускаем.
    next: Instant,
}

// ─────────────── диагностика шейпинга (§6.2 документа: иначе регрессия «маскировка снова жжёт»
// замечается только по разряженной батарее). Счётчики процессные и монотонные; ни адресов, ни
// содержимого — только «сколько мусора мы сами сгенерировали».
static PACE_TICKS: AtomicU64 = AtomicU64::new(0);
static CHAFF_PKTS: AtomicU64 = AtomicU64::new(0);
static CHAFF_BYTES: AtomicU64 = AtomicU64::new(0);
static CHAFF_SKIPPED: AtomicU64 = AtomicU64::new(0);

/// Снимок счётчиков тайминг-шейпинга (для лога диагностики и тестов).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShapingStats {
    /// Сколько раз просыпался pacer (после П2 в простое не растёт).
    pub ticks: u64,
    pub chaff_pkts: u64,
    pub chaff_bytes: u64,
    /// Сколько chaff-пакетов не выпущено из-за исчерпанного бюджета (П3).
    pub chaff_skipped: u64,
}

pub fn shaping_stats() -> ShapingStats {
    ShapingStats {
        ticks: PACE_TICKS.load(Ordering::Relaxed),
        chaff_pkts: CHAFF_PKTS.load(Ordering::Relaxed),
        chaff_bytes: CHAFF_BYTES.load(Ordering::Relaxed),
        chaff_skipped: CHAFF_SKIPPED.load(Ordering::Relaxed),
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
    /// **П1:** момент последнего ПОЛЬЗОВАТЕЛЬСКОГО трафика — от него живёт хвост chaff.
    /// Собственный keep-alive его не двигает: маскировать маячок не от кого (он не несёт
    /// информации о поведении человека), а раньше именно он в простое и взводил окно chaff.
    last_user: Mutex<Instant>,
    /// П1: снимок [`crate::dataplane::user_packets`] на прошлом тике — сдвинулся, значит трафик был.
    user_seen: AtomicU64,
    /// П1: был ли пользовательский трафик хоть раз (до этого chaff не с чем смешивать).
    saw_user: AtomicBool,
    /// П4: затухающий хвост chaff.
    tail: Mutex<ChaffTail>,
    /// П3: бюджет chaff; `None` — без лимита (ручной профиль/`max`).
    chaff_budget: Option<Mutex<TokenBucket>>,
    /// П6: длины последних реальных пакетов на проводе — из них chaff берёт свою длину.
    wire_hist: Mutex<WireHist>,
    /// П2: будильник pacer'а. Его дёргают постановка в очередь и `Drop` сокета; пока работы нет,
    /// pacer спит на нём БЕЗ таймера (вместо 200 пробуждений в секунду).
    notify: Arc<tokio::sync::Notify>,
    /// Waker задачи poll_recv — при rebind будим её, чтобы перерегистрировалась на новом сокете.
    recv_waker: Mutex<Option<Waker>>,
}

impl Drop for ObfsUdpSocket {
    fn drop(&mut self) {
        // П2: разбудить запаркованный pacer, иначе он остался бы спать на `Notify` навсегда —
        // задача на каждый умерший endpoint (а их создаёт каждый реконнект).
        self.notify.notify_one();
    }
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
        let now = Instant::now();
        let (slot, chaff_budget) = match pacing {
            Pacing::Slotted { slot, budget, .. } => (slot, budget),
            Pacing::None => (Duration::from_millis(5), None),
        };
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
            last_user: Mutex::new(now),
            // П1: отсчитываем от ТЕКУЩЕГО значения счётчика — сокет мог подняться посреди жизни
            // процесса (реконнект), и чужая история трафика не должна выглядеть как наша.
            user_seen: AtomicU64::new(crate::dataplane::user_packets()),
            saw_user: AtomicBool::new(false),
            tail: Mutex::new(ChaffTail { step: slot, next: now }),
            chaff_budget: chaff_budget.map(|cfg| Mutex::new(TokenBucket::new(cfg, now))),
            wire_hist: Mutex::new(WireHist::default()),
            notify: Arc::new(tokio::sync::Notify::new()),
            recv_waker: Mutex::new(None),
        })
    }

    /// Миграция пути (M4): заменить исходящий UDP-сокет на новый (новый локальный порт/адрес).
    /// QUIC-соединение по Connection ID переживает смену src (как WiFi↔LTE / NAT-rebind): сервер
    /// видит пакеты с нового пути, валидирует его (PATH_CHALLENGE) и продолжает. obfs-keystream
    /// скоупится на сессию (sid/psk), не на путь — миграция совместима с обфускацией.
    fn rebind(&self) -> io::Result<()> {
        // P-1: маршрут — параметр фабрики. Новый сокет после миграции обязан идти мимо туннеля
        // ровно так же, как исходный: иначе реконнект в сети с поднятым TUN замкнёт транспорт
        // сам на себя, и симптом будет тот же «данные встали, потерь нет».
        let std_sock = crate::protect::bind_udp_ephemeral(crate::protect::Route::Bypass)?;
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
        let sealed = self.sealer_for(dst).seal(pid, &nonce, &inner);
        // П6: запоминаем длину РЕАЛЬНОГО пакета — из этих длин chaff и будет брать свою.
        self.wire_hist.lock().unwrap().push(sealed.len());
        sealed
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

    /// **П6:** длина chaff на проводе — случайная из ЭМПИРИЧЕСКИХ длин реального трафика этой
    /// сессии. Прежняя версия брала равномерное `[floor, cap]` и комментарий утверждал, что это
    /// совпадает с распределением DATA. Не совпадало: мелкие DATA-пакеты (а в простое они все
    /// такие) живут в `256…768`, chaff — в `256…1255`, то есть маскировка была сама себе
    /// сигнатурой. Истории ещё нет (chaff до первых данных) → прежнее равномерное поведение.
    fn chaff_wire_len(&self) -> usize {
        let (floor, cap) = match self.padding {
            citadel_obfs::Padding::Random { floor, cap, .. } => (floor, cap),
            _ => (256, citadel_obfs::WIRE_CAP), // не выше того, что мог бы отправить сам QUIC (MTU)
        };
        let rnd = rand::thread_rng().next_u32() as usize;
        match self.wire_hist.lock().unwrap().pick(rnd) {
            Some(w) => w.clamp(floor, cap),
            None => floor + rnd % (cap - floor + 1),
        }
    }

    /// Chaff-пакет (`TYPE_PAD`) заданной длины на проводе → неотличим от реального трафика.
    fn seal_chaff(&self, dst: SocketAddr, wire: usize) -> Vec<u8> {
        let pid = self.send_ctr.fetch_add(1, Ordering::Relaxed);
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
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
        drop(q);
        // П2: разбудить запаркованный pacer. Он не отправит пакет немедленно — только доспит до
        // ближайшей границы слот-сетки, поэтому квантование таймингов (ради которого всё и есть)
        // сохраняется, а в простое сетка не тикает вхолостую.
        self.notify.notify_one();
    }

    /// **П1:** заметить пользовательский трафик туннеля. Сдвинулся счётчик inner-датаграмм —
    /// значит, был трафик человека (в любую сторону: скачивание маскируется своим ACK-потоком
    /// ровно так же, как отправка). Возвращает `true`, если хвост chaff надо взвести заново.
    fn note_user_traffic(&self, slot: Duration, now: Instant) -> bool {
        let user = crate::dataplane::user_packets();
        if self.user_seen.swap(user, Ordering::Relaxed) == user {
            return false;
        }
        self.saw_user.store(true, Ordering::Relaxed);
        *self.last_user.lock().unwrap() = now;
        let mut tail = self.tail.lock().unwrap();
        tail.step = slot; // хвост начинается заново — с самого плотного шага
        tail.next = now;
        true
    }

    /// Один тик pacer'а: слить из очереди до `burst` реальных пакетов; если очередь была пуста —
    /// при разрешении политикой (и бюджетом) подмешать один chaff на последнее назначение.
    fn pace_tick(&self) {
        let (slot, burst, chaff) = match self.pacing {
            Pacing::Slotted { slot, burst, chaff, .. } => (slot, burst, chaff),
            Pacing::None => return,
        };
        PACE_TICKS.fetch_add(1, Ordering::Relaxed);
        let mut sent_real = 0usize;
        while sent_real < burst {
            let item = self.queue.lock().unwrap().pop_front();
            let Some((quic, dst)) = item else { break };
            let sealed = self.seal(&quic, dst);
            let _ = self.inner.load().try_send_to(&sealed, dst);
            *self.last_dst.lock().unwrap() = Some(dst);
            sent_real += 1;
        }
        let now = Instant::now();
        self.note_user_traffic(slot, now);
        if sent_real > 0 {
            return; // слот занят реальным трафиком — маскировать нечего
        }
        let Some(dst) = *self.last_dst.lock().unwrap() else { return };
        let tail_age = now.saturating_duration_since(*self.last_user.lock().unwrap());
        let mut tail = self.tail.lock().unwrap();
        let step = chaff_step_decision(
            chaff,
            self.saw_user.load(Ordering::Relaxed),
            tail_age,
            now >= tail.next,
            tail.step,
            slot,
        );
        let Some(step) = step else { return };
        tail.step = step;
        tail.next = now + step;
        drop(tail);
        // П3: длину знаем до seal — бюджет проверяем по ней, чтобы не тратить AEAD впустую.
        let wire = self.chaff_wire_len();
        if let Some(b) = &self.chaff_budget {
            if !b.lock().unwrap().allow(TokenBucket::packet_cost(wire), now) {
                CHAFF_SKIPPED.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        let sealed = self.seal_chaff(dst, wire);
        let _ = self.inner.load().try_send_to(&sealed, dst);
        CHAFF_PKTS.fetch_add(1, Ordering::Relaxed);
        CHAFF_BYTES.fetch_add(sealed.len() as u64, Ordering::Relaxed);
    }

    /// **П2:** нечего делать — pacer может спать без таймера. Очередь пуста И хвост chaff
    /// исчерпан (либо chaff вовсе не предусмотрен политикой). Разбудит [`Self::enqueue`]:
    /// пользовательский трафик в любую сторону порождает исходящий пакет (данные либо ACK).
    fn pace_parked(&self) -> bool {
        if !self.queue.lock().unwrap().is_empty() {
            return false;
        }
        match self.pacing {
            Pacing::None => true,
            Pacing::Slotted { chaff, .. } => match chaff {
                Chaff::Off => true,
                Chaff::Always => !self.saw_user.load(Ordering::Relaxed),
                // До первого пользовательского пакета маскировать нечего — спим (иначе сетка
                // крутилась бы вхолостую всё время хендшейка и первых секунд сессии).
                Chaff::Adaptive { window } => {
                    !self.saw_user.load(Ordering::Relaxed)
                        || self.last_user.lock().unwrap().elapsed() > window
                }
            },
        }
    }
}

/// П2: ближайшая граница слот-сетки не раньше `now`. Сетка привязана к якорю запуска pacer'а,
/// поэтому парковка в простое не сдвигает фазу: моменты выпуска остаются кратны `slot`, то есть
/// квантование таймингов (ради которого пейсинг и существует) от сна не страдает.
/// Чистая функция — тестируется без часов.
fn next_slot(next: Instant, now: Instant, slot: Duration) -> Instant {
    if next > now {
        return next;
    }
    let behind = (now - next).as_nanos() / slot.as_nanos().max(1) + 1;
    next + Duration::from_nanos((behind as u64).saturating_mul(slot.as_nanos() as u64))
}

/// **П2:** страховочный интервал парковки. Штатно pacer будят `enqueue` и `Drop` сокета; этот
/// таймер существует на случай, если разбудить забыли, — два пробуждения в минуту против прежних
/// 200 в секунду ничего не стоят, а вечно спящая задача была бы утечкой.
const PACE_PARK_GUARD: Duration = Duration::from_secs(30);

/// Фоновый pacer: на тиках слот-сетки выпускает накопленные пакеты + chaff.
/// Держит `Weak` — когда endpoint (и его `Arc<ObfsUdpSocket>`) дропнут, задача сама завершается.
///
/// **П2:** в простое задача СПИТ на `Notify`, а не крутит `interval(5 мс)`. Прежний вариант давал
/// 200 пробуждений в секунду у процесса с foreground-сервисом (Doze его не усыпляет) — работы на
/// тик почти нет, но такой таймер не даёт ядру уходить в глубокие C-состояния. Важно, что `Notify`
/// хранит permit: разбудить «до `await`» не значит потерять сигнал.
async fn pace_loop(weak: Weak<ObfsUdpSocket>) {
    let (slot, notify) = match weak.upgrade() {
        Some(s) => match s.pacing {
            Pacing::Slotted { slot, .. } => (slot, s.notify.clone()),
            Pacing::None => return,
        },
        None => return,
    };
    // Якорь сетки: моменты выпуска — `anchor + k·slot`, независимо от того, сколько мы спали.
    let anchor = tokio::time::Instant::now();
    let mut next = anchor + slot;
    loop {
        let parked = match weak.upgrade() {
            Some(s) => s.pace_parked(),
            None => break, // сокет дропнут → выходим
        };
        if parked {
            // Держать `Arc` тут нельзя: он не дал бы сокету умереть, а задача — проснуться.
            let _ = tokio::time::timeout(PACE_PARK_GUARD, notify.notified()).await;
        }
        next = tokio::time::Instant::from_std(next_slot(
            next.into_std(),
            tokio::time::Instant::now().into_std(),
            slot,
        ));
        tokio::time::sleep_until(next).await;
        next += slot;
        match weak.upgrade() {
            Some(s) => s.pace_tick(),
            None => break,
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
    // P-1: сокет сюда приходит УЖЕ с принятым решением о маршруте — из фабрики
    // `citadel_protect::{bind_udp_ephemeral, bind_udp_listen}`. Раньше `protect` звался здесь, и
    // это ровно то место, где его однажды потеряли при переносе `pacing` в параметр (заход 7):
    // на Android хендшейк после такой потери проходит (он идёт ДО `VpnService.Builder.establish`,
    // туннеля ещё нет), а в момент подъёма TUN наши же UDP-пакеты к exit'у уходят В СОБСТВЕННЫЙ
    // туннель — данные встают намертво, ACK'и не возвращаются, «на провод ушло 2 из 113, потерь 0».
    // Теперь потерять нечего: без фабрики сокет не создать (линт), а маршрут у неё в сигнатуре.
    // Инвариант держит тест `transport_sockets_go_through_protector`.
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
    // абонента, ответное направление — забота оператора exit'а (M-8, §17.2). Но chaff здесь
    // запрещён — см. [`check_server_chaff`].
    let raw = std::env::var("Citadel_PACING").unwrap_or_default();
    check_server_chaff(&raw)?;
    // P-1: слушающий сокет exit'а — отдельное имя фабрики. Маршрут относительно «собственного
    // туннеля» здесь неприменим по построению: сокет ничего не инициирует, а VpnService-протектора
    // на серверной стороне нет вовсе.
    build_endpoint(
        crate::protect::bind_udp_listen(listen)?,
        Some(server_config),
        psk,
        parse_pacing(&raw),
    )
}

/// N-4: chaff на СЕРВЕРНОЙ стороне запрещён кодом, а не договорённостью в документе.
///
/// Маркер пользовательского трафика (`dataplane::user_packets`) — один на процесс. У клиента это
/// верно: туннель там один. На exit'е один процесс обслуживает всех абонентов сразу, поэтому
/// chaff, взводимый «был ли трафик», взводился бы у одного абонента трафиком другого — то есть
/// появился бы межклиентский тайминговый сайд-канал ровно там, где вся конструкция обещает
/// обратное. Пока это держалось на том, что установщик не выставляет `Citadel_PACING`; одна
/// строка в чужом systemd-юните отменяла бы обещание молча.
///
/// Запрещён именно **chaff**, а не пейсинг вообще: выпуск по слот-сетке без пустых слотов
/// (`5:32:off`) счётчик не читает и остаётся законным инструментом оператора.
fn check_server_chaff(raw: &str) -> Result<()> {
    match parse_pacing(raw) {
        Pacing::Slotted { chaff: Chaff::Adaptive { .. } | Chaff::Always, .. } => Err(anyhow!(
            "Citadel_PACING={raw:?}: chaff на серверной стороне запрещён — маркер \
             пользовательского трафика один на процесс, и chaff одного абонента взводился бы \
             трафиком другого (межклиентский тайминговый канал). Уберите переменную либо задайте \
             форму без chaff, например `5:32:off`; маскировку ОТПРАВКИ включает клиент у себя"
        )),
        _ => Ok(()),
    }
}

/// КЛИЕНТ: ключ всегда один — тот, что он получил у издателя на текущую эпоху (или бутстрапный
/// в token-less деплое). Перебирать эпохи клиенту незачем: он знает, чем говорит.
pub fn client_endpoint_obfs(psk: [u8; 32], pacing: Pacing) -> Result<quinn::Endpoint> {
    build_endpoint(
        crate::protect::bind_udp_ephemeral(crate::protect::Route::Bypass)?,
        None,
        PskSource::Fixed(psk),
        pacing,
    )
}

/// КЛИЕНТ без obfs (token-less деплой/проба, где транспортного PSK нет): обычный QUIC-endpoint,
/// но с той же защитой сокета от заворачивания в собственный туннель, что и у obfs-пути.
///
/// Своя функция нужна ровно из-за этого: `quinn::Endpoint::client` создаёт UDP-сокет ВНУТРИ себя,
/// и вклиниться между `bind` и `connect` с `protect()` там негде — на Android такой endpoint
/// работал бы только до подъёма TUN (та же беда, что описана в [`build_endpoint`]).
pub fn client_endpoint_plain() -> Result<quinn::Endpoint> {
    let sock = crate::protect::bind_udp_ephemeral(crate::protect::Route::Bypass)?;
    let runtime = quinn::default_runtime().ok_or_else(|| anyhow!("нет async runtime (tokio)"))?;
    Ok(quinn::Endpoint::new(quinn::EndpointConfig::default(), None, sock, runtime)?)
}

#[cfg(test)]
mod tests {
    // P-1: тестовая петля 127.0.0.1 к собственному туннелю отношения не имеет — маршрутного
    // решения здесь нет, и фабрика `citadel_protect` не нужна (см. clippy.toml).
    #![allow(clippy::disallowed_methods)]
    use super::*;

    /// П1 опирается на ПРОЦЕССНЫЙ счётчик пользовательских датаграмм, поэтому тесты, которые его
    /// двигают (или ждут его неподвижности), обязаны идти по одному: `cargo test` гонит тесты
    /// потоками одного процесса, и чужой инкремент выглядел бы как «пошёл трафик человека».
    static USER_TRAFFIC_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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

    /// Таблица решений о chaff. Главное здесь — первая строка (**П1**): без пользовательского
    /// трафика chaff не идёт НИКОГДА, даже в constant-rate профиле. Именно её отсутствие (точнее,
    /// то, что в роли «реального трафика» выступал собственный keep-alive) и стоило 2.2 ГБ/сутки.
    #[test]
    fn chaff_decision_table() {
        let w = Duration::from_millis(2_000);
        let slot = Duration::from_millis(5);
        let d = |chaff, saw_user, tail_ms, due| {
            chaff_step_decision(chaff, saw_user, Duration::from_millis(tail_ms), due, slot, slot)
        };
        // нет пользовательского трафика → никогда (даже Always)
        assert!(d(Chaff::Always, false, 0, true).is_none());
        assert!(d(Chaff::Adaptive { window: w }, false, 0, true).is_none());
        // Off → никогда
        assert!(d(Chaff::Off, true, 0, true).is_none());
        // Always → в каждом пустом слоте (когда трафик был)
        assert!(d(Chaff::Always, true, 10_000, true).is_some());
        // Adaptive → внутри хвоста да, за хвостом нет
        assert!(d(Chaff::Adaptive { window: w }, true, 100, true).is_some());
        assert!(d(Chaff::Adaptive { window: w }, true, 2_500, true).is_none());
        // шаг затухания ещё не истёк → пропускаем слот, даже внутри хвоста
        assert!(d(Chaff::Adaptive { window: w }, true, 100, false).is_none());
    }

    /// П4: хвост затухает геометрически и упирается в потолок. Считаем, во что обходится один
    /// всплеск: было 100 пакетов на 500 мс ровным окном, стало ~11 на 2 с — при том, что хвост
    /// СТАЛ ДЛИННЕЕ (наблюдателю неопределённость важна там, где всплеск кончился).
    #[test]
    fn chaff_tail_decays_geometrically() {
        let slot = Duration::from_millis(5);
        let window = Duration::from_millis(2_000);
        let mut step = slot;
        let mut tail = Duration::ZERO;
        let mut pkts = 0;
        while let Some(next) =
            chaff_step_decision(Chaff::Adaptive { window }, true, tail, true, step, slot)
        {
            pkts += 1;
            step = next;
            tail += next;
            assert!(step <= CHAFF_STEP_MAX, "шаг не должен расти выше потолка");
        }
        assert!((8..=14).contains(&pkts), "ожидался хвост в ~11 пакетов, получилось {pkts}");
        assert_eq!(step, CHAFF_STEP_MAX, "к концу хвоста шаг обязан упереться в потолок");
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

    /// N-4: серверный endpoint не должен подниматься с chaff'ом — маркер пользовательского
    /// трафика процессный, и на exit'е chaff одного абонента взводился бы трафиком другого.
    /// Раньше это держалось только на том, что установщик не пишет `Citadel_PACING`.
    #[test]
    fn server_refuses_chaff_but_allows_plain_slotting() {
        for forbidden in ["on", "strict", "lite", "max", "always", "10:8:always", "5:32:adaptive"] {
            let err = check_server_chaff(forbidden).expect_err("{forbidden} обязан быть отвергнут");
            let msg = format!("{err}");
            assert!(msg.contains("chaff"), "причина отказа обязана называть chaff: {msg}");
            assert!(msg.contains(forbidden), "в отказе должно быть само значение: {msg}");
        }
        for allowed in ["", "off", "none", "0", "5:32:off", "3:16:off"] {
            check_server_chaff(allowed)
                .unwrap_or_else(|e| panic!("{allowed:?} обязан оставаться разрешённым: {e}"));
        }
    }

    #[test]
    fn parse_pacing_cases() {
        assert!(matches!(parse_pacing(""), Pacing::None));
        assert!(matches!(parse_pacing("off"), Pacing::None));
        assert!(matches!(parse_pacing("on"), Pacing::Slotted { .. }));
        match parse_pacing("10:8:always") {
            Pacing::Slotted { slot, burst, chaff, budget } => {
                assert_eq!(slot, Duration::from_millis(10));
                assert_eq!(burst, 8);
                assert!(matches!(chaff, Chaff::Always));
                assert!(budget.is_none(), "ручная форма без 4-го поля — без бюджета");
            }
            _ => panic!("ожидался Slotted"),
        }
        match parse_pacing("3:16:off") {
            Pacing::Slotted { chaff, .. } => assert!(matches!(chaff, Chaff::Off)),
            _ => panic!("ожидался Slotted"),
        }
        // ручной бюджет (КиБ/мин) — 4-е поле
        match parse_pacing("5:32:adaptive:64") {
            Pacing::Slotted { budget: Some(b), .. } => {
                assert!((b.rate - 64.0 * 1024.0 / 60.0).abs() < 1e-6)
            }
            _ => panic!("ожидался Slotted с бюджетом"),
        }
        // мусорные/частичные значения → дефолты, не паника
        assert!(matches!(parse_pacing("xyz"), Pacing::Slotted { .. }));
    }

    /// **П3:** у профилей есть потолок расхода, и он именно такой, как обещает интерфейс. Без
    /// этого «маскировка» остаётся статьёй расхода без верхней границы — на мобильном тарифе это
    /// неоплачиваемый счёт, а не настройка приватности.
    #[test]
    fn profiles_carry_a_budget() {
        let kib_min = |p: Pacing| match p {
            Pacing::Slotted { budget: Some(b), .. } => b.rate * 60.0 / 1024.0,
            _ => panic!("у профиля обязан быть бюджет"),
        };
        assert!((kib_min(parse_pacing("lite")) - BUDGET_LITE_KIB_MIN).abs() < 1e-6);
        assert!((kib_min(parse_pacing("on")) - BUDGET_STRICT_KIB_MIN).abs() < 1e-6);
        // constant-rate — только явным выбором и осознанно, бюджет там был бы самообманом
        assert!(matches!(
            parse_pacing("max"),
            Pacing::Slotted { chaff: Chaff::Always, budget: None, .. }
        ));
    }

    /// **П6:** длины chaff берутся из эмпирических длин реального провода. Прежняя равномерная
    /// `[256, 1255]` делала chaff отдельным «горбом» в гистограмме длин — то есть собственной
    /// сигнатурой маскировки.
    #[test]
    fn chaff_length_follows_real_traffic() {
        let mut h = WireHist::default();
        assert_eq!(h.pick(0), None, "истории нет → прежнее поведение (равномерно)");
        for _ in 0..10 {
            h.push(300);
        }
        assert_eq!(h.pick(7), Some(300));
        // кольцо не растёт и вытесняет старое
        for i in 0..WIRE_HIST * 2 {
            h.push(1000 + i % 3);
        }
        assert_eq!(h.len, WIRE_HIST);
        for r in 0..WIRE_HIST {
            let w = h.pick(r).unwrap();
            assert!((1000..=1002).contains(&w), "старые длины обязаны вытесняться, вижу {w}");
        }
    }

    /// **П2:** сетка слотов не сползает от парковки. Если бы она сползала, моменты выпуска после
    /// каждого простоя оказывались бы привязаны к моменту пробуждения — то есть к тому самому
    /// пользовательскому событию, которое пейсинг и должен размазывать.
    #[test]
    fn slot_grid_survives_parking() {
        let slot = Duration::from_millis(5);
        let anchor = Instant::now();
        let next = anchor + slot;
        // не проспали — момент не двигается
        assert_eq!(next_slot(next, anchor, slot), next);
        // проспали 8 с (парковка): следующая граница кратна slot от якоря и строго в будущем
        let now = anchor + Duration::from_secs(8);
        let aligned = next_slot(next, now, slot);
        assert!(aligned > now);
        assert!(aligned - now <= slot);
        assert_eq!((aligned - anchor).as_nanos() % slot.as_nanos(), 0, "фаза сетки сохранена");
    }

    /// Интеграционный: фоновый pacer на loopback реально выпускает очередь и подмешивает chaff.
    /// Покрывает async-путь (interval-дрейн, seal, отправка, приём, дроп TYPE_PAD), который
    /// нельзя проверить чистыми юнит-тестами и который недоступен локально через QUIC/туннель.
    #[tokio::test]
    async fn pacer_delivers_real_and_chaff_over_loopback() {
        let _serial = USER_TRAFFIC_TESTS.lock().await;
        let psk = [7u8; 32];
        let rx = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rx_addr = rx.local_addr().unwrap();

        let tx_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let pacing = Pacing::Slotted {
            slot: Duration::from_millis(5),
            burst: 8,
            chaff: Chaff::Always,
            budget: None,
        };
        let sock = Arc::new(ObfsUdpSocket::new(tx_std, PskSource::Fixed(psk), pacing).unwrap());
        tokio::spawn(pace_loop(Arc::downgrade(&sock)));

        // П1: chaff идёт только вслед пользовательскому трафику — а он здесь и есть.
        crate::dataplane::note_user_packet();
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

    /// **П1 — главный тест захода: собственный keep-alive НЕ считается реальным трафиком.**
    ///
    /// Раньше `last_real` двигала любая выпущенная датаграмма, включая маячок. В простое это
    /// значило: раз в 2–4 с маячок сам себе открывает окно chaff, 100 пустых слотов подряд
    /// заполняются мусором — ~2.2 ГБ в сутки на туннеле, по которому не идёт НИЧЕГО. Здесь
    /// проверяется ровно это: пакет, не сопровождённый пользовательским трафиком, хвоста не
    /// открывает, а настоящий — открывает.
    #[tokio::test]
    async fn keepalive_does_not_trigger_chaff() {
        let _serial = USER_TRAFFIC_TESTS.lock().await;
        let psk = [11u8; 32];
        let rx = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rx_addr = rx.local_addr().unwrap();
        let pacing = Pacing::Slotted {
            slot: Duration::from_millis(5),
            burst: 8,
            chaff: Chaff::Adaptive { window: CHAFF_WINDOW },
            budget: None,
        };
        let sock = Arc::new(
            ObfsUdpSocket::new(
                std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
                PskSource::Fixed(psk),
                pacing,
            )
            .unwrap(),
        );
        tokio::spawn(pace_loop(Arc::downgrade(&sock)));

        // Считаем, что приехало за окно: chaff — это TYPE_PAD.
        async fn drain(rx: &tokio::net::UdpSocket, psk: [u8; 32], for_: Duration) -> (u32, u32) {
            let (mut real, mut chaff) = (0, 0);
            let deadline = tokio::time::Instant::now() + for_;
            let mut buf = [0u8; 2048];
            while let Ok(Ok((n, _))) =
                tokio::time::timeout_at(deadline, rx.recv_from(&mut buf)).await
            {
                let opened = citadel_obfs::open(&psk, &buf[..n]).unwrap();
                match citadel_obfs::parse_inner(&opened.inner) {
                    Some((citadel_obfs::TYPE_PAD, _)) => chaff += 1,
                    Some((citadel_obfs::TYPE_DATA, _)) => real += 1,
                    _ => {}
                }
            }
            (real, chaff)
        }

        // Фаза 1: «маячок» — датаграмма есть, пользовательского трафика нет.
        sock.enqueue(b"keepalive", rx_addr);
        let (real, chaff) = drain(&rx, psk, Duration::from_millis(400)).await;
        assert_eq!(real, 1, "сам маячок обязан уйти");
        assert_eq!(chaff, 0, "маячок не должен открывать хвост chaff (П1)");

        // Фаза 2: настоящий пользовательский пакет — хвост обязан открыться.
        crate::dataplane::note_user_packet();
        sock.enqueue(b"user-data", rx_addr);
        let (real, chaff) = drain(&rx, psk, Duration::from_millis(400)).await;
        assert_eq!(real, 1);
        assert!(chaff > 0, "после пользовательского трафика chaff обязан пойти");
    }

    /// **П3:** исчерпанный бюджет останавливает chaff, а не «замедляет» его задним числом.
    /// Бюджета здесь хватает ровно на один-два пакета — дальше слоты обязаны пропускаться.
    #[tokio::test]
    async fn chaff_budget_caps_the_flood() {
        let _serial = USER_TRAFFIC_TESTS.lock().await;
        let psk = [12u8; 32];
        let rx = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rx_addr = rx.local_addr().unwrap();
        let pacing = Pacing::Slotted {
            slot: Duration::from_millis(5),
            burst: 8,
            chaff: Chaff::Always, // без затухания — проверяем именно бюджет
            // Пополнение почти нулевое, запас — на пару пакетов (chaff берёт длины реального
            // провода, т.е. сотни байт; см. П6), поэтому поток обязан оборваться сразу.
            budget: Some(RateCfg { rate: 1.0, burst: 1500.0 }),
        };
        let sock = Arc::new(
            ObfsUdpSocket::new(
                std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
                PskSource::Fixed(psk),
                pacing,
            )
            .unwrap(),
        );
        tokio::spawn(pace_loop(Arc::downgrade(&sock)));
        crate::dataplane::note_user_packet();
        sock.enqueue(b"user-data", rx_addr);

        let mut chaff = 0;
        let mut buf = [0u8; 2048];
        let deadline = tokio::time::Instant::now() + Duration::from_millis(300);
        while let Ok(Ok((n, _))) = tokio::time::timeout_at(deadline, rx.recv_from(&mut buf)).await {
            let opened = citadel_obfs::open(&psk, &buf[..n]).unwrap();
            if let Some((citadel_obfs::TYPE_PAD, _)) = citadel_obfs::parse_inner(&opened.inner) {
                chaff += 1;
            }
        }
        // Без бюджета за 300 мс ушло бы ~60 пакетов (200 слотов/с); бюджета хватает на ~1500 байт.
        assert!(chaff >= 1, "первый chaff обязан пройти — бюджет не запрет, а потолок");
        assert!(chaff <= 6, "бюджет обязан оборвать поток chaff, ушло {chaff}");
        assert!(shaping_stats().chaff_skipped > 0, "пропуски по бюджету обязаны считаться");
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
