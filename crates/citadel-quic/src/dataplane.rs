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
use std::time::{Duration, Instant};

use anyhow::Result;
use citadel_masque::{datagram, ip};
use citadel_tun::TunIo;

use crate::ratelimit::{RateCfg, RateLimits, TokenBucket};

/// Транспорт туннеля: **всегда** PQ-QUIC (TLS 1.3 + гибридный KEX). Обычно поверх UDP; при
/// заблокированном UDP — поверх obfs-TCP (S0.3/H1), но крипта/control/data-plane идентичны.
/// `over_tcp` — только лейбл для логов (само соединение о транспорте под ним не знает).
pub struct Tunnel {
    conn: quinn::Connection,
    over_tcp: bool,
    /// П5: `max_idle_timeout`, который пир объявил в control-обмене (капсула адреса, необязательный
    /// хвост — см. `citadel_masque::capsule::decode_idle_hint`). `None` — пир прежней версии.
    /// Отсюда pump узнаёт, можно ли перейти на редкий keep-alive, не рискуя разрывом в простое:
    /// эффективный idle-таймаут QUIC равен минимуму из объявленных сторонами, а quinn наружу его
    /// не отдаёт.
    peer_idle: Option<Duration>,
}

impl Tunnel {
    pub fn new(conn: quinn::Connection, over_tcp: bool) -> Self {
        Self { conn, over_tcp, peer_idle: None }
    }

    /// П5: запомнить объявленный пиром idle-таймаут (мс из капсулы). Зовётся один раз, сразу
    /// после control-обмена, ДО `pump`.
    pub fn set_peer_idle_ms(&mut self, ms: Option<u64>) {
        self.peer_idle = ms.map(Duration::from_millis);
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

    /// Идёт ли транспорт поверх obfs-TCP (а не UDP). Нужно циклу реконнекта: лечение
    /// односторонней дыры — смена транспорта, и оно применимо только к UDP-сессии.
    pub fn is_tcp(&self) -> bool {
        self.over_tcp
    }

    pub fn close(&self, code: u32, reason: &[u8]) {
        self.conn.close(code.into(), reason);
    }

    /// Клиент: послать один control-запрос и получить ответ (reliable QUIC bi-stream).
    /// Лимит 8192 — ответ несёт ML-DSA-65 pub(1952)+sig(3309) для commitment-fetch (§S3) ⇒ ~5.3 КБ.
    /// L-15: ошибки quinn несут reason-фразу CONNECTION_CLOSE ровно так, как её прислал пир
    /// (в т.ч. до аутентификации) ⇒ любой текст пира проходит через [`crate::peer_text`], прежде
    /// чем попасть в наш лог и в текст отказа для пользователя.
    pub async fn control_client(&mut self, req: &[u8]) -> Result<Vec<u8>> {
        let (mut send, mut recv) = self
            .conn
            .open_bi()
            .await
            .map_err(|e| anyhow::anyhow!("control: стрим не открыт: {}", crate::peer_text(e)))?;
        send.write_all(req)
            .await
            .map_err(|e| anyhow::anyhow!("control: запрос не отправлен: {}", crate::peer_text(e)))?;
        send.finish()?;
        recv.read_to_end(8192)
            .await
            .map_err(|e| anyhow::anyhow!("control: ответ не получен: {}", crate::peer_text(e)))
    }

    /// Сервер: принять один control-запрос, обработать `handle` (→ ответ + aux) и ответить. `aux`
    /// (напр. выделенный адрес) возвращается вызывающему — так адрес выделяется ВНУТРИ обработки, уже
    /// ПОСЛЕ верификации токена (C6/аудит-3), а не до неё (иначе неавториз. флуд жёг бы пул адресов).
    pub async fn control_server<F, T>(&mut self, handle: F) -> Result<T>
    where
        F: FnOnce(&[u8]) -> Result<(Vec<u8>, T)>,
    {
        // L-15: та же гигиена в обратную сторону — клиент для exit'а такой же недоверенный пир,
        // и его reason-фраза не должна оказаться строкой в логе сервера.
        let (mut send, mut recv) = self
            .conn
            .accept_bi()
            .await
            .map_err(|e| anyhow::anyhow!("control: стрим не принят: {}", crate::peer_text(e)))?;
        let req = recv
            .read_to_end(8192)
            .await
            .map_err(|e| anyhow::anyhow!("control: запрос не прочитан: {}", crate::peer_text(e)))?;
        let (resp, aux) = handle(&req)?;
        send.write_all(&resp)
            .await
            .map_err(|e| anyhow::anyhow!("control: ответ не отправлен: {}", crate::peer_text(e)))?;
        send.finish()?;
        Ok(aux)
    }
}

/// Политика exit'а для трафика ИЗ туннеля. Осмысленна только в exit-режиме (`egress = Some`);
/// на клиенте (`egress = None`) не применяется вовсе.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct EgressPolicy {
    /// C7.2: `Some((admin_vip, admin_port))` → TCP к этому dst:port на exit'е пропускается мимо
    /// egress-фильтра (ядро DNAT'ит его на issuer, admin-плоскость по туннелю). Прочее — как раньше.
    pub admin_dst: Option<([u8; 4], u16)>,
    /// **G1 (аудит-5): адреса, к которым exit не форвардит из туннеля вовсе.** F2 режет приватные
    /// и служебные сети, но публичный адрес САМОГО деплоя для него — обычный публичный адрес, а
    /// ядровый `INPUT -i tun -j DROP` живёт в netns КОНТЕЙНЕРА и такой пакет не видит: он уходит
    /// через `FORWARD`+MASQUERADE на docker-бридж и приходит в INPUT ХОСТА как локальный трафик —
    /// мимо облачной security-group. То есть абонент дотягивался из туннеля до всего, что хост
    /// слушает на 0.0.0.0 (sshd, агенты, published-порты соседних контейнеров). Сюда installer
    /// кладёт публичный IP самой машины и адрес издателя.
    ///
    /// Побочная польза: сокет движка, который по ошибке пошёл В СВОЙ туннель (инвариант protect
    /// ломался дважды), теперь даёт явный дроп с адресом в логе, а не бесконечную петлю.
    pub deny_dsts: Vec<[u8; 4]>,
    /// Исключения к [`Self::deny_dsts`]: **TCP** на эти `(addr, port)` проходит. Нужно ровно для
    /// одного — token-порт издателя: фоновая дозаправка кошелька (§7.1, заход 7) идёт СКВОЗЬ
    /// туннель нарочно, чтобы издатель видел адрес exit'а, а не абонента. Всё остальное на том же
    /// адресе (admin-порт, ssh, published-порты) остаётся закрытым — этим же закрыт G2: прямой
    /// путь абонента к `ISSUER_IP:7001` в обход admin-VIP, где SNAT exit'а выдавал его за
    /// разрешённый адрес exit-машины (`Citadel_ADMIN_PEER`, L-14).
    pub allow_dsts: Vec<([u8; 4], u16)>,
}

impl EgressPolicy {
    /// Запрещён ли `dst` целиком (с учётом исключений по TCP-порту). `dport` — [`ip::tcp_dport`],
    /// то есть `None` для не-TCP: ICMP/UDP на запрещённый адрес не проходят никогда (fail-closed —
    /// исключение выдаётся ровно под один TCP-сервис, а не под адрес).
    pub fn denies(&self, dst: [u8; 4], dport: Option<u16>) -> bool {
        if !self.deny_dsts.contains(&dst) {
            return false;
        }
        !matches!(dport, Some(p) if self.allow_dsts.contains(&(dst, p)))
    }

    /// Есть ли что применять (для лога и для ядровых правил-дублёров).
    pub fn is_empty(&self) -> bool {
        self.deny_dsts.is_empty()
    }
}

/// Обработка входящего (от клиента) пакета на exit: анти-спуфинг + egress-фильтр (S0.2/F2) +
/// rate-limit (F7). `accept` → `true` пропустить в TUN, `false` дропнуть. Per-connection.
pub struct Inbound {
    /// `Some(назначенный клиенту адрес)` → exit-режим (анти-спуфинг+egress); `None` → клиент.
    egress: Option<[u8; 4]>,
    policy: EgressPolicy,
    bucket: Option<TokenBucket>,
    dropped: u64,
    dropped_bytes: u64,
}

impl Inbound {
    pub fn new(egress: Option<[u8; 4]>, rate_limit: Option<RateCfg>) -> Self {
        Self::with_policy(egress, rate_limit, EgressPolicy::default())
    }

    /// Как [`Inbound::new`], но с политикой exit'а (admin-VIP C7.2 + deny/allow G1-G2). Только
    /// exit-режим (`egress = Some`) её использует; на клиенте (`egress = None`) фильтра нет вовсе.
    pub fn with_policy(
        egress: Option<[u8; 4]>,
        rate_limit: Option<RateCfg>,
        policy: EgressPolicy,
    ) -> Self {
        Self {
            egress,
            policy,
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
                        // no-logs: адреса пользователя — только под Citadel_DEBUG_LOG (см. lib::debug_logs)
                        crate::dlog!(
                            "[exit] S0.2: дроп спуфинг inner-src {}.{}.{}.{} (ожидался {}.{}.{}.{})",
                            v.src[0], v.src[1], v.src[2], v.src[3],
                            expected_src[0], expected_src[1], expected_src[2], expected_src[3]
                        );
                        return false;
                    }
                    let dport = ip::tcp_dport(&v);
                    // G1/G2: явный запрет проверяется ПЕРВЫМ — раньше admin-исключения и раньше F2.
                    // Порядок принципиален: список пишет оператор деплоя, и он обязан побеждать
                    // любое послабление, а не наоборот (иначе будущее исключение мимо F2 тихо
                    // открыло бы дорогу к адресам, ради закрытия которых список и заведён).
                    if self.policy.denies(v.dst, dport) {
                        // no-logs: адрес назначения — под Citadel_DEBUG_LOG, как и остальные дропы.
                        crate::dlog!(
                            "[exit] G1: инфраструктурный inner-dst {}.{}.{}.{} запрещён из туннеля",
                            v.dst[0], v.dst[1], v.dst[2], v.dst[3]
                        );
                        return false;
                    }
                    // C7.2: admin-плоскость — TCP к назначенному admin-VIP:порту разрешён мимо
                    // egress-фильтра (ядро DNAT'ит его на issuer). Анти-спуфинг src уже пройден,
                    // так что доступ имеет только легитимно подключённый клиент; сам доступ к
                    // управлению реестром отсекается admin-подписью на issuer (citadel-token::admin).
                    let is_admin =
                        self.policy.admin_dst.is_some_and(|(vip, port)| v.dst == vip && dport == Some(port));
                    // F2: не форвардить во внутренние/служебные сети (metadata/RFC1918/loopback/…)
                    if !is_admin && ip::is_blocked_dst(v.dst) {
                        // no-logs: назначение пользователя — самое чувствительное, что тут есть.
                        crate::dlog!(
                            "[exit] F2: заблокирован inner-dst {}.{}.{}.{}",
                            v.dst[0], v.dst[1], v.dst[2], v.dst[3]
                        );
                        return false;
                    }
                }
                None => {
                    // S0.2/H3: не-IPv4 (IPv6/мусор) is_blocked_dst не покрывает → default-deny
                    // (не fail-open). Туннель назначает только IPv4; v6 внутри пока не поддержан.
                    // Клиент такие пакеты дропает у себя (см. pump), сюда они приходят от старых
                    // клиентов/мусора — молча, без строки на пакет (лог-амплификация).
                    crate::dlog!("[exit] S0.2: дроп не-IPv4 inner-пакета (default-deny)");
                    return false;
                }
            }
        }
        self.charge(pkt.len())
    }

    /// Списать стоимость датаграммы из bucket'а, не проверяя политику. Нужно для датаграмм,
    /// которые в TUN не идут (служебный контекст, keep-alive M-8): полезной нагрузки в них нет,
    /// но обработку и полосу они занимают, а значит, должны считаться в per-client лимит —
    /// иначе злоупотребляющий клиент обходит F7, просто выбрав другой context id.
    pub fn charge(&mut self, len: usize) -> bool {
        if let Some(b) = self.bucket.as_mut() {
            if !b.allow(TokenBucket::packet_cost(len), Instant::now()) {
                self.dropped += 1;
                self.dropped_bytes += len as u64;
                if self.dropped == 1 || self.dropped.is_multiple_of(50) {
                    crate::dlog!(
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

/// M-8: задержка до следующего keep-alive — случайная, выбирается заново перед каждой отправкой
/// (строгого периода в потоке нет ⇒ автокорреляцией маячок не снимается).
///
/// **П5 (батарея).** Диапазон зависит от того, что пир объявил своим `max_idle_timeout`:
///
/// * `relaxed = false` — [`KA_STRICT_MS`], прежние 2–4 с. Так мы говорим со старым пиром (он не
///   прислал подсказку) — у него idle-таймаут 15 с, и редкий маячок просто рвал бы туннель в
///   простое: эффективный таймаут равен МИНИМУМУ из объявленных сторонами.
/// * `relaxed = true` — [`KA_RELAXED_MS`]. Пир объявил ≥ [`RELAXED_MIN_IDLE`], значит два-три
///   пропущенных маячка соединение переживает. Это главный выигрыш в батарее: LTE-модем держит
///   RRC_CONNECTED ещё 5–10 с после передачи, поэтому пакет раз в 2–4 с не давал ему уйти в idle
///   ВООБЩЕ, а раз в ~21 с — даёт.
///
/// Верхняя граница расслабленного режима намеренно ниже 30 с: у CGNAT UDP-биндинг живёт обычно
/// 30–60 с, и маячок должен успеть его обновить (RFC 4787 требует обновления по ИСХОДЯЩЕМУ
/// трафику; на входящий полагаться нельзя). Отсюда же 15–28, а не 20–45 из первоначального
/// предложения: разница в батарее между ними мала, а риск «телефон разбудили — интернета нет,
/// пока не отработает watchdog» реален.
fn keepalive_delay(relaxed: bool) -> std::time::Duration {
    use rand::Rng;
    let ms = match relaxed {
        true => rand::thread_rng().gen_range(KA_RELAXED_MS),
        false => rand::thread_rng().gen_range(KA_STRICT_MS),
    };
    std::time::Duration::from_millis(ms)
}

/// Совместимый режим: пир не подтвердил длинный idle-таймаут (старая версия либо своя политика).
const KA_STRICT_MS: std::ops::RangeInclusive<u64> = 2_000..=4_000;
/// П5: редкий маячок — включается только по подсказке пира (см. [`keepalive_delay`]).
const KA_RELAXED_MS: std::ops::RangeInclusive<u64> = 15_000..=28_000;
/// Какой объявленный пиром `max_idle_timeout` разрешает редкий маячок. 60 с ⇒ даже верхняя
/// граница 28 с оставляет запас на два пропущенных маячка подряд.
const RELAXED_MIN_IDLE: std::time::Duration = std::time::Duration::from_secs(60);

/// П5: разрешён ли редкий keep-alive при таком объявлении пира. Вынесено ради теста —
/// ошибка здесь проявляется не в лаборатории, а разрывами туннеля в простое у людей.
fn keepalive_relaxed(peer_idle: Option<std::time::Duration>) -> bool {
    peer_idle.is_some_and(|d| d >= RELAXED_MIN_IDLE)
}

/// Длина случайного тела keep-alive: на UDP-пути L1 всё равно добьёт пакет паддингом до общего
/// распределения длин (C2), но на obfs-TCP-пути record'ы идут потоком, и постоянная длина маячка
/// была бы отдельной сигнатурой.
fn keepalive_body_len() -> usize {
    use rand::Rng;
    rand::thread_rng().gen_range(0..=96)
}

// ─────────────────────────── счётчики трафика туннеля (индикация скорости в UI) ───────────────
// Монотонные (за время жизни процесса) счётчики inner-байтов, прошедших через туннель НА КЛИЕНТЕ.
// UI показывает по ним текущую скорость — то есть дельту между двумя опросами, делённую на время;
// именно поэтому счётчики не сбрасываются ни на реконнекте, ни на смене профиля: сброс дал бы
// отрицательную дельту и скачок в индикаторе. Итогов за сессию/сутки здесь нет намеренно — это уже
// история пользовательского трафика, которую клиенту незачем накапливать.
//
// Считаем полезную нагрузку (inner IP-пакеты), без QUIC/AEAD/obfs-оверхеда: человек сравнивает
// цифру со скоростью своей загрузки, а не с расходом канала.
//
// На EXIT (`egress = Some`) счётчики НЕ ведутся: там это был бы учёт чужого трафика в общей на
// процесс переменной — против no-logs (см. `citadel_quic::debug_logs`) и бессмысленно при N клиентах.

static TRAFFIC_RX: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static TRAFFIC_TX: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

// ─────────────────── П1: маркер пользовательского трафика для тайминг-шейпинга ────────────────
// Счётчик inner-датаграмм (`CTX_RAW_IP`) в ОБЕ стороны — единственный источник истины для вопроса
// «есть ли сейчас что маскировать». До этого chaff взводился любой выпущенной датаграммой, включая
// собственный keep-alive: простаивающий туннель раз в 2–4 с сам себе открывал окно и слал ~2.2 ГБ
// мусора в сутки, маскируя ничто (docs/COVER-TRAFFIC-BATTERY-2026-08.md §2.2).
//
// Почему это НЕ противоречит no-logs на exit'е (в отличие от TRAFFIC_RX/TX, которые там не
// ведутся): здесь нет ни байтов, ни адресов, ни разделения по клиентам — одно монотонное число в
// памяти процесса, из которого шейпер узнаёт только «с прошлого тика что-то прошло». Наружу оно не
// выходит и в лог не печатается.
static USER_PKTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[inline]
pub(crate) fn note_user_packet() {
    USER_PKTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// П1: снимок маркера пользовательского трафика (см. `obfs_socket::pace_tick`).
pub(crate) fn user_packets() -> u64 {
    USER_PKTS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Снимок счётчиков трафика туннеля: `(принято, отправлено)` в байтах полезной нагрузки.
/// Монотонны за время жизни процесса — вызывающий считает скорость по дельте двух снимков.
pub fn traffic_bytes() -> (u64, u64) {
    use std::sync::atomic::Ordering::Relaxed;
    (TRAFFIC_RX.load(Relaxed), TRAFFIC_TX.load(Relaxed))
}

/// Окно pump-watchdog и минимум отправленных датаграмм в окне, при котором «0 принятых»
/// трактуется как мёртвый путь. Простой отсекается порогом tx (мало шлём — путь не трогаем), и
/// именно поэтому окно не пришлось растягивать под редкий keep-alive (П5): маячок один на 15–28 с
/// до порога не дотягивает, а под нагрузкой окно набирается за доли секунды.
const WATCHDOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(8);
const WATCHDOG_TX_MIN: u64 = 12;

/// Шаг watchdog. Окно диагностики осталось прежним ([`WATCHDOG_INTERVAL`] = [`TICKS_PER_WINDOW`]
/// тиков), но отказ сокета (см. [`uplink_is_stalled`]) проверяется на КАЖДОМ тике: ждать полного
/// окна там нечего, а цена ожидания — секунды мёртвого туннеля у человека в руках.
const WATCHDOG_TICK: std::time::Duration = std::time::Duration::from_secs(2);
const TICKS_PER_WINDOW: u32 = 4;
/// Порог отданных датаграмм НА ТИК для быстрой проверки (ниже — простой, беды не видно).
const STALL_TX_MIN: u64 = 12;
/// Сколько тиков подряд держится затор, прежде чем рвать транспорт (2 тика = 4с).
const STALL_TICKS: u32 = 2;

/// Сколько окон подряд путь должен быть односторонним, прежде чем рвать транспорт. Одно окно —
/// это ещё может быть всплеск потерь на мобильной сети; два подряд (16с) означают, что канал в эту
/// сторону не работает, и ждать дальше бессмысленно — человек всё это время видит «Защищено» и
/// пустой интернет.
const ONE_WAY_WINDOWS: u32 = 2;

/// Чем закончился `pump` (нужно циклу реконнекта, см. `vpn::VpnController::connect`).
///
/// До этого data-plane отдавал только `()`, и цикл не мог отличить «пир закрыл соединение» от
/// «наши пакеты перестали доходить». Разница принципиальна: во втором случае повтор ТОГО ЖЕ
/// транспорта упирается ровно в то же самое, и абонент получает бесконечное «переподключение».
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PumpExit {
    /// Транспорт был жив, но наши датаграммы переставали доходить до пира (потери/чёрная дыра по
    /// MTU/затор своей же очереди) — лечится сменой транспорта, а не повтором.
    pub uplink_dead: bool,
    /// В туннель уходили пакеты, адресованные самому exit'у: собственный транспорт завернулся в
    /// собственный туннель (не сработал `VpnService.protect` / нет bypass-маршрута). Внешне это
    /// неотличимо от мёртвой сети, но причина НАША — и цикл реконнекта не должен записывать сеть в
    /// «не несёт UDP» надолго, иначе наша же поломка тихо маскируется выбором другого транспорта.
    pub looped: bool,
}

/// Что клиентский data-plane знает о СОБСТВЕННОМ канале. Нужно не только логу: операции, которые
/// ходят ПО туннелю (admin-плоскость «Абоненты»), падают по той же причине, что и «интернета нет»,
/// и назвать её обязан движок — иначе экран показывает «не удалось», а человек гадает, сломан ли
/// сервер, ссылка или сеть.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum DataPath {
    /// Ещё не мерили: сессии нет либо в окне не было заметного трафика.
    Unknown = 0,
    /// Обратный трафик идёт — канал рабочий.
    Ok = 1,
    /// Наши пакеты не доезжают до exit'а (потери/узкий MTU пути/затор собственной очереди).
    UplinkDead = 2,
    /// До exit'а доезжают, обратно тихо: дропает exit либо молчит назначение.
    ExitSilent = 3,
}

/// Последний вердикт клиентского watchdog о канале (см. [`DataPath`]). Глобальный на процесс —
/// как и счётчики трафика: клиентская сессия в процессе одна. На exit'е НЕ ведётся (там это был бы
/// учёт чужого трафика, см. no-logs).
static DATA_PATH: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Снимок состояния клиентского канала.
pub fn data_path() -> DataPath {
    match DATA_PATH.load(std::sync::atomic::Ordering::Relaxed) {
        1 => DataPath::Ok,
        2 => DataPath::UplinkDead,
        3 => DataPath::ExitSilent,
        _ => DataPath::Unknown,
    }
}

fn set_data_path(v: DataPath) {
    DATA_PATH.store(v as u8, std::sync::atomic::Ordering::Relaxed);
}

/// Разбор окна watchdog на КЛИЕНТЕ, когда обратных датаграмм нет, а транспорт жив: наши пакеты
/// вообще не доходят до exit'а — или доходят, а exit молчит? Раньше этой развилки не было, и в лог
/// уезжал единственный вердикт «похоже, пакеты дропает exit», который в первом случае просто
/// врёт и уводит разбор в сторону (ровно на этом застряла прошлая сессия).
///
/// `enqueued` — сколько датаграмм мы отдали quinn; `on_wire` — сколько он реально положил на
/// провод (`frame_tx.datagram`); `lost` — сколько отправленных пакетов он объявил потерянными;
/// `acked` — сколько ACK-фреймов пришло от пира (`frame_rx.acks`).
/// Разница `enqueued - on_wire` — не «где-то потерялись»: при заторе quinn МОЛЧА вытесняет из
/// очереди датаграмм самые старые (`datagram_send_buffer_size`), то есть успешный `send_datagram`
/// ничего не обещает. Поэтому «отправлено N» в старом сообщении тоже было неправдой.
///
/// Решающая улика здесь — `acked`, а не соотношение отданного и ушедшего: **ACK-фрейм пир шлёт
/// только за пакеты, которые до него ДОЕХАЛИ**. Ноль ACK'ов за окно активной отправки означает,
/// что канал не несёт наши пакеты (или их подтверждения), сколько бы мы ни отдали в транспорт;
/// поток ACK'ов, наоборот, доказывает, что пакеты у exit'а — и тогда тишина обратно уже не про
/// транспорт. Прежняя версия судила по одному лишь соотношению и потому не отличала мёртвый путь
/// от УЗКОГО (медленная сеть: очередь тоже не рассасывается, но всё доезжает).
fn uplink_is_dead(enqueued: u64, on_wire: u64, lost: u64, acked: u64) -> bool {
    // Ушедшее не подтверждено НИ РАЗУ: до пира не доезжает (либо не доезжают его ответы).
    let unacked = on_wire > 0 && acked == 0;
    // Больше половины даже не ушло в транспорт, и подтверждений нет: очередь встала намертво.
    // Без проверки `acked` сюда попадала и здоровая узкая сеть, где очередь не рассасывается
    // просто потому, что канал медленный.
    let stalled = on_wire * 2 < enqueued && acked == 0;
    // Половина и больше из ушедшего объявлена потерянной: путь их глотает.
    let lossy = on_wire > 0 && lost * 2 >= on_wire;
    unacked || stalled || lossy
}

/// Быстрая (тиковая) проверка одной беды: **датаграммы перестали уходить, и пир этого не
/// подтверждает**. Две локальные причины дают одну и ту же картину счётчиков, и разделять их здесь
/// незачем — реакция общая (сменить транспорт):
///   * сокет не берёт наши пакеты (quinn зовёт `poll_transmit`, только пока UDP-сокет пишется; на
///     Android очередь устройства может перестать принимать — `ENOBUFS`);
///   * cwnd схлопнулся и не открывается, потому что подтверждать нечего — путь не несёт пакеты.
///
/// Полевой лог: за тик отдано 113 датаграмм, на провод ушло 2, потеряно 0. Потерь нет ⇒ пакеты
/// либо не отправлялись вовсе, либо их некому было объявить потерянными.
///
/// `acked == 0` — обязательное условие, и именно оно отделяет беду от УЗКОГО канала. На медленной
/// сети (2G/перегруженный Wi-Fi) картина «отдано 113, ушло 2, потерь 0» совершенно нормальна:
/// в канал физически влезает пара пакетов за тик. Но там они ДОЕЗЖАЮТ, и пир их подтверждает —
/// ACK'и идут. Без этой проверки детектор рвал исправную (пусть и медленную) сессию, что на
/// устройстве выглядело как «каждое подключение обрывается и уходит на 443».
///
/// Это НЕ транзиент: ждать полные два окна (16с) значит держать человека в мёртвом туннеле,
/// который лечится сменой транспорта за секунду. Поэтому сигнатуре хватает 2 тиков (4с).
fn uplink_is_stalled(enqueued: u64, on_wire: u64, lost: u64, acked: u64) -> bool {
    enqueued >= STALL_TX_MIN && lost == 0 && acked == 0 && on_wire * 8 < enqueued
}

/// Решение watchdog по дельтам за окно. Путь считаем мёртвым, только если ОДНОВРЕМЕННО:
///   * отправлено ≥ порога датаграмм (мы реально под нагрузкой, а не в простое);
///   * принято 0 датаграмм (обратного туннельного трафика нет);
///   * `transport_rx == 0` — на транспорте не принято НИ ОДНОГО QUIC-пакета.
///
/// Третье условие критично (без него — ложные разрывы и реконнект-шторм): пока с той стороны идут
/// ACK'и/ответы на keep-alive, путь ЖИВ, а «0 датаграмм» означает, что наши inner-пакеты дропает
/// сам exit (egress-фильтр F2, анти-спуфинг, недостижимое назначение) либо ответа не даёт хост
/// назначения. Рвать в этом случае транспорт бессмысленно: новая сессия упрётся в то же самое, а
/// пользователь получит бесконечное «переподключение». Настоящая чёрная дыра пути (MTU/NAT-rebind
/// после смены сети) даёт `transport_rx == 0` — её мы по-прежнему ловим, и quinn idle-timeout тут
/// не помощник (при keep-alive он молчит до 15с, а мы рвём за 8с).
fn watchdog_trips(sent: u64, recvd: u64, transport_rx: u64) -> bool {
    sent >= WATCHDOG_TX_MIN && recvd == 0 && transport_rx == 0
}

/// Клиентская сторона pump: что движок знает о собственном пути. Диагностика (чтобы «туннель
/// поднят, а трафика нет» не выглядело загадкой — exit дропает такие пакеты молча, и клиент обязан
/// объяснить причину сам) И вход для F8: `assigned` — единственный адрес, на который клиент
/// принимает пакеты из туннеля (см. [`crate::clientfw`]).
pub struct ClientPath {
    /// Назначенный exit'ом адрес: пакет с другим src exit дропнет анти-спуфингом (S0.2/H3).
    pub assigned: [u8; 4],
    /// Куда идёт СОБСТВЕННЫЙ транспорт (см. [`ExitTransport`]). Пакет из TUN, адресованный туда, —
    /// петля: на Android так выглядит незащищённый (`VpnService.protect`) сокет, на desktop —
    /// отсутствие bypass-маршрута к exit. Такая петля убивает сессию за секунды и раньше читалась
    /// в логе лишь как «чужой src».
    pub exit: Option<ExitTransport>,
}

/// Адрес и порт транспорта клиента — то, что отличает НАСТОЯЩУЮ петлю от санкционированного
/// трафика к тому же хосту.
///
/// **Почему одного адреса мало (полевой разбор, август 2026).** В установке «всё на одном сервере»
/// издатель токенов живёт на том же публичном адресе, что и exit, а фоновая дозаправка кошелька
/// (§7.1) идёт СКВОЗЬ туннель НАРОЧНО — чтобы издатель видел адрес exit'а, а не абонента. Ровно на
/// это рассчитан и серверный G1: `Citadel_ALLOW_DSTS` держит token-порт издателя открытым из
/// туннеля, закрыв на том же адресе всё остальное. Детектор же сверял только адрес — и каждая
/// фоновая дозаправка (60–70 пакетов TLS+VOPRF) печаталась как «ПЕТЛЯ … VpnService.protect не
/// сработал». Диагноз при этом ЛОЖНЫЙ и дорогой: он отправляет разбираться в protect-инвариант,
/// которым сессия как раз в порядке, и обесценивает сообщение на случай настоящей петли.
///
/// Настоящая петля — это наш транспорт, вернувшийся в свой же туннель, то есть пакет к
/// `addr:port` того самого сокета: UDP при PQ-QUIC, TCP при obfs-fallback. Порт транспорта у
/// издателя другой, поэтому сверки `addr` + `port` + протокола достаточно, чтобы отделить одно от
/// другого без знания адреса издателя (он живёт в другом крейте).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExitTransport {
    /// IPv4 транспортного пира (exit).
    pub addr: [u8; 4],
    /// Порт, на который реально говорит транспорт: UDP-порт туннеля либо TCP-порт obfs-fallback.
    pub port: u16,
    /// Транспорт идёт поверх obfs-TCP (иначе — QUIC/UDP). Задаёт, петлёй какого протокола считать.
    pub over_tcp: bool,
}

impl ExitTransport {
    /// Пакет из TUN — это наш собственный транспорт, завернувшийся в собственный туннель?
    fn is_self_loop(&self, v: &citadel_masque::ip::Ipv4View<'_>) -> bool {
        let want_proto = if self.over_tcp { 6 } else { 17 };
        v.dst == self.addr
            && v.proto == want_proto
            && citadel_masque::ip::l4_dport(v) == Some(self.port)
    }
}

/// Двунаправленная перекачка TUN ⇄ транспорт (QUIC DATAGRAM либо obfs-TCP record).
/// `egress = Some(назначенный клиенту адрес)` включает egress-политику exit: анти-спуфинг
/// inner-src (S0.2/H3), default-deny не-IPv4 и F2 (дроп во внутренние/служебные сети); `None`
/// (клиент) — без фильтра. `rate` (на exit) ограничивает ОБА направления token-bucket'ами
/// (F7/D3 + M-3-bis: `up` — в `Inbound`, `down` — в sender-задаче ниже).
/// `policy` (только exit) — admin-VIP мимо F2 (C7.2) и список инфраструктурных адресов, к которым
/// из туннеля не форвардим вовсе (G1/G2); на клиенте — [`EgressPolicy::default`], то есть пусто.
///
/// TUN читается/пишется через `TunIo` — блокирующие recv/send изолированы в отдельных
/// потоках и мостятся в async каналами (платформа туннеля движку не важна).
pub async fn pump(
    tunnel: Tunnel,
    tun: Arc<dyn TunIo>,
    egress: Option<[u8; 4]>,
    // Что движок знает о собственном пути — только на КЛИЕНТЕ (взаимоисключимо с `egress`) и
    // только для диагностики (см. [`ClientPath`]).
    client: Option<ClientPath>,
    rate: RateLimits,
    policy: EgressPolicy,
    // Источник return-пакетов (TUN→сеть). На КЛИЕНТЕ — `None`: pump сам читает свой TUN. На EXIT —
    // `Some(rx)` из [`ExitTunRouter`]: единый reader общего exit-TUN демультиплексирует пакеты по
    // inner-dst нужному клиенту. Без этого N pump'ов на общем TUN воровали бы друг у друга return-
    // трафик (гонка multi-client → потеря/медленно/watchdog-шторм при >1 клиента).
    return_rx: Option<tokio::sync::mpsc::Receiver<Vec<u8>>>,
) -> Result<PumpExit> {
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
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
    // Роль: на exit'е (`egress = Some`) диагностический вывод про трафик клиента подчиняется
    // no-logs (`Citadel_DEBUG_LOG`), на клиенте — печатается всегда (это устройство пользователя,
    // лог нужен ему самому и панели диагностики).
    let is_exit = egress.is_some();
    // Счётчики скорости — только на клиенте (см. TRAFFIC_RX/TRAFFIC_TX).
    let count_traffic = !is_exit;
    macro_rules! pump_log {
        ($($t:tt)*) => {
            if !is_exit || crate::debug_logs() {
                eprintln!($($t)*);
            }
        };
    }

    // П5: что пир объявил своим idle-таймаутом — от этого зависит частота маячка (см. ниже).
    let Tunnel { conn, peer_idle, .. } = tunnel;
    let send_conn = conn.clone();
    let send_tx = tx_count.clone();
    // Сколько inner-пакетов не-IPv4 мы отбросили локально (см. ниже) — для диагностики окна.
    let non_v4 = Arc::new(AtomicU64::new(0));
    let send_non_v4 = non_v4.clone();
    // Пакеты, ушедшие в туннель с адресом источника, который exit'у не назначен нам (см. ниже),
    // и последний такой адрес — чтобы в одной строке лога назвать И симптом, И виновника.
    let bad_src = Arc::new(AtomicU64::new(0));
    let bad_src_last = Arc::new(AtomicU32::new(0));
    let (send_bad_src, send_bad_src_last) = (bad_src.clone(), bad_src_last.clone());
    // Из них — адресованные самому exit'у: это уже не «чужой src», а петля собственного транспорта.
    let self_loop = Arc::new(AtomicU64::new(0));
    let send_self_loop = self_loop.clone();
    let (client_assigned, client_exit) = match &client {
        Some(c) => (Some(c.assigned), c.exit),
        None => (None, None),
    };
    // F8 (H-4/аудит-5): клиентский inbound-фильтр — «сервер не открывает соединений к абоненту».
    // Живёт только на КЛИЕНТЕ (`client = Some`); свою, обратную политику exit держит в `Inbound`.
    // Один объект на сессию, общий для sender-задачи (отмечает наши исходящие порты/протоколы) и
    // receiver-задачи (решает по входящим) — см. [`crate::clientfw`].
    let cfw = client
        .as_ref()
        .map(|c| Arc::new(crate::clientfw::ClientFilter::new(c.assigned)));
    if let Some(f) = &cfw {
        if f.audit_only() {
            eprintln!(
                "[pump] ⚠ F8 в режиме наблюдения (Citadel_INBOUND_OPEN=1): входящее из туннеля \
                 НЕ фильтруется, только считается"
            );
        }
    }
    let send_cfw = cfw.clone();
    // M-3-bis: bucket обратного направления (интернет → клиент). Только на exit'е: на клиенте
    // `rate` пуст, а его собственный upload резать незачем. Живёт в sender-задаче, потому что
    // именно она отдаёт клиенту return-трафик из демукса (`return_rx`); дроп здесь TCP переживает
    // как обычную потерю и сам сбрасывает окно.
    let mut down_bucket = rate.down.map(|c| TokenBucket::new(c, Instant::now()));
    let mut down_dropped = 0u64;
    let mut down_dropped_bytes = 0u64;
    let sender = tokio::spawn(async move {
        while let Some(pkt) = tun_to_net_rx.recv().await {
            // S2.2/A2: туннель IPv4-only (адрес назначается v4, exit по default-deny дропает
            // не-IPv4). На Android в TUN намеренно заведён blackhole-маршрут `::/0` (анти-leak),
            // поэтому весь IPv6 приложений сыплется сюда. Гнать его на exit бессмысленно (там он
            // всё равно умрёт), зато он ломает диагностику живости: «шлём много, не принимаем
            // ничего» = ложное срабатывание watchdog → реконнект-шторм. Дропаем на месте и считаем.
            let Some(v4) = ip::parse_ipv4(&pkt) else {
                send_non_v4.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            // F8: наш исходящий порт/протокол открывает обратный путь ЕГО ответам — и только им.
            if let Some(f) = &send_cfw {
                f.note_egress(&v4);
            }
            // Пакет из TUN, адресованный СОКЕТУ нашего транспорта, — петля (наш сокет к exit'у не
            // исключён из туннеля). Проверка стоит ОТДЕЛЬНО от «чужого src», а не внутри неё, как
            // было: когда маршрут к exit уходит в TUN, ядро выбирает адресом источника адрес самого
            // TUN — то есть НАШ назначенный, и петля с проверкой на чужой src не считалась вовсе.
            // Именно этот счётчик отличает «сеть плохая» от «мы сами завернули свой транспорт в
            // свой туннель». Сверяется адрес И порт И протокол — почему не только адрес, см.
            // [`ExitTransport`] (иначе санкционированная дозаправка кошелька через туннель на
            // совмещённом деплое читалась как петля).
            if client_exit.is_some_and(|t| t.is_self_loop(&v4)) {
                send_self_loop.fetch_add(1, Ordering::Relaxed);
            }
            // Диагностика (не фильтр): src ≠ назначенный адрес ⇒ exit дропнет пакет анти-спуфингом
            // и ответа не будет НИКОГДА. Отправляем всё равно — политику решает exit, а клиент лишь
            // обязан объяснить человеку «туннель поднят, а трафика нет» вместо загадочных нулей.
            if let Some(mine) = client_assigned {
                if v4.src != mine {
                    send_bad_src.fetch_add(1, Ordering::Relaxed);
                    send_bad_src_last.store(u32::from_be_bytes(v4.src), Ordering::Relaxed);
                }
            }
            // M-3-bis/F7: лимит «вниз» (exit → клиент). Ровно та же механика, что у `Inbound`,
            // и та же реакция: дроп, а не буферизация (буфер на медленного клиента — это уже
            // память exit'а, которую и хотел бы съесть злоупотребляющий абонент).
            if let Some(b) = down_bucket.as_mut() {
                if !b.allow(TokenBucket::packet_cost(pkt.len()), Instant::now()) {
                    down_dropped += 1;
                    down_dropped_bytes += pkt.len() as u64;
                    if down_dropped == 1 || down_dropped.is_multiple_of(50) {
                        crate::dlog!(
                            "[exit] F7↓: rate-limit обратного направления — дропнуто {} пакетов / {} б",
                            down_dropped, down_dropped_bytes
                        );
                    }
                    continue;
                }
            }
            let dg = datagram::encode(datagram::CTX_RAW_IP, &pkt);
            match send_conn.send_datagram(bytes::Bytes::from(dg)) {
                Ok(()) => {
                    send_tx.fetch_add(1, Ordering::Relaxed);
                    note_user_packet(); // П1: это трафик человека — ему и открывать окно chaff
                    if count_traffic {
                        TRAFFIC_TX.fetch_add(pkt.len() as u64, Ordering::Relaxed);
                    }
                }
                Err(e) => pump_log!("[pump] датаграмма отброшена ({} б): {e}", pkt.len()),
            }
        }
    });
    let recv_conn = conn.clone();
    let recv_stop = stop.clone();
    let recv_rx = rx_count.clone();
    let recv_cfw = cfw.clone();
    let receiver = tokio::spawn(async move {
        let mut inb = Inbound::with_policy(egress, rate.up, policy);
        loop {
            match recv_conn.read_datagram().await {
                Ok(dg) => {
                    // Счётчик обратного ТУННЕЛЬНОГО трафика (для watchdog) — только `CTX_RAW_IP`.
                    // M-8: keep-alive (`CTX_KEEPALIVE`) сюда намеренно НЕ входит, иначе он
                    // маскировал бы диагностику «датаграммы уходят, ответов нет»: пир слал бы
                    // маячки, счётчик рос бы, и клиент молчал бы о том, что трафик не ходит.
                    // Живость самого пути и без того меряется `udp_rx` на транспорте.
                    if let Some((ctx, pkt)) = datagram::decode(&dg) {
                        if ctx != datagram::CTX_RAW_IP {
                            // Чужой/служебный контекст в TUN не попадает, но ресурсы тратит —
                            // засчитываем в per-client лимит (иначе флуд keep-alive'ами обходил бы
                            // F7 целиком: `Inbound::accept` вызывается только для полезных пакетов).
                            inb.charge(dg.len());
                            continue;
                        }
                        recv_rx.fetch_add(1, Ordering::Relaxed);
                        // F8 (клиент): пропускаем только ответы на собственный трафик. Дропы
                        // считаются и печатаются окном (см. watchdog) — это ещё и сигнал о
                        // недобросовестном exit'е, который пытается «позвонить» на устройство.
                        if recv_cfw.as_ref().is_some_and(|f| !f.accept(pkt)) {
                            continue;
                        }
                        if inb.accept(pkt) {
                            // П1: приём тоже трафик человека — исходящий ACK-поток скачивания
                            // маскировать надо ровно так же, как отправку.
                            note_user_packet();
                            if count_traffic {
                                TRAFFIC_RX.fetch_add(pkt.len() as u64, Ordering::Relaxed);
                            }
                            if net_to_tun_tx.send(pkt.to_vec()).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    // L-15: reason-фраза приходит от пира — печатаем только обеззараженной.
                    pump_log!("[pump] соединение закрыто: {}", crate::peer_text(e));
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
    let wd_non_v4 = non_v4.clone();
    let (wd_bad_src, wd_bad_src_last) = (bad_src.clone(), bad_src_last.clone());
    let wd_self_loop = self_loop.clone();
    let wd_cfw = cfw.clone();
    let wd_exit = client_exit;
    let wd_mine = client_assigned;
    // Диагностику окна печатает только КЛИЕНТ (`egress == None`): на exit'е это был бы лог о
    // трафике пользователя — против no-logs (см. handle_client).
    let wd_client = egress.is_none();
    if wd_client {
        // Новая сессия — прежний вердикт о канале недействителен (иначе «Абоненты» объясняли бы
        // свежий отказ диагнозом прошлой, уже оборванной сессии).
        set_data_path(DataPath::Unknown);
    }
    // Итог для вызывающего: путь оказался односторонним (см. [`PumpExit::uplink_dead`]).
    let uplink_dead = Arc::new(AtomicBool::new(false));
    let wd_uplink_dead = uplink_dead.clone();
    let watchdog = tokio::spawn(async move {
        // Базовые снимки СЧЁТЧИКОВ ТРАНСПОРТА берём здесь, а не с нуля: `conn.stats()` считает от
        // начала соединения, и хендшейк уже набил в них свои пакеты, ACK'и и потери. С нулей
        // первое окно получало чужую дельту — и, в частности, `transport_rx` первого окна всегда
        // был > 0 (хендшейк!), то есть путь, умерший сразу после установки сессии, первое окно
        // проскакивал. Счётчики самого pump (`wd_tx`/`wd_rx`) и так стартуют с нуля.
        let st0 = wd_conn.stats();
        let (mut seen_tx, mut seen_rx, mut seen_v6) = (0u64, 0u64, 0u64);
        let mut seen_urx = st0.udp_rx.datagrams;
        let (mut seen_bad_src, mut seen_self_loop) = (0u64, 0u64);
        // Реально ушедшие на провод датаграммы, объявленные потерянными пакеты и принятые
        // ACK-фреймы — предыдущий снимок (считаем дельты за окно, как и всё остальное здесь).
        let (mut seen_wire, mut seen_lost) = (st0.frame_tx.datagram, st0.path.lost_packets);
        let mut seen_acks = st0.frame_rx.acks;
        // UDP-пакеты и байты транспорта — для среднего размера ушедшего пакета (см. ниже).
        let (mut seen_utx, mut seen_ubytes) = (st0.udp_tx.datagrams, st0.udp_tx.bytes);
        // Сколько окон подряд путь односторонний (см. ONE_WAY_WINDOWS).
        let mut one_way = 0u32;
        // F8: предыдущий снимок счётчиков клиентского inbound-фильтра (не-IPv4, чужой dst, без
        // запроса, ICMP-тип) — печатаем дельту за окно, а не итог за сессию.
        let mut seen_fw = (0u64, 0u64, 0u64, 0u64);
        // Сколько chaff-байт сгенерировала маскировка — предыдущий снимок (см. §6.2 ниже).
        let mut seen_chaff = crate::shaping_stats().chaff_bytes;
        // Тиковые снимки (быстрая проверка «датаграммы не уходят») — отдельные от оконных: свой шаг.
        let (mut tick_tx, mut tick_rx) = (0u64, 0u64);
        let (mut tick_wire, mut tick_lost, mut tick_acks) =
            (st0.frame_tx.datagram, st0.path.lost_packets, st0.frame_rx.acks);
        let (mut tick_utx, mut tick_urx) = (st0.udp_tx.datagrams, st0.udp_rx.datagrams);
        let (mut stalled_ticks, mut tick_no) = (0u32, 0u32);
        loop {
            tokio::time::sleep(WATCHDOG_TICK).await;
            if wd_stop.load(Ordering::Acquire) {
                break;
            }
            let st = wd_conn.stats();
            // ── быстрая проверка (каждый тик): датаграммы не уходят и пир их не подтверждает ──
            {
                let (tx, rx, wire, lost, acks, utx, urx) = (
                    wd_tx.load(Ordering::Relaxed),
                    wd_rx.load(Ordering::Relaxed),
                    st.frame_tx.datagram,
                    st.path.lost_packets,
                    st.frame_rx.acks,
                    st.udp_tx.datagrams,
                    st.udp_rx.datagrams,
                );
                let (d_tx, d_rx, d_wire, d_lost, d_acks, d_utx, d_urx) = (
                    tx.wrapping_sub(tick_tx),
                    rx.wrapping_sub(tick_rx),
                    wire.wrapping_sub(tick_wire),
                    lost.wrapping_sub(tick_lost),
                    acks.wrapping_sub(tick_acks),
                    utx.wrapping_sub(tick_utx),
                    urx.wrapping_sub(tick_urx),
                );
                (tick_tx, tick_rx, tick_wire, tick_lost) = (tx, rx, wire, lost);
                (tick_acks, tick_utx, tick_urx) = (acks, utx, urx);
                if wd_client && d_rx == 0 && uplink_is_stalled(d_tx, d_wire, d_lost, d_acks) {
                    stalled_ticks += 1;
                    if stalled_ticks >= STALL_TICKS {
                        // Причину называем по счётчикам транспорта, а не по догадке. Раньше здесь
                        // стояло безусловное «это отказ ОТПРАВКИ» — при мёртвом ПУТИ (пакеты
                        // уходят, ответов нет) оно врало ровно так же, как до него врал вердикт
                        // «дропает exit». Оба случая лечатся сменой транспорта, но в логе они
                        // должны выглядеть по-разному, иначе разбор снова уедет не туда.
                        let why = if d_utx == 0 {
                            "сокет вообще не взял ни одного пакета (очередь устройства/нет \
                             маршрута) — отказ ОТПРАВКИ на устройстве"
                        } else {
                            "пакеты в сеть уходят, но ни один не подтверждён — путь их не несёт \
                             (или не несёт ответы)"
                        };
                        // Итоги «петли» и чужого src за сессию печатались ТОЛЬКО в оконной
                        // диагностике (8с) — а тик рвёт транспорт на 4-й секунде, так что до них
                        // дело не доходило ни разу. Между тем петля (наш собственный транспорт
                        // ушёл в собственный туннель — на Android это не сработавший
                        // `VpnService.protect`) даёт ровно эту картину счётчиков и является
                        // причиной, а не следствием: без неё разбор снова уедет в сеть/MTU.
                        let (loops, alien) = (
                            wd_self_loop.load(Ordering::Relaxed),
                            wd_bad_src.load(Ordering::Relaxed),
                        );
                        let culprit = if loops > 0 {
                            format!(
                                ". ВНИМАНИЕ: {loops} наших пакетов к самому exit'у ушли В ТУННЕЛЬ \
                                 (петля транспорта: на Android — не сработал VpnService.protect, \
                                 на desktop — нет bypass-маршрута). Это и есть причина"
                            )
                        } else if alien > 0 {
                            format!(
                                ". Кроме того, {alien} пакетов ушли с чужим src (exit дропает их \
                                 анти-спуфингом)"
                            )
                        } else {
                            String::new()
                        };
                        eprintln!(
                            "[pump] датаграммы не идут {}с подряд: за тик отдано {d_tx}, на провод \
                             ушло {d_wire}, потеряно 0, ACK'ов от exit 0 (UDP: отправлено {d_utx}, \
                             принято {d_urx}; RTT {} мс, cwnd {}, MTU {}) — {why}{culprit}; рву \
                             транспорт и иду другим",
                            WATCHDOG_TICK.as_secs() * STALL_TICKS as u64,
                            st.path.rtt.as_millis(),
                            st.path.cwnd,
                            st.path.current_mtu,
                        );
                        set_data_path(DataPath::UplinkDead);
                        wd_uplink_dead.store(true, Ordering::Release);
                        wd_conn.close(0u32.into(), b"citadel: send path stalled");
                        break;
                    }
                } else {
                    stalled_ticks = 0;
                }
            }
            tick_no += 1;
            if !tick_no.is_multiple_of(TICKS_PER_WINDOW) {
                continue; // оконная диагностика — раз в WATCHDOG_INTERVAL
            }
            let (tx, rx, v6, urx) = (
                wd_tx.load(Ordering::Relaxed),
                wd_rx.load(Ordering::Relaxed),
                wd_non_v4.load(Ordering::Relaxed),
                st.udp_rx.datagrams,
            );
            let (sent, recvd, dropped_v6, transport_rx) = (
                tx.wrapping_sub(seen_tx),
                rx.wrapping_sub(seen_rx),
                v6.wrapping_sub(seen_v6),
                urx.wrapping_sub(seen_urx),
            );
            (seen_tx, seen_rx, seen_v6, seen_urx) = (tx, rx, v6, urx);
            if watchdog_trips(sent, recvd, transport_rx) {
                eprintln!(
                    "[pump] watchdog: {sent} датаграмм отправлено, 0 принято и НИ ОДНОГО QUIC-пакета от exit за {}с — путь мёртв, рву транспорт",
                    WATCHDOG_INTERVAL.as_secs()
                );
                if wd_client {
                    set_data_path(DataPath::UplinkDead);
                }
                wd_conn.close(0u32.into(), b"citadel: data-path watchdog");
                break;
            }
            // Путь жив (QUIC-пакеты идут), но туннельного ответа нет. Раньше здесь стоял один
            // безусловный вердикт «похоже, пакеты дропает exit» — и он вводил в заблуждение ровно
            // в самом частом мобильном случае, когда до exit'а не доезжаем МЫ. Теперь окно
            // разбирается по счётчикам транспорта (см. [`uplink_is_dead`]), и у двух разных бед
            // разные и диагноз, и реакция.
            let (wire, lost, acked) = (
                st.frame_tx.datagram.wrapping_sub(seen_wire),
                st.path.lost_packets.wrapping_sub(seen_lost),
                st.frame_rx.acks.wrapping_sub(seen_acks),
            );
            (seen_wire, seen_lost, seen_acks) =
                (st.frame_tx.datagram, st.path.lost_packets, st.frame_rx.acks);
            // Средний размер УШЕДШЕГО пакета. Разделяет две локальные причины отказа отправки,
            // которые по остальным счётчикам неотличимы: путь не несёт КРУПНЫЕ пакеты (тогда
            // уходят только мелкие — среднее в районе сотен байт, и лечится это размером) либо
            // очередь устройства переполнена (`ENOBUFS` — уходит всё подряд, просто редко).
            let (utx, ubytes) = (
                st.udp_tx.datagrams.wrapping_sub(seen_utx),
                st.udp_tx.bytes.wrapping_sub(seen_ubytes),
            );
            (seen_utx, seen_ubytes) = (st.udp_tx.datagrams, st.udp_tx.bytes);
            let avg_wire = ubytes.checked_div(utx).unwrap_or(0);
            if wd_client && sent >= WATCHDOG_TX_MIN && recvd == 0 {
                let head = format!(
                    "[pump] обратных датаграмм нет {}с: в транспорт отдано {sent}, на провод ушло \
                     {wire}, объявлено потерянными {lost}, подтверждено ACK'ами {acked}, принято 0 \
                     (QUIC-пакетов от exit: {transport_rx}, RTT {} мс, MTU пути {}, cwnd {}, \
                     средний ушедший пакет {avg_wire} б из {utx})",
                    WATCHDOG_INTERVAL.as_secs(),
                    st.path.rtt.as_millis(),
                    st.path.current_mtu,
                    st.path.cwnd,
                );
                if uplink_is_dead(sent, wire, lost, acked) {
                    set_data_path(DataPath::UplinkDead);
                    one_way += 1;
                    eprintln!(
                        "{head} — НАШИ пакеты не доезжают до exit'а (потери/узкий MTU пути/затор \
                         собственной очереди), окно {one_way} из {ONE_WAY_WINDOWS}"
                    );
                    if one_way >= ONE_WAY_WINDOWS {
                        eprintln!(
                            "[pump] путь односторонний {}с подряд — рву транспорт, чтобы \
                             переподключиться поверх другого (obfs-TCP переживает узкий MTU и \
                             потери там, где QUIC/UDP чёрнодырится)",
                            WATCHDOG_INTERVAL.as_secs() * ONE_WAY_WINDOWS as u64
                        );
                        wd_uplink_dead.store(true, Ordering::Release);
                        wd_conn.close(0u32.into(), b"citadel: one-way data path");
                        break;
                    }
                } else {
                    // Наши датаграммы уходят и подтверждаются — значит, они у exit'а, и тишина
                    // обратно уже НЕ транспортная. Рвать нечего: новая сессия упрётся в то же
                    // самое (это и был реконнект-шторм, закрытый ранее).
                    set_data_path(DataPath::ExitSilent);
                    one_way = 0;
                    eprintln!(
                        "{head} — до exit'а наши пакеты доезжают, обратно тихо: дропает сам exit \
                         (egress-фильтр/лимит) либо молчит назначение; сессию не рву"
                    );
                }
            } else if recvd > 0 {
                one_way = 0; // обратный трафик пошёл — счётчик окон сбрасывается
                if wd_client {
                    set_data_path(DataPath::Ok);
                }
            }
            // Пакеты с чужим src: exit дропает их анти-спуфингом, поэтому «отправлено много,
            // принято 0» — не загадка, а следствие. Называем адрес: по нему сразу видно природу
            // (адрес локалки → NAT-заворот :53 без SNAT; 127.0.0.1 → петлевой bind; адрес другого
            // интерфейса → приложение прибито к нему явно).
            let bad_src = wd_bad_src.load(Ordering::Relaxed);
            let bad_delta = bad_src.wrapping_sub(seen_bad_src);
            seen_bad_src = bad_src;
            // Частный (и самый злой) случай «чужого src»: пакет адресован самому exit'у — значит,
            // в туннель заворачивается НАШ ЖЕ транспорт. Он так не доедет никогда, сессия умрёт за
            // секунды, и виноват не сервер, а маршрутизация на устройстве — говорим это прямо.
            let loops = wd_self_loop.load(Ordering::Relaxed);
            let loop_delta = loops.wrapping_sub(seen_self_loop);
            seen_self_loop = loops;
            if wd_client && loop_delta > 0 {
                let exit = wd_exit
                    .map(|t| {
                        format!(
                            "{}:{}/{}",
                            std::net::Ipv4Addr::from(t.addr),
                            t.port,
                            if t.over_tcp { "tcp" } else { "udp" }
                        )
                    })
                    .unwrap_or_else(|| "?".into());
                eprintln!(
                    "[pump] ПЕТЛЯ: {loop_delta} пакетов к сокету собственного транспорта ({exit}) \
                     ушли в туннель — транспорт заворачивается в собственный туннель. На Android \
                     это означает незащищённый сокет (VpnService.protect не сработал), на \
                     desktop — отсутствие bypass-маршрута к exit. Сессия в таком виде не выживет"
                );
            }
            if wd_client && bad_delta > 0 {
                let last = std::net::Ipv4Addr::from(wd_bad_src_last.load(Ordering::Relaxed));
                let mine = wd_mine.map(std::net::Ipv4Addr::from);
                eprintln!(
                    "[pump] ВНИМАНИЕ: {bad_delta} пакетов ушли в туннель с ЧУЖИМ адресом источника \
                     (последний {last}, а назначен нам {}) — exit обязан дропать такие \
                     анти-спуфингом (S0.2), ответа не будет. Причина обычно в подмене адреса \
                     назначения без подмены источника (заворот :53 без SNAT) или в приложении, \
                     привязанном к другому интерфейсу",
                    mine.map(|m| m.to_string()).unwrap_or_else(|| "?".into())
                );
            }
            // F8: что exit прислал нам сверх ответов на наш трафик. Ноль — норма; ненулевой
            // «не наш dst» или «без запроса» означает, что сервер пытается достучаться до
            // устройства (сканирование портов, пивот в локалку) — это прямой признак
            // скомпрометированного/недобросовестного exit'а, и человек должен об этом узнать.
            if let Some(f) = &wd_cfw {
                let (nv4, ours, uns, icmp, last) = f.counters();
                let d = (
                    nv4.wrapping_sub(seen_fw.0),
                    ours.wrapping_sub(seen_fw.1),
                    uns.wrapping_sub(seen_fw.2),
                    icmp.wrapping_sub(seen_fw.3),
                );
                seen_fw = (nv4, ours, uns, icmp);
                if wd_client && d.0 + d.1 + d.2 + d.3 > 0 {
                    let verb = if f.audit_only() { "ЗАСЧИТАНО (не дропнуто)" } else { "отброшено" };
                    eprintln!(
                        "[pump] F8: {verb} входящих из туннеля за {}с: не наш адрес {} (последний {}), \
                         без нашего запроса {}, ICMP не того типа {}, не-IPv4 {} — ответом на наш \
                         трафик это быть не может; исправный exit такого не присылает",
                        WATCHDOG_INTERVAL.as_secs(),
                        d.1,
                        last.map(|a| std::net::Ipv4Addr::from(a).to_string()).unwrap_or_else(|| "—".into()),
                        d.2,
                        d.3,
                        d.0,
                    );
                }
            }
            // §6.2 документа о маскировке: сколько мусора сгенерировали мы сами. Без этой строки
            // регрессия «маскировка снова жжёт трафик и батарею» замечается только по счёту за
            // мобильный интернет. Печатаем ТОЛЬКО когда chaff в этом окне реально шёл (при
            // выключенной маскировке и в простое — тишина).
            let sh = crate::shaping_stats();
            let chaff_delta = sh.chaff_bytes.wrapping_sub(seen_chaff);
            seen_chaff = sh.chaff_bytes;
            if wd_client && chaff_delta > 0 {
                eprintln!(
                    "[pump] маскировка: chaff {} КБ за {}с ({} пакетов всего, {} пропущено по \
                     бюджету, {} пробуждений pacer'а)",
                    chaff_delta / 1024,
                    WATCHDOG_INTERVAL.as_secs(),
                    sh.chaff_pkts,
                    sh.chaff_skipped,
                    sh.ticks,
                );
            }
            // Отдельный сигнал про IPv6: он уходит в blackhole по дизайну (туннель IPv4-only) —
            // без этой строки «интернет не работает» на v6-only ресурсах выглядит как загадка.
            if wd_client && dropped_v6 > 0 {
                eprintln!(
                    "[pump] IPv6 в туннель не идёт (IPv4-only): отброшено {dropped_v6} пакетов за {}с — \
                     это анти-leak blackhole (S2.2/A2), приложения должны ходить по IPv4",
                    WATCHDOG_INTERVAL.as_secs()
                );
            }
        }
    });

    // M-8/аудит-4: собственный keep-alive со СЛУЧАЙНЫМ интервалом. `keep_alive_interval` у quinn
    // фиксирован — в простое туннель превращался бы в маяк со строгой периодичностью, который
    // снимается автокорреляцией по десятку интервалов и не маскируется ни паддингом размеров
    // (I5/C2), ни шифрованием. Здесь интервал выбирается заново перед каждой отправкой (см.
    // [`keepalive_delay`]), поэтому периода в потоке нет. Пакет — датаграмма `CTX_KEEPALIVE`
    // со случайным телом: приёмник её отбрасывает (не `CTX_RAW_IP`), а L1 паддит её до того же
    // распределения длин, что и данные, — на проводе она неотличима от полезного трафика.
    //
    // Отправляем только в ПРОСТОЕ (за окно не ушло ни одной датаграммы) — под нагрузкой канал
    // и так не даёт quinn'у сработать по неактивности, а лишний пакет только жёг бы трафик.
    // `keep_alive_interval` (60 с) остаётся страховкой: он сбрасывается на каждом принятом пакете,
    // поэтому при живом маячке не срабатывает никогда, а если эта задача умрёт — соединение
    // продержится до idle-таймаута, а не развалится молча.
    //
    // **П5: на EXIT'е маячка нет вовсе.** Держать NAT-биндинг — забота той стороны, что за NAT и
    // на батарее; клиентский маячок и так сбрасывает idle-таймер обеих сторон. Встречный маячок
    // exit'а лишь будил бы радио телефона на приём (и вынуждал его отвечать ACK'ом) вдвое чаще,
    // ничего не добавляя к живости пути. Мёртвого клиента exit убирает по idle-таймауту.
    let ka_relaxed = keepalive_relaxed(peer_idle);
    let ka_conn = conn.clone();
    let ka_tx = tx_count.clone();
    let ka_stop = stop.clone();
    let keepalive = tokio::spawn(async move {
        if is_exit {
            return;
        }
        let mut seen = ka_tx.load(Ordering::Relaxed);
        loop {
            tokio::time::sleep(keepalive_delay(ka_relaxed)).await;
            if ka_stop.load(Ordering::Acquire) {
                break;
            }
            let now = ka_tx.load(Ordering::Relaxed);
            if now == seen {
                let mut body = vec![0u8; keepalive_body_len()];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut body);
                let dg = datagram::encode(datagram::CTX_KEEPALIVE, &body);
                if ka_conn.send_datagram(bytes::Bytes::from(dg)).is_err() {
                    break; // транспорт закрыт — держать нечего
                }
            }
            seen = now;
        }
    });

    let _guard = CancelGuard {
        stop,
        aborts: vec![
            sender.abort_handle(),
            receiver.abort_handle(),
            watchdog.abort_handle(),
            keepalive.abort_handle(),
        ],
        tun: tun.clone(),
    };
    // pump живёт, пока жив ТРАНСПОРТ: ждём завершения receiver (закрытие conn watchdog'ом/peer'ом
    // или отмену). sender и watchdog оборвёт CancelGuard при выходе (drop _guard). Важно НЕ ждать
    // sender: на EXIT он читает return_rx из демукса, а tx там держится до unregister (ПОСЛЕ pump) —
    // при закрытии транспорта его некому закрыть, try_join завис бы и pump не снял бы регистрацию.
    let _ = receiver.await;
    Ok(PumpExit {
        uplink_dead: uplink_dead.load(Ordering::Acquire),
        looped: self_loop.load(Ordering::Relaxed) > 0,
    })
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

    /// **Детектор петли отличает собственный транспорт от санкционированного трафика к тому же
    /// хосту** (полевой разбор, август 2026).
    ///
    /// На совмещённом деплое (`--role all`) издатель токенов живёт по тому же публичному адресу,
    /// что и exit, а фоновая дозаправка кошелька идёт СКВОЗЬ туннель нарочно (§7.1) — под это на
    /// сервере и заведено исключение G1 (`Citadel_ALLOW_DSTS` на token-порт). Детектор же сверял
    /// один адрес и печатал каждую дозаправку как «ПЕТЛЯ … VpnService.protect не сработал»:
    /// диагноз ложный, дорогой (уводит в исправный protect-инвариант) и обесценивающий сообщение
    /// на случай настоящей петли.
    #[test]
    fn self_loop_is_transport_socket_not_issuer_topup() {
        const EXIT: [u8; 4] = [89, 124, 75, 183];
        const ME: [u8; 4] = [10, 7, 0, 2];
        let quic = ExitTransport { addr: EXIT, port: 15388, over_tcp: false };
        let obfs = ExitTransport { addr: EXIT, port: 443, over_tcp: true };

        // Настоящая петля: наш собственный транспортный сокет вернулся в свой же туннель.
        let udp_to_transport = ip::build_ipv4(17, ME, EXIT, &{
            let mut u = vec![0u8; 8];
            u[2..4].copy_from_slice(&15388u16.to_be_bytes());
            u
        });
        assert!(quic.is_self_loop(&ip::parse_ipv4(&udp_to_transport).unwrap()));
        assert!(obfs.is_self_loop(&ip::parse_ipv4(&tcp(ME, EXIT, 443)).unwrap()));

        // Дозаправка кошелька у издателя: тот же адрес, ДРУГОЙ порт — это не петля.
        let topup_pkt = tcp(ME, EXIT, 7000);
        let topup = ip::parse_ipv4(&topup_pkt).unwrap();
        assert!(!quic.is_self_loop(&topup), "дозаправка через туннель — не петля");
        assert!(!obfs.is_self_loop(&topup), "дозаправка через туннель — не петля");

        // Тот же порт, но другой протокол: при QUIC/UDP петля — только UDP, при obfs-TCP — только TCP.
        assert!(!quic.is_self_loop(&ip::parse_ipv4(&tcp(ME, EXIT, 15388)).unwrap()));
        assert!(!obfs.is_self_loop(&ip::parse_ipv4(&udp_to_transport).unwrap()));

        // Обычный трафик человека мимо адреса exit'а детектор не трогает вовсе.
        assert!(!quic.is_self_loop(&ip::parse_ipv4(&tcp(ME, [1, 1, 1, 1], 15388)).unwrap()));
    }

    /// M-8: интервал keep-alive случаен (строгого периода в потоке нет) и в совместимом режиме
    /// остаётся прежним — 2–4 с. Так мы говорим со старым пиром: у него `max_idle_timeout` 15 с,
    /// а эффективный таймаут равен минимуму из объявленных, поэтому редкий маячок рвал бы туннель
    /// в простое.
    #[test]
    fn keepalive_interval_is_random_and_below_quinn_fallback() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let d = keepalive_delay(false);
            assert!(d >= std::time::Duration::from_secs(2), "слишком часто: {d:?}");
            assert!(d <= std::time::Duration::from_secs(4), "не успеет до idle старого пира: {d:?}");
            seen.insert(d);
            assert!(keepalive_body_len() <= 96);
        }
        assert!(seen.len() > 50, "интервал обязан гулять, а не быть константой: {}", seen.len());
    }

    /// **П5 (батарея): редкий маячок и условия, при которых он вообще допустим.**
    ///
    /// Три инварианта, каждый из которых при нарушении даёт разрыв туннеля в простое, а не
    /// «чуть хуже маскировку»:
    ///  1. без подсказки пира режим остаётся частым (старый exit с idle 15 с);
    ///  2. верхняя граница редкого интервала — ниже типового CGNAT-таймаута (30 с), иначе UDP-
    ///     биндинг умирает между маячками;
    ///  3. наш собственный `max_idle_timeout` не ниже порога, разрешающего редкий режим, — иначе
    ///     пир, поверив нашей же подсказке, начал бы слать редко в соединение, которое мы сами
    ///     закрываем раньше.
    #[test]
    fn relaxed_keepalive_requires_peer_confirmation() {
        use std::time::Duration;
        assert!(!keepalive_relaxed(None), "старый пир (без подсказки) → частый маячок");
        assert!(!keepalive_relaxed(Some(Duration::from_secs(15))), "15 с → частый маячок");
        assert!(keepalive_relaxed(Some(RELAXED_MIN_IDLE)));
        assert!(keepalive_relaxed(Some(crate::IDLE_TIMEOUT)));

        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let d = keepalive_delay(true);
            assert!(d >= Duration::from_secs(15), "слишком часто для редкого режима: {d:?}");
            assert!(d < Duration::from_secs(30), "не успеет обновить CGNAT-биндинг: {d:?}");
            seen.insert(d);
        }
        assert!(seen.len() > 50, "интервал обязан гулять и в редком режиме: {}", seen.len());
        assert!(
            crate::IDLE_TIMEOUT >= RELAXED_MIN_IDLE,
            "мы объявляем idle меньше, чем сами считаем достаточным для редкого маячка"
        );
        // Запас на пропуски: даже верхняя граница интервала обязана укладываться в порог с
        // кратностью ≥2, иначе одна потеря маячка = разрыв.
        assert!(*KA_RELAXED_MS.end() * 2 <= RELAXED_MIN_IDLE.as_millis() as u64);
    }

    /// M-8/F7: датаграмма служебного контекста в TUN не идёт, но ресурсы тратит — она обязана
    /// списываться из того же bucket'а. Иначе лимит обходится сменой context id.
    #[test]
    fn service_datagrams_are_charged_to_the_bucket() {
        let cfg = crate::ratelimit::RateCfg { rate: 1.0, burst: 200.0 };
        let mut inb = Inbound::new(Some([10, 7, 0, 9]), Some(cfg));
        // burst 200 при MIN_PACKET_COST=64 → три «служебные» датаграммы съедают лимит…
        assert!(inb.charge(10));
        assert!(inb.charge(10));
        assert!(inb.charge(10));
        assert!(!inb.charge(10), "четвёртая обязана упереться в лимит");
        // …и полезный пакет после этого тоже не проходит (bucket общий на направление)
        assert!(!inb.accept(&ipv4([10, 7, 0, 9], [1, 1, 1, 1])));
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

        // Клиентский режим `Inbound` по-прежнему без egress-политики: она про то, что клиенту
        // позволено ОТПРАВИТЬ, и решает это exit. Входящее на клиенте фильтрует отдельный рубеж
        // F8 (`crate::clientfw`, находка H-4) — см. его тесты; здесь проверяется только, что
        // клиент не применяет к себе серверную политику.
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
        let admin = EgressPolicy { admin_dst: Some((vip, 7001)), ..Default::default() };
        let mut exit = Inbound::with_policy(Some(assigned), None, admin.clone());
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
        let mut plain = Inbound::new(Some(assigned), None);
        assert!(!plain.accept(&tcp(assigned, vip, 7001)), "нет admin-исключения → F2 дропает");
    }

    /// G1/G2 (аудит-5): инфраструктурные адреса (публичный IP самой машины, адрес издателя) из
    /// туннеля недостижимы, хотя F2 их не режет — они публичные. Исключение — ровно один TCP-порт
    /// издателя (§7.1: фоновая дозаправка кошелька идёт СКВОЗЬ туннель нарочно).
    #[test]
    fn inbound_denies_infra_dsts_except_issuer_token_port() {
        let assigned = [10, 7, 0, 5];
        let own = [203, 0, 114, 10]; // публичный адрес самого exit-хоста (F2 его пропускает)
        let issuer = [203, 0, 114, 20];
        let vip = [10, 7, 0, 1];
        let mut exit = Inbound::with_policy(
            Some(assigned),
            None,
            EgressPolicy {
                admin_dst: Some((vip, 7001)),
                deny_dsts: vec![own, issuer],
                allow_dsts: vec![(issuer, 7000)],
            },
        );
        // G1: собственный хост закрыт целиком — и ssh, и published-порты, и ICMP
        assert!(!exit.accept(&tcp(assigned, own, 22)), "ssh хоста из туннеля — дроп");
        assert!(!exit.accept(&tcp(assigned, own, 7000)), "published-порт хоста — дроп");
        assert!(!exit.accept(&ipv4(assigned, own)), "не-TCP на свой хост — дроп");
        // G2: у издателя открыт ровно token-порт; admin-порт напрямую — закрыт (только через VIP)
        assert!(exit.accept(&tcp(assigned, issuer, 7000)), "token-порт издателя — пропуск (§7.1)");
        assert!(!exit.accept(&tcp(assigned, issuer, 7001)), "admin-порт издателя напрямую — дроп (G2)");
        assert!(!exit.accept(&ipv4(assigned, issuer)), "не-TCP на издателя — дроп (исключение только TCP)");
        // Запрет сильнее admin-исключения: список оператора побеждает любое послабление
        let mut both = Inbound::with_policy(
            Some(assigned),
            None,
            EgressPolicy {
                admin_dst: Some((vip, 7001)),
                deny_dsts: vec![vip],
                allow_dsts: vec![],
            },
        );
        assert!(!both.accept(&tcp(assigned, vip, 7001)), "явный deny сильнее admin-исключения");
        // Соседние публичные адреса не задеты (нет over-block)
        assert!(exit.accept(&tcp(assigned, [203, 0, 114, 11], 443)), "чужой публичный dst — пропуск");
        assert!(exit.accept(&tcp(assigned, [1, 1, 1, 1], 443)), "обычный трафик не задет");
    }

    /// pump-watchdog: рвём путь только когда под нагрузкой (tx ≥ порога) нет НИ обратных датаграмм,
    /// НИ вообще QUIC-пакетов от пира. Хоть один принятый пакет любого уровня — путь жив (дроп на
    /// exit'е ≠ мёртвый путь: рвать сессию нельзя, иначе реконнект-шторм). Мало отправили — простой.
    #[test]
    fn watchdog_trips_only_on_dead_path_under_load() {
        assert!(watchdog_trips(WATCHDOG_TX_MIN, 0, 0), "порог tx, ничего не принято — путь мёртв");
        assert!(watchdog_trips(WATCHDOG_TX_MIN + 500, 0, 0), "много шлём, тишина — путь мёртв");
        assert!(!watchdog_trips(WATCHDOG_TX_MIN, 1, 0), "хоть 1 датаграмма — путь жив");
        assert!(!watchdog_trips(WATCHDOG_TX_MIN - 1, 0, 0), "мало отправили (простой) — не трогаем");
        assert!(!watchdog_trips(0, 0, 0), "полный простой — не трогаем");
        // КЛЮЧЕВОЕ (баг реконнект-шторма): датаграмм назад нет, но ACK'и/keep-alive пира идут —
        // это дроп на стороне exit, а не мёртвый путь. Транспорт не рвём.
        assert!(!watchdog_trips(WATCHDOG_TX_MIN + 100, 0, 1), "QUIC-пакеты идут — путь жив");
        assert!(!watchdog_trips(WATCHDOG_TX_MIN, 0, 40), "поток ACK'ов — путь жив");
    }

    /// Разбор «транспорт жив, а обратно тихо» на две РАЗНЫЕ беды. Прежний код валил их в один
    /// вердикт «похоже, пакеты дропает exit», и мобильный случай (до exit'а не доезжаем мы сами)
    /// уводил разбор в сторону: на сервере искали дроп, которого там не было.
    #[test]
    fn uplink_verdict_separates_our_loss_from_exit_silence() {
        // Живой пример из полевого лога: 630 датаграмм отдано транспорту, на провод ушла горстка,
        // ACK'ов нет — очередь не рассасывается, до exit'а физически не доезжаем.
        assert!(uplink_is_dead(630, 30, 5, 0), "очередь встала и не подтверждена — виноват путь");
        // Ушли все, но половину и больше объявили потерянными — путь их глотает (узкий MTU/потери).
        assert!(uplink_is_dead(630, 630, 600, 40), "потеряно почти всё отправленное — путь глотает");
        assert!(uplink_is_dead(100, 100, 50, 10), "ровно половина потерь — уже дыра");
        // Уходили, а подтверждений НОЛЬ: ACK шлют только за доехавшее ⇒ путь не несёт наши пакеты
        // (или их ответы). Прежняя версия этот случай пропускала — «потерь-то нет».
        assert!(uplink_is_dead(630, 630, 0, 0), "ушло всё, не подтверждено ничего — путь мёртв");
        // Уходят и подтверждаются: пакеты У EXIT'а, тишина обратно — не транспортная беда.
        // Рвать сессию нельзя (это и есть закрытый ранее реконнект-шторм).
        assert!(!uplink_is_dead(630, 630, 0, 90), "всё доехало, ответа нет — молчит exit/назначение");
        assert!(!uplink_is_dead(630, 620, 20, 90), "единичные потери — нормальная сеть");
        // УЗКИЙ канал (2G/перегруженный Wi-Fi): очередь не рассасывается, но ушедшее доезжает и
        // подтверждается. Рвать транспорт нельзя — на новом будет ровно та же узкая труба.
        assert!(!uplink_is_dead(630, 30, 0, 25), "медленно, но доезжает — канал узкий, не мёртвый");
        // Вырожденный случай: транспорт вообще ничего не отправлял (простой) — не обвиняем путь.
        assert!(!uplink_is_dead(0, 0, 0, 0), "простоя не бывает виноватым");
    }

    /// Быстрая тиковая сигнатура «датаграммы не уходят и никто их не подтверждает». Числа — из
    /// полевого лога Android: за тик отдано 113, ушло 2, потеряно 0. Ждать полных 16с в таком
    /// состоянии нельзя — лечится сменой транспорта за секунду.
    #[test]
    fn stall_signature_fires_fast_but_not_on_ordinary_loss() {
        assert!(uplink_is_stalled(113, 2, 0, 0), "поле: отдано 113, ушло 2, ни потерь, ни ACK'ов");
        assert!(uplink_is_stalled(583, 33, 0, 0), "первое окно того же лога");
        // КЛЮЧЕВОЕ (жалоба «каждое подключение обрывается и уходит на 443»): ровно та же картина
        // отданного и ушедшего бывает на УЗКОЙ, но исправной сети — туда просто не влезает больше.
        // Отличие одно: ушедшее доезжает и подтверждается. Такую сессию рвать нельзя.
        assert!(!uplink_is_stalled(113, 2, 0, 7), "ACK'и идут — канал узкий, но живой");
        assert!(!uplink_is_stalled(583, 33, 0, 1), "хоть один ACK за тик — путь несёт пакеты");
        // Потери есть ⇒ пакеты УХОДИЛИ и умирали в сети: это другая беда, её судит оконная логика
        // (иначе рвали бы транспорт на всплеске потерь мобильной сети).
        assert!(!uplink_is_stalled(116, 2, 5, 0), "есть потери — не эта сигнатура");
        // Уходит существенная доля — обычный затор cwnd, не отказ.
        assert!(!uplink_is_stalled(100, 20, 0, 0), "ушла пятая часть — не сигнатура отказа");
        // Простой: мало отдали — молчим (иначе рвали бы сессию на любой паузе трафика).
        assert!(!uplink_is_stalled(STALL_TX_MIN - 1, 0, 0, 0), "простой не судим");
        assert!(!uplink_is_stalled(0, 0, 0, 0), "полная тишина — не повод рвать");
    }
}
