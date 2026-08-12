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

use crate::ratelimit::{RateCfg, RateLimits, TokenBucket};

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
                        // no-logs: адреса пользователя — только под Citadel_DEBUG_LOG (см. lib::debug_logs)
                        crate::dlog!(
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

/// M-8: задержка до следующего keep-alive — РАВНОМЕРНО в `[2, 4]` с, выбирается заново каждый раз.
///
/// Верхняя граница держится ниже `keep_alive_interval` quinn (5 с), чтобы штатный периодический
/// PING не срабатывал и не возвращал в поток тот самый строгий период; нижняя — чтобы маячки не
/// стоили заметного трафика. Обе — сильно ниже `max_idle_timeout` (15 с), так что потеря одного
/// пакета соединение не рвёт.
fn keepalive_delay() -> std::time::Duration {
    use rand::Rng;
    std::time::Duration::from_millis(rand::thread_rng().gen_range(2_000..=4_000))
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

/// Снимок счётчиков трафика туннеля: `(принято, отправлено)` в байтах полезной нагрузки.
/// Монотонны за время жизни процесса — вызывающий считает скорость по дельте двух снимков.
pub fn traffic_bytes() -> (u64, u64) {
    use std::sync::atomic::Ordering::Relaxed;
    (TRAFFIC_RX.load(Relaxed), TRAFFIC_TX.load(Relaxed))
}

/// Окно pump-watchdog и минимум отправленных датаграмм в окне, при котором «0 принятых»
/// трактуется как мёртвый путь. Окно > keep-alive-интервала (5с), чтобы здоровый простой и
/// одиночные потери не срабатывали; порог tx отсекает простой (мало шлём — путь не трогаем).
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
/// провод (`frame_tx.datagram`); `lost` — сколько отправленных пакетов он объявил потерянными.
/// Разница `enqueued - on_wire` — не «где-то потерялись»: при заторе quinn МОЛЧА вытесняет из
/// очереди датаграмм самые старые (`datagram_send_buffer_size`), то есть успешный `send_datagram`
/// ничего не обещает. Поэтому «отправлено N» в старом сообщении тоже было неправдой.
fn uplink_is_dead(enqueued: u64, on_wire: u64, lost: u64) -> bool {
    // Больше половины даже не ушло в транспорт: очередь не рассасывается (cwnd схлопнулся).
    let stalled = on_wire * 2 < enqueued;
    // Половина и больше из ушедшего объявлена потерянной: путь их глотает.
    let lossy = on_wire > 0 && lost * 2 >= on_wire;
    stalled || lossy
}

/// Быстрая (тиковая) проверка ровно одной беды: **сокет перестал брать наши пакеты**.
///
/// Полевой лог: за окно отдано 116 датаграмм, на провод ушло 2, потеряно 0 — то есть пакеты никуда
/// не отправлялись (иначе они числились бы потерянными), а те двое, что ушли, — наши keep-alive,
/// мелкие. Механизм локальный: quinn зовёт `poll_transmit` только пока UDP-сокет пишется, а на
/// Android он перестаёт брать пакеты (переполненная очередь устройства → `ENOBUFS`, либо пакет
/// крупнее того, что путь готов нести, при выставленном DF). Уходят лишь те, что попадают на
/// пробуждение по таймеру — отсюда «пара штук за окно».
///
/// Это НЕ транзиент: ждать полные два окна (16с) значит держать человека в мёртвом туннеле,
/// который лечится сменой транспорта за секунду. Поэтому сигнатуре хватает 2 тиков (4с). Условия
/// намеренно жёстче оконных: `lost == 0` (иначе это обычные потери сети, а не отказ сокета) и
/// разрыв на порядок (`on_wire * 8 < enqueued`), чтобы не спутать с честным затором cwnd.
fn uplink_is_stalled(enqueued: u64, on_wire: u64, lost: u64) -> bool {
    enqueued >= STALL_TX_MIN && lost == 0 && on_wire * 8 < enqueued
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
    /// IPv4 транспортного пира (exit). Пакет из TUN, адресованный ЕМУ, — это наш собственный
    /// транспорт, завернувшийся в собственный туннель: на Android так выглядит незащищённый
    /// (`VpnService.protect`) сокет, на desktop — отсутствие bypass-маршрута к exit. Такая петля
    /// убивает сессию за секунды и раньше читалась в логе лишь как «чужой src».
    pub exit: Option<[u8; 4]>,
}

/// Двунаправленная перекачка TUN ⇄ транспорт (QUIC DATAGRAM либо obfs-TCP record).
/// `egress = Some(назначенный клиенту адрес)` включает egress-политику exit: анти-спуфинг
/// inner-src (S0.2/H3), default-deny не-IPv4 и F2 (дроп во внутренние/служебные сети); `None`
/// (клиент) — без фильтра. `rate` (на exit) ограничивает ОБА направления token-bucket'ами
/// (F7/D3 + M-3-bis: `up` — в `Inbound`, `down` — в sender-задаче ниже).
/// `admin_dst` (C7.2, только exit) — `Some((vip, port))` пропускает TCP к admin-VIP мимо F2
/// (ядро DNAT'ит на issuer); `None` — admin-плоскость по туннелю выключена.
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
    admin_dst: Option<([u8; 4], u16)>,
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

    let Tunnel { conn, .. } = tunnel;
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
            // Диагностика (не фильтр): src ≠ назначенный адрес ⇒ exit дропнет пакет анти-спуфингом
            // и ответа не будет НИКОГДА. Отправляем всё равно — политику решает exit, а клиент лишь
            // обязан объяснить человеку «туннель поднят, а трафика нет» вместо загадочных нулей.
            if let Some(mine) = client_assigned {
                if v4.src != mine {
                    send_bad_src.fetch_add(1, Ordering::Relaxed);
                    send_bad_src_last.store(u32::from_be_bytes(v4.src), Ordering::Relaxed);
                    // Пакет к самому exit'у, пришедший из TUN, — петля собственного транспорта.
                    if client_exit == Some(v4.dst) {
                        send_self_loop.fetch_add(1, Ordering::Relaxed);
                    }
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
        let mut inb = Inbound::with_admin(egress, rate.up, admin_dst);
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
        let (mut seen_tx, mut seen_rx, mut seen_v6, mut seen_urx) = (0u64, 0u64, 0u64, 0u64);
        let (mut seen_bad_src, mut seen_self_loop) = (0u64, 0u64);
        // Реально ушедшие на провод датаграммы и объявленные потерянными пакеты — предыдущий
        // снимок (считаем дельты за окно, как и всё остальное здесь).
        let (mut seen_wire, mut seen_lost) = (0u64, 0u64);
        // UDP-пакеты и байты транспорта — для среднего размера ушедшего пакета (см. ниже).
        let (mut seen_utx, mut seen_ubytes) = (0u64, 0u64);
        // Сколько окон подряд путь односторонний (см. ONE_WAY_WINDOWS).
        let mut one_way = 0u32;
        // F8: предыдущий снимок счётчиков клиентского inbound-фильтра (не-IPv4, чужой dst, без
        // запроса, ICMP-тип) — печатаем дельту за окно, а не итог за сессию.
        let mut seen_fw = (0u64, 0u64, 0u64, 0u64);
        // Тиковые снимки (быстрая проверка отказа сокета) — отдельные от оконных: у них свой шаг.
        let (mut tick_tx, mut tick_rx, mut tick_wire, mut tick_lost) = (0u64, 0u64, 0u64, 0u64);
        let (mut stalled_ticks, mut tick_no) = (0u32, 0u32);
        loop {
            tokio::time::sleep(WATCHDOG_TICK).await;
            if wd_stop.load(Ordering::Acquire) {
                break;
            }
            let st = wd_conn.stats();
            // ── быстрая проверка (каждый тик): сокет перестал брать наши пакеты ──
            {
                let (tx, rx, wire, lost) = (
                    wd_tx.load(Ordering::Relaxed),
                    wd_rx.load(Ordering::Relaxed),
                    st.frame_tx.datagram,
                    st.path.lost_packets,
                );
                let (d_tx, d_rx, d_wire, d_lost) = (
                    tx.wrapping_sub(tick_tx),
                    rx.wrapping_sub(tick_rx),
                    wire.wrapping_sub(tick_wire),
                    lost.wrapping_sub(tick_lost),
                );
                (tick_tx, tick_rx, tick_wire, tick_lost) = (tx, rx, wire, lost);
                if wd_client && d_rx == 0 && uplink_is_stalled(d_tx, d_wire, d_lost) {
                    stalled_ticks += 1;
                    if stalled_ticks >= STALL_TICKS {
                        eprintln!(
                            "[pump] транспорт не принимает наши пакеты {}с подряд (за тик отдано \
                             {d_tx}, на провод ушло {d_wire}, потеряно 0) — это отказ ОТПРАВКИ, а \
                             не потери в сети; рву транспорт и иду другим",
                            WATCHDOG_TICK.as_secs() * STALL_TICKS as u64
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
            let (wire, lost) = (
                st.frame_tx.datagram.wrapping_sub(seen_wire),
                st.path.lost_packets.wrapping_sub(seen_lost),
            );
            (seen_wire, seen_lost) = (st.frame_tx.datagram, st.path.lost_packets);
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
                     {wire}, объявлено потерянными {lost}, принято 0 (QUIC-пакетов от exit: \
                     {transport_rx}, RTT {} мс, MTU пути {}, cwnd {}, средний ушедший пакет \
                     {avg_wire} б из {utx})",
                    WATCHDOG_INTERVAL.as_secs(),
                    st.path.rtt.as_millis(),
                    st.path.current_mtu,
                    st.path.cwnd,
                );
                if uplink_is_dead(sent, wire, lost) {
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
                let exit = wd_exit.map(std::net::Ipv4Addr::from);
                eprintln!(
                    "[pump] ПЕТЛЯ: {loop_delta} пакетов к самому exit'у ({}) ушли в туннель — \
                     собственный транспорт заворачивается в собственный туннель. На Android это \
                     означает незащищённый сокет (VpnService.protect не сработал), на desktop — \
                     отсутствие bypass-маршрута к exit. Сессия в таком виде не выживет",
                    exit.map(|e| e.to_string()).unwrap_or_else(|| "?".into())
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
    // фиксирован (5,000 с) — в простое туннель превращается в маяк со строгой периодичностью,
    // который снимается автокорреляцией по десятку интервалов и не маскируется ни паддингом
    // размеров (I5/C2), ни шифрованием. Здесь интервал выбирается заново перед каждой отправкой
    // (см. [`keepalive_delay`]), поэтому периода в потоке нет. Пакет — датаграмма `CTX_KEEPALIVE`
    // со случайным телом: приёмник её отбрасывает (не `CTX_RAW_IP`), а L1 паддит её до того же
    // распределения длин, что и данные, — на проводе она неотличима от полезного трафика.
    //
    // Отправляем только в ПРОСТОЕ (за окно не ушло ни одной датаграммы) — под нагрузкой канал
    // и так не даёт quinn'у сработать по неактивности, а лишний пакет только жёг бы трафик.
    // `keep_alive_interval` остаётся страховкой: если эта задача умрёт, соединение не развалится.
    let ka_conn = conn.clone();
    let ka_tx = tx_count.clone();
    let ka_stop = stop.clone();
    let keepalive = tokio::spawn(async move {
        let mut seen = ka_tx.load(Ordering::Relaxed);
        loop {
            tokio::time::sleep(keepalive_delay()).await;
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
    Ok(PumpExit { uplink_dead: uplink_dead.load(Ordering::Acquire) })
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

    /// M-8: интервал keep-alive случаен и ВСЕГДА строго меньше `keep_alive_interval` quinn (5 с) —
    /// иначе штатный PING успевал бы раньше и возвращал в поток ту самую строгую периодичность,
    /// ради ухода от которой всё и делалось. И сильно меньше `max_idle_timeout` (15 с), чтобы
    /// потеря одного маячка не рвала сессию.
    #[test]
    fn keepalive_interval_is_random_and_below_quinn_fallback() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let d = keepalive_delay();
            assert!(d >= std::time::Duration::from_secs(2), "слишком часто: {d:?}");
            assert!(d <= std::time::Duration::from_secs(4), "не успеет до PING quinn: {d:?}");
            seen.insert(d);
            assert!(keepalive_body_len() <= 96);
        }
        assert!(seen.len() > 50, "интервал обязан гулять, а не быть константой: {}", seen.len());
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
        // Живой пример из полевого лога: 630 датаграмм отдано транспорту, на провод ушла горстка —
        // очередь не рассасывается (cwnd схлопнулся), до exit'а физически не доезжаем.
        assert!(uplink_is_dead(630, 30, 5), "очередь встала — виноват путь, а не exit");
        // Ушли все, но половину и больше объявили потерянными — путь их глотает (узкий MTU/потери).
        assert!(uplink_is_dead(630, 630, 600), "потеряно почти всё отправленное — путь глотает");
        assert!(uplink_is_dead(100, 100, 50), "ровно половина потерь — уже дыра");
        // Уходят и подтверждаются: пакеты У EXIT'а, тишина обратно — не транспортная беда.
        // Рвать сессию нельзя (это и есть закрытый ранее реконнект-шторм).
        assert!(!uplink_is_dead(630, 630, 0), "всё доехало, ответа нет — молчит exit/назначение");
        assert!(!uplink_is_dead(630, 620, 20), "единичные потери — нормальная сеть");
        // Вырожденный случай: транспорт вообще ничего не отправлял (простой) — не обвиняем путь.
        assert!(!uplink_is_dead(0, 0, 0), "простоя не бывает виноватым");
    }

    /// Быстрая тиковая сигнатура «сокет не берёт наши пакеты». Числа — из полевого лога Android:
    /// за окно отдано 116, ушло 2, потеряно 0 (ушли ровно keep-alive). Ждать полных 16с в таком
    /// состоянии нельзя: это не потери сети, а отказ отправки, и лечится он сменой транспорта.
    #[test]
    fn stall_signature_fires_fast_but_not_on_ordinary_loss() {
        assert!(uplink_is_stalled(116, 2, 0), "поле: отдано 116, ушло 2, потерь нет — затор");
        assert!(uplink_is_stalled(583, 33, 0), "первое окно того же лога");
        // Потери есть ⇒ пакеты УХОДИЛИ и умирали в сети: это другая беда, её судит оконная логика
        // (иначе рвали бы транспорт на всплеске потерь мобильной сети).
        assert!(!uplink_is_stalled(116, 2, 5), "есть потери — не отказ отправки");
        // Уходит существенная доля — обычный затор cwnd, не отказ.
        assert!(!uplink_is_stalled(100, 20, 0), "ушла пятая часть — не сигнатура отказа");
        // Простой: мало отдали — молчим (иначе рвали бы сессию на любой паузе трафика).
        assert!(!uplink_is_stalled(STALL_TX_MIN - 1, 0, 0), "простой не судим");
        assert!(!uplink_is_stalled(0, 0, 0), "полная тишина — не повод рвать");
    }
}
