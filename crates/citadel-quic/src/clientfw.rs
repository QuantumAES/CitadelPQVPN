//! CitadelPQVPN — **F8: клиентский inbound-фильтр** (аудит-5 / H-4).
//!
//! Симметричная пара к egress-политике exit'а (`dataplane::Inbound`, S0.2/F2): там сервер решает,
//! что клиенту позволено отправить, здесь — **клиент решает, что серверу позволено ему прислать**.
//!
//! **Зачем.** Туннель — это записывающий доступ в TUN клиентской машины: всё, что exit положит в
//! датаграмму, движок пишет в интерфейс, а ядро обрабатывает как обычный входящий пакет. До F8
//! клиентская сторона не фильтровала ничего (`Inbound::egress == None`), поэтому
//! **скомпрометированный exit (противник A7) мог не только читать трафик, но и сам инициировать
//! соединения к абоненту**:
//!   * `dst = назначенный адрес` → SYN на любой слушающий на устройстве порт (sshd, отладочные
//!     серверы, `adb tcpip` 5555 на Android, SMB/CUPS/X11 на десктопе) — обратный маршрут есть,
//!     ответы уходят по default-route в тот же туннель, канал полностью двунаправленный;
//!   * `dst = адрес другого интерфейса того же хоста` → на Linux работает weak host model:
//!     ядро принимает пакет к ЛЮБОМУ своему адресу с ЛЮБОГО интерфейса, то есть туннель давал
//!     доступ к сервисам, привязанным только к локалке;
//!   * `dst = адрес в LAN` → на хосте с `ip_forward=1` (сервер/ноут с раздачей, контейнерный хост)
//!     туннель становился маршрутом ВНУТРЬ локальной сети абонента;
//!   * ICMP redirect (тип 5) → инъекция маршрута при `accept_redirects=1`.
//!
//! Ни kill-switch (только `OUTPUT`/`ALE_AUTH_CONNECT`), ни WFP-план, ни `VpnService` этого не
//! закрывали — все они про исходящее направление.
//!
//! **Политика.** Пропускаем ровно то, что является ответом на наш собственный исходящий трафик:
//!   1. `dst` обязан быть НАШИМ назначенным адресом (иначе пакет вообще не может быть ответом);
//!   2. TCP/UDP: порт назначения обязан быть портом, с которого мы в этой сессии сами отправляли
//!      (мини-conntrack по локальному порту, [`EgressSeen`]);
//!   3. TCP: `SYN` без `ACK` — попытка открыть НАМ соединение → дроп независимо от порта;
//!   4. ICMP: только служебные типы 0/3/11 (echo-reply, dest-unreachable — нужен для PMTU внутри
//!      туннеля, time-exceeded — traceroute). Остальное, включая redirect(5) и echo-request(8),
//!      дропаем: пинговать абонента через туннель незачем, а redirect — вектор инъекции маршрута;
//!   5. прочие протоколы (ESP/GRE/…): только если мы сами отправляли этим протоколом;
//!   6. не-IPv4 и мусор — default-deny (туннель IPv4-only, S2.2/A2).
//!
//! **Почему без старения записей.** Порт, с которого мы отправляли, остаётся разрешённым до конца
//! сессии. Это осознанно: старение ломало бы живые, но временно молчащие соединения (idle-SSH, где
//! сервер пишет первым после долгой паузы — мы бы дропнули его пакет, а сами ничего не отправили =
//! дедлок). Остаточный риск ничтожен: попасть можно только в порт, который мы уже использовали, и
//! только если на нём в этот момент кто-то слушает; «постоянных» слушателей (22, 445, 5555, 8080)
//! фильтр не пропускает никогда, потому что исходящих пакетов с таких портов не бывает.
//!
//! **Что F8 НЕ закрывает.** Exit по-прежнему видит и может менять/дропать трафик абонента (он
//! эндпоинт NAT — это по построению), может подменять DNS-ответы и MITM'ить незашифрованные
//! протоколы. F8 отнимает именно **инициативу**: сервер больше не может «позвонить» на устройство.
//!
//! Фильтр работает на ВСЕХ платформах, потому что живёт в движке (Linux/Windows/Android — один код),
//! в отличие от iptables/WFP, которых на Android нет вовсе.

use std::sync::atomic::{AtomicU64, Ordering};

use citadel_masque::ip::{self, Ipv4View};

/// Слов по 64 бита на 65536 портов.
const PORT_WORDS: usize = 1024;

/// Разрешённые входящие ICMP-типы: echo-reply, destination-unreachable (в т.ч. frag-needed для
/// PMTU внутри туннеля), time-exceeded (traceroute).
const ICMP_ALLOWED: [u8; 3] = [0, 3, 11];

/// Причина дропа входящего пакета — для агрегированной диагностики (клиент обязан уметь объяснить
/// человеку, что именно ему прислал сервер).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Drop {
    /// Не IPv4 (туннель IPv4-only).
    NotV4,
    /// `dst` — не наш назначенный адрес (чужой хост/локалка/loopback/broadcast).
    NotOurs,
    /// Ответом быть не может: порт/протокол, которым мы не пользовались, либо SYN к нам.
    Unsolicited,
    /// ICMP-тип вне служебного списка (redirect, echo-request, …).
    IcmpKind,
}

/// Битовая карта «мы сами отправляли»: локальные порты TCP/UDP и номера прочих протоколов.
/// Обновляется из sender-задачи `pump`, читается из receiver-задачи ⇒ только атомарные операции,
/// без блокировок на hot-path (одна атомарная OR на исходящий пакет, одна загрузка на входящий).
pub struct EgressSeen {
    tcp: [AtomicU64; PORT_WORDS],
    udp: [AtomicU64; PORT_WORDS],
    /// 256 бит: номера IP-протоколов, которыми мы отправляли (кроме TCP/UDP/ICMP).
    proto: [AtomicU64; 4],
}

impl Default for EgressSeen {
    fn default() -> Self {
        Self::new()
    }
}

impl EgressSeen {
    pub fn new() -> Self {
        Self {
            tcp: std::array::from_fn(|_| AtomicU64::new(0)),
            udp: std::array::from_fn(|_| AtomicU64::new(0)),
            proto: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    fn set(words: &[AtomicU64], bit: usize) {
        words[bit / 64].fetch_or(1u64 << (bit % 64), Ordering::Relaxed);
    }

    fn get(words: &[AtomicU64], bit: usize) -> bool {
        words[bit / 64].load(Ordering::Relaxed) & (1u64 << (bit % 64)) != 0
    }

    /// Отметить исходящий пакет: его порт источника (TCP/UDP) либо номер протокола.
    pub fn note(&self, v: &Ipv4View<'_>) {
        match v.proto {
            6 | 17 => {
                if let Some(sport) = sport(v) {
                    let words = if v.proto == 6 { &self.tcp } else { &self.udp };
                    Self::set(words, sport as usize);
                }
            }
            1 => {} // ICMP портов не имеет — политика по типам, см. ICMP_ALLOWED
            p => Self::set(&self.proto, p as usize),
        }
    }

    /// Пользовались ли мы этим локальным портом (`proto` = 6/17)?
    fn port_used(&self, proto: u8, port: u16) -> bool {
        let words = if proto == 6 { &self.tcp } else { &self.udp };
        Self::get(words, port as usize)
    }

    /// Отправляли ли мы что-нибудь этим протоколом?
    fn proto_used(&self, proto: u8) -> bool {
        Self::get(&self.proto, proto as usize)
    }
}

/// Порт источника TCP/UDP-сегмента (`None` — не TCP/UDP или заголовок усечён).
fn sport(v: &Ipv4View<'_>) -> Option<u16> {
    if (v.proto != 6 && v.proto != 17) || v.payload.len() < 4 {
        return None;
    }
    Some(u16::from_be_bytes([v.payload[0], v.payload[1]]))
}

/// Порт назначения TCP/UDP-сегмента (`ip::tcp_dport` покрывает только TCP).
fn dport(v: &Ipv4View<'_>) -> Option<u16> {
    if (v.proto != 6 && v.proto != 17) || v.payload.len() < 4 {
        return None;
    }
    Some(u16::from_be_bytes([v.payload[2], v.payload[3]]))
}

/// TCP-флаги (`None` — не TCP или заголовок усечён).
fn tcp_flags(v: &Ipv4View<'_>) -> Option<u8> {
    if v.proto != 6 || v.payload.len() < 14 {
        return None;
    }
    Some(v.payload[13])
}

/// Смещение фрагмента (в 8-байтных блоках) из заголовка IPv4.
fn frag_offset(pkt: &[u8]) -> u16 {
    u16::from_be_bytes([pkt[6], pkt[7]]) & 0x1fff
}

/// Решение F8 по одному входящему пакету. Чистая функция — вся политика здесь, счётчики и лог
/// снаружи ([`ClientFilter`]), поэтому её можно исчерпывающе протестировать.
pub fn verdict(pkt: &[u8], assigned: [u8; 4], seen: &EgressSeen) -> Result<(), Drop> {
    let Some(v) = ip::parse_ipv4(pkt) else {
        return Err(Drop::NotV4);
    };
    if v.dst != assigned {
        return Err(Drop::NotOurs);
    }
    // Непервый фрагмент портов не несёт. Пропускаем: без ПЕРВОГО фрагмента (а он проходит проверку
    // портов как обычный пакет) ядро не соберёт датаграмму и никому её не доставит — то есть
    // «пронести» нечего, а очередь реассемблинга ядро само ограничивает. Дропать их нельзя:
    // сломался бы легитимный фрагментированный ответ (крупный DNS/UDP).
    if frag_offset(pkt) != 0 {
        return Ok(());
    }
    match v.proto {
        1 => {
            let t = *v.payload.first().ok_or(Drop::IcmpKind)?;
            if ICMP_ALLOWED.contains(&t) {
                Ok(())
            } else {
                Err(Drop::IcmpKind)
            }
        }
        6 | 17 => {
            // SYN без ACK = попытка открыть соединение К НАМ. Единственный легитимный источник
            // такого пакета — сам exit, а ему это не нужно ни для чего.
            if let Some(f) = tcp_flags(&v) {
                const SYN: u8 = 0x02;
                const ACK: u8 = 0x10;
                if f & SYN != 0 && f & ACK == 0 {
                    return Err(Drop::Unsolicited);
                }
            }
            let p = dport(&v).ok_or(Drop::Unsolicited)?;
            if seen.port_used(v.proto, p) {
                Ok(())
            } else {
                Err(Drop::Unsolicited)
            }
        }
        p => {
            if seen.proto_used(p) {
                Ok(())
            } else {
                Err(Drop::Unsolicited)
            }
        }
    }
}

/// Клиентский inbound-фильтр сессии: политика [`verdict`] + счётчики для диагностики.
/// Разделяется между sender- и receiver-задачами `pump` через `Arc` (внутренняя изменяемость).
pub struct ClientFilter {
    assigned: [u8; 4],
    seen: EgressSeen,
    /// Счётчики дропов по причинам (монотонные за сессию) — watchdog печатает дельту за окно.
    not_v4: AtomicU64,
    not_ours: AtomicU64,
    unsolicited: AtomicU64,
    icmp_kind: AtomicU64,
    /// Последний чужой `dst` (для строки лога: по нему видно природу — локалка, loopback, чужой хост).
    last_foreign_dst: AtomicU64,
    /// Режим только-наблюдения (`Citadel_INBOUND_OPEN=1`): считаем и логируем, но не дропаем.
    /// Аварийный рубильник на случай неизвестного легитимного сценария в поле; по умолчанию ВЫКЛ.
    audit_only: bool,
}

impl ClientFilter {
    pub fn new(assigned: [u8; 4]) -> Self {
        Self {
            assigned,
            seen: EgressSeen::new(),
            not_v4: AtomicU64::new(0),
            not_ours: AtomicU64::new(0),
            unsolicited: AtomicU64::new(0),
            icmp_kind: AtomicU64::new(0),
            last_foreign_dst: AtomicU64::new(u64::MAX),
            audit_only: audit_only_env(),
        }
    }

    /// Учесть исходящий пакет (из TUN в туннель) — открывает обратный путь его ответам.
    pub fn note_egress(&self, v: &Ipv4View<'_>) {
        self.seen.note(v);
    }

    /// Пропустить входящий пакет в TUN? В режиме `audit_only` всегда `true` (дропы только считаются).
    pub fn accept(&self, pkt: &[u8]) -> bool {
        match verdict(pkt, self.assigned, &self.seen) {
            Ok(()) => true,
            Err(reason) => {
                match reason {
                    Drop::NotV4 => &self.not_v4,
                    Drop::NotOurs => &self.not_ours,
                    Drop::Unsolicited => &self.unsolicited,
                    Drop::IcmpKind => &self.icmp_kind,
                }
                .fetch_add(1, Ordering::Relaxed);
                if reason == Drop::NotOurs {
                    if let Some(v) = ip::parse_ipv4(pkt) {
                        self.last_foreign_dst
                            .store(u32::from_be_bytes(v.dst) as u64, Ordering::Relaxed);
                    }
                }
                self.audit_only
            }
        }
    }

    /// Снимок счётчиков: `(не-IPv4, не наш dst, без запроса, ICMP-тип, последний чужой dst)`.
    pub fn counters(&self) -> (u64, u64, u64, u64, Option<[u8; 4]>) {
        let last = self.last_foreign_dst.load(Ordering::Relaxed);
        (
            self.not_v4.load(Ordering::Relaxed),
            self.not_ours.load(Ordering::Relaxed),
            self.unsolicited.load(Ordering::Relaxed),
            self.icmp_kind.load(Ordering::Relaxed),
            u32::try_from(last).ok().map(|a| a.to_be_bytes()),
        )
    }

    pub fn audit_only(&self) -> bool {
        self.audit_only
    }
}

/// `Citadel_INBOUND_OPEN=1` — не дропать, только считать (диагностика в поле). Читается один раз.
fn audit_only_env() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        matches!(std::env::var("Citadel_INBOUND_OPEN").as_deref(), Ok(v) if v != "0" && !v.is_empty())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_masque::ip::{build_icmp_echo_request, build_ipv4, build_tcp4, build_udp4};

    const ME: [u8; 4] = [10, 7, 0, 42];
    const REMOTE: [u8; 4] = [1, 1, 1, 1];

    fn udp(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16) -> Vec<u8> {
        build_udp4(src, sport, dst, dport, b"x")
    }

    /// TCP-пакет с произвольными флагами (0x02 SYN, 0x12 SYN+ACK, 0x10 ACK).
    fn tcp(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, flags: u8) -> Vec<u8> {
        build_tcp4(src, sport, dst, dport, 0, 0, flags, 64240)
    }

    /// Базовый сценарий: ответ на наш собственный запрос проходит, а всё, чего мы не просили, — нет.
    #[test]
    fn reply_to_own_traffic_passes_unsolicited_does_not() {
        let seen = EgressSeen::new();
        // мы отправили UDP-запрос (DNS) с порта 40000
        let out = udp(ME, 40000, REMOTE, 53);
        seen.note(&ip::parse_ipv4(&out).unwrap());

        // ответ на него — пропуск
        assert_eq!(verdict(&udp(REMOTE, 53, ME, 40000), ME, &seen), Ok(()));
        // тот же ответ, но на порт, с которого мы не отправляли — дроп
        assert_eq!(
            verdict(&udp(REMOTE, 53, ME, 40001), ME, &seen),
            Err(Drop::Unsolicited)
        );
        // UDP на «слушающий» порт (никогда не бывает портом источника) — дроп
        assert_eq!(
            verdict(&udp(REMOTE, 1234, ME, 5353), ME, &seen),
            Err(Drop::Unsolicited)
        );
    }

    /// H-4, главное: exit не может открыть соединение к абоненту. SYN дропается даже на порт,
    /// которым мы пользовались (иначе после исходящего соединения с порта X сервер мог бы
    /// «позвонить» на X, если там что-то слушает).
    #[test]
    fn server_cannot_initiate_tcp_connection() {
        let seen = EgressSeen::new();
        let out = tcp(ME, 51000, REMOTE, 443, 0x02);
        seen.note(&ip::parse_ipv4(&out).unwrap());

        // SYN+ACK от того, к кому мы подключились — пропуск (это наш ответ)
        assert_eq!(verdict(&tcp(REMOTE, 443, ME, 51000, 0x12), ME, &seen), Ok(()));
        // данные по установленному соединению — пропуск
        assert_eq!(verdict(&tcp(REMOTE, 443, ME, 51000, 0x10), ME, &seen), Ok(()));
        // SYN к нам на ИСПОЛЬЗОВАННЫЙ порт — дроп (сервер не открывает нам соединений)
        assert_eq!(
            verdict(&tcp(REMOTE, 6666, ME, 51000, 0x02), ME, &seen),
            Err(Drop::Unsolicited)
        );
        // SYN на типичный слушающий порт (sshd/adb/SMB) — дроп
        for p in [22u16, 445, 5555, 8080] {
            assert_eq!(
                verdict(&tcp(REMOTE, 6666, ME, p, 0x02), ME, &seen),
                Err(Drop::Unsolicited),
                "SYN на порт {p} обязан дропаться"
            );
        }
    }

    /// Пивот на другие адреса того же хоста и в локальную сеть: `dst != назначенный` — дроп.
    /// Именно этот класс закрывает weak host model на Linux и `ip_forward=1` на клиенте-роутере.
    #[test]
    fn foreign_destinations_are_dropped() {
        let seen = EgressSeen::new();
        let out = udp(ME, 40000, REMOTE, 53);
        seen.note(&ip::parse_ipv4(&out).unwrap());
        for dst in [
            [127, 0, 0, 1],    // loopback
            [192, 168, 1, 50], // адрес локалки этого же хоста (weak host model)
            [192, 168, 1, 1],  // роутер локалки (при ip_forward=1)
            [10, 7, 0, 43],    // другой абонент того же туннеля
            [255, 255, 255, 255],
            [10, 7, 0, 1], // шлюз/ADMIN_VIP — тоже не наш адрес
        ] {
            assert_eq!(
                verdict(&udp(REMOTE, 53, dst, 40000), ME, &seen),
                Err(Drop::NotOurs),
                "dst {dst:?} обязан дропаться"
            );
        }
    }

    /// ICMP: служебные типы пропускаем (PMTU внутри туннеля обязателен), redirect и echo-request — нет.
    #[test]
    fn icmp_service_types_only() {
        let seen = EgressSeen::new();
        // dest-unreachable (frag-needed) — пропуск: без него ломается PMTU внутри туннеля
        let unreach = build_ipv4(1, REMOTE, ME, &[3, 4, 0, 0, 0, 0, 5, 116]);
        assert_eq!(verdict(&unreach, ME, &seen), Ok(()));
        // time-exceeded — пропуск (traceroute)
        assert_eq!(verdict(&build_ipv4(1, REMOTE, ME, &[11, 0, 0, 0]), ME, &seen), Ok(()));
        // echo-reply — пропуск (ответ на наш ping)
        assert_eq!(verdict(&build_ipv4(1, REMOTE, ME, &[0, 0, 0, 0]), ME, &seen), Ok(()));
        // echo-request К НАМ — дроп (пинговать абонента через туннель незачем)
        let ping = build_icmp_echo_request(REMOTE, ME, 1, 1, b"x");
        assert_eq!(verdict(&ping, ME, &seen), Err(Drop::IcmpKind));
        // ICMP redirect — дроп (инъекция маршрута при accept_redirects=1)
        assert_eq!(
            verdict(&build_ipv4(1, REMOTE, ME, &[5, 1, 0, 0, 10, 7, 0, 9]), ME, &seen),
            Err(Drop::IcmpKind)
        );
        // пустое тело ICMP — дроп (тип не прочитать)
        assert_eq!(verdict(&build_ipv4(1, REMOTE, ME, &[]), ME, &seen), Err(Drop::IcmpKind));
    }

    /// Прочие протоколы — только если мы сами ими отправляли (симметрия с портами).
    #[test]
    fn other_protocols_need_our_egress_first() {
        let seen = EgressSeen::new();
        let esp_in = build_ipv4(50, REMOTE, ME, &[0; 8]);
        assert_eq!(verdict(&esp_in, ME, &seen), Err(Drop::Unsolicited));
        seen.note(&ip::parse_ipv4(&build_ipv4(50, ME, REMOTE, &[0; 8])).unwrap());
        assert_eq!(verdict(&esp_in, ME, &seen), Ok(()));
        // отметка одного протокола не открывает другой
        assert_eq!(
            verdict(&build_ipv4(47, REMOTE, ME, &[0; 8]), ME, &seen),
            Err(Drop::Unsolicited)
        );
    }

    /// Не-IPv4 и мусор — default-deny (туннель IPv4-only). Обрезанный TCP/UDP-заголовок тоже.
    #[test]
    fn non_ipv4_and_truncated_are_denied() {
        let seen = EgressSeen::new();
        assert_eq!(verdict(&[0x60, 0, 0, 0, 0, 0], ME, &seen), Err(Drop::NotV4)); // IPv6
        assert_eq!(verdict(&[0xff], ME, &seen), Err(Drop::NotV4)); // мусор
        // IPv4 к нам, но payload короче портов → как «без запроса»
        let short = build_ipv4(17, REMOTE, ME, &[0, 53]);
        assert_eq!(verdict(&short, ME, &seen), Err(Drop::Unsolicited));
    }

    /// Непервый фрагмент к нашему адресу пропускается (ядро без первого фрагмента ничего не
    /// соберёт), но фрагмент на ЧУЖОЙ адрес — по-прежнему дроп.
    #[test]
    fn non_first_fragment_passes_only_for_our_address() {
        let seen = EgressSeen::new();
        let mut frag = udp(REMOTE, 53, ME, 40000);
        frag[6] = 0x00;
        frag[7] = 0x20; // offset = 32 блока
        assert_eq!(verdict(&frag, ME, &seen), Ok(()), "порты не читаются — но и вреда нет");
        let mut foreign = udp(REMOTE, 53, [192, 168, 1, 50], 40000);
        foreign[6] = 0x00;
        foreign[7] = 0x20;
        assert_eq!(verdict(&foreign, ME, &seen), Err(Drop::NotOurs));
    }

    /// UDP-порт остаётся открытым для ЛЮБОГО источника — так работает hole-punching (WebRTC/VoIP):
    /// ответ приходит с адреса, к которому мы не обращались, но на наш порт.
    #[test]
    fn udp_hole_punching_still_works() {
        let seen = EgressSeen::new();
        seen.note(&ip::parse_ipv4(&udp(ME, 33333, [8, 8, 8, 8], 3478)).unwrap());
        assert_eq!(verdict(&udp([203, 0, 113, 7], 55555, ME, 33333), ME, &seen), Ok(()));
    }

    /// Счётчики: `ClientFilter` считает дропы по причинам и называет последний чужой `dst`.
    #[test]
    fn filter_counts_drops_by_reason() {
        let f = ClientFilter::new(ME);
        assert!(!f.audit_only(), "по умолчанию фильтр ДРОПАЕТ, а не наблюдает");
        f.note_egress(&ip::parse_ipv4(&udp(ME, 40000, REMOTE, 53)).unwrap());
        assert!(f.accept(&udp(REMOTE, 53, ME, 40000)));
        assert!(!f.accept(&tcp(REMOTE, 1, ME, 22, 0x02)));
        assert!(!f.accept(&udp(REMOTE, 53, [192, 168, 1, 50], 40000)));
        assert!(!f.accept(&[0x60, 0, 0, 0, 0, 0]));
        assert!(!f.accept(&build_icmp_echo_request(REMOTE, ME, 1, 1, b"x")));
        let (nv4, ours, uns, icmp, last) = f.counters();
        assert_eq!((nv4, ours, uns, icmp), (1, 1, 1, 1));
        assert_eq!(last, Some([192, 168, 1, 50]));
    }
}
