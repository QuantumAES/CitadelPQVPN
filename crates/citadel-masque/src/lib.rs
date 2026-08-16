//! CitadelPQVPN — `citadel-masque`: data-plane обвязка CONNECT-IP (SPEC §5.3, §6).
//!
//! Содержит:
//! - [`varint`]    — QUIC variable-length integers (RFC 9000 §16);
//! - [`datagram`]  — payload HTTP-датаграммы CONNECT-IP (RFC 9484 §6 / RFC 9297): `Context ID ‖ IP`;
//! - [`capsule`]   — формат капсул (RFC 9297 §3.2) + ADDRESS_ASSIGN/REQUEST (RFC 9484 §4.7);
//! - [`ip`]        — минимальные IPv4/ICMP/UDP/DNS помощники для прогонки реальных пакетов.
//!
//! Это L3 (data plane). Транспорт — QUIC DATAGRAM поверх PQ-соединения (M0).
#![forbid(unsafe_code)]

// =====================================================================================
pub mod varint {
    //! QUIC variable-length integers, RFC 9000 §16.
    pub fn encode(v: u64, out: &mut Vec<u8>) {
        if v <= 63 {
            out.push(v as u8);
        } else if v <= 16383 {
            out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
        } else if v <= 1_073_741_823 {
            out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
        } else if v <= 4_611_686_018_427_387_903 {
            out.extend_from_slice(&(v | 0xC000_0000_0000_0000).to_be_bytes());
        } else {
            panic!("varint out of range");
        }
    }

    pub fn to_vec(v: u64) -> Vec<u8> {
        let mut o = Vec::new();
        encode(v, &mut o);
        o
    }

    /// Возвращает `(value, bytes_consumed)`.
    pub fn decode(buf: &[u8]) -> Option<(u64, usize)> {
        let first = *buf.first()?;
        let len = 1usize << (first >> 6); // 1, 2, 4 или 8
        if buf.len() < len {
            return None;
        }
        let mut v = (first & 0x3f) as u64;
        for &b in &buf[1..len] {
            v = (v << 8) | b as u64;
        }
        Some((v, len))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn rfc9000_appendix_a() {
            // Канонические векторы RFC 9000.
            assert_eq!(decode(&[0x25]).unwrap(), (37, 1));
            assert_eq!(decode(&[0x7b, 0xbd]).unwrap(), (15293, 2));
            assert_eq!(decode(&[0x9d, 0x7f, 0x3e, 0x7d]).unwrap(), (494_878_333, 4));
            assert_eq!(
                decode(&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]).unwrap(),
                (151_288_809_941_952_652, 8)
            );
            assert_eq!(to_vec(37), vec![0x25]);
            assert_eq!(to_vec(15293), vec![0x7b, 0xbd]);
            for v in [0u64, 63, 64, 16383, 16384, 1_073_741_823, 1_073_741_824] {
                assert_eq!(decode(&to_vec(v)).unwrap().0, v);
            }
        }
    }
}

// =====================================================================================
pub mod datagram {
    //! Payload HTTP-датаграммы для CONNECT-IP (RFC 9484 §6): `Context ID (varint) ‖ IP-пакет`.
    //! Context ID = 0 → «сырой» IP-пакет (uncompressed).
    use super::varint;

    pub const CTX_RAW_IP: u64 = 0;

    /// M-8/аудит-4: собственный keep-alive туннеля. Полезной нагрузки не несёт, приёмник его
    /// молча отбрасывает (он не `CTX_RAW_IP` ⇒ в TUN не попадает), но для QUIC это обычный
    /// ack-eliciting пакет — то есть он держит и NAT-биндинг, и idle-таймер.
    ///
    /// Зачем свой, если у quinn есть `keep_alive_interval`: тот шлёт PING строго периодически
    /// (5,000 с), и в простое туннель превращается в идеальный маяк — период снимается
    /// автокорреляцией по десятку интервалов, независимо от того, что размеры пакетов уже
    /// замаскированы паддингом L1. Свой keep-alive шлётся со случайным интервалом и со случайной
    /// длиной, а `keep_alive_interval` quinn остаётся страховкой на случай, если задача умрёт.
    /// Контекст 1 из «приватного» диапазона: RFC 9484 присваивает context id динамически, наш
    /// профиль фиксирует только 0 = сырой IP, так что коллизии с чужим ПО тут быть не может.
    pub const CTX_KEEPALIVE: u64 = 1;

    pub fn encode(context_id: u64, ip_packet: &[u8]) -> Vec<u8> {
        let mut o = varint::to_vec(context_id);
        o.extend_from_slice(ip_packet);
        o
    }

    pub fn decode(buf: &[u8]) -> Option<(u64, &[u8])> {
        let (ctx, n) = varint::decode(buf)?;
        Some((ctx, &buf[n..]))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn roundtrip_raw_ip() {
            let ip = [0x45u8, 0x00, 0x00, 0x14];
            let dg = encode(CTX_RAW_IP, &ip);
            assert_eq!(dg, vec![0x00, 0x45, 0x00, 0x00, 0x14]); // ctx=0 → один байт 0x00
            let (ctx, payload) = decode(&dg).unwrap();
            assert_eq!(ctx, 0);
            assert_eq!(payload, &ip);
        }
    }
}

// =====================================================================================
pub mod capsule {
    //! Capsule Protocol (RFC 9297 §3.2): `Type (varint) ‖ Length (varint) ‖ Value`.
    //! Типы CONNECT-IP — RFC 9484 §4.7.
    use super::varint;

    pub const ADDRESS_ASSIGN: u64 = 1;
    pub const ADDRESS_REQUEST: u64 = 2;
    pub const ROUTE_ADVERTISEMENT: u64 = 3;

    pub fn encode(captype: u64, value: &[u8]) -> Vec<u8> {
        let mut o = varint::to_vec(captype);
        varint::encode(value.len() as u64, &mut o);
        o.extend_from_slice(value);
        o
    }

    /// `(type, value, total_consumed)`
    pub fn decode(buf: &[u8]) -> Option<(u64, &[u8], usize)> {
        let (t, n1) = varint::decode(buf)?;
        let (len, n2) = varint::decode(&buf[n1..])?;
        let start = n1 + n2;
        let end = start.checked_add(len as usize)?;
        if buf.len() < end {
            return None;
        }
        Some((t, &buf[start..end], end))
    }

    /// Одна назначенная (или запрошенная) IPv4-сеть (RFC 9484 §4.7.1/4.7.2).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct AssignedV4 {
        pub request_id: u64,
        pub addr: [u8; 4],
        pub prefix: u8,
    }

    fn encode_v4_body(a: &AssignedV4) -> Vec<u8> {
        let mut v = varint::to_vec(a.request_id);
        v.push(4); // IP Version
        v.extend_from_slice(&a.addr);
        v.push(a.prefix);
        v
    }

    fn decode_v4_body(value: &[u8]) -> Option<AssignedV4> {
        let (rid, n) = varint::decode(value)?;
        let rest = &value[n..];
        if rest.len() < 6 || rest[0] != 4 {
            return None;
        }
        let mut addr = [0u8; 4];
        addr.copy_from_slice(&rest[1..5]);
        let prefix = rest[5];
        // Ф1 (цель `capsule_address`, найдено фаззером 2026-08-16): длина IPv4-префикса больше 32
        // не существует ни при каком корректном пире — это не «странное значение», а невозможное
        // состояние, и разбор не имеет права выпускать его наружу. Политику («какой префикс
        // разумно принять от exit'а») по-прежнему решает вызывающий: клиент требует /12../30
        // (`client::validate_assignment`, H-4), демон границы привилегий — 1..=32
        // (`vpnd::valid`). Здесь — только физическая невозможность.
        //
        // `prefix == 0` остаётся законным: клиент шлёт им ADDRESS_REQUEST («префикс не указан»).
        //
        // Живой уязвимости на момент находки не было — оба потребителя проверяют диапазон сами;
        // это снятие класса, а не заплатка на дыру.
        if prefix > 32 {
            return None;
        }
        Some(AssignedV4 { request_id: rid, addr, prefix })
    }

    pub fn encode_address_assign_v4(a: &AssignedV4) -> Vec<u8> {
        encode(ADDRESS_ASSIGN, &encode_v4_body(a))
    }
    pub fn encode_address_request_v4(a: &AssignedV4) -> Vec<u8> {
        encode(ADDRESS_REQUEST, &encode_v4_body(a))
    }
    pub fn decode_assigned_v4(value: &[u8]) -> Option<AssignedV4> {
        decode_v4_body(value)
    }

    /// **П5 (батарея): необязательный хвост тела капсулы — `varint(max_idle_timeout в мс)`.**
    ///
    /// Зачем на проводе: эффективный idle-таймаут QUIC равен МИНИМУМУ из объявленных сторонами
    /// (RFC 9000 §10.1), а редкий keep-alive (единственное, что даёт модему уйти в idle между
    /// маячками) безопасен, только если этот минимум заведомо больше интервала маячка. Своё
    /// значение сторона знает, чужое — нет: quinn негоциированный таймаут наружу не отдаёт.
    /// Поэтому каждая сторона называет своё прямо в control-обмене, а редкий режим включается,
    /// лишь если названное пиром значение достаточно велико (см. `dataplane::keepalive_delay`).
    ///
    /// Обратная совместимость в обе стороны: старый пир хвоста не шлёт — новый видит `None` и
    /// остаётся на частом маячке; старый пир хвост игнорирует ([`decode_v4_body`] читает ровно
    /// свои 6 байт и не смотрит дальше), поэтому добавление поля не ломает провод.
    pub fn encode_address_assign_v4_hint(a: &AssignedV4, idle_ms: Option<u64>) -> Vec<u8> {
        encode(ADDRESS_ASSIGN, &encode_v4_body_hint(a, idle_ms))
    }
    pub fn encode_address_request_v4_hint(a: &AssignedV4, idle_ms: Option<u64>) -> Vec<u8> {
        encode(ADDRESS_REQUEST, &encode_v4_body_hint(a, idle_ms))
    }

    fn encode_v4_body_hint(a: &AssignedV4, idle_ms: Option<u64>) -> Vec<u8> {
        let mut v = encode_v4_body(a);
        if let Some(ms) = idle_ms {
            v.extend_from_slice(&varint::to_vec(ms));
        }
        v
    }

    /// Прочитать хвост-подсказку из тела капсулы. `None` — пир её не прислал (старая версия)
    /// либо тело битое.
    pub fn decode_idle_hint(value: &[u8]) -> Option<u64> {
        let (_, n) = varint::decode(value)?;
        let rest = value.get(n..)?;
        if rest.len() < 6 || rest[0] != 4 {
            return None;
        }
        varint::decode(rest.get(6..)?).map(|(ms, _)| ms)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn address_assign_vector() {
            let a = AssignedV4 { request_id: 0, addr: [10, 7, 0, 2], prefix: 32 };
            let cap = encode_address_assign_v4(&a);
            // type=01, len=07, value = rid(00) ver(04) ip(0a070002) prefix(20)
            assert_eq!(hex::encode(&cap), "010700040a07000220");
            let (t, val, used) = decode(&cap).unwrap();
            assert_eq!(t, ADDRESS_ASSIGN);
            assert_eq!(used, cap.len());
            assert_eq!(decode_assigned_v4(val).unwrap(), a);
        }

        /// Ф1 (регрессия по находке фаззера, цель `capsule_address`, 2026-08-16): тело капсулы с
        /// префиксом больше 32 не разбирается вовсе.
        ///
        /// Вход `33 04 00 00 00 00 4b 24` — ровно тот, что нашёл libFuzzer: `varint(0x33)`, версия
        /// 4, адрес `0.0.0.0`, префикс `0x4b` = 75. Раньше он выходил из разбора «валидной»
        /// структурой, и правильность держалась на том, что оба потребителя проверяют диапазон
        /// сами. Держится и сейчас — но невозможное состояние больше не создаётся.
        ///
        /// `prefix == 0` обязан остаться разбираемым: им клиент шлёт ADDRESS_REQUEST.
        #[test]
        fn prefix_above_32_is_not_a_capsule() {
            let bad = [0x33u8, 0x04, 0, 0, 0, 0, 0x4b, 0x24];
            assert!(decode_assigned_v4(&bad).is_none(), "префикс /75 не существует");
            let _ = decode_idle_hint(&bad); // соседний разбор того же тела не паникует

            let req = AssignedV4 { request_id: 1, addr: [0, 0, 0, 0], prefix: 0 };
            let cap = encode_address_request_v4(&req);
            let (_, val, _) = decode(&cap).unwrap();
            assert_eq!(decode_assigned_v4(val).unwrap(), req, "/0 в запросе законен");

            let edge = AssignedV4 { request_id: 1, addr: [10, 0, 0, 1], prefix: 32 };
            let cap = encode_address_assign_v4(&edge);
            let (_, val, _) = decode(&cap).unwrap();
            assert_eq!(decode_assigned_v4(val).unwrap(), edge, "/32 — граница, она внутри");
        }

        /// П5: хвост-подсказка читается новым пиром и НЕ мешает старому — тот разбирает те же
        /// адрес и префикс, просто не смотрит дальше своих шести байт. Это и есть условие, при
        /// котором редкий keep-alive можно катить, не ломая связь с прежними версиями.
        #[test]
        fn idle_hint_is_backward_compatible() {
            let a = AssignedV4 { request_id: 1, addr: [10, 7, 0, 9], prefix: 24 };
            let cap = encode_address_assign_v4_hint(&a, Some(90_000));
            let (t, val, used) = decode(&cap).unwrap();
            assert_eq!(t, ADDRESS_ASSIGN);
            assert_eq!(used, cap.len());
            assert_eq!(decode_assigned_v4(val).unwrap(), a, "старый разбор тела не сломан");
            assert_eq!(decode_idle_hint(val), Some(90_000));
            // без хвоста — None (пир прежней версии): режим маячка останется частым
            let plain = encode_address_assign_v4(&a);
            let (_, val, _) = decode(&plain).unwrap();
            assert_eq!(decode_idle_hint(val), None);
        }
    }
}

// =====================================================================================
pub mod ip {
    //! Минимальные IPv4 / ICMP-echo / UDP / DNS помощники (без зависимостей).
    //! Достаточно для прогонки ping и DNS-запроса через туннель.

    /// Internet checksum (RFC 1071), 16-битная one's-complement сумма.
    pub fn inet_checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < data.len() {
            sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
            i += 2;
        }
        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// IPv4-пакет без опций (IHL=5), checksum заголовка посчитан.
    pub fn build_ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut h = vec![0x45, 0x00];
        h.extend_from_slice(&(total as u16).to_be_bytes());
        h.extend_from_slice(&[0, 0]); // identification
        h.extend_from_slice(&[0x40, 0x00]); // flags=DF
        h.push(64); // TTL
        h.push(proto);
        h.extend_from_slice(&[0, 0]); // header checksum (placeholder)
        h.extend_from_slice(&src);
        h.extend_from_slice(&dst);
        let c = inet_checksum(&h);
        h[10..12].copy_from_slice(&c.to_be_bytes());
        h.extend_from_slice(payload);
        h
    }

    pub struct Ipv4View<'a> {
        pub ihl: usize,
        pub proto: u8,
        pub src: [u8; 4],
        pub dst: [u8; 4],
        pub payload: &'a [u8],
    }

    pub fn parse_ipv4(pkt: &[u8]) -> Option<Ipv4View<'_>> {
        if pkt.len() < 20 || pkt[0] >> 4 != 4 {
            return None;
        }
        let ihl = ((pkt[0] & 0x0f) as usize) * 4;
        if pkt.len() < ihl || ihl < 20 {
            return None;
        }
        let total = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        let end = total.min(pkt.len());
        if end < ihl {
            return None;
        }
        let mut src = [0u8; 4];
        let mut dst = [0u8; 4];
        src.copy_from_slice(&pkt[12..16]);
        dst.copy_from_slice(&pkt[16..20]);
        Some(Ipv4View { ihl, proto: pkt[9], src, dst, payload: &pkt[ihl..end] })
    }

    /// Порт назначения TCP-сегмента внутри IPv4-пакета (`None`, если это не TCP или заголовок
    /// усечён). C7.2: exit по нему точечно разрешает admin-VIP:порт мимо egress-фильтра.
    pub fn tcp_dport(v: &Ipv4View<'_>) -> Option<u16> {
        if v.proto != 6 || v.payload.len() < 4 {
            return None;
        }
        Some(u16::from_be_bytes([v.payload[2], v.payload[3]]))
    }

    /// Назначение, которое exit НЕ должен форвардить (анти-пивот во внутреннюю сеть):
    /// приватные/loopback/link-local(incl. 169.254.169.254 metadata)/CGNAT/multicast/reserved
    /// плюс IANA special-purpose (RFC 6890) и облачные metadata-адреса вне link-local.
    ///
    /// **L-1/аудит-4.** Одного 169.254.169.254 недостаточно: у Azure «wireserver» живёт на
    /// **168.63.129.16** — это адрес из ГЛОБАЛЬНО маршрутизируемого диапазона, поэтому прежний
    /// фильтр его пропускал, и абонент дотягивался из туннеля до metadata-плоскости хостера
    /// (в т.ч. до agent'а расширений, т.е. до потенциального RCE на самом VPS). Заодно закрыты
    /// диапазоны, которых в интернете быть не может, но которые ядро/приложения трактуют
    /// по-особому: `192.0.0.0/24` (IETF protocol assignments, DS-Lite `192.0.0.0/29`),
    /// TEST-NET-1/2/3, `198.18.0.0/15` (benchmarking — на роутерах часто заведён локально),
    /// `192.88.99.0/24` (6to4-relay anycast).
    pub fn is_blocked_dst(a: [u8; 4]) -> bool {
        match a {
            [0, ..] => true,                       // 0.0.0.0/8 «this host»
            [10, ..] => true,                      // 10.0.0.0/8 private
            [127, ..] => true,                     // 127.0.0.0/8 loopback
            [169, 254, ..] => true,                // 169.254.0.0/16 link-local + metadata
            [172, b, ..] if (16..=31).contains(&b) => true, // 172.16/12 private (docker!)
            [192, 168, ..] => true,                // 192.168.0.0/16 private
            [100, b, ..] if (64..=127).contains(&b) => true, // 100.64/10 CGNAT
            [168, 63, 129, 16] => true,            // L-1: Azure IMDS/wireserver (публичный диапазон!)
            [192, 0, 0, ..] => true,               // 192.0.0.0/24 IETF protocol assignments (DS-Lite)
            [192, 0, 2, ..] => true,               // TEST-NET-1
            [198, 51, 100, ..] => true,            // TEST-NET-2
            [203, 0, 113, ..] => true,             // TEST-NET-3
            [198, b, ..] if (18..=19).contains(&b) => true, // 198.18.0.0/15 benchmarking
            [192, 88, 99, ..] => true,             // 192.88.99.0/24 6to4-relay anycast (deprecated)
            [b, ..] if b >= 224 => true,           // 224/4 multicast + 240/4 reserved + 255.. broadcast
            _ => false,                            // публичный — разрешаем
        }
    }

    // ---- ICMP echo ----
    pub fn build_icmp_echo_request(src: [u8; 4], dst: [u8; 4], id: u16, seq: u16, data: &[u8]) -> Vec<u8> {
        let mut icmp = vec![8u8, 0, 0, 0];
        icmp.extend_from_slice(&id.to_be_bytes());
        icmp.extend_from_slice(&seq.to_be_bytes());
        icmp.extend_from_slice(data);
        let c = inet_checksum(&icmp);
        icmp[2..4].copy_from_slice(&c.to_be_bytes());
        build_ipv4(1, src, dst, &icmp)
    }

    /// Для echo (type 8) или reply (type 0) → `(type, id, seq)`.
    pub fn icmp_echo_kind(pkt: &[u8]) -> Option<(u8, u16, u16)> {
        let v = parse_ipv4(pkt)?;
        if v.proto != 1 || v.payload.len() < 8 {
            return None;
        }
        let t = v.payload[0];
        if t != 0 && t != 8 {
            return None;
        }
        Some((t, u16::from_be_bytes([v.payload[4], v.payload[5]]), u16::from_be_bytes([v.payload[6], v.payload[7]])))
    }

    /// Синтез echo-reply из echo-request (роль userspace-exit для ping).
    pub fn build_icmp_echo_reply(req: &[u8]) -> Option<Vec<u8>> {
        let v = parse_ipv4(req)?;
        if v.proto != 1 || v.payload.is_empty() || v.payload[0] != 8 {
            return None;
        }
        let mut icmp = v.payload.to_vec();
        icmp[0] = 0; // echo reply
        icmp[2] = 0;
        icmp[3] = 0;
        let c = inet_checksum(&icmp);
        icmp[2..4].copy_from_slice(&c.to_be_bytes());
        Some(build_ipv4(1, v.dst, v.src, &icmp)) // src/dst swap
    }

    // ---- UDP ----
    fn udp_checksum(src: [u8; 4], dst: [u8; 4], udp: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for chunk in [&src[..], &dst[..]] {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            sum += u16::from_be_bytes([chunk[2], chunk[3]]) as u32;
        }
        sum += 17; // zero || protocol
        sum += udp.len() as u32; // UDP length (в псевдозаголовке)
        let mut i = 0;
        while i + 1 < udp.len() {
            sum += u16::from_be_bytes([udp[i], udp[i + 1]]) as u32;
            i += 2;
        }
        if i < udp.len() {
            sum += (udp[i] as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let c = !(sum as u16);
        if c == 0 {
            0xffff
        } else {
            c
        }
    }

    pub fn build_udp4(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, payload: &[u8]) -> Vec<u8> {
        let ulen = 8 + payload.len();
        let mut udp = Vec::with_capacity(ulen);
        udp.extend_from_slice(&sport.to_be_bytes());
        udp.extend_from_slice(&dport.to_be_bytes());
        udp.extend_from_slice(&(ulen as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]); // checksum placeholder
        udp.extend_from_slice(payload);
        let c = udp_checksum(src, dst, &udp);
        udp[6..8].copy_from_slice(&c.to_be_bytes());
        build_ipv4(17, src, dst, &udp)
    }

    pub struct Udp4<'a> {
        pub src: [u8; 4],
        pub dst: [u8; 4],
        pub sport: u16,
        pub dport: u16,
        pub payload: &'a [u8],
    }

    pub fn parse_udp4(pkt: &[u8]) -> Option<Udp4<'_>> {
        let v = parse_ipv4(pkt)?;
        if v.proto != 17 || v.payload.len() < 8 {
            return None;
        }
        let ulen = u16::from_be_bytes([v.payload[4], v.payload[5]]) as usize;
        let end = ulen.min(v.payload.len());
        if end < 8 {
            return None;
        }
        // payload UDP вычисляем как срез исходного пакета, чтобы вернуть ссылку с нужным lifetime
        let start = v.ihl + 8;
        let stop = v.ihl + end;
        Some(Udp4 {
            src: v.src,
            dst: v.dst,
            sport: u16::from_be_bytes([v.payload[0], v.payload[1]]),
            dport: u16::from_be_bytes([v.payload[2], v.payload[3]]),
            payload: &pkt[start..stop],
        })
    }

    // ---- минимальный TCP (для admin-пробы по туннелю) ----
    pub const TCP_FIN: u8 = 0x01;
    pub const TCP_SYN: u8 = 0x02;
    pub const TCP_RST: u8 = 0x04;
    pub const TCP_ACK: u8 = 0x10;

    /// Контрольная сумма TCP — тот же алгоритм, что у UDP, но `proto=6` в псевдозаголовке
    /// и длина = длина сегмента (у TCP нет собственного поля длины).
    fn tcp_checksum(src: [u8; 4], dst: [u8; 4], seg: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for chunk in [&src[..], &dst[..]] {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            sum += u16::from_be_bytes([chunk[2], chunk[3]]) as u32;
        }
        sum += 6; // zero || protocol (TCP)
        sum += seg.len() as u32;
        let mut i = 0;
        while i + 1 < seg.len() {
            sum += u16::from_be_bytes([seg[i], seg[i + 1]]) as u32;
            i += 2;
        }
        if i < seg.len() {
            sum += (seg[i] as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Минимальный TCP-сегмент без опций и без данных (data offset = 5) в IPv4-пакете.
    /// Нужен диагностической admin-пробе: SYN к `ADMIN_VIP:порт` прямо в туннель (мимо ОС-роутинга)
    /// и RST для закрытия полуоткрытого соединения на issuer'е.
    #[allow(clippy::too_many_arguments)] // ровно поля TCP-заголовка: группировать не во что
    pub fn build_tcp4(
        src: [u8; 4],
        sport: u16,
        dst: [u8; 4],
        dport: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
    ) -> Vec<u8> {
        let mut seg = Vec::with_capacity(20);
        seg.extend_from_slice(&sport.to_be_bytes());
        seg.extend_from_slice(&dport.to_be_bytes());
        seg.extend_from_slice(&seq.to_be_bytes());
        seg.extend_from_slice(&ack.to_be_bytes());
        seg.push(5 << 4); // data offset = 5 слов (20 б), reserved = 0
        seg.push(flags);
        seg.extend_from_slice(&window.to_be_bytes());
        seg.extend_from_slice(&[0, 0]); // checksum (placeholder)
        seg.extend_from_slice(&[0, 0]); // urgent pointer
        let c = tcp_checksum(src, dst, &seg);
        seg[16..18].copy_from_slice(&c.to_be_bytes());
        build_ipv4(6, src, dst, &seg)
    }

    pub struct Tcp4 {
        pub src: [u8; 4],
        pub dst: [u8; 4],
        pub sport: u16,
        pub dport: u16,
        pub seq: u32,
        pub ack: u32,
        pub flags: u8,
    }

    /// Разбор TCP-заголовка внутри IPv4-пакета (`None` — не TCP/обрезан).
    pub fn parse_tcp4(pkt: &[u8]) -> Option<Tcp4> {
        let v = parse_ipv4(pkt)?;
        if v.proto != 6 || v.payload.len() < 20 {
            return None;
        }
        let p = v.payload;
        Some(Tcp4 {
            src: v.src,
            dst: v.dst,
            sport: u16::from_be_bytes([p[0], p[1]]),
            dport: u16::from_be_bytes([p[2], p[3]]),
            seq: u32::from_be_bytes([p[4], p[5], p[6], p[7]]),
            ack: u32::from_be_bytes([p[8], p[9], p[10], p[11]]),
            flags: p[13],
        })
    }

    // ---- минимальный DNS ----
    pub fn build_dns_query(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&id.to_be_bytes());
        m.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
        m.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        m.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR = 0
        for label in qname.split('.').filter(|l| !l.is_empty()) {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
        m
    }

    fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
        loop {
            let b = *msg.get(pos)?;
            if b & 0xc0 == 0xc0 {
                return Some(pos + 2); // compression pointer завершает имя
            }
            if b == 0 {
                return Some(pos + 1);
            }
            pos += 1 + b as usize;
            if pos > msg.len() {
                return None;
            }
        }
    }

    /// `(id, ancount, [A-records])`
    pub fn parse_dns_response(msg: &[u8]) -> Option<(u16, u16, Vec<[u8; 4]>)> {
        if msg.len() < 12 {
            return None;
        }
        let id = u16::from_be_bytes([msg[0], msg[1]]);
        let qd = u16::from_be_bytes([msg[4], msg[5]]);
        let an = u16::from_be_bytes([msg[6], msg[7]]);
        let mut pos = 12;
        for _ in 0..qd {
            pos = skip_name(msg, pos)?;
            pos += 4; // QTYPE + QCLASS
        }
        let mut addrs = Vec::new();
        for _ in 0..an {
            pos = skip_name(msg, pos)?;
            if pos + 10 > msg.len() {
                break;
            }
            let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
            let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
            pos += 10;
            if pos + rdlen > msg.len() {
                break;
            }
            if rtype == 1 && rdlen == 4 {
                addrs.push([msg[pos], msg[pos + 1], msg[pos + 2], msg[pos + 3]]);
            }
            pos += rdlen;
        }
        Some((id, an, addrs))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn icmp_echo_roundtrip_and_checksums() {
            let req = build_icmp_echo_request([10, 7, 0, 2], [10, 7, 0, 1], 0x1234, 7, b"Citadel");
            // заголовок IP валиден (полная сумма == 0)
            assert_eq!(inet_checksum(&req[..20]), 0);
            // ICMP валиден
            let v = parse_ipv4(&req).unwrap();
            assert_eq!(inet_checksum(v.payload), 0);
            assert_eq!(icmp_echo_kind(&req), Some((8, 0x1234, 7)));

            let reply = build_icmp_echo_reply(&req).unwrap();
            assert_eq!(icmp_echo_kind(&reply), Some((0, 0x1234, 7)));
            let rv = parse_ipv4(&reply).unwrap();
            assert_eq!(rv.src, [10, 7, 0, 1]); // swap
            assert_eq!(rv.dst, [10, 7, 0, 2]);
            assert_eq!(inet_checksum(&reply[..20]), 0);
            assert_eq!(inet_checksum(rv.payload), 0);
        }

        #[test]
        fn udp_roundtrip_and_checksum() {
            let pkt = build_udp4([10, 7, 0, 2], 5353, [1, 1, 1, 1], 53, b"hello-dns");
            let u = parse_udp4(&pkt).unwrap();
            assert_eq!((u.sport, u.dport), (5353, 53));
            assert_eq!(u.dst, [1, 1, 1, 1]);
            assert_eq!(u.payload, b"hello-dns");
            assert_eq!(inet_checksum(&pkt[..20]), 0); // IP ок
        }

        /// TCP-хелпер admin-пробы: собранный SYN парсится обратно, контрольные суммы IP и TCP
        /// сходятся (полная сумма сегмента с псевдозаголовком == 0), флаги/порты на месте.
        #[test]
        fn tcp_syn_roundtrip_and_checksum() {
            let src = [10, 7, 0, 9];
            let dst = [10, 7, 0, 1];
            let pkt = build_tcp4(src, 41000, dst, 7001, 0xdead_beef, 0, TCP_SYN, 64240);
            assert_eq!(inet_checksum(&pkt[..20]), 0); // IP-заголовок валиден
            let t = parse_tcp4(&pkt).unwrap();
            assert_eq!((t.sport, t.dport), (41000, 7001));
            assert_eq!((t.src, t.dst), (src, dst));
            assert_eq!(t.seq, 0xdead_beef);
            assert_eq!(t.flags, TCP_SYN);
            // TCP-сумма: пересчёт по полученному сегменту (вместе с записанной суммой) даёт 0
            let v = parse_ipv4(&pkt).unwrap();
            assert_eq!(tcp_checksum(src, dst, v.payload), 0);
            // не-TCP (UDP) через tcp-парсер — None (default-deny, не паника)
            assert!(parse_tcp4(&build_udp4(src, 1, dst, 2, b"x")).is_none());
        }

        #[test]
        fn dns_query_format_and_response_parse() {
            let q = build_dns_query(0xabcd, "example.com", 1);
            assert!(q.starts_with(&[0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
            // 07 'example' 03 'com' 00 0001 0001
            assert_eq!(
                hex::encode(&q[12..]),
                "076578616d706c6503636f6d000001 0001".replace(' ', "")
            );
            // ответ с одним A-записью (имя — указатель 0xc00c)
            let resp = hex::decode(
                "abcd8180000100010000000007 6578616d706c6503636f6d0000010001\
                 c00c0001000100000e1000045db8d822"
                    .replace(' ', ""),
            )
            .unwrap();
            let (id, an, addrs) = parse_dns_response(&resp).unwrap();
            assert_eq!(id, 0xabcd);
            assert_eq!(an, 1);
            assert_eq!(addrs, vec![[93, 184, 216, 34]]);
        }

        #[test]
        fn egress_filter_blocks_internal() {
            // публичные — разрешены
            assert!(!is_blocked_dst([1, 1, 1, 1]));
            assert!(!is_blocked_dst([93, 184, 216, 34]));
            assert!(!is_blocked_dst([8, 8, 8, 8]));
            // служебные/внутренние — блок
            for a in [
                [10, 0, 0, 1],
                [172, 18, 0, 1],     // docker-сеть
                [192, 168, 1, 1],
                [127, 0, 0, 1],
                [169, 254, 169, 254], // cloud metadata
                [100, 64, 0, 1],      // CGNAT
                [224, 0, 0, 1],       // multicast
                [0, 0, 0, 0],
                // L-1: metadata вне link-local + IANA special-purpose
                [168, 63, 129, 16],  // Azure wireserver — публичный диапазон, но metadata
                [192, 0, 0, 8],      // IETF protocol assignments
                [192, 0, 2, 5],      // TEST-NET-1
                [198, 51, 100, 5],   // TEST-NET-2
                [203, 0, 113, 5],    // TEST-NET-3
                [198, 18, 0, 1],     // benchmarking
                [198, 19, 255, 254], // benchmarking (верхняя граница /15)
                [192, 88, 99, 1],    // 6to4-relay anycast
            ] {
                assert!(is_blocked_dst(a), "{a:?} должен быть заблокирован");
            }
            assert!(!is_blocked_dst([172, 15, 0, 1])); // вне 172.16/12 — публичный
            assert!(!is_blocked_dst([172, 32, 0, 1]));
            // соседние адреса заблокированных диапазонов остаются публичными (нет over-block)
            assert!(!is_blocked_dst([168, 63, 129, 17]));
            assert!(!is_blocked_dst([168, 63, 128, 16]));
            assert!(!is_blocked_dst([192, 0, 1, 1])); // между 192.0.0/24 и TEST-NET-1
            assert!(!is_blocked_dst([198, 20, 0, 1])); // сразу за 198.18/15
            assert!(!is_blocked_dst([198, 17, 255, 254]));
            assert!(!is_blocked_dst([203, 0, 114, 1]));
        }
    }
}

// ----------------------- robustness / fuzz (no-panic на недоверенном вводе, M6) -----------------------
// cargo-fuzz недоступен (нет nightly/rustup) → детерминированные robustness-тесты на stable: ВСЕ
// парсеры из сети/туннеля (varint/datagram/capsule/ip/icmp/udp/dns) не должны паниковать ни на каком
// вводе (анти-DoS на malformed). PRNG — inline xorshift. Часть ввода с IPv4-hint (0x45) — для глубины.
#[cfg(test)]
mod fuzz {
    use super::*;

    fn xs(seed: &mut u64) -> u64 {
        let mut x = *seed;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *seed = x;
        x
    }

    #[test]
    fn fuzz_all_parsers_no_panic() {
        let mut s = 0x0123_4567_89ab_cdefu64;
        for _ in 0..100_000 {
            let len = (xs(&mut s) % 1500) as usize;
            let mut b: Vec<u8> = (0..len).map(|_| (xs(&mut s) >> 33) as u8).collect();
            // иногда «похоже на IPv4» (version=4, ihl=5) — чтобы парсеры шли глубже
            if !b.is_empty() && xs(&mut s).is_multiple_of(2) {
                b[0] = 0x45;
            }
            let _ = varint::decode(&b);
            let _ = datagram::decode(&b);
            let _ = capsule::decode(&b);
            let _ = capsule::decode_assigned_v4(&b);
            let _ = ip::parse_ipv4(&b);
            let _ = ip::icmp_echo_kind(&b);
            let _ = ip::build_icmp_echo_reply(&b);
            let _ = ip::parse_udp4(&b);
            let _ = ip::parse_tcp4(&b);
            let _ = ip::parse_dns_response(&b);
        }
    }
}
