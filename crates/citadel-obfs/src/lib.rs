//! CitadelPQVPN — obfs L1 (Фаза 0), протокол v1.
//!
//! Симметричная, на pre-shared key, обёртка датаграмм QUIC в стиле Shadowsocks-2022.
//! Нормативный формат, KDF и тест-векторы — в `docs/PHASE0-OBFS.md`.
//!
//! Это L1: обфускация + probe-resistance, НЕ замена реальной конфиденциальности L2.
//!
//! Формат пакета:
//! ```text
//! nonce_pkt(12) ‖ enc_header(16) ‖ aead_body(var)
//!   enc_header = (sid(8) ‖ packet_id(8 BE)) XOR ChaCha20(K_hdr, nonce_pkt)[0:16]
//!   aead_body  = ChaCha20Poly1305(K_sess(sid), body_nonce, AAD=nonce_pkt‖enc_header)(inner)
//! ```
#![forbid(unsafe_code)]

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};

// --- доменно-разделённые контексты KDF (фиксированы протоколом) ---
pub const CTX_HDR: &str = "CitadelPQVPN/obfs/v1/header";
pub const CTX_SESSION: &str = "CitadelPQVPN/obfs/v1/session";

// --- типы пакетов ---
pub const TYPE_INIT_C: u8 = 0x01; // первый пакет клиента (несёт timestamp)
pub const TYPE_INIT_S: u8 = 0x02; // первый пакет сервера (timestamp + echo_csid)
pub const TYPE_DATA: u8 = 0x03; // последующие пакеты
pub const TYPE_PAD: u8 = 0x04; // chaff/dummy (тайминг-шейпинг): приёмник отбрасывает до QUIC

pub const HDR_LEN: usize = 12 + 16; // nonce_pkt + enc_header
pub const TAG_LEN: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum ObfsError {
    TooShort,
    AuthFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub sid: [u8; 8],
    pub packet_id: u64,
    pub inner: Vec<u8>,
}

// ============================ KDF ============================
pub fn k_hdr(psk_obf: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(CTX_HDR, psk_obf)
}

pub fn k_sess(psk_obf: &[u8; 32], sid: &[u8; 8]) -> [u8; 32] {
    let mut km = [0u8; 40];
    km[..32].copy_from_slice(psk_obf);
    km[32..].copy_from_slice(sid);
    blake3::derive_key(CTX_SESSION, &km)
}

// 16-байтовый keystream ChaCha20 (counter=0) для шифрования заголовка
fn ks_hdr(k_hdr: &[u8; 32], nonce_pkt: &[u8]) -> [u8; 16] {
    let mut c = ChaCha20::new_from_slices(k_hdr, nonce_pkt).expect("len 32/12");
    let mut buf = [0u8; 16];
    c.apply_keystream(&mut buf);
    buf
}

fn body_nonce(packet_id: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&packet_id.to_be_bytes());
    n
}

// ============================ inner_plaintext ============================
pub fn build_inner(
    ptype: u8,
    timestamp: Option<u64>,
    echo_csid: Option<&[u8; 8]>,
    padding: &[u8],
    quic_payload: &[u8],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + 8 + 8 + 2 + padding.len() + quic_payload.len());
    v.push(ptype);
    if ptype == TYPE_INIT_C || ptype == TYPE_INIT_S {
        v.extend_from_slice(&timestamp.expect("INIT requires timestamp").to_be_bytes());
    }
    if ptype == TYPE_INIT_S {
        v.extend_from_slice(echo_csid.expect("INIT_S requires echo_csid"));
    }
    v.extend_from_slice(&(padding.len() as u16).to_be_bytes());
    v.extend_from_slice(padding);
    v.extend_from_slice(quic_payload);
    v
}

/// Chaff-пакет (`TYPE_PAD`) для тайминг-шейпинга: только padding, без полезной нагрузки.
/// На проводе неотличим от DATA (тот же фрейминг); приёмник распознаёт `TYPE_PAD`
/// по `parse_inner` и отбрасывает пакет до передачи в QUIC.
pub fn build_chaff(padding: &[u8]) -> Vec<u8> {
    build_inner(TYPE_PAD, None, None, padding, &[])
}

/// Полный фрейминг-оверхед DATA-пакета на проводе:
/// nonce_pkt(12) + enc_header(16) + type(1) + pad_len(2) + tag(16) = 47.
pub const FRAMING_OVERHEAD: usize = 12 + 16 + 1 + 2 + 16;

/// Бакеты размеров пакета НА ПРОВОДЕ по умолчанию (анти-fingerprint по длине, I5).
pub const DEFAULT_BUCKETS: &[usize] = &[256, 512, 1024, 1280];

#[derive(Clone, Copy, Debug)]
pub enum Padding {
    None,
    /// Добить итоговый размер на проводе до ближайшего бакета ≥ настоящего.
    Bucket(&'static [usize]),
}

/// Сколько байт padding добавить в DATA-пакет с `quic_len` полезной нагрузки,
/// чтобы итоговый размер на проводе попал на бакет.
pub fn pad_len_for(policy: Padding, quic_len: usize) -> usize {
    match policy {
        Padding::None => 0,
        Padding::Bucket(buckets) => {
            let wire = FRAMING_OVERHEAD + quic_len;
            for &b in buckets {
                if b >= wire {
                    return b - wire;
                }
            }
            0 // больше наибольшего бакета (в пределах MTU не случается) — не паддим
        }
    }
}

/// Обратный разбор inner_plaintext → (type, quic_payload), пропуская ts/echo/padding.
pub fn parse_inner(inner: &[u8]) -> Option<(u8, &[u8])> {
    let t = *inner.first()?;
    let mut pos = 1usize;
    if t == TYPE_INIT_C || t == TYPE_INIT_S {
        pos = pos.checked_add(8)?; // timestamp
    }
    if t == TYPE_INIT_S {
        pos = pos.checked_add(8)?; // echo_csid
    }
    let pad_len = u16::from_be_bytes([*inner.get(pos)?, *inner.get(pos + 1)?]) as usize;
    pos = pos.checked_add(2)?.checked_add(pad_len)?;
    if pos > inner.len() {
        return None;
    }
    Some((t, &inner[pos..]))
}

// ============================ seal / open ============================
/// Кешированный отправитель: `k_hdr` (от psk) + AEAD-cipher (от `k_sess(psk, sid)`) деривятся
/// ОДИН раз на сессию, а не на каждый пакет (см. docs/BENCHMARKS.md — экономит ~450 ns/пакет).
/// Один `sid` (наш). Hot-path в `ObfsUdpSocket`.
pub struct Sealer {
    k_hdr: [u8; 32],
    sid: [u8; 8],
    cipher: ChaCha20Poly1305,
}

impl Sealer {
    pub fn new(psk_obf: &[u8; 32], sid: &[u8; 8]) -> Self {
        let cipher = ChaCha20Poly1305::new_from_slice(&k_sess(psk_obf, sid)).expect("len 32");
        Self { k_hdr: k_hdr(psk_obf), sid: *sid, cipher }
    }

    pub fn seal(&self, packet_id: u64, nonce_pkt: &[u8; 12], inner: &[u8]) -> Vec<u8> {
        let ks = ks_hdr(&self.k_hdr, nonce_pkt);
        let mut hdr_pt = [0u8; 16];
        hdr_pt[..8].copy_from_slice(&self.sid);
        hdr_pt[8..].copy_from_slice(&packet_id.to_be_bytes());
        let mut enc_header = [0u8; 16];
        for i in 0..16 {
            enc_header[i] = hdr_pt[i] ^ ks[i];
        }
        let mut aad = [0u8; 28];
        aad[..12].copy_from_slice(nonce_pkt);
        aad[12..].copy_from_slice(&enc_header);
        let ct = self
            .cipher
            .encrypt(Nonce::from_slice(&body_nonce(packet_id)), Payload { msg: inner, aad: &aad })
            .expect("aead encrypt");
        let mut out = Vec::with_capacity(HDR_LEN + ct.len());
        out.extend_from_slice(nonce_pkt);
        out.extend_from_slice(&enc_header);
        out.extend_from_slice(&ct);
        out
    }
}

/// Кешированный приёмник: `k_hdr` (от psk) + cipher по последнему `sid` (per-connection обычно
/// один → попадание в кеш). Несовпадение sid → пере-derive `k_sess` и обновление кеша (корректно).
pub struct Opener {
    psk: [u8; 32],
    k_hdr: [u8; 32],
    cache: Option<([u8; 8], ChaCha20Poly1305)>,
}

impl Opener {
    pub fn new(psk_obf: &[u8; 32]) -> Self {
        Self { psk: *psk_obf, k_hdr: k_hdr(psk_obf), cache: None }
    }

    pub fn open(&mut self, packet: &[u8]) -> Result<Opened, ObfsError> {
        if packet.len() < HDR_LEN + TAG_LEN {
            return Err(ObfsError::TooShort);
        }
        let nonce_pkt = &packet[..12];
        let enc_header = &packet[12..28];
        let aead_body = &packet[28..];

        let ks = ks_hdr(&self.k_hdr, nonce_pkt);
        let mut hdr_pt = [0u8; 16];
        for i in 0..16 {
            hdr_pt[i] = enc_header[i] ^ ks[i];
        }
        let mut sid = [0u8; 8];
        sid.copy_from_slice(&hdr_pt[..8]);
        let packet_id = u64::from_be_bytes(hdr_pt[8..16].try_into().unwrap());

        // cipher по sid: переиспользуем кеш при совпадении; иначе derive k_sess и кешируем
        if !matches!(&self.cache, Some((csid, _)) if *csid == sid) {
            let cipher = ChaCha20Poly1305::new_from_slice(&k_sess(&self.psk, &sid)).expect("len 32");
            self.cache = Some((sid, cipher));
        }
        let cipher = &self.cache.as_ref().unwrap().1;

        let mut aad = [0u8; 28];
        aad[..12].copy_from_slice(nonce_pkt);
        aad[12..].copy_from_slice(enc_header);
        let inner = cipher
            .decrypt(Nonce::from_slice(&body_nonce(packet_id)), Payload { msg: aead_body, aad: &aad })
            .map_err(|_| ObfsError::AuthFailed)?;
        Ok(Opened { sid, packet_id, inner })
    }
}

/// Stateless `seal` (тест-векторы / разовый вызов) — делегирует [`Sealer`]. Hot-path: держать `Sealer`.
pub fn seal(
    psk_obf: &[u8; 32],
    sid: &[u8; 8],
    packet_id: u64,
    nonce_pkt: &[u8; 12],
    inner: &[u8],
) -> Vec<u8> {
    Sealer::new(psk_obf, sid).seal(packet_id, nonce_pkt, inner)
}

/// Stateless `open` (тест-векторы / разовый вызов) — делегирует [`Opener`]. Hot-path: держать `Opener`.
pub fn open(psk_obf: &[u8; 32], packet: &[u8]) -> Result<Opened, ObfsError> {
    Opener::new(psk_obf).open(packet)
}

// ============================ ТЕСТЫ ============================
#[cfg(test)]
mod tests {
    use super::*;

    // Те же входы, что в tools/obfs_ref.py
    fn psk() -> [u8; 32] {
        let mut p = [0u8; 32];
        for i in 0..32 {
            p[i] = i as u8;
        }
        p
    }
    const CSID: [u8; 8] = [0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8];
    const SSID: [u8; 8] = [0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8];

    fn arr12(h: &str) -> [u8; 12] {
        hex::decode(h).unwrap().try_into().unwrap()
    }

    #[test]
    fn kdf_matches_python_reference() {
        assert_eq!(
            hex::encode(k_hdr(&psk())),
            "9738885e419c4ffe00280490919669ca6a0e5b30341e9e624178143113e3b626"
        );
        assert_eq!(
            hex::encode(k_sess(&psk(), &CSID)),
            "8a34bf5432d8e103b92f63c0a44b2e6e9c3b15a119d58f33febd98e16a0e9e7e"
        );
        assert_eq!(
            hex::encode(k_sess(&psk(), &SSID)),
            "592daf07bb9bc25882c51b6860309e1137973a9e39a55ff5eaf1280753443a00"
        );
    }

    #[test]
    fn vector1_init_c() {
        let inner = build_inner(
            TYPE_INIT_C,
            Some(1_750_000_000),
            None,
            &hex::decode("f0f1f2f3").unwrap(),
            &hex::decode("c000000001").unwrap(),
        );
        assert_eq!(hex::encode(&inner), "0100000000684ee1800004f0f1f2f3c000000001");
        let pkt = seal(&psk(), &CSID, 0, &arr12("000102030405060708090a0b"), &inner);
        assert_eq!(
            hex::encode(&pkt),
            "000102030405060708090a0bace0fdb7fa9e87a1c38469396d1269d1\
             e3feb33fd51837d9a70d5269110e53e06a6602470e525cc2f74fb44eadcc8eae204e60a6"
                .replace(' ', "")
        );
        let o = open(&psk(), &pkt).unwrap();
        assert_eq!(o.sid, CSID);
        assert_eq!(o.packet_id, 0);
        assert_eq!(o.inner, inner);
    }

    #[test]
    fn vector2_init_s() {
        let inner = build_inner(
            TYPE_INIT_S,
            Some(1_750_000_001),
            Some(&CSID),
            &[],
            &hex::decode("c000000001").unwrap(),
        );
        assert_eq!(hex::encode(&inner), "0200000000684ee181a1a2a3a4a5a6a7a80000c000000001");
        let pkt = seal(&psk(), &SSID, 0, &arr12("101112131415161718191a1b"), &inner);
        assert_eq!(
            hex::encode(&pkt),
            "101112131415161718191a1b86669d5a598713d88a6270cbae9f60fe\
             d225c50c76c6691cb151c987c94ee9ad97bc31763830b1efaf1f9e71dbb30f1a8031c31cb73d3ace"
                .replace(' ', "")
        );
        let o = open(&psk(), &pkt).unwrap();
        assert_eq!(o.sid, SSID);
        assert_eq!(o.inner, inner);
    }

    #[test]
    fn vector3_data() {
        let inner = build_inner(TYPE_DATA, None, None, &[], &hex::decode("411234").unwrap());
        assert_eq!(hex::encode(&inner), "030000411234");
        let pkt = seal(&psk(), &CSID, 1, &arr12("202122232425262728292a2b"), &inner);
        assert_eq!(
            hex::encode(&pkt),
            "202122232425262728292a2b48b1192cd8a464221dc88806b9cbe084\
             0a2ca9318102feabdeb60a063d4f1e738aef2833953f"
                .replace(' ', "")
        );
        let o = open(&psk(), &pkt).unwrap();
        assert_eq!(o.sid, CSID);
        assert_eq!(o.packet_id, 1);
    }

    #[test]
    fn wrong_psk_fails_probe_resistance() {
        let inner = build_inner(TYPE_DATA, None, None, &[], b"hello");
        let pkt = seal(&psk(), &CSID, 7, &arr12("0102030405060708090a0b0c"), &inner);
        // верный PSK — открывается
        assert!(open(&psk(), &pkt).is_ok());
        // неверный PSK — AEAD verify обязан упасть (пробер ничего не получает)
        assert_eq!(open(&[0xFFu8; 32], &pkt), Err(ObfsError::AuthFailed));
    }

    #[test]
    fn tamper_header_breaks_auth() {
        let inner = build_inner(TYPE_DATA, None, None, &[], b"payload");
        let mut pkt = seal(&psk(), &CSID, 3, &arr12("0a0b0c0d0e0f101112131415"), &inner);
        pkt[20] ^= 0x01; // флип бита в enc_header (входит в AAD) → тег не сойдётся
        assert_eq!(open(&psk(), &pkt), Err(ObfsError::AuthFailed));
    }

    #[test]
    fn parse_inner_roundtrip() {
        let quic = [0xc0u8, 0, 0, 0, 1, 0x42];
        // DATA
        let i = build_inner(TYPE_DATA, None, None, &[0xaa, 0xbb], &quic);
        assert_eq!(parse_inner(&i), Some((TYPE_DATA, &quic[..])));
        // INIT_C (с timestamp)
        let i = build_inner(TYPE_INIT_C, Some(1_750_000_000), None, &[], &quic);
        assert_eq!(parse_inner(&i), Some((TYPE_INIT_C, &quic[..])));
        // INIT_S (timestamp + echo)
        let i = build_inner(TYPE_INIT_S, Some(1), Some(&[1, 2, 3, 4, 5, 6, 7, 8]), &[9], &quic);
        assert_eq!(parse_inner(&i), Some((TYPE_INIT_S, &quic[..])));
    }

    // ----------------------- политика паддинга (I5) -----------------------

    /// FRAMING_OVERHEAD обязан совпадать с реальным размером DATA-пакета на проводе
    /// при pad=0 и пустом quic_payload — иначе бакетирование промахнётся.
    #[test]
    fn framing_overhead_matches_real_seal() {
        let inner = build_inner(TYPE_DATA, None, None, &[], &[]);
        let pkt = seal(&psk(), &CSID, 0, &arr12("000102030405060708090a0b"), &inner);
        assert_eq!(pkt.len(), FRAMING_OVERHEAD);
    }

    #[test]
    fn pad_none_is_always_zero() {
        for q in [0usize, 1, 100, 1000, 5000] {
            assert_eq!(pad_len_for(Padding::None, q), 0);
        }
    }

    /// На границе бакета (quic_len = bucket − overhead) добавочный паддинг = 0.
    #[test]
    fn pad_bucket_exact_boundary_is_zero() {
        for &b in DEFAULT_BUCKETS {
            let q = b - FRAMING_OVERHEAD;
            assert_eq!(pad_len_for(Padding::Bucket(DEFAULT_BUCKETS), q), 0);
        }
    }

    /// Один байт сверх бакета перескакивает на следующий бакет.
    #[test]
    fn pad_bucket_rounds_up_to_next() {
        let p = Padding::Bucket(DEFAULT_BUCKETS);
        // quic_len=0 → wire=47 → ближайший бакет 256
        assert_eq!(pad_len_for(p, 0), 256 - FRAMING_OVERHEAD);
        // ровно бакет 256, плюс 1 байт → перескок на 512
        let q = (256 - FRAMING_OVERHEAD) + 1;
        assert_eq!(pad_len_for(p, q), 512 - (FRAMING_OVERHEAD + q));
    }

    /// Главный инвариант I5: ЛЮБАЯ длина полезной нагрузки (в пределах макс. бакета)
    /// схлопывается на проводе ровно в один из бакетов — распределение длин теряет сигнал.
    #[test]
    fn pad_bucket_collapses_every_length_onto_a_bucket() {
        let p = Padding::Bucket(DEFAULT_BUCKETS);
        let max_q = *DEFAULT_BUCKETS.last().unwrap() - FRAMING_OVERHEAD;
        for q in 0..=max_q {
            let wire = FRAMING_OVERHEAD + q + pad_len_for(p, q);
            assert!(DEFAULT_BUCKETS.contains(&wire), "quic_len={q}: wire={wire} не бакет");
        }
    }

    /// Свыше наибольшего бакета не паддим (вернём 0) — пакет уходит как есть, без раздувания за MTU.
    #[test]
    fn pad_bucket_over_max_no_padding() {
        let p = Padding::Bucket(DEFAULT_BUCKETS);
        let over = *DEFAULT_BUCKETS.last().unwrap() - FRAMING_OVERHEAD + 1;
        assert_eq!(pad_len_for(p, over), 0);
    }

    /// Сквозной тест: политика → build_inner → seal даёт длину ровно в бакет,
    /// а приёмная сторона (open → parse_inner) срезает padding и возвращает исходный quic.
    #[test]
    fn pad_then_seal_lands_on_bucket_and_strips_clean() {
        let p = Padding::Bucket(DEFAULT_BUCKETS);
        for q in [0usize, 3, 50, 209, 210, 600, 977, 1233] {
            let quic: Vec<u8> = (0..q).map(|i| i as u8).collect();
            let padding = vec![0u8; pad_len_for(p, q)];
            let inner = build_inner(TYPE_DATA, None, None, &padding, &quic);
            let pkt = seal(&psk(), &CSID, 5, &arr12("0102030405060708090a0b0c"), &inner);
            assert!(DEFAULT_BUCKETS.contains(&pkt.len()), "q={q}: len={}", pkt.len());
            let o = open(&psk(), &pkt).unwrap();
            assert_eq!(parse_inner(&o.inner), Some((TYPE_DATA, &quic[..])));
        }
    }

    // ----------------------- chaff / тайминг-шейпинг -----------------------

    /// Chaff: seal → open → parse_inner распознаёт TYPE_PAD, полезной нагрузки нет.
    #[test]
    fn chaff_roundtrip_typed_empty_payload() {
        let inner = build_chaff(&vec![0u8; 200]);
        let pkt = seal(&psk(), &CSID, 9, &arr12("0102030405060708090a0b0c"), &inner);
        let o = open(&psk(), &pkt).unwrap();
        assert_eq!(parse_inner(&o.inner), Some((TYPE_PAD, &[][..])));
    }

    /// Chaff паддится до бакета тем же фреймингом, что DATA → неотличим по длине на проводе.
    #[test]
    fn chaff_lands_on_buckets() {
        for &b in DEFAULT_BUCKETS {
            let inner = build_chaff(&vec![0u8; b - FRAMING_OVERHEAD]);
            let pkt = seal(&psk(), &CSID, 0, &arr12("000102030405060708090a0b"), &inner);
            assert_eq!(pkt.len(), b, "chaff на бакет {b}");
        }
    }

    /// Кеш-оптимизация (M6): Sealer/Opener дают тот же результат, что stateless seal/open,
    /// и кеш cipher корректен при чередующихся sid (как на сервере с несколькими клиентами).
    #[test]
    fn sealer_opener_equiv_and_cache_multi_sid() {
        let psk = psk();
        let inner = build_inner(TYPE_DATA, None, None, &[1, 2], b"hot-path");
        let nonce = arr12("0102030405060708090a0b0c");
        // Sealer == free seal (байт-идентично)
        assert_eq!(Sealer::new(&psk, &CSID).seal(5, &nonce, &inner), seal(&psk, &CSID, 5, &nonce, &inner));
        // Opener корректен на чередующихся sid (кеш пере-derive при смене)
        let p1 = seal(&psk, &CSID, 0, &nonce, &inner);
        let p2 = seal(&psk, &SSID, 1, &nonce, &inner);
        let mut opener = Opener::new(&psk);
        for (pkt, sid, pid) in [(&p1, CSID, 0u64), (&p2, SSID, 1), (&p1, CSID, 0), (&p2, SSID, 1)] {
            let o = opener.open(pkt).unwrap();
            assert_eq!((o.sid, o.packet_id, &o.inner), (sid, pid, &inner));
        }
        // probe-resistance сохранена: неверный PSK → AuthFailed
        assert_eq!(Opener::new(&[0xFFu8; 32]).open(&p1), Err(ObfsError::AuthFailed));
    }

    // ----------------------- robustness / fuzz (no-panic на недоверенном вводе, M6) -----------------------
    // cargo-fuzz/libFuzzer недоступен (нет nightly/rustup) → детерминированные robustness-тесты на
    // stable: парсеры из сети (`open`, `parse_inner`) НЕ должны паниковать/крашиться ни на каком
    // вводе (анти-DoS на malformed input). PRNG — inline xorshift (воспроизводимо, без зависимостей).

    fn xs(seed: &mut u64) -> u64 {
        let mut x = *seed;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *seed = x;
        x
    }
    fn fuzz_bytes(seed: &mut u64, len: usize) -> Vec<u8> {
        (0..len).map(|_| (xs(seed) >> 33) as u8).collect()
    }

    #[test]
    fn fuzz_open_no_panic() {
        let psk = psk();
        let mut s = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..30_000 {
            let len = (xs(&mut s) % 2049) as usize; // вкл. короче заголовка
            let buf = fuzz_bytes(&mut s, len);
            let _ = open(&psk, &buf); // ожидаем Err, не панику
        }
        // mutated valid: реальный пакет с флипами байт и случайной обрезкой
        let inner = build_inner(TYPE_DATA, None, None, &[0xaa, 0xbb, 0xcc], b"payload");
        let pkt = seal(&psk, &CSID, 1, &arr12("000102030405060708090a0b"), &inner);
        for _ in 0..30_000 {
            let mut m = pkt.clone();
            for _ in 0..(xs(&mut s) % 6) {
                let i = (xs(&mut s) as usize) % m.len();
                m[i] ^= (xs(&mut s) as u8) | 1;
            }
            let cut = (xs(&mut s) as usize) % (m.len() + 1);
            let _ = open(&psk, &m[..cut]);
        }
    }

    #[test]
    fn fuzz_parse_inner_no_panic() {
        let mut s = 0xdead_beef_cafe_babeu64;
        for _ in 0..50_000 {
            let len = (xs(&mut s) % 600) as usize;
            let buf = fuzz_bytes(&mut s, len);
            let _ = parse_inner(&buf); // Some/None, без паники
        }
        // mutated valid inner-структуры всех типов
        let valids = [
            build_inner(TYPE_DATA, None, None, &[1, 2], b"x"),
            build_inner(TYPE_INIT_C, Some(1_700_000_000), None, &[3], b"yz"),
            build_inner(TYPE_INIT_S, Some(1), Some(&[1, 2, 3, 4, 5, 6, 7, 8]), &[], b"q"),
            build_chaff(&[9, 9, 9]),
        ];
        for _ in 0..30_000 {
            let mut m = valids[(xs(&mut s) as usize) % valids.len()].clone();
            let i = (xs(&mut s) as usize) % m.len();
            m[i] ^= xs(&mut s) as u8;
            let cut = (xs(&mut s) as usize) % (m.len() + 1);
            let _ = parse_inner(&m[..cut]);
        }
    }
}
