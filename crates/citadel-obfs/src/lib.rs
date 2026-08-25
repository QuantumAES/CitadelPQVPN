//! CitadelPQVPN — obfs L1 (Фаза 0), протокол **v2**.
//!
//! Симметричная, на pre-shared key, обёртка датаграмм QUIC в стиле Shadowsocks-2022.
//! Нормативный формат, KDF и тест-векторы — в `docs/PHASE0-OBFS.md`.
//!
//! Это L1: обфускация + probe-resistance, НЕ замена реальной конфиденциальности L2.
//!
//! **v2 (M2-full, слом wire относительно v1):** `sid` расширен 8→16 байт и служит
//! 128-битной **per-session солью** в `k_sess`. Это закрывает nonce-reuse тела AEAD
//! под общим PSK: раньше при коллизии 64-битного `sid` (birthday ~2³²) два сеанса
//! делили один `k_sess` → пересечение `packet_id` = повтор (ключ, nonce) ChaCha20Poly1305.
//! 16-байтный случайный `sid` даёт коллизию 2⁻¹²⁸ → per-session ключ уникален.
//! KDF-контексты подняты `v1`→`v2` (старое/новое взаимно нерасшифровываемы).
//!
//! Формат пакета:
//! ```text
//! nonce_pkt(12) ‖ enc_header(24) ‖ aead_body(var)
//!   enc_header = (sid(16) ‖ packet_id(8 BE)) XOR ChaCha20(K_hdr, nonce_pkt)[0:24]
//!   aead_body  = ChaCha20Poly1305(K_sess(sid), body_nonce, AAD=nonce_pkt‖enc_header)(inner)
//! ```
#![forbid(unsafe_code)]

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};

// --- доменно-разделённые контексты KDF (фиксированы протоколом, v2) ---
pub const CTX_HDR: &str = "CitadelPQVPN/obfs/v2/header";
pub const CTX_SESSION: &str = "CitadelPQVPN/obfs/v2/session";
/// H-3: контекст вывода PSK эпохи из мастер-секрета сервера.
pub const CTX_EPOCH_PSK: &str = "CitadelPQVPN/obfs/v2/epoch-psk";

/// Длина session_id (v2): 128-битная per-session соль для `k_sess`. Был 8 (v1).
pub const SID_LEN: usize = 16;

// --- типы пакетов ---
pub const TYPE_INIT_C: u8 = 0x01; // первый пакет клиента (несёт timestamp)
pub const TYPE_INIT_S: u8 = 0x02; // первый пакет сервера (timestamp + echo_csid)
pub const TYPE_DATA: u8 = 0x03; // последующие пакеты
pub const TYPE_PAD: u8 = 0x04; // chaff/dummy (тайминг-шейпинг): приёмник отбрасывает до QUIC

pub const HDR_LEN: usize = 12 + SID_LEN + 8; // nonce_pkt(12) + enc_header(sid16 ‖ pid8 = 24) = 36
pub const TAG_LEN: usize = 16;

// Длина открытого текста заголовка (sid ‖ packet_id) = длина enc_header и keystream.
const HDR_PT_LEN: usize = SID_LEN + 8; // 24

#[derive(Debug, PartialEq, Eq)]
pub enum ObfsError {
    TooShort,
    AuthFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub sid: [u8; SID_LEN],
    pub packet_id: u64,
    pub inner: Vec<u8>,
}

// ============================ KDF ============================
pub fn k_hdr(psk_obf: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(CTX_HDR, psk_obf)
}

pub fn k_sess(psk_obf: &[u8; 32], sid: &[u8; SID_LEN]) -> [u8; 32] {
    let mut km = [0u8; 32 + SID_LEN];
    km[..32].copy_from_slice(psk_obf);
    km[32..].copy_from_slice(sid);
    blake3::derive_key(CTX_SESSION, &km)
}

/// **H-3/аудит-4: PSK эпохи.** Ключ L1 для канала данных выводится сервером из мастер-секрета,
/// который НЕ покидает сервер, и меняется каждую эпоху (ту же, что скоупит токены Layer-2).
///
/// Зачем: до этого весь деплой жил на ОДНОМ симметричном секрете, который лежал в открытом виде в
/// каждой `citadel://`. Одна утёкшая ссылка давала бессрочный детерминированный классификатор
/// трафика (trial-decrypt заголовка), а отзыв абонента его не отменял — отозванный абонент
/// навсегда сохранял и способность классифицировать, и проход L1-гейта. Теперь ключ живёт эпоху и
/// выдаётся только тому, кто прошёл Layer-1 у издателя ⇒ отзыв начинает работать и на L1, а утечка
/// ссылки перестаёт быть бессрочной.
///
/// **Чего это НЕ даёт (и не должно казаться, что даёт):** адреса exit'а и издателя лежат в той же
/// ссылке, поэтому «кто ходит на этот узел» видно и без всякой криптографии. Ротация закрывает
/// обнаружение ДРУГИХ узлов деплоя и бессрочность доступа отозванного, а не факт пользования.
///
/// **Почему не «PSK на абонента»** (вариант из отчёта): exit, подбирающий ключ L1 по абоненту, тем
/// самым узнаёт абонента на L1 — и вся неразличимость Layer-2 (VOPRF) обесценивается: анонимный
/// токен предъявлялся бы в сессии, уже подписанной именем.
pub fn psk_epoch(master: &[u8; 32], epoch: u64) -> [u8; 32] {
    let mut km = [0u8; 32 + 8];
    km[..32].copy_from_slice(master);
    km[32..].copy_from_slice(&epoch.to_be_bytes());
    blake3::derive_key(CTX_EPOCH_PSK, &km)
}

// keystream ChaCha20 (counter=0) для шифрования заголовка (HDR_PT_LEN=24 байта)
fn ks_hdr(k_hdr: &[u8; 32], nonce_pkt: &[u8]) -> [u8; HDR_PT_LEN] {
    let mut c = ChaCha20::new_from_slices(k_hdr, nonce_pkt).expect("len 32/12");
    let mut buf = [0u8; HDR_PT_LEN];
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
    echo_csid: Option<&[u8; SID_LEN]>,
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
/// nonce_pkt(12) + enc_header(24) + type(1) + pad_len(2) + tag(16) = 55 (v2; было 47 в v1).
pub const FRAMING_OVERHEAD: usize = 12 + HDR_PT_LEN + 1 + 2 + 16;

/// Максимальный QUIC-пакет, который может прийти на упаковку: `initial_mtu` транспорта в
/// `citadel_quic::transport()` (MTU-discovery выключен ⇒ размер фиксирован). Держится в синхроне
/// тестом `obfs_wire_cap_matches_quic_mtu` в citadel-quic.
pub const MAX_QUIC_PACKET: usize = 1200;

/// **Потолок размера пакета НА ПРОВОДЕ.** Ключевой MTU-инвариант L1: obfs добавляет к QUIC-пакету
/// `FRAMING_OVERHEAD` + паддинг, но QUIC об этом не знает — он считает, что укладывается в свой
/// `initial_mtu`. Если паддинг раздувает провод выше `MAX_QUIC_PACKET + FRAMING_OVERHEAD`, то
/// полноразмерные пакеты (и только они!) начинают не влезать в путь, где MTU впритык — мобильные
/// сети/NAT64/CLAT/GTP. Диагноз при этом коварный: хендшейк и мелкие пакеты идут, а данные —
/// чёрная дыра. Поэтому потолок = ровно то, что мог бы отправить сам QUIC: паддинг добивает
/// МЕЛКИЕ пакеты и никогда не увеличивает крупные (для них он и так бесполезен — они у потолка).
/// На проводе это 1255 б UDP-payload ⇒ ≤1283 б IPv4-пакет.
pub const WIRE_CAP: usize = FRAMING_OVERHEAD + MAX_QUIC_PACKET;

/// Бакеты размеров пакета НА ПРОВОДЕ по умолчанию (анти-fingerprint по длине, I5).
/// Верхний бакет = [`WIRE_CAP`] (см. MTU-инвариант выше), а не «круглые» 1280.
pub const DEFAULT_BUCKETS: &[usize] = &[256, 512, 1024, WIRE_CAP];

#[derive(Clone, Copy, Debug)]
pub enum Padding {
    None,
    /// Добить итоговый размер на проводе до ближайшего бакета ≥ настоящего.
    Bucket(&'static [usize]),
    /// C2/аудит-3: СЛУЧАЙНЫЙ добор до размера в `[max(wire,floor), cap]` — непрерывное распределение
    /// длин на проводе (нет дискретной сигнатуры «ровно 256/512/1024/1280», по которой цензор
    /// фингерпринтил протокол), при этом мелкие пакеты скрыты полом `floor`, а `cap` держит MTU.
    /// Требует RNG у вызывающего → длина считается [`pad_len_random`] (pad_len_for(Random)=0).
    Random { floor: usize, jitter: usize, cap: usize },
}

/// C2: дефолтная политика случайного паддинга (анти-fingerprint по длине). Параметры — компромисс
/// анти-DPI vs overhead; tunable. floor 256 (скрыть мелкие), jitter 512 (спред), cap — [`WIRE_CAP`]
/// (MTU-инвариант: паддинг не делает пакет больше, чем мог бы отправить сам QUIC).
pub const DEFAULT_RANDOM_PAD: Padding = Padding::Random { floor: 256, jitter: 512, cap: WIRE_CAP };

/// Сколько байт padding добавить в DATA-пакет с `quic_len` полезной нагрузки,
/// чтобы итоговый размер на проводе попал на бакет. `Random` считается [`pad_len_random`] (нужен RNG).
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
        Padding::Random { .. } => 0, // считается через pad_len_random (RNG у вызывающего)
    }
}

/// C2: длина случайного паддинга. `rand_val` — случайное число от вызывающего (RNG в obfs-сокете) →
/// функция pure/тестируема. Провод = `max(wire, floor) + rand_val % (jitter+1)`, капнут `cap`.
pub fn pad_len_random(floor: usize, jitter: usize, cap: usize, quic_len: usize, rand_val: usize) -> usize {
    let wire = FRAMING_OVERHEAD + quic_len;
    if wire >= cap {
        return 0; // уже у cap (MTU) — паддить некуда
    }
    let base = wire.max(floor);
    let target = (base + rand_val % (jitter + 1)).min(cap);
    target.saturating_sub(wire)
}

/// Обратный разбор inner_plaintext → (type, quic_payload), пропуская ts/echo/padding.
pub fn parse_inner(inner: &[u8]) -> Option<(u8, &[u8])> {
    let t = *inner.first()?;
    let mut pos = 1usize;
    if t == TYPE_INIT_C || t == TYPE_INIT_S {
        pos = pos.checked_add(8)?; // timestamp
    }
    if t == TYPE_INIT_S {
        pos = pos.checked_add(SID_LEN)?; // echo_csid (16 в v2)
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
    sid: [u8; SID_LEN],
    cipher: ChaCha20Poly1305,
}

impl Sealer {
    pub fn new(psk_obf: &[u8; 32], sid: &[u8; SID_LEN]) -> Self {
        let cipher = ChaCha20Poly1305::new_from_slice(&k_sess(psk_obf, sid)).expect("len 32");
        Self { k_hdr: k_hdr(psk_obf), sid: *sid, cipher }
    }

    pub fn seal(&self, packet_id: u64, nonce_pkt: &[u8; 12], inner: &[u8]) -> Vec<u8> {
        let ks = ks_hdr(&self.k_hdr, nonce_pkt);
        let mut hdr_pt = [0u8; HDR_PT_LEN];
        hdr_pt[..SID_LEN].copy_from_slice(&self.sid);
        hdr_pt[SID_LEN..].copy_from_slice(&packet_id.to_be_bytes());
        let mut enc_header = [0u8; HDR_PT_LEN];
        for i in 0..HDR_PT_LEN {
            enc_header[i] = hdr_pt[i] ^ ks[i];
        }
        let mut aad = [0u8; 12 + HDR_PT_LEN];
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

/// Ёмкость кеша сессионных шифров приёмника (L-11). 64 — это про exit с несколькими десятками
/// одновременных клиентов; память на запись — ключ ChaCha20Poly1305, десятки байт.
const OPENER_CACHE_CAP: usize = 64;

/// Кешированный приёмник: `k_hdr` (от psk) + шифры по `sid` (MRU-кеш).
///
/// **L-11/аудит-4: кеш был на ОДИН sid.** На exit'е один сокет принимает пакеты всех клиентов
/// вперемежку, поэтому кеш промахивался почти на каждом пакете, и каждый пакет стоил `BLAKE3-derive`
/// плюс разворачивание ключа ChaCha20Poly1305 заново. Под флудом это множитель стоимости обработки,
/// то есть усиление того самого DoS, от которого стоят гейты pre-auth.
///
/// **Важно, что в кеш попадает только ПРОВЕРЕННЫЙ sid.** Раньше запись делалась до расшифровки,
/// поэтому пакет с произвольным (мусорным) sid вытеснял из кеша живую сессию: атакующий без
/// всякого PSK мог гарантированно держать кеш холодным. Теперь запись — после успешного AEAD, а
/// мусор не оставляет следа вообще.
pub struct Opener {
    psk: [u8; 32],
    k_hdr: [u8; 32],
    /// MRU в начале: попаданий на длинных сессиях подавляющее большинство, поиск — memcmp по 16 Б.
    cache: Vec<([u8; SID_LEN], ChaCha20Poly1305)>,
}

impl Opener {
    pub fn new(psk_obf: &[u8; 32]) -> Self {
        Self { psk: *psk_obf, k_hdr: k_hdr(psk_obf), cache: Vec::new() }
    }

    pub fn open(&mut self, packet: &[u8]) -> Result<Opened, ObfsError> {
        if packet.len() < HDR_LEN + TAG_LEN {
            return Err(ObfsError::TooShort);
        }
        let nonce_pkt = &packet[..12];
        let enc_header = &packet[12..HDR_LEN];
        let aead_body = &packet[HDR_LEN..];

        let ks = ks_hdr(&self.k_hdr, nonce_pkt);
        let mut hdr_pt = [0u8; HDR_PT_LEN];
        for i in 0..HDR_PT_LEN {
            hdr_pt[i] = enc_header[i] ^ ks[i];
        }
        let mut sid = [0u8; SID_LEN];
        sid.copy_from_slice(&hdr_pt[..SID_LEN]);
        let packet_id = u64::from_be_bytes(hdr_pt[SID_LEN..HDR_PT_LEN].try_into().unwrap());

        let mut aad = [0u8; 12 + HDR_PT_LEN];
        aad[..12].copy_from_slice(nonce_pkt);
        aad[12..].copy_from_slice(enc_header);
        let bn = body_nonce(packet_id);
        let nonce = Nonce::from_slice(&bn);
        let payload = Payload { msg: aead_body, aad: &aad };

        // cipher по sid: попадание в кеш → используем и поднимаем в MRU; промах → derive k_sess,
        // и в кеш он попадает ТОЛЬКО если пакет оказался подлинным (иначе кеш вытесняется мусором).
        let inner = match self.cache.iter().position(|(s, _)| *s == sid) {
            Some(i) => {
                let inner = self.cache[i].1.decrypt(nonce, payload).map_err(|_| ObfsError::AuthFailed)?;
                if i > 0 {
                    self.cache.swap(0, i);
                }
                inner
            }
            None => {
                let cipher =
                    ChaCha20Poly1305::new_from_slice(&k_sess(&self.psk, &sid)).expect("len 32");
                let inner = cipher.decrypt(nonce, payload).map_err(|_| ObfsError::AuthFailed)?;
                self.cache.insert(0, (sid, cipher));
                self.cache.truncate(OPENER_CACHE_CAP);
                inner
            }
        };
        Ok(Opened { sid, packet_id, inner })
    }
}

/// Stateless `seal` (тест-векторы / разовый вызов) — делегирует [`Sealer`]. Hot-path: держать `Sealer`.
pub fn seal(
    psk_obf: &[u8; 32],
    sid: &[u8; SID_LEN],
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
        for (i, slot) in p.iter_mut().enumerate() {
            *slot = i as u8;
        }
        p
    }
    // session_id v2 — 16 байт (см. tools/obfs_ref.py)
    const CSID: [u8; SID_LEN] = [
        0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
    ];
    const SSID: [u8; SID_LEN] = [
        0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0,
    ];

    fn arr12(h: &str) -> [u8; 12] {
        hex::decode(h).unwrap().try_into().unwrap()
    }

    #[test]
    fn kdf_matches_python_reference() {
        assert_eq!(
            hex::encode(k_hdr(&psk())),
            "7c18a6102af38008d307e13c375d87bc523536982b26b95405c3c13788997885"
        );
        assert_eq!(
            hex::encode(k_sess(&psk(), &CSID)),
            "08d562d215bf14dc6296ebdc5f56a7e95c7f10fb12ba605e12635b1122efd129"
        );
        assert_eq!(
            hex::encode(k_sess(&psk(), &SSID)),
            "bb80f8542266f71b52a24b31813e16f71cb37512396f63f701dbd2a59db4a87b"
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
            "000102030405060708090a0b095fde1f42d8c31ebb03bd82332b5d0a7d37c49224c62dfc\
             237fc535a9603560f4ee23d27c67859a0e2844a7fd22d25cc5c47d9b18fb2591072beabf"
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
        assert_eq!(
            hex::encode(&inner),
            "0200000000684ee181a1a2a3a4a5a6a7a8a9aaabacadaeafb00000c000000001"
        );
        let pkt = seal(&psk(), &SSID, 0, &arr12("101112131415161718191a1b"), &inner);
        assert_eq!(
            hex::encode(&pkt),
            "101112131415161718191a1b2a28e1349daf788167ba1f313ee8c6849edf68bbab5a56e6\
             0b1a44bc18851e9fda38c8a152ccbbe95b3766fff0bda94739a6574d2d54f184e514b9d8f54cc370103b9f94a80a2ff0"
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
            "202122232425262728292a2bee3be35a8b422a5ee78fad3493fb174e1d60d7939039b304\
             4cd451497a8ca41ed0db72ab7fc0cceafb96b2051118"
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
        let i = build_inner(TYPE_INIT_S, Some(1), Some(&[1u8; SID_LEN]), &[9], &quic);
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

    /// C2: случайный паддинг — провод в `[max(wire,floor), cap]`, НЕПРЕРЫВНЫЙ (а не 4 дискретных
    /// бакета-сигнатуры); мелкие скрыты полом; крупные у cap не паддятся (MTU).
    #[test]
    fn pad_random_bounds_cap_and_continuity() {
        let (floor, jitter, cap) = (256, 512, WIRE_CAP);
        // мелкий пакет (q=5, wire=60): провод всегда в [floor, cap]
        for r in [0usize, 1, 100, 511, 512, 513, 99_999] {
            let wire = FRAMING_OVERHEAD + 5 + pad_len_random(floor, jitter, cap, 5, r);
            assert!((floor..=cap).contains(&wire), "r={r}: wire={wire} вне [{floor},{cap}]");
        }
        // rand=0 → ровно floor (нижняя граница)
        assert_eq!(FRAMING_OVERHEAD + 5 + pad_len_random(floor, jitter, cap, 5, 0), floor);
        // крупный пакет (wire >= cap) → паддинга нет
        assert_eq!(pad_len_random(floor, jitter, cap, cap, 999), 0);
        // непрерывность: разные rand → много разных размеров (не дискретные бакеты)
        let sizes: std::collections::HashSet<usize> = (0..300)
            .map(|r| FRAMING_OVERHEAD + 5 + pad_len_random(floor, jitter, cap, 5, r))
            .collect();
        assert!(sizes.len() > 50, "распределение непрерывно, не дискретно ({} значений)", sizes.len());
    }

    /// MTU-инвариант: при дефолтной политике паддинг НИКОГДА не делает провод больше, чем
    /// `MAX_QUIC_PACKET + FRAMING_OVERHEAD`. Это и есть баг «на мобильной сети хендшейк проходит,
    /// а данные не идут»: раздутый паддингом полноразмерный пакет не влезал в узкий путь.
    #[test]
    fn default_padding_never_exceeds_quic_mtu_on_wire() {
        let Padding::Random { floor, jitter, cap } = DEFAULT_RANDOM_PAD else {
            panic!("дефолт — Random");
        };
        for q in [0usize, 40, 500, 1100, MAX_QUIC_PACKET - 1, MAX_QUIC_PACKET] {
            for r in [0usize, 7, 511, 512, 4096, 65_535] {
                let wire = FRAMING_OVERHEAD + q + pad_len_random(floor, jitter, cap, q, r);
                assert!(wire <= WIRE_CAP, "q={q}, r={r}: провод {wire} > потолка {WIRE_CAP}");
            }
        }
        // полноразмерный QUIC-пакет паддингом не раздувается вовсе
        assert_eq!(pad_len_random(floor, jitter, cap, MAX_QUIC_PACKET, 12_345), 0);
    }

    /// Сквозной тест: политика → build_inner → seal даёт длину ровно в бакет,
    /// а приёмная сторона (open → parse_inner) срезает padding и возвращает исходный quic.
    #[test]
    fn pad_then_seal_lands_on_bucket_and_strips_clean() {
        let p = Padding::Bucket(DEFAULT_BUCKETS);
        // верхняя граница = максимальный бакет (WIRE_CAP) − FRAMING_OVERHEAD = MAX_QUIC_PACKET
        for q in [0usize, 3, 50, 209, 210, 600, 977, MAX_QUIC_PACKET] {
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
        let inner = build_chaff(&[0u8; 200]);
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

    /// H-3: PSK эпохи детерминирован (обе стороны считают одинаково), различается на КАЖДОЙ эпохе
    /// и на каждом мастере, и по нему не восстанавливается мастер (иначе утечка одного ключа
    /// эпохи компрометировала бы все остальные — и прошлые, и будущие).
    #[test]
    fn epoch_psk_is_deterministic_and_separated() {
        let m = psk();
        let a = psk_epoch(&m, 100);
        assert_eq!(a, psk_epoch(&m, 100), "детерминирован");
        assert_ne!(a, psk_epoch(&m, 101), "соседняя эпоха — другой ключ");
        assert_ne!(a, psk_epoch(&[0xAAu8; 32], 100), "другой мастер — другой ключ");
        assert_ne!(a, m, "ключ эпохи ≠ мастер");
        // домен отделён от прочих выводов на том же секрете
        assert_ne!(a, k_hdr(&m));
        assert_ne!(a, k_sess(&m, &CSID));
    }

    /// L-11: кеш держит МНОГО сессий (exit обслуживает клиентов одним сокетом), а мусорный пакет
    /// в него не попадает — иначе поток случайных sid'ов гарантированно вымывал бы живые сессии.
    #[test]
    fn opener_cache_holds_many_sessions_and_ignores_garbage() {
        let psk = psk();
        let inner = build_inner(TYPE_DATA, None, None, &[], b"multi-client");
        let nonce = arr12("0102030405060708090a0b0c");
        // 16 «клиентов» со своими sid
        let sids: Vec<[u8; SID_LEN]> = (0u8..16).map(|i| [i.wrapping_add(1); SID_LEN]).collect();
        let pkts: Vec<Vec<u8>> = sids.iter().map(|s| seal(&psk, s, 7, &nonce, &inner)).collect();

        let mut op = Opener::new(&psk);
        for p in &pkts {
            op.open(p).unwrap();
        }
        assert_eq!(op.cache.len(), sids.len(), "все сессии обязаны осесть в кеше");

        // мусор с чужим PSK (валидная длина, но AEAD не сойдётся) кеш не трогает
        let junk = seal(&[0xFFu8; 32], &[0xEE; SID_LEN], 1, &nonce, &inner);
        assert_eq!(op.open(&junk), Err(ObfsError::AuthFailed));
        assert_eq!(op.cache.len(), sids.len(), "мусорный sid не должен вытеснять живые сессии");

        // перемежающийся приём остаётся корректным (тот же результат, что stateless open)
        for (s, p) in sids.iter().zip(&pkts) {
            let o = op.open(p).unwrap();
            assert_eq!((o.sid, &o.inner), (*s, &inner));
        }
        // потолок кеша соблюдается
        for i in 0..(OPENER_CACHE_CAP + 8) {
            let sid = [(i % 251) as u8 + 3; SID_LEN];
            op.open(&seal(&psk, &sid, 1, &nonce, &inner)).unwrap();
        }
        assert!(op.cache.len() <= OPENER_CACHE_CAP, "кеш не должен расти без предела");
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
            build_inner(TYPE_INIT_S, Some(1), Some(&[1u8; SID_LEN]), &[], b"q"),
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
