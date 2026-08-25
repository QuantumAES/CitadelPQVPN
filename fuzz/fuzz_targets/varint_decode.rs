//! F5 — QUIC-varint (`citadel_masque::varint::decode`).
//!
//! Примитив под всеми кадрами и капсулами: ошибка здесь протекает во все разборщики сразу.
//! **Инвариант:** нет переполнения, нет чтения за границей, `used` не больше входа.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some((v, used)) = citadel_masque::varint::decode(data) {
        assert!(used <= data.len(), "varint::decode: used={used} > len={}", data.len());
        assert!(used > 0, "varint::decode: нулевой сдвиг зациклит вызывающего");
        let _ = v;
    }
});
