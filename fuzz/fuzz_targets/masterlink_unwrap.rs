//! B-2 — парольный конверт мастер-ссылки, разбор ДО KDF (`masterlink::probe_block`).
//!
//! **Кто подаёт:** канал доставки мастер-ссылки. Argon2id (256 МиБ) за этой границей намеренно
//! не трогаем: на случайных байтах он не проверяет ничего, кроме тега AEAD, и съедает весь бюджет
//! фаззинга. Проверяется рамка, base64, длина и магия — всё, что исполняется до единого байта
//! криптографии.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let _ = citadel_client::masterlink::probe_block(text);
    let _ = citadel_client::masterlink::looks_wrapped(text);
});
