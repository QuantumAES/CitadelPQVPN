//! F9 — разбор ссылки `citadel://` (`CredentialLink::from_uri`).
//!
//! **Кто подаёт:** тот, кто дал человеку ссылку. В модели компрометации это либо
//! скомпрометированный издатель/админ (ссылки выдаёт он), либо кто угодно — QR со стены, письмо,
//! буфер обмена. Ссылка задаёт адрес exit'а, pin и PSK, то есть ошибка разбора здесь — это ошибка
//! в самом корне доверия клиента.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let _ = citadel_client::CredentialLink::from_uri(text);
});
