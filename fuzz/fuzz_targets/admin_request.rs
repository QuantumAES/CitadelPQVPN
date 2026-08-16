//! S5 — admin-команды (CBOR `AdminRequest`) на стороне издателя.
//!
//! **Кто подаёт:** абонент из туннеля — до проверки admin-подписи кадр уже разобран. То есть
//! разбор стоит ПЕРЕД авторизацией, и это ровно тот порядок, при котором «скомпрометированный
//! клиент» превращается в «ввод в парсер издателя».
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _: Result<citadel_token::admin::AdminRequest, _> = ciborium::from_reader(data);
    let _: Result<citadel_token::admin::AdminResponse, _> = ciborium::from_reader(data);
});
