//! F7 — кадр гейта эпохи (`citadel_token::parse_gate_frame`).
//!
//! **Кто подаёт:** клиент (в т.ч. скомпрометированный) — это первый кадр, который издатель читает
//! от него на пути выдачи.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = citadel_token::parse_gate_frame(data);
});
