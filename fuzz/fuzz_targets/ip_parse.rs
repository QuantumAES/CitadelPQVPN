//! F4 — разбор IPv4-заголовка внутреннего пакета (`ip::parse_ipv4`, `ip::tcp_dport`).
//!
//! **Кто подаёт:** и абонент (его собственный стек), и **скомпрометированный exit** — inner-пакеты
//! идут в обе стороны. На exit'е этот же разбор стоит на пути анти-спуфинга (H3), то есть паника
//! здесь = отказ узла от одного кривого пакета любого абонента.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(v) = citadel_masque::ip::parse_ipv4(data) {
        let _ = citadel_masque::ip::tcp_dport(&v);
    }
});
