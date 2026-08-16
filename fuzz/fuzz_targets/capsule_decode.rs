//! F2 — капсулы MASQUE (`citadel_masque::capsule::decode`).
//!
//! **Кто подаёт:** пир туннеля, то есть в первую очередь **скомпрометированный exit** — он
//! аутентифицирован, его капсулы доходят до клиента без фильтра. Это самая недооценённая
//! поверхность: сеть на этом уровне видит только шифртекст, а exit — нет.
//!
//! **Инвариант:** `Option`, без паник и переполнений; `decode` не обязан доверять полю длины.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some((ty, value, used)) = citadel_masque::capsule::decode(data) {
        // Длина «съеденного» обязана быть в пределах входа — иначе вызывающий уедет за буфер.
        assert!(used <= data.len(), "capsule::decode: used={used} > len={}", data.len());
        assert!(value.len() <= data.len());
        let _ = ty;
    }
    let _ = citadel_masque::datagram::decode(data);
});
