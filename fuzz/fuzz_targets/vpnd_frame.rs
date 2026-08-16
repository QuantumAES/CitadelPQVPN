//! F11 — граница привилегий Linux (`citadel_vpnd`): кадры от НЕпривилегированного приложения к
//! демону и валидация того, что из них вышло.
//!
//! **Кто подаёт:** локальный пользователь. Ему не нужно ничего компрометировать — сокет демона
//! доступен ему по построению; а если скомпрометирован сам клиент, то это ровно тот же ввод, но
//! уже под управлением противника. За этой границей стоят argv `ip`/`iptables` от root, поэтому
//! приоритет цели высший.
//!
//! **Инвариант:** ни одна строка не проходит в argv неразобранной; любой мусор → `Err`, не паника.
#![no_main]

use libfuzzer_sys::fuzz_target;

use citadel_vpnd::proto::{CtlRequest, EngineMsg};

fuzz_target!(|data: &[u8]| {
    // Управляющий сокет (CLI/GUI → демон).
    let mut cur = std::io::Cursor::new(data);
    let _: Result<Option<CtlRequest>, _> = citadel_vpnd::proto::read_frame(&mut cur);

    // Канал движка (движок → демон): здесь приходит TunSetup, из которого рождаются сетевые
    // команды. Разбор кадра и валидация проверяются вместе — по отдельности они ничего не значат.
    let mut cur = std::io::Cursor::new(data);
    if let Ok(Some(msg)) = citadel_vpnd::proto::read_frame::<_, EngineMsg>(&mut cur) {
        match msg {
            EngineMsg::TunSetup(req) => {
                if let Ok(s) = citadel_vpnd::valid::TunSetup::parse(&req) {
                    // Разобралось — значит поедет в `ip`/`iptables`. Значения обязаны быть в
                    // диапазонах, а не «строкой, которая случайно прошла».
                    assert!((1..=32).contains(&s.prefix), "prefix {} вне 1..=32", s.prefix);
                    assert!(s.mtu >= 576 && s.mtu <= 65535, "mtu {} вне диапазона", s.mtu);
                }
            }
            EngineMsg::AllowExits(list) => {
                let _ = citadel_vpnd::valid::parse_allow_exits(&list);
            }
            _ => {}
        }
    }
});
