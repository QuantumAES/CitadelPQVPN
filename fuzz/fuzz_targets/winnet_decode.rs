//! F12 — граница привилегий Windows (`citadel_winnet`): кадры named pipe к службе SYSTEM.
//!
//! **Кто подаёт:** любой интерактивный пользователь машины (опознание клиента пайпа — отдельный
//! рубеж, L-9, и он стоит ПОСЛЕ разбора). Скомпрометированный клиент подаёт то же самое, но
//! осмысленно. За границей — WFP-план и маршруты, применяемые от SYSTEM, поэтому приоритет высший.
//!
//! **Инвариант:** служба не паникует и не собирает план из мусора; `parse_stream` не выходит за
//! буфер и не зацикливается на нулевой длине.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(setup) = citadel_winnet::decode_config(data) {
        // Разобралось — значит пойдёт в WFP/маршруты. Дальше конфиг обязан пройти собственную
        // проверку, и именно её результат решает, армируется план или нет.
        let _ = setup.validate();
        let _ = citadel_winnet::tunnel_route_entries(&setup.routes);
        let _ = citadel_winnet::is_full_tunnel(&setup.routes);
        let plan = citadel_winnet::wfp_killswitch_plan(&setup.exit_ips, &setup.bypass);
        // Kill-switch, собранный из недоверенных строк, обязан оставаться проверяемым планом:
        // слой из одного block-catch-all (без permit'ов) отсекается здесь, а не на живой машине.
        let _ = citadel_winnet::check_wfp_plan(&plan);
    }
    let _ = citadel_winnet::parse_stream(data);
    let _ = citadel_winnet::decode_ready(data);
});
