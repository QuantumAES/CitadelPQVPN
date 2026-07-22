//! Чистая оркестрация сессии службы: из [`TunSetup`] — конкретные действия по настройке адаптера
//! (netsh-команды IP/маршрутов/DNS + bypass-маршруты + WFP-план). WinAPI-исполнители (`main.rs`,
//! cfg(windows)) их применяют. Тестируется на ЛЮБОЙ ОС — как rule-генераторы `citadel-helper`.

use citadel_winnet::{tunnel_route_entries, wfp_killswitch_plan, TunSetup, WfpFilter};

/// Имя WinTUN-адаптера (служба создаёт его под этим именем; netsh-команды ссылаются на него).
pub const ADAPTER_NAME: &str = "Citadel";

/// План применения сети для сессии. Разложен по осям, чтобы исполнитель применял и откатывал их
/// независимо (маршруты/DNS — всегда; WFP — держится fail-closed при аварийном разрыве).
pub struct SessionPlan {
    /// `netsh`-команды на туннель-адаптере (по порядку): адрес, MTU, маршруты-в-туннель, DNS.
    /// Каждая — argv БЕЗ ведущего `netsh` (исполнитель префиксует). Только адаптерные (не bypass).
    pub netsh: Vec<Vec<String>>,
    /// Bypass-назначения (exit-IP + split-Exclude): маршрутизируются мимо туннеля через ФИЗИЧЕСКИЙ
    /// шлюз. CIDR/host-строки; шлюз/интерфейс исполнитель определяет в рантайме (default-route).
    pub bypass: Vec<String>,
    /// WFP kill-switch план (`Some`, если запрошен) — исполнитель ставит фильтры (fail-closed).
    pub wfp: Option<Vec<WfpFilter>>,
}

/// Собрать план применения сети из конфига. Чистая функция.
pub fn plan_session(s: &TunSetup, adapter: &str) -> SessionPlan {
    let mut netsh: Vec<Vec<String>> = Vec::new();
    let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();

    // адрес/маска на адаптере
    netsh.push(a(&["interface", "ipv4", "set", "address"]).into_iter()
        .chain([format!("name={adapter}"), "static".into(), ip4(&s.addr), mask(s.prefix)])
        .collect());
    // MTU (store=active — не персистить в реестр)
    netsh.push(vec![
        "interface".into(), "ipv4".into(), "set".into(), "subinterface".into(),
        format!("interface={adapter}"), format!("mtu={}", s.mtu), "store=active".into(),
    ]);
    // маршруты В туннель: full-tunnel (0.0.0.0/0) → две /1-половины (физический default выживает)
    for r in tunnel_route_entries(&s.routes) {
        netsh.push(vec![
            "interface".into(), "ipv4".into(), "add".into(), "route".into(),
            r, format!("interface={adapter}"), "store=active".into(),
        ]);
    }
    // DNS через туннель (анти-leak): статический на адаптере
    if let Some(dns) = &s.dns {
        netsh.push(vec![
            "interface".into(), "ipv4".into(), "set".into(), "dnsservers".into(),
            format!("name={adapter}"), "static".into(), dns.clone(), "primary".into(),
        ]);
    }

    // bypass = exit-IP (анти-петля) + split-Exclude «в обход»: физическим шлюзом (как Linux-helper).
    let mut bypass: Vec<String> = Vec::new();
    bypass.extend(s.exit_ips.iter().cloned());
    bypass.extend(s.bypass.iter().cloned());

    let wfp = if s.killswitch { Some(wfp_killswitch_plan(&s.exit_ips, &s.bypass)) } else { None };

    SessionPlan { netsh, bypass, wfp }
}

fn ip4(a: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
}

/// Префикс-длина → маска IPv4 в точечной нотации (`16` → `255.255.0.0`).
fn mask(prefix: u8) -> String {
    let p = prefix.min(32) as u32;
    let m: u32 = if p == 0 { 0 } else { u32::MAX << (32 - p) };
    format!("{}.{}.{}.{}", m >> 24, (m >> 16) & 0xff, (m >> 8) & 0xff, m & 0xff)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(killswitch: bool, routes: &[&str]) -> TunSetup {
        TunSetup {
            addr: [10, 7, 0, 5],
            prefix: 16,
            mtu: 1100,
            routes: routes.iter().map(|s| s.to_string()).collect(),
            dns: Some("1.1.1.1".into()),
            exit_ips: vec!["203.0.113.9".into()],
            bypass: vec!["192.168.1.0/24".into()],
            killswitch,
        }
    }

    #[test]
    fn mask_from_prefix() {
        assert_eq!(mask(16), "255.255.0.0");
        assert_eq!(mask(24), "255.255.255.0");
        assert_eq!(mask(32), "255.255.255.255");
        assert_eq!(mask(0), "0.0.0.0");
    }

    /// full-tunnel раскрывается в две /1-маршрута на адаптере; адрес/DNS присутствуют.
    #[test]
    fn full_tunnel_plan() {
        let p = plan_session(&setup(false, &["0.0.0.0/0"]), "Citadel");
        let flat: Vec<String> = p.netsh.iter().flatten().cloned().collect();
        assert!(flat.contains(&"10.7.0.5".to_string()) && flat.contains(&"255.255.0.0".to_string()));
        assert!(flat.contains(&"0.0.0.0/1".to_string()) && flat.contains(&"128.0.0.0/1".to_string()));
        assert!(flat.contains(&"1.1.1.1".to_string())); // DNS
        assert!(p.wfp.is_none()); // killswitch off
    }

    /// killswitch → WFP-план присутствует; bypass = exit-IP + split-Exclude (в обход физ.шлюзом).
    #[test]
    fn killswitch_and_bypass() {
        let p = plan_session(&setup(true, &["0.0.0.0/0"]), "Citadel");
        assert!(p.wfp.is_some());
        assert!(p.bypass.contains(&"203.0.113.9".to_string())); // exit-IP
        assert!(p.bypass.contains(&"192.168.1.0/24".to_string())); // split-обход (Q5)
    }
}
