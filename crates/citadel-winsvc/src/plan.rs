//! Чистая оркестрация сессии службы: из [`TunSetup`] — конкретные действия по настройке адаптера
//! (netsh-команды IP/маршрутов/DNS + bypass-маршруты + WFP-план). WinAPI-исполнители (`main.rs`,
//! cfg(windows)) их применяют. Тестируется на ЛЮБОЙ ОС — как rule-генераторы `citadel-helper`.

use citadel_winnet::{
    is_full_tunnel, tunnel_route_entries, wfp_ipv6_block_plan, wfp_killswitch_plan, TunSetup,
    WfpFilter,
};

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

    // WFP: IPv4 kill-switch (при killswitch) + IPv6-блок утечки (при killswitch ИЛИ full-tunnel).
    // W1/аудит-3: туннель IPv4-only ⇒ нативный IPv6 (данные + IPv6-DNS) иначе течёт мимо туннеля И
    // мимо IPv4-kill-switch (деанон на dual-stack). Триггер `killswitch || full_tunnel` = как
    // `block_ipv6` на Linux-helper (S2.2/A2). Оба слоя (V4 KS + V6 block) — в ОДНОЙ dynamic
    // WFP-сессии, армятся/снимаются вместе. Full-tunnel без KS → только V6-блок (IPv4 не режем).
    let mut wfp_filters: Vec<WfpFilter> = Vec::new();
    if s.killswitch {
        wfp_filters.extend(wfp_killswitch_plan(&s.exit_ips, &s.bypass));
    }
    if s.killswitch || is_full_tunnel(&s.routes) {
        wfp_filters.extend(wfp_ipv6_block_plan());
    }
    let wfp = (!wfp_filters.is_empty()).then_some(wfp_filters);

    SessionPlan { netsh, bypass, wfp }
}

fn ip4(a: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
}

/// Распарсить IPv4 default-gateway из вывода `route print -4`. Ищем строки, где первые два токена =
/// `0.0.0.0` (destination + netmask default-маршрута), третий — валидный IPv4 (шлюз, не «On-link»);
/// среди них берём с наименьшей метрикой (последний токен). Данные-строки — числа, локаль-независимы
/// (локализуются только заголовки). Чистая функция (тестируется на любой ОС).
pub fn parse_default_gateway(route_print: &str) -> Option<String> {
    let mut best: Option<(u32, String)> = None; // (метрика, шлюз)
    for line in route_print.lines() {
        let t: Vec<&str> = line.split_whitespace().collect();
        if t.len() < 5 || t[0] != "0.0.0.0" || t[1] != "0.0.0.0" {
            continue;
        }
        if t[2].parse::<std::net::Ipv4Addr>().is_err() {
            continue; // «On-link» и прочее — не шлюз
        }
        let metric: u32 = t[4].parse().unwrap_or(u32::MAX);
        if best.as_ref().is_none_or(|(m, _)| metric < *m) {
            best = Some((metric, t[2].to_string()));
        }
    }
    best.map(|(_, gw)| gw)
}

/// `dest` (CIDR `a.b.c.d/p` или голый IP = /32) → `(сеть, маска)` в точечной нотации для `route add`.
pub fn dest_net_mask(dest: &str) -> (String, String) {
    match dest.split_once('/') {
        Some((net, p)) => (net.to_string(), mask(p.parse().unwrap_or(32))),
        None => (dest.to_string(), "255.255.255.255".to_string()),
    }
}

/// Аргументы legacy-команды `route` для bypass-маршрута мимо туннеля через физический шлюз `gw`
/// (`route add <сеть> mask <маска> <gw>`). Legacy `route` сам подбирает интерфейс по шлюзу.
pub fn bypass_route_add(dest: &str, gw: &str) -> Vec<String> {
    let (net, m) = dest_net_mask(dest);
    vec!["add".into(), net, "mask".into(), m, gw.into()]
}

/// Аргументы `route delete <сеть>` для отката bypass-маршрута на teardown.
pub fn bypass_route_del(dest: &str) -> Vec<String> {
    let (net, _) = dest_net_mask(dest);
    vec!["delete".into(), net]
}

/// W3 (аудит-3): лежит ли `file` НЕПОСРЕДСТВЕННО в каталоге `dir` (совпадение родителя). Используется
/// службой для аутентификации клиента пайпа: подключившийся процесс обязан быть образом из install-dir
/// службы (Program Files, куда пишет только админ ⇒ медиум-малварь туда бинарь не положит), иначе
/// любой процесс юзера (ACL даёт IU) гонял бы привилегированную реконфигурацию сети. Регистро- и
/// сепаратор-независимо (Windows-FS). Чистая функция (юнит-тест на любой ОС).
pub fn same_dir(file: &std::path::Path, dir: &std::path::Path) -> bool {
    // Своё разбиение по '/' (а не Path::parent) — чтобы Windows-пути с '\' корректно сравнивались и
    // при тесте на Linux (Path::parent там не парсит '\' как сепаратор). Нормализуем оба: '\'→'/',
    // lower-case (Windows-FS регистронезависима), с dir снимаем хвостовой '/'.
    let norm = |p: &std::path::Path| p.as_os_str().to_string_lossy().replace('\\', "/").to_lowercase();
    let dir_n = norm(dir);
    let dir_n = dir_n.trim_end_matches('/');
    match norm(file).rsplit_once('/') {
        Some((parent, _name)) => parent == dir_n,
        None => false,
    }
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

    /// full-tunnel раскрывается в две /1-маршрута на адаптере; адрес/DNS присутствуют. W1: даже БЕЗ
    /// kill-switch full-tunnel ставит IPv6-блок (V6-only), т.к. IPv4-only туннель иначе течёт по IPv6.
    #[test]
    fn full_tunnel_plan() {
        let p = plan_session(&setup(false, &["0.0.0.0/0"]), "Citadel");
        let flat: Vec<String> = p.netsh.iter().flatten().cloned().collect();
        assert!(flat.contains(&"10.7.0.5".to_string()) && flat.contains(&"255.255.0.0".to_string()));
        assert!(flat.contains(&"0.0.0.0/1".to_string()) && flat.contains(&"128.0.0.0/1".to_string()));
        assert!(flat.contains(&"1.1.1.1".to_string())); // DNS
        // W1: full-tunnel без KS → WFP = ТОЛЬКО IPv6-блок (V4-трафик не режем; V6-утечку закрываем).
        let wfp = p.wfp.expect("full-tunnel → IPv6-блок даже без kill-switch");
        assert!(wfp.iter().all(|f| f.family == citadel_winnet::WfpFamily::V6), "только V6-фильтры");
        assert!(
            wfp.iter().any(|f| f.action == citadel_winnet::WfpAction::Block
                && f.match_ == citadel_winnet::WfpMatch::Any),
            "fail-closed Block IPv6"
        );
    }

    /// W1: матрица WFP по режиму. split-tunnel без KS → WFP не нужен; full-tunnel без KS → только
    /// V6-блок; kill-switch → оба слоя (V4 KS + V6-блок) в одном плане (одна dynamic WFP-сессия).
    #[test]
    fn wfp_families_by_mode() {
        use citadel_winnet::WfpFamily;
        // split-tunnel (не full), KS off → WFP не нужен вовсе
        assert!(plan_session(&setup(false, &["10.0.0.0/8"]), "Citadel").wfp.is_none());
        // full-tunnel, KS off → только V6
        let ft = plan_session(&setup(false, &["0.0.0.0/0"]), "Citadel").wfp.unwrap();
        assert!(ft.iter().all(|f| f.family == WfpFamily::V6));
        // KS on → есть и V4, и V6
        let ks = plan_session(&setup(true, &["0.0.0.0/0"]), "Citadel").wfp.unwrap();
        assert!(ks.iter().any(|f| f.family == WfpFamily::V4));
        assert!(ks.iter().any(|f| f.family == WfpFamily::V6));
    }

    /// killswitch → WFP-план присутствует; bypass = exit-IP + split-Exclude (в обход физ.шлюзом).
    #[test]
    fn killswitch_and_bypass() {
        let p = plan_session(&setup(true, &["0.0.0.0/0"]), "Citadel");
        assert!(p.wfp.is_some());
        assert!(p.bypass.contains(&"203.0.113.9".to_string())); // exit-IP
        assert!(p.bypass.contains(&"192.168.1.0/24".to_string())); // split-обход (Q5)
    }

    /// Парсер default-gw из `route print -4`: берёт шлюз default-маршрута с наименьшей метрикой,
    /// игнорирует «On-link» и не-default строки.
    #[test]
    fn default_gateway_from_route_print() {
        let out = "\
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.50     35
          0.0.0.0          0.0.0.0       10.0.0.1        10.0.0.7        25
      192.168.1.0    255.255.255.0         On-link      192.168.1.50    281
===========================================================================";
        assert_eq!(parse_default_gateway(out), Some("10.0.0.1".to_string())); // метрика 25 < 35
        assert_eq!(parse_default_gateway("нет маршрутов"), None);
    }

    /// CIDR/host → (сеть, маска) и аргументы route add/delete.
    #[test]
    fn route_commands() {
        assert_eq!(dest_net_mask("192.168.1.0/24"), ("192.168.1.0".into(), "255.255.255.0".into()));
        assert_eq!(dest_net_mask("203.0.113.9"), ("203.0.113.9".into(), "255.255.255.255".into()));
        assert_eq!(
            bypass_route_add("203.0.113.9", "10.0.0.1"),
            vec!["add", "203.0.113.9", "mask", "255.255.255.255", "10.0.0.1"]
        );
        assert_eq!(bypass_route_del("192.168.1.0/24"), vec!["delete", "192.168.1.0"]);
    }

    /// W3: клиент пайпа аутентифицируется по «образ в том же каталоге, что служба». app.exe и
    /// citadel-svc.exe Inno ставит в один `{app}` (=%ProgramFiles%\CitadelPQVPN) → same_dir=true;
    /// малварь из Temp / подкаталога / другого места → false (Program Files пишет только админ).
    #[test]
    fn client_image_same_dir_as_service() {
        use std::path::Path;
        let dir = Path::new(r"C:\Program Files\CitadelPQVPN");
        assert!(same_dir(Path::new(r"C:\Program Files\CitadelPQVPN\app.exe"), dir));
        assert!(same_dir(Path::new(r"c:\program files\citadelpqvpn\App.exe"), dir), "регистронезависимо");
        assert!(!same_dir(Path::new(r"C:\Users\bob\AppData\Local\Temp\evil.exe"), dir), "чужой каталог");
        assert!(!same_dir(Path::new(r"C:\Program Files\CitadelPQVPN\sub\app.exe"), dir), "подкаталог ≠ каталог");
        assert!(!same_dir(Path::new("app.exe"), dir), "без родителя");
    }
}
