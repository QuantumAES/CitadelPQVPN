//! `winnet` — фасад над крейтом [`citadel_winnet`] (ядро Windows-модели W2) + `split_routes`.
//!
//! Пуре-логика IPC-кадров/WFP-плана/маршрутов вынесена в лёгкий крейт `citadel-winnet` (им же
//! пользуется привилегированная служба `citadel-svc`, не линкуя движок). Здесь — ре-экспорт этого
//! ядра + `split_routes` (единственное, что требует `SplitMode` из движка ⇒ живёт на app-стороне).
//! Провайдеры (`gui_tun`, `win_tun`) продолжают звать `crate::winnet::{split_routes, TunSetup, …}`.

pub use citadel_winnet::*;

use citadel_quic::config::SplitMode;

/// C8.3: из режима «по назначению» → `(маршруты В туннель, CIDR В обход)`. **Единый источник** для
/// Linux (`citadel-helper --routes/--bypass`) и Windows (`TunSetup.routes/bypass`): split-семантика
/// (включая Q5 kill-switch⇄split) одна на все платформы. Include → в туннель ТОЛЬКО выбранные CIDR
/// (default физический); Exclude → маршруты ссылки как есть + выбранные в обход; Off → маршруты ссылки.
///
/// `tun_net` — назначенная подсеть туннеля (`addr`, `prefix`): из «обхода» ВСЕГДА вырезаются CIDR,
/// пересекающиеся с ней. В этой подсети живёт шлюз exit'а = `ADMIN_VIP` (C7.2, admin-канал
/// «Абоненты»); bypass-маршрут на неё (напр. пользователь добавил «локальную подсеть», совпавшую с
/// туннельной, или широкий `10.0.0.0/8`) перебил бы on-link маршрут интерфейса и увёл admin-канал в
/// физический шлюз — «No route to host». Тот же инвариант держит Android (`CitadelVpnService`).
pub fn split_routes(
    mode: SplitMode,
    link_routes: &str,
    dest_routes: &[String],
    tun_net: ([u8; 4], u8),
) -> (Vec<String>, Vec<String>) {
    let link: Vec<String> = link_routes.split_whitespace().map(String::from).collect();
    let safe_bypass = || -> Vec<String> {
        dest_routes.iter().filter(|d| !overlaps_tun_net(d, tun_net)).cloned().collect()
    };
    match mode {
        SplitMode::Include => (dest_routes.to_vec(), Vec::new()),
        SplitMode::Exclude => (link, safe_bypass()),
        SplitMode::Off => (link, Vec::new()),
    }
}

/// Пересекается ли CIDR (`a.b.c.d/len`, без `/len` → `/32`) с подсетью туннеля. Неразобранное —
/// `false` (маршрут уйдёт как есть; валидацию полей делает `validate_net_fields`).
fn overlaps_tun_net(cidr: &str, (net_ip, net_prefix): ([u8; 4], u8)) -> bool {
    let (ip_s, prefix) = match cidr.split_once('/') {
        Some((i, p)) => (i, p.parse::<u8>().unwrap_or(33)),
        None => (cidr, 32),
    };
    let Ok(ip) = ip_s.parse::<std::net::Ipv4Addr>() else { return false };
    if prefix > 32 || net_prefix > 32 {
        return false;
    }
    let shortest = prefix.min(net_prefix);
    let mask = if shortest == 0 { 0 } else { u32::MAX << (32 - shortest as u32) };
    (u32::from(ip) & mask) == (u32::from(std::net::Ipv4Addr::from(net_ip)) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Подсеть туннеля для тестов: клиент 10.7.0.2/16 (шлюз/ADMIN_VIP 10.7.0.1 внутри).
    const TUN: ([u8; 4], u8) = ([10, 7, 0, 2], 16);

    /// split_routes — единый источник split-семантики Linux+Windows (та же логика, что была в gui_tun).
    #[test]
    fn split_routes_modes() {
        let dests = vec!["192.168.0.0/16".to_string(), "172.16.0.5/32".to_string()];
        // Off → маршруты ссылки, без обхода
        assert_eq!(split_routes(SplitMode::Off, "0.0.0.0/0", &dests, TUN), (vec!["0.0.0.0/0".to_string()], vec![]));
        // Include → в туннель только выбранные, обхода нет
        assert_eq!(split_routes(SplitMode::Include, "0.0.0.0/0", &dests, TUN), (dests.clone(), vec![]));
        // Exclude → маршруты ссылки + выбранные в обход
        assert_eq!(split_routes(SplitMode::Exclude, "0.0.0.0/0", &dests, TUN), (vec!["0.0.0.0/0".to_string()], dests.clone()));
    }

    /// Инвариант: подсеть туннеля (в ней шлюз = ADMIN_VIP, admin-канал) НИКОГДА не уходит в обход —
    /// ни точным совпадением, ни более широким/узким префиксом. Прочие назначения не трогаются.
    #[test]
    fn split_routes_never_bypasses_tunnel_subnet() {
        let dests = vec![
            "10.7.0.0/24".to_string(),    // внутри подсети туннеля (кнопка «локальная подсеть» при VPN)
            "10.0.0.0/8".to_string(),     // шире подсети туннеля
            "10.7.0.1/32".to_string(),    // сам ADMIN_VIP
            "192.168.1.0/24".to_string(), // настоящая локалка — остаётся
        ];
        let (routes, bypass) = split_routes(SplitMode::Exclude, "0.0.0.0/0", &dests, TUN);
        assert_eq!(routes, vec!["0.0.0.0/0".to_string()]);
        assert_eq!(bypass, vec!["192.168.1.0/24".to_string()]);
    }

    #[test]
    fn overlaps_tun_net_edges() {
        assert!(overlaps_tun_net("10.7.255.255/32", TUN)); // край /16
        assert!(!overlaps_tun_net("10.8.0.0/16", TUN)); // соседняя подсеть
        assert!(!overlaps_tun_net("не-cidr", TUN)); // мусор → не фильтруем
        assert!(overlaps_tun_net("0.0.0.0/0", TUN)); // default накрывает всё
    }
}
