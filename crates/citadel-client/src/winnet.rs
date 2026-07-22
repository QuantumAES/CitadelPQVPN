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
pub fn split_routes(mode: SplitMode, link_routes: &str, dest_routes: &[String]) -> (Vec<String>, Vec<String>) {
    let link: Vec<String> = link_routes.split_whitespace().map(String::from).collect();
    match mode {
        SplitMode::Include => (dest_routes.to_vec(), Vec::new()),
        SplitMode::Exclude => (link, dest_routes.to_vec()),
        SplitMode::Off => (link, Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// split_routes — единый источник split-семантики Linux+Windows (та же логика, что была в gui_tun).
    #[test]
    fn split_routes_modes() {
        let dests = vec!["192.168.0.0/16".to_string(), "10.0.0.5/32".to_string()];
        // Off → маршруты ссылки, без обхода
        assert_eq!(split_routes(SplitMode::Off, "0.0.0.0/0", &dests), (vec!["0.0.0.0/0".to_string()], vec![]));
        // Include → в туннель только выбранные, обхода нет
        assert_eq!(split_routes(SplitMode::Include, "0.0.0.0/0", &dests), (dests.clone(), vec![]));
        // Exclude → маршруты ссылки + выбранные в обход
        assert_eq!(split_routes(SplitMode::Exclude, "0.0.0.0/0", &dests), (vec!["0.0.0.0/0".to_string()], dests.clone()));
    }
}
