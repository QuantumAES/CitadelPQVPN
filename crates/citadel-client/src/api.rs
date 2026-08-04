//! Поверхность `citadel-client` для GUI (flutter_rust_bridge → Dart).
//!
//! Codegen (трек C2.2) генерирует Dart-обёртки из pub-функций/структур этого модуля.
//! Типы — frb-совместимые (`String`/`Vec`/`bool`/`Result`). Stateful connect/disconnect/поток
//! событий добавятся при сквозной интеграции (C2.4), когда появится Linux-`TunProvider`.

use anyhow::Result;

use crate::creds::{CredentialBundle, CredentialLink};

/// Версия ядра (about-экран UI).
pub fn version() -> String {
    crate::version().to_string()
}

/// UI-сводка по кредам — что внутри ссылки/бандла (экран подтверждения перед подключением).
pub struct CredentialSummary {
    /// Exit-серверы `host:port`.
    pub servers: Vec<String>,
    /// SNI сервера.
    pub server_name: String,
    /// KX-suite ("", "pq", "classical", "all").
    pub kx_suite: String,
    /// Задан cert-pin (F1).
    pub has_pin: bool,
    /// Доступна PQ-аутентификация сервера (ML-DSA-65, M7).
    pub has_pq_auth: bool,
    /// Включена обфускация L1.
    pub has_obfs: bool,
    /// Привязан издатель токенов (M5).
    pub has_issuer: bool,
    /// C7.4: мастер-ссылка (несёт admin_seed → admin-операции доступны). Показ в UI важен:
    /// мастер-ссылку нельзя раздавать абонентам.
    pub is_admin: bool,
}

impl CredentialSummary {
    fn from_link(l: &CredentialLink) -> Self {
        Self {
            servers: l.servers.clone(),
            server_name: l.server_name.clone(),
            kx_suite: l.kx_suite.clone(),
            has_pin: l.cert_pin.is_some(),
            has_pq_auth: l.mldsa_commit.is_some(),
            has_obfs: l.obfs_psk.is_some(),
            has_issuer: l.issuer.is_some(),
            is_admin: l.is_admin(),
        }
    }

    fn from_bundle(b: &CredentialBundle) -> Self {
        Self {
            servers: b.servers.clone(),
            server_name: b.server_name.clone(),
            kx_suite: b.kx_suite.clone(),
            has_pin: b.cert_pin.is_some(),
            has_pq_auth: b.mldsa_pub.is_some(),
            has_obfs: b.obfs_psk.is_some(),
            has_issuer: b.issuer.is_some(),
            is_admin: b.admin_seed.is_some(),
        }
    }
}

/// Разобрать `citadel://`-ссылку (из QR/буфера обмена) → сводка для UI.
pub fn parse_link(uri: String) -> Result<CredentialSummary> {
    Ok(CredentialSummary::from_link(&CredentialLink::from_uri(&uri)?))
}

/// Загрузить бандл `.citadelconf` → сводка для UI.
pub fn load_bundle_file(path: String) -> Result<CredentialSummary> {
    Ok(CredentialSummary::from_bundle(&CredentialBundle::load_file(&path)?))
}

/// QR-SVG для `citadel://`-ссылки (admin-экран выдачи кред).
pub fn link_qr_svg(uri: String) -> Result<String> {
    CredentialLink::from_uri(&uri)?.to_qr_svg()
}

/// C7.4: QR ссылки как битовая матрица `size × size` (1 = тёмный модуль) — Flutter рисует её
/// кастомным painter'ом (без SVG-рендера в Dart-зависимостях).
pub fn link_qr_matrix(uri: String) -> Result<(u32, Vec<u8>)> {
    CredentialLink::from_uri(&uri)?.to_qr_matrix()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_bundle() -> CredentialBundle {
        CredentialBundle {
            version: crate::creds::BUNDLE_VERSION,
            servers: vec!["exit.example:4433".into()],
            server_name: "citadel.exit".into(),
            kx_suite: "pq".into(),
            cert_pin: Some([1u8; 32]),
            mldsa_pub: Some(vec![2u8; 1952]),
            obfs_psk: Some([3u8; 32]),
            tcp_port: None,
            issuer: Some("issuer.example:7000".into()),
            issuer_pub: Some(vec![4u8; 270]),
            issuer_pin: Some([5u8; 32]),
            issuer_mldsa: Some([9u8; 32]),
            client_seed: None,
            admin_seed: None,
            admin_port: None,
            routes: String::new(),
            dns: None,
        }
    }

    #[test]
    fn parse_link_to_summary() {
        let uri = CredentialLink::from_bundle(&sample_bundle()).to_uri().unwrap();
        let s = parse_link(uri).unwrap();
        assert_eq!(s.servers, vec!["exit.example:4433".to_string()]);
        assert_eq!(s.server_name, "citadel.exit");
        assert!(s.has_pin && s.has_pq_auth && s.has_obfs && s.has_issuer);
        assert!(!s.is_admin, "без admin_seed ссылка не мастер");
    }

    /// C7.4: сводка видит мастер-ссылку (admin_seed) — UI пометит её и покажет пункт «Абоненты».
    #[test]
    fn summary_flags_admin_link() {
        let mut b = sample_bundle();
        b.admin_seed = Some([0x77; 32]);
        b.admin_port = Some("7001".into());
        let uri = CredentialLink::from_bundle(&b).to_uri().unwrap();
        assert!(parse_link(uri).unwrap().is_admin);
    }

    #[test]
    fn link_qr_svg_renders() {
        let uri = CredentialLink::from_bundle(&sample_bundle()).to_uri().unwrap();
        assert!(link_qr_svg(uri).unwrap().contains("<svg"));
    }

    /// C7.4: QR-матрица согласована (size², модули 0/1, есть и тёмные, и светлые).
    #[test]
    fn link_qr_matrix_consistent() {
        let uri = CredentialLink::from_bundle(&sample_bundle()).to_uri().unwrap();
        let (size, cells) = link_qr_matrix(uri).unwrap();
        assert!(size >= 21, "минимум QR v1");
        assert_eq!(cells.len(), (size * size) as usize);
        assert!(cells.contains(&1) && cells.contains(&0));
        assert!(cells.iter().all(|c| *c <= 1));
    }

    #[test]
    fn version_nonempty() {
        assert!(!version().is_empty());
    }
}
