//! Формат клиентских кред.
//!
//! Две формы (см. docs/CLIENT-ARCH.md §9):
//!   - **полный бандл** `.citadelconf` — CBOR, все ключи инлайн (импорт файлом / air-gapped);
//!   - **компактная ссылка** `citadel://`/QR — только обязательства-хэши (C1.2), ключи
//!     дотягиваются по каналу и сверяются с хэшами.
//!
//! C1.1: [`CredentialBundle`] + CBOR-сериализация + файловый I/O. Преобразование
//! бандла в `citadel_quic::config::ClientConfig` — C1.4.

use anyhow::{Context, Result};
use citadel_quic::config::{ClientConfig, MldsaSource, PinSource};
use serde::{Deserialize, Serialize};

/// Версия формата бандла (растёт при несовместимых изменениях схемы).
pub const BUNDLE_VERSION: u8 = 1;

/// Полный набор кред для подключения к exit'ам — всё инлайн.
///
/// Поля `Option` отражают PoC-градации: без pin (no-pin), без obfs (PSK=None), без PQ-auth
/// (mldsa_pub=None), без токенов (issuer=None), без идентичности Layer-1 (client_seed=None).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialBundle {
    /// Версия формата (= [`BUNDLE_VERSION`]).
    pub version: u8,
    /// Exit-серверы `host:port` (M5 multi-server).
    pub servers: Vec<String>,
    /// SNI / server_name для TLS.
    pub server_name: String,
    /// KX-suite (M6): "", "pq", "classical", "all".
    pub kx_suite: String,
    /// Cert-pin (F1, SHA-256 SPKI); `None` → PoC no-pin.
    #[serde(with = "serde_bytes")]
    pub cert_pin: Option<[u8; 32]>,
    /// ML-DSA-65 pub (M7, 1952 B); `None` → только Ed25519+pin.
    #[serde(with = "serde_bytes")]
    pub mldsa_pub: Option<Vec<u8>>,
    /// L1-obfs PSK (32 B); `None` → без обфускации.
    #[serde(with = "serde_bytes")]
    pub obfs_psk: Option<[u8; 32]>,
    /// Порт obfs-over-TCP fallback (M4); `None` → дефолт 443.
    pub tcp_port: Option<String>,
    /// Endpoint издателя токенов `host:port` (M5); `None` → токены не используются.
    pub issuer: Option<String>,
    /// Pub издателя (RSA) для проверки токенов на клиенте.
    #[serde(with = "serde_bytes")]
    pub issuer_pub: Option<Vec<u8>>,
    /// Ed25519 client-seed (Layer-1 «абонемент», C5); `None` → анонимный режим без идентичности.
    #[serde(with = "serde_bytes")]
    pub client_seed: Option<[u8; 32]>,
    /// Маршруты в туннель (через пробел).
    pub routes: String,
    /// DNS-резолвер (F6); `None` → не настраивать.
    pub dns: Option<String>,
}

impl CredentialBundle {
    /// Сериализовать в CBOR.
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).context("CBOR-сериализация бандла")?;
        Ok(buf)
    }

    /// Разобрать из CBOR (проверяет версию формата).
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        let b: CredentialBundle = ciborium::from_reader(bytes).context("CBOR-разбор бандла")?;
        if b.version != BUNDLE_VERSION {
            anyhow::bail!(
                "несовместимая версия бандла: {} (ожидалась {BUNDLE_VERSION})",
                b.version
            );
        }
        Ok(b)
    }

    /// Записать бандл в файл `.citadelconf` (CBOR).
    pub fn save_file(&self, path: &str) -> Result<()> {
        std::fs::write(path, self.to_cbor()?).with_context(|| format!("запись {path}"))
    }

    /// Прочитать бандл из файла `.citadelconf`.
    pub fn load_file(path: &str) -> Result<Self> {
        let bytes = std::fs::read(path).with_context(|| format!("чтение {path}"))?;
        Self::from_cbor(&bytes)
    }

    /// Преобразовать в `ClientConfig` (готовый к подключению конфиг движка).
    ///
    /// `token` остаётся ПУСТЫМ — анонимный токен добывается отдельно (TokenAgent по
    /// `issuer`+`client_seed`, трек C5) и кладётся в `config.token`. MTU дефолтный (бандл его
    /// не несёт). `issuer`/`issuer_pub`/`client_seed` — входы для добычи токена, в конфиг
    /// коннекта не входят. pin/mldsa берутся из инлайн-байтов бандла (`PinSource::Bytes`/
    /// `MldsaSource::Bytes` — host-независимо).
    pub fn to_client_config(&self) -> ClientConfig {
        ClientConfig {
            servers: self.servers.clone(),
            server_name: self.server_name.clone(),
            obfs_psk: self.obfs_psk,
            kx_suite: self.kx_suite.clone(),
            tcp_port: self.tcp_port.clone().unwrap_or_else(|| "443".into()),
            routes: self.routes.clone(),
            dns: self.dns.clone(),
            mtu: "1280".into(),
            token: Vec::new(),
            pin: self.cert_pin.map_or(PinSource::None, PinSource::Bytes),
            mldsa: self
                .mldsa_pub
                .clone()
                .map_or(MldsaSource::None, MldsaSource::Bytes),
            allow_insecure_no_pin: false,
        }
    }
}

/// Префикс компактной ссылки.
const URI_PREFIX: &str = "citadel://";

/// SHA-256 — обязательство к публичному ключу.
fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}

/// Компактная форма кред для `citadel://`-ссылки / QR: вместо больших публичных ключей —
/// **обязательства** `H(pub)` (32 B). Секреты (`obfs_psk`, `client_seed`) и сам pin (он уже
/// SHA-256 сертификата) идут инлайн. Полные `mldsa_pub`/`issuer_pub` дотягиваются по каналу
/// и сверяются ([`verify_mldsa`](CredentialLink::verify_mldsa)/[`verify_issuer`](CredentialLink::verify_issuer)):
/// out-of-band обязательство связывает PQ-ключ независимо от стойкости транспортного pin
/// (CRQC-safe bootstrap, §9.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialLink {
    pub version: u8,
    pub servers: Vec<String>,
    pub server_name: String,
    pub kx_suite: String,
    /// Cert-pin (F1) — уже обязательство (SHA-256 SPKI), идёт инлайн.
    #[serde(with = "serde_bytes")]
    pub cert_pin: Option<[u8; 32]>,
    /// Обязательство к ML-DSA-65 pub: `H(mldsa_pub)`.
    #[serde(with = "serde_bytes")]
    pub mldsa_commit: Option<[u8; 32]>,
    /// L1-obfs PSK (секрет — инлайн, дотянуть нельзя).
    #[serde(with = "serde_bytes")]
    pub obfs_psk: Option<[u8; 32]>,
    pub tcp_port: Option<String>,
    pub issuer: Option<String>,
    /// Обязательство к pub издателя: `H(issuer_pub)`.
    #[serde(with = "serde_bytes")]
    pub issuer_commit: Option<[u8; 32]>,
    /// Ed25519 client-seed (секрет Layer-1 — инлайн).
    #[serde(with = "serde_bytes")]
    pub client_seed: Option<[u8; 32]>,
    pub routes: String,
    pub dns: Option<String>,
}

impl CredentialLink {
    /// Построить компактную форму из полного бандла (большие ключи → обязательства `H(pub)`).
    pub fn from_bundle(b: &CredentialBundle) -> Self {
        Self {
            version: b.version,
            servers: b.servers.clone(),
            server_name: b.server_name.clone(),
            kx_suite: b.kx_suite.clone(),
            cert_pin: b.cert_pin,
            mldsa_commit: b.mldsa_pub.as_deref().map(sha256),
            obfs_psk: b.obfs_psk,
            tcp_port: b.tcp_port.clone(),
            issuer: b.issuer.clone(),
            issuer_commit: b.issuer_pub.as_deref().map(sha256),
            client_seed: b.client_seed,
            routes: b.routes.clone(),
            dns: b.dns.clone(),
        }
    }

    /// Кодировать в `citadel://`-ссылку (CBOR → base64url-no-pad).
    pub fn to_uri(&self) -> Result<String> {
        use base64::Engine;
        let mut cbor = Vec::new();
        ciborium::into_writer(self, &mut cbor).context("CBOR-сериализация ссылки")?;
        Ok(format!(
            "{URI_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cbor)
        ))
    }

    /// Разобрать `citadel://`-ссылку (проверяет префикс и версию формата).
    pub fn from_uri(s: &str) -> Result<Self> {
        use base64::Engine;
        let payload = s
            .trim()
            .strip_prefix(URI_PREFIX)
            .with_context(|| format!("ссылка не начинается с {URI_PREFIX}"))?;
        let cbor = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .context("base64url-декод ссылки")?;
        let link: CredentialLink =
            ciborium::from_reader(&cbor[..]).context("CBOR-разбор ссылки")?;
        if link.version != BUNDLE_VERSION {
            anyhow::bail!(
                "несовместимая версия ссылки: {} (ожидалась {BUNDLE_VERSION})",
                link.version
            );
        }
        Ok(link)
    }

    /// Сверить дотянутый ML-DSA-65 pub с обязательством. Нет обязательства (PQ-auth не
    /// запрашивается) → проверять нечего → `true`.
    pub fn verify_mldsa(&self, pub_key: &[u8]) -> bool {
        self.mldsa_commit.is_none_or(|c| sha256(pub_key) == c)
    }

    /// Сверить дотянутый pub издателя с обязательством.
    pub fn verify_issuer(&self, pub_key: &[u8]) -> bool {
        self.issuer_commit.is_none_or(|c| sha256(pub_key) == c)
    }

    /// Сгенерировать QR компактной ссылки как **SVG** (EC=M). UI рисует напрямую; декод
    /// QR-картинки делает камера платформы (в Rust приходит уже строка `citadel://`).
    /// Альтернатива — UI берёт `to_uri()` и рисует QR сам (Dart `qr_flutter` и т.п.).
    pub fn to_qr_svg(&self) -> Result<String> {
        let uri = self.to_uri()?;
        let code = qrcode::QrCode::with_error_correction_level(uri.as_bytes(), qrcode::EcLevel::M)
            .context("QR-кодирование citadel://-ссылки")?;
        Ok(code
            .render::<qrcode::render::svg::Color>()
            .min_dimensions(256, 256)
            .build())
    }

    /// Преобразовать компактную ссылку в `ClientConfig` для подключения. pin берётся из
    /// инлайн-`cert_pin`, obfs_psk инлайн. `mldsa = None` — в ссылке только обязательство
    /// `H(pub)`, поэтому PQ-auth (ML-DSA) пропускается, пока полный pub не дотянут по каналу
    /// (commitment-fetch — deferred). `token` пуст (добывается отдельно, C5).
    pub fn to_client_config(&self) -> ClientConfig {
        ClientConfig {
            servers: self.servers.clone(),
            server_name: self.server_name.clone(),
            obfs_psk: self.obfs_psk,
            kx_suite: self.kx_suite.clone(),
            tcp_port: self.tcp_port.clone().unwrap_or_else(|| "443".into()),
            routes: self.routes.clone(),
            dns: self.dns.clone(),
            mtu: "1280".into(),
            token: Vec::new(),
            pin: self.cert_pin.map_or(PinSource::None, PinSource::Bytes),
            mldsa: MldsaSource::None,
            allow_insecure_no_pin: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CredentialBundle {
        CredentialBundle {
            version: BUNDLE_VERSION,
            servers: vec!["exit1.example:4433".into(), "exit2.example:4433".into()],
            server_name: "citadel.exit".into(),
            kx_suite: "pq".into(),
            cert_pin: Some([0x11; 32]),
            mldsa_pub: Some(vec![0x22; 1952]),
            obfs_psk: Some([0x33; 32]),
            tcp_port: Some("443".into()),
            issuer: Some("issuer.example:7000".into()),
            issuer_pub: Some(vec![0x44; 270]),
            client_seed: Some([0x55; 32]),
            routes: "1.1.1.1/32 0.0.0.0/0".into(),
            dns: Some("1.1.1.1".into()),
        }
    }

    #[test]
    fn cbor_roundtrip_full() {
        let b = sample();
        let back = CredentialBundle::from_cbor(&b.to_cbor().unwrap()).unwrap();
        assert_eq!(b, back);
    }

    #[test]
    fn cbor_roundtrip_minimal() {
        // PoC-минимум: без pin/psk/mldsa/issuer/seed
        let b = CredentialBundle {
            version: BUNDLE_VERSION,
            servers: vec!["10.0.0.1:4433".into()],
            server_name: "citadel.exit".into(),
            kx_suite: String::new(),
            cert_pin: None,
            mldsa_pub: None,
            obfs_psk: None,
            tcp_port: None,
            issuer: None,
            issuer_pub: None,
            client_seed: None,
            routes: String::new(),
            dns: None,
        };
        let back = CredentialBundle::from_cbor(&b.to_cbor().unwrap()).unwrap();
        assert_eq!(b, back);
    }

    #[test]
    fn rejects_wrong_version() {
        let mut b = sample();
        b.version = 99;
        assert!(CredentialBundle::from_cbor(&b.to_cbor().unwrap()).is_err());
    }

    #[test]
    fn file_roundtrip() {
        let b = sample();
        let path = std::env::temp_dir().join(format!("citadel-{}.citadelconf", std::process::id()));
        let path = path.to_str().unwrap();
        b.save_file(path).unwrap();
        let back = CredentialBundle::load_file(path).unwrap();
        let _ = std::fs::remove_file(path);
        assert_eq!(b, back);
    }

    #[test]
    fn link_uri_roundtrip() {
        let link = CredentialLink::from_bundle(&sample());
        let uri = link.to_uri().unwrap();
        assert!(uri.starts_with("citadel://"));
        assert_eq!(link, CredentialLink::from_uri(&uri).unwrap());
    }

    #[test]
    fn link_carries_commitments_not_keys() {
        let b = sample();
        let link = CredentialLink::from_bundle(&b);
        // большие ключи → обязательства H(pub), не сами ключи
        assert_eq!(link.mldsa_commit, Some(sha256(b.mldsa_pub.as_ref().unwrap())));
        assert_eq!(link.issuer_commit, Some(sha256(b.issuer_pub.as_ref().unwrap())));
        // секреты — инлайн как есть
        assert_eq!(link.obfs_psk, b.obfs_psk);
        assert_eq!(link.client_seed, b.client_seed);
    }

    #[test]
    fn verify_against_commitment() {
        let b = sample();
        let link = CredentialLink::from_bundle(&b);
        assert!(link.verify_mldsa(b.mldsa_pub.as_ref().unwrap())); // правильный — проходит
        assert!(link.verify_issuer(b.issuer_pub.as_ref().unwrap()));
        assert!(!link.verify_mldsa(b"forgery")); // подменённый ключ — отвергнут
        assert!(!link.verify_issuer(b"forgery"));
    }

    #[test]
    fn from_uri_rejects_bad_prefix() {
        assert!(CredentialLink::from_uri("https://evil/x").is_err());
    }

    #[test]
    fn link_much_smaller_than_bundle() {
        let b = sample();
        let bundle_len = b.to_cbor().unwrap().len();
        let uri_len = CredentialLink::from_bundle(&b).to_uri().unwrap().len();
        // mldsa 1952B → 32B обязательство ⇒ ссылка кратно меньше полного бандла
        assert!(uri_len < bundle_len / 2, "uri {uri_len} vs bundle {bundle_len}");
    }

    #[test]
    fn qr_fits_r4() {
        let link = CredentialLink::from_bundle(&sample());
        let uri = link.to_uri().unwrap();
        let code =
            qrcode::QrCode::with_error_correction_level(uri.as_bytes(), qrcode::EcLevel::M).unwrap();
        let width = code.width();
        let version = (width - 17) / 4; // версия V → 17+4V модулей на сторону
        eprintln!(
            "R4: citadel:// = {} байт; QR версия {version} (EC=M, {width}×{width} модулей)",
            uri.len()
        );
        // «жирный» sample (pin+mldsa+psk+issuer+seed) должен влезать с большим запасом (макс v40)
        assert!(version <= 22, "QR версия {version} великовата для надёжного скана");
        assert!(link.to_qr_svg().unwrap().contains("<svg"));
    }

    #[test]
    fn to_client_config_maps_fields() {
        let b = sample();
        let cfg = b.to_client_config();
        assert_eq!(cfg.servers, b.servers);
        assert_eq!(cfg.server_name, b.server_name);
        assert_eq!(cfg.obfs_psk, b.obfs_psk);
        assert_eq!(cfg.kx_suite, b.kx_suite);
        assert_eq!(cfg.tcp_port, "443"); // bundle.tcp_port = Some("443")
        assert_eq!(cfg.routes, b.routes);
        assert_eq!(cfg.dns, b.dns);
        assert!(cfg.token.is_empty()); // токен добывается отдельно (C5)
        // pin/mldsa резолвятся из инлайн-байтов бандла (host-независимо для Bytes-варианта)
        assert!(matches!(
            cfg.pin_for("any"),
            citadel_quic::config::PinMode::Pinned(p) if Some(p) == b.cert_pin
        ));
        assert_eq!(cfg.mldsa_for("any"), b.mldsa_pub);
    }

    #[test]
    fn to_client_config_defaults_tcp_port() {
        let mut b = sample();
        b.tcp_port = None;
        assert_eq!(b.to_client_config().tcp_port, "443"); // дефолт при отсутствии в бандле
    }
}
