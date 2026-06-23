//! CitadelPQVPN — общая конфигурация PQ-QUIC (используется бинарями M0 и M1).
//!
//! Гибридная KX-группа X25519MLKEM768 (aws-lc-rs), TLS 1.3 over QUIC,
//! self-signed Ed25519 (этап-1 аутентификация), включённые QUIC DATAGRAM.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{aws_lc_rs, CryptoProvider, SupportedKxGroup};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

mod obfs_socket;
pub mod pqauth;
pub mod ratelimit;
pub mod tcp_obfs;
pub use obfs_socket::{client_endpoint_obfs, server_endpoint_obfs};

pub const ALPN: &[u8] = b"Citadel-pq";

pub fn pq_groups() -> Vec<&'static dyn SupportedKxGroup> {
    vec![aws_lc_rs::kx_group::X25519MLKEM768]
}
pub fn classical_groups() -> Vec<&'static dyn SupportedKxGroup> {
    vec![aws_lc_rs::kx_group::X25519]
}

/// Crypto-agility (M6): именованный выбор KX-suite. TLS 1.3 negotiate'ит общую группу из списка,
/// поэтому смена suite на одной стороне совместима, если у другой есть пересечение (graceful
/// downgrade/upgrade без слома). Добавление нового suite — одна ветка здесь.
///   `pq` (default) — `X25519MLKEM768` (гибрид, анти-HNDL);
///   `classical`    — `X25519` (без PQ — для отладки/совместимости);
///   `all`          — оба по приоритету (negotiate; миграция парка без флэг-дня).
pub fn kx_groups_for(suite: &str) -> Vec<&'static dyn SupportedKxGroup> {
    match suite.trim() {
        "classical" | "x25519" => classical_groups(),
        "all" | "hybrid" => vec![aws_lc_rs::kx_group::X25519MLKEM768, aws_lc_rs::kx_group::X25519],
        _ => pq_groups(), // "pq" / пусто / неизвестное → безопасный default (PQ)
    }
}

/// Имя выбранного KX-suite (для логов).
pub fn kx_suite_name(suite: &str) -> &'static str {
    match suite.trim() {
        "classical" | "x25519" => "X25519 (classical)",
        "all" | "hybrid" => "X25519MLKEM768+X25519 (negotiate)",
        _ => "X25519MLKEM768 (PQ-гибрид)",
    }
}

/// KX-suite из env `Citadel_KX` (`pq`|`classical`|`all`), по умолчанию `pq`.
pub fn kx_groups_from_env() -> Vec<&'static dyn SupportedKxGroup> {
    kx_groups_for(&std::env::var("Citadel_KX").unwrap_or_default())
}

pub fn provider(groups: Vec<&'static dyn SupportedKxGroup>) -> Arc<CryptoProvider> {
    let mut p = aws_lc_rs::default_provider();
    p.kx_groups = groups;
    Arc::new(p)
}

pub fn self_signed_ed25519() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let cert = rcgen::CertificateParams::new(vec!["Citadel.exit".to_string()])?.self_signed(&key)?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    Ok((cert_der, key_der))
}

// QUIC-транспорт с включёнными датаграммами + keepalive (для удержания туннеля).
fn transport() -> Arc<quinn::TransportConfig> {
    let mut tc = quinn::TransportConfig::default();
    tc.datagram_receive_buffer_size(Some(1 << 20));
    tc.datagram_send_buffer_size(1 << 20);
    tc.keep_alive_interval(Some(Duration::from_secs(5)));
    tc.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    // Фиксируем MTU: запас под obfs-оверхед L1 (M3), без агрессивного discovery до 1500.
    tc.initial_mtu(1200);
    tc.mtu_discovery_config(None);
    Arc::new(tc)
}

/// Pin сертификата = BLAKE3 от его DER (формат провижининга, см. THREAT-MODEL §3 F1).
pub fn cert_pin(cert: &CertificateDer<'_>) -> [u8; 32] {
    blake3::hash(cert.as_ref()).into()
}

pub fn server_config(groups: Vec<&'static dyn SupportedKxGroup>) -> Result<quinn::ServerConfig> {
    Ok(server_config_with_pin(groups)?.0)
}

/// Как [`server_config`], но дополнительно отдаёт pin серверного сертификата —
/// клиент пиннит его (канал провижининга), чтобы исключить MITM (S1/F1).
pub fn server_config_with_pin(
    groups: Vec<&'static dyn SupportedKxGroup>,
) -> Result<(quinn::ServerConfig, [u8; 32])> {
    let (cert, key) = self_signed_ed25519()?;
    let pin = cert_pin(&cert);
    let mut crypto = rustls::ServerConfig::builder_with_provider(provider(groups))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let mut sc = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));
    sc.transport_config(transport());
    // M4: принимать миграцию соединения (смена пути client'а: WiFi↔LTE / NAT-rebind). QUIC опознаёт
    // соединение по Connection ID, валидирует новый путь (PATH_CHALLENGE) и продолжает без разрыва.
    sc.migration(true);
    Ok((sc, pin))
}

pub fn client_config(groups: Vec<&'static dyn SupportedKxGroup>) -> Result<quinn::ClientConfig> {
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider(groups))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert)) // PoC: фокус на KX, не PKI
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let mut cc = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
    cc.transport_config(transport());
    Ok(cc)
}

/// Прод-путь (F1): клиент пиннит серверный сертификат по `pin` И проверяет CertVerify-подпись.
pub fn client_config_pinned(
    groups: Vec<&'static dyn SupportedKxGroup>,
    pin: [u8; 32],
) -> Result<quinn::ClientConfig> {
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider(groups))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServerCert::new(pin)))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let mut cc = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
    cc.transport_config(transport());
    Ok(cc)
}

/// Верификатор с pinning: сверяет pin сертификата И проверяет подпись хендшейка
/// штатными алгоритмами провайдера (без этого pin публичного ключа не защищал бы от MITM).
pub struct PinnedServerCert {
    pin: [u8; 32],
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl PinnedServerCert {
    pub fn new(pin: [u8; 32]) -> Self {
        Self {
            pin,
            algs: aws_lc_rs::default_provider().signature_verification_algorithms,
        }
    }
}

impl std::fmt::Debug for PinnedServerCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PinnedServerCert({})", hex::encode(self.pin))
    }
}

impl ServerCertVerifier for PinnedServerCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if cert_pin(end_entity) == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("Citadel: server certificate pin mismatch".into()))
        }
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, dss, &self.algs)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, dss, &self.algs)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// PoC-only верификатор: принимает любой серверный сертификат (демо про KX, не про доверие цепочке).
#[derive(Debug)]
pub struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Crypto-agility (M6): именованный выбор KX-suite и человекочитаемые имена.
    #[test]
    fn kx_suite_selection() {
        assert_eq!(kx_groups_for("pq").len(), 1);
        assert_eq!(kx_groups_for("classical").len(), 1);
        assert_eq!(kx_groups_for("all").len(), 2); // negotiate из двух групп
        assert_eq!(kx_groups_for("").len(), 1); // пусто → default pq
        assert_eq!(kx_groups_for("garbage").len(), 1); // неизвестное → default pq
        assert!(kx_suite_name("pq").contains("MLKEM"));
        assert!(kx_suite_name("classical").contains("X25519"));
        assert!(kx_suite_name("all").contains("negotiate"));
    }
}
