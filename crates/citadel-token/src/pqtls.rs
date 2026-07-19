//! S2.1/A1 — защищённый канал к издателю: синхронный **rustls TLS 1.3** с гибридной PQ-группой
//! (`X25519MLKEM768`) и **пиннингом серта издателя** (BLAKE3(DER), как у exit — F1).
//!
//! Закрывает A1 (голый TCP issuer, аудит-2): раньше Layer-1 challenge-response и слепая выдача шли
//! по plaintext TCP → (a) активный MITM пропускал Layer-1 клиента и подставлял свои `blind_msg`
//! (кража токенов под чужой подпиской), (b) `client_id` (Ed25519 pub «абонемента») светился →
//! деанон подписчика, (c) издатель не аутентифицировался → импёрсонация. TLS 1.3 закрывает (a)/(b)
//! (целостность+конфиденциальность), pinning закрывает (c) (клиент верит только серту из ссылки).
//! Гибридная PQ-группа даёт анти-HNDL и для этого канала.
//!
//! Синхронный (`StreamOwned`): и издатель (std::net + потоки), и `fetch_tokens` работают блокирующе;
//! `read_frame`/`write_frame` дженерик по `Read`/`Write`, поэтому поверх TLS-потока — без изменений.

use std::net::TcpStream;
use std::sync::Arc;

use crate::obfs_stream::ObfsMaybe;

use anyhow::{anyhow, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::aws_lc_rs;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{
    ClientConnection, DigitallySignedStruct, ServerConfig, ServerConnection, SignatureScheme,
    StreamOwned,
};

/// ALPN канала издателя (отделяет от туннеля, помогает мультиплексировать/файрволить).
const ALPN: &[u8] = b"citadel-issuer/1";
/// SNI фиксирован (сервер пиннится → имя не проверяется, но `ClientConnection` требует `ServerName`).
const SERVER_NAME: &str = "citadel.issuer";

/// TLS-поток издателя (сервер) / клиента. Нижний транспорт — [`ObfsMaybe`]: голый TCP или obfs
/// поверх TCP (probe-resistance, S2.1/A1-остаток). Downstream (admin/EKM) ссылается через эти alias
/// и от выбора транспорта не зависит.
pub type IssuerTlsStream = StreamOwned<ServerConnection, ObfsMaybe>;
pub type ClientTlsStream = StreamOwned<ClientConnection, ObfsMaybe>;

/// Крипто-провайдер с ЕДИНСТВЕННОЙ гибридной PQ-группой (`X25519MLKEM768`, тот же codepoint, что и
/// в движке): классический X25519 не согласуется ⇒ канал издателя тоже пост-квантовый (анти-HNDL).
fn provider() -> Arc<CryptoProvider> {
    let mut p = aws_lc_rs::default_provider();
    p.kx_groups = vec![aws_lc_rs::kx_group::X25519MLKEM768];
    Arc::new(p)
}

/// Pin серта = BLAKE3(DER) — та же схема пиннинга, что у exit (F1, `citadel_quic::cert_pin`).
pub fn cert_pin(cert: &CertificateDer<'_>) -> [u8; 32] {
    blake3::hash(cert.as_ref()).into()
}

/// Self-signed Ed25519-серт издателя (как `citadel_quic::self_signed_ed25519`).
fn self_signed() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let cert = rcgen::CertificateParams::new(vec![SERVER_NAME.to_string()])?.self_signed(&key)?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    Ok((cert_der, key_der))
}

/// Постоянная идентичность издателя. `pin` кладётся в `citadel://`-ссылку (клиент пиннит канал).
pub struct IssuerIdentity {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    pub pin: [u8; 32],
}

impl IssuerIdentity {
    /// Загрузить постоянный серт из `dir` (`issuer-tls.crt`/`.key`) или сгенерировать и сохранить.
    /// **Стабильная идентичность** переживает рестарт контейнера → pin в розданных ссылках остаётся
    /// валиден (иначе каждый рестарт ломал бы клиентов, ср. A7). Публикует `issuer-tls.pin` (hex).
    pub fn load_or_generate(dir: &str) -> Result<Self> {
        let crt_path = format!("{dir}/issuer-tls.crt");
        let key_path = format!("{dir}/issuer-tls.key");
        let (cert, key) = match (std::fs::read(&crt_path), std::fs::read(&key_path)) {
            (Ok(c), Ok(k)) if !c.is_empty() && !k.is_empty() => (
                CertificateDer::from(c),
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(k)),
            ),
            _ => {
                let (c, k) = self_signed()?;
                std::fs::write(&crt_path, c.as_ref()).with_context(|| format!("запись {crt_path}"))?;
                std::fs::write(&key_path, k.secret_der()).with_context(|| format!("запись {key_path}"))?;
                // TLS-приватник — секрет (как obfs.psk/client.seed): 600, не покидает сервер.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
                }
                (c, k)
            }
        };
        let pin = cert_pin(&cert);
        std::fs::write(format!("{dir}/issuer-tls.pin"), hex::encode(pin))
            .context("публикация issuer-tls.pin")?;
        Ok(Self { cert, key, pin })
    }

    /// Собрать `ServerConfig` (клонируется на каждое соединение).
    pub fn server_config(&self) -> Result<Arc<ServerConfig>> {
        let mut cfg = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(vec![self.cert.clone()], self.key.clone_key())?;
        cfg.alpn_protocols = vec![ALPN.to_vec()];
        Ok(Arc::new(cfg))
    }
}

/// Издатель: обернуть accept'нутый TCP в TLS-сервер. Хендшейк ленивый (на первом read/write кадра).
/// `obfs_psk`: `Some` → под TLS кладём obfs-слой (probe-resistance, S2.1/A1-остаток — issuer-порт
/// молчит на не-obfs пробу и неотличим от туннеля); `None` → голый TLS. Клиент должен совпадать по
/// наличию psk (иначе `open` первого record падает → разрыв, fail-closed).
pub fn accept_tls(
    tcp: TcpStream,
    cfg: Arc<ServerConfig>,
    obfs_psk: Option<[u8; 32]>,
) -> Result<IssuerTlsStream> {
    let conn = ServerConnection::new(cfg).map_err(|e| anyhow!("TLS ServerConnection: {e}"))?;
    Ok(StreamOwned::new(conn, ObfsMaybe::wrap(tcp, obfs_psk)))
}

/// Клиент: обернуть установленный TCP в TLS-клиент, **пиннящий** серт издателя. Хендшейк ленивый;
/// несовпадение pin (MITM/подмена) → ошибка на первом кадре (fail-closed). `obfs_psk` — см.
/// [`accept_tls`] (должен совпадать с серверным).
pub fn connect_tls(tcp: TcpStream, pin: [u8; 32], obfs_psk: Option<[u8; 32]>) -> Result<ClientTlsStream> {
    let cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedIssuerCert::new(pin)))
        .with_no_client_auth();
    let mut cfg = cfg;
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    let name = ServerName::try_from(SERVER_NAME)?.to_owned();
    let conn = ClientConnection::new(Arc::new(cfg), name)
        .map_err(|e| anyhow!("TLS ClientConnection: {e}"))?;
    Ok(StreamOwned::new(conn, ObfsMaybe::wrap(tcp, obfs_psk)))
}

/// Верификатор с пиннингом: сверяет pin серта И проверяет подпись хендшейка штатными алгоритмами
/// (без последнего pin публичного ключа не защищал бы от MITM). Копия `citadel_quic::PinnedServerCert`
/// (крейт citadel-token не может зависеть от citadel-quic — обратная зависимость в графе).
#[derive(Debug)]
struct PinnedIssuerCert {
    pin: [u8; 32],
    algs: WebPkiSupportedAlgorithms,
}

impl PinnedIssuerCert {
    fn new(pin: [u8; 32]) -> Self {
        Self { pin, algs: aws_lc_rs::default_provider().signature_verification_algorithms }
    }
}

impl ServerCertVerifier for PinnedIssuerCert {
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
            Err(rustls::Error::General("citadel-issuer: pin mismatch (MITM?)".into()))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{read_frame, write_frame};
    use std::net::TcpListener;

    /// PQ-TLS канал издателя: рамочный обмен поверх TLS 1.3 (гибрид) с корректным pin проходит;
    /// подменённый pin (MITM с другим сертом) — отказ на хендшейке (fail-closed). Прогоняем в обоих
    /// режимах транспорта: голый TLS и obfs-обёрнутый (S2.1/A1-остаток), формат кадров тот же.
    fn pqtls_roundtrip_and_pin_enforced_impl(obfs_psk: Option<[u8; 32]>) {
        let dir = std::env::temp_dir()
            .join(format!("citadel-pqtls-{}-{}", std::process::id(), obfs_psk.is_some() as u8));
        std::fs::create_dir_all(&dir).unwrap();
        let dir = dir.to_str().unwrap();
        let id = IssuerIdentity::load_or_generate(dir).unwrap();
        let good_pin = id.pin;
        let scfg = id.server_config().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = std::thread::spawn(move || {
            // два соединения: (1) с верным pin, (2) с чужим pin (MITM)
            for _ in 0..2 {
                let (tcp, _) = listener.accept().unwrap();
                let scfg = scfg.clone();
                std::thread::spawn(move || {
                    if let Ok(mut tls) = accept_tls(tcp, scfg, obfs_psk) {
                        // хендшейк с чужим pin оборвётся здесь (write/handshake → Err) — это ок
                        if write_frame(&mut tls, b"challenge-ok").is_ok() {
                            let _ = read_frame(&mut tls);
                        }
                    }
                });
            }
        });

        // (1) верный pin — обмен проходит
        let tcp = TcpStream::connect(addr).unwrap();
        let mut tls = connect_tls(tcp, good_pin, obfs_psk).unwrap();
        let got = read_frame(&mut tls).unwrap();
        assert_eq!(got, b"challenge-ok");
        write_frame(&mut tls, b"pub-and-sig").unwrap();

        // (2) чужой pin — хендшейк должен провалиться (pin mismatch), кадр не прочитается
        let tcp = TcpStream::connect(addr).unwrap();
        let mut tls = connect_tls(tcp, [0xFFu8; 32], obfs_psk).unwrap();
        assert!(read_frame(&mut tls).is_err(), "MITM/чужой pin → отказ (fail-closed)");

        srv.join().unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn pqtls_roundtrip_and_pin_enforced() {
        pqtls_roundtrip_and_pin_enforced_impl(None); // голый TLS
    }

    /// S2.1/A1-остаток: тот же обмен/пиннинг работает и с obfs-обёрнутым каналом (probe-resistance).
    #[test]
    fn pqtls_over_obfs_roundtrip_and_pin_enforced() {
        pqtls_roundtrip_and_pin_enforced_impl(Some([0x5a; 32]));
    }

    /// Идентичность издателя ПОСТОЯННА: повторный `load_or_generate` из того же каталога даёт тот же
    /// pin (переживает рестарт → розданные ссылки не ломаются).
    #[test]
    fn identity_is_persistent() {
        let dir = std::env::temp_dir().join(format!("citadel-pqtls-persist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dir = dir.to_str().unwrap();
        let a = IssuerIdentity::load_or_generate(dir).unwrap().pin;
        let b = IssuerIdentity::load_or_generate(dir).unwrap().pin;
        assert_eq!(a, b, "pin стабилен между запусками");
        let _ = std::fs::remove_dir_all(dir);
    }
}
