//! M7 — PQ-аутентификация: гибрид Ed25519 (TLS-сертификат + pinning, F1) + **ML-DSA-65**
//! (FIPS 204, aws-lc-rs). Сервер держит ML-DSA-65 keypair и публикует pk (провижининг, рядом с
//! pin). На control-стриме сервер подписывает привязку `DOMAIN ‖ nonce ‖ cert_pin ‖ tls_exporter`,
//! клиент проверяет её под известным pk → PQ-доказательство подлинности сервера. CRQC не подделает
//! ML-DSA-подпись ⇒ аутентификация устойчива даже к квантовому MITM в реальном времени (классический
//! Ed25519 один — нет; см. SPEC §3.2).
//!
//! S2.6/A3 (аудит-2): в привязку входит **TLS keying-material exporter** (RFC 5705) — он уникален
//! на КАЖДУЮ TLS-сессию. Раньше подписывался только `nonce ‖ cert_pin`, где cert_pin статичен, а
//! nonce пересылаем → relay-MITM (под CRQC, подделав Ed25519 CertVerify) мог ретранслировать
//! ML-DSA challenge/response между двумя TLS-сессиями. С экспортером у двух плеч MITM разные
//! значения ⇒ подпись сервера не проходит на клиенте (channel-binding закрывает relay).

use anyhow::{anyhow, Result};
use aws_lc_rs::signature::{KeyPair, UnparsedPublicKey};
use aws_lc_rs::unstable::signature::{PqdsaKeyPair, ML_DSA_65, ML_DSA_65_SIGNING};

/// Длина seed'а ML-DSA-65 (детерминированная генерация ключа из seed — для персистентности, A7).
pub const MLDSA_SEED_LEN: usize = 32;

const DOMAIN: &[u8] = b"CitadelPQVPN/pqauth/v1";

/// S2.6/A3: метка для `Connection::export_keying_material` (RFC 5705). Одна на обоих концах.
pub const EXPORTER_LABEL: &[u8] = b"CitadelPQVPN/pqauth/exporter/v1";
/// Длина выводимого экспортера (channel-binding).
pub const EXPORTER_LEN: usize = 32;

/// Сервер: ML-DSA-65 keypair. `sk` остаётся в процессе, `public_key()` публикуется клиентам.
pub struct ServerSigner {
    kp: PqdsaKeyPair,
}

impl ServerSigner {
    pub fn generate() -> Result<Self> {
        let kp = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).map_err(|_| anyhow!("ML-DSA-65 keygen"))?;
        Ok(Self { kp })
    }

    /// A7: детерминированно из 32-байтного seed (FIPS 204 seed→keypair). Персист seed'а (600 на
    /// диске) даёт СТАБИЛЬНЫЙ ML-DSA pub между рестартами → обязательство `H(pub)` в розданных
    /// ссылках не ломается (иначе каждый рестарт инвалидировал бы клиентов).
    pub fn from_seed(seed: &[u8; MLDSA_SEED_LEN]) -> Result<Self> {
        let kp = PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, seed)
            .map_err(|_| anyhow!("ML-DSA-65 from_seed"))?;
        Ok(Self { kp })
    }

    /// Публичный ключ (raw) для провижининга клиенту (≈1952 байта для ML-DSA-65).
    pub fn public_key(&self) -> Vec<u8> {
        self.kp.public_key().as_ref().to_vec()
    }

    /// Подписать привязку соединения: `ML-DSA(DOMAIN ‖ nonce ‖ cert_pin ‖ tls_exporter)`.
    /// `exporter` — TLS keying-material exporter соединения (S2.6/A3, channel-binding).
    pub fn sign_binding(&self, nonce: &[u8], cert_pin: &[u8; 32], exporter: &[u8]) -> Result<Vec<u8>> {
        let msg = bind_msg(nonce, cert_pin, exporter);
        let mut sig = vec![0u8; self.kp.algorithm().signature_len()];
        let n = self.kp.sign(&msg, &mut sig).map_err(|_| anyhow!("ML-DSA sign"))?;
        sig.truncate(n);
        Ok(sig)
    }
}

/// Клиент: проверить ML-DSA-подпись привязки под известным (провижированным) pk сервера.
/// `exporter` — TLS exporter соединения КЛИЕНТА; при relay-MITM он не совпадёт с серверным.
pub fn verify_binding(pk: &[u8], nonce: &[u8], cert_pin: &[u8; 32], exporter: &[u8], sig: &[u8]) -> bool {
    UnparsedPublicKey::new(&ML_DSA_65, pk)
        .verify(&bind_msg(nonce, cert_pin, exporter), sig)
        .is_ok()
}

fn bind_msg(nonce: &[u8], cert_pin: &[u8; 32], exporter: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(DOMAIN.len() + nonce.len() + 32 + exporter.len());
    m.extend_from_slice(DOMAIN);
    m.extend_from_slice(nonce);
    m.extend_from_slice(cert_pin);
    m.extend_from_slice(exporter);
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip_and_tamper() {
        let s = ServerSigner::generate().unwrap();
        let pk = s.public_key();
        let nonce = [7u8; 32];
        let pin = [0x42u8; 32];
        let exporter = [0x5cu8; 32];
        let sig = s.sign_binding(&nonce, &pin, &exporter).unwrap();
        assert!(verify_binding(&pk, &nonce, &pin, &exporter, &sig), "валидная подпись принимается");

        // подмена nonce / pin / exporter / pk / самой подписи → отказ
        assert!(!verify_binding(&pk, &[8u8; 32], &pin, &exporter, &sig));
        assert!(!verify_binding(&pk, &nonce, &[0x43u8; 32], &exporter, &sig));
        // S2.6/A3: чужой TLS exporter (другое плечо relay-MITM) → подпись не проходит
        assert!(!verify_binding(&pk, &nonce, &pin, &[0x5du8; 32], &sig));
        assert!(!verify_binding(&s2_pk(), &nonce, &pin, &exporter, &sig));
        let mut bad = sig.clone();
        bad[100] ^= 1;
        assert!(!verify_binding(&pk, &nonce, &pin, &exporter, &bad));
    }

    fn s2_pk() -> Vec<u8> {
        ServerSigner::generate().unwrap().public_key()
    }

    /// A7: `from_seed` детерминирован (тот же seed → тот же pub → стабильное H(pub) между рестартами);
    /// разный seed → разный pub; подпись от seed-ключа проверяется штатно.
    #[test]
    fn from_seed_deterministic_and_signs() {
        let seed = [0x11u8; MLDSA_SEED_LEN];
        let a = ServerSigner::from_seed(&seed).unwrap();
        let b = ServerSigner::from_seed(&seed).unwrap();
        assert_eq!(a.public_key(), b.public_key(), "seed→pub детерминирован (персист A7)");
        let (nonce, pin, exp) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let sig = a.sign_binding(&nonce, &pin, &exp).unwrap();
        assert!(verify_binding(&a.public_key(), &nonce, &pin, &exp, &sig));
        let other = ServerSigner::from_seed(&[0x22u8; MLDSA_SEED_LEN]).unwrap();
        assert_ne!(a.public_key(), other.public_key(), "разный seed → разный pub");
    }
}
