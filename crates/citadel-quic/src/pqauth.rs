//! M7 — PQ-аутентификация: гибрид Ed25519 (TLS-сертификат + pinning, F1) + **ML-DSA-65**
//! (FIPS 204, aws-lc-rs). Сервер держит ML-DSA-65 keypair и публикует pk (провижининг, рядом с
//! pin). На control-стриме сервер подписывает привязку `DOMAIN ‖ nonce ‖ cert_pin`, клиент проверяет
//! её под известным pk → PQ-доказательство подлинности сервера, привязанное к TLS-сессии (`cert_pin`)
//! и свежее (`nonce`). CRQC не подделает ML-DSA-подпись ⇒ аутентификация устойчива даже к квантовому
//! MITM в реальном времени (классический Ed25519 один — нет; см. SPEC §3.2).

use anyhow::{anyhow, Result};
use aws_lc_rs::signature::{KeyPair, UnparsedPublicKey};
use aws_lc_rs::unstable::signature::{PqdsaKeyPair, ML_DSA_65, ML_DSA_65_SIGNING};

const DOMAIN: &[u8] = b"CitadelPQVPN/pqauth/v1";

/// Сервер: ML-DSA-65 keypair. `sk` остаётся в процессе, `public_key()` публикуется клиентам.
pub struct ServerSigner {
    kp: PqdsaKeyPair,
}

impl ServerSigner {
    pub fn generate() -> Result<Self> {
        let kp = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).map_err(|_| anyhow!("ML-DSA-65 keygen"))?;
        Ok(Self { kp })
    }

    /// Публичный ключ (raw) для провижининга клиенту (≈1952 байта для ML-DSA-65).
    pub fn public_key(&self) -> Vec<u8> {
        self.kp.public_key().as_ref().to_vec()
    }

    /// Подписать привязку соединения: `ML-DSA(DOMAIN ‖ nonce ‖ cert_pin)`.
    pub fn sign_binding(&self, nonce: &[u8], cert_pin: &[u8; 32]) -> Result<Vec<u8>> {
        let msg = bind_msg(nonce, cert_pin);
        let mut sig = vec![0u8; self.kp.algorithm().signature_len()];
        let n = self.kp.sign(&msg, &mut sig).map_err(|_| anyhow!("ML-DSA sign"))?;
        sig.truncate(n);
        Ok(sig)
    }
}

/// Клиент: проверить ML-DSA-подпись привязки под известным (провижированным) pk сервера.
pub fn verify_binding(pk: &[u8], nonce: &[u8], cert_pin: &[u8; 32], sig: &[u8]) -> bool {
    UnparsedPublicKey::new(&ML_DSA_65, pk)
        .verify(&bind_msg(nonce, cert_pin), sig)
        .is_ok()
}

fn bind_msg(nonce: &[u8], cert_pin: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(DOMAIN.len() + nonce.len() + 32);
    m.extend_from_slice(DOMAIN);
    m.extend_from_slice(nonce);
    m.extend_from_slice(cert_pin);
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
        let sig = s.sign_binding(&nonce, &pin).unwrap();
        assert!(verify_binding(&pk, &nonce, &pin, &sig), "валидная подпись принимается");

        // подмена nonce / pin / pk / самой подписи → отказ
        assert!(!verify_binding(&pk, &[8u8; 32], &pin, &sig));
        assert!(!verify_binding(&pk, &nonce, &[0x43u8; 32], &sig));
        assert!(!verify_binding(&s2_pk(), &nonce, &pin, &sig));
        let mut bad = sig.clone();
        bad[100] ^= 1;
        assert!(!verify_binding(&pk, &nonce, &pin, &bad));
    }

    fn s2_pk() -> Vec<u8> {
        ServerSigner::generate().unwrap().public_key()
    }
}
