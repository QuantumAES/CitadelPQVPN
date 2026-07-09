//! CitadelPQVPN — анонимные токены на blind RSA (RFC 9474), стиль Privacy Pass.
//!
//! Свойство **unlinkability**: издатель подписывает *ослеплённое* сообщение и не видит
//! сам токен → даже если издатель и есть провайдер (exit), он не может связать выданный
//! токен с предъявленным при подключении. Закрывает приватностный риск A4 (SPEC §8, F-M4).
//!
//! Токен на проводе: `nonce(32) ‖ msg_randomizer(32) ‖ signature(|RSA|)`.
//!
//! Роли разделены (M5, issuer↔exit split): `client_blind`/`client_finalize` (клиент держит nonce
//! и секреты ослепления) ↔ `issuer_blind_sign` (издатель держит только sk, подписывает вслепую).
//! По сети ходят лишь `blind_msg` и `blind_sig`. `issue_batch` (всё в одном процессе) оставлен
//! для тестов/локального демо.

use anyhow::{anyhow, Result};
use blind_rsa_signatures::{
    BlindSignature, KeyPair, MessageRandomizer, Options, PublicKey, Secret, SecretKey, Signature,
};
use rand::RngCore;

pub const NONCE_LEN: usize = 32;
pub const RAND_LEN: usize = 32;

/// C5.1: номер текущей эпохи = unix-время / длина эпохи (сек). Токены Layer-2 скоупятся на эпоху —
/// exit проверяет их ТОЛЬКО ключом текущей (± прошлой, grace) эпохи, поэтому токен «гаснет» к концу
/// эпохи автоматически (отзыв по времени). Отзыв при компрометации — issuer перестаёт подписывать
/// такому клиенту, эффект ≤ длины эпохи. Требует слабой синхронизации часов issuer↔exit.
pub fn current_epoch(epoch_secs: u64) -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now / epoch_secs.max(1) // max(1): защита от деления на ноль при кривом конфиге
}

/// C5.1: имя файла pub издателя для эпохи. Issuer публикует `issuer-<epoch>.pub`; exit читает
/// current(±prev). Старые pub'ы остаются на диске для grace, но exit их уже не запрашивает.
pub fn epoch_pub_name(epoch: u64) -> String {
    format!("issuer-{epoch}.pub")
}

/// C5.1: проверить токен против нескольких pub'ов издателя (эпохи current±prev — grace на границе
/// эпохи и при скью часов issuer↔exit). Возвращает nonce при успехе под ЛЮБЫМ pub; иначе None.
pub fn verify_token_multi(pubs: &[Vec<u8>], token: &[u8]) -> Option<[u8; NONCE_LEN]> {
    pubs.iter().find_map(|pk| verify_token(pk, token))
}

// ===================== Layer-1 «абонемент» (C5.2): Ed25519 client-id =====================
// Клиент держит 32-байтный seed (= приватный Ed25519); его pub — client_id в реестре issuer'а.
// Issuer шлёт челлендж, клиент подписывает, issuer проверяет подпись + запись реестра
// (valid_until/status) ДО слепой подписи токенов. Отзыв: status=revoked (≤ длины эпохи) + expiry.

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _, UnparsedPublicKey, ED25519};

/// Ed25519 pub из 32-байтного client-seed (детерминированно; seed = приватный ключ «абонента»).
pub fn ed25519_pub_from_seed(seed: &[u8; 32]) -> Result<[u8; 32]> {
    let kp = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| anyhow!("ed25519 seed"))?;
    kp.public_key().as_ref().try_into().map_err(|_| anyhow!("ed25519 pub len"))
}

/// Подписать сообщение (челлендж issuer'а) client-seed'ом.
pub fn ed25519_sign(seed: &[u8; 32], msg: &[u8]) -> Result<[u8; 64]> {
    let kp = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| anyhow!("ed25519 seed"))?;
    kp.sign(msg).as_ref().try_into().map_err(|_| anyhow!("ed25519 sig len"))
}

/// Проверить подпись челленджа под pub'ом (issuer-сторона Layer-1).
pub fn ed25519_verify(pub_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    UnparsedPublicKey::new(&ED25519, pub_key).verify(msg, sig).is_ok()
}

// ===================== интерактивный issuance по ролям (M5, issuer↔exit split) =====================
// Разделение: КЛИЕНТ держит nonce + секреты ослепления и делает finalize; ИЗДАТЕЛЬ держит только
// секретный ключ и подписывает ослеплённое сообщение ВСЛЕПУЮ (не видит nonce/токен) → unlinkability,
// даже если издатель (биллинг) и exit сговорятся. По сети ходят только blind_msg и blind_sig.

/// Сгенерировать ключевую пару издателя → (pk_der, sk_der). pk публикуется (exit-верификатор),
/// sk держит только издатель.
pub fn issuer_keypair(bits: usize) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = rand::thread_rng();
    let kp = KeyPair::generate(&mut rng, bits)?;
    Ok((kp.pk.to_der()?, kp.sk.to_der()?))
}

/// Состояние клиента между blind и finalize (секреты ослепления; НЕ покидает клиента).
pub struct BlindState {
    nonce: [u8; NONCE_LEN],
    secret: Secret,
    randomizer: MessageRandomizer,
}

/// Роль клиента (шаг 1): сгенерировать nonce + ослеплённое сообщение для издателя.
/// Возвращает (`blind_msg` на отправку издателю, состояние для finalize). Издатель nonce НЕ увидит.
pub fn client_blind(pk_der: &[u8]) -> Result<(Vec<u8>, BlindState)> {
    let opts = Options::default();
    let pk = PublicKey::from_der(pk_der)?;
    let mut rng = rand::thread_rng();
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let br = pk.blind(&mut rng, nonce, true, &opts)?;
    let randomizer = br.msg_randomizer.ok_or_else(|| anyhow!("нет msg_randomizer"))?;
    Ok((br.blind_msg.0, BlindState { nonce, secret: br.secret, randomizer }))
}

/// Роль издателя: подписать ослеплённое сообщение ВСЛЕПУЮ. Видит только `blind_msg`, не токен.
pub fn issuer_blind_sign(sk_der: &[u8], blind_msg: &[u8]) -> Result<Vec<u8>> {
    let opts = Options::default();
    let sk = SecretKey::from_der(sk_der)?;
    let mut rng = rand::thread_rng();
    Ok(sk.blind_sign(&mut rng, blind_msg, &opts)?.0)
}

/// Роль клиента (шаг 2): снять ослепление → готовый токен `nonce‖randomizer‖sig`.
pub fn client_finalize(pk_der: &[u8], blind_sig: &[u8], st: &BlindState) -> Result<Vec<u8>> {
    let opts = Options::default();
    let pk = PublicKey::from_der(pk_der)?;
    let sig = pk.finalize(
        &BlindSignature(blind_sig.to_vec()),
        &st.secret,
        Some(st.randomizer),
        st.nonce,
        &opts,
    )?;
    let mut t = Vec::with_capacity(NONCE_LEN + RAND_LEN + sig.len());
    t.extend_from_slice(&st.nonce);
    t.extend_from_slice(st.randomizer.as_ref());
    t.extend_from_slice(&sig);
    Ok(t)
}

pub struct Issued {
    pub pk_der: Vec<u8>,
    pub tokens: Vec<Vec<u8>>,
}

/// Выпуск `count` токенов и публичного ключа издателя (DER).
pub fn issue_batch(count: usize, bits: usize) -> Result<Issued> {
    let opts = Options::default();
    let mut rng = rand::thread_rng();
    let kp = KeyPair::generate(&mut rng, bits)?;
    let mut tokens = Vec::with_capacity(count);
    for _ in 0..count {
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        // blinding (роль клиента): издатель не увидит nonce
        let br = kp.pk.blind(&mut rng, nonce, true, &opts)?;
        // signing (роль издателя): видит только br.blind_msg
        let blind_sig = kp.sk.blind_sign(&mut rng, &br.blind_msg, &opts)?;
        // finalize (роль клиента): получаем готовую подпись
        let sig = kp.pk.finalize(&blind_sig, &br.secret, br.msg_randomizer, nonce, &opts)?;
        let randomizer = br.msg_randomizer.ok_or_else(|| anyhow!("нет msg_randomizer"))?;
        let mut t = Vec::with_capacity(NONCE_LEN + RAND_LEN + sig.len());
        t.extend_from_slice(&nonce);
        t.extend_from_slice(randomizer.as_ref());
        t.extend_from_slice(&sig);
        tokens.push(t);
    }
    Ok(Issued { pk_der: kp.pk.to_der()?, tokens })
}

/// Проверка токена под публичным ключом издателя. Возвращает nonce (для учёта double-spend).
pub fn verify_token(pk_der: &[u8], token: &[u8]) -> Option<[u8; NONCE_LEN]> {
    if token.len() <= NONCE_LEN + RAND_LEN {
        return None;
    }
    let opts = Options::default();
    let pk = PublicKey::from_der(pk_der).ok()?;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&token[..NONCE_LEN]);
    let mut rand = [0u8; RAND_LEN];
    rand.copy_from_slice(&token[NONCE_LEN..NONCE_LEN + RAND_LEN]);
    let sig = Signature::new(token[NONCE_LEN + RAND_LEN..].to_vec());
    let mr = MessageRandomizer::new(rand);
    sig.verify(&pk, Some(mr), nonce, &opts).ok()?;
    Some(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_layer1_roundtrip() {
        let seed = [0x11u8; 32];
        let pk = ed25519_pub_from_seed(&seed).unwrap();
        let msg = b"issuer-challenge-nonce";
        let sig = ed25519_sign(&seed, msg).unwrap();
        assert!(ed25519_verify(&pk, msg, &sig)); // валидная подпись
        assert!(!ed25519_verify(&pk, b"other", &sig)); // чужое сообщение
        assert!(!ed25519_verify(&ed25519_pub_from_seed(&[0x22u8; 32]).unwrap(), msg, &sig)); // чужой pub
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(!ed25519_verify(&pk, msg, &bad)); // подделанная подпись
        assert_eq!(pk, ed25519_pub_from_seed(&seed).unwrap()); // детерминизм seed→pub
    }

    #[test]
    fn epoch_basics() {
        assert!(current_epoch(3600) > 0); // после 1970 эпоха положительна
        assert_eq!(current_epoch(u64::MAX), 0); // эпоха длиннее возраста unix → 0
        let _ = current_epoch(0); // div-by-zero защита (max(1)) — не паникует
    }

    /// C5.1/M6: токен эпохи A НЕ принимается ключом эпохи B (epoch-scoping = отзыв по времени);
    /// проходит под своим ключом и в grace-наборе [prev, cur].
    #[test]
    fn epoch_scoping_cross_key_rejected() {
        let a = issue_batch(1, 2048).unwrap();
        let b = issue_batch(1, 2048).unwrap();
        let tok = &a.tokens[0];
        assert!(verify_token(&b.pk_der, tok).is_none(), "ключ чужой эпохи не должен принять");
        assert!(verify_token(&a.pk_der, tok).is_some());
        assert!(verify_token_multi(std::slice::from_ref(&b.pk_der), tok).is_none());
        assert!(verify_token_multi(&[b.pk_der.clone(), a.pk_der.clone()], tok).is_some()); // grace prev+cur
        assert!(verify_token_multi(&[], tok).is_none());
    }

    #[test]
    fn issue_and_verify() {
        let issued = issue_batch(3, 2048).unwrap();
        assert_eq!(issued.tokens.len(), 3);
        // все валидны, nonce различны
        let mut seen = std::collections::HashSet::new();
        for t in &issued.tokens {
            let nonce = verify_token(&issued.pk_der, t).expect("валидный токен");
            assert!(seen.insert(nonce), "nonce должны быть уникальны");
        }
    }

    #[test]
    fn tampered_token_rejected() {
        let issued = issue_batch(1, 2048).unwrap();
        let mut t = issued.tokens[0].clone();
        let last = t.len() - 1;
        t[last] ^= 0x01; // портим подпись
        assert!(verify_token(&issued.pk_der, &t).is_none());
    }

    #[test]
    fn forged_token_rejected() {
        let issued = issue_batch(1, 2048).unwrap();
        let forged = vec![0x42u8; NONCE_LEN + RAND_LEN + 256];
        assert!(verify_token(&issued.pk_der, &forged).is_none());
    }

    /// M5 split: клиент (blind→finalize) ↔ издатель (только blind_sign) → валидный токен.
    /// Издатель видит лишь blind_msg; по сети ходят только blind_msg и blind_sig.
    #[test]
    fn split_issuance_roundtrip() {
        let (pk, sk) = issuer_keypair(2048).unwrap();
        let (blind_msg, st) = client_blind(&pk).unwrap(); // клиент
        let blind_sig = issuer_blind_sign(&sk, &blind_msg).unwrap(); // издатель (вслепую)
        let token = client_finalize(&pk, &blind_sig, &st).unwrap(); // клиент
        let nonce = verify_token(&pk, &token).expect("split-токен валиден"); // exit
        // защита от подделки: blind_sig под другим ключом не финализируется в валидный токен
        let (pk2, sk2) = issuer_keypair(2048).unwrap();
        let (bm2, st2) = client_blind(&pk2).unwrap();
        let bsig2 = issuer_blind_sign(&sk2, &bm2).unwrap();
        let tok2 = client_finalize(&pk2, &bsig2, &st2).unwrap();
        assert_ne!(nonce, verify_token(&pk2, &tok2).unwrap(), "nonce разных токенов различны");
        assert!(verify_token(&pk, &tok2).is_none(), "токен чужого издателя отвергнут");
    }

    // robustness/fuzz (M6): verify_token не паникует ни на каком токене/ключе (анти-DoS на malformed).
    fn xs(seed: &mut u64) -> u64 {
        let mut x = *seed;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *seed = x;
        x
    }

    #[test]
    fn fuzz_verify_token_no_panic() {
        let issued = issue_batch(1, 2048).unwrap();
        let pk = &issued.pk_der;
        let valid = &issued.tokens[0];
        let mut s = 0xfeed_face_dead_c0deu64;
        // случайные токены под валидным ключом (RSA-verify в debug медленный → умеренно итераций)
        for _ in 0..1_000 {
            let len = (xs(&mut s) % 600) as usize;
            let b: Vec<u8> = (0..len).map(|_| (xs(&mut s) >> 33) as u8).collect();
            assert!(verify_token(pk, &b).is_none() || !b.is_empty()); // главное — без паники
        }
        // mutated валидный токен (флип байта)
        for _ in 0..1_000 {
            let mut m = valid.clone();
            let i = (xs(&mut s) as usize) % m.len();
            m[i] ^= (xs(&mut s) as u8) | 1;
            let _ = verify_token(pk, &m);
        }
        // malformed pk_der тоже не должен ронять верификатор
        for _ in 0..300 {
            let len = (xs(&mut s) % 400) as usize;
            let bad_pk: Vec<u8> = (0..len).map(|_| (xs(&mut s) >> 33) as u8).collect();
            let _ = verify_token(&bad_pk, valid);
        }
    }
}
