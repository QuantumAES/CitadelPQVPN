//! C5.3: `TokenAgent` — добыча анонимных epoch-токенов у issuer через Layer-1 «абонемент».
//!
//! GUI-клиент, имея бандл кред (`issuer` host:port + `client_seed`), получает N unlinkable
//! токенов ДО подключения к exit'у: `client_seed` (Ed25519) доказывает «абонемент» издателю
//! (Layer-1), издатель слепо подписывает epoch-токены (не видит их → unlinkability). Токены
//! кладутся в `ClientConfig.token` для предъявления exit'у (M4/M5).
//!
//! Протокол sync (std::net в `citadel_token::fetch_tokens`) — гоняем в `spawn_blocking`, чтобы не
//! блокировать движковый tokio-runtime (на мобилке блокирующий TCP → blocking-pool tokio).

use anyhow::{Context, Result};
use citadel_quic::config::ClientConfig;

/// Добыть `count` epoch-токенов у `issuer` (host:port), авторизуясь `client_seed`'ом (Layer-1).
/// `retries` — попытки коннекта (издатель мог ещё генерить RSA-ключ). Издатель токены НЕ видит.
/// S2.1/A1: канал к issuer'у — PQ-TLS с пиннингом (`issuer_pin`) → анти-MITM + скрытие client_id.
/// PQ: `issuer_mldsa` — обязательство к ML-DSA-идентичности издателя из ссылки; издатель обязан
/// доказать владение ею подписью привязки к сессии, иначе канал рвётся до отправки `client_id`.
pub async fn fetch_tokens(
    issuer: &str,
    issuer_pin: &[u8; 32],
    issuer_mldsa: &[u8; 32],
    client_seed: &[u8; 32],
    count: usize,
    retries: u32,
    obfs_psk: Option<[u8; 32]>,
) -> Result<citadel_token::Grant> {
    let issuer = issuer.to_string();
    let pin = *issuer_pin;
    let mldsa = *issuer_mldsa;
    let seed = *client_seed;
    tokio::task::spawn_blocking(move || {
        citadel_token::fetch_tokens(&issuer, &pin, &mldsa, &seed, count, retries, obfs_psk)
    })
    .await
    .context("token-fetch задача паникнула")?
}

/// C5.4: авто-фетч для connect-flow. Если бандл/ссылка несут `issuer`+`issuer_pin`+`client_seed`
/// (Layer-1) — добываем токен по PQ-TLS каналу и вписываем в `config.token` (предъявится exit'у).
/// Без issuer/seed → config как есть (без токена; exit может отказать). **issuer без pin — ошибка**
/// (S2.1/A1 fail-closed: голый канал к издателю недопустим). Один токен на подключение.
pub async fn with_token(
    mut config: ClientConfig,
    issuer: Option<&str>,
    issuer_pin: Option<&[u8; 32]>,
    issuer_mldsa: Option<&[u8; 32]>,
    client_seed: Option<&[u8; 32]>,
) -> Result<ClientConfig> {
    // нет issuer/seed → без токена (passthrough); есть issuer — pin и PQ-обязательство обязательны
    // (fail-closed).
    if let (Some(issuer), Some(seed)) = (issuer, client_seed) {
        let pin = issuer_pin.ok_or_else(|| {
            anyhow::anyhow!("issuer задан без issuer_pin — небезопасный канал (A1); ссылка устарела?")
        })?;
        let mldsa = issuer_mldsa.ok_or_else(|| {
            anyhow::anyhow!(
                "в ссылке нет PQ-обязательства издателя — канал держался бы на классической \
                 подписи серта; перевыпустите ссылку у администратора"
            )
        })?;
        // S2.1/A1-остаток: obfs-обёртка issuer-канала берётся из того же ClientConfig.obfs_psk,
        // что и туннель (probe-resistance; None → голый TLS для ссылок без obfs).
        let obfs_psk = config.obfs_psk;
        let mut grant = fetch_tokens(issuer, pin, mldsa, seed, 1, 20, obfs_psk).await?;
        if let Some(t) = grant.tokens.pop() {
            config.token = t;
        }
        // H-3: тем же заходом приезжает ключ L1 текущей эпохи для канала данных к exit'у.
        if grant.data_psk.is_some() {
            config.data_psk = grant.data_psk;
        }
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    /// Недоступный issuer → Err (обёртка не паникует и не виснет); 1 попытка → быстро.
    #[tokio::test]
    async fn unreachable_issuer_errs() {
        assert!(super::fetch_tokens("127.0.0.1:9", &[0u8; 32], &[1u8; 32], &[7u8; 32], 1, 1, None)
            .await
            .is_err());
    }

    /// C5.4: без issuer/seed `with_token` возвращает config без токена (passthrough, не виснет).
    #[tokio::test]
    async fn with_token_passthrough_without_layer1() {
        let cfg = crate::creds::CredentialBundle {
            version: crate::creds::BUNDLE_VERSION,
            servers: vec!["exit:4433".into()],
            server_name: "citadel.exit".into(),
            kx_suite: "pq".into(),
            cert_pin: None,
            mldsa_pub: None,
            obfs_psk: None,
            tcp_port: None,
            issuer: None,
            issuer_pub: None,
            issuer_pin: None,
            issuer_mldsa: Some([9u8; 32]),
            client_seed: None,
            admin_seed: None,
            admin_port: None,
            routes: String::new(),
            dns: None,
        }
        .to_client_config();
        let out = super::with_token(cfg, None, None, None, None).await.unwrap();
        assert!(out.token.is_empty());
    }

    /// Fail-closed на границе доверия к издателю: issuer задан, но нет pin (S2.1/A1) ЛИБО нет
    /// PQ-обязательства (`issuer_mldsa`) → `with_token` возвращает ошибку, а не молча идёт в
    /// небезопасный фетч.
    #[tokio::test]
    async fn with_token_requires_pin_and_pq_commitment_when_issuer_set() {
        let cfg = crate::creds::CredentialBundle {
            version: crate::creds::BUNDLE_VERSION,
            servers: vec!["exit:4433".into()],
            server_name: "citadel.exit".into(),
            kx_suite: "pq".into(),
            cert_pin: None,
            mldsa_pub: None,
            obfs_psk: None,
            tcp_port: None,
            issuer: Some("issuer:7000".into()),
            issuer_pub: None,
            issuer_pin: None,
            issuer_mldsa: Some([9u8; 32]),
            client_seed: None,
            admin_seed: None,
            admin_port: None,
            routes: String::new(),
            dns: None,
        }
        .to_client_config();
        let seed = [9u8; 32];
        // issuer без pin — отказ (A1)
        assert!(super::with_token(cfg.clone(), Some("issuer:7000"), None, Some(&[1u8; 32]), Some(&seed))
            .await
            .is_err());
        // issuer с pin, но БЕЗ PQ-обязательства издателя — тоже отказ (fail-closed, PQ-трек)
        assert!(super::with_token(cfg, Some("issuer:7000"), Some(&[2u8; 32]), None, Some(&seed))
            .await
            .is_err());
    }
}
