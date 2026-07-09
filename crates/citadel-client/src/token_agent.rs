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
pub async fn fetch_tokens(
    issuer: &str,
    client_seed: &[u8; 32],
    count: usize,
    retries: u32,
) -> Result<Vec<Vec<u8>>> {
    let issuer = issuer.to_string();
    let seed = *client_seed;
    tokio::task::spawn_blocking(move || citadel_token::fetch_tokens(&issuer, &seed, count, retries))
        .await
        .context("token-fetch задача паникнула")?
}

/// C5.4: авто-фетч для connect-flow. Если бандл/ссылка несут `issuer`+`client_seed` (Layer-1) —
/// добываем токен и вписываем в `config.token` (предъявится exit'у). Иначе возвращаем config как
/// есть (без Layer-1 — без токена; exit может отказать, если требует). Один токен на подключение.
pub async fn with_token(
    mut config: ClientConfig,
    issuer: Option<&str>,
    client_seed: Option<&[u8; 32]>,
) -> Result<ClientConfig> {
    if let (Some(issuer), Some(seed)) = (issuer, client_seed) {
        let mut tokens = fetch_tokens(issuer, seed, 1, 20).await?;
        if let Some(t) = tokens.pop() {
            config.token = t;
        }
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    /// Недоступный issuer → Err (обёртка не паникует и не виснет); 1 попытка → быстро.
    #[tokio::test]
    async fn unreachable_issuer_errs() {
        assert!(super::fetch_tokens("127.0.0.1:9", &[7u8; 32], 1, 1).await.is_err());
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
            client_seed: None,
            routes: String::new(),
            dns: None,
        }
        .to_client_config();
        let out = super::with_token(cfg, None, None).await.unwrap();
        assert!(out.token.is_empty());
    }
}
