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

#[cfg(test)]
mod tests {
    /// Недоступный issuer → Err (обёртка не паникует и не виснет); 1 попытка → быстро.
    #[tokio::test]
    async fn unreachable_issuer_errs() {
        assert!(super::fetch_tokens("127.0.0.1:9", &[7u8; 32], 1, 1).await.is_err());
    }
}
