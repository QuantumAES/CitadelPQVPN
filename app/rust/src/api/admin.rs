//! Мост GUI → Admin-режим: управление развёрнутым сервером по SSH.
//!
//! Пока — управление Layer-1 реестром абонентов (C5.5) поверх `citadel_client::AdminDeployer`
//! (russh) и серверного CLI `citadel-token registry`. Каждая операция самодостаточна:
//! SSH `connect → op → close` за один вызов; сессия между вызовами НЕ удерживается — так проще и
//! устойчивее к жизненному циклу async-рантайма frb. Dart-слой держит параметры Admin-сессии.
//!
//! Admin — **десктоп-функция** (russh/`AdminDeployer` не тянется в мобильный APK). FFI-функции
//! присутствуют на всех платформах (иначе безусловные ссылки из `frb_generated.rs` сломали бы
//! мобильную сборку), но их бэкенд cfg-переключается: на мобилке — заглушка-отказ.
//! Host-key: TOFU accept-first-use (persistent-пиннинг фингерпринта — follow-up хардненинга).

use anyhow::Result;

/// Запись Layer-1 реестра для Admin-UI.
pub struct RegistryEntryDto {
    /// client_id абонента (Ed25519 pub, 64 hex).
    pub client_id: String,
    /// Срок действия (unix-секунды).
    pub valid_until_unix: i64,
    /// Статус строки реестра как есть (`active`|`revoked`|…).
    pub status: String,
    /// Удобный флаг для UI: строка активна (`status == "active"`).
    pub active: bool,
}

// ─────────── FFI-поверхность (одинаковая на всех платформах; frb парсит эти сигнатуры) ───────────

/// Список абонентов реестра развёрнутого сервера (SSH → `citadel-token registry list`).
pub async fn admin_registry_list(
    host: String,
    port: u16,
    user: String,
    password: String,
) -> Result<Vec<RegistryEntryDto>> {
    backend::list(host, port, user, password).await
}

/// Зарегистрировать абонента. `client_id` — Ed25519 pub (64 hex). `valid_until` — `+<N>d`/`+<N>h`/
/// unix-секунды или пусто (дефолт +365d на сервере). Ввод валидируется в ядре (анти-инъекция).
pub async fn admin_registry_add(
    host: String,
    port: u16,
    user: String,
    password: String,
    client_id: String,
    valid_until: String,
) -> Result<()> {
    backend::add(host, port, user, password, client_id, valid_until).await
}

/// Отозвать абонента по `client_id` (status=revoked; действует ≤ длины эпохи).
pub async fn admin_registry_revoke(
    host: String,
    port: u16,
    user: String,
    password: String,
    client_id: String,
) -> Result<()> {
    backend::revoke(host, port, user, password, client_id).await
}

// ─────────── Десктоп-бэкенд: реальный SSH через AdminDeployer ───────────
#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod backend {
    use super::RegistryEntryDto;
    use anyhow::{Context, Result};
    use citadel_client::{AdminDeployer, MemoryTofu, RegistryEntry, SshAuth};

    impl From<RegistryEntry> for RegistryEntryDto {
        fn from(e: RegistryEntry) -> Self {
            Self {
                active: e.status == "active",
                client_id: e.client_id,
                valid_until_unix: e.valid_until as i64,
                status: e.status,
            }
        }
    }

    async fn connect(host: &str, port: u16, user: &str, password: &str) -> Result<AdminDeployer> {
        AdminDeployer::connect(
            host,
            port,
            user,
            SshAuth::Password(password.to_string()),
            Box::new(MemoryTofu::new()), // TOFU: принять host-key при первом коннекте (см. модульный док)
        )
        .await
        .context("SSH-подключение к серверу")
    }

    pub(super) async fn list(
        host: String,
        port: u16,
        user: String,
        password: String,
    ) -> Result<Vec<RegistryEntryDto>> {
        let d = connect(&host, port, &user, &password).await?;
        let r = d.registry_list().await;
        let _ = d.close().await;
        Ok(r?.into_iter().map(RegistryEntryDto::from).collect())
    }

    pub(super) async fn add(
        host: String,
        port: u16,
        user: String,
        password: String,
        client_id: String,
        valid_until: String,
    ) -> Result<()> {
        let d = connect(&host, port, &user, &password).await?;
        let vu = valid_until.trim();
        let r = d.registry_add(&client_id, if vu.is_empty() { None } else { Some(vu) }).await;
        let _ = d.close().await;
        r
    }

    pub(super) async fn revoke(
        host: String,
        port: u16,
        user: String,
        password: String,
        client_id: String,
    ) -> Result<()> {
        let d = connect(&host, port, &user, &password).await?;
        let r = d.registry_revoke(&client_id).await;
        let _ = d.close().await;
        r
    }
}

// ─────────── Мобильный бэкенд: заглушка (Admin недоступен на телефоне) ───────────
#[cfg(any(target_os = "android", target_os = "ios"))]
mod backend {
    use super::RegistryEntryDto;
    use anyhow::{bail, Result};

    fn na<T>() -> Result<T> {
        bail!("Admin-режим (SSH-управление сервером) доступен только на десктопе")
    }

    pub(super) async fn list(_: String, _: u16, _: String, _: String) -> Result<Vec<RegistryEntryDto>> {
        na()
    }
    pub(super) async fn add(_: String, _: u16, _: String, _: String, _: String, _: String) -> Result<()> {
        na()
    }
    pub(super) async fn revoke(_: String, _: u16, _: String, _: String, _: String) -> Result<()> {
        na()
    }
}
