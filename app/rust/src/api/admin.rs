//! Мост GUI → Admin-режим: управление развёрнутым сервером по SSH.
//!
//! Пока — управление Layer-1 реестром абонентов (C5.5) поверх `citadel_client::AdminDeployer`
//! (russh) и серверного CLI `citadel-token registry`. Каждая операция самодостаточна:
//! SSH `connect → op → close` за один вызов; сессия между вызовами НЕ удерживается.
//!
//! Аутентификация: пароль ИЛИ приватный SSH-ключ (`AdminConn.key_path` не пуст → key-auth; ключ
//! читается в ядре из файла, в Dart-память не попадает).
//!
//! Admin — **десктоп-функция** (russh/`AdminDeployer` не тянется в мобильный APK). FFI-функции
//! присутствуют на всех платформах (иначе безусловные ссылки из `frb_generated.rs` сломали бы
//! мобильную сборку), но бэкенд cfg-переключается: на мобилке — заглушка-отказ.
//! Host-key: TOFU accept-first-use (persistent-пиннинг фингерпринта — follow-up хардненинга).

use anyhow::Result;

/// Параметры SSH-подключения к серверу для Admin-операций.
pub struct AdminConn {
    pub host: String,
    pub port: u16,
    pub user: String,
    /// Пароль (используется, если `key_path` пуст).
    pub password: String,
    /// Путь к приватному SSH-ключу (OpenSSH-PEM). Не пуст → key-auth вместо пароля. Ключ читается
    /// в ядре, в Dart не передаётся.
    pub key_path: String,
    /// Passphrase ключа (пусто → без passphrase).
    pub key_passphrase: String,
}

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
pub async fn admin_registry_list(conn: AdminConn) -> Result<Vec<RegistryEntryDto>> {
    backend::list(conn).await
}

/// Зарегистрировать абонента. `client_id` — Ed25519 pub (64 hex). `valid_until` — `+<N>d`/`+<N>h`/
/// unix-секунды или пусто (дефолт +365d на сервере). Ввод валидируется в ядре (анти-инъекция).
pub async fn admin_registry_add(
    conn: AdminConn,
    client_id: String,
    valid_until: String,
) -> Result<()> {
    backend::add(conn, client_id, valid_until).await
}

/// Отозвать абонента по `client_id` (status=revoked; действует ≤ длины эпохи).
pub async fn admin_registry_revoke(conn: AdminConn, client_id: String) -> Result<()> {
    backend::revoke(conn, client_id).await
}

// ─────────── Десктоп-бэкенд: реальный SSH через AdminDeployer ───────────
#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod backend {
    use super::{AdminConn, RegistryEntryDto};
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

    async fn connect(c: &AdminConn) -> Result<AdminDeployer> {
        // key_path не пуст → key-auth (читаем PEM из файла в ядре); иначе пароль.
        let auth = if c.key_path.trim().is_empty() {
            SshAuth::Password(c.password.clone())
        } else {
            // раскрываем ~/ (std::fs тильду не понимает)
            let path = c.key_path.trim();
            let path = match path.strip_prefix("~/") {
                Some(rest) => std::env::var("HOME")
                    .map(|h| format!("{h}/{rest}"))
                    .unwrap_or_else(|_| path.to_string()),
                None => path.to_string(),
            };
            let pem = std::fs::read_to_string(&path)
                .with_context(|| format!("не прочитать SSH-ключ: {path}"))?;
            SshAuth::Key {
                private_pem: pem,
                passphrase: (!c.key_passphrase.is_empty()).then(|| c.key_passphrase.clone()),
            }
        };
        AdminDeployer::connect(&c.host, c.port, &c.user, auth, Box::new(MemoryTofu::new()))
            .await
            .context("SSH-подключение к серверу")
    }

    pub(super) async fn list(c: AdminConn) -> Result<Vec<RegistryEntryDto>> {
        let d = connect(&c).await?;
        let r = d.registry_list().await;
        let _ = d.close().await;
        Ok(r?.into_iter().map(RegistryEntryDto::from).collect())
    }

    pub(super) async fn add(c: AdminConn, client_id: String, valid_until: String) -> Result<()> {
        let d = connect(&c).await?;
        let vu = valid_until.trim();
        let r = d.registry_add(&client_id, if vu.is_empty() { None } else { Some(vu) }).await;
        let _ = d.close().await;
        r
    }

    pub(super) async fn revoke(c: AdminConn, client_id: String) -> Result<()> {
        let d = connect(&c).await?;
        let r = d.registry_revoke(&client_id).await;
        let _ = d.close().await;
        r
    }
}

// ─────────── Мобильный бэкенд: заглушка (Admin недоступен на телефоне) ───────────
#[cfg(any(target_os = "android", target_os = "ios"))]
mod backend {
    use super::{AdminConn, RegistryEntryDto};
    use anyhow::{bail, Result};

    fn na<T>() -> Result<T> {
        bail!("Admin-режим (SSH-управление сервером) доступен только на десктопе")
    }

    pub(super) async fn list(_: AdminConn) -> Result<Vec<RegistryEntryDto>> {
        na()
    }
    pub(super) async fn add(_: AdminConn, _: String, _: String) -> Result<()> {
        na()
    }
    pub(super) async fn revoke(_: AdminConn, _: String) -> Result<()> {
        na()
    }
}
