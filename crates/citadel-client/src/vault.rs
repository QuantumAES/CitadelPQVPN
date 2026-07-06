//! `citadel_client::vault` — зашифрованное хранилище профилей подключения (`SecretStore`).
//!
//! Несколько профилей (имя + `citadel://`-ссылка с pin/psk/seed) шифруются мастер-паролем
//! и лежат одним файлом. Крипта — в Rust-ядре (aws-lc-rs, та же библиотека, что и в движке;
//! кроссится под Android/iOS), НЕ в открытом виде и без зависимости от OS-keyring-демона.
//!
//! Формат файла (binary):
//! ```text
//! "CPQV" | ver(1) | iters(u32 BE) | salt(16) | nonce(12) | AES-256-GCM(ciphertext‖tag)
//! ```
//! Ключ = PBKDF2-HMAC-SHA256(passphrase, salt, iters) → 32 B. Открытый текст = CBOR(VaultData).
//! Неверный пароль → AEAD open не проходит → `open` возвращает ошибку (аутентификация AEAD =
//! проверка пароля, отдельный верификатор не нужен).

use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::pbkdf2;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::creds::CredentialLink;

const MAGIC: &[u8; 4] = b"CPQV";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
/// PBKDF2-HMAC-SHA256 итерации (OWASP-2023 ≥ 600k). Хранится в файле → можно поднять позже.
const KDF_ITERS: u32 = 600_000;
const HEADER_LEN: usize = 4 + 1 + 4 + SALT_LEN + NONCE_LEN; // magic+ver+iters+salt+nonce

/// Профиль подключения (один exit-сервер). `uri` несёт секреты (pin/psk/seed) — поэтому весь
/// vault шифруется.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// Стабильный id (для выбора/удаления из UI).
    pub id: String,
    /// Человекочитаемое имя профиля.
    pub name: String,
    /// `citadel://`-ссылка (валидируется при добавлении).
    pub uri: String,
    /// Когда добавлен (unix-секунды).
    pub created: u64,
    /// Последний exit, к которому реально подключались (для UI «недавние»).
    pub last_exit: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
struct VaultData {
    profiles: Vec<Profile>,
}

/// Разблокированное хранилище профилей. Держит производный ключ в памяти, пока открыто;
/// каждое изменение немедленно пере-шифровывает и атомарно пишет файл.
pub struct Vault {
    path: PathBuf,
    key: LessSafeKey,
    salt: [u8; SALT_LEN],
    iters: u32,
    data: VaultData,
}

impl Drop for Vault {
    /// S1.3/M7: при закрытии хранилища затираем расшифрованные профили (uri несёт pin/psk/seed).
    /// Производный ключ (`LessSafeKey`) чистит aws-lc-rs; `save` уже перезаписал plaintext шифртекстом.
    fn drop(&mut self) {
        for p in &mut self.data.profiles {
            p.uri.zeroize();
        }
    }
}

impl Vault {
    /// Существует ли файл хранилища (UI решает: разблокировать vs создать).
    pub fn exists(path: impl AsRef<Path>) -> bool {
        path.as_ref().is_file()
    }

    /// Создать новое пустое хранилище под мастер-паролем (перезаписывает существующее).
    pub fn create(path: impl AsRef<Path>, passphrase: &str) -> Result<Vault> {
        if passphrase.is_empty() {
            bail!("мастер-пароль не может быть пустым");
        }
        let rng = SystemRandom::new();
        let mut salt = [0u8; SALT_LEN];
        rng.fill(&mut salt).map_err(|_| anyhow!("RNG"))?;
        let key = derive_key(passphrase, &salt, KDF_ITERS)?;
        let v = Vault {
            path: path.as_ref().to_path_buf(),
            key,
            salt,
            iters: KDF_ITERS,
            data: VaultData::default(),
        };
        v.save()?;
        Ok(v)
    }

    /// Открыть существующее хранилище мастер-паролем. Неверный пароль → ошибка.
    pub fn open(path: impl AsRef<Path>, passphrase: &str) -> Result<Vault> {
        let path = path.as_ref().to_path_buf();
        let raw = std::fs::read(&path).with_context(|| format!("читать vault {}", path.display()))?;
        if raw.len() < HEADER_LEN || &raw[0..4] != MAGIC {
            bail!("повреждённый файл хранилища (не CitadelPQVPN vault)");
        }
        if raw[4] != VERSION {
            bail!("неподдерживаемая версия хранилища: {}", raw[4]);
        }
        let iters = u32::from_be_bytes(raw[5..9].try_into().unwrap());
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&raw[9..9 + SALT_LEN]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&raw[9 + SALT_LEN..HEADER_LEN]);

        let key = derive_key(passphrase, &salt, iters)?;
        let mut in_out = raw[HEADER_LEN..].to_vec();
        let plain = key
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut in_out)
            .map_err(|_| anyhow!("неверный мастер-пароль или повреждённое хранилище"))?;
        let data: VaultData =
            ciborium::from_reader(&plain[..]).context("разобрать профили (CBOR)")?;
        in_out.zeroize(); // S1.3/M7: затереть расшифрованный plaintext профилей (секреты)
        Ok(Vault { path, key, salt, iters, data })
    }

    /// Список профилей (копия для UI).
    pub fn list(&self) -> Vec<Profile> {
        self.data.profiles.clone()
    }

    /// Добавить профиль из `citadel://`-ссылки (валидируется). Возвращает созданный профиль.
    pub fn add(&mut self, name: &str, uri: &str) -> Result<Profile> {
        // валидность ссылки — до сохранения секрета (мусор в vault не кладём)
        CredentialLink::from_uri(uri).context("невалидная citadel://-ссылка")?;
        let name = name.trim();
        let p = Profile {
            id: random_id()?,
            name: if name.is_empty() { default_name(uri) } else { name.to_string() },
            uri: uri.to_string(),
            created: now_unix(),
            last_exit: None,
        };
        self.data.profiles.push(p.clone());
        self.save()?;
        Ok(p)
    }

    /// Удалить профиль по id.
    pub fn remove(&mut self, id: &str) -> Result<()> {
        let before = self.data.profiles.len();
        self.data.profiles.retain(|p| p.id != id);
        if self.data.profiles.len() == before {
            bail!("профиль не найден: {id}");
        }
        self.save()
    }

    /// Отметить exit последнего успешного подключения (UI «недавние»).
    pub fn set_last_exit(&mut self, id: &str, exit: &str) -> Result<()> {
        if let Some(p) = self.data.profiles.iter_mut().find(|p| p.id == id) {
            p.last_exit = Some(exit.to_string());
            self.save()?;
        }
        Ok(())
    }

    /// Сменить мастер-пароль (новый salt + перешифровка). Vault уже разблокирован — текущий
    /// пароль проверяется на уровне FFI повторным `open`.
    pub fn change_password(&mut self, new_passphrase: &str) -> Result<()> {
        if new_passphrase.is_empty() {
            bail!("новый мастер-пароль не может быть пустым");
        }
        let rng = SystemRandom::new();
        let mut salt = [0u8; SALT_LEN];
        rng.fill(&mut salt).map_err(|_| anyhow!("RNG"))?;
        self.key = derive_key(new_passphrase, &salt, KDF_ITERS)?;
        self.salt = salt;
        self.iters = KDF_ITERS;
        self.save()
    }

    /// Сериализовать + зашифровать + атомарно записать (temp → rename).
    fn save(&self) -> Result<()> {
        let mut plain = Vec::new();
        ciborium::into_writer(&self.data, &mut plain).context("сериализовать профили (CBOR)")?;

        let rng = SystemRandom::new();
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill(&mut nonce).map_err(|_| anyhow!("RNG"))?;

        let mut in_out = plain;
        self.key
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut in_out)
            .map_err(|_| anyhow!("шифрование AEAD"))?;

        let mut out = Vec::with_capacity(HEADER_LEN + in_out.len());
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.iters.to_be_bytes());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&in_out);

        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("создать {}", dir.display()))?;
        }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &out).with_context(|| format!("писать {}", tmp.display()))?;
        std::fs::rename(&tmp, &self.path).context("атомарно заменить vault")?;
        Ok(())
    }
}

/// PBKDF2-HMAC-SHA256(passphrase, salt, iters) → ключ AES-256-GCM.
fn derive_key(passphrase: &str, salt: &[u8], iters: u32) -> Result<LessSafeKey> {
    let iters = NonZeroU32::new(iters).ok_or_else(|| anyhow!("iters=0"))?;
    let mut key = [0u8; KEY_LEN];
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, iters, salt, passphrase.as_bytes(), &mut key);
    let unbound = UnboundKey::new(&AES_256_GCM, &key).map_err(|_| anyhow!("ключ AEAD"))?;
    key.zeroize(); // S1.3/M7: затереть сырой производный ключ (UnboundKey уже скопировал его)
    Ok(LessSafeKey::new(unbound))
}

fn random_id() -> Result<String> {
    let rng = SystemRandom::new();
    let mut b = [0u8; 8];
    rng.fill(&mut b).map_err(|_| anyhow!("RNG"))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Имя по умолчанию из первого хоста ссылки (если пользователь не задал).
fn default_name(uri: &str) -> String {
    CredentialLink::from_uri(uri)
        .ok()
        .and_then(|l| l.servers.first().cloned())
        .unwrap_or_else(|| "профиль".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::creds::{CredentialBundle, CredentialLink, BUNDLE_VERSION};

    fn sample_uri() -> String {
        let b = CredentialBundle {
            version: BUNDLE_VERSION,
            servers: vec!["exit.example:4433".into()],
            server_name: "citadel.exit".into(),
            kx_suite: "pq".into(),
            cert_pin: Some([7u8; 32]),
            mldsa_pub: None,
            obfs_psk: Some([9u8; 32]),
            tcp_port: None,
            issuer: None,
            issuer_pub: None,
            client_seed: None,
            routes: String::new(),
            dns: None,
        };
        CredentialLink::from_bundle(&b).to_uri().unwrap()
    }

    fn tmp_path(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("citadel-vault-test-{tag}-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn create_add_reopen_roundtrip() {
        let path = tmp_path("roundtrip");
        let uri = sample_uri();
        {
            let mut v = Vault::create(&path, "correct horse").unwrap();
            assert!(v.list().is_empty());
            let p = v.add("nl", &uri).unwrap();
            assert_eq!(p.name, "nl");
        }
        // переоткрытие тем же паролем видит профиль
        let v = Vault::open(&path, "correct horse").unwrap();
        let list = v.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].uri, uri);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn wrong_password_rejected() {
        let path = tmp_path("wrongpass");
        Vault::create(&path, "right").unwrap();
        assert!(Vault::open(&path, "wrong").is_err());
        assert!(Vault::open(&path, "right").is_ok());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn add_remove_and_invalid_uri() {
        let path = tmp_path("addremove");
        let uri = sample_uri();
        let mut v = Vault::create(&path, "pw").unwrap();
        let p = v.add("a", &uri).unwrap();
        v.add("b", &uri).unwrap();
        assert_eq!(v.list().len(), 2);
        v.remove(&p.id).unwrap();
        assert_eq!(v.list().len(), 1);
        assert!(v.remove("nope").is_err());
        assert!(v.add("bad", "not-a-citadel-link").is_err()); // мусор не кладём
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn change_password_reencrypts() {
        let path = tmp_path("chpass");
        let uri = sample_uri();
        {
            let mut v = Vault::create(&path, "old").unwrap();
            v.add("x", &uri).unwrap();
            v.change_password("new").unwrap();
        }
        assert!(Vault::open(&path, "old").is_err());
        let v = Vault::open(&path, "new").unwrap();
        assert_eq!(v.list().len(), 1);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn default_name_from_host() {
        let path = tmp_path("defname");
        let uri = sample_uri();
        let mut v = Vault::create(&path, "pw").unwrap();
        let p = v.add("   ", &uri).unwrap(); // пустое имя → хост из ссылки
        assert_eq!(p.name, "exit.example:4433");
        std::fs::remove_file(&path).ok();
    }
}
