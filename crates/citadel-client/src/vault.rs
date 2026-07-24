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
/// v2 (C1/аудит-3) = Argon2id (memory-hard). v1 = legacy PBKDF2 — читается для миграции на open.
const VERSION: u8 = 2;
const VERSION_PBKDF2: u8 = 1;
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
/// Argon2id-параметры (C1): memory-hard KDF против GPU/ASIC-перебора мастер-пароля (vault хранит
/// bearer-креды: obfs_psk/seed/pins). OWASP-рекомендация: m=19 MiB, t=2, p=1 — memory-hard (память —
/// основной фактор GPU-стойкости), но щадит RAM/латентность на слабых мобильных (unlock редкий).
/// Параметры хранятся В ФАЙЛЕ → можно поднять позже без слома существующих vault'ов.
const ARGON_M_KIB: u32 = 19 * 1024; // 19 MiB (OWASP min)
const ARGON_T: u32 = 2; // проходов
const ARGON_P: u32 = 1; // parallelism (без тредпула → кроссплатформенно)
/// Минимальная длина мастер-пароля (backstop; визуальную «силу» показывает UI отдельно).
const MIN_PASSPHRASE_LEN: usize = 8;
/// Заголовок v2: magic+ver+m_kib+t+p+salt+nonce = 45. v1 (legacy): magic+ver+iters+salt+nonce = 37.
const HEADER_LEN_V2: usize = 4 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN;
const HEADER_LEN_V1: usize = 4 + 1 + 4 + SALT_LEN + NONCE_LEN;

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

/// C7.3: локальная метка выданного админом абонента. Живёт ТОЛЬКО в vault админа (на сервере —
/// лишь pub+срок+статус, без имён): «кому какой client_id выдан». Не покидает устройство.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct IssuedRecord {
    /// client_id абонента (Ed25519 pub, 64 hex) — связь с записью реестра на сервере.
    pub client_id_hex: String,
    /// Человеческая метка («телефон Али», «ноут»), заданная админом при выдаче.
    pub label: String,
    /// Когда выдан (unix-секунды).
    pub created: u64,
    /// Срок из реестра на момент выдачи (unix-секунды; 0 = серверный дефолт).
    pub valid_until: u64,
}

#[derive(Serialize, Deserialize, Default)]
struct VaultData {
    profiles: Vec<Profile>,
    /// C7.3: admin-локальные метки выданных абонентов. `#[serde(default)]` → старые vault-файлы
    /// (без этого поля) читаются как пустой список (та же map-совместимость CBOR, что и creds v3).
    #[serde(default)]
    issued: Vec<IssuedRecord>,
}

/// Разблокированное хранилище профилей. Держит производный ключ в памяти, пока открыто;
/// каждое изменение немедленно пере-шифровывает и атомарно пишет файл.
pub struct Vault {
    path: PathBuf,
    key: LessSafeKey,
    salt: [u8; SALT_LEN],
    /// Argon2id-параметры этого файла (v2). Хранятся в файле → future-bump читается.
    m_kib: u32,
    t: u32,
    p: u32,
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

    /// Создать новое пустое хранилище под мастер-паролем (перезаписывает существующее). Argon2id (C1).
    pub fn create(path: impl AsRef<Path>, passphrase: &str) -> Result<Vault> {
        check_passphrase(passphrase)?;
        let rng = SystemRandom::new();
        let mut salt = [0u8; SALT_LEN];
        rng.fill(&mut salt).map_err(|_| anyhow!("RNG"))?;
        let key = derive_key_argon2(passphrase, &salt, ARGON_M_KIB, ARGON_T, ARGON_P)?;
        let v = Vault {
            path: path.as_ref().to_path_buf(),
            key,
            salt,
            m_kib: ARGON_M_KIB,
            t: ARGON_T,
            p: ARGON_P,
            data: VaultData::default(),
        };
        v.save()?;
        Ok(v)
    }

    /// Открыть существующее хранилище мастер-паролем. Неверный пароль → ошибка. v2 (Argon2id) —
    /// штатно; v1 (PBKDF2) — расшифровывается и МИГРИРУЕТ на Argon2id (пере-сохранение файла, C1).
    pub fn open(path: impl AsRef<Path>, passphrase: &str) -> Result<Vault> {
        let path = path.as_ref().to_path_buf();
        let raw = std::fs::read(&path).with_context(|| format!("читать vault {}", path.display()))?;
        if raw.len() < 5 || &raw[0..4] != MAGIC {
            bail!("повреждённый файл хранилища (не CitadelPQVPN vault)");
        }
        match raw[4] {
            VERSION => Self::open_v2(path, passphrase, &raw),
            VERSION_PBKDF2 => Self::open_v1_migrate(path, passphrase, &raw),
            v => bail!("неподдерживаемая версия хранилища: {v}"),
        }
    }

    /// v2: Argon2id-заголовок `m_kib‖t‖p‖salt‖nonce` → derive → decrypt.
    fn open_v2(path: PathBuf, passphrase: &str, raw: &[u8]) -> Result<Vault> {
        if raw.len() < HEADER_LEN_V2 {
            bail!("повреждённый v2-заголовок хранилища");
        }
        let m_kib = u32::from_be_bytes(raw[5..9].try_into().unwrap());
        let t = u32::from_be_bytes(raw[9..13].try_into().unwrap());
        let p = u32::from_be_bytes(raw[13..17].try_into().unwrap());
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&raw[17..17 + SALT_LEN]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&raw[17 + SALT_LEN..HEADER_LEN_V2]);

        let key = derive_key_argon2(passphrase, &salt, m_kib, t, p)?;
        let mut in_out = raw[HEADER_LEN_V2..].to_vec();
        let plain = key
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut in_out)
            .map_err(|_| anyhow!("неверный мастер-пароль или повреждённое хранилище"))?;
        let data: VaultData =
            ciborium::from_reader(&plain[..]).context("разобрать профили (CBOR)")?;
        in_out.zeroize(); // S1.3/M7: затереть расшифрованный plaintext профилей (секреты)
        Ok(Vault { path, key, salt, m_kib, t, p, data })
    }

    /// v1 (legacy PBKDF2): расшифровать старым ключом, затем МИГРИРОВАТЬ на Argon2id — новый salt,
    /// Argon2-ключ, пере-сохранить как v2 (прозрачный upgrade при первом открытии, C1).
    fn open_v1_migrate(path: PathBuf, passphrase: &str, raw: &[u8]) -> Result<Vault> {
        if raw.len() < HEADER_LEN_V1 {
            bail!("повреждённый v1-заголовок хранилища");
        }
        let iters = u32::from_be_bytes(raw[5..9].try_into().unwrap());
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&raw[9..9 + SALT_LEN]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&raw[9 + SALT_LEN..HEADER_LEN_V1]);

        let key = derive_key_pbkdf2(passphrase, &salt, iters)?;
        let mut in_out = raw[HEADER_LEN_V1..].to_vec();
        let plain = key
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut in_out)
            .map_err(|_| anyhow!("неверный мастер-пароль или повреждённое хранилище"))?;
        let data: VaultData =
            ciborium::from_reader(&plain[..]).context("разобрать профили (CBOR)")?;
        in_out.zeroize();

        // миграция → Argon2id v2 (новый salt + ключ, пере-сохранить файл)
        let rng = SystemRandom::new();
        let mut new_salt = [0u8; SALT_LEN];
        rng.fill(&mut new_salt).map_err(|_| anyhow!("RNG"))?;
        let new_key = derive_key_argon2(passphrase, &new_salt, ARGON_M_KIB, ARGON_T, ARGON_P)?;
        let v = Vault {
            path,
            key: new_key,
            salt: new_salt,
            m_kib: ARGON_M_KIB,
            t: ARGON_T,
            p: ARGON_P,
            data,
        };
        v.save()?; // перезаписать файл как v2 (Argon2id)
        eprintln!("[vault] мигрирован PBKDF2(v1) → Argon2id(v2)");
        Ok(v)
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

    // ── C7.3: admin-локальные метки выданных абонентов (только устройство админа) ──

    /// Список выданных абонентов (метки), копия для UI.
    pub fn list_issued(&self) -> Vec<IssuedRecord> {
        self.data.issued.clone()
    }

    /// Записать/обновить метку выданного абонента (upsert по client_id). Возвращает запись.
    pub fn add_issued(&mut self, client_id_hex: &str, label: &str, valid_until: u64) -> Result<IssuedRecord> {
        let rec = IssuedRecord {
            client_id_hex: client_id_hex.trim().to_lowercase(),
            label: label.trim().to_string(),
            created: now_unix(),
            valid_until,
        };
        self.data.issued.retain(|r| r.client_id_hex != rec.client_id_hex); // upsert
        self.data.issued.push(rec.clone());
        self.save()?;
        Ok(rec)
    }

    /// Удалить метку выданного абонента по client_id (например, после отзыва). Нет записи — no-op.
    pub fn remove_issued(&mut self, client_id_hex: &str) -> Result<()> {
        let want = client_id_hex.trim().to_lowercase();
        let before = self.data.issued.len();
        self.data.issued.retain(|r| r.client_id_hex != want);
        if self.data.issued.len() != before {
            self.save()?;
        }
        Ok(())
    }

    /// Сменить мастер-пароль (новый salt + перешифровка). Vault уже разблокирован — текущий
    /// пароль проверяется на уровне FFI повторным `open`.
    pub fn change_password(&mut self, new_passphrase: &str) -> Result<()> {
        check_passphrase(new_passphrase)?;
        let rng = SystemRandom::new();
        let mut salt = [0u8; SALT_LEN];
        rng.fill(&mut salt).map_err(|_| anyhow!("RNG"))?;
        self.key = derive_key_argon2(new_passphrase, &salt, ARGON_M_KIB, ARGON_T, ARGON_P)?;
        self.salt = salt;
        self.m_kib = ARGON_M_KIB;
        self.t = ARGON_T;
        self.p = ARGON_P;
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

        let mut out = Vec::with_capacity(HEADER_LEN_V2 + in_out.len());
        out.extend_from_slice(MAGIC);
        out.push(VERSION); // v2 = Argon2id
        out.extend_from_slice(&self.m_kib.to_be_bytes());
        out.extend_from_slice(&self.t.to_be_bytes());
        out.extend_from_slice(&self.p.to_be_bytes());
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

/// C1: Argon2id(passphrase, salt, m_kib/t/p) → ключ AES-256-GCM. Memory-hard → перебор мастер-пароля
/// (при утечке файла vault) на порядки дороже, чем PBKDF2, особенно на GPU/ASIC (память-bound).
fn derive_key_argon2(
    passphrase: &str,
    salt: &[u8],
    m_kib: u32,
    t: u32,
    p: u32,
) -> Result<LessSafeKey> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(m_kib, t, p, Some(KEY_LEN)).map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("argon2 derive: {e}"))?;
    let unbound = UnboundKey::new(&AES_256_GCM, &key).map_err(|_| anyhow!("ключ AEAD"))?;
    key.zeroize(); // S1.3/M7: затереть сырой производный ключ (UnboundKey уже скопировал его)
    Ok(LessSafeKey::new(unbound))
}

/// Legacy PBKDF2-HMAC-SHA256 — ТОЛЬКО для чтения старых v1-файлов (миграция на Argon2id при open).
fn derive_key_pbkdf2(passphrase: &str, salt: &[u8], iters: u32) -> Result<LessSafeKey> {
    let iters = NonZeroU32::new(iters).ok_or_else(|| anyhow!("iters=0"))?;
    let mut key = [0u8; KEY_LEN];
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, iters, salt, passphrase.as_bytes(), &mut key);
    let unbound = UnboundKey::new(&AES_256_GCM, &key).map_err(|_| anyhow!("ключ AEAD"))?;
    key.zeroize();
    Ok(LessSafeKey::new(unbound))
}

/// Политика мастер-пароля (backstop): не пустой и не короче [`MIN_PASSPHRASE_LEN`]. Визуальную
/// оценку силы показывает UI; здесь — жёсткий минимум перед дорогим Argon2-derive.
fn check_passphrase(p: &str) -> Result<()> {
    if p.is_empty() {
        bail!("мастер-пароль не может быть пустым");
    }
    if p.chars().count() < MIN_PASSPHRASE_LEN {
        bail!("мастер-пароль слишком короткий (минимум {MIN_PASSPHRASE_LEN} символов)");
    }
    Ok(())
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
            issuer_pin: None,
            client_seed: None,
            admin_seed: None,
            admin_port: None,
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
        Vault::create(&path, "rightpass").unwrap();
        assert!(Vault::open(&path, "wrongpass").is_err());
        assert!(Vault::open(&path, "rightpass").is_ok());
        std::fs::remove_file(&path).ok();
    }

    /// C1: политика мастер-пароля — пустой и слишком короткий (<8) отклоняются на create/change.
    #[test]
    fn short_passphrase_rejected() {
        let path = tmp_path("shortpw");
        assert!(Vault::create(&path, "").is_err());
        assert!(Vault::create(&path, "short7!").is_err()); // 7 символов
        let mut v = Vault::create(&path, "longenough1").unwrap();
        assert!(v.change_password("tiny").is_err());
        assert!(v.change_password("anotherlong1").is_ok());
        std::fs::remove_file(&path).ok();
    }

    /// C1: старый v1-файл (PBKDF2) читается и МИГРИРУЕТ на Argon2id (v2) при открытии — прозрачный
    /// upgrade без потери профилей; после миграции файл — v2, повторное открытие работает.
    #[test]
    fn v1_pbkdf2_migrates_to_argon2() {
        let path = tmp_path("migrate");
        let uri = sample_uri();
        let pass = "correct horse";
        // построить legacy v1-файл (PBKDF2) с одним профилем — формат до C1.
        let mut data = VaultData::default();
        data.profiles.push(Profile {
            id: "id1".into(),
            name: "nl".into(),
            uri: uri.clone(),
            created: 1,
            last_exit: None,
        });
        write_legacy_v1(&path, pass, &data);
        assert_eq!(std::fs::read(&path).unwrap()[4], VERSION_PBKDF2, "исходно v1");

        // открытие мигрирует на v2
        let v = Vault::open(&path, pass).unwrap();
        assert_eq!(v.list().len(), 1);
        assert_eq!(v.list()[0].uri, uri);
        drop(v);
        assert_eq!(std::fs::read(&path).unwrap()[4], VERSION, "после миграции — v2 Argon2id");
        // повторное открытие тем же паролем (уже Argon2id) работает
        assert!(Vault::open(&path, pass).is_ok());
        assert!(Vault::open(&path, "wrongpass").is_err());
        std::fs::remove_file(&path).ok();
    }

    /// Собрать legacy-v1-файл (PBKDF2) вручную — для теста миграции (write-путь v1 удалён из прода).
    fn write_legacy_v1(path: &std::path::Path, passphrase: &str, data: &VaultData) {
        let iters: u32 = 600_000;
        let rng = SystemRandom::new();
        let mut salt = [0u8; SALT_LEN];
        rng.fill(&mut salt).unwrap();
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill(&mut nonce).unwrap();
        let key = derive_key_pbkdf2(passphrase, &salt, iters).unwrap();
        let mut plain = Vec::new();
        ciborium::into_writer(data, &mut plain).unwrap();
        let mut in_out = plain;
        key.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut in_out)
            .unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(VERSION_PBKDF2);
        out.extend_from_slice(&iters.to_be_bytes());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&in_out);
        std::fs::write(path, out).unwrap();
    }

    #[test]
    fn add_remove_and_invalid_uri() {
        let path = tmp_path("addremove");
        let uri = sample_uri();
        let mut v = Vault::create(&path, "vaultpass1").unwrap();
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
            let mut v = Vault::create(&path, "oldpassword").unwrap();
            v.add("x", &uri).unwrap();
            v.change_password("newpassword").unwrap();
        }
        assert!(Vault::open(&path, "oldpassword").is_err());
        let v = Vault::open(&path, "newpassword").unwrap();
        assert_eq!(v.list().len(), 1);
        std::fs::remove_file(&path).ok();
    }

    /// C7.3: метки выданных абонентов переживают переоткрытие, upsert по client_id схлопывает,
    /// remove чистит. Профили и метки независимы.
    #[test]
    fn issued_records_roundtrip_and_upsert() {
        let path = tmp_path("issued");
        {
            let mut v = Vault::create(&path, "issuedpass1").unwrap();
            v.add("prof", &sample_uri()).unwrap(); // профиль отдельно
            v.add_issued("aa", "телефон", 100).unwrap();
            v.add_issued("bb", "ноут", 200).unwrap();
            v.add_issued("AA", "телефон-2", 300).unwrap(); // upsert того же id (нормализуется в lower)
            assert_eq!(v.list_issued().len(), 2, "AA==aa → апдейт, не дубль");
            assert_eq!(v.list_issued().iter().find(|r| r.client_id_hex == "aa").unwrap().label, "телефон-2");
        }
        // переоткрытие видит метки И профиль
        let mut v = Vault::open(&path, "issuedpass1").unwrap();
        assert_eq!(v.list_issued().len(), 2);
        assert_eq!(v.list().len(), 1);
        v.remove_issued("bb").unwrap();
        assert_eq!(v.list_issued().len(), 1);
        v.remove_issued("nope").unwrap(); // no-op
        assert_eq!(v.list_issued().len(), 1);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn default_name_from_host() {
        let path = tmp_path("defname");
        let uri = sample_uri();
        let mut v = Vault::create(&path, "defnamepass1").unwrap();
        let p = v.add("   ", &uri).unwrap(); // пустое имя → хост из ссылки
        assert_eq!(p.name, "exit.example:4433");
        std::fs::remove_file(&path).ok();
    }
}
