//! `citadel_client::vault` — зашифрованное хранилище профилей подключения (`SecretStore`).
//!
//! Несколько профилей (имя + `citadel://`-ссылка с pin/psk/seed) шифруются мастер-паролем
//! и лежат одним файлом. Крипта — в Rust-ядре (aws-lc-rs, та же библиотека, что и в движке;
//! кроссится под Android/iOS), НЕ в открытом виде и без зависимости от OS-keyring-демона.
//!
//! Формат файла (binary), v3 — текущий:
//! ```text
//! "CPQV" | ver(1)=3 | m_kib(u32 BE) | t(u32 BE) | p(u32 BE) | salt(16) | nonce(12) | AES-256-GCM(ct‖tag)
//! ```
//! Ключ = Argon2id(passphrase, salt, m_kib/t/p) → 32 B. Открытый текст = CBOR(VaultData).
//! **Весь заголовок входит в AAD** (L-2/аудит-4), поэтому его правка ломает проверку тега.
//! Неверный пароль → AEAD open не проходит → `open` возвращает ошибку (аутентификация AEAD =
//! проверка пароля, отдельный верификатор не нужен).
//!
//! Читаются и прозрачно пере-сохраняются как v3: **v2** (тот же Argon2id, но AAD пустой) и
//! **v1** (legacy PBKDF2-HMAC-SHA256 — миграция на Argon2id при первом открытии, C1/аудит-3).

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
/// v3 (L-2/аудит-4) = Argon2id + заголовок под AAD. v2 = Argon2id без AAD, v1 = legacy PBKDF2 —
/// оба читаются и прозрачно пере-сохраняются как v3 при первом успешном открытии.
const VERSION: u8 = 3;
const VERSION_ARGON_NO_AAD: u8 = 2;
const VERSION_PBKDF2: u8 = 1;
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
/// Argon2id-параметры (C1): memory-hard KDF против GPU/ASIC-перебора мастер-пароля (vault хранит
/// bearer-креды: obfs_psk/seed/pins). Параметры хранятся В ФАЙЛЕ → поднимаются без слома
/// существующих хранилищ (старые до-считываются своими, а затем прозрачно пере-шифровываются —
/// см. [`Vault::open_v2`]).
///
/// Целимся НЕ в OWASP-минимум (m=19 MiB, t=2 — это ~45 мс, то есть дешёвый перебор), а в ~1–2 с на
/// разблокировку: она происходит раз за запуск, и лишняя секунда человеку не мешает, а стоимость
/// офлайн-перебора украденного файла растёт на два порядка.
///
/// На Android память дороже времени (бюджетные устройства и OOM-killer), поэтому там меньше
/// памяти и больше проходов при сопоставимом времени.
#[cfg(target_os = "android")]
const ARGON_M_KIB: u32 = 64 * 1024; // 64 MiB — не провоцируем OOM на дешёвых телефонах
#[cfg(target_os = "android")]
const ARGON_T: u32 = 8; // время добираем проходами
#[cfg(not(target_os = "android"))]
const ARGON_M_KIB: u32 = 256 * 1024; // 256 MiB (desktop: памяти хватает, GPU-перебор дорожает)
#[cfg(not(target_os = "android"))]
const ARGON_T: u32 = 4; // проходов
const ARGON_P: u32 = 1; // parallelism (без тредпула → кроссплатформенно)

/// «Стоимость» набора Argon2-параметров для сравнения (память × проходы). Нужна, чтобы при
/// открытии поднимать СЛАБЫЕ файлы до текущих настроек и НЕ понижать те, что созданы сильнее
/// (в т.ч. на другой платформе: у Android и десктопа разный баланс памяти/времени).
fn argon_cost(m_kib: u32, t: u32) -> u64 {
    u64::from(m_kib) * u64::from(t)
}

/// **L-2/аудит-4: границы Argon2-параметров, ПРИНИМАЕМЫХ ИЗ ФАЙЛА.**
///
/// Параметры лежат в заголовке открытым текстом, а прочитать их приходится ДО того, как AEAD
/// подтвердит подлинность файла (из них же и выводится ключ). Значит, подложенный/битый файл
/// диктует нам объём аллокации и число проходов: `m_kib = 0xFFFFFFFF` — это запрос на 4 ТиБ
/// (OOM-killer вместо сообщения об ошибке, а на Android — падение приложения), `t = 2^32` — вечное
/// «открываю…». Владелец файла — не всегда владелец устройства: vault может прийти из бэкапа,
/// синхронизации или от локального соседа (противник A6), поэтому границы — обязательны, и это
/// **не** проверка криптостойкости, а защита доступности процесса.
///
/// Диапазон заведомо шире любых наших дефолтов (desktop 256 MiB/t=4, Android 64 MiB/t=8), чтобы
/// будущий рост параметров не сделал старые файлы нечитаемыми, но с потолком по произведению
/// «память × проходы» — иначе комбинация «1 GiB × 16» даёт минуты работы на телефоне.
const ARGON_M_KIB_MIN: u32 = 8; // argon2 требует ≥ 8·p KiB
const ARGON_M_KIB_MAX: u32 = 1024 * 1024; // 1 GiB
const ARGON_T_MAX: u32 = 16;
const ARGON_P_MAX: u32 = 4;
const ARGON_COST_MAX: u64 = 8 * 1024 * 1024; // m_kib × t — 8× текущего десктопного набора

fn check_argon_params(m_kib: u32, t: u32, p: u32) -> Result<()> {
    if !(ARGON_M_KIB_MIN..=ARGON_M_KIB_MAX).contains(&m_kib)
        || !(1..=ARGON_T_MAX).contains(&t)
        || !(1..=ARGON_P_MAX).contains(&p)
        || m_kib < ARGON_M_KIB_MIN.saturating_mul(p)
        || argon_cost(m_kib, t) > ARGON_COST_MAX
    {
        bail!(
            "параметры Argon2id в заголовке вне допустимых границ (m={m_kib}KiB, t={t}, p={p}) — \
             файл повреждён или подложен"
        );
    }
    Ok(())
}

/// AAD для AEAD хранилища (L-2): весь заголовок — `magic‖version‖m_kib‖t‖p‖salt‖nonce`.
/// Заголовок перестаёт быть «свободным» полем: любая его правка (в т.ч. подмена версии на v2,
/// чтобы отключить саму эту привязку, или перестановка salt/nonce/шифртекста между двумя
/// файлами) ломает проверку тега и даёт честную ошибку вместо тихой работы с чужим заголовком.
fn header_aad(header: &[u8]) -> Aad<&[u8]> {
    Aad::from(header)
}
/// Минимальная длина мастер-пароля (backstop; визуальную «силу» показывает UI отдельно).
/// Публичная: UI обязан проверять то же самое ДО дорогого Argon2-derive и говорить человеку
/// конкретное число, а не «не удалось» (иначе пользователь угадывает политику вслепую).
pub const MIN_PASSPHRASE_LEN: usize = 8;
/// Потолок длины имени профиля. Имя — чисто отображаемое поле, но приходит от человека и
/// попадает в список/заголовки/журнал: длинную «простыню» и управляющие символы (перевод строки)
/// режем на входе, а не в каждом месте показа.
pub const MAX_PROFILE_NAME_LEN: usize = 64;
/// Префикс авто-имени профиля, когда пользователь своё не задал: `Citadel001`, `Citadel002`, …
const DEFAULT_NAME_PREFIX: &str = "Citadel";
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

/// Почему не открылось хранилище. Разделение обязательное, а не косметическое: «пароль не подошёл»
/// — это про ввод пользователя, а «файла нет / нет доступа / он повреждён» — про машину, и путать
/// их в UI нельзя (человек перебирает пароли там, где надо чинить права на папку).
#[derive(Debug)]
pub enum VaultOpenError {
    /// AEAD не сошёлся: введённый мастер-пароль неверен (либо файл подменён/побит).
    WrongPassword,
    /// Всё остальное: файла нет, нет прав, битый заголовок, неподдерживаемая версия, битый CBOR.
    Unavailable(anyhow::Error),
}

impl std::fmt::Display for VaultOpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongPassword => write!(f, "неверный мастер-пароль"),
            Self::Unavailable(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for VaultOpenError {}

impl VaultOpenError {
    /// Схлопнуть в обычную `anyhow`-ошибку (для вызывающих, которым причина не важна).
    /// Своего `From` быть не может: `anyhow` уже покрывает любые `std::error::Error`, а его
    /// обёртка потеряла бы цепочку причин `Unavailable`.
    fn flatten(self) -> anyhow::Error {
        match self {
            Self::WrongPassword => anyhow!("неверный мастер-пароль или повреждённое хранилище"),
            Self::Unavailable(e) => e,
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
        Self::open_detailed(path, passphrase).map_err(VaultOpenError::flatten)
    }

    /// Как [`Vault::open`], но с разделением причин ([`VaultOpenError`]) — для UI, который обязан
    /// сказать «пароль неверен» ровно тогда, когда неверен именно пароль.
    pub fn open_detailed(
        path: impl AsRef<Path>,
        passphrase: &str,
    ) -> std::result::Result<Vault, VaultOpenError> {
        let path = path.as_ref().to_path_buf();
        let raw = std::fs::read(&path)
            .with_context(|| format!("читать хранилище {}", path.display()))
            .map_err(VaultOpenError::Unavailable)?;
        if raw.len() < 5 || &raw[0..4] != MAGIC {
            return Err(VaultOpenError::Unavailable(anyhow!(
                "повреждённый файл хранилища (не CitadelPQVPN vault): {}",
                path.display()
            )));
        }
        match raw[4] {
            // v3 — заголовок под AAD; v2 — тот же Argon2id, но AAD пустой (читаем и апгрейдим).
            VERSION => Self::open_v2(path, passphrase, &raw, true),
            VERSION_ARGON_NO_AAD => Self::open_v2(path, passphrase, &raw, false),
            VERSION_PBKDF2 => Self::open_v1_migrate(path, passphrase, &raw),
            v => Err(VaultOpenError::Unavailable(anyhow!(
                "неподдерживаемая версия хранилища: {v}"
            ))),
        }
    }

    /// Подходит ли мастер-пароль к файлу хранилища: `Ok(true|false)` — про пароль, `Err` — про
    /// доступность файла. Нужна там, где хранилище УЖЕ открыто в памяти и переоткрывать его незачем
    /// (смена пароля: подтверждаем текущий, не трогая рабочую копию).
    pub fn password_matches(path: impl AsRef<Path>, passphrase: &str) -> Result<bool> {
        match Self::open_detailed(path, passphrase) {
            Ok(_) => Ok(true),
            Err(VaultOpenError::WrongPassword) => Ok(false),
            Err(VaultOpenError::Unavailable(e)) => Err(e),
        }
    }

    /// v2/v3: Argon2id-заголовок `m_kib‖t‖p‖salt‖nonce` → derive → decrypt.
    /// `aad = true` (v3) — заголовок входит в AAD (L-2); `false` (v2) — как раньше, пустой AAD.
    fn open_v2(
        path: PathBuf,
        passphrase: &str,
        raw: &[u8],
        aad: bool,
    ) -> std::result::Result<Vault, VaultOpenError> {
        if raw.len() < HEADER_LEN_V2 {
            return Err(VaultOpenError::Unavailable(anyhow!("повреждённый v2-заголовок хранилища")));
        }
        let m_kib = u32::from_be_bytes(raw[5..9].try_into().unwrap());
        let t = u32::from_be_bytes(raw[9..13].try_into().unwrap());
        let p = u32::from_be_bytes(raw[13..17].try_into().unwrap());
        // L-2: границы ДО derive — иначе подложенный заголовок сам назначает нам аллокацию и время.
        check_argon_params(m_kib, t, p).map_err(VaultOpenError::Unavailable)?;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&raw[17..17 + SALT_LEN]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&raw[17 + SALT_LEN..HEADER_LEN_V2]);

        let key = derive_key_argon2(passphrase, &salt, m_kib, t, p)
            .map_err(VaultOpenError::Unavailable)?;
        let header = raw[..HEADER_LEN_V2].to_vec();
        let mut in_out = raw[HEADER_LEN_V2..].to_vec();
        // AEAD не сошёлся = пароль (штатный случай), а не поломка машины — отдельная ветка.
        let plain = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                // v2 читается с пустым AAD, v3 — с заголовком (типы должны совпасть → срез).
                header_aad(if aad { &header } else { &[] }),
                &mut in_out,
            )
            .map_err(|_| VaultOpenError::WrongPassword)?;
        let data: VaultData = ciborium::from_reader(&plain[..])
            .context("разобрать профили (CBOR)")
            .map_err(VaultOpenError::Unavailable)?;
        in_out.zeroize(); // S1.3/M7: затереть расшифрованный plaintext профилей (секреты)
        let mut v = Vault { path, key, salt, m_kib, t, p, data };
        // Файл сделан на слабых параметрах (старая версия клиента) — поднимаем до текущих прямо
        // сейчас: пароль в руках, момент единственный. Не смогли пере-записать — не беда, работаем
        // на прочитанных параметрах (открытие хранилища важнее апгрейда его стойкости).
        if argon_cost(m_kib, t) < argon_cost(ARGON_M_KIB, ARGON_T) {
            match v.rekey(passphrase) {
                Ok(()) => eprintln!(
                    "[vault] параметры Argon2id подняты: m={m_kib}KiB,t={t} → m={ARGON_M_KIB}KiB,t={ARGON_T}"
                ),
                Err(e) => eprintln!("[vault] апгрейд параметров Argon2id пропущен: {e:#}"),
            }
        } else if !aad {
            // L-2: файл v2 (без AAD) — пере-сохранить как v3 тем же ключом. Пароль менять не надо:
            // salt и параметры те же, меняется только привязка заголовка к шифртексту.
            match v.save() {
                Ok(()) => eprintln!("[vault] хранилище пере-сохранено как v3 (заголовок под AAD)"),
                Err(e) => eprintln!("[vault] апгрейд формата v2→v3 пропущен: {e:#}"),
            }
        }
        Ok(v)
    }

    /// v1 (legacy PBKDF2): расшифровать старым ключом, затем МИГРИРОВАТЬ на Argon2id — новый salt,
    /// Argon2-ключ, пере-сохранить как v2 (прозрачный upgrade при первом открытии, C1).
    fn open_v1_migrate(
        path: PathBuf,
        passphrase: &str,
        raw: &[u8],
    ) -> std::result::Result<Vault, VaultOpenError> {
        if raw.len() < HEADER_LEN_V1 {
            return Err(VaultOpenError::Unavailable(anyhow!("повреждённый v1-заголовок хранилища")));
        }
        let iters = u32::from_be_bytes(raw[5..9].try_into().unwrap());
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&raw[9..9 + SALT_LEN]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&raw[9 + SALT_LEN..HEADER_LEN_V1]);

        let key =
            derive_key_pbkdf2(passphrase, &salt, iters).map_err(VaultOpenError::Unavailable)?;
        let mut in_out = raw[HEADER_LEN_V1..].to_vec();
        let plain = key
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut in_out)
            .map_err(|_| VaultOpenError::WrongPassword)?;
        let data: VaultData = ciborium::from_reader(&plain[..])
            .context("разобрать профили (CBOR)")
            .map_err(VaultOpenError::Unavailable)?;
        in_out.zeroize();

        // миграция → Argon2id v2 (новый salt + ключ, пере-сохранить файл)
        let migrate = |e: anyhow::Error| VaultOpenError::Unavailable(e);
        let rng = SystemRandom::new();
        let mut new_salt = [0u8; SALT_LEN];
        rng.fill(&mut new_salt).map_err(|_| migrate(anyhow!("RNG")))?;
        let new_key = derive_key_argon2(passphrase, &new_salt, ARGON_M_KIB, ARGON_T, ARGON_P)
            .map_err(migrate)?;
        let v = Vault {
            path,
            key: new_key,
            salt: new_salt,
            m_kib: ARGON_M_KIB,
            t: ARGON_T,
            p: ARGON_P,
            data,
        };
        v.save().map_err(migrate)?; // перезаписать файл как v2 (Argon2id)
        eprintln!("[vault] мигрирован PBKDF2(v1) → Argon2id(v2)");
        Ok(v)
    }

    /// Путь файла хранилища (диагностика: в сообщениях об ошибках человеку нужно знать, ГДЕ лежит
    /// его хранилище — на Windows это уже стоило разбирательства).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Список профилей (копия для UI).
    pub fn list(&self) -> Vec<Profile> {
        self.data.profiles.clone()
    }

    /// Добавить профиль из `citadel://`-ссылки (валидируется). Возвращает созданный профиль.
    /// Пустое имя → авто-имя [`Vault::next_default_name`] (`Citadel001`, …).
    pub fn add(&mut self, name: &str, uri: &str) -> Result<Profile> {
        // валидность ссылки — до сохранения секрета (мусор в vault не кладём)
        CredentialLink::from_uri(uri).context("невалидная citadel://-ссылка")?;
        let name = sanitize_name(name);
        let p = Profile {
            id: random_id()?,
            name: if name.is_empty() { self.next_default_name() } else { name },
            uri: uri.to_string(),
            created: now_unix(),
            last_exit: None,
        };
        self.data.profiles.push(p.clone());
        self.save()?;
        Ok(p)
    }

    /// Переименовать профиль. Пустое (после очистки) имя — отказ: «профиль без имени» в списке
    /// неотличим от соседей, а молча подставлять авто-имя вместо введённого человеком — врать ему.
    pub fn rename(&mut self, id: &str, name: &str) -> Result<()> {
        let name = sanitize_name(name);
        if name.is_empty() {
            bail!("Имя профиля не может быть пустым");
        }
        let p = self
            .data
            .profiles
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or_else(|| anyhow!("профиль не найден: {id}"))?;
        if p.name == name {
            return Ok(()); // ничего не изменилось — не переписываем файл
        }
        p.name = name;
        self.save()
    }

    /// Переставить профиль на позицию `to` (индекс в списке после перемещения). Порядок профилей в
    /// файле — и есть порядок списка в UI (отдельного поля сортировки нет: список короткий, а ручной
    /// порядок должен переживать перезапуск и смену устройства вместе с хранилищем).
    ///
    /// Перенос, а не обмен соседей: интерфейс переставляет профиль перетаскиванием сразу на нужное
    /// место, и промежуточные состояния (N записей файла на один жест) хранилищу не нужны. Индекс
    /// за границей списка прижимается к последней позиции — так UI не обязан знать длину списка;
    /// перемещение «на своё же место» — no-op без перезаписи файла.
    pub fn move_to(&mut self, id: &str, to: usize) -> Result<()> {
        let from = self
            .data
            .profiles
            .iter()
            .position(|p| p.id == id)
            .ok_or_else(|| anyhow!("профиль не найден: {id}"))?;
        let to = to.min(self.data.profiles.len().saturating_sub(1));
        if from == to {
            return Ok(());
        }
        let p = self.data.profiles.remove(from);
        self.data.profiles.insert(to, p);
        self.save()
    }

    /// Первое свободное авто-имя `CitadelNNN`. Занятые номера берём из ИМЁН существующих профилей
    /// (а не из их количества): иначе после удаления профиля новый получил бы имя-двойник.
    fn next_default_name(&self) -> String {
        let used: std::collections::BTreeSet<u32> =
            self.data.profiles.iter().filter_map(|p| default_name_number(&p.name)).collect();
        let mut n: u32 = 1;
        while used.contains(&n) {
            n += 1;
        }
        format!("{DEFAULT_NAME_PREFIX}{n:03}")
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
    /// пароль проверяется вызывающим ([`Vault::password_matches`]).
    ///
    /// Если записать файл не удалось (нет прав на папку, кончилось место), ключ в памяти
    /// ВОЗВРАЩАЕТСЯ к прежнему: иначе разблокированное хранилище осталось бы зашифрованным новым
    /// паролем только в оперативке, а на диске — старым, и следующая же запись профиля сделала бы
    /// файл нечитаемым обоими паролями.
    pub fn change_password(&mut self, new_passphrase: &str) -> Result<()> {
        check_passphrase(new_passphrase)?;
        self.rekey(new_passphrase)
    }

    /// Пере-шифровать файл под `passphrase` с ТЕКУЩИМИ Argon2-параметрами (новый salt + ключ).
    /// Общий шаг для смены пароля и для апгрейда параметров старого хранилища.
    fn rekey(&mut self, passphrase: &str) -> Result<()> {
        let rng = SystemRandom::new();
        let mut salt = [0u8; SALT_LEN];
        rng.fill(&mut salt).map_err(|_| anyhow!("RNG"))?;
        let new_key = derive_key_argon2(passphrase, &salt, ARGON_M_KIB, ARGON_T, ARGON_P)?;
        let prev = (
            std::mem::replace(&mut self.key, new_key),
            self.salt,
            self.m_kib,
            self.t,
            self.p,
        );
        self.salt = salt;
        self.m_kib = ARGON_M_KIB;
        self.t = ARGON_T;
        self.p = ARGON_P;
        if let Err(e) = self.save() {
            (self.key, self.salt, self.m_kib, self.t, self.p) = prev; // откат: диск — источник истины
            return Err(e);
        }
        Ok(())
    }

    /// Сериализовать + зашифровать + атомарно записать (temp → rename).
    fn save(&self) -> Result<()> {
        let mut plain = Vec::new();
        ciborium::into_writer(&self.data, &mut plain).context("сериализовать профили (CBOR)")?;

        let rng = SystemRandom::new();
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill(&mut nonce).map_err(|_| anyhow!("RNG"))?;

        // Заголовок собирается ПЕРВЫМ: он же AAD (L-2), значит шифруем уже под него.
        let mut out = Vec::with_capacity(HEADER_LEN_V2 + plain.len() + AES_256_GCM.tag_len());
        out.extend_from_slice(MAGIC);
        out.push(VERSION); // v3 = Argon2id + заголовок под AAD
        out.extend_from_slice(&self.m_kib.to_be_bytes());
        out.extend_from_slice(&self.t.to_be_bytes());
        out.extend_from_slice(&self.p.to_be_bytes());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&nonce);
        debug_assert_eq!(out.len(), HEADER_LEN_V2);

        let mut in_out = plain;
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                header_aad(&out),
                &mut in_out,
            )
            .map_err(|_| anyhow!("шифрование AEAD"))?;
        out.extend_from_slice(&in_out);

        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("создать {}", dir.display()))?;
            restrict_dir(dir);
        }
        let tmp = self.path.with_extension("tmp");
        write_private(&tmp, &out).with_context(|| format!("писать {}", tmp.display()))?;
        std::fs::rename(&tmp, &self.path).context("атомарно заменить vault")?;
        Ok(())
    }
}

/// Записать файл хранилища так, чтобы его не мог прочитать никто, кроме владельца.
///
/// L7 (аудит Linux-клиента): `std::fs::write` создаёт файл с `0666 & ~umask` — на типичной
/// многопользовательской машине это `0644`, то есть **шифртекст vault'а читает любой локальный
/// пользователь** и может унести его на офлайн-перебор мастер-пароля. Argon2id делает перебор
/// дорогим, но давать его бесплатно незачем: файл создаётся сразу с `0600`. На не-unix (Windows,
/// где доступ разграничивает ACL профиля, и Android с приватным каталогом приложения) — обычная запись.
#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    std::fs::write(path, data)?;
    Ok(())
}

/// Каталог хранилища — только владельцу (0700). Best-effort: на не-unix и при отсутствии прав
/// (каталог создан платформой) молча пропускаем.
#[cfg(unix)]
fn restrict_dir(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn restrict_dir(_dir: &Path) {}

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
pub fn check_passphrase(p: &str) -> Result<()> {
    if p.is_empty() {
        bail!("Пароль не может быть пустым");
    }
    if p.chars().count() < MIN_PASSPHRASE_LEN {
        bail!("Пароль слишком короткий: минимум {MIN_PASSPHRASE_LEN} символов");
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

/// Очистить пользовательское имя профиля: убрать управляющие символы (перевод строки в имени
/// ломает и список, и журнал), обрезать пробелы и ужать до [`MAX_PROFILE_NAME_LEN`].
/// Пустая строка на выходе = «имя не задано» (вызывающий подставит авто-имя либо откажет).
fn sanitize_name(name: &str) -> String {
    let cleaned: String = name.chars().filter(|c| !c.is_control()).collect();
    cleaned.trim().chars().take(MAX_PROFILE_NAME_LEN).collect::<String>().trim_end().to_string()
}

/// Номер авто-имени (`Citadel007` → 7); любое другое имя — `None`. Нужен, чтобы нумерация
/// продолжалась после удалений и не сталкивалась с именем, введённым/переименованным вручную.
fn default_name_number(name: &str) -> Option<u32> {
    let digits = name.strip_prefix(DEFAULT_NAME_PREFIX)?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
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
            issuer_mldsa: Some([9u8; 32]),
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

    /// Хранилище, созданное прежними (слабыми) Argon2-параметрами, при открытии поднимается до
    /// текущих: пароль тот же, профили на месте, а файл на диске пере-шифрован — иначе усиление KDF
    /// не дошло бы до тех, у кого хранилище уже есть.
    /// L-2: параметры Argon2id из заголовка проверяются ДО derive. Подложенный «m=4 ТиБ» обязан
    /// давать ошибку `Unavailable`, а не OOM-killer, и обязан отваливаться быстро (мы не начинаем
    /// derive). Тест не трогает диск дважды: правим байты заголовка на месте.
    #[test]
    fn planted_argon_params_rejected_before_derive() {
        let path = tmp_path("argon-bounds");
        let pass = "boundspass1";
        Vault::create(&path, pass).unwrap();
        let good = std::fs::read(&path).unwrap();

        // (позиция, значение) → каждое сочетание должно быть отвергнуто
        let cases: [(&str, u32, u32, u32); 6] = [
            ("память 4 ТиБ", u32::MAX, ARGON_T, ARGON_P),
            ("память 0", 0, ARGON_T, ARGON_P),
            ("проходов 0", ARGON_M_KIB, 0, ARGON_P),
            ("проходов 2^32-1", ARGON_M_KIB, u32::MAX, ARGON_P),
            ("parallelism 2^32-1", ARGON_M_KIB, ARGON_T, u32::MAX),
            ("произведение выше потолка", ARGON_M_KIB_MAX, ARGON_T_MAX, 1),
        ];
        for (why, m, t, p) in cases {
            let mut raw = good.clone();
            raw[5..9].copy_from_slice(&m.to_be_bytes());
            raw[9..13].copy_from_slice(&t.to_be_bytes());
            raw[13..17].copy_from_slice(&p.to_be_bytes());
            std::fs::write(&path, &raw).unwrap();
            let started = std::time::Instant::now();
            match Vault::open_detailed(&path, pass) {
                Err(VaultOpenError::Unavailable(_)) => {}
                Err(VaultOpenError::WrongPassword) => panic!("{why}: диагноз «неверный пароль» вместо отказа по границам"),
                Ok(_) => panic!("{why}: файл с такими параметрами открылся"),
            }
            assert!(started.elapsed().as_secs() < 2, "{why}: derive всё-таки запустился");
        }
        std::fs::remove_file(&path).ok();
    }

    /// L-2: старый файл v2 (заголовок не в AAD) открывается тем же паролем и молча
    /// пере-сохраняется как v3; попытка выдать v3 за v2 (сброс версии, чтобы «отключить» AAD)
    /// ломает AEAD — ровно то, ради чего заголовок и попал в AAD.
    #[test]
    fn v2_upgrades_to_v3_and_version_downgrade_breaks_aead() {
        let path = tmp_path("aad-upgrade");
        let pass = "aadpass12345";
        let uri = sample_uri();
        // v2-файл: те же параметры (иначе сработает ветка апгрейда стойкости), но AAD пустой.
        {
            let mut v = Vault::create(&path, pass).unwrap();
            v.add("p", &uri).unwrap();
            let mut plain = Vec::new();
            ciborium::into_writer(&v.data, &mut plain).unwrap();
            let nonce = [0x11u8; NONCE_LEN];
            let mut in_out = plain;
            v.key
                .seal_in_place_append_tag(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::empty(),
                    &mut in_out,
                )
                .unwrap();
            let mut out = Vec::new();
            out.extend_from_slice(MAGIC);
            out.push(VERSION_ARGON_NO_AAD);
            out.extend_from_slice(&v.m_kib.to_be_bytes());
            out.extend_from_slice(&v.t.to_be_bytes());
            out.extend_from_slice(&v.p.to_be_bytes());
            out.extend_from_slice(&v.salt);
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&in_out);
            std::fs::write(&path, &out).unwrap();
        }
        assert_eq!(std::fs::read(&path).unwrap()[4], VERSION_ARGON_NO_AAD, "исходно v2");

        let v = Vault::open(&path, pass).unwrap();
        assert_eq!(v.list().len(), 1, "профиль пережил апгрейд формата");
        drop(v);
        let raw = std::fs::read(&path).unwrap();
        assert_eq!(raw[4], VERSION, "после открытия файл стал v3");
        assert!(Vault::open(&path, pass).is_ok(), "v3 открывается тем же паролем");

        // downgrade-атака на формат: объявляем v3-файл как v2 (AAD «выключен») → тег не сойдётся
        let mut tampered = raw.clone();
        tampered[4] = VERSION_ARGON_NO_AAD;
        std::fs::write(&path, &tampered).unwrap();
        assert!(
            matches!(Vault::open_detailed(&path, pass), Err(VaultOpenError::WrongPassword)),
            "подмена версии обязана ломать AEAD"
        );
        // правка любого поля заголовка — то же самое (здесь: parallelism в допустимых границах)
        let mut tampered = raw.clone();
        tampered[16] = 2;
        std::fs::write(&path, &tampered).unwrap();
        assert!(Vault::open_detailed(&path, pass).is_err(), "правка заголовка обязана ломать open");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn weak_argon_params_upgraded_on_open() {
        let path = tmp_path("argon-upgrade");
        let pass = "upgradepass1";
        let uri = sample_uri();
        {
            // файл со слабыми параметрами (прежний OWASP-минимум: m=19 MiB, t=2)
            let mut v = Vault::create(&path, pass).unwrap();
            v.add("p", &uri).unwrap();
            let weak = 19 * 1024;
            v.key = derive_key_argon2(pass, &v.salt, weak, 2, ARGON_P).unwrap();
            v.m_kib = weak;
            v.t = 2;
            v.save().unwrap();
        }
        let raw = std::fs::read(&path).unwrap();
        assert_eq!(u32::from_be_bytes(raw[5..9].try_into().unwrap()), 19 * 1024, "исходно слабый");

        let v = Vault::open(&path, pass).unwrap();
        assert_eq!(v.list().len(), 1, "профили пережили апгрейд");
        drop(v);
        let raw = std::fs::read(&path).unwrap();
        assert_eq!(u32::from_be_bytes(raw[5..9].try_into().unwrap()), ARGON_M_KIB);
        assert_eq!(u32::from_be_bytes(raw[9..13].try_into().unwrap()), ARGON_T);
        assert!(Vault::open(&path, pass).is_ok(), "тот же пароль открывает поднятый файл");
        assert!(Vault::open(&path, "wrongpass1").is_err());
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

    /// UI обязан отличать «пароль не тот» от «хранилища нет / не читается»: в первом случае человек
    /// пробует другой пароль, во втором — чинит доступ к файлу. Раньше обе ситуации приходили одной
    /// ошибкой, и смена пароля рапортовала «текущий пароль неверен» на отказ в доступе к файлу.
    #[test]
    fn password_matches_separates_wrong_password_from_unavailable() {
        let path = tmp_path("verify");
        Vault::create(&path, "verifypass1").unwrap();
        assert!(Vault::password_matches(&path, "verifypass1").unwrap(), "верный пароль");
        assert!(!Vault::password_matches(&path, "wrongpass1").unwrap(), "неверный — это Ok(false)");

        let missing = tmp_path("verify-missing");
        let err = Vault::password_matches(&missing, "verifypass1");
        assert!(err.is_err(), "нет файла — это Err (не «неверный пароль»)");
        assert!(matches!(
            Vault::open_detailed(&path, "wrongpass1"),
            Err(VaultOpenError::WrongPassword)
        ));
        assert!(matches!(
            Vault::open_detailed(&missing, "verifypass1"),
            Err(VaultOpenError::Unavailable(_))
        ));
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

    /// L7: файл хранилища не должен быть читаем другими пользователями машины — иначе шифртекст
    /// уносят на офлайн-перебор мастер-пароля. Проверяем И после создания, И после изменения.
    #[cfg(unix)]
    #[test]
    fn vault_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp_path("perms");
        let mut v = Vault::create(&path, "permspass1").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "после create ожидается 0600, получено {mode:o}");
        v.add("p", &sample_uri()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "после записи профиля ожидается 0600, получено {mode:o}");
        std::fs::remove_file(&path).ok();
    }

    /// Имя не задано → `Citadel001`, `Citadel002`, … Нумерация идёт по ЗАНЯТЫМ именам: после
    /// удаления освободившийся номер переиспользуется, а имя, заданное человеком, не подменяется.
    #[test]
    fn default_name_is_numbered_citadel() {
        let path = tmp_path("defname");
        let uri = sample_uri();
        let mut v = Vault::create(&path, "defnamepass1").unwrap();
        assert_eq!(v.add("   ", &uri).unwrap().name, "Citadel001");
        let second = v.add("", &uri).unwrap();
        assert_eq!(second.name, "Citadel002");
        assert_eq!(v.add("домашний", &uri).unwrap().name, "домашний", "заданное имя не трогаем");
        assert_eq!(v.add("", &uri).unwrap().name, "Citadel003");
        v.remove(&second.id).unwrap();
        assert_eq!(v.add("", &uri).unwrap().name, "Citadel002", "освободившийся номер переиспользуем");
        // управляющие символы и длина: имя — отображаемое поле, мусор в него не пускаем
        assert_eq!(v.add("  ноут\nвторая строка ", &uri).unwrap().name, "ноутвторая строка");
        let long = v.add(&"я".repeat(200), &uri).unwrap();
        assert_eq!(long.name.chars().count(), MAX_PROFILE_NAME_LEN);
        assert_eq!(v.add("\u{7}\u{1}", &uri).unwrap().name, "Citadel004", "имя из одних управляющих = пустое");
        std::fs::remove_file(&path).ok();
    }

    /// Переименование: сохраняется на диск, пустое имя отвергается, неизвестный id — ошибка.
    #[test]
    fn rename_persists_and_rejects_empty() {
        let path = tmp_path("rename");
        let uri = sample_uri();
        let id = {
            let mut v = Vault::create(&path, "renamepass1").unwrap();
            let p = v.add("", &uri).unwrap();
            v.rename(&p.id, "  рабочий  ").unwrap();
            assert_eq!(v.list()[0].name, "рабочий");
            assert!(v.rename(&p.id, "   ").is_err(), "пустое имя — отказ");
            assert!(v.rename("нет-такого", "имя").is_err());
            p.id
        };
        let v = Vault::open(&path, "renamepass1").unwrap();
        assert_eq!(v.list()[0].name, "рабочий", "переименование пережило переоткрытие");
        assert_eq!(v.list()[0].id, id);
        std::fs::remove_file(&path).ok();
    }

    /// Порядок профилей = порядок в файле: перенос на произвольную позицию (перетаскивание в UI)
    /// переживает переоткрытие, индекс за границей прижимается к концу, перенос на своё же место —
    /// молчаливый no-op (жест, не сдвинувший профиль, не должен переписывать хранилище).
    #[test]
    fn move_to_reorders_and_persists() {
        let path = tmp_path("reorder");
        let uri = sample_uri();
        let (a, b, c) = {
            let mut v = Vault::create(&path, "reorderpass1").unwrap();
            let a = v.add("a", &uri).unwrap().id;
            let b = v.add("b", &uri).unwrap().id;
            let c = v.add("c", &uri).unwrap().id;
            v.move_to(&c, 1).unwrap(); // c на 2-е место → a, c, b
            assert_eq!(names(&v), vec!["a", "c", "b"]);
            v.move_to(&a, 1).unwrap(); // a на 2-е место → c, a, b
            assert_eq!(names(&v), vec!["c", "a", "b"]);
            v.move_to(&c, 0).unwrap(); // уже первый — no-op
            v.move_to(&b, 99).unwrap(); // за границей → прижать к последней позиции (уже там)
            assert_eq!(names(&v), vec!["c", "a", "b"]);
            v.move_to(&b, 0).unwrap(); // с конца в начало через весь список → b, c, a
            assert_eq!(names(&v), vec!["b", "c", "a"]);
            v.move_to(&b, 2).unwrap(); // обратно в конец → c, a, b
            assert_eq!(names(&v), vec!["c", "a", "b"]);
            assert!(v.move_to("нет-такого", 0).is_err());
            (a, b, c)
        };
        let v = Vault::open(&path, "reorderpass1").unwrap();
        assert_eq!(
            v.list().iter().map(|p| p.id.clone()).collect::<Vec<_>>(),
            vec![c, a, b],
            "порядок пережил переоткрытие"
        );
        std::fs::remove_file(&path).ok();
    }

    fn names(v: &Vault) -> Vec<String> {
        v.list().into_iter().map(|p| p.name).collect()
    }
}
