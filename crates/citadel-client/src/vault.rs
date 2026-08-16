//! `citadel_client::vault` — зашифрованное хранилище профилей подключения (`SecretStore`).
//!
//! Несколько профилей (имя + `citadel://`-ссылка с pin/psk/seed) шифруются мастер-паролем
//! и лежат одним файлом. Крипта — в Rust-ядре (aws-lc-rs, та же библиотека, что и в движке;
//! кроссится под Android/iOS), НЕ в открытом виде и без зависимости от OS-keyring-демона.
//!
//! Формат файла (binary), v4 — текущий:
//! ```text
//! "CPQV" | ver(1)=4 | m_kib(u32 BE) | t(u32 BE) | p(u32 BE) | salt(16) | nonce(12)
//!        | slots_len(u16 BE) | slots(CBOR) | AES-256-GCM(ct‖tag)
//! ```
//! Открытый текст = CBOR(VaultData). **Всё, что до шифртекста (заголовок И таблица слотов), входит
//! в AAD** (L-2/аудит-4 + C9): правка любого поля ломает проверку тега.
//!
//! **Ключевая схема (C9, key slots — как у LUKS/FileVault).** Данные шифрует случайный мастер-ключ
//! `MK` (32 B), а сам `MK` лежит в файле столько раз, сколькими способами хранилище разрешено
//! открыть:
//!   * слот `password` — `MK`, завёрнутый в AES-256-GCM под `Argon2id(passphrase, salt, m/t/p)`;
//!   * слот `platform` — `MK`, завёрнутый **платформенным** хранилищем ключей (Android Keystore,
//!     ключ неэкспортируемый и требует биометрии; см. [`Vault::set_platform_slot`]). Блоб для нас
//!     непрозрачен: развернуть его умеет только та же ОС на том же устройстве.
//!
//! Так пароль перестаёт быть ключом файла и становится ОДНИМ ИЗ способов добыть ключ. Практическая
//! разница: смена пароля не трогает `MK` (биометрия переживает её), а платформенный слот на чужом
//! устройстве — мёртвый груз (ключа в TEE нет), и хранилище там открывается по-старому, паролем.
//! Стойкость к офлайн-перебору не меняется: слот `platform` без TEE не даёт ничего, и украденный
//! файл по-прежнему упирается в Argon2id над паролем.
//!
//! Неверный пароль → AEAD слота не проходит → `open` возвращает ошибку (аутентификация AEAD =
//! проверка пароля, отдельный верификатор не нужен).
//!
//! Читаются и прозрачно пере-сохраняются как v4: **v3** (ключ файла = Argon2id(пароль), заголовок в
//! AAD), **v2** (то же, но AAD пустой) и **v1** (legacy PBKDF2-HMAC-SHA256 — миграция на Argon2id
//! при первом открытии, C1/аудит-3). Обратной дороги нет: v4 старым клиентом не читается — ровно
//! как было при миграциях v1→v2→v3.

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
/// v4 (C9) = мастер-ключ в слотах (пароль + платформенный). v3 (L-2/аудит-4) = ключ файла выведен
/// из пароля, заголовок под AAD; v2 = то же без AAD; v1 = legacy PBKDF2. Все три читаются и
/// прозрачно пере-сохраняются как v4 при первом успешном открытии.
const VERSION: u8 = 4;
const VERSION_DIRECT_KEY_AAD: u8 = 3;
const VERSION_ARGON_NO_AAD: u8 = 2;
const VERSION_PBKDF2: u8 = 1;
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
/// Длина мастер-ключа `MK` (он же ключ AES-256-GCM для полезной нагрузки).
const MK_LEN: usize = 32;
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

// ────────────────────────────── C9: слоты мастер-ключа (v4) ──────────────────────────────

/// Слот пароля: `MK` под ключом `Argon2id(passphrase, salt, m/t/p)` из заголовка.
const SLOT_PASSWORD: u8 = 1;
/// Слот платформенного хранилища ключей: `MK`, завёрнутый ОС (Android Keystore под биометрией).
/// Для нас блоб непрозрачен — мы его только храним и отдаём обратно платформе.
const SLOT_PLATFORM: u8 = 2;

/// Потолок числа слотов и размера их таблицы. Границы нужны по той же причине, что и границы
/// Argon2-параметров (L-2): таблица читается ДО того, как AEAD подтвердит подлинность файла, и
/// подложенный файл иначе диктует нам объём разбора. Реальный файл держит 1–2 слота по ~60–100 B.
const MAX_SLOTS: usize = 8;
const MAX_SLOTS_BLOB: usize = 8 * 1024;

/// Завёрнутый `MK` = `nonce(12) ‖ AES-256-GCM(MK)‖tag`.
const WRAPPED_MK_LEN: usize = NONCE_LEN + MK_LEN + 16;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct KeySlot {
    /// [`SLOT_PASSWORD`] | [`SLOT_PLATFORM`]. Незнакомый вид слота (файл от более новой версии)
    /// не ошибка: он просто не подойдёт ни одному способу открытия — пропускаем и сохраняем как есть.
    kind: u8,
    /// Завёрнутый мастер-ключ. Для `password` — [`WRAPPED_MK_LEN`] байт нашего формата, для
    /// `platform` — непрозрачный блоб ОС (у Android Keystore это `IV(12) ‖ ct(32) ‖ tag(16)`).
    #[serde(with = "serde_bytes")]
    wrapped: Vec<u8>,
    /// Метка платформы (`"android-keystore"`) — диагностика и различение слотов, когда их станет
    /// больше одного (Windows Hello и т.д.). Для слота пароля пустая.
    #[serde(default)]
    label: String,
}

/// Платформенный слот, прочитанный из файла без пароля (для экрана блокировки).
#[derive(Clone, Debug)]
pub struct PlatformSlot {
    /// Непрозрачный блоб ОС: развернуть его умеет только то же устройство после аутентификации.
    pub blob: Vec<u8>,
    /// Метка платформы (`"android-keystore"`).
    pub label: String,
}

/// AAD слота пароля: домен ‖ версия ‖ Argon2-параметры ‖ salt. Привязывает завёрнутый `MK` к тем
/// самым параметрам вывода ключа, которыми он был завёрнут — подмена `m/t/p/salt` в заголовке (в
/// том числе на более слабые) ломает разворачивание, а не тихо меняет стоимость перебора.
///
/// Nonce полезной нагрузки сюда НЕ входит намеренно: он меняется при каждой записи файла, а слот
/// пароля переписывать на каждое сохранение нечем — пароля в памяти нет.
fn pass_slot_aad(m_kib: u32, t: u32, p: u32, salt: &[u8; SALT_LEN]) -> Vec<u8> {
    let mut a = Vec::with_capacity(64);
    a.extend_from_slice(b"CitadelPQVPN/vault/v4/slot/pass");
    a.push(VERSION);
    a.extend_from_slice(&m_kib.to_be_bytes());
    a.extend_from_slice(&t.to_be_bytes());
    a.extend_from_slice(&p.to_be_bytes());
    a.extend_from_slice(salt);
    a
}

/// Завернуть `MK` под ключом слота (KEK).
fn wrap_mk(kek: &LessSafeKey, mk: &[u8; MK_LEN], aad: &[u8]) -> Result<Vec<u8>> {
    let rng = SystemRandom::new();
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce).map_err(|_| anyhow!("RNG"))?;
    let mut buf = mk.to_vec();
    kek.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad),
        &mut buf,
    )
    .map_err(|_| anyhow!("завернуть мастер-ключ (AEAD)"))?;
    let mut out = Vec::with_capacity(WRAPPED_MK_LEN);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buf);
    Ok(out)
}

/// Развернуть `MK`. `None` — ключ слота не тот (для слота пароля это и есть «неверный пароль»).
fn unwrap_mk(kek: &LessSafeKey, wrapped: &[u8], aad: &[u8]) -> Option<[u8; MK_LEN]> {
    if wrapped.len() != WRAPPED_MK_LEN {
        return None;
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&wrapped[..NONCE_LEN]);
    let mut buf = wrapped[NONCE_LEN..].to_vec();
    let mk = {
        let plain = kek
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(aad), &mut buf)
            .ok()?;
        let mut mk = [0u8; MK_LEN];
        if plain.len() != MK_LEN {
            return None;
        }
        mk.copy_from_slice(plain);
        mk
    };
    buf.zeroize();
    Some(mk)
}

/// Ключ AES-256-GCM полезной нагрузки из мастер-ключа.
fn payload_key(mk: &[u8; MK_LEN]) -> Result<LessSafeKey> {
    let unbound = UnboundKey::new(&AES_256_GCM, mk).map_err(|_| anyhow!("ключ AEAD"))?;
    Ok(LessSafeKey::new(unbound))
}

fn random_mk() -> Result<[u8; MK_LEN]> {
    let mut mk = [0u8; MK_LEN];
    SystemRandom::new().fill(&mut mk).map_err(|_| anyhow!("RNG"))?;
    Ok(mk)
}

/// Разобранный заголовок v4 (всё, что лежит в файле открытым текстом).
struct V4Header {
    m_kib: u32,
    t: u32,
    p: u32,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    slots: Vec<KeySlot>,
    /// Граница AAD и начало шифртекста: длина всего, что предшествует полезной нагрузке.
    aad_end: usize,
}

/// **Ф1/F10** (`docs/CWE-REVIEW-PLAN-2026-08.md`, Приложение A): публичная точка входа фаззера в
/// разбор ОТКРЫТОЙ части файла хранилища — всё, что происходит **до** криптографии.
///
/// Противник здесь — тот, кто подменил файл: бэкап, синхронизация, сосед по устройству, а в
/// пределе — скомпрометированный клиент, которому подсунули чужое хранилище. Инвариант: любые
/// байты дают `Err`, а не панику, не аллокацию по длине из файла и не запуск Argon2 с параметрами
/// из этого же файла. Возвращает `()`, чтобы не выносить наружу внутренний тип заголовка.
pub fn probe_header(raw: &[u8]) -> Result<()> {
    parse_v4(raw).map(|_| ())
}

/// Разобрать открытую часть файла v4. Все границы проверяются ДО криптографии: таблица слотов —
/// недоверенный ввод ровно в том же смысле, что и Argon2-параметры (L-2).
fn parse_v4(raw: &[u8]) -> Result<V4Header> {
    if raw.len() < HEADER_LEN_V2 + SLOTS_LEN_FIELD {
        bail!("повреждённый v4-заголовок хранилища");
    }
    let m_kib = u32::from_be_bytes(raw[5..9].try_into().unwrap());
    let t = u32::from_be_bytes(raw[9..13].try_into().unwrap());
    let p = u32::from_be_bytes(raw[13..17].try_into().unwrap());
    check_argon_params(m_kib, t, p)?;
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&raw[17..17 + SALT_LEN]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&raw[17 + SALT_LEN..HEADER_LEN_V2]);

    let slots_len = u16::from_be_bytes(
        raw[HEADER_LEN_V2..HEADER_LEN_V2 + SLOTS_LEN_FIELD].try_into().unwrap(),
    ) as usize;
    let start = HEADER_LEN_V2 + SLOTS_LEN_FIELD;
    let aad_end = start.checked_add(slots_len).filter(|e| *e <= raw.len()).ok_or_else(|| {
        anyhow!("таблица слотов ключа не помещается в файл — хранилище повреждено")
    })?;
    if slots_len > MAX_SLOTS_BLOB {
        bail!("таблица слотов ключа неправдоподобно велика ({slots_len} б) — файл повреждён или подложен");
    }
    let slots: Vec<KeySlot> = ciborium::from_reader(&raw[start..aad_end])
        .context("разобрать таблицу слотов ключа (CBOR)")?;
    if slots.len() > MAX_SLOTS {
        bail!("слотов ключа больше допустимого: {}", slots.len());
    }
    Ok(V4Header { m_kib, t, p, salt, nonce, slots, aad_end })
}

/// Общий хвост миграции v1/v2/v3 → v4: рождаем новый мастер-ключ, заворачиваем его в слот пароля и
/// перезаписываем файл. Профили при этом не меняются — меняется только то, как хранится ключ.
///
/// Мастер-ключ именно НОВЫЙ, а не «старый производный»: иначе ключ файла навсегда остался бы
/// функцией пароля, и смена пароля продолжала бы перешифровывать всё, а платформенный слот —
/// слетать при каждой такой смене.
fn migrate_to_v4(
    path: PathBuf,
    passphrase: &str,
    data: VaultData,
    from: &str,
) -> std::result::Result<Vault, VaultOpenError> {
    let mk = random_mk().map_err(VaultOpenError::Unavailable)?;
    let v = Vault::with_master_key(path, mk, passphrase, data)
        .map_err(VaultOpenError::Unavailable)?;
    eprintln!("[vault] хранилище мигрировано {from} → v4 (мастер-ключ в слотах)");
    Ok(v)
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
/// У v4 фиксированная часть заголовка байт-в-байт та же, что у v2/v3 (те же поля и порядок), а за
/// ней идёт `slots_len(u16 BE) ‖ slots(CBOR)` — поэтому разбор заголовка общий, отличается только
/// то, что делается с выведенным из пароля ключом: в v2/v3 это ключ файла, в v4 — ключ слота.
const HEADER_LEN_V2: usize = 4 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN;
const HEADER_LEN_V1: usize = 4 + 1 + 4 + SALT_LEN + NONCE_LEN;
/// Длина поля `slots_len` (u16 BE) сразу за фиксированным заголовком v4.
const SLOTS_LEN_FIELD: usize = 2;

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
    /// M-9: **устройственный** Layer-1 ключ, рождённый на этом устройстве при активации первичной
    /// ссылки. С момента активации подключения идут им, а ключ из ссылки больше не используется
    /// (издатель его и не примет — запись `consumed`). `None` — профиль из многоразовой ссылки
    /// (поведение до M-9) либо активация ещё не проходила.
    ///
    /// Хранится ЗДЕСЬ, а не в подменённой ссылке, ровно по одной причине: ссылка обязана остаться
    /// нетронутой до подтверждения активации издателем. Иначе оборванная на полпути активация
    /// (потеряли ответ, сел телефон) оставляла бы устройство без обоих ключей — с новым, которого
    /// сервер не знает, и без старого, который мы бы уже затёрли.
    #[serde(default, with = "serde_bytes")]
    pub device_seed: Option<[u8; 32]>,
    /// M-9: издатель подтвердил активацию (`device_seed` — рабочий ключ). Пока `false`, ключ уже
    /// создан и сохранён, но подписка на нём ещё не числится, и Layer-1 идёт ключом из ссылки.
    #[serde(default)]
    pub enrolled: bool,
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

/// Разблокированное хранилище профилей. Держит мастер-ключ в памяти, пока открыто;
/// каждое изменение немедленно пере-шифровывает и атомарно пишет файл.
pub struct Vault {
    path: PathBuf,
    key: LessSafeKey,
    /// C9: мастер-ключ в сыром виде. Нужен именно так (а не только внутри `key`): им
    /// перезаворачиваются слоты — при смене пароля и при включении биометрии. Затирается в `drop`.
    mk: [u8; MK_LEN],
    salt: [u8; SALT_LEN],
    /// Argon2id-параметры СЛОТА ПАРОЛЯ этого файла. Хранятся в файле → future-bump читается.
    m_kib: u32,
    t: u32,
    p: u32,
    /// C9: способы добыть `MK` (слот пароля обязателен, платформенный — по желанию пользователя).
    slots: Vec<KeySlot>,
    data: VaultData,
}

impl Drop for Vault {
    /// S1.3/M7: при закрытии хранилища затираем расшифрованные профили (uri несёт pin/psk/seed)
    /// и мастер-ключ. Производный ключ (`LessSafeKey`) чистит aws-lc-rs; `save` уже перезаписал
    /// plaintext шифртекстом.
    fn drop(&mut self) {
        for p in &mut self.data.profiles {
            p.uri.zeroize();
        }
        self.mk.zeroize();
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
        Self::with_master_key(path.as_ref().to_path_buf(), random_mk()?, passphrase, VaultData::default())
    }

    /// C9: собрать хранилище вокруг готового `MK` со слотом пароля и записать файл. Общий шаг для
    /// [`Vault::create`] и для миграции v1/v2/v3 (там `data` уже расшифрована старым ключом).
    fn with_master_key(
        path: PathBuf,
        mk: [u8; MK_LEN],
        passphrase: &str,
        data: VaultData,
    ) -> Result<Vault> {
        let rng = SystemRandom::new();
        let mut salt = [0u8; SALT_LEN];
        rng.fill(&mut salt).map_err(|_| anyhow!("RNG"))?;
        let kek = derive_key_argon2(passphrase, &salt, ARGON_M_KIB, ARGON_T, ARGON_P)?;
        let wrapped = wrap_mk(&kek, &mk, &pass_slot_aad(ARGON_M_KIB, ARGON_T, ARGON_P, &salt))?;
        let v = Vault {
            path,
            key: payload_key(&mk)?,
            mk,
            salt,
            m_kib: ARGON_M_KIB,
            t: ARGON_T,
            p: ARGON_P,
            slots: vec![KeySlot { kind: SLOT_PASSWORD, wrapped, label: String::new() }],
            data,
        };
        v.save()?;
        Ok(v)
    }

    /// Открыть существующее хранилище мастер-паролем. Неверный пароль → ошибка. v4 (слоты) —
    /// штатно; v1/v2/v3 расшифровываются старым способом и МИГРИРУЮТ на v4 (C1/C9).
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
        let raw = Self::read_raw(&path)?;
        match raw[4] {
            // v4 — мастер-ключ в слотах; v3 — ключ файла из пароля, заголовок под AAD;
            // v2 — то же, но AAD пустой. Все дочитываются и мигрируют на v4.
            VERSION => Self::open_v4(path, passphrase, &raw),
            VERSION_DIRECT_KEY_AAD => Self::open_legacy_argon(path, passphrase, &raw, true),
            VERSION_ARGON_NO_AAD => Self::open_legacy_argon(path, passphrase, &raw, false),
            VERSION_PBKDF2 => Self::open_v1_migrate(path, passphrase, &raw),
            v => Err(VaultOpenError::Unavailable(anyhow!(
                "неподдерживаемая версия хранилища: {v}"
            ))),
        }
    }

    /// Прочитать файл и убедиться, что это вообще наше хранилище. Общий шаг для всех путей
    /// открытия и для чтения таблицы слотов БЕЗ пароля ([`Vault::platform_slot_blob`]).
    fn read_raw(path: &Path) -> std::result::Result<Vec<u8>, VaultOpenError> {
        let raw = std::fs::read(path)
            .with_context(|| format!("читать хранилище {}", path.display()))
            .map_err(VaultOpenError::Unavailable)?;
        if raw.len() < 5 || &raw[0..4] != MAGIC {
            return Err(VaultOpenError::Unavailable(anyhow!(
                "повреждённый файл хранилища (не CitadelPQVPN vault): {}",
                path.display()
            )));
        }
        Ok(raw)
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

    /// v4: заголовок + таблица слотов → развернуть `MK` слотом ПАРОЛЯ → расшифровать профили.
    fn open_v4(
        path: PathBuf,
        passphrase: &str,
        raw: &[u8],
    ) -> std::result::Result<Vault, VaultOpenError> {
        let h = parse_v4(raw).map_err(VaultOpenError::Unavailable)?;
        let kek = derive_key_argon2(passphrase, &h.salt, h.m_kib, h.t, h.p)
            .map_err(VaultOpenError::Unavailable)?;
        let aad = pass_slot_aad(h.m_kib, h.t, h.p, &h.salt);
        // Слот не открылся = пароль не тот (штатный случай), а не поломка машины. Слотов пароля
        // в норме один, но перебираем все: так добавление второго (напр. «пароль восстановления»)
        // не потребует трогать путь открытия.
        let mk = h
            .slots
            .iter()
            .filter(|s| s.kind == SLOT_PASSWORD)
            .find_map(|s| unwrap_mk(&kek, &s.wrapped, &aad))
            .ok_or(VaultOpenError::WrongPassword)?;
        let (m_kib, t) = (h.m_kib, h.t);
        let mut v = Self::open_payload(path, raw, h, mk)?;
        // Файл сделан на слабых параметрах (старая версия клиента) — поднимаем до текущих прямо
        // сейчас: пароль в руках, момент единственный. Мастер-ключ при этом НЕ меняется, поэтому
        // платформенный слот (биометрия) переживает апгрейд. Не смогли пере-записать — не беда,
        // работаем на прочитанных параметрах (открытие хранилища важнее апгрейда его стойкости).
        if argon_cost(m_kib, t) < argon_cost(ARGON_M_KIB, ARGON_T) {
            match v.rewrap_password(passphrase) {
                Ok(()) => eprintln!(
                    "[vault] параметры Argon2id подняты: m={m_kib}KiB,t={t} → m={ARGON_M_KIB}KiB,t={ARGON_T}"
                ),
                Err(e) => eprintln!("[vault] апгрейд параметров Argon2id пропущен: {e:#}"),
            }
        }
        Ok(v)
    }

    /// C9: открыть хранилище **платформенным** мастер-ключом — тем, что вернуло хранилище ключей
    /// ОС после успешной биометрии (см. [`Vault::set_platform_slot`]). Пароль здесь не участвует:
    /// Argon2id не считается вовсе, поэтому разблокировка мгновенная.
    ///
    /// `WrongPassword` тут означает «ключ не подошёл»: файл подменили либо блоб от другого
    /// хранилища. Для UI это не «неверный палец» (палец проверила ОС) — это «биометрия больше не
    /// открывает ЭТО хранилище, войдите паролем».
    pub fn open_with_master_key(
        path: impl AsRef<Path>,
        mk: &[u8],
    ) -> std::result::Result<Vault, VaultOpenError> {
        let path = path.as_ref().to_path_buf();
        let raw = Self::read_raw(&path)?;
        if raw[4] != VERSION {
            return Err(VaultOpenError::Unavailable(anyhow!(
                "хранилище версии {} не умеет открываться платформенным ключом",
                raw[4]
            )));
        }
        let mk: [u8; MK_LEN] = mk.try_into().map_err(|_| {
            VaultOpenError::Unavailable(anyhow!("платформенный ключ не той длины ({} б)", mk.len()))
        })?;
        let h = parse_v4(&raw).map_err(VaultOpenError::Unavailable)?;
        Self::open_payload(path, &raw, h, mk)
    }

    /// Общий хвост открытия v4: расшифровать полезную нагрузку готовым `MK` и собрать `Vault`.
    fn open_payload(
        path: PathBuf,
        raw: &[u8],
        h: V4Header,
        mk: [u8; MK_LEN],
    ) -> std::result::Result<Vault, VaultOpenError> {
        let key = payload_key(&mk).map_err(VaultOpenError::Unavailable)?;
        let mut in_out = raw[h.aad_end..].to_vec();
        let plain = key
            .open_in_place(
                Nonce::assume_unique_for_key(h.nonce),
                header_aad(&raw[..h.aad_end]), // заголовок + таблица слотов
                &mut in_out,
            )
            .map_err(|_| VaultOpenError::WrongPassword)?;
        let data: VaultData = ciborium::from_reader(&plain[..])
            .context("разобрать профили (CBOR)")
            .map_err(VaultOpenError::Unavailable)?;
        in_out.zeroize(); // S1.3/M7: затереть расшифрованный plaintext профилей (секреты)
        Ok(Vault {
            path,
            key,
            mk,
            salt: h.salt,
            m_kib: h.m_kib,
            t: h.t,
            p: h.p,
            slots: h.slots,
            data,
        })
    }

    /// v2/v3: Argon2id-заголовок `m_kib‖t‖p‖salt‖nonce` → derive → decrypt → МИГРАЦИЯ на v4.
    /// `aad = true` (v3) — заголовок входит в AAD (L-2); `false` (v2) — как раньше, пустой AAD.
    fn open_legacy_argon(
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
        migrate_to_v4(path, passphrase, data, if aad { "v3" } else { "v2" })
    }

    /// v1 (legacy PBKDF2): расшифровать старым ключом, затем МИГРИРОВАТЬ на v4 — новый мастер-ключ
    /// в слоте под Argon2id (прозрачный upgrade при первом открытии, C1/C9).
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
        migrate_to_v4(path, passphrase, data, "v1 (PBKDF2)")
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
            device_seed: None,
            enrolled: false,
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

    /// M-9: сохранить устройственный ключ ДО обращения к издателю (ключ рождён, но подписка на
    /// нём ещё не числится). Порядок именно такой: сначала на диск, потом в сеть — иначе успешная
    /// у издателя активация с потерянным ответом оставила бы устройство без доступа навсегда.
    pub fn set_device_seed(&mut self, id: &str, seed: &[u8; 32]) -> Result<()> {
        let p = self
            .data
            .profiles
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or_else(|| anyhow!("профиль не найден: {id}"))?;
        p.device_seed = Some(*seed);
        p.enrolled = false;
        self.save()
    }

    /// M-9: издатель подтвердил активацию — с этого момента Layer-1 идёт устройственным ключом.
    pub fn mark_enrolled(&mut self, id: &str) -> Result<()> {
        let p = self
            .data
            .profiles
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or_else(|| anyhow!("профиль не найден: {id}"))?;
        if p.device_seed.is_none() {
            bail!("нечего подтверждать: устройственный ключ не создан");
        }
        p.enrolled = true;
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
        self.rewrap_password(new_passphrase)
    }

    /// C9: перезавернуть мастер-ключ в слот пароля под `passphrase` с ТЕКУЩИМИ Argon2-параметрами
    /// (новый salt + новый KEK). Общий шаг для смены пароля и для апгрейда параметров старого
    /// хранилища.
    ///
    /// Сам `MK` НЕ меняется — и это главное практическое следствие перехода на слоты: смена пароля
    /// больше не отзывает биометрию (раньше ключ файла был функцией пароля, и любой платформенный
    /// слот пришлось бы отзывать вместе с ним).
    fn rewrap_password(&mut self, passphrase: &str) -> Result<()> {
        let rng = SystemRandom::new();
        let mut salt = [0u8; SALT_LEN];
        rng.fill(&mut salt).map_err(|_| anyhow!("RNG"))?;
        let kek = derive_key_argon2(passphrase, &salt, ARGON_M_KIB, ARGON_T, ARGON_P)?;
        let wrapped =
            wrap_mk(&kek, &self.mk, &pass_slot_aad(ARGON_M_KIB, ARGON_T, ARGON_P, &salt))?;
        let prev = (self.salt, self.m_kib, self.t, self.p, self.slots.clone());
        self.salt = salt;
        self.m_kib = ARGON_M_KIB;
        self.t = ARGON_T;
        self.p = ARGON_P;
        self.put_slot(SLOT_PASSWORD, wrapped, String::new());
        if let Err(e) = self.save() {
            // откат: диск — источник истины (иначе в памяти файл заперт новым паролем, а на диске
            // старым, и следующая же запись сделала бы его нечитаемым обоими)
            (self.salt, self.m_kib, self.t, self.p, self.slots) = prev;
            return Err(e);
        }
        Ok(())
    }

    /// Заменить единственный слот данного вида (или добавить, если его не было). `retain` перед
    /// вставкой — не перестраховка: два слота одного вида означали бы, что старый способ открытия
    /// продолжает работать после «смены», а это тихая дыра.
    fn put_slot(&mut self, kind: u8, wrapped: Vec<u8>, label: String) {
        self.slots.retain(|s| s.kind != kind);
        self.slots.push(KeySlot { kind, wrapped, label });
        self.slots.sort_by_key(|s| s.kind); // стабильный порядок в файле: пароль, затем платформа
    }

    // ── C9: платформенный слот (Android Keystore под биометрией; опционально) ──

    /// **Мастер-ключ хранилища в сыром виде** — чтобы платформенное хранилище ключей завернуло его
    /// своим неэкспортируемым ключом. Единственный законный потребитель — FFI-слой приложения,
    /// который сразу передаёт эти байты в ОС и затирает свою копию.
    ///
    /// Метод намеренно называется прямо, а не `secret()`/`token()`: тот, кто его вызывает, обязан
    /// понимать, что держит в руках ключ ко ВСЕМУ хранилищу.
    pub fn master_key(&self) -> [u8; MK_LEN] {
        self.mk
    }

    /// Есть ли у этого хранилища платформенный слот (биометрия включена).
    pub fn has_platform_slot(&self) -> bool {
        self.slots.iter().any(|s| s.kind == SLOT_PLATFORM)
    }

    /// Включить платформенную разблокировку: положить в файл блоб, который вернула ОС, завернув
    /// [`Vault::master_key`]. Повторный вызов заменяет прежний блоб (перевыпуск ключа в Keystore).
    pub fn set_platform_slot(&mut self, blob: Vec<u8>, label: &str) -> Result<()> {
        if blob.is_empty() || blob.len() > MAX_SLOTS_BLOB / 2 {
            bail!("платформенный блоб неправдоподобного размера ({} б)", blob.len());
        }
        let prev = self.slots.clone();
        self.put_slot(SLOT_PLATFORM, blob, sanitize_name(label));
        if let Err(e) = self.save() {
            self.slots = prev;
            return Err(e);
        }
        Ok(())
    }

    /// Выключить платформенную разблокировку (слот из файла долой). Ключ в самом Keystore удаляет
    /// платформенный слой — здесь мы отвечаем только за файл. Нет слота — no-op без перезаписи.
    pub fn clear_platform_slot(&mut self) -> Result<()> {
        if !self.has_platform_slot() {
            return Ok(());
        }
        let prev = self.slots.clone();
        self.slots.retain(|s| s.kind != SLOT_PLATFORM);
        if let Err(e) = self.save() {
            self.slots = prev;
            return Err(e);
        }
        Ok(())
    }

    /// Блоб платформенного слота, прочитанный из файла **без пароля** — экран блокировки обязан
    /// узнать, предлагать ли отпечаток, ДО того как что-либо разблокировано. Секрета здесь нет:
    /// блоб бесполезен без ключа из TEE того же устройства.
    ///
    /// `None` — биометрия не настроена либо файл не годится (нет, не наш, старой версии, побит):
    /// во всех этих случаях UI просто не показывает кнопку, а причину человек увидит на обычном
    /// пути с паролем — там ошибки разобраны по смыслу ([`VaultOpenError`]).
    pub fn platform_slot_blob(path: impl AsRef<Path>) -> Option<PlatformSlot> {
        let raw = Self::read_raw(path.as_ref()).ok()?;
        if raw[4] != VERSION {
            return None;
        }
        let h = parse_v4(&raw)
            .inspect_err(|e| eprintln!("[vault] таблица слотов не читается: {e:#}"))
            .ok()?;
        h.slots
            .into_iter()
            .find(|s| s.kind == SLOT_PLATFORM)
            .map(|s| PlatformSlot { blob: s.wrapped, label: s.label })
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
        out.push(VERSION); // v4 = мастер-ключ в слотах, заголовок и слоты под AAD
        out.extend_from_slice(&self.m_kib.to_be_bytes());
        out.extend_from_slice(&self.t.to_be_bytes());
        out.extend_from_slice(&self.p.to_be_bytes());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&nonce);
        debug_assert_eq!(out.len(), HEADER_LEN_V2);

        // C9: таблица слотов идёт следом и тоже входит в AAD. Поэтому вычеркнуть слот пароля из
        // файла (оставив только биометрический) или подставить чужой набор слотов нельзя молча —
        // тег полезной нагрузки перестанет сходиться.
        let mut slots = Vec::new();
        ciborium::into_writer(&self.slots, &mut slots).context("сериализовать слоты ключа (CBOR)")?;
        let slots_len = u16::try_from(slots.len())
            .map_err(|_| anyhow!("таблица слотов ключа не помещается в формат"))?;
        out.extend_from_slice(&slots_len.to_be_bytes());
        out.extend_from_slice(&slots);

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
            exp: None,
            enroll: false,
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

    /// L-2/C9: старый файл v2 (заголовок не в AAD) открывается тем же паролем и молча
    /// пере-сохраняется как v4; попытка выдать v4 за v2 (сброс версии, чтобы «отключить» AAD)
    /// ломает AEAD — ровно то, ради чего заголовок и попал в AAD.
    #[test]
    fn v2_upgrades_to_v4_and_version_downgrade_breaks_aead() {
        let path = tmp_path("aad-upgrade");
        let pass = "aadpass12345";
        let uri = sample_uri();
        // v2-файл: ключ файла выведен прямо из пароля, AAD пустой (формат до L-2).
        let mut data = VaultData::default();
        data.profiles.push(sample_profile("p", &uri));
        write_legacy_argon(&path, pass, &data, ARGON_M_KIB, ARGON_T, ARGON_P, false);
        assert_eq!(std::fs::read(&path).unwrap()[4], VERSION_ARGON_NO_AAD, "исходно v2");

        let v = Vault::open(&path, pass).unwrap();
        assert_eq!(v.list().len(), 1, "профиль пережил апгрейд формата");
        drop(v);
        let raw = std::fs::read(&path).unwrap();
        assert_eq!(raw[4], VERSION, "после открытия файл стал v4");
        assert!(Vault::open(&path, pass).is_ok(), "v4 открывается тем же паролем");

        // downgrade-атака на формат: объявляем v4-файл как v2 (AAD «выключен») → тег не сойдётся
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

    /// Апгрейд слабых Argon2-параметров при открытии. C9: апгрейд перезаворачивает СЛОТ ПАРОЛЯ и
    /// не трогает мастер-ключ — поэтому платформенный слот (биометрия) обязан его пережить.
    #[test]
    fn weak_argon_params_upgraded_on_open() {
        let path = tmp_path("argon-upgrade");
        let pass = "upgradepass1";
        let uri = sample_uri();
        let weak = 19 * 1024;
        {
            // файл со слабыми параметрами (прежний OWASP-минимум: m=19 MiB, t=2)
            let mut v = Vault::create(&path, pass).unwrap();
            v.add("p", &uri).unwrap();
            v.set_platform_slot(b"opaque-keystore-blob".to_vec(), "android-keystore").unwrap();
            weaken_password_slot(&mut v, pass, weak, 2);
        }
        let raw = std::fs::read(&path).unwrap();
        assert_eq!(u32::from_be_bytes(raw[5..9].try_into().unwrap()), 19 * 1024, "исходно слабый");

        let v = Vault::open(&path, pass).unwrap();
        assert_eq!(v.list().len(), 1, "профили пережили апгрейд");
        assert!(v.has_platform_slot(), "биометрия пережила апгрейд параметров");
        drop(v);
        let raw = std::fs::read(&path).unwrap();
        assert_eq!(u32::from_be_bytes(raw[5..9].try_into().unwrap()), ARGON_M_KIB);
        assert_eq!(u32::from_be_bytes(raw[9..13].try_into().unwrap()), ARGON_T);
        assert!(Vault::open(&path, pass).is_ok(), "тот же пароль открывает поднятый файл");
        assert!(Vault::open(&path, "wrongpass1").is_err());
        std::fs::remove_file(&path).ok();
    }

    /// C1/C9: старый v1-файл (PBKDF2) читается и МИГРИРУЕТ на v4 (Argon2id + слоты) при открытии —
    /// прозрачный upgrade без потери профилей; после миграции файл — v4, повторное открытие работает.
    #[test]
    fn v1_pbkdf2_migrates_to_v4() {
        let path = tmp_path("migrate");
        let uri = sample_uri();
        let pass = "correct horse";
        // построить legacy v1-файл (PBKDF2) с одним профилем — формат до C1.
        let mut data = VaultData::default();
        data.profiles.push(sample_profile("nl", &uri));
        write_legacy_v1(&path, pass, &data);
        assert_eq!(std::fs::read(&path).unwrap()[4], VERSION_PBKDF2, "исходно v1");

        // открытие мигрирует на v4
        let v = Vault::open(&path, pass).unwrap();
        assert_eq!(v.list().len(), 1);
        assert_eq!(v.list()[0].uri, uri);
        drop(v);
        assert_eq!(std::fs::read(&path).unwrap()[4], VERSION, "после миграции — v4 (слоты)");
        // повторное открытие тем же паролем (уже Argon2id) работает
        assert!(Vault::open(&path, pass).is_ok());
        assert!(Vault::open(&path, "wrongpass").is_err());
        std::fs::remove_file(&path).ok();
    }

    fn sample_profile(name: &str, uri: &str) -> Profile {
        Profile {
            id: format!("id-{name}"),
            name: name.into(),
            uri: uri.into(),
            created: 1,
            last_exit: None,
            device_seed: None,
            enrolled: false,
        }
    }

    /// Собрать legacy-файл v2/v3 (ключ файла = Argon2id(пароль)) — для тестов миграции на v4:
    /// write-путь этих версий из прода удалён, а читать их мы обязаны.
    fn write_legacy_argon(
        path: &std::path::Path,
        passphrase: &str,
        data: &VaultData,
        m_kib: u32,
        t: u32,
        p: u32,
        aad: bool,
    ) {
        let rng = SystemRandom::new();
        let mut salt = [0u8; SALT_LEN];
        rng.fill(&mut salt).unwrap();
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill(&mut nonce).unwrap();
        let key = derive_key_argon2(passphrase, &salt, m_kib, t, p).unwrap();

        let mut header = Vec::new();
        header.extend_from_slice(MAGIC);
        header.push(if aad { VERSION_DIRECT_KEY_AAD } else { VERSION_ARGON_NO_AAD });
        header.extend_from_slice(&m_kib.to_be_bytes());
        header.extend_from_slice(&t.to_be_bytes());
        header.extend_from_slice(&p.to_be_bytes());
        header.extend_from_slice(&salt);
        header.extend_from_slice(&nonce);

        let mut in_out = Vec::new();
        ciborium::into_writer(data, &mut in_out).unwrap();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            header_aad(if aad { &header } else { &[] }),
            &mut in_out,
        )
        .unwrap();
        let mut out = header;
        out.extend_from_slice(&in_out);
        std::fs::write(path, out).unwrap();
    }

    /// Перезавернуть слот пароля СЛАБЫМИ Argon2-параметрами (эмуляция файла от старого клиента) и
    /// записать файл. Мастер-ключ не меняется — как и при штатном перезаворачивании.
    fn weaken_password_slot(v: &mut Vault, passphrase: &str, m_kib: u32, t: u32) {
        let mut salt = [0u8; SALT_LEN];
        SystemRandom::new().fill(&mut salt).unwrap();
        let kek = derive_key_argon2(passphrase, &salt, m_kib, t, ARGON_P).unwrap();
        let wrapped = wrap_mk(&kek, &v.mk, &pass_slot_aad(m_kib, t, ARGON_P, &salt)).unwrap();
        v.salt = salt;
        v.m_kib = m_kib;
        v.t = t;
        v.put_slot(SLOT_PASSWORD, wrapped, String::new());
        v.save().unwrap();
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

    // ─────────────────────────── C9: слоты ключа и платформенная разблокировка ───────────────────

    /// Главный сценарий биометрии: мастер-ключ открывает хранилище без пароля, а смена пароля его
    /// НЕ отзывает. Именно ради второго свойства ключ файла и перестал быть функцией пароля —
    /// иначе каждая смена пароля просила бы человека заново прикладывать палец.
    #[test]
    fn platform_slot_unlocks_and_survives_password_change() {
        let path = tmp_path("platform-unlock");
        let uri = sample_uri();
        let mk = {
            let mut v = Vault::create(&path, "firstpass1").unwrap();
            v.add("nl", &uri).unwrap();
            let mk = v.master_key(); // это отдаётся Keystore на обёртку
            v.set_platform_slot(b"blob-from-keystore".to_vec(), "android-keystore").unwrap();
            assert!(v.has_platform_slot());
            mk
        };

        let v = Vault::open_with_master_key(&path, &mk).unwrap();
        assert_eq!(v.list()[0].uri, uri, "хранилище открылось платформенным ключом");
        drop(v);

        let mut v = Vault::open(&path, "firstpass1").unwrap();
        v.change_password("secondpass1").unwrap();
        drop(v);
        assert!(Vault::open(&path, "firstpass1").is_err(), "старый пароль отозван");
        assert!(Vault::open(&path, "secondpass1").is_ok(), "новый пароль работает");
        let v = Vault::open_with_master_key(&path, &mk).unwrap();
        assert!(v.has_platform_slot(), "смена пароля не отозвала биометрию");
        assert_eq!(v.list().len(), 1);
        std::fs::remove_file(&path).ok();
    }

    /// Экран блокировки обязан узнать про биометрию ДО разблокировки — блоб читается из файла без
    /// пароля. И исчезает, когда пользователь биометрию выключил.
    #[test]
    fn platform_blob_is_readable_without_password_and_removable() {
        let path = tmp_path("platform-blob");
        let mut v = Vault::create(&path, "blobpass123").unwrap();
        assert!(Vault::platform_slot_blob(&path).is_none(), "по умолчанию биометрии нет");

        v.set_platform_slot(b"blob-42".to_vec(), "android-keystore").unwrap();
        let slot = Vault::platform_slot_blob(&path).expect("слот виден без пароля");
        assert_eq!(slot.blob, b"blob-42");
        assert_eq!(slot.label, "android-keystore");

        v.clear_platform_slot().unwrap();
        assert!(Vault::platform_slot_blob(&path).is_none(), "выключили — слота нет");
        assert!(v.clear_platform_slot().is_ok(), "повторное выключение — no-op");
        drop(v);
        assert!(Vault::open(&path, "blobpass123").is_ok(), "пароль работает как работал");
        std::fs::remove_file(&path).ok();
    }

    /// Мастер-ключ ЧУЖОГО хранилища не открывает наше (иначе подложенный блоб от другого файла
    /// давал бы «успешную» биометрию с мусором вместо профилей), и битый ключ не паникует.
    #[test]
    fn foreign_master_key_rejected() {
        let a = tmp_path("mk-a");
        let b = tmp_path("mk-b");
        let mk_a = Vault::create(&a, "apass12345").unwrap().master_key();
        let mk_b = Vault::create(&b, "bpass12345").unwrap().master_key();
        assert!(matches!(
            Vault::open_with_master_key(&a, &mk_b),
            Err(VaultOpenError::WrongPassword)
        ));
        assert!(matches!(
            Vault::open_with_master_key(&a, &mk_a[..16]),
            Err(VaultOpenError::Unavailable(_)),
        ));
        assert!(Vault::open_with_master_key(&a, &mk_a).is_ok());
        std::fs::remove_file(&a).ok();
        std::fs::remove_file(&b).ok();
    }

    /// Таблица слотов входит в AAD: пересадить в наш файл слоты из ЧУЖОГО хранилища (чтобы открыть
    /// его известным паролем) невозможно — тег полезной нагрузки перестаёт сходиться. Точечная
    /// правка байта внутри завёрнутого ключа — то же самое.
    #[test]
    fn slot_table_is_bound_to_payload() {
        let a = tmp_path("slots-a");
        let b = tmp_path("slots-b");
        Vault::create(&a, "apass12345").unwrap().add("p", &sample_uri()).unwrap();
        Vault::create(&b, "bpass12345").unwrap();
        let (raw_a, raw_b) = (std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
        let (ha, hb) = (parse_v4(&raw_a).unwrap(), parse_v4(&raw_b).unwrap());

        // файл A, но заголовок+слоты от B (то есть пароль B) — шифртекст остаётся от A
        let mut spliced = raw_b[..hb.aad_end].to_vec();
        spliced.extend_from_slice(&raw_a[ha.aad_end..]);
        std::fs::write(&a, &spliced).unwrap();
        assert!(
            matches!(Vault::open_detailed(&a, "bpass12345"), Err(VaultOpenError::WrongPassword)),
            "чужая таблица слотов не должна открывать наш шифртекст"
        );

        // правка одного байта в завёрнутом ключе → пароль перестаёт разворачивать слот
        let mut bitflip = raw_a.clone();
        let victim = HEADER_LEN_V2 + SLOTS_LEN_FIELD + 8;
        bitflip[victim] ^= 0x01;
        std::fs::write(&a, &bitflip).unwrap();
        assert!(Vault::open_detailed(&a, "apass12345").is_err(), "битый слот обязан ломать open");

        std::fs::write(&a, &raw_a).unwrap();
        assert!(Vault::open(&a, "apass12345").is_ok(), "исходный файл цел");
        std::fs::remove_file(&a).ok();
        std::fs::remove_file(&b).ok();
    }

    /// Границы таблицы слотов (та же логика, что у Argon2-параметров, L-2): длина читается ДО
    /// проверки подлинности файла, поэтому подложенное значение обязано давать честную ошибку, а
    /// не панику по выходу за срез и не аллокацию «на 64 КиБ мусора».
    #[test]
    fn planted_slot_table_rejected() {
        let path = tmp_path("slots-bounds");
        Vault::create(&path, "boundspass2").unwrap();
        let good = std::fs::read(&path).unwrap();

        for (why, len) in [("длина за концом файла", u16::MAX), ("длина обрывает CBOR", 3u16)] {
            let mut raw = good.clone();
            raw[HEADER_LEN_V2..HEADER_LEN_V2 + SLOTS_LEN_FIELD]
                .copy_from_slice(&len.to_be_bytes());
            std::fs::write(&path, &raw).unwrap();
            assert!(
                matches!(Vault::open_detailed(&path, "boundspass2"), Err(VaultOpenError::Unavailable(_))),
                "{why}: ожидалась ошибка «файл не годится»"
            );
        }
        // файл вовсе без слотов (slots_len=0 → пустой CBOR не разберётся) тоже не должен паниковать
        let mut raw = good.clone();
        raw.truncate(HEADER_LEN_V2 + SLOTS_LEN_FIELD);
        raw[HEADER_LEN_V2..].copy_from_slice(&0u16.to_be_bytes());
        std::fs::write(&path, &raw).unwrap();
        assert!(Vault::open_detailed(&path, "boundspass2").is_err());
        std::fs::remove_file(&path).ok();
    }

    /// Слот каждого вида — ровно один: повторное включение биометрии заменяет блоб, а не копит
    /// слоты (два слота одного вида означали бы, что прежний способ открытия продолжает работать).
    #[test]
    fn slot_of_a_kind_is_replaced_not_appended() {
        let path = tmp_path("slots-unique");
        let mut v = Vault::create(&path, "uniqpass123").unwrap();
        v.set_platform_slot(b"first".to_vec(), "android-keystore").unwrap();
        v.set_platform_slot(b"second".to_vec(), "android-keystore").unwrap();
        v.change_password("uniqpass456").unwrap();
        assert_eq!(v.slots.len(), 2, "ровно два слота: пароль и платформа");
        assert_eq!(v.slots[0].kind, SLOT_PASSWORD, "слот пароля идёт первым");
        assert_eq!(Vault::platform_slot_blob(&path).unwrap().blob, b"second");
        std::fs::remove_file(&path).ok();
    }
}
