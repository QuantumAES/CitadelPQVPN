//! B-2 (аудит-4, R4.2): **мастер-ссылка в парольной обёртке** вместо голого текста/QR.
//!
//! ## Что было не так
//!
//! Установка печатает мастер-ссылку один раз в терминал. Сама ссылка — предъявительский секрет:
//! в ней инлайном лежат `admin_seed` (admin-плоскость), Layer-1 `client_seed`, obfs-PSK и pin'ы.
//! Дальше она живёт своей жизнью в местах, которые никто не считает хранилищем секретов:
//! скролбэк SSH-сессии, лог терминала/tmux, скриншот, «отправлю себе в мессенджер, чтобы открыть
//! на телефоне». Одноразовость (M-9) сужает окно — до активации на первом устройстве, — но внутри
//! окна (по умолчанию сутки) поднявший текст получает управление сервером целиком.
//!
//! ## Что здесь
//!
//! Тот же текст, но в конверте: `Argon2id(пароль)` → AES-256-GCM. Наружу отдаётся печатаемый блок
//! (base64 в рамке `-----BEGIN CITADEL MASTER LINK-----`), который можно скопировать, переслать и
//! сохранить, не отдавая доступ: без пароля это шум, а перебор пароля упирается в memory-hard KDF.
//!
//! ## Границы (и почему они такие)
//!
//! * **Это защита ДОСТАВКИ, а не резервная копия.** После активации мастер-ссылки (M-9) блок
//!   мёртв так же, как исходный текст: подписка переехала на ключ устройства. Хранить его «на
//!   всякий случай» бессмысленно — восстановление доступа при потере устройства решается на
//!   сервере (перевыпуск admin-идентичности, `--reissue-admin`), а не этим файлом.
//! * **Стойкость = стойкость пароля.** Конверт не превращает «12345» в защиту; параметры Argon2id
//!   выбраны как у хранилища (~1–2 с на разворачивание), и это всё, что криптография тут может.
//! * **Пароль передаётся другим каналом.** Смысл конверта именно в разделении каналов: блок — в
//!   мессенджере, пароль — голосом. Отправленные вместе, они равны голой ссылке.

use anyhow::{anyhow, bail, Context, Result};
use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use base64::Engine as _;
use zeroize::Zeroize;

/// Рамка печатаемого блока — по образцу PEM: её видно в любом мессенджере и не спутать со ссылкой.
const BEGIN: &str = "-----BEGIN CITADEL MASTER LINK-----";
const END: &str = "-----END CITADEL MASTER LINK-----";

/// Магия и версия бинарного конверта (внутри base64).
const MAGIC: &[u8; 8] = b"CITADMK\x01";
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;

/// Argon2id-параметры конверта. Как у хранилища на десктопе (256 MiB / t=4): разворачивание
/// делается один раз человеком, а офлайн-перебор блока, попавшего в чужие руки, дорожает на
/// порядки. Телефонного послабления здесь нет намеренно — блок разворачивают на устройстве
/// администратора, и это редкая одноразовая операция.
const ARGON_M_KIB: u32 = 256 * 1024;
const ARGON_T: u32 = 4;
const ARGON_P: u32 = 1;

/// Потолок длины конверта (анти-OOM при разборе чужого текста). Ссылка — сотни байт.
const MAX_ENVELOPE: usize = 64 * 1024;

/// Минимальная длина пароля. Не «политика сложности» (она бесполезна и раздражает), а нижняя
/// граница, ниже которой конверт создаёт ложное чувство защиты: перебор четырёх символов не
/// остановит никакой KDF.
pub const MIN_PASSWORD_LEN: usize = 8;

/// Похоже ли на парольно-обёрнутый блок (а не на обычную `citadel://`-ссылку). Нужна вызывающим,
/// чтобы спросить пароль ровно тогда, когда он нужен, а не всегда.
pub fn looks_wrapped(text: &str) -> bool {
    text.contains(BEGIN)
}

/// Завернуть ссылку в парольный конверт и вернуть печатаемый блок.
pub fn wrap(link: &str, password: &str) -> Result<String> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        bail!("пароль короче {MIN_PASSWORD_LEN} символов — конверт не даст защиты");
    }
    let rng = SystemRandom::new();
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut salt).map_err(|_| anyhow!("RNG"))?;
    rng.fill(&mut nonce).map_err(|_| anyhow!("RNG"))?;

    let header = header_bytes(&salt, &nonce);
    let key = derive(password, &salt)?;
    let mut buf = link.as_bytes().to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(&header),
        &mut buf,
    )
    .map_err(|_| anyhow!("зашифровать мастер-ссылку"))?;

    let mut envelope = header;
    envelope.extend_from_slice(&buf);
    Ok(armor(&envelope))
}

/// Развернуть блок. Неверный пароль и поломанный/подменённый блок неотличимы намеренно: оба —
/// «не разворачивается», и гадать по сообщению, «тот ли пароль», противнику не с чего.
pub fn unwrap(block: &str, password: &str) -> Result<String> {
    let (salt, nonce, mut buf) = parse_envelope(block)?;
    let header = header_bytes(&salt, &nonce);
    // Заголовок целиком идёт в AAD: подмена соли/nonce (в том числе перестановка их между двумя
    // блоками) ломает тег, а не тихо меняет то, что развернётся.
    let key = derive(password, &salt)?;
    let plain = key
        .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(&header), &mut buf)
        .map_err(|_| anyhow!("неверный пароль или повреждённый блок мастер-ссылки"))?;
    let link = String::from_utf8(plain.to_vec())
        .context("развёрнутое содержимое не текст — блок не от этой версии?")?;
    buf.zeroize();
    if !link.starts_with("citadel://") {
        bail!("развернулось не ссылкой Citadel — блок собран не установкой сервера");
    }
    Ok(link)
}

/// **Ф1** (`docs/CWE-REVIEW-PLAN-2026-08.md`, Приложение A): разбор недоверенного блока **до**
/// KDF — рамка, base64, длина, магия. Отдельная дверь для фаззера нужна потому, что за ней стоит
/// Argon2id на 256 МиБ: гонять его на случайных байтах бессмысленно (проверять там нечего, кроме
/// тега AEAD) и невозможно по времени. Противник — тот, кто прислал человеку «мастер-ссылку»:
/// скомпрометированный канал доставки, подменённое письмо, чужой QR.
pub fn probe_block(block: &str) -> Result<()> {
    parse_envelope(block).map(|_| ())
}

/// Общая часть [`unwrap`] и [`probe_block`]: печатаемый блок → `(соль, nonce, шифртекст)`.
/// Всё, что здесь проверяется, обязано проверяться ДО единого байта криптографии.
fn parse_envelope(block: &str) -> Result<([u8; SALT_LEN], [u8; NONCE_LEN], Vec<u8>)> {
    let raw = dearmor(block)?;
    if raw.len() < MAGIC.len() + SALT_LEN + NONCE_LEN {
        bail!("блок мастер-ссылки повреждён (слишком короткий)");
    }
    if &raw[..MAGIC.len()] != MAGIC {
        bail!("это не блок мастер-ссылки Citadel (или он другой версии)");
    }
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    let s = MAGIC.len();
    salt.copy_from_slice(&raw[s..s + SALT_LEN]);
    nonce.copy_from_slice(&raw[s + SALT_LEN..s + SALT_LEN + NONCE_LEN]);
    let ct = raw[MAGIC.len() + SALT_LEN + NONCE_LEN..].to_vec();
    Ok((salt, nonce, ct))
}

/// Открытая часть конверта (она же AAD): `magic ‖ salt ‖ nonce`. Argon2-параметры сюда НЕ
/// пишутся: у конверта они фиксированы версией магии, и «параметры из файла» (то, что в хранилище
/// потребовало отдельной проверки границ, L-2) здесь просто не существуют как поверхность атаки.
fn header_bytes(salt: &[u8; SALT_LEN], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut h = Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN);
    h.extend_from_slice(MAGIC);
    h.extend_from_slice(salt);
    h.extend_from_slice(nonce);
    h
}

fn derive(password: &str, salt: &[u8]) -> Result<LessSafeKey> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(ARGON_M_KIB, ARGON_T, ARGON_P, Some(KEY_LEN))
        .map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("argon2 derive: {e}"))?;
    let unbound = UnboundKey::new(&AES_256_GCM, &key).map_err(|_| anyhow!("ключ AEAD"))?;
    key.zeroize();
    Ok(LessSafeKey::new(unbound))
}

/// Бинарь → печатаемый блок (строки по 64 символа, как в PEM: переживает перенос в мессенджере).
fn armor(raw: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
    let mut out = String::with_capacity(b64.len() + 128);
    out.push_str(BEGIN);
    out.push('\n');
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 — ASCII"));
        out.push('\n');
    }
    out.push_str(END);
    out
}

/// Печатаемый блок → бинарь. Всё вне рамки игнорируется: человек копирует блок вместе с соседними
/// строками письма гораздо чаще, чем ровно по границе.
fn dearmor(block: &str) -> Result<Vec<u8>> {
    let start = block.find(BEGIN).ok_or_else(|| {
        anyhow!("в тексте нет блока мастер-ссылки (строки {BEGIN} … {END})")
    })?;
    let after = start + BEGIN.len();
    let end = block[after..]
        .find(END)
        .ok_or_else(|| anyhow!("блок мастер-ссылки не закрыт строкой {END}"))?;
    let body: String = block[after..after + end].split_whitespace().collect();
    if body.len() > MAX_ENVELOPE {
        bail!("блок мастер-ссылки неправдоподобно велик ({} символов)", body.len());
    }
    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .context("блок мастер-ссылки: base64 не разбирается (текст побит переносом?)")
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK: &str = "citadel://eyJ2IjoxfQ";

    /// Круг: завернули → развернули тем же паролем. И главное свойство — чужой пароль не
    /// разворачивает, причём ошибка не отличает «пароль не тот» от «блок побит».
    #[test]
    fn wrap_unwrap_roundtrip_and_wrong_password() {
        let block = wrap(LINK, "correct horse battery").unwrap();
        assert!(looks_wrapped(&block));
        assert!(!block.contains(LINK), "ссылка не должна светиться в блоке");
        assert_eq!(unwrap(&block, "correct horse battery").unwrap(), LINK);
        assert!(unwrap(&block, "correct horse batterx").is_err(), "чужой пароль не разворачивает");
    }

    /// Блок переживает то, что с ним делают люди: копирование с лишними строками вокруг и
    /// перенос/склейку строк в мессенджере.
    #[test]
    fn survives_copy_paste_mangling() {
        let block = wrap(LINK, "passphrase-1").unwrap();
        let pasted = format!("Привет! Вот блок:\n\n{block}\n\nПароль скажу голосом.");
        assert_eq!(unwrap(&pasted, "passphrase-1").unwrap(), LINK);
        // склеили строки base64 в одну — тоже норма
        let glued = block.replace('\n', "");
        let glued = glued
            .replace(BEGIN, &format!("{BEGIN}\n"))
            .replace(END, &format!("\n{END}"));
        assert_eq!(unwrap(&glued, "passphrase-1").unwrap(), LINK);
    }

    /// Правка любого байта конверта (в т.ч. открытой части — соли/nonce) ломает разворачивание:
    /// заголовок накрыт AAD, а не «просто лежит рядом».
    #[test]
    fn tampering_breaks_open() {
        let block = wrap(LINK, "passphrase-2").unwrap();
        let raw = dearmor(&block).unwrap();
        for i in [MAGIC.len(), MAGIC.len() + SALT_LEN, raw.len() - 1] {
            let mut bad = raw.clone();
            bad[i] ^= 1;
            assert!(unwrap(&armor(&bad), "passphrase-2").is_err(), "правка байта {i} прошла");
        }
    }

    /// Короткий пароль отклоняется на создании: конверт под «1234» — это ложное чувство защиты,
    /// а не защита. И наоборот, посторонний текст не притворяется блоком.
    #[test]
    fn refuses_weak_password_and_foreign_text() {
        assert!(wrap(LINK, "1234").is_err());
        assert!(!looks_wrapped("citadel://eyJ2IjoxfQ"));
        assert!(unwrap("citadel://eyJ2IjoxfQ", "passphrase-3").is_err());
        assert!(unwrap(&format!("{BEGIN}\nне-base64!!\n{END}"), "passphrase-3").is_err());
    }

    /// Развернуться обязано именно ССЫЛКОЙ: конверт с посторонним содержимым (подсунутый файл,
    /// чужой формат) не должен молча уехать дальше по коду импорта.
    #[test]
    fn refuses_envelope_with_non_link_payload() {
        let block = wrap("citadel://ok", "passphrase-4").unwrap();
        assert!(unwrap(&block, "passphrase-4").is_ok());
        // тот же конверт, но внутри не ссылка — собираем вручную тем же кодом
        let rng = SystemRandom::new();
        let (mut salt, mut nonce) = ([0u8; SALT_LEN], [0u8; NONCE_LEN]);
        rng.fill(&mut salt).unwrap();
        rng.fill(&mut nonce).unwrap();
        let header = header_bytes(&salt, &nonce);
        let key = derive("passphrase-4", &salt).unwrap();
        let mut buf = b"rm -rf /".to_vec();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&header),
            &mut buf,
        )
        .unwrap();
        let mut env = header;
        env.extend_from_slice(&buf);
        assert!(unwrap(&armor(&env), "passphrase-4").is_err());
    }
}
