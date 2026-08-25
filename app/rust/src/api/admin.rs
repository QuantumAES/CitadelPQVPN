//! Мост GUI → admin-плоскость (C7.4): управление Layer-1 реестром абонентов ПО ТУННЕЛЮ.
//!
//! Заменяет SSH/russh-путь C5.5 (`AdminConn` + `AdminDeployer`): теперь операции идут через
//! `citadel_client::admin` — PQ-TLS канал к `ADMIN_VIP:admin_port` (достижим только из-под
//! поднятого туннеля), аутентификация Ed25519 `admin_seed` из МАСТЕР-ссылки профиля (domain+EKM).
//! Бэкенд один для ВСЕХ платформ (никакого cfg-гейта — russh больше не нужен), т.е. admin-режим
//! этим же коммитом появляется и на мобильных.
//!
//! Все параметры канала (адрес/pin/seed) ядро выводит из ссылки профиля; с клиентской (не мастер)
//! ссылки операции fail-closed. Каждая операция самодостаточна: connect → op → close.
//!
//! Метки «кому какой client_id выдан» живут ТОЛЬКО в vault админа (на сервере — pub+срок+статус);
//! сюда они подмешиваются в [`SubscriberDto::label`] при листинге.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use citadel_client::admin as core_admin;

use super::citadel::{profile_uri, with_vault};

/// Абонент Layer-1 реестра для UI: серверная запись + локальная метка админа.
pub struct SubscriberDto {
    /// client_id абонента (Ed25519 pub, 64 hex).
    pub client_id_hex: String,
    /// Срок действия (unix-секунды).
    pub valid_until_unix: i64,
    /// Статус строки реестра как есть (`active`|`revoked`|…).
    pub status: String,
    /// Удобный флаг для UI: строка активна (`status == "active"`).
    pub active: bool,
    /// Метка админа из vault («телефон Али»); пусто — если не сохранена (выдан вне этого устройства).
    pub label: String,
}

/// Результат выдачи доступа: client_id + готовая КЛИЕНТСКАЯ ссылка (без admin-полей).
/// `uri` показывается один раз (QR/копирование) — seed абонента у админа НЕ сохраняется.
pub struct IssuedLinkDto {
    pub client_id_hex: String,
    pub uri: String,
    /// M-9: код сверки — короткий отпечаток ссылки. Называется абоненту ОТДЕЛЬНО от самой ссылки
    /// (голосом, при встрече): он ловит подмену при доставке, чего сама ссылка поймать не может.
    pub verify_code: String,
    /// M-9: до какого момента (unix) ссылку нужно активировать. Позже — она мертва.
    pub activate_until_unix: i64,
}

/// Список абонентов реестра сервера admin-профиля (по туннелю), с локальными метками.
/// Требует разблокированного vault; канал достижим только при поднятой сессии этого профиля.
pub async fn admin_subscribers(profile_id: String) -> Result<Vec<SubscriberDto>> {
    let uri = profile_uri(&profile_id)?;
    let list = core_admin::admin_list(uri).await?;
    let labels: HashMap<String, String> = with_vault(|v| Ok(v.list_issued()))?
        .into_iter()
        .map(|r| (r.client_id_hex, r.label))
        .collect();
    // M-9: пара «ссылка + устройство» уже свёрнута ядром в одну строку абонента
    // (`citadel_client::admin::fold_activated`), а `label_id_hex` говорит, под каким id искать
    // метку админа: у активированной ссылки метка сохранена под ЕЁ id, а показываем мы запись
    // устройства.
    Ok(list
        .into_iter()
        .map(|e| SubscriberDto {
            label: labels.get(&e.label_id_hex).cloned().unwrap_or_default(),
            client_id_hex: e.client_id_hex,
            valid_until_unix: e.valid_until_unix,
            active: e.active,
            status: e.status,
        })
        .collect())
}

/// Выдать доступ новому абоненту: свежий seed → регистрация pub по каналу → клиентская ссылка
/// (собирается локально, issuer seed не видит — модель C5.4b). `valid_until`: пусто → серверный
/// дефолт (+365d), `+30d`/`+12h`/unix-секунды. `label` — локальная метка (только vault админа).
pub async fn admin_issue_subscriber(
    profile_id: String,
    label: String,
    valid_until: String,
) -> Result<IssuedLinkDto> {
    let uri = profile_uri(&profile_id)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).context("часы до 1970")?.as_secs();
    let vu = core_admin::parse_valid_until(&valid_until, now)?;
    let issued = core_admin::admin_issue(uri, vu).await?;
    // Метка — best-effort ПОСЛЕ успешной регистрации (реестр — источник истины; провал записи
    // метки не должен ронять выдачу — ссылка уже зарегистрирована и обязана дойти до UI).
    let _ = with_vault(|v| v.add_issued(&issued.client_id_hex, &label, vu));
    Ok(IssuedLinkDto {
        client_id_hex: issued.client_id_hex,
        uri: issued.uri,
        verify_code: issued.verify_code,
        activate_until_unix: issued.activate_until as i64,
    })
}

/// Отозвать абонента по client_id (status=revoked; действует ≤ длины эпохи). Отзыв собственного
/// admin client_id сервер отклонит (анти-self-lockout, R6). Метку в vault НЕ удаляем — «кому был
/// выдан отозванный id» остаётся видно в списке.
pub async fn admin_revoke_subscriber(profile_id: String, client_id_hex: String) -> Result<()> {
    let uri = profile_uri(&profile_id)?;
    core_admin::admin_revoke(uri, client_id_hex).await
}
