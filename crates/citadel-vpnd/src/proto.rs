//! Кадры IPC клиента Linux (трек L). Формат кадра — `u32 BE len ‖ CBOR(payload)`.
//!
//! Два независимых канала:
//!   1. **управляющий** `citadel-cli` (непривилегированный юзер) → демон: [`CtlRequest`] /
//!      [`CtlResponse`]. Строго типизированный набор операций (L1): «подключись по этой ссылке»,
//!      «отключись», «статус», «сними kill-switch». НЕТ операций вида «выполни команду»,
//!      «прочитай файл по пути» — иначе член группы `citadel-vpn` получил бы root-чтение/запись
//!      произвольных путей чужими руками (classic confused deputy).
//!   2. **приватный** демон ↔ движок (socketpair, fd 3 у движка): [`DaemonMsg`] / [`EngineMsg`].
//!      Движок — единственный, кто разбирает `citadel://` и сетевые пакеты; демону он присылает
//!      уже конкретный запрос на конфигурацию туннеля ([`TunSetupReq`]), который тот **валидирует
//!      заново** (`crate::valid`) — движок недоверен ровно так же, как CLI.
//!
//! Лимит кадра [`MAX_FRAME`] + `read_exact` по объявленной длине: злонамеренный/битый клиент не
//! может заставить демона выделить произвольную память (анти-DoS на границе привилегий).

use std::io::{Read, Write};

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

/// Потолок размера кадра IPC. Самый крупный полезный кадр — `Connect` со ссылкой (`citadel://`
/// с ML-DSA pub ≈ 2.7 КиБ base64) плюс split-список; 64 КиБ — с большим запасом.
pub const MAX_FRAME: usize = 64 * 1024;

/// Дескриптор приватного канала, который демон передаёт движку при exec (fd 3).
/// Конфиг с секретами приходит по нему кадром — НЕ через argv/env (L5: `/proc/*/cmdline`
/// и `/proc/*/environ` утекают локальным наблюдателям).
pub const ENGINE_CHANNEL_FD: i32 = 3;

// ───────────────────────────── управляющий канал (cli → vpnd) ─────────────────────────────

/// Запрос от `citadel-cli`. Каждый вариант — законченная операция; демон не исполняет
/// ничего, что не выражено этим перечислением.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum CtlRequest {
    /// Версия демона (диагностика/совместимость).
    Version,
    /// Текущее состояние сессии.
    Status,
    /// Поднять туннель по ссылке (секрет живёт в кадре, а не в argv).
    Connect(ConnectReq),
    /// Разорвать активную сессию (чистый disconnect → kill-switch снимается).
    Disconnect,
    /// Аварийно снять залипший kill-switch/IPv6-блок (L11): fail-closed правила остались после
    /// краха, интернета нет. Идемпотентно.
    DisarmKillswitch,
    /// Подписка на поток событий: демон шлёт [`CtlResponse::Event`]-кадры, пока клиент читает.
    Events,
}

/// Параметры подключения. Всё, что несёт секреты, приходит одним кадром и затирается демоном
/// после передачи движку.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ConnectReq {
    /// `citadel://`-ссылка целиком (pin/psk/seed внутри). Демон её НЕ разбирает — передаёт
    /// движку как непрозрачную строку (парсер base64/CBOR работает без привилегий, L13).
    pub link: String,
    /// C6/M9 kill-switch: fail-closed firewall на время сессии.
    pub killswitch: bool,
    /// C8.3 split-tunnel по назначениям: `"off"|"include"|"exclude"`.
    pub split_mode: String,
    /// Записи назначений как их ввёл пользователь (`domain`|`IP`|`IP/prefix`); домены резолвит
    /// движок перед конфигурацией туннеля.
    pub split_dests: Vec<String>,
    /// Метка профиля для `status` (человекочитаемая). Санитизируется перед показом (L16).
    pub label: String,
}

/// Ответ демона.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum CtlResponse {
    /// Операция принята.
    Ok,
    Version(String),
    Status(StatusInfo),
    /// Событие сессии (только в потоке после [`CtlRequest::Events`]).
    Event(EventMsg),
    /// Отказ с причиной (в т.ч. «нет прав», «уже подключено другим пользователем»).
    Err(String),
}

/// Снимок состояния сессии для `status`/TUI.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct StatusInfo {
    /// `idle`|`connecting`|`up`|`migrating`|`down`.
    pub state: String,
    /// Выбранный exit (`host:port`), пока не поднято — пусто.
    pub exit: String,
    /// `QUIC/UDP`|`obfs-TCP`.
    pub transport: String,
    /// Назначенный адрес туннеля (CIDR).
    pub cidr: String,
    /// Когда стартовала сессия (unix-секунды; 0 — нет сессии).
    pub since_unix: u64,
    /// Метка профиля, с которой подключались.
    pub label: String,
    /// Kill-switch армирован ПРЯМО СЕЙЧАС (в т.ч. осиротевший после краха — L11).
    pub killswitch_armed: bool,
    /// Последняя ошибка сессии (пусто — не было).
    pub last_error: String,
    /// uid владельца сессии (кто её поднял). 0 — сессии нет.
    pub owner_uid: u32,
    /// Версия демона.
    pub version: String,
}

/// Событие движка, ретранслируемое подписчикам.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct EventMsg {
    /// `state`|`connected`|`error`.
    pub kind: String,
    pub state: String,
    pub exit: String,
    pub transport: String,
    pub cidr: String,
    pub error: String,
}

impl EventMsg {
    pub fn state(s: &str) -> Self {
        Self { kind: "state".into(), state: s.into(), ..Default::default() }
    }
    pub fn error(e: &str) -> Self {
        Self { kind: "error".into(), error: e.into(), ..Default::default() }
    }
}

// ───────────────────────────── приватный канал (vpnd ↔ engine) ─────────────────────────────

/// Демон → движок.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum DaemonMsg {
    /// Стартовый конфиг (первый кадр после exec): ссылка + клиентские настройки.
    Config(ConnectReq),
    /// Пользователь попросил разрыв: движок закрывает сессию и завершает процесс, послав
    /// перед этим [`EngineMsg::CleanShutdown`] (сигнал «снять kill-switch»).
    Stop,
    /// Ответ на [`EngineMsg::TunSetup`]: fd туннеля приходит отдельно (SCM_RIGHTS) вместе с ним.
    TunReady,
    /// Ответ на [`EngineMsg::TunSetup`]: отказ (валидация не прошла / не удалось поднять сеть).
    TunError(String),
}

/// Движок → демон.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum EngineMsg {
    /// Адреса, к которым движку нужен доступ ДО подъёма туннеля: exit'ы и issuer.
    ///
    /// Зачем отдельное сообщение: kill-switch может быть уже армирован (остался fail-closed
    /// после аварийного разрыва — так и задумано). Тогда движок не пробьётся ни к exit'у, ни к
    /// issuer'у за токеном, `establish` не состоится, `TunSetup` никогда не придёт — и сессия
    /// не поднимется НИКОГДА, пока человек не снимет защиту руками. Это сообщение открывает
    /// точечные исключения (`-d <ip>/32`, при возможности — с привязкой к uid движка) до того,
    /// как начнётся установка сессии. Адреса валидируются демоном как IPv4-список.
    AllowExits(Vec<String>),
    /// Просьба сконфигурировать туннель под назначенный exit'ом адрес. **Недоверенный ввод**:
    /// демон валидирует (`crate::valid::TunSetup::parse`) перед любым `ip`/`iptables`.
    TunSetup(TunSetupReq),
    /// Событие для UI.
    Event(EventMsg),
    /// Чистый disconnect (аналог байта `'Q'` у `citadel-helper`): снять kill-switch. Разрыв БЕЗ
    /// этого сообщения (краш движка) оставляет fail-closed правила — утечки нет.
    CleanShutdown,
}

/// Запрос конфигурации туннеля от движка. Все поля — строки/числа «как договорились»; демон
/// принимает их только через [`crate::valid`].
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct TunSetupReq {
    /// Адрес туннеля, назначенный exit'ом.
    pub addr: [u8; 4],
    pub prefix: u8,
    pub mtu: String,
    /// Маршруты в туннель (`0.0.0.0/0` = full-tunnel).
    pub routes: Vec<String>,
    /// DNS-резолвер внутри туннеля (F6).
    pub dns: Option<String>,
    /// IP exit'ов — bypass-маршрут мимо туннеля (анти-петля).
    pub exit_ips: Vec<String>,
    /// Армировать kill-switch.
    pub killswitch: bool,
    /// C8.3: назначения «в обход» туннеля (уже резолвнутые в CIDR).
    pub bypass: Vec<String>,
}

// ───────────────────────────── кадрирование ─────────────────────────────

/// Записать кадр `u32 BE len ‖ CBOR`.
pub fn write_frame<W: Write, T: Serialize>(w: &mut W, msg: &T) -> Result<()> {
    let mut body = Vec::new();
    ciborium::into_writer(msg, &mut body)?;
    if body.len() > MAX_FRAME {
        bail!("кадр IPC больше лимита ({} > {MAX_FRAME})", body.len());
    }
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()?;
    Ok(())
}

/// Прочитать кадр. `Ok(None)` — корректный EOF (партнёр закрыл канал).
pub fn read_frame<R: Read, T: for<'de> Deserialize<'de>>(r: &mut R) -> Result<Option<T>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let n = u32::from_be_bytes(len) as usize;
    // Лимит ДО выделения памяти: объявленная длина — недоверенное число.
    if n > MAX_FRAME {
        bail!("кадр IPC больше лимита ({n} > {MAX_FRAME})");
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body)?;
    Ok(Some(ciborium::from_reader(&body[..])?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let mut buf = Vec::new();
        let req = CtlRequest::Connect(ConnectReq {
            link: "citadel://abc".into(),
            killswitch: true,
            split_mode: "exclude".into(),
            split_dests: vec!["192.168.1.0/24".into()],
            label: "дом".into(),
        });
        write_frame(&mut buf, &req).unwrap();
        let got: CtlRequest = read_frame(&mut &buf[..]).unwrap().unwrap();
        match got {
            CtlRequest::Connect(c) => {
                assert_eq!(c.link, "citadel://abc");
                assert!(c.killswitch);
                assert_eq!(c.split_dests, vec!["192.168.1.0/24".to_string()]);
            }
            other => panic!("не тот вариант: {other:?}"),
        }
    }

    /// EOF на границе кадра — это не ошибка, а нормальное закрытие канала.
    #[test]
    fn eof_is_none() {
        let empty: &[u8] = &[];
        let got: Option<CtlRequest> = read_frame(&mut &empty[..]).unwrap();
        assert!(got.is_none());
    }

    /// Анти-DoS: объявленная длина больше лимита отвергается ДО выделения памяти.
    #[test]
    fn oversized_declared_length_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_FRAME as u32 + 1).to_be_bytes());
        let r: Result<Option<CtlRequest>> = read_frame(&mut &buf[..]);
        assert!(r.is_err(), "кадр сверх лимита должен отвергаться");
    }

    /// Мусор вместо CBOR не паникует, а возвращает ошибку (парсер недоверенного ввода).
    #[test]
    fn garbage_body_is_error() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&4u32.to_be_bytes());
        buf.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        let r: Result<Option<CtlRequest>> = read_frame(&mut &buf[..]);
        assert!(r.is_err());
    }

    /// Обрыв посреди кадра (объявлено больше, чем прислано) — ошибка, не зависание/паника.
    #[test]
    fn truncated_body_is_error() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&64u32.to_be_bytes());
        buf.extend_from_slice(b"short");
        let r: Result<Option<CtlRequest>> = read_frame(&mut &buf[..]);
        assert!(r.is_err());
    }
}
