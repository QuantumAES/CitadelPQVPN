//! Мост GUI → ядро CitadelPQVPN (`citadel-client`).
//!
//! Три поверхности:
//!   - **vault** — зашифрованное хранилище профилей (мастер-пароль; крипта в Rust-ядре);
//!   - **vpn** — stateful сессия: `vpn_connect*` поднимает туннель и стримит события, `vpn_disconnect` рвёт;
//!   - **creds** — разбор `citadel://`-ссылки для превью перед сохранением.
//!
//! Движок крутится на глобальном tokio-runtime; привилегированный TUN создаёт `citadel-helper`
//! через polkit (Linux-desktop).

use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{anyhow, bail, Result};
use flutter_rust_bridge::frb;

use crate::frb_generated::StreamSink;

use citadel_client::{
    CredentialLink, Profile, SplitMode, SplitTunnel, TunIo, TunParams, TunProvider,
    Vault, VpnController, VpnEvent, VpnState,
};
// Провайдер туннеля desktop зависит от ОС: Linux — polkit-helper (GuiTunProvider), Windows —
// служба citadel-svc по named pipe (WindowsTunProvider). Каждый экспортится только на своей ОС.
#[cfg(not(windows))]
use citadel_client::GuiTunProvider;
#[cfg(windows)]
use citadel_client::WindowsTunProvider;

/// Версия PQ-VPN-ядра (about-экран).
#[frb(sync)]
pub fn core_version() -> String {
    citadel_client::api::version()
}

// ───────────────────────────── DTO для UI (плоские структуры, без sealed-enum) ─────────────

/// Событие VPN-сессии для UI. `kind`: `state` | `connected` | `error`.
pub struct VpnEventDto {
    pub kind: String,
    /// Для `kind=state`: `idle`|`connecting`|`up`|`migrating`|`down`.
    pub state: String,
    /// Для `kind=connected`: выбранный exit, транспорт, адрес (CIDR).
    pub exit: String,
    pub transport: String,
    pub cidr: String,
    /// Для `kind=error`: текст ошибки.
    pub error: String,
}

/// Профиль из хранилища (без секретов — только метаданные для списка/карточки).
pub struct ProfileDto {
    pub id: String,
    pub name: String,
    pub servers: String,
    pub has_pin: bool,
    pub has_pq_auth: bool,
    pub has_obfs: bool,
    /// C7.4: мастер-профиль (ссылка несёт admin_seed) — UI показывает пункт «Абоненты».
    pub is_admin: bool,
    pub last_exit: String,
}

/// Превью разобранной `citadel://`-ссылки (экран добавления профиля).
#[derive(Default)]
pub struct LinkSummaryDto {
    pub valid: bool,
    pub servers: String,
    pub server_name: String,
    pub kx_suite: String,
    pub has_pin: bool,
    pub has_pq_auth: bool,
    pub has_obfs: bool,
    /// C7.4: мастер-ссылка (admin) — UI предупреждает: такую нельзя раздавать абонентам.
    pub is_admin: bool,
    /// M-9: первичная (одноразовая) ссылка — активируется на ОДНОМ устройстве.
    pub is_enroll: bool,
    /// M-9: до какого момента (unix) её нужно активировать; `0` — без срока.
    pub activate_until_unix: i64,
    /// M-9: код сверки этой ссылки — абонент сверяет его с тем, что назвал админ по другому
    /// каналу. Единственная проверка, которая ловит подмену ссылки при доставке.
    pub verify_code: String,
}

/// C7.4: QR-код ссылки как битовая матрица `size × size` (1 = тёмный модуль) — рендер в UI
/// кастомным painter'ом, без SVG-зависимости на Dart-стороне.
pub struct QrDto {
    pub size: u32,
    pub cells: Vec<u8>,
}

/// Счётчики трафика туннеля в байтах полезной нагрузки, монотонные за время жизни процесса
/// (см. [`traffic_counters`]). UI считает по ним текущую скорость приёма/передачи.
///
/// Тип `i64`, а не `u64`: на Dart-стороне `u64` превращается в `BigInt` (арифметика дельт стала бы
/// неоправданно громоздкой), тогда как `i64` — обычное целое. Переполнения не будет: 2^63 байт —
/// это 9 эксабайт трафика за один запуск приложения.
pub struct TrafficDto {
    pub rx_bytes: i64,
    pub tx_bytes: i64,
}

/// Снимок статуса живой Android-сессии для UI при перезапуске (нюанс 2: натив переживает смерть
/// Activity, Dart — нет). `state`: `idle`|`connecting`|`up`|`migrating`|`down`; `profile_id` — ""
/// если коннект по сырой ссылке.
pub struct AndroidStatusDto {
    pub state: String,
    pub exit: String,
    pub transport: String,
    pub cidr: String,
    pub profile_id: String,
}

// ───────────────────────────── глобальное состояние ─────────────────────────────

static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
fn rt() -> &'static tokio::runtime::Runtime {
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
    })
}
static ACTIVE: Mutex<Option<Arc<VpnController>>> = Mutex::new(None);
static VAULT: Mutex<Option<Vault>> = Mutex::new(None);

/// C6/S3 (нюанс 2). Снимок статуса активной Android-сессии — обновляется персистентной форвард-
/// задачей на КАЖДОЕ событие контроллера (даже когда Dart не подписан), чтобы перезапуск (новый
/// изолят) увидел живой VPN. Процесс жив foreground-сервисом → статик переживает смерть Activity.
struct AndroidStatus {
    state: &'static str,
    exit: String,
    transport: String,
    cidr: String,
    profile_id: String,
}
impl AndroidStatus {
    const fn idle() -> Self {
        Self {
            state: "idle",
            exit: String::new(),
            transport: String::new(),
            cidr: String::new(),
            profile_id: String::new(),
        }
    }
}
static ANDROID_STATUS: Mutex<AndroidStatus> = Mutex::new(AndroidStatus::idle());
/// Свап-able sink: пересылка событий в ТЕКУЩИЙ Dart-изолят. Умирает с изолятом (окно закрыто) —
/// форвард-задача снимает мёртвый; новый изолят ставит свежий через [`android_attach_events`].
static ANDROID_SINK: Mutex<Option<StreamSink<VpnEventDto>>> = Mutex::new(None);
/// Поколение Android-сессии: инкремент при старте/остановке глушит форвард-задачу прошлой сессии,
/// чтобы её события (напр. поздний `Down` от останавливаемого контроллера) не перезаписали статус
/// новой (анти-гонка при рестарте сессии поверх живой).
static ANDROID_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Базовый каталог данных, заданный платформой (Android: app filesDir). На десктопе не ставится —
/// там путь резолвится из XDG/HOME. Без него на Android cwd=`/` (песочница не writable) и vault не создать.
static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();
/// C6/M9 kill-switch (desktop): включён ли. Читается в `start_connect` → `ClientConfig.killswitch`.
/// GUI-тумблер через [`set_killswitch`]; персистится в файл рядом с vault (переживает рестарт).
static KILLSWITCH: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static KILLSWITCH_LOADED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Файл персиста настройки kill-switch (рядом с vault: XDG/DATA_DIR).
fn killswitch_file() -> PathBuf {
    vault_path().with_file_name("killswitch")
}

/// Включить/выключить kill-switch (GUI-тумблер, desktop). Применяется со СЛЕДУЮЩЕГО подключения;
/// сохраняется на диск (переживает рестарт приложения).
#[frb(sync)]
pub fn set_killswitch(on: bool) {
    use std::sync::atomic::Ordering::Relaxed;
    KILLSWITCH.store(on, Relaxed);
    KILLSWITCH_LOADED.store(true, Relaxed);
    let f = killswitch_file();
    if let Some(d) = f.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::write(f, if on { "1" } else { "0" });
}

/// Текущее состояние kill-switch (инициализация тумблера). Ленивая подгрузка сохранённого значения
/// при первом обращении — персист между запусками.
#[frb(sync)]
pub fn killswitch_enabled() -> bool {
    use std::sync::atomic::Ordering::Relaxed;
    if !KILLSWITCH_LOADED.swap(true, Relaxed) {
        if let Ok(s) = std::fs::read_to_string(killswitch_file()) {
            KILLSWITCH.store(s.trim() == "1", Relaxed);
        }
    }
    KILLSWITCH.load(Relaxed)
}

/// Режим отладки (журнал ядра + диагностика в UI). Персистится в файл рядом с vault (как kill-switch),
/// иначе тумблер сбрасывался бы в дефолт при каждом рестарте. Дефолт (файла нет) — ВЫКЛЮЧЕН (на всех
/// клиентах: журнал ядра пишется только при явном включении пользователем — приватность/no-logs).
static DEBUG_ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static DEBUG_LOADED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn debug_flag_file() -> PathBuf {
    vault_path().with_file_name("debug")
}

/// Сохранить настройку режима отладки (GUI-тумблер) на диск — переживает рестарт приложения.
#[frb(sync)]
pub fn set_debug_enabled(on: bool) {
    use std::sync::atomic::Ordering::Relaxed;
    DEBUG_ENABLED.store(on, Relaxed);
    DEBUG_LOADED.store(true, Relaxed);
    let f = debug_flag_file();
    if let Some(d) = f.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::write(f, if on { "1" } else { "0" });
}

/// Сохранённое состояние режима отладки (инициализация тумблера). Ленивая подгрузка при первом
/// обращении; файла нет → дефолт ВЫКЛЮЧЕН. Имя `*_persisted` — чтобы Dart-обёртка не конфликтовала
/// с полем `AppState.debugEnabled`.
#[frb(sync)]
pub fn debug_enabled_persisted() -> bool {
    use std::sync::atomic::Ordering::Relaxed;
    if !DEBUG_LOADED.swap(true, Relaxed) {
        if let Ok(s) = std::fs::read_to_string(debug_flag_file()) {
            DEBUG_ENABLED.store(s.trim() == "1", Relaxed);
        }
    }
    DEBUG_ENABLED.load(Relaxed)
}

// ─────────────────────────── C8.5 запрет скриншотов (Android FLAG_SECURE) ───────────────────────────
// Блокировка скриншотов/записи экрана/каста и чёрный кадр в «Недавних». Персист рядом с vault (как
// debug); **дефолт ВКЛЮЧЁН** (файла нет → true). Применяет флаг платформа (Android FLAG_SECURE через
// MethodChannel); ядро только хранит настройку. На desktop не enforce'ится (тумблер гейтится Android).

static SCREENSHOT_BLOCK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
static SCREENSHOT_LOADED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn screenshot_block_file() -> PathBuf {
    vault_path().with_file_name("screenshot_block")
}

/// Сохранить настройку запрета скриншотов (GUI-тумблер) — переживает рестарт.
#[frb(sync)]
pub fn set_screenshot_block(on: bool) {
    use std::sync::atomic::Ordering::Relaxed;
    SCREENSHOT_BLOCK.store(on, Relaxed);
    SCREENSHOT_LOADED.store(true, Relaxed);
    let f = screenshot_block_file();
    if let Some(d) = f.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::write(f, if on { "1" } else { "0" });
}

/// Сохранённое состояние запрета скриншотов (инициализация тумблера/применения). Ленивая подгрузка;
/// файла нет → **дефолт true** (запрет включён). Только "0" в файле выключает.
#[frb(sync)]
pub fn screenshot_block_enabled() -> bool {
    use std::sync::atomic::Ordering::Relaxed;
    if !SCREENSHOT_LOADED.swap(true, Relaxed) {
        if let Ok(s) = std::fs::read_to_string(screenshot_block_file()) {
            SCREENSHOT_BLOCK.store(s.trim() != "0", Relaxed);
        }
    }
    SCREENSHOT_BLOCK.load(Relaxed)
}

// ─────────────────────────── язык интерфейса ───────────────────────────
// Выбор пользователя хранится там же, где остальные настройки клиента (файл рядом с vault): язык
// нужен ДО открытия хранилища (экран разблокировки уже говорит с человеком), поэтому класть его
// внутрь зашифрованного vault нельзя. Сами строки живут в Dart (`app/lib/l10n`), ядро хранит только
// код языка. Дефолт — русский.

/// Код языка ограничиваем по форме (2–8 символов ASCII-букв/дефис): значение приходит из UI, но
/// пишется в файл и потом читается обратно — принимать оттуда произвольную строку незачем.
fn valid_lang(code: &str) -> bool {
    let n = code.len();
    (2..=8).contains(&n)
        && code.chars().all(|c| c.is_ascii_alphabetic() || c == '-')
}

fn language_file() -> PathBuf {
    vault_path().with_file_name("language")
}

/// Сохранить выбранный язык интерфейса (код вида `ru`, `en`, …) — переживает рестарт.
#[frb(sync)]
pub fn set_language(code: String) {
    if !valid_lang(&code) {
        return;
    }
    let f = language_file();
    if let Some(d) = f.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::write(f, &code);
}

/// Сохранённый язык интерфейса; файла нет или содержимое непохоже на код языка → `ru`.
#[frb(sync)]
pub fn language() -> String {
    match std::fs::read_to_string(language_file()) {
        Ok(s) if valid_lang(s.trim()) => s.trim().to_string(),
        _ => "ru".to_string(),
    }
}

// ─────────────────────────── индикация трафика (скорость на плашке подключения) ───────────────
// Тумблер «Показывать индикацию трафика» + снимок счётчиков туннеля. Персист рядом с vault (как
// debug/screenshot_block); **дефолт ВЫКЛЮЧЕН** — цифры скорости на главном экране нужны не всем, а
// лишний опрос раз в секунду и лишняя строка на скриншоте по умолчанию ни к чему.

static TRAFFIC_METER: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static TRAFFIC_METER_LOADED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn traffic_meter_file() -> PathBuf {
    vault_path().with_file_name("traffic_meter")
}

/// Сохранить настройку индикации трафика (GUI-тумблер) — переживает рестарт.
#[frb(sync)]
pub fn set_traffic_meter(on: bool) {
    use std::sync::atomic::Ordering::Relaxed;
    TRAFFIC_METER.store(on, Relaxed);
    TRAFFIC_METER_LOADED.store(true, Relaxed);
    let f = traffic_meter_file();
    if let Some(d) = f.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::write(f, if on { "1" } else { "0" });
}

/// Сохранённое состояние индикации трафика (инициализация тумблера). Ленивая подгрузка; файла нет
/// → **дефолт false** (выключено).
#[frb(sync)]
pub fn traffic_meter_enabled() -> bool {
    use std::sync::atomic::Ordering::Relaxed;
    if !TRAFFIC_METER_LOADED.swap(true, Relaxed) {
        if let Ok(s) = std::fs::read_to_string(traffic_meter_file()) {
            TRAFFIC_METER.store(s.trim() == "1", Relaxed);
        }
    }
    TRAFFIC_METER.load(Relaxed)
}

// ─────────────────────── маскировка таймингов (M-8, профиль «высокий риск») ───────────────────
// Тумблер включает тайминг-шейпинг ИСХОДЯЩЕГО потока (DAITA-стиль: выпуск по слот-сетке + adaptive
// chaff). До этого профиль существовал только как `Citadel_PACING` — то есть был доступен серверу и
// консольному клиенту, но не тому, кому он нужен больше всех: пользователю GUI под наблюдением.
//
// **Дефолт ВЫКЛЮЧЕН** и это осознанно: шейпинг платит латентностью и лишним трафиком (chaff), а
// защищает от корреляции по времени — размен, который пользователь должен сделать сам. Ответное
// направление шейпит exit своим `Citadel_PACING`: клиентский тумблер маскирует ОТПРАВКУ.

static PACING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static PACING_LOADED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn pacing_file() -> PathBuf {
    vault_path().with_file_name("pacing")
}

/// Сохранить настройку маскировки таймингов (GUI-тумблер). Применяется со СЛЕДУЮЩЕГО подключения.
#[frb(sync)]
pub fn set_pacing(on: bool) {
    use std::sync::atomic::Ordering::Relaxed;
    PACING.store(on, Relaxed);
    PACING_LOADED.store(true, Relaxed);
    let f = pacing_file();
    if let Some(d) = f.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::write(f, if on { "1" } else { "0" });
}

/// Сохранённое состояние маскировки таймингов (инициализация тумблера); файла нет → выключено.
#[frb(sync)]
pub fn pacing_enabled() -> bool {
    use std::sync::atomic::Ordering::Relaxed;
    if !PACING_LOADED.swap(true, Relaxed) {
        if let Ok(s) = std::fs::read_to_string(pacing_file()) {
            PACING.store(s.trim() == "1", Relaxed);
        }
    }
    PACING.load(Relaxed)
}

/// Снимок счётчиков трафика туннеля (монотонных за время жизни процесса) для расчёта СКОРОСТИ:
/// UI делит дельту между двумя опросами на прошедшее время. Итогов за сессию тут нет намеренно —
/// накапливать историю пользовательского трафика клиенту незачем.
#[frb(sync)]
pub fn traffic_counters() -> TrafficDto {
    let (rx, tx) = citadel_client::traffic_bytes();
    TrafficDto { rx_bytes: rx as i64, tx_bytes: tx as i64 }
}

// ─────────────────────────── C8.3 split-tunneling (Android) ───────────────────────────
// Клиентская настройка (не из ссылки): фильтр по приложениям (package-имена) и/или по назначениям
// (домен/IP/CIDR, в т.ч. локальная подсеть). Персистится текстовым файлом рядом с vault (как
// kill-switch/debug), накатывается в `spawn_controller` на `ClientConfig.split`. Применяет её только
// Android-провайдер (VpnService); desktop игнорирует (Linux split-tunnel — позже, C8.3-Linux).

/// Плоское DTO split-настройки для FFI. `*_mode` = "off"|"include"|"exclude".
#[derive(Clone)]
pub struct SplitTunnelDto {
    pub app_mode: String,
    pub apps: Vec<String>,
    pub dest_mode: String,
    pub dests: Vec<String>,
}

impl SplitTunnelDto {
    fn off() -> Self {
        Self { app_mode: "off".into(), apps: vec![], dest_mode: "off".into(), dests: vec![] }
    }
}

fn split_file() -> PathBuf {
    vault_path().with_file_name("split")
}

/// Сериализация в простой построчный формат (без новых зависимостей, человекочитаемо):
/// `app_mode=…` / `app=…`(×N) / `dest_mode=…` / `dest=…`(×N).
fn serialize_split(c: &SplitTunnelDto) -> String {
    let mut s = format!("app_mode={}\n", c.app_mode.trim());
    for a in &c.apps {
        let a = a.trim();
        if !a.is_empty() {
            s.push_str(&format!("app={a}\n"));
        }
    }
    s.push_str(&format!("dest_mode={}\n", c.dest_mode.trim()));
    for d in &c.dests {
        let d = d.trim();
        if !d.is_empty() {
            s.push_str(&format!("dest={d}\n"));
        }
    }
    s
}

fn parse_split(text: &str) -> SplitTunnelDto {
    let mut c = SplitTunnelDto::off();
    for line in text.lines() {
        let line = line.trim();
        // длинные префиксы (app_mode/dest_mode) проверяем ДО коротких (app/dest)
        if let Some(v) = line.strip_prefix("app_mode=") {
            c.app_mode = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("dest_mode=") {
            c.dest_mode = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("app=") {
            let v = v.trim();
            if !v.is_empty() {
                c.apps.push(v.to_string());
            }
        } else if let Some(v) = line.strip_prefix("dest=") {
            let v = v.trim();
            if !v.is_empty() {
                c.dests.push(v.to_string());
            }
        }
    }
    c
}

fn dto_to_split(c: &SplitTunnelDto) -> SplitTunnel {
    SplitTunnel {
        app_mode: SplitMode::parse(&c.app_mode),
        apps: c.apps.clone(),
        dest_mode: SplitMode::parse(&c.dest_mode),
        dests: c.dests.clone(),
    }
}

/// Загрузить сохранённую split-настройку (для `spawn_controller`). Файла нет / ошибка → Off.
fn load_split_config() -> SplitTunnel {
    match std::fs::read_to_string(split_file()) {
        Ok(text) => dto_to_split(&parse_split(&text)),
        Err(_) => SplitTunnel::default(),
    }
}

/// Сохранить split-настройку (GUI). Применяется со СЛЕДУЮЩЕГО подключения; переживает рестарт.
#[frb(sync)]
pub fn set_split_config(cfg: SplitTunnelDto) {
    let f = split_file();
    if let Some(d) = f.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::write(f, serialize_split(&cfg));
}

/// Прочитать сохранённую split-настройку (инициализация GUI). Файла нет → всё "off".
#[frb(sync)]
pub fn split_config() -> SplitTunnelDto {
    std::fs::read_to_string(split_file())
        .map(|t| parse_split(&t))
        .unwrap_or_else(|_| SplitTunnelDto::off())
}

/// Каталог данных, заданный платформой (Android передаёт filesDir через [`set_data_dir`]).
/// Если задан — хранилище кладём прямо в него (он уже приватный и writable, без подпапки `.config`).
/// Иначе: Windows — `%LOCALAPPDATA%\CitadelPQVPN`, прочие — `$XDG_CONFIG_HOME|~/.config/citadel-pqvpn`.
fn vault_path() -> PathBuf {
    if let Some(dir) = DATA_DIR.get() {
        return dir.join("vault.bin");
    }
    #[cfg(windows)]
    {
        windows_store_path().clone()
    }
    #[cfg(not(windows))]
    {
        xdg_store_path()
    }
}

/// Unix-путь хранилища (Linux/macOS-desktop): `$XDG_CONFIG_HOME|~/.config/citadel-pqvpn/vault.bin`.
/// На Windows остаётся только как адрес СТАРОГО (сломанного) расположения — для миграции.
fn xdg_store_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("citadel-pqvpn").join("vault.bin")
}

/// Windows: `%LOCALAPPDATA%\CitadelPQVPN\vault.bin` (+ разовый перенос старого хранилища).
///
/// Почему отдельная ветка. Общий резолвер ищет `XDG_CONFIG_HOME`/`HOME`, а на Windows их обычно нет
/// (профиль задают `LOCALAPPDATA`/`USERPROFILE`), поэтому он сваливался в `.` — то есть хранилище
/// оказывалось в РАБОЧЕМ КАТАЛОГЕ ПРОЦЕССА. Для установленного приложения это `C:\Program Files\
/// CitadelPQVPN`, и последствия ровно те, на которые жаловались:
///   • создание хранилища падало с «Отказано в доступе» (обычному пользователю туда не писать);
///   • если файл там всё же появился (запуск от администратора), смена пароля не сохранялась:
///     ЧТЕНИЕ из Program Files разрешено всем, а запись — нет, и отказ выглядел как «неверный пароль»;
///   • путь зависел от того, откуда запущен процесс, поэтому «обычный» и «от имени администратора»
///     запуски могли видеть РАЗНЫЕ хранилища.
/// `%LOCALAPPDATA%` (а не Roaming) — потому что vault несёт bearer-креды: их не надо синхронизировать
/// по доменному профилю. Доступ разграничивает ACL профиля пользователя.
#[cfg(windows)]
fn windows_store_path() -> &'static PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("USERPROFILE")
                    .map(|p| PathBuf::from(p).join("AppData").join("Local"))
            })
            // Профиля пользователя нет вовсе (среда сломана) — прежнее поведение, чтобы не падать.
            .unwrap_or_else(|| PathBuf::from("."));
        let path = base.join("CitadelPQVPN").join("vault.bin");
        if !path.is_file() {
            migrate_legacy_windows_store(&path);
        }
        path
    })
}

/// Разовый перенос хранилища со старого (cwd-зависимого) места в `%LOCALAPPDATA%`: иначе апгрейд
/// стёр бы пользователю профили — с его точки зрения приложение «забыло всё». Переносим весь
/// каталог: рядом с `vault.bin` лежат настройки (`killswitch`, `debug`, `split`, `screenshot_block`).
/// Best-effort: не смогли скопировать — работаем с чистого места (о чём говорим в журнал); не смогли
/// удалить оригинал (типично для `Program Files` без прав) — предупреждаем, что копия осталась.
#[cfg(windows)]
fn migrate_legacy_windows_store(new_vault: &std::path::Path) {
    let legacy_vault = xdg_store_path();
    if !legacy_vault.is_file() {
        return;
    }
    let (Some(legacy_dir), Some(new_dir)) = (legacy_vault.parent(), new_vault.parent()) else {
        return;
    };
    if let Err(e) = std::fs::create_dir_all(new_dir) {
        eprintln!("[vault] не создать {}: {e}", new_dir.display());
        return;
    }
    let Ok(entries) = std::fs::read_dir(legacy_dir) else { return };
    let mut moved = 0usize;
    for entry in entries.flatten() {
        if !entry.path().is_file() {
            continue;
        }
        let dst = new_dir.join(entry.file_name());
        match std::fs::copy(entry.path(), &dst) {
            Ok(_) => {
                moved += 1;
                if let Err(e) = std::fs::remove_file(entry.path()) {
                    eprintln!(
                        "[vault] старая копия {} осталась на месте ({e}) — удалите её вручную",
                        entry.path().display()
                    );
                }
            }
            Err(e) => eprintln!("[vault] не перенести {}: {e}", entry.path().display()),
        }
    }
    if moved > 0 {
        eprintln!(
            "[vault] хранилище перенесено {} → {} ({moved} файл(ов))",
            legacy_dir.display(),
            new_dir.display()
        );
    }
}

/// Задать каталог данных приложения (вызывается из Dart на старте, до любых vault-операций).
/// На Android — `getApplicationSupportDirectory()`; на десктопе можно не вызывать. Идемпотентно:
/// первый успешный вызов фиксирует путь (повторные молча игнорируются).
#[frb(sync)]
pub fn set_data_dir(dir: String) {
    let _ = DATA_DIR.set(PathBuf::from(dir));
}

fn profile_to_dto(p: &Profile) -> ProfileDto {
    let link = CredentialLink::from_uri(&p.uri).ok();
    ProfileDto {
        id: p.id.clone(),
        name: p.name.clone(),
        servers: link.as_ref().map(|l| l.servers.join(", ")).unwrap_or_default(),
        has_pin: link.as_ref().map(|l| l.cert_pin.is_some()).unwrap_or(false),
        has_pq_auth: link.as_ref().map(|l| l.mldsa_commit.is_some()).unwrap_or(false),
        has_obfs: link.as_ref().map(|l| l.obfs_psk.is_some()).unwrap_or(false),
        is_admin: link.as_ref().map(|l| l.is_admin()).unwrap_or(false),
        last_exit: p.last_exit.clone().unwrap_or_default(),
    }
}

/// Ссылка сохранённого профиля из vault (общая для connect/diag/admin-путей).
/// Ошибка — если vault заблокирован или профиль не найден. Секрет не покидает Rust-ядро.
/// M-9: устройственный Layer-1 ключ профиля, если активация подтверждена. Хранилище может быть
/// заперто (пользователь закрыл замок при живой сессии) — тогда `None`, и Layer-1 пойдёт ключом из
/// ссылки; сервер такой ключ уже не примет, зато человек увидит внятную причину, а не тишину.
pub(crate) fn device_seed_of(profile_id: &str) -> Option<[u8; 32]> {
    with_vault(|v| {
        Ok(v.list().into_iter().find(|p| p.id == profile_id).and_then(|p| {
            if p.enrolled {
                p.device_seed
            } else {
                None
            }
        }))
    })
    .ok()
    .flatten()
}

/// M-9: активировать профиль (одноразовая ссылка → устройственный доступ). Идемпотентна.
///
/// Возвращает `true`, если активация действительно произошла (или уже была подтверждена ранее);
/// `false` — издатель активации не требует (многоразовая ссылка старого образца). Ошибка —
/// просроченная ссылка, «уже активирована на другом устройстве», недоступный издатель: текст
/// показывается человеку как есть, он объясняет, что делать.
pub async fn vpn_activate_profile(id: String) -> Result<bool> {
    // Хранилище берётся ТОЛЬКО на время чтения профиля и двух коротких записей — держать его
    // замок через сетевой обмен с издателем (секунды таймаутов) нельзя ни по отзывчивости
    // интерфейса, ни по типам (std-мьютекс через `.await`).
    let profile = with_vault(|v| {
        v.list().into_iter().find(|p| p.id == id).ok_or_else(|| anyhow!("профиль не найден"))
    })?;
    let (sid, mid) = (id.clone(), id.clone());
    let done = citadel_client::activate_profile(
        &profile,
        |seed| with_vault(|v| v.set_device_seed(&sid, seed)),
        || with_vault(|v| v.mark_enrolled(&mid)),
    )
    .await?;
    Ok(done == citadel_client::Activation::Activated)
}

pub(crate) fn profile_uri(id: &str) -> Result<String> {
    let g = VAULT.lock().unwrap();
    let v = g.as_ref().ok_or_else(|| anyhow!("хранилище заблокировано"))?;
    v.list()
        .into_iter()
        .find(|p| p.id == id)
        .map(|p| p.uri)
        .ok_or_else(|| anyhow!("профиль не найден"))
}

/// Выполнить операцию над разблокированным vault (для admin-модуля: метки выданных абонентов).
/// Лок берётся только на время `f` — НЕ держать через await.
pub(crate) fn with_vault<T>(f: impl FnOnce(&mut Vault) -> Result<T>) -> Result<T> {
    let mut g = VAULT.lock().unwrap();
    let v = g.as_mut().ok_or_else(|| anyhow!("хранилище заблокировано"))?;
    f(v)
}

// ───────────────────────────── vault FFI ─────────────────────────────

/// Существует ли файл хранилища (UI: разблокировать vs первый запуск).
#[frb(sync)]
pub fn vault_exists() -> bool {
    Vault::exists(vault_path())
}

/// Разблокирован ли vault в текущей сессии приложения.
#[frb(sync)]
pub fn vault_is_unlocked() -> bool {
    VAULT.lock().unwrap().is_some()
}

/// Заблокировать (забыть ключ из памяти).
///
/// **Замок хранилища не имеет отношения к туннелю и обязан его не трогать.** Живой сессии vault не
/// нужен: ссылка разобрана в [`spawn_controller`] при старте, свежий Layer-1 токен на каждый
/// establish добывает собственный refresher (у него своя копия issuer+seed), а `update_last_exit`
/// под замком просто пропускается. Инвариант закреплён тестом `vault_lock_does_not_touch_session`:
/// раньше «Заблокировать хранилище» на поднятом туннеле обрывало связь (Dart звал `disconnect()`),
/// хотя пользователь просил ровно обратное — убрать профили с глаз, а не выйти из VPN.
#[frb(sync)]
pub fn vault_lock() {
    *VAULT.lock().unwrap() = None;
}

/// Где лежит файл хранилища (диагностика в UI: «нет доступа» без пути — бесполезное сообщение).
#[frb(sync)]
pub fn vault_location() -> String {
    vault_path().display().to_string()
}

/// Минимальная длина мастер-пароля из ядра — чтобы UI проверял ДО дорогого Argon2-derive и
/// называл человеку то же число, что enforce'ит крипта (без второй захардкоженной константы).
#[frb(sync)]
pub fn vault_min_password_len() -> u32 {
    citadel_client::MIN_PASSPHRASE_LEN as u32
}

/// Открыть хранилище мастер-паролем (Argon2id — намеренно НЕ sync: тяжело, уводим с UI-потока).
/// Ошибка приходит в UI уже человеческой фразой (см. [`vault_error`]).
pub fn vault_unlock(passphrase: String) -> Result<()> {
    let path = vault_path();
    let v = Vault::open_detailed(&path, &passphrase).map_err(|e| vault_error(e, &path))?;
    *VAULT.lock().unwrap() = Some(v);
    Ok(())
}

/// Создать новое хранилище под мастер-паролем (первый запуск / первое сохранение).
pub fn vault_create(passphrase: String) -> Result<()> {
    citadel_client::vault::check_passphrase(&passphrase)?; // политика — до файловых операций
    let path = vault_path();
    let v = Vault::create(&path, &passphrase).map_err(|e| write_error(e, &path, "Создать"))?;
    *VAULT.lock().unwrap() = Some(v);
    Ok(())
}

/// Сменить мастер-пароль. Три отказа — три РАЗНЫХ ответа, потому что чинятся они по-разному:
/// новый пароль не проходит политику (её видно до дорогого derive), текущий пароль не тот,
/// файл не удалось перезаписать. Раньше всё это приходило в UI как «текущий пароль неверен» —
/// и пользователь перебирал верный пароль, пока ядро жаловалось на длину нового.
pub fn vault_change_password(old: String, new: String) -> Result<()> {
    citadel_client::vault::check_passphrase(&new)?; // про НОВЫЙ пароль — единственная политика здесь
    let path = vault_path();
    if !Vault::password_matches(&path, &old).map_err(|e| read_error(e, &path))? {
        bail!("Текущий пароль неверен");
    }
    let mut g = VAULT.lock().unwrap();
    g.as_mut()
        .ok_or_else(|| anyhow!("Хранилище заблокировано — разблокируйте его и повторите"))?
        .change_password(&new)
        .map_err(|e| write_error(e, &path, "Сохранить"))
}

// ────────── C9: разблокировка хранилища отпечатком (Android; строго по желанию) ──────────
//
// **Дефолт — выключено, и это часть замысла.** Биометрия удобна, но меняет модель угроз: палец
// прикладывают под принуждением (досмотр на границе, отделение), а пароль остаётся в голове.
// Поэтому включает её только сам человек, пароль продолжает работать всегда, а выключение
// мгновенно и не требует пароля (хранилище в этот момент уже открыто).
//
// Как это устроено (детали формата — в `citadel_client::vault`): ядро отдаёт мастер-ключ
// хранилища платформе, платформа заворачивает его НЕЭКСПОРТИРУЕМЫМ ключом Android Keystore,
// который требует биометрической аутентификации на КАЖДУЮ операцию, и возвращает непрозрачный
// блоб. Блоб ложится в файл хранилища отдельным слотом. Обратно: блоб → Keystore (после отпечатка)
// → мастер-ключ → хранилище открыто, Argon2id считать не нужно.
//
// Почему не «спросить у ОС, приложен ли палец, и разблокировать паролем из настроек»: такой ответ
// — обычный булев результат в памяти приложения, и на рутованном устройстве он подделывается
// хуком. Здесь же расшифровку делает сам TEE и только после успешной аутентификации; подделать
// «да» бесполезно, ключ из TEE не выйдет.
//
// Метка слота — платформа, а не устройство: она различает СПОСОБ (Android Keystore, в будущем
// Windows Hello), чтобы UI знал, что предлагать, не зная формата.
const PLATFORM_SLOT_LABEL: &str = "android-keystore";

/// Настроена ли разблокировка отпечатком для этого файла хранилища. Читается БЕЗ пароля (в слоте
/// нет секрета — он бесполезен без ключа из TEE), потому что экран блокировки обязан решить,
/// показывать ли кнопку, до того как что-либо разблокировано.
#[frb(sync)]
pub fn vault_biometric_enrolled() -> bool {
    Vault::platform_slot_blob(vault_path()).is_some()
}

/// Завёрнутый мастер-ключ из файла — его надо отдать Keystore на разворачивание.
#[frb(sync)]
pub fn vault_biometric_blob() -> Option<Vec<u8>> {
    Vault::platform_slot_blob(vault_path()).map(|s| s.blob)
}

/// **Мастер-ключ хранилища для обёртки платформой.** Требует разблокированного хранилища: включить
/// биометрию можно только тому, кто уже доказал знание пароля.
///
/// Байты пересекают границу FFI и на короткое время живут в Dart — иного пути нет, ключ обязан
/// попасть в `Cipher` из Keystore, а тот живёт в Kotlin. Вызывающий обязан затереть свою копию
/// сразу после обёртки (см. `lib/biometric.dart`). Экспозиция ограничена: это тот же процесс, в
/// котором уже лежит расшифрованное хранилище, — читающий его память противник и так победил.
pub fn vault_biometric_key_to_wrap() -> Result<Vec<u8>> {
    with_vault(|v| Ok(v.master_key().to_vec()))
}

/// Включить разблокировку отпечатком: положить в файл блоб, который вернул Keystore.
pub fn vault_biometric_enable(wrapped: Vec<u8>) -> Result<()> {
    let path = vault_path();
    with_vault(|v| {
        v.set_platform_slot(wrapped, PLATFORM_SLOT_LABEL)
            .map_err(|e| write_error(e, &path, "Сохранить"))
    })
}

/// Выключить разблокировку отпечатком (слот из файла долой). Ключ в самом Keystore удаляет
/// платформенный слой — здесь только файл.
///
/// Мастер-ключ при этом НЕ меняется, и это осознанно: сменить его — значит перезавернуть слот
/// пароля, а пароля у нас в этот момент нет (хранилище могли открыть тем же отпечатком). Остаточный
/// риск — старая КОПИЯ файла хранилища плюс живой ключ в Keystore; закрывается тем, что ключ
/// удаляется вместе со слотом. Человеку, у которого утекли резервные копии, поможет смена пароля.
pub fn vault_biometric_disable() -> Result<()> {
    let path = vault_path();
    with_vault(|v| {
        v.clear_platform_slot().map_err(|e| write_error(e, &path, "Сохранить"))
    })
}

/// Открыть хранилище мастер-ключом, который Keystore вернул после успешного отпечатка.
///
/// Отказ здесь — это НЕ «палец не подошёл» (палец проверила ОС до нас): это «ключ не открывает
/// именно этот файл» — хранилище пересоздали, восстановили из чужой копии, подменили. Поэтому и
/// фраза человеку другая, чем при неверном пароле.
pub fn vault_unlock_biometric(master_key: Vec<u8>) -> Result<()> {
    let path = vault_path();
    let v = Vault::open_with_master_key(&path, &master_key).map_err(|e| match e {
        citadel_client::VaultOpenError::WrongPassword => {
            anyhow!("Отпечаток больше не открывает это хранилище — войдите мастер-паролем")
        }
        citadel_client::VaultOpenError::Unavailable(e) => read_error(e, &path),
    })?;
    *VAULT.lock().unwrap() = Some(v);
    Ok(())
}

/// Отказ открытия хранилища → фраза для человека. Верхняя строка попадает в диалог, полная цепочка
/// причин — в журнал отладки (S1.4: журнал локальный, ring-буфер).
fn vault_error(e: citadel_client::VaultOpenError, path: &std::path::Path) -> anyhow::Error {
    match e {
        citadel_client::VaultOpenError::WrongPassword => anyhow!("Неверный мастер-пароль"),
        citadel_client::VaultOpenError::Unavailable(e) => read_error(e, path),
    }
}

/// Отказ ЧТЕНИЯ файла хранилища (не про пароль): «нет доступа», «файла нет», всё прочее.
fn read_error(e: anyhow::Error, path: &std::path::Path) -> anyhow::Error {
    eprintln!("[vault] чтение {}: {e:#}", path.display());
    if is_permission_denied(&e) {
        return anyhow!("Нет доступа к файлу хранилища:\n{}", path.display());
    }
    if is_not_found(&e) {
        return anyhow!("Файл хранилища не найден:\n{}", path.display());
    }
    anyhow!("Хранилище недоступно: {}", first_line(&e))
}

/// Отказ ЗАПИСИ файла хранилища. `action` — «Создать»/«Сохранить» (начало фразы).
fn write_error(e: anyhow::Error, path: &std::path::Path, action: &str) -> anyhow::Error {
    eprintln!("[vault] запись {}: {e:#}", path.display());
    let msg = first_line(&e);
    let dir = path.parent().unwrap_or(path).display();
    if is_permission_denied(&e) {
        return anyhow!("Нет доступа к папке хранилища:\n{dir}");
    }
    anyhow!("{action} хранилище не удалось: {msg}")
}

/// Первая строка `Debug`-цепочки anyhow — самый верхний, человеческий контекст (остальное —
/// «Caused by:» для журнала, в диалоге оно только мешает).
fn first_line(e: &anyhow::Error) -> String {
    format!("{e}").lines().next().unwrap_or_default().to_string()
}

/// Есть ли в цепочке причин io-ошибка данного вида (текст ОС локализован — сверяем по `ErrorKind`).
fn io_kind_in_chain(e: &anyhow::Error, kind: std::io::ErrorKind) -> bool {
    e.chain().any(|c| c.downcast_ref::<std::io::Error>().is_some_and(|io| io.kind() == kind))
}

fn is_permission_denied(e: &anyhow::Error) -> bool {
    io_kind_in_chain(e, std::io::ErrorKind::PermissionDenied)
}

fn is_not_found(e: &anyhow::Error) -> bool {
    io_kind_in_chain(e, std::io::ErrorKind::NotFound)
}

/// Список профилей (vault должен быть разблокирован).
#[frb(sync)]
pub fn vault_list() -> Result<Vec<ProfileDto>> {
    let g = VAULT.lock().unwrap();
    let v = g.as_ref().ok_or_else(|| anyhow!("хранилище заблокировано"))?;
    Ok(v.list().iter().map(profile_to_dto).collect())
}

/// Добавить профиль из `citadel://`-ссылки (валидируется через тот же анти-перебор-гейт, что и
/// живое превью, — иначе «добавить» осталось бы быстрым способом проверять догадки).
/// Не `sync`: гейт спит, а на UI-потоке спать нельзя.
pub fn vault_add(name: String, uri: String) -> Result<ProfileDto> {
    if guarded_parse_link(&uri).is_none() {
        bail!("Ссылка не распознана");
    }
    let mut g = VAULT.lock().unwrap();
    let v = g.as_mut().ok_or_else(|| anyhow!("Хранилище заблокировано"))?;
    Ok(profile_to_dto(&v.add(&name, &uri)?))
}

/// Удалить профиль по id.
#[frb(sync)]
pub fn vault_remove(id: String) -> Result<()> {
    let mut g = VAULT.lock().unwrap();
    g.as_mut().ok_or_else(|| anyhow!("хранилище заблокировано"))?.remove(&id)
}

/// Переименовать профиль (пункт «Переименовать» в меню профиля). Имя — отображаемое поле, ядро
/// само чистит его от управляющих символов и ужимает до предела; пустое — отказ.
#[frb(sync)]
pub fn vault_rename(id: String, name: String) -> Result<()> {
    let mut g = VAULT.lock().unwrap();
    g.as_mut().ok_or_else(|| anyhow!("Хранилище заблокировано"))?.rename(&id, &name)
}

/// Переставить профиль на позицию `index` (перетаскивание в списке профилей). Порядок хранится в
/// самом vault, поэтому переживает перезапуск и переносится вместе с хранилищем. Индекс за границей
/// списка ядро прижимает к последней позиции.
#[frb(sync)]
pub fn vault_move_to(id: String, index: u32) -> Result<()> {
    let mut g = VAULT.lock().unwrap();
    g.as_mut().ok_or_else(|| anyhow!("Хранилище заблокировано"))?.move_to(&id, index as usize)
}

/// Предел длины имени профиля из ядра — чтобы поле ввода в UI ограничивало ровно тем же числом,
/// а не «своим» (иначе человек набирает имя, которое молча обрежется).
#[frb(sync)]
pub fn vault_max_name_len() -> u32 {
    citadel_client::MAX_PROFILE_NAME_LEN as u32
}

/// Разобрать `citadel://`-ссылку → превью для UI (валидация при вставке).
///
/// НЕ `sync` и намеренно небыстрая: см. [`guarded_parse_link`] — мгновенный вердикт «распознана /
/// не распознана» на каждый чих клавиатуры был бесплатным оракулом для подбора ссылки.
pub fn parse_link_summary(uri: String) -> LinkSummaryDto {
    match guarded_parse_link(&uri) {
        Some(s) => LinkSummaryDto {
            valid: true,
            servers: s.servers.join(", "),
            server_name: s.server_name,
            kx_suite: s.kx_suite,
            has_pin: s.has_pin,
            has_pq_auth: s.has_pq_auth,
            has_obfs: s.has_obfs,
            is_admin: s.is_admin,
            is_enroll: s.is_enroll,
            activate_until_unix: s.activate_until as i64,
            verify_code: s.verify_code,
        },
        None => LinkSummaryDto::default(),
    }
}

/// Минимальное время ответа проверки, шаг удорожания на каждую неудачу подряд и потолок ожидания
/// (сброс — на первой распознанной ссылке). Числа скромные намеренно: см. оговорку о границах
/// применимости в [`guarded_parse_link`] — платить за это секундами UX бессмысленно.
const LINK_CHECK_MIN: std::time::Duration = std::time::Duration::from_millis(600);
const LINK_CHECK_STEP: std::time::Duration = std::time::Duration::from_millis(600);
const LINK_CHECK_MAX: std::time::Duration = std::time::Duration::from_secs(4);

/// Счётчик подряд идущих нераспознанных ссылок (штраф темпа). Живёт в процессе: перезапуск
/// приложения сбрасывает — против онлайн-подбора этого достаточно, дольше держать штраф значило бы
/// наказывать человека, который просто закрыл окно.
static LINK_FAILS: Mutex<u32> = Mutex::new(0);

/// Разбор `citadel://`-ссылки с ограничением темпа проверок:
///   • ответ не раньше [`LINK_CHECK_MIN`] — и для валидной, и для битой ссылки (тайминг сам по
///     себе не должен их различать);
///   • каждая следующая неудача подряд дороже предыдущей (до [`LINK_CHECK_MAX`]);
///   • проверки сериализованы одним мьютексом — параллельными вызовами задержку не обойти.
///
/// ГРАНИЦЫ ПРИМЕНИМОСТИ — чтобы никто не принял это за защиту от подбора ссылки. Разбор проверяет
/// СТРУКТУРУ (`base64url` → CBOR → версия → dns/routes), а не секреты: любые 32 случайных байта в
/// поле `obfs_psk` дают вердикт «валидна». Подобрать через него ключи нельзя в принципе. Полезен
/// вердикт лишь для восстановления УЖЕ утёкшей, но повреждённой ссылки — а такую атаку ведут не
/// через наш UI: формат открытый, парсер публичный (репозиторий, `citadel-linkgen`, сам бинарь
/// клиента), и догадки проверяются офлайн своей копией кода со скоростью миллионов в секунду.
/// Настоящий рубеж против подбора кред — сетевой (квоты issuer/exit, single-session lease, отзыв),
/// а против утечки ссылки — гигиена (vault, FLAG_SECURE, no-logs). Здесь же — гигиена темпа и
/// главное: вердикт «не распознана» больше не выскакивает на каждый символ недописанной ссылки.
fn guarded_parse_link(uri: &str) -> Option<citadel_client::api::CredentialSummary> {
    let started = std::time::Instant::now();
    // Лок держим ВКЛЮЧАЯ сон — это и есть сериализация темпа, а не оплошность.
    let mut fails = LINK_FAILS.lock().unwrap();
    let parsed = citadel_client::api::parse_link(uri.to_string()).ok();
    let wait = if parsed.is_some() {
        LINK_CHECK_MIN
    } else {
        LINK_CHECK_MIN
            .saturating_add(LINK_CHECK_STEP.saturating_mul(*fails))
            .min(LINK_CHECK_MAX)
    };
    if let Some(left) = wait.checked_sub(started.elapsed()) {
        std::thread::sleep(left);
    }
    *fails = if parsed.is_some() { 0 } else { fails.saturating_add(1) };
    parsed
}

/// C7.4: QR-матрица `citadel://`-ссылки (экран выдачи доступа абоненту). Sync — кодирование QR
/// дёшево, а ссылка и так уже в Dart-памяти (только что выдана).
#[frb(sync)]
pub fn link_qr(uri: String) -> Result<QrDto> {
    let (size, cells) = citadel_client::api::link_qr_matrix(uri)?;
    Ok(QrDto { size, cells })
}

// ───────────────────────────── vpn FFI ─────────────────────────────

fn vpn_state_str(s: VpnState) -> &'static str {
    match s {
        VpnState::Idle => "idle",
        VpnState::Connecting => "connecting",
        VpnState::Up => "up",
        VpnState::Migrating => "migrating",
        VpnState::Down => "down",
    }
}

fn to_dto(ev: VpnEvent) -> VpnEventDto {
    let mut d = VpnEventDto {
        kind: String::new(),
        state: String::new(),
        exit: String::new(),
        transport: String::new(),
        cidr: String::new(),
        error: String::new(),
    };
    match ev {
        VpnEvent::State(s) => {
            d.kind = "state".into();
            d.state = vpn_state_str(s).into();
        }
        VpnEvent::Connected { exit, transport, cidr } => {
            d.kind = "connected".into();
            d.exit = exit;
            d.transport = transport;
            d.cidr = cidr;
        }
        VpnEvent::Error(e) => {
            d.kind = "error".into();
            d.error = e;
        }
    }
    d
}

/// Плоский `state`-DTO (для прайминга re-attach текущим состоянием).
fn state_dto(state: &str) -> VpnEventDto {
    VpnEventDto {
        kind: "state".into(),
        state: state.into(),
        exit: String::new(),
        transport: String::new(),
        cidr: String::new(),
        error: String::new(),
    }
}

/// Отметить exit последнего успешного коннекта в vault (только для сохранённого профиля).
fn update_last_exit(profile_id: &Option<String>, ev: &VpnEvent) {
    if let (VpnEvent::Connected { exit, .. }, Some(id)) = (ev, profile_id) {
        if let Ok(mut g) = VAULT.lock() {
            if let Some(v) = g.as_mut() {
                let _ = v.set_last_exit(id, exit);
            }
        }
    }
}

/// Обновить снимок [`ANDROID_STATUS`] по событию контроллера (нюанс 2: перезапуск видит живой VPN).
/// Возвращает `false`, если поколение устарело (стартовала/остановилась новая сессия) → форвард-
/// задача должна выйти. Проверка `ANDROID_GEN` ПОД локом статуса делает её атомарной с переустановкой
/// статуса в [`android_start`]/[`android_stop_session`] → поздний `Down` старого контроллера не
/// перезапишет статус новой сессии (иначе рестарт увидел бы живой VPN как «отключён»).
fn update_android_status(ev: &VpnEvent, generation: u64) -> bool {
    let mut st = ANDROID_STATUS.lock().unwrap();
    if ANDROID_GEN.load(std::sync::atomic::Ordering::SeqCst) != generation {
        return false;
    }
    match ev {
        VpnEvent::State(s) => st.state = vpn_state_str(*s),
        VpnEvent::Connected { exit, transport, cidr } => {
            st.exit = exit.clone();
            st.transport = transport.clone();
            st.cidr = cidr.clone();
        }
        VpnEvent::Error(_) => {}
    }
    true
}

/// Общее ядро запуска сессии (desktop+Android): останавливает прошлую активную сессию (её нативный
/// loop иначе продолжит крутиться поверх новой — двойной establish/туннель), создаёт `VpnController`
/// под ссылку (+ token-refresher: свежий Layer-1 токен на КАЖДЫЙ establish — анти-double-spend на
/// реконнекте, exit иначе рвёт потраченный токен), кладёт в `ACTIVE` и крутит `connect`-loop на rt().
/// Реконнект/backoff держит сам нативный loop → переживает смерть UI-изолята (Android — C6).
/// Возвращает подписку на события для платформенной пересылки в UI.
fn spawn_controller(
    uri: &str,
    provider: Arc<dyn TunProvider>,
    // M-9: Layer-1 ключ, которым представляться издателю. `None` → из ссылки (профиль не
    // активирован либо ссылка многоразовая); `Some` → устройственный ключ активированного профиля.
    layer1_seed: Option<[u8; 32]>,
) -> Result<tokio::sync::broadcast::Receiver<VpnEvent>> {
    // C5.4b: разбираем ссылку целиком — из неё issuer+client_seed для авто-фетча Layer-1 токена.
    let link = CredentialLink::from_uri(uri)?;
    let mut cfg = link.to_client_config();
    cfg.killswitch = killswitch_enabled(); // C6/M9: kill-switch по GUI-тумблеру (desktop; Android — OS-level)
    cfg.split = load_split_config(); // C8.3: split-tunnel по приложениям/назначениям (Android; desktop игнорит)
    // M-8: профиль «высокий риск» — шейпинг таймингов исходящего потока по GUI-тумблеру.
    cfg.pacing = pacing_enabled().then(|| "on".to_string());
    // Остановить прошлую сессию перед новой (анти-double-connect): её loop глушим, иначе он продолжит
    // держать/реконнектить старый туннель параллельно новому. Берём Arc и disconnect() вне лока.
    let prev = ACTIVE.lock().unwrap().take();
    if let Some(old) = prev {
        old.disconnect();
    }
    let controller = Arc::new(VpnController::new());
    *ACTIVE.lock().unwrap() = Some(controller.clone());
    // S2.1/A1 + PQ: Layer-1 требует issuer + issuer_pin (PQ-TLS канал) + issuer_mldsa
    // (PQ-обязательство издателя) + client_seed. Чего-то нет → кошелёк не ставим (token-less
    // путь; exit откажет, если требует токен — misconfig виден).
    // §7.1 (заход 7): вместо «токен у издателя на КАЖДЫЙ establish» — кошелёк: пачка на эпоху в
    // памяти + фоновая дозаправка со случайной задержкой ЧЕРЕЗ туннель. Реконнекты (в т.ч.
    // мобильные, самые частые) издателю больше не видны, а видимая ему дозаправка приходит с
    // адреса exit'а. Ошибки фетча логируются внутри кошелька полной цепочкой `{e:#}` — диагноз
    // «issuer недоступен / pin / obfs / осиротевший kill-switch» виден в лог-панели ядра.
    let seed = layer1_seed.or(link.client_seed);
    if !citadel_client::token_agent::install_with_seed(&controller, &link, seed) {
        eprintln!("[token] Layer-1 не настроен в ссылке — идём к exit'у без токена");
    }
    // Подписка ДО begin() (первый Connecting буферизуется в broadcast до старта форвард-задачи).
    let rx = controller.subscribe();
    rt().spawn(async move {
        controller.begin();
        #[cfg(target_os = "android")]
        wait_for_socket_protector().await;
        let _ = controller.connect(cfg, provider).await;
    });
    Ok(rx)
}

/// Android: дождаться регистрации `CitadelVpnService` протектором сокетов, прежде чем движок
/// создаст ПЕРВЫЙ транспортный сокет.
///
/// Порядок «сервис → сессия» держит Kotlin (`startService` ждёт `onServiceReady`), но полагаться
/// только на него нельзя: сервис может пересоздаваться (быстрое «Отключить → Подключить»,
/// воскрешение по START_STICKY), и тогда между снятием старого протектора и регистрацией нового
/// есть окно. Сокет, созданный в этом окне, не защищён — а значит, уйдёт в собственный туннель,
/// как только поднимется TUN. Симптом при этом обманчив: хендшейк проходит (туннеля ещё нет), и
/// беда всплывает лишь на данных.
///
/// Ждём коротко и не насмерть: если протектора нет и через секунду — идём как есть, но говорим об
/// этом прямо. Пустая сессия хуже, чем сессия с честным предупреждением в журнале.
#[cfg(target_os = "android")]
async fn wait_for_socket_protector() {
    use std::time::{Duration, Instant};
    const WAIT: Duration = Duration::from_secs(1);
    let started = Instant::now();
    while !citadel_client::protector_active() {
        if started.elapsed() >= WAIT {
            eprintln!(
                "[protect] ⚠ VpnService не зарегистрировался за {}с — сокеты движка сейчас НЕ \
                 защищены от собственного туннеля",
                WAIT.as_secs()
            );
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    if started.elapsed() > Duration::from_millis(50) {
        eprintln!("[protect] протектор сокетов встал за {} мс", started.elapsed().as_millis());
    }
}

/// Desktop: старт через polkit-helper (`GuiTunProvider`) + прямая пересылка событий в `sink`
/// (десктопный изолят живёт с процессом → swap-able sink не нужен, в отличие от Android).
fn start_connect(uri: &str, profile_id: Option<String>, sink: StreamSink<VpnEventDto>) -> Result<()> {
    // Windows — служба citadel-svc (W2, named pipe); прочий desktop — polkit-helper.
    #[cfg(windows)]
    let provider: Arc<dyn TunProvider> = Arc::new(WindowsTunProvider::default());
    #[cfg(not(windows))]
    let provider: Arc<dyn TunProvider> = Arc::new(GuiTunProvider::default());
    // M-9: сохранённый профиль мог быть активирован на этом устройстве — тогда Layer-1 идёт
    // устройственным ключом. Сама активация делается отдельным шагом (`activate`), потому что
    // требует хранилища и сети; здесь только выбираем ключ.
    let seed = profile_id.as_deref().and_then(device_seed_of);
    let mut rx = spawn_controller(uri, provider, seed)?;
    rt().spawn(async move {
        while let Ok(ev) = rx.recv().await {
            update_last_exit(&profile_id, &ev);
            if sink.add(to_dto(ev)).is_err() {
                break; // Dart отписался
            }
        }
    });
    Ok(())
}

/// Подключить по «сырой» ссылке (ещё не сохранённой — первый коннект перед сохранением).
pub fn vpn_connect(link: String, sink: StreamSink<VpnEventDto>) -> Result<()> {
    start_connect(&link, None, sink)
}

/// Подключить по сохранённому профилю (ссылка достаётся из vault, не покидает ядро).
pub fn vpn_connect_profile(id: String, sink: StreamSink<VpnEventDto>) -> Result<()> {
    let uri = profile_uri(&id)?;
    start_connect(&uri, Some(id), sink)
}

// ─────────────────────────── Android: нативная сессия (C6/S1) ───────────────────────────
// TUN-fd даёт VpnService (не polkit-helper). `AndroidTunProvider::configure` зовёт
// `CitadelVpnService.establishTun(...)` по JNI (Rust→Kotlin) и оборачивает fd — так ТОТ ЖЕ
// `VpnController::connect`-loop, что на desktop, держит establish+реконнект НАТИВНО (переживает
// смерть UI-изолята: сессия жива, пока сервис активен, даже при закрытом окне). Заменяет прежний
// двухфазный Dart-цикл (establish → Dart строит TUN → data_plane).

/// Провайдер туннеля для Android: `configure` (в `VpnController::connect`-loop, на КАЖДЫЙ
/// (ре)коннект) зовёт `CitadelVpnService.establishTun(...)` по JNI → detached fd → `TunIo`.
/// Аналог desktop `GuiTunProvider` (там fd приходит от polkit-helper). Внутренний, не FFI: codegen
/// его пропускает (unit-struct — логирует INFO-skip, Dart-тип не генерит; это и нужно).
struct AndroidTunProvider;

impl TunProvider for AndroidTunProvider {
    fn configure(&self, p: &TunParams) -> Result<Arc<dyn TunIo>> {
        #[cfg(target_os = "android")]
        {
            let fd = crate::android_jni::establish_tun(p)?;
            if fd < 0 {
                return Err(anyhow!("VpnService.establish() не выдал TUN-fd (нет разрешения VPN?)"));
            }
            // SAFETY: fd получен от VpnService.establish() (detachFd) — владеем им единолично.
            Ok(unsafe { citadel_client::tun_from_fd(fd) })
        }
        // Не-Android: провайдер не используется (frb-функции ниже зовутся лишь из Android-Dart), но
        // тип компилируется всюду — не городим cfg вокруг frb-поверхности (как прежние android_*).
        #[cfg(not(target_os = "android"))]
        {
            let _ = p;
            Err(anyhow!("AndroidTunProvider доступен только на Android"))
        }
    }
}

/// Android: общий старт нативной сессии. Спавнит контроллер с `AndroidTunProvider`, ставит свежий
/// статус+sink (перекрывает мёртвый от прошлого изолята) и ПЕРСИСТЕНТНУЮ форвард-задачу: она обновляет
/// [`ANDROID_STATUS`] на каждое событие (даже когда Dart не подписан → перезапуск видит живой VPN,
/// нюанс 2) и шлёт в swap-able [`ANDROID_SINK`]. Поколение [`ANDROID_GEN`] глушит задачу прошлой
/// сессии. Останов — [`android_stop_session`].
fn android_start(uri: &str, profile_id: Option<String>, sink: StreamSink<VpnEventDto>) -> Result<()> {
    // M-9: как и на десктопе — активированный профиль ходит своим устройственным ключом.
    let seed = profile_id.as_deref().and_then(device_seed_of);
    let mut rx = spawn_controller(uri, Arc::new(AndroidTunProvider), seed)?; // парсит ссылку (может упасть)
    let generation = ANDROID_GEN.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
    {
        let mut st = ANDROID_STATUS.lock().unwrap();
        *st = AndroidStatus::idle();
        st.state = "connecting";
        st.profile_id = profile_id.clone().unwrap_or_default();
    }
    *ANDROID_SINK.lock().unwrap() = Some(sink);
    rt().spawn(async move {
        while let Ok(ev) = rx.recv().await {
            // Обновить статус (нюанс 2) — и выйти, если сессию сменили (устаревшее поколение).
            if !update_android_status(&ev, generation) {
                break;
            }
            // Постоянная нотификация — единственное, что видно о сессии при закрытом окне: держим
            // её текст в согласии с состоянием движка (переподключение ≠ «туннель активен»).
            #[cfg(target_os = "android")]
            if let VpnEvent::State(s) = &ev {
                crate::android_jni::set_status(vpn_state_str(*s));
            }
            update_last_exit(&profile_id, &ev);
            // Переслать в текущий изолят (если подписан); мёртвый sink снимаем до re-attach.
            let mut guard = ANDROID_SINK.lock().unwrap();
            if let Some(s) = guard.as_ref() {
                if s.add(to_dto(ev)).is_err() {
                    *guard = None;
                }
            }
        }
    });
    Ok(())
}

/// Android: старт нативной сессии (сырая ссылка). Останов — [`android_stop_session`].
pub fn android_start_session(link: String, sink: StreamSink<VpnEventDto>) -> Result<()> {
    android_start(&link, None, sink)
}

/// Android: старт нативной сессии по сохранённому профилю (ссылка не покидает ядро).
pub fn android_start_session_profile(id: String, sink: StreamSink<VpnEventDto>) -> Result<()> {
    let uri = profile_uri(&id)?;
    android_start(&uri, Some(id), sink)
}

/// Android: снимок статуса сессии (sync) — перезапуск (новый изолят) спрашивает при старте, чтобы
/// отразить живой VPN, а не показать «отключено» и не поднять второй коннект поверх (нюанс 2).
#[frb(sync)]
pub fn android_session_status() -> AndroidStatusDto {
    let st = ANDROID_STATUS.lock().unwrap();
    AndroidStatusDto {
        state: st.state.into(),
        exit: st.exit.clone(),
        transport: st.transport.clone(),
        cidr: st.cidr.clone(),
        profile_id: st.profile_id.clone(),
    }
}

/// Android: переподписать новый Dart-изолят на события живой сессии (перезапуск после закрытия окна).
/// Ставит `sink` текущим (перекрывает мёртвый) и сразу праймит его снимком (state + connected-инфо),
/// чтобы UI-поток был консистентен без ожидания следующего события контроллера.
pub fn android_attach_events(sink: StreamSink<VpnEventDto>) -> Result<()> {
    {
        let st = ANDROID_STATUS.lock().unwrap();
        let _ = sink.add(state_dto(st.state));
        if !st.exit.is_empty() {
            let _ = sink.add(VpnEventDto {
                kind: "connected".into(),
                state: String::new(),
                exit: st.exit.clone(),
                transport: st.transport.clone(),
                cidr: st.cidr.clone(),
                error: String::new(),
            });
        }
    }
    *ANDROID_SINK.lock().unwrap() = Some(sink);
    Ok(())
}

/// Android: остановить сессию (пользователь нажал «Отключить»). Глушит нативный loop (реконнект),
/// инкремент [`ANDROID_GEN`] выводит форвард-задачу, статус → idle, sink снят — чтобы перезапуск
/// не принял мёртвую сессию за живую.
#[frb(sync)]
pub fn android_stop_session() {
    ANDROID_GEN.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    if let Some(c) = ACTIVE.lock().unwrap().take() {
        c.disconnect();
    }
    *ANDROID_STATUS.lock().unwrap() = AndroidStatus::idle();
    *ANDROID_SINK.lock().unwrap() = None;
}

/// Android: есть ли активная нативная сессия (живой `VpnController` — включая фазу переподключения:
/// он остаётся в [`ACTIVE`], пока сессию не остановили явно). Зовётся из JNI при воскрешении
/// `CitadelVpnService` системой, чтобы отличить «процесс жив, туннель работает» от «процесс убили,
/// восстанавливать нечего» (см. `Java_..._nativeHasSession`).
#[cfg(target_os = "android")]
pub(crate) fn has_active_session() -> bool {
    // Отравленный мьютекс (паника под локом) — сам по себе повод считать сессию нежизнеспособной.
    ACTIVE.lock().map(|g| g.is_some()).unwrap_or(false)
}

/// Android: сигнал «сменилась underlying-сеть» (WiFi↔LTE/toggle) → активный `VpnController`
/// оборвёт текущий pump и переустановит сессию над новой сетью СРАЗУ (не ждёт pump-watchdog ~8с).
/// No-op, если активной сессии нет. Зовётся из JNI `Java_..._nativeNetworkChanged` (NetworkCallback
/// живёт в `CitadelVpnService` — переживает Activity), т.е. сигнал нативный, минуя Dart (S2).
#[cfg(target_os = "android")]
pub(crate) fn notify_active_network_changed() {
    if let Some(c) = ACTIVE.lock().unwrap().as_ref() {
        c.notify_network_changed();
    }
}

/// Разорвать активную сессию (если есть).
#[frb(sync)]
pub fn vpn_disconnect() {
    let had = ACTIVE.lock().unwrap().take();
    if let Some(c) = &had {
        c.disconnect();
    }
    // Linux-desktop: гарантированно снять kill-switch. При чистом disconnect из фазы `up` его снимет
    // сам helper по сигналу 'Q' (clean_shutdown); но если disconnect пришёлся на фазу РЕКОНЕКТА,
    // живого helper'а нет → правила остались бы fail-closed и интернет заблокирован после выхода.
    // Явный disarm (идемпотентный) закрывает эту дыру. Android — KS системный; Windows держит служба.
    #[cfg(target_os = "linux")]
    if had.is_some() && killswitch_enabled() {
        citadel_client::gui_tun::disarm_killswitch(citadel_client::gui_tun::HELPER_PATH);
    }
}

/// Windows: погасить привилегированную службу `citadel-svc` при ВЫХОДЕ из приложения (п.2) —
/// elevated-процесс не должен висеть в задачах, когда клиента нет. Зовётся из Dart последним шагом
/// выхода (после [`vpn_disconnect`], иначе служба занята pump'ом активной сессии и не ответит).
/// На следующем подключении провайдер поднимет службу обратно через SCM. Best-effort: на прочих
/// платформах и при недоступной службе — тихий no-op (выход из приложения не блокируем).
#[frb(sync)]
pub fn desktop_service_quit() {
    #[cfg(windows)]
    if let Err(e) = citadel_client::win_tun::service_request_quit() {
        eprintln!("[app] остановка службы citadel-svc пропущена: {e:#}");
    }
}

/// Windows: завершить процесс НЕМЕДЛЕННО — последний шаг выхода из приложения.
///
/// Зачем так, а не `windowManager.destroy()`. `destroy()` лишь шлёт `WM_QUIT`: цикл сообщений
/// выходит, а дальше рантайм разбирает движок Flutter, плагины и COM — уже после `CoUninitialize()`
/// в runner'е — пока живы наши нативные потоки (лог-захват stderr, реконнект-воркеры, tokio) и
/// FRB-стримы, которые в этот момент ещё могут постить в гаснущий изолят. Разбор такого хозяйства
/// в правильном порядке нам не нужен: к моменту вызова всё, что должно пережить выход, уже на
/// диске (vault пишется атомарно на каждую операцию), kill-switch снят disconnect'ом, служба
/// уведомлена, иконка трея убрана. Поэтому просто выходим с кодом 0 — это и есть то, что делают
/// десктопные приложения с нативными фоновыми потоками (ср. `TerminateCurrentProcessImmediately`
/// в Chromium), и заодно исчезает окно WER «Программа прекратила работу» на штатном закрытии.
///
/// `TerminateProcess`, а не `ExitProcess`: последний рассылает `DLL_PROCESS_DETACH` уже после
/// остановки остальных потоков — поток, замороженный внутри аллокатора, оставил бы захваченный
/// heap-лок, и detach-обработчик мог бы на нём повиснуть (выход «зависает» вместо мгновенного).
/// На прочих платформах — no-op: там выход и так штатный.
#[frb(sync)]
pub fn desktop_exit_now() {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, TerminateProcess};
        // SAFETY: псевдо-хэндл текущего процесса всегда валиден; вызов не возвращается.
        unsafe { TerminateProcess(GetCurrentProcess(), 0) };
    }
}

// ───────────────────────────── диагностика (задача 3) ─────────────────────────────

/// Один шаг прогона диагностики для UI.
pub struct DiagLineDto {
    pub step: String,
    pub ok: bool,
    pub detail: String,
}

/// Разобрать креды сохранённого профиля (по id) или сырой `citadel://`-ссылки в [`CredentialLink`]
/// (нужны issuer+client_seed для добычи Layer-1 токена в диагностике, не только `ClientConfig`).
fn link_from(profile_id: Option<String>, link: Option<String>) -> Result<(String, CredentialLink)> {
    let uri = match (profile_id, link) {
        (Some(id), _) => profile_uri(&id)?,
        (None, Some(l)) => l,
        (None, None) => return Err(anyhow!("нужен profile_id или link")),
    };
    let parsed = CredentialLink::from_uri(&uri)?;
    Ok((uri, parsed))
}

/// Прогнать тест-кейсы подключения к exit'у профиля/ссылки, стримя результат по шагам
/// (DNS → QUIC/UDP → TCP → establish → egress). Диагностика идёт тем же путём, что реальный
/// коннект, поэтому показывает, где именно рвётся связь. Не трогает активную сессию.
pub fn run_diagnostics(
    profile_id: Option<String>,
    link: Option<String>,
    sink: StreamSink<DiagLineDto>,
) -> Result<()> {
    let (uri, dlink) = link_from(profile_id, link)?;
    let cfg = dlink.to_client_config();
    // Мастер-профиль → добавляем пробу admin-канала (C7.2) по туннелю: именно она отвечает на
    // жалобу «не открывается список абонентов» — проверяет путь до issuer'а мимо ОС-роутинга.
    let admin = citadel_client::admin_probe_dst(&uri);
    let issuer = dlink.issuer.clone();
    let issuer_pin = dlink.issuer_pin; // S2.1/A1: pin PQ-TLS канала к издателю
    let issuer_mldsa = dlink.issuer_mldsa; // PQ: обязательство к ML-DSA-идентичности издателя
    let client_seed = dlink.client_seed;
    rt().spawn(async move {
        // Диагностика идёт тем же путём, что реальный коннект: если креды несут Layer-1
        // (issuer+client_seed) — ДОБЫВАЕМ epoch-токен, иначе establish к token-required exit всегда
        // «✗» без токена (хотя exit исправен — ложный негатив). Токен тратится (proba spend'ит его).
        let cfg = if issuer.is_some() && client_seed.is_some() {
            match citadel_client::token_agent::with_token(
                cfg.clone(),
                issuer.as_deref(),
                issuer_pin.as_ref(),
                issuer_mldsa.as_ref(),
                client_seed.as_ref(),
            )
            .await
            {
                Ok(c) => {
                    let _ = sink.add(DiagLineDto {
                        step: "Токен (Layer-1)".into(),
                        ok: true,
                        detail: "добыт у issuer (предъявится exit'у)".into(),
                    });
                    c
                }
                Err(e) => {
                    let _ = sink.add(DiagLineDto {
                        step: "Токен (Layer-1)".into(),
                        ok: false,
                        // `{e:#}` — вся цепочка: без неё в панели оставался верхний контекст
                        // («издатель прекратил выдачу»), а настоящая причина обрыва терялась.
                        detail: format!("не удалось добыть у issuer: {e:#}"),
                    });
                    cfg // без токена — establish покажет отказ token-required exit честно
                }
            }
        } else {
            cfg
        };
        citadel_client::run_diagnostics(&cfg, admin, |s| {
            let _ = sink.add(DiagLineDto { step: s.name, ok: s.ok, detail: s.detail });
        })
        .await;
        // sink закроется при дропе (функция вернулась) → Dart увидит конец стрима
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Код языка приходит из UI, но попадает в файл настроек и читается обратно — поэтому форма
    /// проверяется на входе. Пропускаем только то, что бывает кодом языка; всё остальное (пути,
    /// переводы строки, кириллица, пустое) отвергаем, а чтение непонятного файла даёт русский.
    #[test]
    fn language_code_shape_is_validated() {
        for ok in ["ru", "en", "pt-BR", "zh"] {
            assert!(valid_lang(ok), "{ok} — допустимый код языка");
        }
        for bad in ["", "r", "../etc/passwd", "ru\n", "ру", "en_US", "toolongcode"] {
            assert!(!valid_lang(bad), "{bad:?} не должен приниматься как код языка");
        }
    }

    /// Замок хранилища и жизнь туннеля — независимые вещи, и это должно оставаться правдой на
    /// ВСЕХ клиентах (общий Dart-слой + это ядро): «Заблокировать хранилище» убирает профили с
    /// глаз, а не выходит из VPN. Регрессия ловится здесь, а не на устройстве: раньше
    /// `AppState.lockVault()` первым делом звал `disconnect()`, и на живом туннеле замок рвал связь.
    #[test]
    fn vault_lock_does_not_touch_session() {
        let ctrl = Arc::new(VpnController::new());
        ctrl.begin();
        *ACTIVE.lock().unwrap() = Some(ctrl.clone());

        vault_lock();

        assert!(ACTIVE.lock().unwrap().is_some(), "замок не должен снимать активную сессию");
        assert!(!ctrl.is_stopped(), "замок не должен глушить контроллер (авто-реконнект жив)");
        assert_eq!(ctrl.state(), VpnState::Connecting, "фаза сессии замком не меняется");

        // Не оставляем сессию в статике: следующие тесты в этом процессе видят чистое состояние.
        *ACTIVE.lock().unwrap() = None;
    }

    /// Обратная сторона того же инварианта: `vpn_disconnect` — единственная дверь, через которую
    /// UI гасит сессию (её зовут «Отключить» на главном экране, в трее и на экране разблокировки).
    #[test]
    fn vpn_disconnect_stops_session() {
        let ctrl = Arc::new(VpnController::new());
        ctrl.begin();
        *ACTIVE.lock().unwrap() = Some(ctrl.clone());

        vpn_disconnect();

        assert!(ACTIVE.lock().unwrap().is_none(), "disconnect снимает сессию со статика");
        assert!(ctrl.is_stopped(), "disconnect глушит авто-реконнект");
    }
}
