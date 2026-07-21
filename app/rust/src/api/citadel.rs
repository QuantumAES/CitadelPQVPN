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

use anyhow::{anyhow, Context, Result};
use flutter_rust_bridge::frb;

use crate::frb_generated::StreamSink;

use citadel_client::{
    CredentialLink, GuiTunProvider, Profile, SplitMode, SplitTunnel, TunIo, TunParams, TunProvider,
    Vault, VpnController, VpnEvent, VpnState,
};

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
}

/// C7.4: QR-код ссылки как битовая матрица `size × size` (1 = тёмный модуль) — рендер в UI
/// кастомным painter'ом, без SVG-зависимости на Dart-стороне.
pub struct QrDto {
    pub size: u32,
    pub cells: Vec<u8>,
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
/// иначе тумблер сбрасывался бы в дефолт при каждом рестарте. Дефолт (файла нет) — включён (предрелиз).
static DEBUG_ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
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
/// обращении; файла нет → дефолт (включён). Имя `*_persisted` — чтобы Dart-обёртка не конфликтовала
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
/// Иначе (десктоп) — `$XDG_CONFIG_HOME|~/.config/citadel-pqvpn`.
fn vault_path() -> PathBuf {
    if let Some(dir) = DATA_DIR.get() {
        return dir.join("vault.bin");
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("citadel-pqvpn").join("vault.bin")
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
#[frb(sync)]
pub fn vault_lock() {
    *VAULT.lock().unwrap() = None;
}

/// Открыть хранилище мастер-паролем (PBKDF2 — намеренно НЕ sync: тяжело, уводим с UI-потока).
pub fn vault_unlock(passphrase: String) -> Result<()> {
    let v = Vault::open(vault_path(), &passphrase)?;
    *VAULT.lock().unwrap() = Some(v);
    Ok(())
}

/// Создать новое хранилище под мастер-паролем (первый запуск / первое сохранение).
pub fn vault_create(passphrase: String) -> Result<()> {
    let v = Vault::create(vault_path(), &passphrase)?;
    *VAULT.lock().unwrap() = Some(v);
    Ok(())
}

/// Сменить мастер-пароль (текущий проверяется повторным open).
pub fn vault_change_password(old: String, new: String) -> Result<()> {
    Vault::open(vault_path(), &old).context("текущий пароль неверен")?;
    let mut g = VAULT.lock().unwrap();
    g.as_mut().ok_or_else(|| anyhow!("хранилище заблокировано"))?.change_password(&new)
}

/// Список профилей (vault должен быть разблокирован).
#[frb(sync)]
pub fn vault_list() -> Result<Vec<ProfileDto>> {
    let g = VAULT.lock().unwrap();
    let v = g.as_ref().ok_or_else(|| anyhow!("хранилище заблокировано"))?;
    Ok(v.list().iter().map(profile_to_dto).collect())
}

/// Добавить профиль из `citadel://`-ссылки (валидируется).
#[frb(sync)]
pub fn vault_add(name: String, uri: String) -> Result<ProfileDto> {
    let mut g = VAULT.lock().unwrap();
    let v = g.as_mut().ok_or_else(|| anyhow!("хранилище заблокировано"))?;
    Ok(profile_to_dto(&v.add(&name, &uri)?))
}

/// Удалить профиль по id.
#[frb(sync)]
pub fn vault_remove(id: String) -> Result<()> {
    let mut g = VAULT.lock().unwrap();
    g.as_mut().ok_or_else(|| anyhow!("хранилище заблокировано"))?.remove(&id)
}

/// Разобрать `citadel://`-ссылку → превью для UI (живая валидация при вставке).
#[frb(sync)]
pub fn parse_link_summary(uri: String) -> LinkSummaryDto {
    match citadel_client::api::parse_link(uri) {
        Ok(s) => LinkSummaryDto {
            valid: true,
            servers: s.servers.join(", "),
            server_name: s.server_name,
            kx_suite: s.kx_suite,
            has_pin: s.has_pin,
            has_pq_auth: s.has_pq_auth,
            has_obfs: s.has_obfs,
            is_admin: s.is_admin,
        },
        Err(_) => LinkSummaryDto::default(),
    }
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
) -> Result<tokio::sync::broadcast::Receiver<VpnEvent>> {
    // C5.4b: разбираем ссылку целиком — из неё issuer+client_seed для авто-фетча Layer-1 токена.
    let link = CredentialLink::from_uri(uri)?;
    let mut cfg = link.to_client_config();
    cfg.killswitch = killswitch_enabled(); // C6/M9: kill-switch по GUI-тумблеру (desktop; Android — OS-level)
    cfg.split = load_split_config(); // C8.3: split-tunnel по приложениям/назначениям (Android; desktop игнорит)
    // Остановить прошлую сессию перед новой (анти-double-connect): её loop глушим, иначе он продолжит
    // держать/реконнектить старый туннель параллельно новому. Берём Arc и disconnect() вне лока.
    let prev = ACTIVE.lock().unwrap().take();
    if let Some(old) = prev {
        old.disconnect();
    }
    let controller = Arc::new(VpnController::new());
    *ACTIVE.lock().unwrap() = Some(controller.clone());
    // S2.1/A1: Layer-1 фетч требует issuer + issuer_pin (PQ-TLS канал) + client_seed. Без pin
    // refresher не ставим (token-less путь; exit откажет, если требует токен — misconfig виден).
    if let (Some(iss), Some(pin), Some(seed)) =
        (link.issuer.clone(), link.issuer_pin, link.client_seed)
    {
        // S2.1/A1-остаток: issuer-канал оборачиваем в obfs тем же PSK, что и туннель (probe-resistance;
        // None для ссылок без obfs → голый TLS). Обязан совпадать с серверной обёрткой.
        let obfs_psk = link.obfs_psk;
        controller.set_token_refresher(Arc::new(move || {
            let iss = iss.clone();
            Box::pin(async move {
                citadel_client::token_agent::fetch_tokens(&iss, &pin, &seed, 1, 3, obfs_psk)
                    .await
                    .ok()
                    .and_then(|mut v| v.pop())
            }) as std::pin::Pin<Box<dyn std::future::Future<Output = Option<Vec<u8>>> + Send>>
        }));
    }
    // Подписка ДО begin() (первый Connecting буферизуется в broadcast до старта форвард-задачи).
    let rx = controller.subscribe();
    rt().spawn(async move {
        controller.begin();
        let _ = controller.connect(cfg, provider).await;
    });
    Ok(rx)
}

/// Desktop: старт через polkit-helper (`GuiTunProvider`) + прямая пересылка событий в `sink`
/// (десктопный изолят живёт с процессом → swap-able sink не нужен, в отличие от Android).
fn start_connect(uri: &str, profile_id: Option<String>, sink: StreamSink<VpnEventDto>) -> Result<()> {
    let mut rx = spawn_controller(uri, Arc::new(GuiTunProvider::default()))?;
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
    let mut rx = spawn_controller(uri, Arc::new(AndroidTunProvider))?; // парсит ссылку (может упасть)
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
    if let Some(c) = ACTIVE.lock().unwrap().take() {
        c.disconnect();
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
fn link_from(profile_id: Option<String>, link: Option<String>) -> Result<CredentialLink> {
    let uri = match (profile_id, link) {
        (Some(id), _) => profile_uri(&id)?,
        (None, Some(l)) => l,
        (None, None) => return Err(anyhow!("нужен profile_id или link")),
    };
    CredentialLink::from_uri(&uri)
}

/// Прогнать тест-кейсы подключения к exit'у профиля/ссылки, стримя результат по шагам
/// (DNS → QUIC/UDP → TCP → establish → egress). Диагностика идёт тем же путём, что реальный
/// коннект, поэтому показывает, где именно рвётся связь. Не трогает активную сессию.
pub fn run_diagnostics(
    profile_id: Option<String>,
    link: Option<String>,
    sink: StreamSink<DiagLineDto>,
) -> Result<()> {
    let dlink = link_from(profile_id, link)?;
    let cfg = dlink.to_client_config();
    let issuer = dlink.issuer.clone();
    let issuer_pin = dlink.issuer_pin; // S2.1/A1: pin PQ-TLS канала к издателю
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
                        detail: format!("не удалось добыть у issuer: {e}"),
                    });
                    cfg // без токена — establish покажет отказ token-required exit честно
                }
            }
        } else {
            cfg
        };
        citadel_client::run_diagnostics(&cfg, |s| {
            let _ = sink.add(DiagLineDto { step: s.name, ok: s.ok, detail: s.detail });
        })
        .await;
        // sink закроется при дропе (функция вернулась) → Dart увидит конец стрима
    });
    Ok(())
}
