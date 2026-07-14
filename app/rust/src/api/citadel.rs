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
    CredentialLink, GuiTunProvider, Profile, TunIo, TunParams, TunProvider, Vault, VpnController,
    VpnEvent, VpnState,
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
        last_exit: p.last_exit.clone().unwrap_or_default(),
    }
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
        },
        Err(_) => LinkSummaryDto::default(),
    }
}

// ───────────────────────────── vpn FFI ─────────────────────────────

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
            d.state = match s {
                VpnState::Idle => "idle",
                VpnState::Connecting => "connecting",
                VpnState::Up => "up",
                VpnState::Migrating => "migrating",
                VpnState::Down => "down",
            }
            .into();
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

/// Ядро запуска нативной сессии (общее для desktop и Android). Создаёт `VpnController`, ставит
/// token-refresher (свежий Layer-1 токен на КАЖДЫЙ establish — анти-double-spend на реконнекте),
/// форвардит события в `sink` (+ отмечает `last_exit` профиля) и крутит `connect`-loop на rt() с
/// платформенным `provider`. Реконнект/backoff держит сам нативный loop → он переживает смерть
/// UI-изолята (Android: сессия жива, пока `CitadelVpnService` активен, даже при закрытом окне — C6).
/// `profile_id` — коннект по сохранённому профилю (тогда на Connected обновляем его `last_exit`).
fn start_session_with_provider(
    uri: &str,
    profile_id: Option<String>,
    provider: Arc<dyn TunProvider>,
    sink: StreamSink<VpnEventDto>,
) -> Result<()> {
    // C5.4b: разбираем ссылку целиком — из неё берём issuer+client_seed для авто-фетча Layer-1
    // токена. `to_client_config` теряет эти поля.
    let link = CredentialLink::from_uri(uri)?;
    let mut cfg = link.to_client_config();
    cfg.killswitch = killswitch_enabled(); // C6/M9: kill-switch по GUI-тумблеру (desktop; Android — OS-level)
    let controller = Arc::new(VpnController::new());
    *ACTIVE.lock().unwrap() = Some(controller.clone());
    // Свежий Layer-1 токен на КАЖДЫЙ establish (в т.ч. реконнект): иначе реконнект предъявляет уже
    // потраченный токен, exit рвёт его как double-spend (M4/M5) → establish «connection lost» в петле.
    // Заменяет однократный with_token; refresher фетчит и первый токен (перед первым establish).
    if let (Some(iss), Some(seed)) = (link.issuer.clone(), link.client_seed) {
        controller.set_token_refresher(Arc::new(move || {
            let iss = iss.clone();
            Box::pin(async move {
                citadel_client::token_agent::fetch_tokens(&iss, &seed, 1, 3)
                    .await
                    .ok()
                    .and_then(|mut v| v.pop())
            }) as std::pin::Pin<Box<dyn std::future::Future<Output = Option<Vec<u8>>> + Send>>
        }));
    }

    let mut rx = controller.subscribe();
    rt().spawn(async move {
        while let Ok(ev) = rx.recv().await {
            // отметить exit последнего успешного коннекта (только сохранённый профиль)
            if let (VpnEvent::Connected { exit, .. }, Some(id)) = (&ev, &profile_id) {
                if let Ok(mut g) = VAULT.lock() {
                    if let Some(v) = g.as_mut() {
                        let _ = v.set_last_exit(id, exit);
                    }
                } // guard сброшен до следующего await
            }
            if sink.add(to_dto(ev)).is_err() {
                break; // Dart отписался
            }
        }
    });

    rt().spawn(async move {
        // Сразу показываем «подключаемся»; токен добывает refresher перед каждым establish (внутри
        // connect), в т.ч. первый — реконнект берёт свежий, не потраченный.
        controller.begin();
        let _ = controller.connect(cfg, provider).await;
    });
    Ok(())
}

/// Desktop: старт сессии через polkit-helper (`GuiTunProvider`).
fn start_connect(uri: &str, profile_id: Option<String>, sink: StreamSink<VpnEventDto>) -> Result<()> {
    let provider: Arc<dyn TunProvider> = Arc::new(GuiTunProvider::default());
    start_session_with_provider(uri, profile_id, provider, sink)
}

/// Подключить по «сырой» ссылке (ещё не сохранённой — первый коннект перед сохранением).
pub fn vpn_connect(link: String, sink: StreamSink<VpnEventDto>) -> Result<()> {
    start_connect(&link, None, sink)
}

/// Подключить по сохранённому профилю (ссылка достаётся из vault, не покидает ядро).
pub fn vpn_connect_profile(id: String, sink: StreamSink<VpnEventDto>) -> Result<()> {
    let uri = {
        let g = VAULT.lock().unwrap();
        let v = g.as_ref().ok_or_else(|| anyhow!("хранилище заблокировано"))?;
        v.list()
            .into_iter()
            .find(|p| p.id == id)
            .map(|p| p.uri)
            .ok_or_else(|| anyhow!("профиль не найден"))?
    };
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

/// Android: старт нативной сессии (сырая ссылка). Спавнит `VpnController::connect` с
/// `AndroidTunProvider` на rt() — реконнект-loop нативный, события стримятся через `sink`.
/// Заменяет двухфазный `android_establish` + `android_run_data_plane`; останов — `vpn_disconnect`.
pub fn android_start_session(link: String, sink: StreamSink<VpnEventDto>) -> Result<()> {
    let provider: Arc<dyn TunProvider> = Arc::new(AndroidTunProvider);
    start_session_with_provider(&link, None, provider, sink)
}

/// Android: старт нативной сессии по сохранённому профилю (ссылка не покидает ядро).
pub fn android_start_session_profile(id: String, sink: StreamSink<VpnEventDto>) -> Result<()> {
    let uri = {
        let g = VAULT.lock().unwrap();
        let v = g.as_ref().ok_or_else(|| anyhow!("хранилище заблокировано"))?;
        v.list()
            .into_iter()
            .find(|p| p.id == id)
            .map(|p| p.uri)
            .ok_or_else(|| anyhow!("профиль не найден"))?
    };
    let provider: Arc<dyn TunProvider> = Arc::new(AndroidTunProvider);
    start_session_with_provider(&uri, Some(id), provider, sink)
}

/// Android: сигнал «сменилась underlying-сеть» (WiFi↔LTE/toggle) от NetworkCallback → нативный
/// loop оборвёт текущий pump и переустановит сессию над новой сетью СРАЗУ (не ждёт pump-watchdog
/// ~8с). No-op, если активной сессии нет.
#[frb(sync)]
pub fn android_notify_network_changed() {
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
        (Some(id), _) => {
            let g = VAULT.lock().unwrap();
            let v = g.as_ref().ok_or_else(|| anyhow!("хранилище заблокировано"))?;
            v.list()
                .into_iter()
                .find(|p| p.id == id)
                .map(|p| p.uri)
                .ok_or_else(|| anyhow!("профиль не найден"))?
        }
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
    let client_seed = dlink.client_seed;
    rt().spawn(async move {
        // Диагностика идёт тем же путём, что реальный коннект: если креды несут Layer-1
        // (issuer+client_seed) — ДОБЫВАЕМ epoch-токен, иначе establish к token-required exit всегда
        // «✗» без токена (хотя exit исправен — ложный негатив). Токен тратится (proba spend'ит его).
        let cfg = if issuer.is_some() && client_seed.is_some() {
            match citadel_client::token_agent::with_token(
                cfg.clone(),
                issuer.as_deref(),
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
