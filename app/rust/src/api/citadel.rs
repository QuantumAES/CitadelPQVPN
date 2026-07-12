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
    establish_session, run_data_plane, tun_from_fd, CredentialLink, GuiTunProvider,
    Profile, Session, TunProvider, Vault, VpnController, VpnEvent, VpnState,
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

/// Параметры назначенного туннеля для Android `VpnService.Builder` (фаза 1 → фаза 2).
pub struct TunSetupDto {
    pub addr: String,
    pub prefix: u32,
    pub mtu: String,
    pub routes: String,
    pub dns: String,
    pub exit: String,
    pub transport: String,
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
/// Установленная сессия (сеть готова, TUN ещё нет) между фазами Android-подключения.
static ANDROID_SESSION: Mutex<Option<Session>> = Mutex::new(None);
/// Хэндл задачи Android data-plane — для остановки (abort → pump сворачивается, fd закрывается).
static ANDROID_DP: Mutex<Option<tokio::task::AbortHandle>> = Mutex::new(None);
/// Базовый каталог данных, заданный платформой (Android: app filesDir). На десктопе не ставится —
/// там путь резолвится из XDG/HOME. Без него на Android cwd=`/` (песочница не writable) и vault не создать.
static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();
/// C6/M9 kill-switch (desktop): включён ли. Читается в `start_connect` → `ClientConfig.killswitch`.
/// GUI-тумблер через [`set_killswitch`]. Пока session-level (персист настройки — follow-up).
static KILLSWITCH: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Включить/выключить kill-switch (GUI-тумблер, desktop). Применяется со СЛЕДУЮЩЕГО подключения.
#[frb(sync)]
pub fn set_killswitch(on: bool) {
    KILLSWITCH.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// Текущее состояние kill-switch (инициализация тумблера).
#[frb(sync)]
pub fn killswitch_enabled() -> bool {
    KILLSWITCH.load(std::sync::atomic::Ordering::Relaxed)
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

/// Общий старт сессии. `profile_id` — если коннект по сохранённому профилю (тогда на событии
/// Connected обновляем его `last_exit` в vault).
fn start_connect(uri: &str, profile_id: Option<String>, sink: StreamSink<VpnEventDto>) -> Result<()> {
    // C5.4b: разбираем ссылку целиком — из неё берём issuer+client_seed для авто-фетча Layer-1
    // токена (симметрично android-пути do_android_establish). `to_client_config` теряет эти поля.
    let link = CredentialLink::from_uri(uri)?;
    let mut cfg = link.to_client_config();
    cfg.killswitch = killswitch_enabled(); // C6/M9: desktop kill-switch по GUI-тумблеру
    let issuer = link.issuer.clone();
    let client_seed = link.client_seed;
    let controller = Arc::new(VpnController::new());
    *ACTIVE.lock().unwrap() = Some(controller.clone());

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

    let provider: Arc<dyn TunProvider> = Arc::new(GuiTunProvider::default());
    rt().spawn(async move {
        // Сразу показываем «подключаемся» — фетч токена может занять секунды (issuer-раунд).
        controller.begin();
        // Если ссылка несёт Layer-1 (issuer+client_seed) — добываем epoch-токен ДО коннекта и
        // вписываем в config.token. Ошибку фетча превращаем в Error+Down (UI не виснет в спиннере).
        let cfg = match citadel_client::token_agent::with_token(
            cfg,
            issuer.as_deref(),
            client_seed.as_ref(),
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                controller.fail(format!("не удалось получить токен доступа: {e}"));
                return;
            }
        };
        let _ = controller.connect(cfg, provider).await;
    });
    Ok(())
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

// ─────────────────────────── Android: двухфазное подключение ───────────────────────────
// TUN-fd даёт VpnService (не polkit-helper), поэтому используем split движка:
// establish (сеть, без TUN) → Dart строит TUN через VpnService.Builder → fd → data-plane.

fn state_dto(s: &str) -> VpnEventDto {
    VpnEventDto {
        kind: "state".into(),
        state: s.into(),
        exit: String::new(),
        transport: String::new(),
        cidr: String::new(),
        error: String::new(),
    }
}

async fn do_android_establish(uri: &str) -> Result<TunSetupDto> {
    // C5.4: авто-фетч Layer-1 токена (если ссылка несёт issuer+client_seed) перед коннектом.
    let link = CredentialLink::from_uri(uri)?;
    let cfg = citadel_client::token_agent::with_token(
        link.to_client_config(),
        link.issuer.as_deref(),
        link.client_seed.as_ref(),
    )
    .await?;
    let session = establish_session(&cfg).await?;
    let a = session.addr;
    // Клампим MTU под бюджет QUIC-датаграммы (иначе полноразмерные пакеты дропаются «datagram
    // too large»). VpnService.Builder примет это как MTU интерфейса.
    let mtu = citadel_client::clamp_tun_mtu(&cfg.mtu, session.quic_datagram_mtu());
    let dto = TunSetupDto {
        addr: format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]),
        prefix: session.prefix as u32,
        mtu,
        routes: cfg.routes.clone(),
        dns: cfg.dns.clone().unwrap_or_default(),
        exit: session.chosen.clone(),
        transport: session.transport().to_string(),
    };
    *ANDROID_SESSION.lock().unwrap() = Some(session);
    Ok(dto)
}

/// Фаза 1 (сырая ссылка): установить сессию (PQ-хендшейк + адрес, БЕЗ TUN). Вернуть параметры
/// для `VpnService.Builder`. Сессия удерживается до фазы 2.
pub async fn android_establish(link: String) -> Result<TunSetupDto> {
    do_android_establish(&link).await
}

/// Фаза 1 (сохранённый профиль): ссылка достаётся из vault, не покидает ядро.
pub async fn android_establish_profile(id: String) -> Result<TunSetupDto> {
    let uri = {
        let g = VAULT.lock().unwrap();
        let v = g.as_ref().ok_or_else(|| anyhow!("хранилище заблокировано"))?;
        v.list()
            .into_iter()
            .find(|p| p.id == id)
            .map(|p| p.uri)
            .ok_or_else(|| anyhow!("профиль не найден"))?
    };
    do_android_establish(&uri).await
}

/// Фаза 2: Dart получил TUN-fd от `VpnService.establish()` → запустить data-plane, стримить
/// события. Останов — со стороны Dart (stopService закрывает fd → reader завершает pump).
pub fn android_run_data_plane(fd: i32, sink: StreamSink<VpnEventDto>) -> Result<()> {
    let session = ANDROID_SESSION
        .lock()
        .unwrap()
        .take()
        .ok_or_else(|| anyhow!("нет установленной сессии — сначала android_establish"))?;
    let connected = VpnEventDto {
        kind: "connected".into(),
        state: String::new(),
        exit: session.chosen.clone(),
        transport: session.transport().to_string(),
        cidr: session.cidr(),
        error: String::new(),
    };
    let _ = sink.add(connected);
    let _ = sink.add(state_dto("up"));
    // SAFETY: fd получен от VpnService.establish() (detachFd) — владеем им единолично.
    let tun = unsafe { tun_from_fd(fd) };
    let h = rt().spawn(async move {
        // Лог в панель (stderr движка): показывает, ЗАВЕРШИЛСЯ ли data-plane сам (транспорт
        // детектировал мёртвое соединение — тогда цикл реконнектит) или молчит (стоит). При аборте
        // (android_disconnect) эта ветка не выполняется — задача снята, что и отличает разрыв от стопа.
        match run_data_plane(session, tun).await {
            Ok(()) => eprintln!("[android] data-plane завершился штатно → реконнект"),
            Err(e) => eprintln!("[android] data-plane упал: {e} → реконнект"),
        }
        let _ = sink.add(state_dto("down"));
    });
    *ANDROID_DP.lock().unwrap() = Some(h.abort_handle());
    Ok(())
}

/// Остановить Android data-plane (Dart зовёт при stopService). Аборт задачи → pump-CancelGuard
/// закрывает TUN-fd → интерфейс VpnService гаснет.
#[frb(sync)]
pub fn android_disconnect() {
    // Диагностика (видно в панели лога — это stderr движка): помогает понять, доходит ли цепочка
    // смены сети (NetworkCallback → onNetworkChanged → _onNetworkChanged) до аборта data-plane.
    let had = ANDROID_DP.lock().unwrap().take();
    eprintln!(
        "[android] android_disconnect: аборт data-plane ({})",
        if had.is_some() { "есть активный — реконнект" } else { "нет активного" }
    );
    if let Some(h) = had {
        h.abort();
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
