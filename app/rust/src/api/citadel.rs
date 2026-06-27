//! Мост GUI → ядро CitadelPQVPN (`citadel-client`).
//!
//! Три поверхности:
//!   - **vault** — зашифрованное хранилище профилей (мастер-пароль; крипта в Rust-ядре);
//!   - **vpn** — stateful сессия: `vpn_connect*` поднимает туннель и стримит события, `vpn_disconnect` рвёт;
//!   - **creds** — разбор `citadel://`-ссылки для превью перед сохранением.
//! Движок крутится на глобальном tokio-runtime; привилегированный TUN создаёт `citadel-helper`
//! через polkit (Linux-desktop).

use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{anyhow, Context, Result};
use flutter_rust_bridge::frb;

use crate::frb_generated::StreamSink;

use citadel_client::{CredentialLink, GuiTunProvider, Profile, TunProvider, Vault, VpnController, VpnEvent, VpnState};

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

/// Путь файла хранилища: `$XDG_CONFIG_HOME|~/.config/citadel-pqvpn/vault.bin`.
fn vault_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("citadel-pqvpn").join("vault.bin")
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
    let cfg = CredentialLink::from_uri(uri)?.to_client_config();
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

/// Разорвать активную сессию (если есть).
#[frb(sync)]
pub fn vpn_disconnect() {
    if let Some(c) = ACTIVE.lock().unwrap().take() {
        c.disconnect();
    }
}
