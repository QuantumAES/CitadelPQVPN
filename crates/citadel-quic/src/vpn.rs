//! `VpnController` — высокоуровневый фасад движка для GUI/FFI.
//!
//! Оркеструет `establish_session` → конфигурацию туннеля через [`TunProvider`] →
//! `run_data_plane`, отдавая поток событий состояния. UI/FFI (Flutter, C0.6+) держит
//! `Arc<VpnController>`, зовёт [`VpnController::connect`]/[`VpnController::disconnect`]
//! и слушает [`VpnController::subscribe`]. Платформа туннеля скрыта за `TunProvider`
//! (Linux `/dev/net/tun`, Android `VpnService.Builder`) — см. docs/CLIENT-ARCH.md §4.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use tokio::sync::{broadcast, Notify};

use citadel_tun::TunIo;

use crate::client::{establish_session, run_data_plane};
use crate::config::ClientConfig;

/// Стартовый интервал backoff между попытками восстановления соединения.
const RECONNECT_BACKOFF_START: Duration = Duration::from_secs(1);
/// Потолок backoff (после ряда неудач ретраим не реже, чем раз в 30с).
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Состояние VPN-сессии.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VpnState {
    Idle,
    Connecting,
    Up,
    /// Миграция пути (WiFi↔LTE/NAT-rebind). Пока НЕ эмитится автоматически: миграция
    /// прозрачна на уровне `obfs_socket` (M4); проброс сигнала в события — follow-up.
    Migrating,
    Down,
}

/// Событие движка для UI/FFI.
#[derive(Clone, Debug)]
pub enum VpnEvent {
    /// Смена состояния.
    State(VpnState),
    /// Сессия установлена: выбранный exit, транспорт ("QUIC/UDP"|"obfs-TCP"), адрес (CIDR).
    Connected {
        exit: String,
        transport: String,
        cidr: String,
    },
    /// Ошибка установки/работы сессии.
    Error(String),
}

/// Параметры конфигурации туннеля: назначенный сервером адрес + сетевые настройки из конфига.
pub struct TunParams {
    pub addr: [u8; 4],
    pub prefix: u8,
    pub mtu: String,
    pub routes: String,
    pub dns: Option<String>,
    /// IP-адреса exit'ов для bypass-маршрута (Linux): собственные пакеты клиента к exit НЕ должны
    /// уходить в туннель при full-tunnel (`0.0.0.0/0`), иначе — петля маршрутизации и egress встаёт.
    /// На Android не используется (там `VpnService.protect()` исключает сокет из туннеля).
    pub exit_ips: Vec<String>,
    /// C6/M9 kill-switch: провайдер (Linux `citadel-helper`) ставит fail-closed firewall —
    /// не-туннельный трафик блокируется, пока туннель активен; переживает краш движка.
    pub killswitch: bool,
}

/// Платформенный провайдер туннеля: по назначенному адресу строит/конфигурирует TUN и
/// отдаёт пакетный I/O. Linux — `/dev/net/tun` + `ip`; Android — `VpnService.Builder.establish()`.
///
/// Вызывается **после** `establish_session` (адрес уже известен) — порядок, которого требуют
/// мобильные ОС (адрес скармливается билдеру ДО получения fd).
pub trait TunProvider: Send + Sync + 'static {
    fn configure(&self, p: &TunParams) -> Result<Arc<dyn TunIo>>;
}

/// Асинхронный добытчик свежего Layer-1 токена: зовётся перед КАЖДЫМ establish (в т.ч. реконнект),
/// чтобы не переиспользовать потраченный токен (exit ловит double-spend, M4/M5). `None` из замыкания —
/// токен не обновляем (token-less exit / нет Layer-1). Ставится приложением ([`VpnController::set_token_refresher`]).
pub type TokenRefresher = Arc<
    dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<Vec<u8>>> + Send>>
        + Send
        + Sync,
>;

/// Высокоуровневый контроллер VPN-сессии. Потокобезопасен; для фонового запуска
/// держится в `Arc` и `connect` крутится в `tokio::spawn`, а `disconnect` зовётся из UI-потока.
pub struct VpnController {
    state: Mutex<VpnState>,
    events: broadcast::Sender<VpnEvent>,
    shutdown: Notify,
    /// Сигнал «сменилась underlying-сеть» (Android NetworkCallback): будит connect-loop оборвать
    /// текущий pump и НЕМЕДЛЕННО переустановить сессию над новой сетью — не ждать pump-watchdog
    /// (~8с) / QUIC idle-timeout. В отличие от [`shutdown`] — НЕ персистентный флаг: пропущенный
    /// сигнал (пришёл вне `select!`, напр. в фазе establish) безвреден, т.к. следующий establish и
    /// так идёт над новой сетью (`setUnderlyingNetworks` уже применён нативно).
    network_changed: Notify,
    /// Пользователь запросил разрыв — глушит авто-реконнект. Persistent-флаг (не только `Notify`)
    /// закрывает гонку: disconnect между итерациями цикла не теряется.
    stopped: AtomicBool,
    /// Добытчик свежего токена на каждый establish (реконнект-безопасность).
    token_refresh: Mutex<Option<TokenRefresher>>,
}

impl Default for VpnController {
    fn default() -> Self {
        Self::new()
    }
}

impl VpnController {
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(64);
        Self {
            state: Mutex::new(VpnState::Idle),
            events,
            shutdown: Notify::new(),
            network_changed: Notify::new(),
            stopped: AtomicBool::new(false),
            token_refresh: Mutex::new(None),
        }
    }

    /// Задать добытчик свежего Layer-1 токена (зовётся перед каждым establish). Приложение
    /// передаёт замыкание с `token_agent`, чтобы реконнект брал НОВЫЙ токен, а не потраченный.
    pub fn set_token_refresher(&self, f: TokenRefresher) {
        *self.token_refresh.lock().unwrap() = Some(f);
    }

    /// Подписаться на поток событий (несколько подписчиков допустимы).
    pub fn subscribe(&self) -> broadcast::Receiver<VpnEvent> {
        self.events.subscribe()
    }

    /// Текущее состояние.
    pub fn state(&self) -> VpnState {
        *self.state.lock().unwrap()
    }

    fn set_state(&self, s: VpnState) {
        *self.state.lock().unwrap() = s;
        let _ = self.events.send(VpnEvent::State(s)); // Err только если нет подписчиков — игнор
    }

    fn emit(&self, e: VpnEvent) {
        let _ = self.events.send(e);
    }

    /// Отметить начало подключения ДО вызова [`connect`] — для pre-connect шагов в GUI-мосте
    /// (напр. добыча Layer-1 токена у issuer, C5.4b): UI сразу видит «подключаемся», а не висит
    /// в idle пока идёт фетч. Затем вызывающий зовёт [`connect`] (он повторно выставит Connecting —
    /// идемпотентно) либо при неудаче шага — [`fail`].
    pub fn begin(&self) {
        self.set_state(VpnState::Connecting);
    }

    /// Сообщить о фатальной ошибке pre-connect шага (эмитит `Error` + переводит в `Down`), чтобы
    /// UI вышел из спиннера, а не завис. Используется, когда до [`connect`] дело не дошло (напр.
    /// не удалось получить токен доступа).
    pub fn fail(&self, msg: String) {
        self.emit(VpnEvent::Error(msg));
        self.set_state(VpnState::Down);
    }

    /// Поднять VPN и **держать соединение живым**, пока пользователь не позовёт `disconnect`.
    ///
    /// Первичный коннект: `establish` → `provider.configure` → `data_plane`. При неудаче
    /// первичного коннекта — сразу ошибка (пользователь должен увидеть причину: битый конфиг,
    /// недоступный exit и т.п.). После того как соединение **хотя бы раз поднялось**, при разрыве
    /// транспорта (или падении data-plane) — **авто-реконнект с прогрессивным backoff**
    /// (1→2→4→…→30с, сброс после успеха), пока `disconnect` не остановит. Мягкие смены пути
    /// (WiFi↔LTE/NAT-rebind) прозрачны на уровне QUIC-миграции и сюда не доходят.
    ///
    /// Для фонового запуска — `tokio::spawn` с `Arc<VpnController>`. События — через `subscribe`.
    pub async fn connect(&self, mut cfg: ClientConfig, provider: Arc<dyn TunProvider>) -> Result<()> {
        self.stopped.store(false, Ordering::SeqCst);
        self.set_state(VpnState::Connecting);
        let mut backoff = RECONNECT_BACKOFF_START;
        let mut ever_up = false;

        loop {
            if self.stopped.load(Ordering::SeqCst) {
                self.set_state(VpnState::Down);
                return Ok(());
            }

            // Свежий Layer-1 токен на КАЖДУЮ попытку establish: реконнект НЕ должен переиспользовать
            // потраченный токен — exit отвергнет его как double-spend (M4/M5) и порвёт control-стрим.
            // Недоступен issuer → None → establish покажет отказ token-required exit, цикл ретраит
            // (само-лечится по восстановлении сети). token-less/без Layer-1 → refresher не задан.
            let refresher = self.token_refresh.lock().unwrap().clone();
            if let Some(f) = refresher {
                if let Some(t) = f().await {
                    cfg.token = t;
                }
            }

            // ── establish ──
            let session = match establish_session(&cfg).await {
                Ok(s) => s,
                Err(e) => {
                    // Ретраим ВСЕГДА, в т.ч. ПЕРВЫЙ коннект: сеть/issuer могли быть недоступны на
                    // старте (подключились до появления сети) — по восстановлении следующая попытка
                    // возьмёт свежий токен и поднимется. Причину показываем (Error), но не сдаёмся до
                    // disconnect (стандартное поведение VPN «connecting…»). Пользователь остановит сам.
                    self.emit(VpnEvent::Error(e.to_string()));
                    eprintln!("[vpn] establish не удался: {e} — ретрай через {:?}", backoff);
                    self.set_state(if ever_up { VpnState::Migrating } else { VpnState::Connecting });
                    if self.sleep_or_stop(backoff).await {
                        self.set_state(VpnState::Down);
                        return Ok(());
                    }
                    backoff = next_backoff(backoff);
                    continue;
                }
            };
            self.emit(VpnEvent::Connected {
                exit: session.chosen.clone(),
                transport: session.transport().to_string(),
                cidr: session.cidr(),
            });

            // Собрать IP всех сконфигурированных exit'ов (+ фактический peer) для bypass-маршрута:
            // при full-tunnel исключаем их из туннеля, иначе собственный QUIC/obfs-трафик к exit
            // заворачивается обратно в citadel0 → петля, egress встаёт (см. TunParams::exit_ips).
            let mut exit_ips = std::collections::BTreeSet::new();
            exit_ips.insert(session.peer_addr().ip().to_string());
            for s in &cfg.servers {
                if let Ok(addrs) = tokio::net::lookup_host(s).await {
                    for a in addrs {
                        exit_ips.insert(a.ip().to_string());
                    }
                }
            }

            // Конфигурируем туннель ПОД назначенный адрес (на Android — VpnService.Builder).
            // На реконнекте адрес может смениться — TUN пере-конфигурируется под новый; polkit с
            // auth_admin_keep не переспрашивает пароль в пределах сессии.
            let params = TunParams {
                addr: session.addr,
                prefix: session.prefix,
                mtu: clamp_tun_mtu(&cfg.mtu, session.quic_datagram_mtu()),
                routes: cfg.routes.clone(),
                dns: cfg.dns.clone(),
                exit_ips: exit_ips.into_iter().collect(),
                killswitch: cfg.killswitch,
            };
            let tun = match provider.configure(&params) {
                Ok(t) => t,
                Err(e) => {
                    if !ever_up {
                        self.emit(VpnEvent::Error(e.to_string()));
                        self.set_state(VpnState::Down);
                        return Err(e);
                    }
                    eprintln!("[vpn] реконнект: configure TUN не удался: {e} — ретрай через {:?}", backoff);
                    self.set_state(VpnState::Migrating);
                    if self.sleep_or_stop(backoff).await {
                        self.set_state(VpnState::Down);
                        return Ok(());
                    }
                    backoff = next_backoff(backoff);
                    continue;
                }
            };

            self.set_state(VpnState::Up);
            ever_up = true;
            backoff = RECONNECT_BACKOFF_START; // успех — сбрасываем backoff

            // data-plane крутится до разрыва транспорта ИЛИ до disconnect (тогда future data-plane
            // дропается → транспорт (QUIC/TCP) закрывается при drop, TUN сворачивается).
            // Клон для сигнала ЧИСТОГО disconnect: на shutdown-ветке зовём clean_shutdown() ДО дропа
            // (Linux GuiTun шлёт 'Q' → helper снимает kill-switch). На реконнекте не зовём → KS остаётся.
            let tun_ctrl = tun.clone();
            let mut net_changed = false;
            let r = tokio::select! {
                r = run_data_plane(session, tun) => r,
                _ = self.shutdown.notified() => {
                    eprintln!("[vpn] disconnect — закрываю сессию");
                    tun_ctrl.clean_shutdown();
                    self.set_state(VpnState::Down);
                    return Ok(());
                }
                _ = self.network_changed.notified() => {
                    // Смена сети (Android): путь над старой сетью, скорее всего, мёртв — рвём pump и
                    // реконнектимся над новой СРАЗУ, не дожидаясь pump-watchdog / QUIC idle-timeout.
                    // Не глушит авто-реконнект (в отличие от disconnect): loop идёт на следующую итерацию.
                    eprintln!("[vpn] смена сети — переустанавливаю сессию над новой сетью");
                    net_changed = true;
                    Ok(())
                }
            };
            drop(tun_ctrl); // реконнект: закрыть старый TUN/сокет сейчас (helper EOF без 'Q' → KS держится)
            if self.stopped.load(Ordering::SeqCst) {
                self.set_state(VpnState::Down);
                return Ok(());
            }

            // Транспорт упал сам (не пользователь) → авто-реконнект.
            if !net_changed {
                match r {
                    Ok(()) => eprintln!("[vpn] транспорт закрылся — восстанавливаю соединение"),
                    Err(e) => eprintln!("[vpn] data-plane упал: {e} — восстанавливаю соединение"),
                }
            }
            self.set_state(VpnState::Migrating);
            // Смена сети → реконнект немедленный (новая сеть уже поднята) — сбрасываем backoff и НЕ
            // спим. Иначе — прогрессивный backoff между попытками (сеть/exit могут быть ещё недоступны).
            if net_changed {
                backoff = RECONNECT_BACKOFF_START;
            } else {
                if self.sleep_or_stop(backoff).await {
                    self.set_state(VpnState::Down);
                    return Ok(());
                }
                backoff = next_backoff(backoff);
            }
        }
    }

    /// Подождать `d` ИЛИ пробуждение по `disconnect`. `true` — пользователь остановил (прервать
    /// реконнект); `false` — таймаут истёк, продолжаем попытки.
    async fn sleep_or_stop(&self, d: Duration) -> bool {
        if self.stopped.load(Ordering::SeqCst) {
            return true;
        }
        tokio::select! {
            _ = tokio::time::sleep(d) => self.stopped.load(Ordering::SeqCst),
            _ = self.shutdown.notified() => true,
        }
    }

    /// Запросить разрыв активной сессии и остановить авто-реконнект (persistent-флаг + будим
    /// `connect`). Безопасно в любом состоянии (нет активной сессии → no-op).
    pub fn disconnect(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.shutdown.notify_waiters();
    }

    /// Сигнал «сменилась underlying-сеть» (Android NetworkCallback: WiFi↔LTE/toggle): оборвать
    /// текущий pump и немедленно переустановить сессию над новой сетью. НЕ глушит авто-реконнект
    /// (в отличие от [`disconnect`]). Безопасно в любом состоянии: если активного pump нет,
    /// `notify_waiters` не запоминает сигнал — следующий establish и так пойдёт над новой сетью.
    pub fn notify_network_changed(&self) {
        self.network_changed.notify_waiters();
    }
}

/// Следующий backoff: удвоение с потолком [`RECONNECT_BACKOFF_MAX`].
fn next_backoff(cur: Duration) -> Duration {
    (cur * 2).min(RECONNECT_BACKOFF_MAX)
}

/// Ужать `cfg_mtu` под бюджет QUIC-датаграммы (`budget` от [`crate::client::Session::quic_datagram_mtu`]):
/// если сконфигурированный MTU больше бюджета — вернуть бюджет (иначе полноразмерные пакеты
/// дропаются в pump «datagram too large»). `None` (obfs-TCP) или MTU ≤ бюджета — оставить как есть.
pub fn clamp_tun_mtu(cfg_mtu: &str, budget: Option<usize>) -> String {
    let cur: usize = cfg_mtu.parse().unwrap_or(1280);
    match budget {
        Some(b) if cur > b => {
            eprintln!("[vpn] TUN MTU {cur} > бюджет QUIC-датаграммы {b} — ужимаю до {b}");
            b.to_string()
        }
        _ => cfg_mtu.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn state_transitions_and_events() {
        let c = VpnController::new();
        assert_eq!(c.state(), VpnState::Idle);
        let mut rx = c.subscribe();

        c.set_state(VpnState::Connecting);
        c.set_state(VpnState::Up);
        assert_eq!(c.state(), VpnState::Up);

        // подписчик получает оба State-события по порядку
        assert!(matches!(rx.recv().await.unwrap(), VpnEvent::State(VpnState::Connecting)));
        assert!(matches!(rx.recv().await.unwrap(), VpnEvent::State(VpnState::Up)));
    }

    #[test]
    fn disconnect_when_idle_is_safe() {
        let c = VpnController::new();
        c.disconnect(); // не паникует, no-op без активной сессии
        assert_eq!(c.state(), VpnState::Idle);
    }

    #[test]
    fn notify_network_changed_when_idle_is_safe() {
        let c = VpnController::new();
        // Нет активного pump → notify_waiters без ждущих: сигнал не запоминается, не паникует,
        // состояние не трогает (реконнект инициирует только connect-loop, если он крутится).
        c.notify_network_changed();
        assert_eq!(c.state(), VpnState::Idle);
    }

    #[test]
    fn backoff_doubles_and_caps() {
        let mut b = RECONNECT_BACKOFF_START;
        assert_eq!(b, Duration::from_secs(1));
        b = next_backoff(b);
        assert_eq!(b, Duration::from_secs(2));
        b = next_backoff(b);
        assert_eq!(b, Duration::from_secs(4));
        for _ in 0..10 {
            b = next_backoff(b); // упирается в потолок, не растёт бесконечно
        }
        assert_eq!(b, RECONNECT_BACKOFF_MAX);
    }

    #[tokio::test]
    async fn sleep_or_stop_returns_immediately_when_stopped() {
        let c = VpnController::new();
        c.disconnect(); // ставит stopped
        // не ждёт 10с — сразу true (реконнект прерывается пользовательским disconnect)
        assert!(c.sleep_or_stop(Duration::from_secs(10)).await);
    }

    /// C5.4b: pre-connect провал (напр. фетч Layer-1 токена не удался) эмитит Error → Down,
    /// чтобы UI вышел из спиннера, а не завис. `begin` перед этим показывает Connecting.
    #[tokio::test]
    async fn fail_emits_error_then_down() {
        let c = VpnController::new();
        let mut rx = c.subscribe();
        c.begin();
        c.fail("токен недоступен".into());
        assert_eq!(c.state(), VpnState::Down);
        assert!(matches!(rx.recv().await.unwrap(), VpnEvent::State(VpnState::Connecting)));
        assert!(matches!(rx.recv().await.unwrap(), VpnEvent::Error(e) if e.contains("токен")));
        assert!(matches!(rx.recv().await.unwrap(), VpnEvent::State(VpnState::Down)));
    }
}
