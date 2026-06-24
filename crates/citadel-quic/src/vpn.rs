//! `VpnController` — высокоуровневый фасад движка для GUI/FFI.
//!
//! Оркеструет `establish_session` → конфигурацию туннеля через [`TunProvider`] →
//! `run_data_plane`, отдавая поток событий состояния. UI/FFI (Flutter, C0.6+) держит
//! `Arc<VpnController>`, зовёт [`VpnController::connect`]/[`VpnController::disconnect`]
//! и слушает [`VpnController::subscribe`]. Платформа туннеля скрыта за `TunProvider`
//! (Linux `/dev/net/tun`, Android `VpnService.Builder`) — см. docs/CLIENT-ARCH.md §4.

use std::sync::{Arc, Mutex};

use anyhow::Result;
use tokio::sync::{broadcast, Notify};

use citadel_tun::TunIo;

use crate::client::{establish_session, run_data_plane};
use crate::config::ClientConfig;

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
}

/// Платформенный провайдер туннеля: по назначенному адресу строит/конфигурирует TUN и
/// отдаёт пакетный I/O. Linux — `/dev/net/tun` + `ip`; Android — `VpnService.Builder.establish()`.
///
/// Вызывается **после** `establish_session` (адрес уже известен) — порядок, которого требуют
/// мобильные ОС (адрес скармливается билдеру ДО получения fd).
pub trait TunProvider: Send + Sync + 'static {
    fn configure(&self, p: &TunParams) -> Result<Arc<dyn TunIo>>;
}

/// Высокоуровневый контроллер VPN-сессии. Потокобезопасен; для фонового запуска
/// держится в `Arc` и `connect` крутится в `tokio::spawn`, а `disconnect` зовётся из UI-потока.
pub struct VpnController {
    state: Mutex<VpnState>,
    events: broadcast::Sender<VpnEvent>,
    shutdown: Notify,
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
        }
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

    /// Поднять VPN: `establish` → `provider.configure(назначенный_адрес)` → `data_plane`.
    /// Блокирует до завершения сессии (разрыв транспорта, ошибка или `disconnect`). Для
    /// фонового запуска — `tokio::spawn` с `Arc<VpnController>`. События — через `subscribe`.
    pub async fn connect(&self, cfg: ClientConfig, provider: Arc<dyn TunProvider>) -> Result<()> {
        self.set_state(VpnState::Connecting);
        let session = match establish_session(&cfg).await {
            Ok(s) => s,
            Err(e) => {
                self.emit(VpnEvent::Error(e.to_string()));
                self.set_state(VpnState::Down);
                return Err(e);
            }
        };
        self.emit(VpnEvent::Connected {
            exit: session.chosen.clone(),
            transport: session.transport().to_string(),
            cidr: session.cidr(),
        });

        // Конфигурируем туннель ПОД назначенный адрес (на Android — VpnService.Builder).
        let params = TunParams {
            addr: session.addr,
            prefix: session.prefix,
            mtu: cfg.mtu.clone(),
            routes: cfg.routes.clone(),
            dns: cfg.dns.clone(),
        };
        let tun = match provider.configure(&params) {
            Ok(t) => t,
            Err(e) => {
                self.emit(VpnEvent::Error(e.to_string()));
                self.set_state(VpnState::Down);
                return Err(e);
            }
        };

        self.set_state(VpnState::Up);
        // data-plane крутится до разрыва транспорта ИЛИ до disconnect (тогда future data-plane
        // дропается → транспорт (QUIC/TCP) закрывается при drop).
        let r = tokio::select! {
            r = run_data_plane(session, tun) => r,
            _ = self.shutdown.notified() => {
                eprintln!("[vpn] disconnect — закрываю сессию");
                Ok(())
            }
        };
        self.set_state(VpnState::Down);
        r
    }

    /// Запросить разрыв активной сессии (будит `connect`, который роняет транспорт).
    /// Безопасно в любом состоянии (нет активной сессии → no-op).
    pub fn disconnect(&self) {
        self.shutdown.notify_waiters();
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
}
