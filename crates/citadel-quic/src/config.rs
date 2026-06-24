//! `ClientConfig` — конфигурация клиента движка, развязанная от окружения.
//!
//! Бинарь `citadel-m1` строит её `ClientConfig::from_env()` (контракт `Citadel_*`);
//! GUI-клиент (трек C0.4+) построит из распарсенного бандла/QR/ссылки. Движок
//! (connect/handshake/data-plane) читает ТОЛЬКО эту структуру и НЕ трогает env —
//! это предпосылка к встраиванию в мобильный/десктоп-клиент (docs/CLIENT-ARCH.md §4.2).

use anyhow::{Context, Result};

/// Режим pinning сертификата сервера (F1) для конкретного host.
pub enum PinMode {
    Pinned([u8; 32]),
    Waiting, // pinning настроен, но pin ещё не доступен (ждём, пока exit его запишет)
    NoPin,   // pinning не настроен (PoC-режим)
}

/// Откуда брать pin сервера, резолвится per-host в [`ClientConfig::pin_for`].
#[derive(Clone)]
pub enum PinSource {
    Bytes([u8; 32]), // прямые байты pin (из бандла кред / QR — мобильный путь, C1.4)
    Shared(String), // общий hex-pin на все exit (Citadel_PIN)
    Dir(String),    // <dir>/<host>.pin — per-exit, multi-server (Citadel_PIN_DIR)
    File(String),   // один файл (Citadel_PIN_FILE, legacy single-server)
    None,           // PoC: pinning не настроен
}

/// Откуда брать ML-DSA-65 pub сервера (M7), резолвится per-host в [`ClientConfig::mldsa_for`].
#[derive(Clone)]
pub enum MldsaSource {
    Bytes(Vec<u8>), // прямые байты ML-DSA pub (из бандла кред / QR, C1.4)
    File(String), // Citadel_MLDSA_PUB
    Dir(String),  // <dir>/<host>.mldsa (Citadel_PIN_DIR)
    None,
}

/// Конфигурация клиента: всё, что нужно движку для подключения к exit'ам.
#[derive(Clone)]
pub struct ClientConfig {
    /// Список exit-серверов `host:port` (уже перемешан для балансировки, M5).
    pub servers: Vec<String>,
    /// SNI / server_name для TLS.
    pub server_name: String,
    /// L1-obfs PSK (`None` → без обфускации, PoC).
    pub obfs_psk: Option<[u8; 32]>,
    /// KX-suite (crypto-agility, M6): сырое значение `Citadel_KX` ("", "pq", "classical", "all").
    pub kx_suite: String,
    /// Порт obfs-over-TCP fallback (M4).
    pub tcp_port: String,
    /// Маршруты в туннель (через пробел); пусто → таблицу не трогаем.
    pub routes: String,
    /// DNS-резолвер для F6 (`None` → не настраиваем).
    pub dns: Option<String>,
    /// MTU туннеля.
    pub mtu: String,
    /// Анонимный токен для предъявления exit (M4/M5); пусто → exit может отказать.
    pub token: Vec<u8>,
    /// Источник pin'ов сервера (F1).
    pub pin: PinSource,
    /// Источник ML-DSA pub (M7).
    pub mldsa: MldsaSource,
}

/// Pin из hex (ровно 32 байта).
pub fn parse_pin(s: &str) -> Option<[u8; 32]> {
    hex::decode(s.trim()).ok().and_then(|v| v.try_into().ok())
}

/// obfs PSK из строки: 64 hex = 32 байта напрямую, иначе BLAKE3-derive по контексту.
pub fn parse_obfs_psk(v: &str) -> Option<[u8; 32]> {
    let v = v.trim();
    if v.is_empty() {
        return None;
    }
    if v.len() == 64 {
        if let Ok(bytes) = hex::decode(v) {
            if let Ok(a) = bytes.try_into() {
                return Some(a);
            }
        }
    }
    Some(blake3::derive_key("CitadelPQVPN/obfs/v1/psk", v.as_bytes()))
}

impl ClientConfig {
    /// Построить из окружения `Citadel_*` (контракт бинаря/Docker).
    pub fn from_env() -> Result<Self> {
        let mut servers: Vec<String> = match std::env::var("Citadel_SERVERS") {
            Ok(s) => s
                .split([' ', ';', ','])
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(String::from)
                .collect(),
            Err(_) => vec![std::env::var("Citadel_CONNECT")
                .context("ни Citadel_SERVERS, ни Citadel_CONNECT не заданы")?],
        };
        use rand::seq::SliceRandom;
        servers.shuffle(&mut rand::thread_rng());

        // pin: Citadel_PIN (общий) > Citadel_PIN_DIR (per-host) > Citadel_PIN_FILE (legacy).
        let pin = if let Ok(h) = std::env::var("Citadel_PIN") {
            PinSource::Shared(h)
        } else if let Ok(d) = std::env::var("Citadel_PIN_DIR") {
            PinSource::Dir(d)
        } else if let Ok(f) = std::env::var("Citadel_PIN_FILE") {
            PinSource::File(f)
        } else {
            PinSource::None
        };

        // mldsa: Citadel_MLDSA_PUB (файл) > Citadel_PIN_DIR/<host>.mldsa.
        let mldsa = if let Ok(f) = std::env::var("Citadel_MLDSA_PUB") {
            MldsaSource::File(f)
        } else if let Ok(d) = std::env::var("Citadel_PIN_DIR") {
            MldsaSource::Dir(d)
        } else {
            MldsaSource::None
        };

        let token = std::env::var("Citadel_TOKENS")
            .ok()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| s.lines().next().map(|l| l.trim().to_string()))
            .and_then(|l| hex::decode(l).ok())
            .unwrap_or_default();

        Ok(Self {
            servers,
            server_name: std::env::var("Citadel_SERVER_NAME").unwrap_or_else(|_| "Citadel.exit".into()),
            obfs_psk: std::env::var("Citadel_OBFS_PSK")
                .ok()
                .as_deref()
                .and_then(parse_obfs_psk),
            kx_suite: std::env::var("Citadel_KX").unwrap_or_default(),
            tcp_port: std::env::var("Citadel_TCP_PORT").unwrap_or_else(|_| "443".into()),
            routes: std::env::var("Citadel_ROUTES").unwrap_or_default(),
            dns: std::env::var("Citadel_DNS").ok(),
            mtu: std::env::var("Citadel_MTU").unwrap_or_else(|_| "1280".into()),
            token,
            pin,
            mldsa,
        })
    }

    /// Pin сервера `host`: Shared > Dir/`<host>.pin` > File. Совпадает со старым `read_pin_for`.
    pub fn pin_for(&self, host: &str) -> PinMode {
        match &self.pin {
            PinSource::Bytes(p) => PinMode::Pinned(*p),
            PinSource::Shared(h) => parse_pin(h).map(PinMode::Pinned).unwrap_or(PinMode::Waiting),
            PinSource::Dir(dir) => pin_from_file(&format!("{dir}/{host}.pin")),
            PinSource::File(f) => pin_from_file(f),
            PinSource::None => PinMode::NoPin,
        }
    }

    /// ML-DSA-65 pub выбранного `host` (M7): File > Dir/`<host>.mldsa`. None → PQ-auth не запрашивается.
    pub fn mldsa_for(&self, host: &str) -> Option<Vec<u8>> {
        match &self.mldsa {
            MldsaSource::Bytes(k) => Some(k.clone()),
            MldsaSource::File(f) => std::fs::read(f).ok(),
            MldsaSource::Dir(dir) => std::fs::read(format!("{dir}/{host}.mldsa")).ok(),
            MldsaSource::None => None,
        }
    }
}

fn pin_from_file(path: &str) -> PinMode {
    match std::fs::read_to_string(path) {
        Ok(s) => parse_pin(&s).map(PinMode::Pinned).unwrap_or(PinMode::Waiting),
        Err(_) => PinMode::Waiting,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pin_cases() {
        let p = [0xABu8; 32];
        assert_eq!(parse_pin(&hex::encode(p)), Some(p));
        assert_eq!(parse_pin("  not-hex  "), None);
        assert_eq!(parse_pin(&hex::encode([0u8; 31])), None); // не 32 байта
    }

    #[test]
    fn obfs_psk_hex_vs_derive() {
        assert_eq!(parse_obfs_psk(""), None);
        assert_eq!(parse_obfs_psk("   "), None);
        // 64 hex → 32 байта напрямую
        assert_eq!(parse_obfs_psk(&hex::encode([7u8; 32])), Some([7u8; 32]));
        // короткая строка → детерминированный BLAKE3-derive по фиксированному контексту
        assert_eq!(
            parse_obfs_psk("hunter2"),
            Some(blake3::derive_key("CitadelPQVPN/obfs/v1/psk", b"hunter2"))
        );
    }

    #[test]
    fn pin_for_modes() {
        let mk = |pin| ClientConfig {
            servers: vec![],
            server_name: "x".into(),
            obfs_psk: None,
            kx_suite: String::new(),
            tcp_port: "443".into(),
            routes: String::new(),
            dns: None,
            mtu: "1280".into(),
            token: vec![],
            pin,
            mldsa: MldsaSource::None,
        };
        assert!(matches!(mk(PinSource::None).pin_for("h"), PinMode::NoPin));
        let p = [3u8; 32];
        assert!(matches!(mk(PinSource::Shared(hex::encode(p))).pin_for("h"), PinMode::Pinned(x) if x == p));
        assert!(matches!(mk(PinSource::Shared("nothex".into())).pin_for("h"), PinMode::Waiting));
        assert!(matches!(mk(PinSource::Bytes(p)).pin_for("h"), PinMode::Pinned(x) if x == p));
    }

    #[test]
    fn mldsa_for_bytes() {
        let cfg = ClientConfig {
            servers: vec![],
            server_name: "x".into(),
            obfs_psk: None,
            kx_suite: String::new(),
            tcp_port: "443".into(),
            routes: String::new(),
            dns: None,
            mtu: "1280".into(),
            token: vec![],
            pin: PinSource::None,
            mldsa: MldsaSource::Bytes(vec![1, 2, 3]),
        };
        assert_eq!(cfg.mldsa_for("any"), Some(vec![1, 2, 3]));
    }
}
