//! CitadelPQVPN — клиентская оркестрация движка: установка сессии и data-plane.
//!
//! [`establish_session`] поднимает транспорт (failover по списку exit'ов, M5) и делает
//! control-обмен (анонимный токен → назначенный адрес, PQ-auth M7) — **без TUN и без
//! сетевой настройки**. [`run_data_plane`] гоняет пакеты между TUN и транспортом.
//!
//! Разделение `establish` / `data_plane` — предпосылка мобильной совместимости: ОС
//! (Android `VpnService.Builder`) требует адрес туннеля ДО выдачи fd, поэтому сначала
//! получаем адрес (establish), затем конфигурируем TUN, затем качаем (data_plane).
//! Сетевую настройку интерфейса (адрес/маршруты/DNS) делает вызывающий: на Linux —
//! `NetConfigurator` в бинаре, на Android — `VpnService.Builder`. См. docs/CLIENT-ARCH.md §4.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use rand::RngCore;

use citadel_masque::capsule;
use citadel_tun::TunIo;

use crate::config::{ClientConfig, PinMode};
use crate::dataplane::{pump, Tunnel};
use crate::tcp_obfs::TcpObfs;

/// Установленная клиентская сессия: поднятый транспорт + назначенный сервером адрес.
/// Сетевую настройку интерфейса делает вызывающий (Linux `NetConfigurator`, Android
/// `VpnService.Builder` — адрес скармливается ДО получения fd).
pub struct Session {
    tunnel: Tunnel, // приватный: транспорт целиком уходит в run_data_plane
    /// Назначенный exit'ом IPv4-адрес клиента.
    pub addr: [u8; 4],
    /// Длина префикса назначенного адреса.
    pub prefix: u8,
    /// Выбранный exit `host:port` (для логов/диагностики).
    pub chosen: String,
}

impl Session {
    /// Транспорт сессии: `"QUIC/UDP"` или `"obfs-TCP"`.
    pub fn transport(&self) -> &'static str {
        self.tunnel.kind()
    }
    /// Назначенный адрес в форме CIDR (например, `"10.7.0.3/24"`).
    pub fn cidr(&self) -> String {
        format!(
            "{}.{}.{}.{}/{}",
            self.addr[0], self.addr[1], self.addr[2], self.addr[3], self.prefix
        )
    }
}

/// Хост-часть `host:port` (для pin-файла и TCP-fallback цели).
pub fn host_of(server: &str) -> &str {
    server.rsplit_once(':').map(|(h, _)| h).unwrap_or(server)
}

/// Поднять сессию: failover по списку exit'ов (M5) + control-обмен (токен→адрес, PQ-auth M7).
/// **Без TUN и без сетевой настройки** — только транспорт и назначенный адрес.
pub async fn establish_session(cfg: &ClientConfig) -> Result<Session> {
    eprintln!("[citadel-m1:client] exit-серверы (перемешаны): {}", cfg.servers.join(", "));

    // M5 multi-server: идём по списку failover'ом — первый поднявшийся exit (QUIC или TCP-fallback).
    let mut tunnel = None;
    let mut chosen = String::new();
    for server in &cfg.servers {
        match connect_server(server, cfg).await {
            Ok(Some(t)) => {
                eprintln!("[citadel-m1:client] ВЫБРАН exit {server} (транспорт {})", t.kind());
                tunnel = Some(t);
                chosen = server.clone();
                break;
            }
            Ok(None) => eprintln!("[citadel-m1:client] exit {server} недоступен — пробую следующий"),
            Err(e) => eprintln!("[citadel-m1:client] exit {server}: {e} — пробую следующий"),
        }
    }
    let mut tunnel = tunnel
        .ok_or_else(|| anyhow!("ни один exit недоступен: {}", cfg.servers.join(", ")))?;

    // M7 PQ-auth: pin (Ed25519-cert) + ML-DSA-65 pk выбранного exit (если провижированы)
    let host = host_of(&chosen);
    let cert_pin = match cfg.pin_for(host) {
        PinMode::Pinned(p) => p,
        _ => [0u8; 32],
    };
    let mldsa_pk = cfg.mldsa_for(host);
    if mldsa_pk.is_some() {
        eprintln!("[citadel-m1:client] PQ-auth (M7): буду проверять ML-DSA-65 подпись exit {host}");
    }

    // M2+M4/M5: предъявляем анонимный токен и получаем адрес капсулой
    if cfg.token.is_empty() {
        eprintln!("[citadel-m1:client] WARN: токен (Citadel_TOKENS) не задан — exit может отказать");
    } else {
        eprintln!("[citadel-m1:client] предъявляю анонимный токен ({} б)", cfg.token.len());
    }
    let a = client_request_address(&mut tunnel, &cfg.token, mldsa_pk.as_deref(), cert_pin).await?;
    Ok(Session {
        tunnel,
        addr: a.addr,
        prefix: a.prefix,
        chosen,
    })
}

/// Запустить data-plane: перекачка пакетов TUN ⇄ транспорт. Клиент себя не лимитирует
/// (rate-limit F7 — забота exit). Поглощает `session` (транспорт уходит в `pump`).
pub async fn run_data_plane(session: Session, tun: Arc<dyn TunIo>) -> Result<()> {
    pump(session.tunnel, tun, false, None).await
}

/// Подключиться к ОДНОМУ exit'у: основной путь PQ-QUIC, при недоступности — obfs-over-TCP
/// fallback (M4, порт `cfg.tcp_port`, по умолчанию 443). `None` — exit недоступен → вызывающий
/// пробует следующий из списка (M5 failover).
async fn connect_server(server: &str, cfg: &ClientConfig) -> Result<Option<Tunnel>> {
    let host = host_of(server);
    let addr = match tokio::net::lookup_host(server).await.map(|mut it| it.next()) {
        Ok(Some(a)) => a,
        _ => return Ok(None),
    };
    // failover/fallback хотят быстрый QUIC-timeout; один сервер без fallback — ждём дольше.
    let multi = cfg.servers.len() > 1;
    let attempts = if multi || cfg.obfs_psk.is_some() { 5 } else { 60 };
    if let Some(conn) = try_quic_connect(server, addr, cfg, attempts, host).await? {
        eprintln!("[citadel-m1:client] PQ-туннель (QUIC/UDP) к {server} ✔");
        return Ok(Some(Tunnel::Quic(conn)));
    }
    if let Some(psk) = cfg.obfs_psk {
        let tcp_target = format!("{host}:{}", cfg.tcp_port);
        if let Ok(Some(taddr)) = tokio::net::lookup_host(&tcp_target).await.map(|mut it| it.next()) {
            eprintln!("[citadel-m1:client] QUIC к {server} недоступен → obfs-TCP к {tcp_target}");
            // таймаут: мёртвый host иначе висит на TCP connect (~минуты) и ломает failover
            if let Ok(Ok(tcp)) =
                tokio::time::timeout(Duration::from_secs(3), TcpObfs::connect(taddr, psk)).await
            {
                eprintln!("[citadel-m1:client] obfs-TCP туннель к {tcp_target} ✔");
                return Ok(Some(Tunnel::Tcp(tcp)));
            }
        }
    }
    Ok(None)
}

/// Попытаться поднять PQ-QUIC к одному серверу. `None` — не удалось за `attempts` попыток
/// (UDP/QUIC заблокирован или exit недоступен). Pin берётся per-host (`cfg.pin_for`).
async fn try_quic_connect(
    connect: &str,
    addr: SocketAddr,
    cfg: &ClientConfig,
    attempts: u32,
    pin_host: &str,
) -> Result<Option<quinn::Connection>> {
    let ep = match cfg.obfs_psk {
        Some(psk) => crate::client_endpoint_obfs(psk)?,
        None => quinn::Endpoint::client("0.0.0.0:0".parse()?)?,
    };
    eprintln!(
        "[citadel-m1:client] QUIC: пробую {connect} ({addr}), server_name={}, KX={}",
        cfg.server_name,
        crate::kx_suite_name(&cfg.kx_suite)
    );
    let mut logged_pin = false;
    for attempt in 1..=attempts {
        let qcfg = match cfg.pin_for(pin_host) {
            PinMode::Pinned(p) => {
                if !logged_pin {
                    eprintln!("[citadel-m1:client] pinning {pin_host}: {}", hex::encode(p));
                    logged_pin = true;
                }
                crate::client_config_pinned(crate::kx_groups_for(&cfg.kx_suite), p)?
            }
            PinMode::NoPin => {
                if !logged_pin {
                    eprintln!("[citadel-m1:client] WARN: pin не настроен — принимаю любой серт (PoC)");
                    logged_pin = true;
                }
                crate::client_config(crate::kx_groups_for(&cfg.kx_suite))?
            }
            PinMode::Waiting => {
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }
        };
        match tokio::time::timeout(Duration::from_secs(3), ep.connect_with(qcfg, addr, &cfg.server_name)?).await {
            Ok(Ok(c)) => return Ok(Some(c)),
            Ok(Err(e)) => eprintln!("[citadel-m1:client] QUIC попытка {attempt}: {e}"),
            Err(_) => eprintln!("[citadel-m1:client] QUIC попытка {attempt}: таймаут (exit/UDP недоступен?)"),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Ok(None)
}

/// Control-обмен (M2): nonce(32)‖varint(token_len)‖token‖ADDRESS_REQUEST → проверка ML-DSA
/// подписи сервера (M7, если pk провижирован) → ADDRESS_ASSIGN. Возвращает назначенный адрес.
async fn client_request_address(
    tunnel: &mut Tunnel,
    token: &[u8],
    mldsa_pk: Option<&[u8]>,
    cert_pin: [u8; 32],
) -> Result<capsule::AssignedV4> {
    // M7 PQ-auth: nonce(32) для привязки подписи сервера; далее токен + ADDRESS_REQUEST
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let req = capsule::AssignedV4 { request_id: 1, addr: [0, 0, 0, 0], prefix: 0 };
    let mut out = nonce.to_vec();
    out.extend_from_slice(&citadel_masque::varint::to_vec(token.len() as u64));
    out.extend_from_slice(token);
    out.extend_from_slice(&capsule::encode_address_request_v4(&req));

    let buf = tunnel.control_client(&out).await?;
    // ответ: varint(sig_len) ‖ ML-DSA-sig ‖ ADDRESS_ASSIGN
    let (sig_len, m) =
        citadel_masque::varint::decode(&buf).ok_or_else(|| anyhow!("нет sig-префикса"))?;
    let sig_end = m + sig_len as usize;
    if buf.len() < sig_end {
        return Err(anyhow!("обрезанная PQ-подпись"));
    }
    let sig = &buf[m..sig_end];
    let rest = &buf[sig_end..];

    // M7: проверяем ML-DSA-65 подпись сервера, если его pk провижирован (гибрид с Ed25519+pin)
    if let Some(pk) = mldsa_pk {
        if !crate::pqauth::verify_binding(pk, &nonce, &cert_pin, sig) {
            return Err(anyhow!("PQ-auth: ML-DSA подпись сервера НЕ прошла — возможен MITM"));
        }
        eprintln!("[citadel-m1:client] PQ-auth ✔ ML-DSA-65 подпись сервера верна (гибрид Ed25519+ML-DSA)");
    }

    let (t, val, _) = capsule::decode(rest).ok_or_else(|| anyhow!("битая капсула в ответе"))?;
    if t != capsule::ADDRESS_ASSIGN {
        return Err(anyhow!("ожидался ADDRESS_ASSIGN, получен type={t}"));
    }
    capsule::decode_assigned_v4(val).ok_or_else(|| anyhow!("битое тело ADDRESS_ASSIGN"))
}
