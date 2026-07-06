//! Ручная проверка авто-реконнекта `VpnController` (задача 1) против e2e-exit.
//!
//! Поднимает сессию с noop-TUN, печатает поток событий. Оборви exit в середине
//! (`docker compose -f docker/compose.e2e.yml restart exit`) — контроллер должен уйти в
//! Migrating и сам восстановиться (Up) без ручного коннекта.
//!
//! ```text
//! cargo run -p citadel-client --example reconnect_probe -- "citadel://…"
//! ```

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use citadel_client::{CredentialLink, TunIo, TunParams, TunProvider, VpnController, VpnEvent};

/// TUN-заглушка: раз в ~2с «читает» мелкий пакет (чтобы транспорт активно слал и быстро ловил
/// мёртвый peer — иначе obfs-TCP без трафика висит), отправка — в никуда. `raw_fd=None`.
struct NoopTun;
impl TunIo for NoopTun {
    fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        std::thread::sleep(Duration::from_secs(2));
        let n = 28.min(buf.len());
        buf[..n].fill(0); // содержимое неважно — цель лишь заставить транспорт слать
        Ok(n)
    }
    fn send(&self, pkt: &[u8]) -> std::io::Result<usize> {
        Ok(pkt.len())
    }
    fn raw_fd(&self) -> Option<i32> {
        None
    }
}

struct NoopProvider;
impl TunProvider for NoopProvider {
    fn configure(&self, p: &TunParams) -> Result<Arc<dyn TunIo>> {
        println!(
            ">>> configure TUN: addr {}.{}.{}.{}/{}, exit_ips={:?}",
            p.addr[0], p.addr[1], p.addr[2], p.addr[3], p.prefix, p.exit_ips
        );
        Ok(Arc::new(NoopTun))
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let link = std::env::args().nth(1).expect("укажи citadel://-ссылку аргументом");
    let cfg = CredentialLink::from_uri(&link)?.to_client_config();

    let ctrl = Arc::new(VpnController::new());
    let mut rx = ctrl.subscribe();
    let c2 = ctrl.clone();
    tokio::spawn(async move {
        let _ = c2.connect(cfg, Arc::new(NoopProvider)).await;
    });

    // печатаем события PROBE_SECS (по умолч. 45); обрыв детектится по QUIC idle-timeout (~30с),
    // поэтому для теста stop→start бери окно побольше (напр. PROBE_SECS=90).
    let secs: u64 = std::env::var("PROBE_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(45);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            break;
        }
        match tokio::time::timeout(left, rx.recv()).await {
            Ok(Ok(ev)) => match ev {
                VpnEvent::State(s) => println!("[event] state = {s:?}"),
                VpnEvent::Connected { exit, transport, cidr } => {
                    println!("[event] CONNECTED exit={exit} transport={transport} cidr={cidr}")
                }
                VpnEvent::Error(e) => println!("[event] ERROR {e}"),
            },
            _ => break,
        }
    }
    ctrl.disconnect();
    println!(">>> disconnect — конец пробы");
    Ok(())
}
