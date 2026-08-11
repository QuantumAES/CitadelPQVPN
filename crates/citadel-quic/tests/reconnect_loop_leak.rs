//! Вторая ступень разбора нагрузки на CPU (см. `failed_attempt_leak.rs`).
//!
//! Там проверялся голый `establish_session` — он ресурсов не оставляет. Здесь проверяется то, что
//! на самом деле крутится в клиенте: **цикл `VpnController`** с бесконечным реконнектом к
//! недоступному серверу, а затем `disconnect` — ровно последовательность «жму подключиться → не
//! может → отключаюсь», после которой у абонента оставалась постоянная нагрузка.
//!
//! Инвариант: после `disconnect` от сессии не должно остаться работающей работы. Меряем
//! процессорное время процесса в простое.

#![cfg(target_os = "linux")]

use std::net::{TcpListener, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use citadel_quic::config::{ClientConfig, MldsaSource, PinSource};
use citadel_quic::vpn::{TunParams, TunProvider, VpnController};
use citadel_tun::TunIo;

fn cpu_ms() -> u64 {
    let s = std::fs::read_to_string("/proc/self/stat").expect("/proc/self/stat");
    let tail = &s[s.rfind(')').expect("stat") + 2..];
    let f: Vec<&str> = tail.split_whitespace().collect();
    (f[11].parse::<u64>().unwrap() + f[12].parse::<u64>().unwrap()) * 1000 / 100
}

async fn idle_cpu_ms(dur: Duration) -> u64 {
    let a = cpu_ms();
    tokio::time::sleep(dur).await;
    cpu_ms() - a
}

/// TUN не нужен: до `configure` дело не доходит — establish к чёрной дыре не удаётся никогда.
struct NoTun;
impl TunProvider for NoTun {
    fn configure(&self, _p: &TunParams) -> anyhow::Result<Arc<dyn TunIo>> {
        Err(anyhow!("в тесте туннель не поднимается"))
    }
}

fn cfg(udp: &str, tcp_port: u16) -> ClientConfig {
    ClientConfig {
        servers: vec![udp.to_string()],
        server_name: "citadel.exit".into(),
        obfs_psk: Some([0x11; 32]),
        kx_suite: String::new(),
        tcp_port: tcp_port.to_string(),
        routes: String::new(),
        dns: None,
        mtu: "1280".into(),
        token: vec![7u8; 32],
        data_psk: None,
        pin: PinSource::Bytes([0x22; 32]),
        mldsa: MldsaSource::None,
        allow_insecure_no_pin: false,
        allow_classical_kx: false,
        require_pq_auth: false,
        killswitch: false,
        split: Default::default(),
        pacing: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "долгий (~2 мин): инструмент разбора, а не гейт"]
async fn stopped_session_leaves_no_running_work() {
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_addr = udp.local_addr().unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp_port = tcp.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        while let Ok((s, _)) = tcp.accept() {
            held.push(s);
        }
    });

    let base = idle_cpu_ms(Duration::from_secs(2)).await;

    // Три «нажатия подключиться», как у абонента: каждое вытесняет предыдущую сессию.
    for round in 1..=3 {
        let c = Arc::new(VpnController::new());
        let cfg = cfg(&udp_addr.to_string(), tcp_port);
        let c2 = c.clone();
        let h = tokio::spawn(async move {
            c2.begin();
            let _ = c2.connect(cfg, Arc::new(NoTun)).await;
        });

        // Даём циклу поработать (одна итерация = 5 QUIC-попыток + obfs-TCP), затем — «Отключить».
        tokio::time::sleep(Duration::from_secs(12)).await;
        c.disconnect();
        let _ = tokio::time::timeout(Duration::from_secs(30), h).await;

        let idle = idle_cpu_ms(Duration::from_secs(2)).await;
        eprintln!("[repro] после сессии {round}: простой стоит {idle} мс CPU (базовый {base} мс)");
    }

    let after = idle_cpu_ms(Duration::from_secs(3)).await;
    assert!(
        after < base + 300,
        "после остановленных сессий процесс продолжает работать: простой стоит {after} мс CPU \
         против {base} мс до них"
    );
}
