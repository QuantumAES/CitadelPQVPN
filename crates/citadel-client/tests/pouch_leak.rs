//! Третья ступень разбора нагрузки на CPU (после `citadel-quic`: `failed_attempt_leak`,
//! `reconnect_loop_leak`). Здесь собран полный клиентский путь GUI: цикл `VpnController`
//! **с кошельком токенов** (`install_with_seed`), недоступный exit и издатель, который на каждое
//! обращение отвечает мгновенным разрывом — так вёл себя необновлённый сервер у абонента.
//!
//! Кошелёк важен именно здесь: он ходит к издателю блокирующим кодом через `spawn_blocking`, а
//! такие задачи `disconnect` отменить не может — если бы там осталась работа, она пережила бы
//! «Отключить» и накапливалась с каждой попыткой. Инвариант: после остановки сессии процесс снова
//! тих.

#![cfg(target_os = "linux")]

use std::net::{TcpListener, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use citadel_client::creds::CredentialLink;
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

struct NoTun;
impl TunProvider for NoTun {
    fn configure(&self, _p: &TunParams) -> anyhow::Result<Arc<dyn TunIo>> {
        Err(anyhow!("в тесте туннель не поднимается"))
    }
}

/// Принимать соединения и сразу рвать: издатель «отвечает», но ничего осмысленного — фетч токена
/// падает быстро, и цикл реконнекта крутится на полной скорости.
fn spawn_rude_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        while let Ok((s, _)) = l.accept() {
            drop(s);
        }
    });
    port
}

fn link(exit: &str, tcp_port: u16, issuer: &str) -> CredentialLink {
    CredentialLink {
        version: 5,
        servers: vec![exit.to_string()],
        server_name: "citadel.exit".into(),
        kx_suite: String::new(),
        cert_pin: Some([0x22; 32]),
        mldsa_commit: None,
        obfs_psk: Some([0x11; 32]),
        tcp_port: Some(tcp_port.to_string()),
        issuer: Some(issuer.to_string()),
        issuer_commit: None,
        issuer_pin: Some([0x33; 32]),
        issuer_mldsa: Some([0x44; 32]),
        client_seed: Some([0x55; 32]),
        admin_seed: None,
        admin_port: None,
        routes: String::new(),
        dns: None,
        exp: None,
        enroll: false,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "долгий (~1.5 мин): инструмент разбора, а не гейт"]
async fn stopped_session_with_pouch_leaves_no_running_work() {
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let exit = udp.local_addr().unwrap().to_string();
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp_port = tcp.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        while let Ok((s, _)) = tcp.accept() {
            held.push(s); // obfs-TCP порт принимает и молчит
        }
    });
    let issuer = format!("127.0.0.1:{}", spawn_rude_server());

    let base = idle_cpu_ms(Duration::from_secs(2)).await;

    for round in 1..=3 {
        let c = Arc::new(VpnController::new());
        let l = link(&exit, tcp_port, &issuer);
        let cfg = l.to_client_config();
        assert!(
            citadel_client::token_agent::install_with_seed(&c, &l, l.client_seed),
            "кошелёк обязан установиться: в ссылке есть issuer+pin+обязательство+seed"
        );
        let c2 = c.clone();
        let h = tokio::spawn(async move {
            c2.begin();
            let _ = c2.connect(cfg, Arc::new(NoTun)).await;
        });

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
