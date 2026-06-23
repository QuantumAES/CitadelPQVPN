//! CitadelPQVPN — M0 PoC: гибридный постквантовый QUIC-хендшейк (бинарь `Citadel-m0`).
//!
//! 1) POSITIVE: клиент и сервер с единственной KX-группой X25519MLKEM768 завершают
//!    хендшейк и прокачивают данные ⇒ согласована именно гибридная PQ-группа.
//! 2) NEGATIVE: классический клиент X25519 получает отказ — downgrade невозможен.

use anyhow::{anyhow, Result};
use rustls::crypto::aws_lc_rs;
use citadel_quic::{classical_groups, client_config, pq_groups, server_config};

async fn run_server(endpoint: quinn::Endpoint) {
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    eprintln!("[server] соединение установлено от {}", conn.remote_address());
                    if let Ok(mut recv) = conn.accept_uni().await {
                        if let Ok(buf) = recv.read_to_end(64 * 1024).await {
                            eprintln!("[server] получено по туннелю: {:?}", String::from_utf8_lossy(&buf));
                        }
                    }
                }
                Err(e) => eprintln!("[server] входящее соединение не завершило хендшейк: {e}"),
            }
        });
    }
}

async fn try_connect(
    client_ep: &quinn::Endpoint,
    cfg: quinn::ClientConfig,
    addr: std::net::SocketAddr,
    send_payload: Option<&[u8]>,
) -> Result<()> {
    let connecting = client_ep.connect_with(cfg, addr, "Citadel.exit")?;
    let conn = tokio::time::timeout(std::time::Duration::from_secs(8), connecting)
        .await
        .map_err(|_| anyhow!("таймаут хендшейка"))??;
    if let Some(payload) = send_payload {
        let mut send = conn.open_uni().await?;
        send.write_all(payload).await?;
        send.finish()?;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    conn.close(0u32.into(), b"done");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("CitadelPQVPN M0 PoC — гибридный постквантовый QUIC-хендшейк");
    println!("KX группа (PQ): {:?}", aws_lc_rs::kx_group::X25519MLKEM768.name());
    println!("KX группа (классика, негатив): {:?}\n", aws_lc_rs::kx_group::X25519.name());

    let addr_loopback = "127.0.0.1:0".parse()?;
    let server_ep = quinn::Endpoint::server(server_config(pq_groups())?, addr_loopback)?;
    let server_addr = server_ep.local_addr()?;
    println!("[server] слушает {server_addr}, KX = только X25519MLKEM768");
    tokio::spawn(run_server(server_ep));

    let client_ep = quinn::Endpoint::client(addr_loopback)?;

    print!("\n[TEST 1 / POSITIVE] клиент X25519MLKEM768 → сервер X25519MLKEM768 ... ");
    match try_connect(&client_ep, client_config(pq_groups())?, server_addr, Some(b"Citadel-m0-ping")).await {
        Ok(()) => println!("OK ✔  (хендшейк завершён ⇒ согласована X25519MLKEM768; данные прошли)"),
        Err(e) => {
            println!("FAIL ✗ — {e}");
            return Err(anyhow!("позитивный тест провалился: {e}"));
        }
    }

    print!("[TEST 2 / NEGATIVE] клиент X25519 (классика) → сервер X25519MLKEM768 ... ");
    match try_connect(&client_ep, client_config(classical_groups())?, server_addr, None).await {
        Err(e) => println!("OK ✔  (ожидаемый отказ, downgrade невозможен: {e})"),
        Ok(()) => {
            println!("FAIL ✗ — классический клиент не должен был подключиться!");
            return Err(anyhow!("негативный тест провалился: произошёл downgrade"));
        }
    }

    client_ep.wait_idle().await;
    println!("\nИТОГ: M0 подтверждён — постквантовый гибридный KX обязателен и работает.");
    Ok(())
}
