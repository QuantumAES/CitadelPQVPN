//! CitadelPQVPN — data plane (L3): транспортная абстракция `Tunnel{Quic,Tcp}`,
//! обработка входящего трафика `Inbound` (egress-фильтр F2 + rate-limit F7) и
//! `pump` — двунаправленная перекачка TUN ⇄ транспорт.
//!
//! Вынесено из `bin/citadel-m1` (трек C0.2): движок работает поверх
//! `Arc<dyn TunIo>` (citadel-tun) и не знает конкретной платформы туннеля —
//! это и есть граница, через которую ОС отдаёт туннель в движок (Linux
//! `/dev/net/tun`, Android `VpnService` fd, …). См. docs/CLIENT-ARCH.md §3–4.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use citadel_masque::{datagram, ip};
use citadel_tun::TunIo;

use crate::ratelimit::{RateCfg, TokenBucket};
use crate::tcp_obfs::TcpObfs;

/// Транспорт туннеля: основной PQ-QUIC либо obfs-over-TCP fallback (M4).
pub enum Tunnel {
    Quic(quinn::Connection),
    Tcp(TcpObfs),
}

impl Tunnel {
    pub fn peer(&self) -> SocketAddr {
        match self {
            Tunnel::Quic(c) => c.remote_address(),
            Tunnel::Tcp(t) => t.peer(),
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Tunnel::Quic(_) => "QUIC/UDP",
            Tunnel::Tcp(_) => "obfs-TCP",
        }
    }

    pub fn close(&self, code: u32, reason: &[u8]) {
        if let Tunnel::Quic(c) = self {
            c.close(code.into(), reason);
        }
        // TCP закрывается при drop
    }

    /// Клиент: послать один control-запрос и получить ответ (reliable message).
    pub async fn control_client(&mut self, req: &[u8]) -> Result<Vec<u8>> {
        match self {
            Tunnel::Quic(conn) => {
                let (mut send, mut recv) = conn.open_bi().await?;
                send.write_all(req).await?;
                send.finish()?;
                Ok(recv.read_to_end(4096).await?)
            }
            Tunnel::Tcp(t) => {
                t.send_msg(req).await?;
                Ok(t.recv_msg().await?)
            }
        }
    }

    /// Сервер: принять один control-запрос, обработать `handle` и ответить.
    pub async fn control_server<F>(&mut self, handle: F) -> Result<()>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>>,
    {
        match self {
            Tunnel::Quic(conn) => {
                let (mut send, mut recv) = conn.accept_bi().await?;
                let req = recv.read_to_end(8192).await?;
                let resp = handle(&req)?;
                send.write_all(&resp).await?;
                send.finish()?;
                Ok(())
            }
            Tunnel::Tcp(t) => {
                let req = t.recv_msg().await?;
                let resp = handle(&req)?;
                t.send_msg(&resp).await?;
                Ok(())
            }
        }
    }
}

/// Обработка входящего (от клиента) пакета на exit: egress-фильтр (F2) + rate-limit (F7).
/// `accept` → `true` пропустить в TUN, `false` дропнуть. Состояние bucket/счётчики — per-connection.
pub struct Inbound {
    egress_filter: bool,
    bucket: Option<TokenBucket>,
    dropped: u64,
    dropped_bytes: u64,
}

impl Inbound {
    pub fn new(egress_filter: bool, rate_limit: Option<RateCfg>) -> Self {
        Self {
            egress_filter,
            bucket: rate_limit.map(|c| TokenBucket::new(c, Instant::now())),
            dropped: 0,
            dropped_bytes: 0,
        }
    }

    pub fn accept(&mut self, pkt: &[u8]) -> bool {
        if self.egress_filter {
            if let Some(v) = ip::parse_ipv4(pkt) {
                if ip::is_blocked_dst(v.dst) {
                    eprintln!(
                        "[exit] F2: заблокирован inner-dst {}.{}.{}.{}",
                        v.dst[0], v.dst[1], v.dst[2], v.dst[3]
                    );
                    return false;
                }
            }
        }
        if let Some(b) = self.bucket.as_mut() {
            if !b.allow(TokenBucket::packet_cost(pkt.len()), Instant::now()) {
                self.dropped += 1;
                self.dropped_bytes += pkt.len() as u64;
                if self.dropped == 1 || self.dropped.is_multiple_of(50) {
                    eprintln!(
                        "[exit] F7: rate-limit — дропнуто {} пакетов / {} б (клиент превысил лимит)",
                        self.dropped, self.dropped_bytes
                    );
                }
                return false;
            }
        }
        true
    }
}

/// Двунаправленная перекачка TUN ⇄ транспорт (QUIC DATAGRAM либо obfs-TCP record).
/// `egress_filter` (на exit) дропает inner-пакеты во внутренние/служебные сети (F2).
/// `rate_limit` (на exit) ограничивает входящее от клиента направление token-bucket'ом
/// (F7 / D3); `None` → без лимита.
///
/// TUN читается/пишется через `TunIo` — блокирующие recv/send изолированы в отдельных
/// потоках и мостятся в async каналами (платформа туннеля движку не важна).
pub async fn pump(
    tunnel: Tunnel,
    tun: Arc<dyn TunIo>,
    egress_filter: bool,
    rate_limit: Option<RateCfg>,
) -> Result<()> {
    use tokio::sync::mpsc;
    let (tun_to_net_tx, mut tun_to_net_rx) = mpsc::channel::<Vec<u8>>(1024);
    let (net_to_tun_tx, mut net_to_tun_rx) = mpsc::channel::<Vec<u8>>(1024);

    // TUN → сеть (блокирующее чтение TUN в отдельном потоке)
    {
        let tun = tun.clone();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            loop {
                match tun.recv(&mut buf) {
                    Ok(n) if n > 0 => {
                        if tun_to_net_tx.blocking_send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });
    }
    // сеть → TUN
    {
        let tun = tun.clone();
        std::thread::spawn(move || {
            while let Some(pkt) = net_to_tun_rx.blocking_recv() {
                let _ = tun.send(&pkt);
            }
        });
    }

    match tunnel {
        Tunnel::Quic(conn) => {
            let send_conn = conn.clone();
            let sender = tokio::spawn(async move {
                while let Some(pkt) = tun_to_net_rx.recv().await {
                    let dg = datagram::encode(datagram::CTX_RAW_IP, &pkt);
                    if let Err(e) = send_conn.send_datagram(bytes::Bytes::from(dg)) {
                        eprintln!("[pump] датаграмма отброшена ({} б): {e}", pkt.len());
                    }
                }
            });
            let recv_conn = conn.clone();
            let receiver = tokio::spawn(async move {
                let mut inb = Inbound::new(egress_filter, rate_limit);
                loop {
                    match recv_conn.read_datagram().await {
                        Ok(dg) => {
                            if let Some((datagram::CTX_RAW_IP, pkt)) = datagram::decode(&dg) {
                                if inb.accept(pkt) && net_to_tun_tx.send(pkt.to_vec()).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("[pump] соединение закрыто: {e}");
                            break;
                        }
                    }
                }
            });
            let _ = tokio::try_join!(sender, receiver);
        }
        Tunnel::Tcp(tcp) => {
            let (mut tx, mut rx) = tcp.into_split();
            let sender = tokio::spawn(async move {
                while let Some(pkt) = tun_to_net_rx.recv().await {
                    if let Err(e) = tx.send_packet(&pkt).await {
                        eprintln!("[pump:tcp] отправка не удалась ({} б): {e}", pkt.len());
                        break;
                    }
                }
            });
            let receiver = tokio::spawn(async move {
                let mut inb = Inbound::new(egress_filter, rate_limit);
                loop {
                    match rx.recv_packet().await {
                        Ok(pkt) => {
                            if inb.accept(&pkt) && net_to_tun_tx.send(pkt).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            eprintln!("[pump:tcp] соединение закрыто: {e}");
                            break;
                        }
                    }
                }
            });
            let _ = tokio::try_join!(sender, receiver);
        }
    }
    Ok(())
}
