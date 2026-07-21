//! S0.3/H1 — obfs-over-TCP как `AsyncUdpSocket`: тот же quinn (TLS 1.3 + X25519MLKEM768 +
//! pin + ML-DSA + токены + MASQUE) крутится поверх TCP, когда UDP/QUIC заблокирован.
//!
//! **Зачем.** Раньше TCP-fallback (`tcp_obfs::TcpObfs`) нёс «голый» control/datagram-протокол
//! напрямую под общим статическим PSK — без TLS, без гибридного PQ-KEX, без forward secrecy.
//! Срабатывало это ровно в цензуре (UDP заблокирован), т.е. самым уязвимым пользователям
//! доставалась самая слабая крипта. Теперь TCP — просто транспорт для настоящего QUIC: вся
//! защита L2 (PFS + PQ + серверная аутентификация pin/ML-DSA) сохраняется и в fallback.
//!
//! **Как.** Каждая QUIC-датаграмма ⇄ один obfs-record (`len(2 BE) ‖ obfs_seal`, реюз
//! `tcp_obfs::{read_record,write_record}` — формат L1 не меняется). Фоновые reader/writer-
//! задачи мостят TCP-поток в tokio-каналы; `poll_recv` делегирует в `mpsc::Receiver::poll_recv`
//! (интеграция с waker бесплатно). Адресация: одно TCP-соединение = один пир (на сервере —
//! отдельный quinn-Endpoint на каждый accept'нутый стрим). Meltdown TCP-in-TCP — принятая
//! деградация fallback (безопасность важнее скорости в цензуре).

use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use anyhow::{anyhow, Result};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rand::RngCore;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::tcp_obfs::{read_record, write_record};

/// Потолки очередей (переполнение → дроп датаграммы = как потеря UDP, QUIC ретрансмитит).
const SEND_CAP: usize = 1024;
const RECV_CAP: usize = 1024;

/// `AsyncUdpSocket` поверх одного obfs-TCP соединения (point-to-point, один пир).
struct ObfsTcpSocket {
    send_tx: mpsc::Sender<Vec<u8>>,
    recv_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    local: SocketAddr,
    peer: SocketAddr,
}

impl std::fmt::Debug for ObfsTcpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ObfsTcpSocket({} → {})", self.local, self.peer)
    }
}

impl ObfsTcpSocket {
    /// Обернуть установленный TCP-поток: split на half'ы + reader/writer-задачи.
    fn new(stream: TcpStream, psk: [u8; 32]) -> io::Result<Self> {
        let local = stream.local_addr()?;
        let peer = stream.peer_addr()?;
        let (mut rd, mut wr) = stream.into_split();

        // reader: TCP-record'ы → канал приёма. Битый record (проба/чужой PSK) / EOF → задача
        // завершается, канал закрывается → poll_recv вернёт ошибку → quinn закроет соединение.
        let (recv_tx, recv_rx) = mpsc::channel::<Vec<u8>>(RECV_CAP);
        tokio::spawn(async move {
            // Err (EOF / битый record — проба/чужой PSK) завершает цикл → канал закрывается.
            while let Ok(opened) = read_record(&mut rd, &psk).await {
                if recv_tx.send(opened.inner).await.is_err() {
                    break; // сокет дропнут (poll_recv больше не читает)
                }
            }
        });

        // writer: канал отправки → TCP-record'ы. Случайный per-session `sid` (16 байт, obfs v2 —
        // 128-битная per-session соль в k_sess, закрывает body-AEAD nonce-reuse под общим PSK);
        // старт `packet_id` со случайного u64 (доп. запас).
        let (send_tx, mut send_rx) = mpsc::channel::<Vec<u8>>(SEND_CAP);
        let mut sid = [0u8; citadel_obfs::SID_LEN];
        rand::thread_rng().fill_bytes(&mut sid);
        let mut pid: u64 = rand::random();
        tokio::spawn(async move {
            while let Some(dg) = send_rx.recv().await {
                if write_record(&mut wr, &psk, &sid, pid, &dg).await.is_err() {
                    break;
                }
                pid = pid.wrapping_add(1);
            }
        });

        Ok(Self { send_tx, recv_rx: Mutex::new(recv_rx), local, peer })
    }
}

/// Всегда-готовый writer-poller: отправка идёт через bounded-канал (переполнение = дроп),
/// backpressure не нужен — QUIC сам ретрансмитит потерянное.
#[derive(Debug)]
struct TcpPoller;

impl UdpPoller for TcpPoller {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for ObfsTcpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(TcpPoller)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // max_transmit_segments()==1 → одна датаграмма. Переполнение канала → дроп (потеря UDP).
        let _ = self.send_tx.try_send(transmit.contents.to_vec());
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut rx = self.recv_rx.lock().unwrap();
        match rx.poll_recv(cx) {
            Poll::Ready(Some(dg)) => {
                let n = dg.len().min(bufs[0].len());
                bufs[0][..n].copy_from_slice(&dg[..n]);
                meta[0] = RecvMeta { addr: self.peer, len: n, stride: n, ecn: None, dst_ip: None };
                Poll::Ready(Ok(1))
            }
            // reader-задача завершилась (EOF/битый record) → транспорт мёртв.
            Poll::Ready(None) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, "obfs-TCP закрыт")))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
    fn max_transmit_segments(&self) -> usize {
        1
    }
    fn max_receive_segments(&self) -> usize {
        1
    }
    fn may_fragment(&self) -> bool {
        false
    }
}

fn endpoint_over(
    stream: TcpStream,
    server_config: Option<quinn::ServerConfig>,
    psk: [u8; 32],
) -> Result<quinn::Endpoint> {
    let socket: Arc<dyn AsyncUdpSocket> = Arc::new(ObfsTcpSocket::new(stream, psk)?);
    let runtime = quinn::default_runtime().ok_or_else(|| anyhow!("нет async runtime (tokio)"))?;
    let ep = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        server_config,
        socket,
        runtime,
    )?;
    Ok(ep)
}

/// Клиент: quinn-Endpoint поверх установленного obfs-TCP соединения к exit. Вызывающий делает
/// `ep.connect_with(pinned_cfg, peer_addr, server_name)` — обычный PQ-QUIC хендшейк, просто по TCP.
pub fn client_endpoint_obfs_tcp(stream: TcpStream, psk: [u8; 32]) -> Result<quinn::Endpoint> {
    endpoint_over(stream, None, psk)
}

/// Сервер: quinn-Endpoint поверх ОДНОГО accept'нутого obfs-TCP стрима (single-conn). Вызывающий
/// делает `ep.accept()` ровно один раз. `server_config` — тот же серт/pin/KX, что у UDP-endpoint.
pub fn server_endpoint_obfs_tcp(
    stream: TcpStream,
    server_config: quinn::ServerConfig,
    psk: [u8; 32],
) -> Result<quinn::Endpoint> {
    endpoint_over(stream, Some(server_config), psk)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ключевая валидация S0.3: настоящий PQ-QUIC хендшейк (TLS 1.3 + X25519MLKEM768) + обмен
    /// датаграммой ПОВЕРХ obfs-TCP на loopback. Если зелёный — подход «QUIC над TCP» рабочий,
    /// и вся клиент/серверная обвязка — механика.
    #[tokio::test]
    async fn quic_handshake_and_datagram_over_obfs_tcp() {
        let psk = [0x5au8; 32];
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let srv = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let scfg = crate::server_config(crate::kx_groups_for("pq")).unwrap();
            let ep = server_endpoint_obfs_tcp(stream, scfg, psk).unwrap();
            let conn = ep.accept().await.unwrap().await.unwrap();
            let dg = conn.read_datagram().await.unwrap();
            conn.send_datagram(dg).unwrap(); // эхо
            // держим ep+conn живыми, пока клиент читает эхо
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let ep = client_endpoint_obfs_tcp(stream, psk).unwrap();
        let ccfg = crate::client_config(crate::kx_groups_for("pq")).unwrap();
        let conn = ep.connect_with(ccfg, addr, "Citadel.exit").unwrap().await.unwrap();
        conn.send_datagram(bytes::Bytes::from_static(b"hello-pq-over-tcp")).unwrap();
        let echo = conn.read_datagram().await.unwrap();
        assert_eq!(&echo[..], b"hello-pq-over-tcp");
        srv.await.unwrap();
    }
}
