//! obfs-over-TCP: транспорт-fallback, когда UDP/QUIC заблокирован (SPEC M4, подход 1).
//!
//! Тот же L1 obfs (probe-resistance по PSK), но датаграммы фреймятся в TCP-потоке:
//! ```text
//!   len(2 BE) ‖ obfs_seal(psk, sid, pid, nonce, payload)
//! ```
//! `seal`/`open` переиспользуются как есть (AEAD-гейт = probe-resistance): невалидный record
//! (чужой/нет PSK) → `open` падает → соединение молча рвётся, пробер не получает отличимого.
//!
//! Фазовый протокол на одном соединении: сначала control-обмен (токен → ADDRESS, по одному
//! record в каждую сторону), затем datagram-фаза (IP-пакеты как records) после `into_split`.
//!
//! **Ограничения (future):** на проводе — random-поток на :443 (не TLS-вид), поэтому против
//! цензора, валидирующего TLS на 443, слабее TLS-mimicry; probe-resistance — молчаливый разрыв
//! (не «как реальный сервис»); size-padding в TCP пока нет. Всё это — следующий слой (Reality).

use std::io;
use std::net::SocketAddr;

use anyhow::Result;
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

/// Потолок размера record на проводе (obfs-overhead + MTU с запасом). Анти-OOM при чтении len.
const MAX_RECORD: usize = 4096;

/// Записать один obfs-record: `len(2 BE) ‖ seal(payload)`.
pub async fn write_record<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    psk: &[u8; 32],
    sid: &[u8; 8],
    pid: u64,
    payload: &[u8],
) -> io::Result<()> {
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let sealed = citadel_obfs::seal(psk, sid, pid, &nonce, payload);
    let len = u16::try_from(sealed.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "record слишком большой"))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&sealed).await?;
    Ok(())
}

/// Прочитать один obfs-record и открыть его. AEAD-fail (мусор/проба/чужой PSK) → `InvalidData`.
pub async fn read_record<R: AsyncReadExt + Unpin>(
    r: &mut R,
    psk: &[u8; 32],
) -> io::Result<citadel_obfs::Opened> {
    let mut lenb = [0u8; 2];
    r.read_exact(&mut lenb).await?;
    let len = u16::from_be_bytes(lenb) as usize;
    if !(citadel_obfs::HDR_LEN + citadel_obfs::TAG_LEN..=MAX_RECORD).contains(&len) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "плохая длина record"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    citadel_obfs::open(psk, &buf)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "obfs open провалился (проба?)"))
}

/// obfs-over-TCP соединение (после connect/accept). Per-connection: случайный `sid` + счётчик pid.
pub struct TcpObfs {
    stream: TcpStream,
    psk: [u8; 32],
    sid: [u8; 8],
    send_ctr: u64,
    peer: SocketAddr,
}

impl TcpObfs {
    /// Клиент: подключиться к exit:443 и завернуть в obfs-over-TCP.
    pub async fn connect(addr: SocketAddr, psk: [u8; 32]) -> Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        Self::wrap(stream, psk)
    }

    /// Сервер: обернуть принятое TCP-соединение.
    pub fn wrap(stream: TcpStream, psk: [u8; 32]) -> Result<Self> {
        let peer = stream.peer_addr()?;
        let mut sid = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut sid);
        Ok(Self { stream, psk, sid, send_ctr: 0, peer })
    }

    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    fn next_pid(&mut self) -> u64 {
        let p = self.send_ctr;
        self.send_ctr += 1;
        p
    }

    /// Control-фаза: отправить одно сообщение (на не-split потоке).
    pub async fn send_msg(&mut self, payload: &[u8]) -> io::Result<()> {
        let pid = self.next_pid();
        write_record(&mut self.stream, &self.psk, &self.sid, pid, payload).await
    }

    /// Control-фаза: принять одно сообщение.
    pub async fn recv_msg(&mut self) -> io::Result<Vec<u8>> {
        Ok(read_record(&mut self.stream, &self.psk).await?.inner)
    }

    /// Перейти в datagram-фазу: разделить на отправляющую и принимающую половины (для `pump`).
    pub fn into_split(self) -> (TcpObfsTx, TcpObfsRx) {
        let (rd, wr) = self.stream.into_split();
        (
            TcpObfsTx { wr, psk: self.psk, sid: self.sid, send_ctr: self.send_ctr },
            TcpObfsRx { rd, psk: self.psk },
        )
    }
}

/// Отправляющая половина datagram-фазы (владеет write-half + счётчиком pid).
pub struct TcpObfsTx {
    wr: OwnedWriteHalf,
    psk: [u8; 32],
    sid: [u8; 8],
    send_ctr: u64,
}

impl TcpObfsTx {
    pub async fn send_packet(&mut self, pkt: &[u8]) -> io::Result<()> {
        let pid = self.send_ctr;
        self.send_ctr += 1;
        write_record(&mut self.wr, &self.psk, &self.sid, pid, pkt).await
    }
}

/// Принимающая половина datagram-фазы.
pub struct TcpObfsRx {
    rd: OwnedReadHalf,
    psk: [u8; 32],
}

impl TcpObfsRx {
    pub async fn recv_packet(&mut self) -> io::Result<Vec<u8>> {
        Ok(read_record(&mut self.rd, &self.psk).await?.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn psk() -> [u8; 32] {
        [0x42; 32]
    }
    const SID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    #[tokio::test]
    async fn record_roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(8192);
        let payload = b"hello-over-tcp";
        write_record(&mut a, &psk(), &SID, 0, payload).await.unwrap();
        let o = read_record(&mut b, &psk()).await.unwrap();
        assert_eq!(o.inner, payload);
        assert_eq!(o.sid, SID);
        assert_eq!(o.packet_id, 0);
    }

    #[tokio::test]
    async fn multiple_records_framed_in_stream() {
        let (mut a, mut b) = tokio::io::duplex(16384);
        for i in 0..5u64 {
            let p = vec![i as u8; (i as usize + 1) * 10];
            write_record(&mut a, &psk(), &SID, i, &p).await.unwrap();
        }
        for i in 0..5u64 {
            let o = read_record(&mut b, &psk()).await.unwrap();
            assert_eq!(o.inner, vec![i as u8; (i as usize + 1) * 10]);
            assert_eq!(o.packet_id, i);
        }
    }

    #[tokio::test]
    async fn wrong_psk_fails_probe_resistance() {
        let (mut a, mut b) = tokio::io::duplex(8192);
        write_record(&mut a, &psk(), &SID, 0, b"secret").await.unwrap();
        // чужой PSK → open падает → пробер ничего отличимого не получает
        assert!(read_record(&mut b, &[0xFFu8; 32]).await.is_err());
    }

    /// Реальный TCP loopback: connect/wrap → control send/recv → into_split → datagram-фаза.
    #[tokio::test]
    async fn tcp_loopback_control_then_datagrams() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let srv = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut s = TcpObfs::wrap(stream, psk()).unwrap();
            // control: принять запрос, ответить
            let req = s.recv_msg().await.unwrap();
            assert_eq!(req, b"REQUEST");
            s.send_msg(b"ASSIGN").await.unwrap();
            // datagram-фаза
            let (mut _tx, mut rx) = s.into_split();
            let pkt = rx.recv_packet().await.unwrap();
            assert_eq!(pkt, b"ip-packet-1");
        });

        let mut c = TcpObfs::connect(addr, psk()).await.unwrap();
        c.send_msg(b"REQUEST").await.unwrap();
        assert_eq!(c.recv_msg().await.unwrap(), b"ASSIGN");
        let (mut tx, mut _rx) = c.into_split();
        tx.send_packet(b"ip-packet-1").await.unwrap();
        srv.await.unwrap();
    }

    /// robustness/fuzz (M6): read_record не паникует на произвольном «потоке» (len-framing + open).
    #[tokio::test]
    async fn fuzz_read_record_no_panic() {
        let mut s = 0xc0ff_ee00_1234_5678u64;
        let xs = |seed: &mut u64| {
            let mut x = *seed;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *seed = x;
            x
        };
        for _ in 0..5_000 {
            let len = (xs(&mut s) % 600) as usize;
            let data: Vec<u8> = (0..len).map(|_| (xs(&mut s) >> 33) as u8).collect();
            let (mut a, mut b) = tokio::io::duplex(2048);
            let _ = a.write_all(&data).await;
            drop(a); // EOF — read_record получит обрезанный/мусорный кадр
            let _ = read_record(&mut b, &psk()).await; // Err, не паника
        }
    }
}
