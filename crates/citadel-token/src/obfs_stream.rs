//! S2.1/A1 (остаток) — obfs-обёртка канала к издателю: probe-resistance/анти-DPI для issuer-порта.
//!
//! Голый TLS 1.3 на публичном :7000 фингерпринтится цензором (единственная гибридная PQ-группа,
//! ALPN `citadel-issuer/1`, SNI `citadel.issuer` — нетипичный ClientHello). Основной туннель уже
//! завёрнут в obfs L1 (на проводе — псевдослучайный поток); здесь тем же слоем оборачиваем
//! TLS-байты issuer-канала, поэтому его трафик неотличим от туннельного (тот же `obfs_psk` из
//! ссылки) и порт молчит на не-obfs пробу.
//!
//! Слои: `TCP ── obfs-record (seal/open) ── TLS 1.3 (pin) ── кадры протокола`. Record на проводе —
//! `len(2 BE) ‖ seal(psk, sid, pid, nonce, chunk)` (формат `crate::tcp_obfs` в citadel-quic, но
//! **синхронный**: issuer и `fetch_tokens` работают блокирующе поверх `std::net`). AEAD-fail на
//! приёме (мусор/чужой PSK/проба) → разрыв соединения, отличимого ответа пробер не получает.

use std::io::{self, Read, Write};
use std::net::TcpStream;

use rand::RngCore;

use citadel_obfs::{seal, HDR_LEN, TAG_LEN};

/// Потолок obfs-record на проводе (как `tcp_obfs::MAX_RECORD`): вмещает крупнейший кадр канала
/// (issuer_pub RSA / ML-DSA нет — тут кадры мелкие) + overhead; анти-OOM при чтении длины.
const MAX_RECORD: usize = 8192;
/// Максимум полезной нагрузки в одном record (TLS-запись рубим на чанки этого размера).
const MAX_PAYLOAD: usize = MAX_RECORD - HDR_LEN - TAG_LEN;

/// Синхронная obfs-обёртка над потоком `S` (`Read`+`Write`): каждая запись → один или несколько
/// obfs-record'ов, чтение собирает по одному record и отдаёт распакованный plaintext. Ставится
/// МЕЖДУ TCP и TLS (rustls `StreamOwned` дженерик по нижнему `Read`+`Write`).
pub struct ObfsStream<S> {
    inner: S,
    psk: [u8; 32],
    /// sid исходящего направления (случайный на соединение; демукс не нужен — канал point-to-point,
    /// `open` возвращает sid из record и его не сверяет).
    send_sid: [u8; 8],
    /// Счётчик packet_id исходящих record'ов (как send_ctr туннеля).
    send_pid: u64,
    /// Распакованный, ещё не отданный `read`'ом plaintext текущего record, и позиция в нём.
    rx: Vec<u8>,
    rx_pos: usize,
}

impl<S: Read + Write> ObfsStream<S> {
    pub fn new(inner: S, psk: [u8; 32]) -> Self {
        let mut send_sid = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut send_sid);
        Self { inner, psk, send_sid, send_pid: 0, rx: Vec::new(), rx_pos: 0 }
    }

    /// Прочитать и распаковать ОДИН obfs-record в `self.rx` (blocking). AEAD-fail → InvalidData.
    fn fill(&mut self) -> io::Result<()> {
        let mut lenb = [0u8; 2];
        self.inner.read_exact(&mut lenb)?;
        let len = u16::from_be_bytes(lenb) as usize;
        if !(HDR_LEN + TAG_LEN..=MAX_RECORD).contains(&len) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "плохая длина obfs-record"));
        }
        let mut buf = vec![0u8; len];
        self.inner.read_exact(&mut buf)?;
        let opened = citadel_obfs::open(&self.psk, &buf)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "obfs open провалился (проба?)"))?;
        self.rx = opened.inner;
        self.rx_pos = 0;
        Ok(())
    }
}

impl<S: Read + Write> Read for ObfsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Дочитываем record'ы, пока не наберётся непустой plaintext (пустых не шлём, но устойчиво).
        while self.rx_pos >= self.rx.len() {
            self.fill()?;
        }
        let n = (self.rx.len() - self.rx_pos).min(buf.len());
        buf[..n].copy_from_slice(&self.rx[self.rx_pos..self.rx_pos + n]);
        self.rx_pos += n;
        Ok(n)
    }
}

impl<S: Read + Write> Write for ObfsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // Один record за вызов (rustls повторит с остатком): рубим TLS-запись по MAX_PAYLOAD.
        let n = buf.len().min(MAX_PAYLOAD);
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let sealed = seal(&self.psk, &self.send_sid, self.send_pid, &nonce, &buf[..n]);
        self.send_pid += 1;
        let len = u16::try_from(sealed.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "record слишком большой"))?;
        self.inner.write_all(&len.to_be_bytes())?;
        self.inner.write_all(&sealed)?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Нижний транспорт issuer-канала: голый TCP (obfs_psk не задан) ИЛИ obfs поверх TCP. Прячет выбор
/// за одним типом, чтобы alias'ы TLS-потока (`IssuerTlsStream`/`ClientTlsStream`) и весь downstream
/// (admin `serve_conn`/EKM/`AdminClient`) не зависели от того, обёрнут канал или нет.
pub enum ObfsMaybe {
    Plain(TcpStream),
    Obfs(ObfsStream<TcpStream>),
}

impl ObfsMaybe {
    /// Обернуть TCP: `Some(psk)` → obfs-слой (probe-resistant), `None` → голый TLS (как раньше).
    /// Обе стороны должны совпадать по наличию psk — иначе `open` первого record падает (fail-closed).
    pub fn wrap(tcp: TcpStream, obfs_psk: Option<[u8; 32]>) -> Self {
        match obfs_psk {
            Some(psk) => ObfsMaybe::Obfs(ObfsStream::new(tcp, psk)),
            None => ObfsMaybe::Plain(tcp),
        }
    }
}

impl Read for ObfsMaybe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ObfsMaybe::Plain(s) => s.read(buf),
            ObfsMaybe::Obfs(s) => s.read(buf),
        }
    }
}

impl Write for ObfsMaybe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            ObfsMaybe::Plain(s) => s.write(buf),
            ObfsMaybe::Obfs(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            ObfsMaybe::Plain(s) => s.flush(),
            ObfsMaybe::Obfs(s) => s.flush(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PSK: [u8; 32] = [0x42; 32];

    /// Дуплекс поверх socketpair-подобной пары: obfs-обёртка сохраняет байты в обе стороны, чанкует
    /// крупную запись по нескольким record'ам и собирает обратно (record-framing консистентен).
    #[test]
    fn obfs_stream_roundtrip_and_chunking() {
        use std::net::{TcpListener, TcpStream};
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let big: Vec<u8> = (0..(MAX_PAYLOAD * 2 + 123)).map(|i| (i * 7) as u8).collect();
        let big_srv = big.clone();
        let srv = std::thread::spawn(move || {
            let (tcp, _) = l.accept().unwrap();
            let mut s = ObfsStream::new(tcp, PSK);
            // эхо: прочитать ровно big.len() байт (через несколько record'ов) и отправить назад
            let mut got = vec![0u8; big_srv.len()];
            s.read_exact(&mut got).unwrap();
            assert_eq!(got, big_srv);
            s.write_all(&got).unwrap();
            s.flush().unwrap();
        });
        let tcp = TcpStream::connect(addr).unwrap();
        let mut c = ObfsStream::new(tcp, PSK);
        c.write_all(&big).unwrap();
        c.flush().unwrap();
        let mut back = vec![0u8; big.len()];
        c.read_exact(&mut back).unwrap();
        assert_eq!(back, big);
        srv.join().unwrap();
    }

    /// Чужой PSK на приёме → `open` падает → чтение рвётся (probe-resistance: не отдаём отличимого).
    #[test]
    fn wrong_psk_breaks_read() {
        use std::net::{TcpListener, TcpStream};
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let srv = std::thread::spawn(move || {
            let (tcp, _) = l.accept().unwrap();
            let mut s = ObfsStream::new(tcp, PSK);
            let _ = s.write_all(b"secret-frame");
            let _ = s.flush();
        });
        let tcp = TcpStream::connect(addr).unwrap();
        let mut c = ObfsStream::new(tcp, [0xFFu8; 32]); // не тот psk
        let mut buf = [0u8; 32];
        assert!(c.read(&mut buf).is_err(), "чужой psk → open fail → разрыв");
        srv.join().unwrap();
    }
}
