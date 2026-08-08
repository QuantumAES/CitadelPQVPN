//! S2.1/A1 (остаток) — obfs-обёртка канала к издателю: probe-resistance/анти-DPI для issuer-порта.
//!
//! Голый TLS 1.3 на публичном :7000 фингерпринтится цензором (единственная гибридная PQ-группа,
//! ALPN `citadel-issuer/1`, SNI `citadel.issuer` — нетипичный ClientHello). Основной туннель уже
//! завёрнут в obfs L1 (на проводе — псевдослучайный поток); здесь тем же слоем оборачиваем
//! TLS-байты issuer-канала, поэтому его трафик неотличим от туннельного (тот же `obfs_psk` из
//! ссылки) и порт молчит на не-obfs пробу.
//!
//! Слои: `TCP ── obfs-record (seal/open) ── TLS 1.3 (pin) ── кадры протокола`. Record на проводе —
//! `len(2 BE) ‖ seal(psk, sid, pid, nonce, inner)`, где `inner` — фрейм citadel-obfs
//! (`type ‖ pad_len ‖ padding ‖ payload`), тот же, что в UDP-пути (формат `crate::tcp_obfs` в
//! citadel-quic, но **синхронный**: issuer и `fetch_tokens` работают блокирующе поверх `std::net`).
//! AEAD-fail на приёме (мусор/чужой PSK/проба) → разрыв соединения, отличимого ответа пробер не
//! получает.
//!
//! **M-8/аудит-4: слом формата этого канала** — раньше внутри record'а лежал голый TLS-чанк без
//! паддинга, и длины на проводе повторяли длины TLS-записей. Клиент и издатель обновляются вместе.

use std::io::{self, Read, Write};
use std::net::TcpStream;

use rand::{Rng, RngCore};

use citadel_obfs::{build_chaff, build_inner, parse_inner, seal, HDR_LEN, TAG_LEN, TYPE_DATA};

/// Потолок obfs-record на проводе (как `tcp_obfs::MAX_RECORD`): вмещает крупнейший кадр канала
/// (hello издателя — ML-DSA-65 pub 1952 + sig 3309 ≈ 5,3 КБ) + overhead; анти-OOM при чтении длины.
const MAX_RECORD: usize = 8192;
/// Оверхед inner-фрейминга внутри record'а: `type(1) ‖ pad_len(2)` (M-8, см. ниже).
const INNER_OVERHEAD: usize = 3;
/// Максимум полезной нагрузки в одном record (TLS-запись рубим на чанки этого размера).
const MAX_PAYLOAD: usize = MAX_RECORD - HDR_LEN - TAG_LEN - INNER_OVERHEAD;

/// M-8/аудит-4: политика паддинга записей issuer-канала.
///
/// Раньше record был `len(2) ‖ seal(chunk)` с фиксированным оверхедом 54 байта и БЕЗ паддинга,
/// то есть длина каждого record'а равнялась длине TLS-записи под ним плюс константа. На проводе
/// это давало детерминированную последовательность длин: ClientHello (~1,2 КБ, гибридная группа) →
/// hello-кадр с ML-DSA (~5,3 КБ) → ровно N пар «запрос/ответ» по ~256 Б. Такой профиль опознаётся
/// вообще без знания PSK — то есть probe-resistance L1 на этом канале не работала против пассивного
/// наблюдателя, хотя ровно ради неё канал и заворачивали в obfs.
///
/// Теперь plaintext record'а — это `inner` формата citadel-obfs (`type ‖ pad_len ‖ padding ‖
/// payload`), а длина добивается СЛУЧАЙНО: `floor` прячет мелкие кадры, `jitter` размывает
/// крупные. Приёмник срезает паддинг `parse_inner`. Дополнительно поддержан `TYPE_PAD` — chaff-
/// record без полезной нагрузки: читатель пропускает его прозрачно, а на проводе он неотличим от
/// содержательного, поэтому сбивается и КОЛИЧЕСТВО записей, а не только их размеры.
///
/// MTU-инварианта (как у UDP-пути) здесь нет: это TCP-поток, крупный record просто разложится по
/// сегментам. Потолок — `MAX_RECORD`, чтобы приёмник не выделял больше своего лимита.
const PAD_FLOOR: usize = 256;
const PAD_JITTER: usize = 512;

/// Длина паддинга для полезной нагрузки `n` байт: считается ровно так же, как на UDP-пути
/// (`citadel_obfs::pad_len_random`), потому что `FRAMING_OVERHEAD` = `HDR_LEN + INNER_OVERHEAD +
/// TAG_LEN` — то есть размер именно этого record'а без паддинга.
fn pad_for(n: usize) -> usize {
    let r: usize = rand::thread_rng().gen_range(0..=PAD_JITTER);
    citadel_obfs::pad_len_random(PAD_FLOOR, PAD_JITTER, MAX_RECORD, n, r)
}

/// Синхронная obfs-обёртка над потоком `S` (`Read`+`Write`): каждая запись → один или несколько
/// obfs-record'ов, чтение собирает по одному record и отдаёт распакованный plaintext. Ставится
/// МЕЖДУ TCP и TLS (rustls `StreamOwned` дженерик по нижнему `Read`+`Write`).
pub struct ObfsStream<S> {
    inner: S,
    psk: [u8; 32],
    /// sid исходящего направления (случайный на соединение; демукс не нужен — канал point-to-point,
    /// `open` возвращает sid из record и его не сверяет). 16 байт (obfs v2).
    send_sid: [u8; citadel_obfs::SID_LEN],
    /// Счётчик packet_id исходящих record'ов (как send_ctr туннеля).
    send_pid: u64,
    /// Распакованный, ещё не отданный `read`'ом plaintext текущего record, и позиция в нём.
    rx: Vec<u8>,
    rx_pos: usize,
    /// M-8: chaff перед первой содержательной записью ещё не отправлен. Сбивает начало диалога —
    /// иначе первый record на проводе всегда TLS ClientHello известного размера.
    chaff_pending: bool,
}

impl<S: Read + Write> ObfsStream<S> {
    pub fn new(inner: S, psk: [u8; 32]) -> Self {
        let mut send_sid = [0u8; citadel_obfs::SID_LEN];
        rand::thread_rng().fill_bytes(&mut send_sid);
        Self {
            inner,
            psk,
            send_sid,
            send_pid: 0,
            rx: Vec::new(),
            rx_pos: 0,
            chaff_pending: true,
        }
    }

    /// Запечатать и отправить один record с готовым `inner` (см. `citadel_obfs::build_inner`).
    fn send_record(&mut self, inner: &[u8]) -> io::Result<()> {
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let sealed = seal(&self.psk, &self.send_sid, self.send_pid, &nonce, inner);
        self.send_pid += 1;
        let len = u16::try_from(sealed.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "record слишком большой"))?;
        self.inner.write_all(&len.to_be_bytes())?;
        self.inner.write_all(&sealed)
    }

    /// Прочитать и распаковать ОДИН obfs-record в `self.rx` (blocking). AEAD-fail → InvalidData.
    /// Паддинг и chaff (`TYPE_PAD`) срезаются здесь же: наверх уходит только полезная нагрузка
    /// (для chaff — пустая, и тогда `read` просто дочитает следующий record).
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
        let (_t, payload) = parse_inner(&opened.inner)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "битый inner obfs-record"))?;
        self.rx = payload.to_vec();
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
        // M-8: перед самой первой содержательной записью — chaff случайной длины. Он делает
        // непредсказуемым начало диалога (у TLS оно самое узнаваемое: ClientHello фиксированного
        // для нашей конфигурации размера), и стоит это ровно одного лишнего пакета за соединение.
        if self.chaff_pending {
            self.chaff_pending = false;
            self.send_record(&build_chaff(&vec![0u8; pad_for(0)]))?;
        }
        // Один record за вызов (rustls повторит с остатком): рубим TLS-запись по MAX_PAYLOAD.
        let n = buf.len().min(MAX_PAYLOAD);
        let padding = vec![0u8; pad_for(n)];
        self.send_record(&build_inner(TYPE_DATA, None, None, &padding, &buf[..n]))?;
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

    /// Приёмник, который ничего не отдаёт: нужен, чтобы посмотреть на БАЙТЫ, уходящие в сеть.
    struct Sink(Vec<u8>);
    impl Read for Sink {
        fn read(&mut self, _b: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }
    impl Write for Sink {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Разобрать провод на длины record'ов (`len(2 BE) ‖ sealed`).
    fn record_lens(wire: &[u8]) -> Vec<usize> {
        let (mut i, mut out) = (0usize, Vec::new());
        while i + 2 <= wire.len() {
            let len = u16::from_be_bytes([wire[i], wire[i + 1]]) as usize;
            out.push(len);
            i += 2 + len;
        }
        out
    }

    /// M-8: длина record'а больше НЕ равна «длина TLS-записи + константа».
    ///   * первая запись на проводе — chaff, а не полезная (начало диалога непредсказуемо);
    ///   * мелкие записи подняты до пола `PAD_FLOOR` (256) — по ним не видно, что кадр короткий;
    ///   * одна и та же полезная нагрузка даёт РАЗНЫЕ длины на проводе.
    #[test]
    fn records_are_padded_and_start_with_chaff() {
        let payload = b"issuer-frame-0123456789"; // 23 Б — было бы 77 Б на проводе без паддинга
        let mut sizes = std::collections::HashSet::new();
        for _ in 0..40 {
            let mut s = ObfsStream::new(Sink(Vec::new()), PSK);
            s.write_all(payload).unwrap();
            s.write_all(payload).unwrap();
            let lens = record_lens(&s.inner.0);
            assert_eq!(lens.len(), 3, "chaff + две полезные записи");
            for l in &lens {
                assert!(*l >= PAD_FLOOR - 2, "record {l} Б — короткая запись не скрыта");
                assert!(*l <= MAX_RECORD);
            }
            sizes.extend(lens);
        }
        assert!(sizes.len() > 20, "длины должны гулять, а не быть константой: {}", sizes.len());

        // …и при этом канал остаётся байт-прозрачным: приёмник срезает и chaff, и паддинг.
        let mut s = ObfsStream::new(Sink(Vec::new()), PSK);
        s.write_all(payload).unwrap();
        let mut r = ObfsStream::new(io::Cursor::new(std::mem::take(&mut s.inner.0)), PSK);
        let mut got = vec![0u8; payload.len()];
        r.read_exact(&mut got).unwrap();
        assert_eq!(got, payload);
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
