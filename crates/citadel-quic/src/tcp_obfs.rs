//! obfs record-фрейминг для TCP: примитивы `write_record`/`read_record`.
//!
//! Кадр на проводе: `len(2 BE) ‖ obfs_seal(psk, sid, pid, nonce, payload)`. `seal`/`open`
//! переиспользуются как есть (AEAD-гейт = probe-resistance): невалидный record (чужой/нет PSK)
//! → `open` падает → соединение рвётся, пробер не получает отличимого.
//!
//! S0.3/H1: эти record'ы несут датаграммы НАСТОЯЩЕГО QUIC (см. [`crate::obfs_tcp`]), когда
//! UDP/QUIC заблокирован. Раньше здесь был ещё и «голый» control/datagram-протокол под общим
//! PSK (без TLS/PFS/PQ) — удалён: TCP-fallback теперь = PQ-QUIC поверх этих record'ов.

use std::io;

use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Потолок размера record на проводе (obfs-overhead + MTU с запасом). Анти-OOM при чтении len.
/// 8192 — чтобы control-ответ с ML-DSA-65 pub(1952)+sig(3309) (commitment-fetch, §S3, ~5.3 КБ)
/// уместился в один record (data-plane record'ы — в пределах MTU, много меньше).
const MAX_RECORD: usize = 8192;

/// Записать один obfs-record: `len(2 BE) ‖ seal(payload)`.
pub async fn write_record<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    psk: &[u8; 32],
    sid: &[u8; citadel_obfs::SID_LEN],
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

/// Прочитать байты одного record (без открытия). Отдельно от `open`, чтобы приёмник мог
/// попробовать НЕСКОЛЬКО ключей (H-3: exit принимает ключи текущей и прошлой эпохи).
pub async fn read_record_bytes<R: AsyncReadExt + Unpin>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut lenb = [0u8; 2];
    r.read_exact(&mut lenb).await?;
    let len = u16::from_be_bytes(lenb) as usize;
    if !(citadel_obfs::HDR_LEN + citadel_obfs::TAG_LEN..=MAX_RECORD).contains(&len) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "плохая длина record"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Прочитать один obfs-record и открыть его. AEAD-fail (мусор/проба/чужой PSK) → `InvalidData`.
pub async fn read_record<R: AsyncReadExt + Unpin>(
    r: &mut R,
    psk: &[u8; 32],
) -> io::Result<citadel_obfs::Opened> {
    let buf = read_record_bytes(r).await?;
    citadel_obfs::open(psk, &buf)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "obfs open провалился (проба?)"))
}

/// H-3: открыть record ЛЮБЫМ из ключей (порядок = приоритет проб) и сказать, какой подошёл.
/// Дальше соединение фиксируется на этом ключе: TCP-поток — один пир, перебирать на каждом
/// record'е незачем (и это была бы лишняя работа на пакет под флудом).
pub fn open_any(keys: &[[u8; 32]], buf: &[u8]) -> Option<(citadel_obfs::Opened, [u8; 32])> {
    keys.iter().find_map(|k| citadel_obfs::open(k, buf).ok().map(|o| (o, *k)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn psk() -> [u8; 32] {
        [0x42; 32]
    }
    const SID: [u8; citadel_obfs::SID_LEN] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

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
