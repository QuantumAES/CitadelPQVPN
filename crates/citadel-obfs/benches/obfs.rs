//! Бенчмарки obfs L1 (M6): per-packet оверхед hot-path — KDF, seal/open, политика паддинга.
//! Запуск: `cargo bench -p citadel-obfs`.

use citadel_obfs::*;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

fn psk() -> [u8; 32] {
    [0x42; 32]
}
const SID: [u8; SID_LEN] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
const NONCE: [u8; 12] = [7; 12];

fn bench_kdf(c: &mut Criterion) {
    let psk = psk();
    c.bench_function("kdf/k_hdr", |b| b.iter(|| k_hdr(black_box(&psk))));
    c.bench_function("kdf/k_sess", |b| b.iter(|| k_sess(black_box(&psk), black_box(&SID))));
}

fn bench_seal_open(c: &mut Criterion) {
    let psk = psk();
    let mut g = c.benchmark_group("obfs");
    // типичные размеры quic-нагрузки: ACK (мелкий) … почти-MTU
    for size in [64usize, 256, 512, 1024, 1232] {
        let quic = vec![0xab_u8; size];
        let inner = build_inner(TYPE_DATA, None, None, &[], &quic);
        let pkt = seal(&psk, &SID, 0, &NONCE, &inner);
        g.throughput(Throughput::Bytes(size as u64));
        // stateless — пере-derive KDF + AEAD-init на КАЖДЫЙ вызов
        g.bench_with_input(BenchmarkId::new("seal", size), &inner, |b, inner| {
            b.iter(|| seal(black_box(&psk), &SID, 0, &NONCE, black_box(inner)))
        });
        g.bench_with_input(BenchmarkId::new("open", size), &pkt, |b, pkt| {
            b.iter(|| open(black_box(&psk), black_box(pkt)))
        });
        // cached — Sealer/Opener деривят ключи/cipher один раз (hot-path)
        let sealer = Sealer::new(&psk, &SID);
        g.bench_with_input(BenchmarkId::new("seal_cached", size), &inner, |b, inner| {
            b.iter(|| sealer.seal(0, &NONCE, black_box(inner)))
        });
        let mut opener = Opener::new(&psk);
        let _ = opener.open(&pkt); // прогрев кеша
        g.bench_with_input(BenchmarkId::new("open_cached", size), &pkt, |b, pkt| {
            b.iter(|| opener.open(black_box(pkt)))
        });
    }
    g.finish();
}

fn bench_padding(c: &mut Criterion) {
    let p = Padding::Bucket(DEFAULT_BUCKETS);
    c.bench_function("padding/pad_len_for", |b| {
        b.iter(|| pad_len_for(black_box(p), black_box(700)))
    });
}

criterion_group!(benches, bench_kdf, bench_seal_open, bench_padding);
criterion_main!(benches);
