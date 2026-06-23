//! Бенчмарки анонимных токенов (M6): стоимость blind-RSA операций issuance/verify (control-path).
//! RSA-2048 медленный → малый sample_size. Запуск: `cargo bench -p citadel-token`.

use citadel_token::*;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_token(c: &mut Criterion) {
    let (pk, sk) = issuer_keypair(2048).unwrap();
    let (blind_msg, st) = client_blind(&pk).unwrap();
    let blind_sig = issuer_blind_sign(&sk, &blind_msg).unwrap();
    let token = client_finalize(&pk, &blind_sig, &st).unwrap();

    let mut g = c.benchmark_group("token");
    g.sample_size(20); // RSA-2048 медленный — иначе бенч идёт минуты
    g.bench_function("client_blind", |b| b.iter(|| client_blind(black_box(&pk))));
    g.bench_function("issuer_blind_sign", |b| {
        b.iter(|| issuer_blind_sign(black_box(&sk), black_box(&blind_msg)))
    });
    g.bench_function("client_finalize", |b| {
        b.iter(|| client_finalize(black_box(&pk), black_box(&blind_sig), black_box(&st)))
    });
    g.bench_function("verify_token", |b| {
        b.iter(|| verify_token(black_box(&pk), black_box(&token)))
    });
    g.finish();
}

criterion_group!(benches, bench_token);
criterion_main!(benches);
