//! Бенчмарки анонимных токенов Layer-2 (M6/M-6): стоимость операций issuance/verify на
//! control-path. Схема v2 — VOPRF над ristretto255; каждая операция это 1–2 скалярных умножения,
//! то есть десятки микросекунд вместо миллисекунд blind-RSA (и генерация ключа эпохи —
//! микросекунды вместо ~10 с RSA-keygen, что и делало ротацию эпох заметной операцией).
//!
//! Запуск: `cargo bench -p citadel-token`.

use citadel_token::*;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_token(c: &mut Criterion) {
    let key = EpochKey::generate().unwrap();
    let public = key.public_bytes();
    let st = BlindState::new().unwrap();
    let blinded = st.blinded_element();
    let (evaluated, proof) = key.evaluate(&blinded).unwrap();
    let token = BlindState::new()
        .and_then(|s| {
            let (e, p) = key.evaluate(&s.blinded_element())?;
            s.finalize(&public, &e, &p)
        })
        .unwrap();
    // Контекст предъявления — как в реальном обмене (TLS-exporter сессии).
    let ctx = redeem_context(&[0x22u8; 32]);
    let redeem = token.redeem(&ctx);

    let mut g = c.benchmark_group("token");
    g.bench_function("epoch_keygen", |b| b.iter(EpochKey::generate));
    g.bench_function("client_blind", |b| b.iter(BlindState::new));
    g.bench_function("issuer_evaluate", |b| b.iter(|| key.evaluate(black_box(&blinded))));
    // finalize потребляет своё состояние ослепления и обязан получить ответ ИМЕННО на него
    // (иначе меряли бы отказ DLEQ), поэтому меряем всю выдачу целиком — это и есть то, что
    // клиент платит за один токен.
    g.bench_function("issuance_roundtrip", |b| {
        b.iter(|| {
            let s = BlindState::new().unwrap();
            let (e, p) = key.evaluate(&s.blinded_element()).unwrap();
            s.finalize(black_box(&public), &e, &p).unwrap()
        })
    });
    let _ = (&evaluated, &proof);
    g.bench_function("token_redeem", |b| b.iter(|| token.redeem(black_box(&ctx))));
    g.bench_function("verify_redemption", |b| {
        b.iter(|| key.verify_redemption(black_box(&redeem), black_box(&ctx)))
    });
    g.finish();
}

criterion_group!(benches, bench_token);
criterion_main!(benches);
