//! Бенчмарки data-plane парсеров (M6): hot-path разбор на каждый пакет туннеля.
//! Запуск: `cargo bench -p citadel-masque`.

use citadel_masque::*;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn ipv4_udp_pkt() -> Vec<u8> {
    // минимальный валидный IPv4 (ver=4, ihl=5, total_len=40, proto=UDP) + 20 байт UDP/payload
    let mut p = vec![0x45, 0x00, 0x00, 0x28, 0, 0, 0, 0, 64, 17, 0, 0, 10, 7, 0, 2, 1, 1, 1, 1];
    p.extend_from_slice(&[0u8; 20]);
    p
}

fn bench_parse(c: &mut Criterion) {
    let ip = ipv4_udp_pkt();
    c.bench_function("ip/parse_ipv4", |b| b.iter(|| ip::parse_ipv4(black_box(&ip))));

    let dg = datagram::encode(datagram::CTX_RAW_IP, &ip);
    c.bench_function("datagram/decode", |b| b.iter(|| datagram::decode(black_box(&dg))));

    let v = varint::to_vec(0x3fff_ffff);
    c.bench_function("varint/decode", |b| b.iter(|| varint::decode(black_box(&v))));

    let cap = capsule::encode_address_request_v4(&capsule::AssignedV4 {
        request_id: 1,
        addr: [0, 0, 0, 0],
        prefix: 0,
    });
    c.bench_function("capsule/decode", |b| b.iter(|| capsule::decode(black_box(&cap))));
}

criterion_group!(benches, bench_parse);
criterion_main!(benches);
