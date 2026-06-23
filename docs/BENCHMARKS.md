# CitadelPQVPN — бенчмарки (M6)

Criterion, bench-профиль (opt-level 3), rustc 1.85. Запуск: `cargo bench -p <crate>`.
Числа — медиана разового прогона на dev-машине: **порядок величин**, не абсолют; для регрессий
сравнивать прогоны на одной машине (criterion хранит baseline в `target/criterion`).

## obfs L1 — hot path, на каждый пакет (`citadel-obfs`)

| Операция | Время | Throughput |
|---|---|---|
| KDF `k_hdr` (blake3 derive) | ~225 ns | — |
| KDF `k_sess` | ~245 ns | — |
| `seal` 64 B | ~3.17 µs | ~19 MiB/s |
| `open` 64 B | ~3.10 µs | ~20 MiB/s |
| `seal` 512 B | ~3.57 µs | ~137 MiB/s |
| `seal` 1024 B | ~4.29 µs | ~227 MiB/s |
| `seal` 1232 B | ~5.05 µs | ~233 MiB/s |
| `open` 1232 B | ~4.79 µs | ~245 MiB/s |
| `pad_len_for` (паддинг-политика) | ~4.3 ns | — |

**Находка → реализовано (`Sealer`/`Opener`, M6):** stateless `seal`/`open` пере-вычисляли KDF
(`k_hdr`+`k_sess` ≈ 450 ns) и пере-инициализировали ChaCha20Poly1305 на КАЖДЫЙ пакет. Кеш
ключей/cipher per-session убрал это:

| Размер | stateless | cached (`Sealer`/`Opener`) | выигрыш |
|---|---|---|---|
| seal 64 B | ~3.14 µs | ~2.68 µs | **−15 %** (~373k pps) |
| open 64 B | ~3.13 µs | ~2.68 µs | **−14 %** |
| seal 1232 B | ~5.10 µs | ~4.75 µs | −7 % |
| open 1232 B | ~5.36 µs | ~4.43 µs | −17 % |

Экономия ~460 ns/пакет (как раз 2× KDF-derive). Подключено в `ObfsUdpSocket` (`Sealer` — immutable
на send; `Opener` под Mutex на recv, кеш cipher по `sid`). Паддинг-политика практически бесплатна.

## data-plane parse — hot path (`citadel-masque`)

| Парсер | Время |
|---|---|
| `ip::parse_ipv4` | ~11.5 ns |
| `datagram::decode` | ~3.2 ns |
| `varint::decode` | ~6.8 ns |
| `capsule::decode` | ~6.3 ns |

**Вывод:** разбор пакетов ничтожен (наносекунды) против obfs-крипты (µs) и сети — не bottleneck.

## токены blind-RSA — control path, на подключение (`citadel-token`)

| Операция | Время | Роль |
|---|---|---|
| `client_blind` | ~515 µs | клиент (RSA-pub + ослепление) |
| `issuer_blind_sign` | ~3.1 ms | издатель (RSA-priv — самая дорогая) |
| `client_finalize` | ~323 µs | клиент |
| `verify_token` | ~311 µs | exit (на подключение, НЕ per-packet) |

**Вывод:** issuance ≈ 4 мс/токен; издатель ~320 подписей/с (1 поток). `verify_token` на exit
~311 µs — control-path (один раз при коннекте), не влияет на throughput данных. RSA-2048
priv-операция доминирует; при росте нагрузки issuer масштабируется потоками/репликами.

---

## Итоги для дизайна
- **Throughput данных** ограничен obfs-криптой (~245 MiB/s на крупных пакетах) и фиксированным
  per-packet оверхедом, а не разбором пакетов. Кеш KDF/cipher — главный рычаг.
- **Аутентификация** (RSA) — на установление сессии, не на поток; не влияет на скорость туннеля.
- Цифры покрывают добавленное в M3–M5 (паддинг ничтожен; пейсинг — это политика выпуска, не CPU).
