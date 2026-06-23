# Changelog

Формат — [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/); версии по [SemVer](https://semver.org/lang/ru/).

## [0.1.0] — 2026-06-22

Первый публичный **PoC-релиз**. Вся дорожная карта `SPEC.md §12` (M0–M7) закрыта на уровне
proof-of-concept: **49 unit-тестов, 15 Docker-сценариев, 0 предупреждений компилятора**.

### Добавлено
- **M0** — гибридный PQ-QUIC хендшейк `X25519MLKEM768` (quinn + rustls/aws-lc-rs).
- **M1–M2** — CONNECT-IP туннель поверх QUIC DATAGRAM, динамический адрес (`ADDRESS_ASSIGN`),
  NAT; pinning сертификата (F1), egress-фильтр (F2), сброс привилегий до nobody (F4),
  DNS-leak protection + DoH (F6).
- **M3** — обфускация L1 (PSK-gated ChaCha20-Poly1305) → probe-resistance (F3), анти-DPI (F5);
  анти-fingerprint по размеру (bucketed padding) и по времени (DAITA-пейсинг + chaff) — ось I5.
- **F7** — per-client token-bucket rate-limit на exit (анти-абуз).
- **M4** — TCP/443-fallback (obfs-over-TCP при блокировке UDP/QUIC) + миграция соединения
  (QUIC connection migration: WiFi↔LTE / NAT-rebind).
- **M5** — анонимные токены (blind RSA, RFC 9474) + интерактивный issuer↔exit split (слепое
  подписание) + выбор exit из списка с failover.
- **M6** — robustness-fuzzing парсеров недоверенного ввода, criterion-бенчмарки
  (`docs/BENCHMARKS.md`), кеш KDF/cipher в hot-path (−15% на мелких пакетах), crypto-agility
  (именованный выбор KX-suite, TLS-negotiate).
- **M7** — PQ-аутентификация: гибрид Ed25519 (TLS-cert + pin) + **ML-DSA-65** (FIPS 204).

### Безопасность
- Никаких секретов в репозитории: общий obfs-PSK, RSA-ключ издателя, ML-DSA-ключ exit и pin
  сертификата генерируются в рантайме (Docker-том), не версионируются.

### Известные ограничения
- Исследовательский PoC — **не проходил независимый аудит**, не для production.
- obfs-over-TCP — псевдослучайный поток на :443 (не TLS-mimicry) → слабее против цензора,
  валидирующего TLS на :443.
- coverage-guided fuzzing требует nightly toolchain (сейчас — robustness-тесты на stable).
- Backlog (полировка, не этапы): TLS-mimicry/Reality, полный kill-switch, h3 Extended-CONNECT,
  latency-based выбор exit, ротация токенов на клиенте. См. `docs/SPEC.md §12`, `THREAT-MODEL §4`.
