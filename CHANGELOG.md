# Changelog

Формат — [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/); версии по [SemVer](https://semver.org/lang/ru/).

## [Unreleased]

Фундамент клиентского приложения (треки **C0–C1**, см. `docs/CLIENT-ARCH.md`): движок
выделен во встраиваемую библиотеку и добавлен формат клиентских кред.
**70 unit-тестов, Docker 15/15, `clippy --workspace --all-targets -D warnings` чисто.**

### Добавлено
- **C0 — ядро-как-библиотека.** Движок вынесен из бинаря `citadel-m1` в библиотечные модули
  `citadel_quic::{config,dataplane,client,vpn}`:
  - `TunIo`-трейт (абстракция туннеля) + `Tun::from_raw_fd` — платформенный TUN инъектируется
    (Android `VpnService` fd и т.п.);
  - `ClientConfig` + `from_env()` — движок конфигурируется структурой, не окружением;
  - `establish_session` / `run_data_plane` — разделение «адрес → TUN» (порядок для мобильных ОС);
  - `VpnController` (`connect`/`disconnect`/`subscribe()` события `Connecting/Up/Down`) + трейт
    `TunProvider` (платформа туннеля за абстракцией);
  - крейт **`citadel-client`** (`cdylib`/`staticlib`) — FFI-вуаль для GUI; кросс-собирается под
    `aarch64-linux-android` (aws-lc-rs + PQ-крипта под Android NDK — риск R1 снят).
- **C1 — формат кредов** (`citadel_client::creds`):
  - `CredentialBundle` — полный набор кред (CBOR, файл `.citadelconf`);
  - `CredentialLink` — компактная `citadel://`-ссылка/QR: большие публичные ключи → обязательства
    `H(pub)` (CRQC-safe bootstrap), секреты инлайн; генерация QR (`to_qr_svg`) — компактная
    ссылка влезает в QR версии 18 (545 B против ~2.4 КБ полного бандла);
  - `to_client_config()` — `CredentialBundle` → `ClientConfig` (`PinSource::Bytes`/`MldsaSource::Bytes`).
- **Инфраструктура разработки:** `tools/setup-dev-env.sh` — идемпотентный установщик окружения
  (rustup, Android NDK/SDK, Flutter, кросс-таргеты); `tools/requirements.txt`.

### Изменено
- `pump` (data-plane) работает поверх `Arc<dyn TunIo>` вместо конкретного `Tun`.
- Весь workspace приведён к чистоте `clippy --all-targets -D warnings` на тулчейне Rust 1.96.
- Docker-демо (`entrypoint-client.sh`): устранены флаки оркестрации (probe по IP под DNS-lock;
  снятие UDP-блока после TCP-fallback теста; `wait` предшественника + retry в тестах с рестартом).

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
