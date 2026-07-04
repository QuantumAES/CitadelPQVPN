# Changelog

Формат — [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/); версии по [SemVer](https://semver.org/lang/ru/).

## [Unreleased]

Клиентское приложение (треки **C0–C4**, см. `docs/CLIENT-ARCH.md`): движок выделен во
встраиваемую библиотеку, добавлены формат клиентских кред, десктоп-клиент (Linux) с GUI,
привилегированным TUN и зашифрованным хранилищем профилей, Android-клиент через `VpnService`
и разворачивание exit-сервера подписанным скриптом-инсталлером (admin, supply-chain через minisign).
**90 unit-тестов, Docker 15/15, `clippy --workspace --all-targets -D warnings` чисто; APK собирается,
Android-коннект подтверждён на эмуляторе, exit развёрнут инсталлером на боевом VDS.**

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
- **C2 — десктоп-клиент (Linux):** GUI на Flutter + flutter_rust_bridge поверх `citadel-client`.
  - **Привилегии через polkit:** `citadel-helper` (root по `pkexec`) создаёт TUN + настраивает
    адрес/маршруты/DNS и передаёт fd приложению по `SCM_RIGHTS`; непривилегированный GUI крутит
    data-plane (`GuiTunProvider`). Polkit-политика + `tools/install-desktop.sh`.
  - **GUI** (connection-centric): подключение по `citadel://`-ссылке/профилю, поток событий
    состояния (карточка статуса с таймером сессии), мультипрофильность, диалог переключения.
  - **Vault** (`citadel_client::vault`) — зашифрованное хранилище профилей: мастер-пароль →
    PBKDF2-HMAC-SHA256 → AES-256-GCM (aws-lc-rs, кроссится под Android); профиль сохраняется
    после первого успешного подключения; выбор/удаление/смена пароля.
  - **Тестовый стенд:** QEMU/KVM VM (`tools/qemu-testvm.sh` — Debian-13/xfce/startx, 9p-шара,
    общий буфер обмена через spice-vdagent) + token-less E2E-exit с публикацией портов
    (`docker/compose.e2e.yml`, `run-e2e-exit.sh`) + генератор ссылок (бинарь `citadel-linkgen`).
- **C3 — Android-клиент (`VpnService`):** мобильный путь поверх того же движка/FFI.
  - Двухфазное подключение (мобильный порядок «адрес → TUN»): `android_establish` (PQ-хендшейк
    + назначение адреса, без TUN) → Kotlin `VpnService.Builder.establish()` → fd → Rust
    `android_run_data_plane` (data-plane + поток событий). `citadel_tun::Tun` (fd-путь) расширен
    на Android.
  - **Анти-петля `protect()`:** хук `citadel_quic::protect` (`SocketProtector` / `protect_socket`)
    в движке + JNI-мост (`android_jni.rs` ↔ `CitadelVpnService.protectFd`) — исходящие сокеты
    движка исключаются из собственного туннеля.
  - `CitadelVpnService` (foreground) + MethodChannel + Dart-ветка `Platform.isAndroid` в UI.
- **C4 — Admin-deploy (разворачивание сервера скриптом):** первая установка exit — standalone
  bootstrap на сервере (без GUI): авто-Docker (с проверкой запущенности демона) → скачивание
  **подписанного** бинаря с GitHub Release + проверка `minisign` и SHA-256 (supply-chain) →
  серверный keygen → `docker compose up` → печать админской `citadel://`. Инструменты:
  `tools/{gen-release-key,mk-release,publish-release,install-citadel-server}.sh`, бинарь
  `citadel-linkgen` (генерация ссылки на сервере). `citadel-client` получил модуль `deploy`
  (`AdminDeployer` на `russh` — задел под GUI-remote-deploy, десктоп-only). Подтверждено на боевом VDS.
- **Инфраструктура разработки:** `tools/setup-dev-env.sh` — идемпотентный установщик окружения
  (rustup, Android NDK/SDK, Flutter, кросс-таргеты); `tools/requirements.txt`.

### Изменено
- `pump` (data-plane) работает поверх `Arc<dyn TunIo>` вместо конкретного `Tun`.
- `pump`: **отменяемый TUN-reader** (`poll` + stop-флаг) — на disconnect интерфейс/fd корректно
  закрываются (чинит «не переподключается до перезапуска»); попутно закрыта серверная гонка
  чтения общего TUN при multi-client.
- Exit: **MSS-clamp** (`TCPMSS --clamp-mss-to-pmtu`) — анти-PMTUD-блэкхол, иначе TCP/HTTPS сквозь
  туннель виснет (ICMP идёт). Пул адресов конфигурируем из `Citadel_TUN_ADDR` (база/префикс,
  готов к /16).
- Весь workspace приведён к чистоте `clippy --all-targets -D warnings` на тулчейне Rust 1.96.
- `citadel-tun`/`citadel-client` компилируются и под `target_os = "android"` (fd-путь TUN,
  `gui_tun`/`sendfd`; `ioctl`-request `c_int`/`c_ulong` для bionic/glibc).
- cargokit/rust_builder адаптированы под Gradle 9.1 / AGP 9.0.1 (инжект `ExecOperations` вместо
  удалённого `Project.exec()`, rustup-тулчейн в PATH сборки, `compileSdk` 36).
- Docker-демо (`entrypoint-client.sh`): устранены флаки оркестрации (probe по IP под DNS-lock;
  снятие UDP-блока после TCP-fallback теста; `wait` предшественника + retry в тестах с рестартом).
- **Клиент:** профиль сохраняется в хранилище **сразу при добавлении** (раньше — только после
  первого успешного подключения → терялся при неудаче); ненужный конфиг удаляется вручную.

### Исправлено
- **Android: создание хранилища падало ложным «Неверный пароль».** Путь vault резолвился из
  `XDG_CONFIG_HOME`/`HOME`, которых в песочнице Android нет → файл уходил в недоступную для записи
  директорию, `Vault::create` падал, а диалог трактовал любую ошибку как неверный пароль. Каталог
  данных теперь задаёт платформа (`set_data_dir` ← `getApplicationSupportDirectory()`, Android
  `filesDir`); десктоп по-прежнему использует `XDG`/`HOME`. Диалог создания хранилища показывает
  реальную причину ошибки вместо «неверного пароля».

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
