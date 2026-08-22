# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Что это

CitadelPQVPN — постквантовый VPN: гибридный обмен ключами X25519 + ML-KEM-768 поверх QUIC/MASQUE,
обфускация трафика под анти-DPI, анонимная аутентификация без учётных записей (VOPRF/ristretto255,
Privacy Pass). Клиенты — Android/Linux/Windows (Flutter GUI + Rust-ядро), сервер-exit — Docker.

Полное описание протокола — `docs/SPEC.md`, модель угроз — `docs/THREAT-MODEL-STRIDE.md`.
README.md и docs/ написаны по-русски и детальны — читай их, а не только этот файл, для контекста
конкретной подсистемы.

## Сборка и тесты

Требуется rustup **stable 1.96+** (системный `/bin/cargo` 1.85 не соберёт зависимости), `cmake` +
`clang` для `aws-lc-rs`, Flutter 3.44+ для приложения. Полная настройка окружения —
`tools/setup-dev-env.sh`. Подробности сборки/установки — `docs/BUILD-INSTALL.md`.

```bash
cargo test --workspace                      # юнит-тесты Rust-движка (200+)
cargo test -p citadel-obfs some_test_name    # один тест в одном крейте
cargo clippy --workspace --all-targets -- -D warnings

bash docker/run-demo.sh                     # e2e: настоящий туннель в контейнерах (издатель + 2 exit'а + клиент)
bash docker/run-cli-tests.sh                # e2e: консольный клиент, привилегии, kill-switch
```

Оба e2e-харнеса сами поднимают и гасят стенд (даже при провале сценария) и возвращают ненулевой
код при провале — это те же команды, что гоняет CI. Не считай задачу законченной, пока
`cargo test --workspace`, `cargo clippy -- -D warnings` и, если тронут протокол/L1/токены,
соответствующий e2e-харнес не проходят.

```bash
cd app && flutter build linux --release      # клиент-Linux → build/linux/x64/release/bundle/
cd app && flutter build apk --release        # клиент-Android
flutter analyze                              # статический анализ Dart (см. предупреждение ниже)
```

`flutter analyze` в `app/` не должен тонуть в вендоренном `cargokit` (см. коммит
`chore(app): flutter analyze перестал тонуть в вендоренном cargokit`) — если анализ внезапно
разросся на тысячи предупреждений из `rust_builder/cargokit`, проверь `analysis_options.yaml`,
а не чини сами предупреждения там.

`cargo bench -p citadel-obfs --bench obfs -- --baseline before` — перепроверять после любой правки
hot-path обфускации/data-plane (переполнение int теперь паникует и в release, `Cargo.toml`
`[profile.release] overflow-checks = true`; критерий — не хуже 3% регрессии, см. `docs/BENCHMARKS.md`).

## Структура workspace

Rust workspace — `Cargo.toml` в корне; `app/rust` (FFI-мост Flutter, flutter_rust_bridge) **исключён**
из workspace и собирается отдельно cargokit'ом, хотя path-зависимо тянет `citadel-client`.

Протокол — стек слоёв сверху вниз:

```
L4 управление  токены и выдача, выбор exit, назначение адреса (capsules)
L3 данные      CONNECT-IP: IP-пакеты как QUIC DATAGRAM        ── citadel-masque, citadel-tun
L2 сессия      PQ-QUIC + TLS 1.3 (X25519MLKEM768), pin, ML-DSA ── citadel-quic
L1 обфускация  ChaCha20-Poly1305 PSK-wrap, паддинг, пейсинг    ── citadel-obfs
L0 транспорт   UDP (основной) / TCP:443 (обход блокировки)
```

| Крейт | Назначение |
|---|---|
| `citadel-obfs` | обфускация L1: PSK-gated AEAD, паддинг, анти-реплей, байт-точные тест-векторы |
| `citadel-masque` | плоскость данных CONNECT-IP: varint, датаграммы, капсулы, IPv4/ICMP/UDP/DNS |
| `citadel-tun` | TUN-устройство (Linux) |
| `citadel-token` | анонимные токены (VOPRF/ristretto255): роли клиента, издателя, admin-канал |
| `citadel-protect` | фабрика исходящих сокетов движка (см. ниже — обязательна для нового кода) |
| `citadel-quic` | PQ-QUIC, obfs-сокет, rate-limit, TCP-fallback, миграция, PQ-аутентификация |
| `citadel-client` | движок как встраиваемая библиотека + хранилище профилей и креды |
| `citadel-helper` | привилегированный помощник Linux-GUI (polkit): TUN и маршруты, fd по SCM_RIGHTS |
| `citadel-vpnd` / `citadel-engine` / `citadel-cli` | консольный клиент: демон под root, движок без привилегий, TUI |
| `citadel-winnet` / `citadel-winsvc` | Windows: сеть, WFP, WinTUN и служба-плумбер |

Клиентское приложение — Flutter (`app/`) поверх `citadel-client` через `flutter_rust_bridge`
(`docs/CLIENT-ARCH.md`); консольный клиент — `docs/LINUX-CLI.md` (демон под root + движок без
привилегий + TUI, с разделением привилегий через `citadel-vpnd`/`citadel-engine`/`citadel-cli`).

## Инварианты, которые обязан держать код

- **Исходящие сокеты движка идут мимо собственного туннеля, всегда явно.** Прямой
  `UdpSocket::bind` / `TcpStream::connect` (std и tokio) запрещён `clippy.toml`
  (`disallowed-methods`, `-D warnings` валит сборку). Единственный путь — фабрика
  `citadel_protect::{bind_udp_route, bind_udp_ephemeral, connect_tcp_route, connect_tcp_str_route}`,
  где маршрут (`Route::Bypass` / `Route::Tunnel`) — обязательный параметр сигнатуры, а не
  побочная договорённость. Это ломалось дважды (obfs-TCP, потом QUIC/UDP) именно как «забыли
  protect()», и оба раза проявлялось как будто плохая сеть, а не как ошибка. Слушающий сокет
  сервера — `bind_udp_listen`, к нему протекция не относится. Точечные исключения из линта —
  только сама фабрика и тестовые модули (петля на 127.0.0.1), помечены
  `#[allow(clippy::disallowed_methods)]` с обоснованием рядом.
- **G1: хост сервера закрыт для трафика из собственного туннеля** (кроме token-порта издателя при
  раздельном деплое) — это ядровое `Citadel_DENY_DSTS`/`Citadel_ALLOW_DSTS` в entrypoint exit'а,
  не то же самое, что iptables-INPUT (тот действует только в netns контейнера).
  Администрировать сервер из-под собственного же туннеля не получится — это ожидаемо, не баг.
- **`ufw` не видит порты, опубликованные docker'ом** (DNAT в `PREROUTING`, минует `INPUT`).
  Фильтровать такие порты можно только в цепочке `DOCKER-USER` (`$DIR/etc/admin-fw.sh`). Не
  предлагай `ufw allow/deny` как решение для docker-published портов — оно ничего не сделает.
  Порты, которые слушает сам хост (ssh), `ufw` фильтрует как обычно.
- **Порты сервера (UDP-туннель, TCP-fallback:443, издатель) выбираются случайно при первой
  установке**, а не жёстко заданы — фиксированные значения были узнаваемой сигнатурой Citadel при
  сканировании. Не возвращай в код константные дефолтные порты.
- **Секретов в репозитории нет и не должно быть.** PSK, ключи издателя и exit'а, cert-pin
  генерируются в рантайме на сервере. Релизный minisign-ключ и Android keystore хранятся вне
  репозитория (см. `.gitignore`, `docs/BUILD-INSTALL.md`).
- **`applicationId` Android (`com.quantumaes.citadelpqvpn`) неизменяем** — зашит в имена JNI-символов
  (`Java_com_quantumaes_citadelpqvpn_…` в `app/rust/src/android_jni.rs`), связываемых в рантайме;
  расхождение даёт APK, падающий при старте VpnService. Инвариант проверяет
  `tools/check-android-jni.py` (в CI).
- **`overflow-checks = true` в release** (`Cargo.toml`) — намеренно, для арифметики на недоверенном
  вводе (длины из пакетов, MTU, счётчики анти-реплея, квоты). Не убирай этот флаг ради
  производительности без перепроверки `docs/BENCHMARKS.md`.
- Крейты внутренние, `publish = false` в workspace — на crates.io не публикуются никогда, это
  осознанный выбор (path-зависимости, нестабильный API), не забытая настройка.

## Коммиты

Сообщения коммитов в этом репозитории — на русском, в формате
`тип(область1,область2): суть по-русски (заход N)` (conventional-commit тип + русская сводка).
Смотри `git log` за примерами стиля перед тем, как формулировать сообщение самостоятельно.
