# CitadelPQVPN — архитектура клиентского приложения (трек C*)

**Мастер-документ клиента v0.1 (черновик)**
Дата: 2026-06-23
Профиль: консьюмерский GUI-клиент · Flutter + Rust-ядро · режимы User/Admin · кроссплатформенность Android/Windows/macOS/Linux

> Этот документ описывает **клиентское приложение** поверх уже готового ядра (см. `SPEC.md`, roadmap M0–M7 ✅).
> Серверная/протокольная часть здесь не переопределяется — только потребляется. Все ссылки `§N` без указания файла — на этот документ; протокол — в `SPEC.md`, угрозы — в `THREAT-MODEL-STRIDE.md`.

---

## 0. Цели и не-цели

### Цели
- **Один UI-код на 5 целей** — Android, Windows (x86-64 + ARM64), macOS, Linux. Единая кодовая база интерфейса.
- **Два режима в одном приложении** — **User** (импорт конфига/ссылки/QR → подключение) и **Admin** (разворачивание сервера в Docker по SSH + выпуск кредов для новых клиентов).
- **Консьюмерское удобство** — выпуск нового клиента и отзыв (по времени/при компрометации) в один клик; авто-рефреш токенов невидим пользователю.
- **Переиспользование ядра** — никакого форка протокола: GUI оборачивает существующие крейты `citadel-*` как библиотеку.
- **Приватность по умолчанию** — exit не линкует сессии с личностью (наследуем модель токенов M5, см. §10).

### Не-цели (явно вне области)
- Переписывание протокола/крипты — фиксировано в `SPEC.md`.
- iOS как обязательная цель этапа 1 (Flutter её поддержит, но в roadmap C* не закладываем как блокирующую — NetworkExtension-нюансы те же, что у macOS).
- Web-клиент (браузер не даёт TUN).
- Самостоятельная установка Docker на сервер без участия админа (детектируем и подсказываем, но не автоустанавливаем молча).

---

## 1. Контекст: что уже готово и что строим

**Готово (PoC-уровень, M0–M7 ✅):** Rust-воркспейс `citadel-{obfs,masque,tun,token,quic}`; бинарь `citadel-m1` (роли `server|client|probe|auth-probe`, конфиг через `Citadel_*` env, сам открывает TUN через ioctl); `citadel-token` (issuer/client/batch, blind-RSA RFC 9474); `docker/` демка (issuer :7000 → exit :4433 + TCP-fallback :443 → client). Гибрид X25519+ML-KEM-768, obfs L1, миграция, multi-server, ML-DSA-65 PQ-auth.

**Строим (трек C*):** клиентское приложение, которое:
1. оборачивает движок как **встраиваемую библиотеку** `citadel-client`;
2. даёт **Flutter-GUI** с режимами User/Admin;
3. в Admin-режиме **разворачивает серверный стек по SSH** и **выпускает креды** (конфиг/ссылка/QR);
4. интегрируется с **платформенными TUN-API** каждой ОС.

---

## 2. Ключевое архитектурное решение: ядро-как-библиотека

Текущий движок зашит в `bin/citadel-m1.rs`: читает `Citadel_*` env → `open_tun()` (ioctl) → `run_client`. **В таком виде он непригоден для GUI-клиента**, потому что:

- На **Android/iOS** нельзя форкнуть привилегированный процесс и самому создать TUN: ОС отдаёт **файловый дескриптор** туннеля через `VpnService`/`NetworkExtension`, и пакеты гоняются **внутри** процесса приложения.
- GUI должен управлять движком по API (статус, события, переподключение), а не парсить stdout стороннего процесса.

> **Решение:** выделяем крейт **`citadel-client`** — библиотека-«мозг», собираемая как `cdylib`/`staticlib` и линкуемая во все GUI. Бинарь `citadel-m1` остаётся, но обслуживает **только серверную сторону** (в Docker). Движок клиента выносится из бинаря в библиотеку.

Это критический путь всего трека — этап **C0**.

---

## 3. Слоистая архитектура клиента

```
┌──────────────────────────────────────────────────────────┐
│  Flutter UI  (один Dart-код: Android/Win/macOS/Linux)      │
│   • User-режим:  импорт config/citadel://-link/QR → Connect│
│   • Admin-режим: SSH-деплой → минт кредов → QR/ссылка       │
└──────────────────────┬───────────────────────────────────┘
            flutter_rust_bridge (Dart) │ UniFFI (Kotlin/Swift)
┌──────────────────────┴───────────────────────────────────┐
│  citadel-client  (Rust «мозг», cdylib/staticlib)           │
│   ConfigManager  — citadel:// ↔ CBOR ↔ QR ↔ .citadelconf   │
│   VpnController  — connect/disconnect, поток статуса        │
│   AdminDeployer  — russh → docker, keygen, чтение pin/pub   │
│   TokenAgent     — авто-рефреш epoch-токенов у issuer       │
│   SecretStore    — абстракция OS-keychain                  │
│   (поверх citadel-quic/obfs/masque/token — уже готовы)     │
└──────────────────────┬───────────────────────────────────┘
            TunIo (read/write packet) — реализации per-OS
┌──────────┬───────────┬───────────┬────────────────────────┐
│ Android  │ Windows   │ macOS     │ Linux                   │
│VpnService│ WinTUN    │NEPacket/  │ /dev/net/tun (есть)     │
│  (fd)    │(wintun.dll)│ utun     │  + polkit helper        │
└──────────┴───────────┴───────────┴────────────────────────┘
```

**Принцип:** вся логика — в Rust-ядре (один источник истины, тестируемый, переиспользуемый). UI и платформенные TUN-плагины — максимально тонкие.

---

## 4. Ядро `citadel-client` (Rust lib-API)

### 4.1 `TunIo` — абстракция туннеля
Движок больше не открывает TUN сам. Вместо этого работает поверх трейта (живёт в `citadel-tun`; **блокирующий** — `pump` уже изолирует чтение TUN в `std::thread`+mpsc, async тут лишний):

```rust
// crates/citadel-tun/src/lib.rs
pub trait TunIo: Send + Sync + 'static {
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;
    fn send(&self, pkt: &[u8]) -> io::Result<usize>;
}
impl TunIo for Tun { /* делегирует к существующим recv/send */ }
```
Реализации: Linux `/dev/net/tun` (текущий `citadel-tun::Tun`); мобилки/десктоп — обёртка над **внешним fd** от ОС (`Tun::from_raw_fd(fd)`). Платформенные обёртки (Android и т.д.) живут в `citadel-client` — orphan-rule соблюдён (тип локальный, трейт чужой).

### 4.2 `ClientConfig` — конфиг-структура вместо env
Все текущие `Citadel_*` становятся полями (env-парсинг остаётся тонкой обёрткой только для бинаря):

| Поле | Источник сейчас | Назначение |
|---|---|---|
| `servers: Vec<Endpoint>` | `Citadel_SERVERS`/`Citadel_CONNECT` | multi-server + failover (M5) |
| `server_name` | `Citadel_SERVER_NAME` | SNI |
| `cert_pin` | `Citadel_PIN`/`PIN_DIR`/`PIN_FILE` | pinning (F1) |
| `mldsa_pub` | `Citadel_MLDSA_PUB`/`_FILE` | PQ-auth (M7) |
| `obfs_psk` | `Citadel_OBFS_PSK` | obfs L1 PSK |
| `kx_suite` | `Citadel_KX` | crypto-agility (M6) |
| `tcp_fallback_port` | `Citadel_TCP_PORT`/`TCP_CONNECT` | :443 fallback (M4) |
| `issuer` + `issuer_pub` | `Citadel_ISSUER_PUB` + endpoint | минт токенов (M5) |
| `routes`, `dns`, `mtu` | `Citadel_ROUTES`/`DNS`/`MTU` | split-tunnel, DoH (F6) |

### 4.3 `VpnController` — управление сессией
```rust
pub struct VpnController { /* … */ }
impl VpnController {
    pub async fn connect(&self, cfg: ClientConfig, tun: Arc<dyn TunIo>) -> Result<SessionHandle>;
    pub fn status_stream(&self) -> impl Stream<Item = VpnEvent>; // Connecting/Up/Migrating/Down + байты, текущий exit
    pub async fn disconnect(&self) -> Result<()>;
}
```
Внутри — уже готовое: `enum Tunnel{Quic,Tcp}`, миграция, multi-server failover, PQ-auth, rate-limit на приёме.

### 4.4 `AdminDeployer` — см. §8. `TokenAgent` — см. §10. `SecretStore` — см. §11.

---

## 5. FFI-граница

- **UniFFI** (Mozilla) — генерирует обвязку для **Kotlin** (Android) и **Swift** (macOS/iOS) из `.udl`/proc-macro.
- **flutter_rust_bridge** — генерирует обвязку для **Dart** (основной UI-слой).

Оба биндят **один и тот же** `citadel-client`. Асинхронность пробрасывается (frb поддерживает `Stream` → Dart Stream для событий статуса).

---

## 6. GUI (Flutter)

**User-режим:**
- Импорт: вставить `citadel://`-ссылку, открыть `.citadelconf`-файл, **сканировать QR** (камера на мобилке / из файла на десктопе).
- Большая кнопка Connect/Disconnect, индикатор статуса (поток из `VpnController`), выбор exit, split-tunnel/DNS, kill-switch.

**Admin-режим (реализовано в C7 — по туннелю, без SSH):**
- Admin-профиль = профиль, чья ссылка — **мастер** (несёт `admin_seed`; в UI — чип `admin`, предупреждение «не передавайте её никому» при добавлении).
- Меню admin-профиля → **«Абоненты»** (требует активной сессии этого профиля — канал живёт за туннелем): список реестра с локальными метками, «Выдать доступ» (метка + срок → регистрация pub по каналу → клиентская ссылка + QR, показывается **один раз** — seed абонента у админа не хранится), «Отозвать» (с guard-rail: self-revoke отклоняет сервер).
- Разворачивание сервера — bootstrap-скриптом на самом сервере (`tools/install-citadel-server.sh`, C4): печатает мастер- и клиентскую ссылки. SSH-управление реестром из клиента (страница C5.5) **удалено** — заменено туннельным каналом (§10).

---

## 7. Платформенная TUN-интеграция

Единственный неустранимо-нативный слой — по тонкому плагину на ОС, каждый отдаёт `TunIo` в ядро:

| ОС | Механизм | Привилегии | Заметки |
|---|---|---|---|
| **Linux** | `/dev/net/tun` (есть `citadel-tun`) | `CAP_NET_ADMIN` | privileged helper / polkit / systemd |
| **Android** | `VpnService.establish()` → fd | нет root | маршруты/DNS через `Builder`; ядро берёт fd |
| **Windows** | **WinTUN** (`wintun.dll`, от WireGuard) | elevation | userspace-адаптер; создание через службу |
| **macOS** | `NEPacketTunnelProvider` или `utun` | entitlement / привилегии | App Store ⇒ NetworkExtension + provisioning |

---

## 8. Admin-режим: разворачивание сервера

> **Статус (2026-07):** актуальный путь деплоя — **bootstrap-скрипт на сервере** (`tools/install-citadel-server.sh`: Docker, keygen на сервере, issuer+exit, мастер-/клиентская ссылки; см. C4). SSH-деплой из GUI ниже — дизайн на будущее; `AdminDeployer` (russh) остаётся библиотечным. **Управление абонентами больше не SSH-операция** — оно ушло в admin-плоскость по туннелю (§10, C7).

### 8.1 Доставка бинаря — из GitHub Release
- **CI** (`.github/workflows/release.yml`): матрица `amd64 + aarch64` (нативные arm64-раннеры — `aws-lc-rs` тянет cmake/C, под QEMU медленно/хрупко). Артефакты: `citadel-m1-{x86_64,aarch64}.zst` (стрип + zstd; сейчас бинарь ~72 МБ), `citadel-token-*`, `sha256sums`, подпись (minisign/cosign).

### 8.2 Деплой по SSH (`russh`)
> SSH-клиент — **`russh`** (чистый Rust, async, без OpenSSL-C). `ssh2`/libssh2 отвергнут: C-зависимость не соберётся под Android/ARM-цели единым ядром.

Поток:
1. SSH-коннект (пароль или ключ), TOFU по host-key.
2. `uname -m` → выбор арки; проверка Docker — **нет → авто-установка** (официальный `get.docker.com` под root; Debian/Ubuntu — наша база, надёжно; RHEL/прочие — best-effort + внятный фолбэк, не молчим).
3. **Сервер сам тянет бинарь** с GitHub Release (`curl` на хосте — не льём 70 МБ через SSH). Фолбэк без egress: админ-приложение качает один раз, кэширует, стримит через sftp.
4. Проверка `sha256` + подписи → `/opt/citadel/bin/citadel-m1`.
5. **Генерация серверных ключей** (на хосте или локально с заливкой): self-signed cert + pin (F1), ML-DSA-65 keypair (M7), issuer RSA-2048 (M5), obfs PSK.
6. Рендер `compose.yml` + entrypoints → `docker compose up -d`.
7. **Чтение обратно** pin/pubkeys → сборка клиентского бандла (§9).

### 8.3 Dev vs Prod
- **Dev (оптимум итераций):** базовый образ **пинуется один раз** (`debian:trixie-slim` + рантайм-deps), бинарь и ключи идут **bind-mount’ом** (volume). Обновление = заменить файл + `docker compose up -d --force-recreate` — **без `docker build`**. Версия в лейбле `citadel.release=<tag>+<sha>`.
- **Prod:** бинарь **запечён** в образ (воспроизводимость), опционально пуш в GHCR. Переключатель `CITADEL_BINARY_MODE=mount|baked`, единый `compose.yml`.

---

## 9. Формат кредов: конфиг ↔ ссылка ↔ QR

### 9.1 Две формы
- **Полный бандл `.citadelconf`** (CBOR, либо человекочитаемый TOML) — все ключи инлайн; для импорта файлом / air-gapped.
- **Компактная ссылка/QR `citadel://`** — только **обязательства (хэши)**, полные публичные ключи дотягиваются in-band и проверяются против хэшей (см. 9.3).

### 9.2 Содержимое бандла
endpoints (+TCP/443 fallback), **cert pin** (BLAKE3 DER, 32 B), **ML-DSA-65 pub** (1952 B), **obfs PSK** (32 B), `kx_suite`, **issuer endpoint + issuer.pub** (RSA-2048 ≈ 270 B), **issuer TLS-pin** (BLAKE3 DER, 32 B — PQ-TLS канал к издателю, S2.1/A1), **Ed25519 client-seed** (Слой-1, 32 B, §10), routes/DNS/SNI.

### 9.3 QR-ёмкость — узкое место и решение
ML-DSA pub (1952 B) доминирует. Прикидка сырья ≈ 2.5 КБ; QR version 40 byte-mode даёт ~2953 B только на **низшем** уровне коррекции (хрупко), base64url (×1.33) уже **не влезает**. Ключи высокоэнтропийны — сжатие не помогает.

> **Решение (рекомендуется): QR несёт обязательства, не ключи.** В `citadel://` кладём endpoints + `pin(32)` + `H(mldsa_pub)(32)` + `H(issuer_pub)(32)` + `issuer_pin(32)` + `obfs_psk(32)` + `ed25519_seed(32)` + мета ⇒ **~330 B** → влезает даже на высоком уровне коррекции QR. Полные публичные ключи клиент дотягивает при первом коннекте и **сверяет с хэшами из QR**.

**Бонус-свойство (CRQC-safe bootstrap):** обязательство `H(mldsa_pub)` пришло **вне канала** (QR/ссылка). Даже если будущий CRQC сломает классический pin и устроит MITM на дотягивании ключей — он не подберёт ML-DSA pub под заданный SHA-256-хэш (стойкость к прообразу). Out-of-band-обязательство **связывает** PQ-ключ независимо от стойкости транспортного pin.

`.citadelconf` (не-QR) несёт ключи инлайн — для оффлайна/air-gapped.

---

## 10. Модель идентичности (двухслойная, Privacy Pass production pattern)

**Противоречие:** blind-RSA токены (M5) **unlinkable** — exit не знает, чей токен, и не может отозвать конкретного юзера. Это максимум приватности, но «отозвать при компрометации» так невозможно. Консьюмерское «создать/отозвать удобно» требует идентичности. Развязка — разнести идентичность и анонимность по слоям.

### Слой 1 — клиентский «абонемент» (отзываемый; на exit НЕ виден)
При «создании клиента» генерим `client_id` + долгоживущую **Ed25519** ключ-пару, используемую **только против issuer’а**, на exit она не уходит. Issuer держит реестр: `client_id → pubkey, valid_until, status(active|revoked)`. Здесь вся подотчётность.

### Слой 2 — короткоживущие анонимные токены (unlinkable на exit)
Клиент раз в эпоху (1–24 ч, конфиг) аутентифицируется в issuer по Слою-1 (Ed25519 challenge-response) и получает пачку **blind-подписанных epoch-токенов** (механизм `citadel-token`, но issuer подписывает **ключом эпохи**; epoch_id зашит в подписываемое сообщение). Exit принимает токен только текущей эпохи.

**Канал к issuer'у — PQ-TLS с пиннингом (S2.1/A1).** Весь Слой-1 обмен и слепая выдача идут поверх TLS 1.3 с гибридной группой `X25519MLKEM768` и **пиннингом серта издателя** (`issuer_pin` из ссылки). Это закрыло аудит-2/A1: (a) активный MITM не подставит свои `blind_msg` под чужую Layer-1-авторизацию (кража токенов), (b) `client_id` не светится в открытом виде (деанон подписчика), (c) издатель аутентифицируется клиентом (анти-импёрсонация). Идентичность издателя (TLS-серт) постоянна (переживает рестарт → розданные ссылки не ломаются).

### Свойства
| Требование | Как достигается |
|---|---|
| **Приватность data-path** | exit видит только unlinkable-токены — не линкует сессии к юзеру (даже при сговоре issuer+exit на уровне сессии) ✓ |
| **Отзыв по времени** | нет рефреша (истёк `valid_until`) → токены гаснут к концу текущей эпохи, автоматически ✓ |
| **Отзыв при компрометации** | admin → `status=revoked` → нет новых токенов; немедленность ≤ длины эпохи (берём эпоху короче для жёсткого отзыва) ✓ |
| **Удобство** | один QR бутстрапит Слой-1; рефреш токенов невидим (`TokenAgent`); «создать»/«отозвать» = клик ✓ |

### Честный трейдофф
Появляется точка линковки **на issuer’е**: он знает «абонент X активен в эпоху N» (но НЕ его сессии/назначения — это видит только обфусцированный data-path, там анонимно). Это неустранимо для любой revocable-by-identity схемы. Ровно так работают боевые Privacy Pass / Apple Private Access Tokens: issuer аутентифицирует личность, redeemer (exit) — только unlinkable-токены.

### Admin-плоскость (C7): «выдать/отозвать» по туннелю — реализовано
Управление Слоем-1 (реестром) идёт **in-band, из-под поднятого туннеля** — публичная поверхность сервера не растёт:

- **Канал:** TCP к `ADMIN_VIP:admin_port` (`ADMIN_VIP` = шлюз туннеля, on-link и в split-tunnel) → data-plane exit'а пропускает точечно (после анти-спуфинга src) и DNAT'ит на issuer **только с туннельного интерфейса**; снаружи порт закрыт. Поверх — PQ-TLS с тем же `issuer_pin`, что token-fetch; аутентификация админа — Ed25519 в отдельном домене (`citadel-admin/v1`) + EKM channel-binding (кросс-протокольный replay и релей исключены). Каждая операция самодостаточна: connect → op → close.
- **Роли ссылок (креды v3):** **мастер-ссылка** = клиентская + `admin_seed`/`admin_port` — только у админа; **клиентская** — свой `client_seed`, admin-полей нет. Выдача абонента целиком на устройстве админа: свежий CSPRNG-seed → по каналу уходит только pub (client_id) → ссылка минтится локально. Issuer seed абонента не видит (модель C5.4b сохранена).
- **Приватность и метки:** на сервере — только `pub + срок + статус`; человекочитаемые метки («телефон Али») — исключительно в зашифрованном vault админа (`IssuedRecord`).
- **Guard-rails:** `admin_id` отсутствует → канал никого не пускает (secure default); отзыв client_id самого админа отклоняется (анти-self-lockout, break-glass — на сервере); провал auth → throttle 1с + разрыв без ack (не оракул).
- **Поверхности:** GUI «Абоненты» (все платформы, включая мобильные — russh не нужен) и CLI `citadel-token admin <list|add|revoke>` (ops/break-glass с любой машины с мастер-кредами и туннелем; `registry` — оффлайн-правка на самом сервере).

### Дельты по коду
- `citadel-token`: **epoch-ключи** (keyring per-epoch RSA, публикация pub текущей+следующей эпохи; epoch_id в сообщении); `verify_token` проверяет окно эпохи.
- Issuer: **client-registry** + Ed25519-аутентификация перед blind-signing; `revoke` = флип статуса; **admin-listener** (`Citadel_ADMIN_LISTEN`) — управление реестром по каналу (C7.1).
- Клиент: `TokenAgent` — фоновый рефреш; `citadel_client::admin` — admin-операции + минт клиентских ссылок (C7.3); FFI/GUI «Абоненты» (C7.4).

---

## 11. Безопасность клиента

- **`SecretStore`** — абстракция OS-keychain: Android Keystore / Windows DPAPI / macOS Keychain / Linux libsecret (Secret Service). Хранит: SSH-ключи (admin), obfs PSK, Ed25519 client-seed, пачку токенов. **Никаких секретов в plain-конфиге на диске.**
- **Admin-режим = высокая привилегия:** подпись клиентских бандлов; TOFU по SSH host-key против MITM при первичном деплое; аудит-лог выданных/отозванных кредов.
- **Kill-switch** — fail-closed маршрутизация (наследует F6 DNS-leak-protection); при разрыве туннеля трафик не утекает в открытую сеть.
- **Угрозы вне области:** компрометация эндпоинта пользователя (см. `SPEC.md §0`).

---

## 12. Структура репозитория

```
CitadelPQVPN/
├─ crates/
│  ├─ citadel-{obfs,masque,tun,token,quic}/   # есть
│  └─ citadel-client/         # НОВОЕ: lib-API, FFI, TunIo, ClientConfig, AdminDeployer
├─ app/                       # НОВОЕ: Flutter-проект
│  ├─ lib/                    # Dart UI (user + admin)
│  ├─ rust/                   # flutter_rust_bridge-биндинги к citadel-client
│  └─ {android,windows,macos,linux}/   # платформенные TUN-плагины
├─ docker/                    # серверная сторона (есть)
└─ .github/workflows/release.yml       # multi-arch бинари в Release
```

---

## 13. Критические инженерные риски (читать до кодинга)

| # | Риск | Митигация | Когда проверять |
|---|---|---|---|
| R1 | **Кросс-сборка `aws-lc-rs` под Android/iOS NDK** (cmake/C) — самая капризная часть FFI | проверить минимальный `cdylib` под `aarch64-linux-android` рано | **C0** |
| R2 | **macOS NetworkExtension entitlements** — нужен Apple Developer аккаунт + provisioning | иначе только `utun` с привилегиями (не App Store); решить модель распространения | C3 |
| R3 | **Windows WinTUN elevation** — создание адаптера требует прав; наш бинарь не подписан драйвер-сертификатом | служба-helper + подпись установщика | C3 |
| R4 | **QR-ёмкость** | решено дизайном §9.3 (обязательства, не ключи) — подтвердить замером | C1 |
| R5 | **Размер `cdylib`** (aws-lc статика ~десятки МБ) на мобилке | стрип, `lto`, split per-ABI | C0 |

---

## 14. Дорожная карта (трек C*)

| Этап | Содержание | Зависит от |
|---|---|---|
| **C0** | **Ядро-как-библиотека** (критич. путь): движок из `bin/citadel-m1` → модуль `citadel_quic::{config,dataplane,client}` (NB: **не** отдельный крейт на этом шаге — иначе цикл с серверным бинарём, живущим в `citadel-quic`; крейт `citadel-client` появляется на FFI-под-шаге как тонкая вуаль); `TunIo`-трейт; `ClientConfig`; `Session`/`establish_session`/`run_data_plane`; `VpnController`+события; `citadel-tun::from_raw_fd`; FFI (UniFFI + frb); smoke-сборка `cdylib` под Android (R1) | — |
| **C1** | **Формат кредов**: `citadel://` + CBOR + base64url, `.citadelconf`, QR encode/decode (дизайн обязательств §9.3), `ConfigManager`; замер QR (R4) | C0 |
| **C2** | **User-mode на Linux** (быстрый E2E): Flutter-скелет + frb + Linux-TUN (polkit-helper); Connect/Disconnect/Status поверх текущей docker-демки | C0, C1 |
| **C3** | **Платформенные TUN**: Android `VpnService` **✅** → Windows WinTUN → macOS NEPacketTunnel (R2, R3) | C2 |
| **C4** ✅ | **Admin-deploy**: bootstrap-скрипт на сервере (`tools/install-citadel-server.sh`: авто-установка Docker, серверный keygen, рендер `compose`/entrypoints, `docker compose up`, чтение pin/pubkeys, минт мастер-/клиентской ссылок). SSH-деплой из GUI (`russh`) — дизайн на будущее (§8) | C0, C1 |
| **C5** ✅ | **Идентичность и доступ**: двухслойная (epoch-ключи в `citadel-token` + issuer client-registry + Ed25519-auth), `TokenAgent` авто-рефреш; **«выдать/отозвать»** — по туннелю (admin-plane, ниже) | C4 |
| **C6** ✅ (частично) | **Упаковка/секреты**: kill-switch (Linux firewall + Android always-on) ✅; vault (AES-256-GCM) ✅; APK ✅; `SecretStore` keychain / msix/dmg / нотаризация macOS — остаток | C2–C5 |
| **admin-plane v2** ✅ | **Управление абонентами по туннелю** (в `SECURITY-ROADMAP` — трек **C7**): PQ-TLS admin-канал к issuer из-под туннеля, роли ссылок (мастер/клиент), GUI «Абоненты», CLI `citadel-token admin`. Заменил SSH-путь C5.5 (§8/§10) | C5 |
| **C7 (сетевой контроль)** | **Сетевой контроль User-mode** *(ещё не начат; NB: одноимённый номер с admin-plane в SECURITY-ROADMAP — развести при следующей правке нумерации)*: **split-tunnel** — *per-app* (Android `VpnService.addAllowed/DisallowedApplication`; десктоп позже) + *per-domain* (DNS-перехватчик: DoH-резолв → динамич. маршруты); **DNSSEC + DoH** | C3 |

---

## Приложение A. Открытые вопросы
- A1. Длина эпохи токенов по умолчанию (баланс «жёсткость отзыва ↔ нагрузка на issuer»). Кандидат: 1 ч для жёсткого отзыва, 24 ч для лёгкой нагрузки.
- A2. iOS — включать в C3 или отдельным треком после стабилизации macOS NE?
- A3. Модель распространения десктоп-сборок (свой сайт vs сторы) — влияет на подпись/нотаризацию и на macOS-entitlements (R2).
- A4. Нужен ли offline-режим Admin (деплой на air-gapped сервер) на этапе 1 — влияет на фолбэк доставки бинаря (§8.2 п.3).

## Приложение B. Переиспользуемое из текущего кода
- `citadel-quic`: `Tunnel{Quic,Tcp}`, миграция (`ArcSwap<UdpSocket>`+`rebind`), `ratelimit`, `tcp_obfs`, `pqauth`, `kx_groups_for` — берутся как есть, оборачиваются `VpnController`.
- `citadel-tun`: добавить `from_raw_fd`; ioctl-путь остаётся для Linux/сервера.
- `citadel-token`: расширить epoch-ключами + client-registry (С5), роли `client`-минта переиспользуются в `TokenAgent`.
- `docker/`: `compose.yml`/entrypoints → шаблоны для `AdminDeployer` (§8).
