# Сборка и установка CitadelPQVPN

Клиент = Flutter-GUI + Rust-ядро (Linux/Android); сервер-exit = Docker-контейнер.
Полная настройка окружения — `tools/setup-dev-env.sh` (rustup, Flutter, Android SDK/NDK,
кросс-таргеты, cmake). Ниже — краткая выжимка.

## Окружение

- **Rust** — rustup **stable 1.96+** (НЕ системный `/bin/cargo` 1.85: зависимости требуют новее).
- **cmake** (для `aws-lc-rs`) — системный `/bin/cmake`; НЕ ставь `.venv` первым в `PATH`.
- **Flutter** — stable 3.44+ (`$HOME/flutter/bin`).
- **Android** (для APK) — SDK 36 + build-tools 36 + NDK 27 (`ANDROID_NDK_HOME`), cargo-ndk.
- PATH для сборок: `export PATH="$HOME/flutter/bin:$HOME/.cargo/bin:$PATH"`.

## Клиент — Linux (desktop)

```sh
cd app
flutter build linux --release                 # → build/linux/x64/release/bundle/
( cd .. && cargo build --release -p citadel-helper )   # TUN-хелпер (polkit)
```

Установка (на машине **с TUN**, нужен root/pkexec):

```sh
sudo tools/install-desktop.sh --with-app       # helper + polkit (политика + правило) + app → /opt/citadel-pqvpn
sudo usermod -aG citadel-vpn $USER              # чтобы GUI не спрашивал пароль (затем ПЕРЕЛОГИН)
/opt/citadel-pqvpn/app                          # запуск GUI
```

**Про запрос пароля.** GUI поднимает туннель через `pkexec citadel-helper`, и polkit по умолчанию
просит пароль администратора — причём не только на первое подключение: каждый автоматический
реконнект (смена Wi-Fi/LTE, восстановление связи) запускает хелпер заново, то есть спрашивает
снова. Установщик поэтому ставит правило `/etc/polkit-1/rules.d/49-citadel-pqvpn.rules`: членам
группы `citadel-vpn` (та же группа, что даёт право управлять туннелем консольному клиенту)
подтверждение не требуется. Кто не в группе — работает как раньше, по паролю.
Не нужно такого поведения — `sudo tools/install-desktop.sh --with-app --ask-password`.
Добавлять в группу стоит только тех, кому доверяете администрирование сети машины (член группы
может завернуть весь её трафик в свой exit) — поэтому установщик никого не добавляет сам,
`--user ИМЯ` делает это по явной просьбе.

### Чистка кешей сборки

Дерево сборки растёт до десятков гигабайт (`target/` + `app/build` + per-ABI Rust под Android):

```sh
bash tools/clean-caches.sh -n            # показать, что и сколько удалится
bash tools/clean-caches.sh               # безопасно: incremental-кеши + мусор docker
bash tools/clean-caches.sh --deep        # + cargo clean, flutter clean, gradle-трансформы
```

`--deep` означает полную пересборку в следующий раз (cargo ~10–15 мин из-за aws-lc-rs, APK ~6–8 мин
из-за четырёх ABI). Скрипт не трогает исходники, `dist/` с релизами, `~/.cargo/registry`,
`~/.pub-cache`, хранилища профилей и ключи; удаляет только то, что пересоздаётся сборкой.

## Клиент — Android (APK)

```sh
cd app
flutter build apk --release                     # все ABI; либо конкретные:
flutter build apk --release --target-platform android-arm64,android-x64
# → build/app/outputs/flutter-apk/app-release.apk
#   (release использует debug-signing из шаблона Flutter → APK устанавливается без своего keystore)
```

Установка:

```sh
adb install -r build/app/outputs/flutter-apk/app-release.apk
# либо скинуть APK на телефон и поставить вручную (разрешив установку из неизвестных источников)
```

Подключение (оба клиента): **«Добавить профиль» → вставить `citadel://`-ссылку → «Подключить»**.
Профиль сохраняется сразу при добавлении (удалить можно в меню профиля).

## Сервер — exit (режим Admin)

Первая установка — скриптом **на самом сервере, без клиента** (детали: `docs/CLIENT-ARCH.md` §8).
Бинарь тянется с GitHub Release и проверяется подписью minisign (supply-chain).

**Один раз (мейнтейнер) — ключ подписи релиза:**
```sh
tools/gen-release-key.sh          # → packaging/release/citadel-release.pub (коммитится)
#   секрет — вне репо (~/.citadel/release, password-protected); сделай ОФЛАЙН-БЭКАП, не коммить
git add packaging/release/citadel-release.pub
```

**Собрать + подписать + выложить релиз (под арку сервера):**
```sh
tools/mk-release.sh    vX.Y.Z      # → dist/vX.Y.Z/{citadel-m1,citadel-linkgen}-<arch>.zst + sha256sums(.minisig)
gh auth login
tools/publish-release.sh vX.Y.Z    # выкладка на GitHub Release
```

**Развернуть на сервере (root):**
```sh
CITADEL_VERSION=vX.Y.Z ./install-citadel-server.sh
# авто-Docker → verified-pull бинаря → keygen на сервере → docker compose up → печать citadel://
```

> **Firewall:** открой на VDS входящие **4433/udp** (PQ-QUIC) и **443/tcp** (obfs-fallback) —
> в облачной security-group провайдера и, при наличии, в `ufw`/`nftables`. Иначе клиент увидит
> «ни один exit недоступен».

Ссылку `citadel://` из вывода — вставить в клиент.
