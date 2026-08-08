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
```

### Подпись APK

`applicationId` приложения — **`com.quantumaes.citadelpqvpn`**. Менять его нельзя: для Android
это другое приложение, обновление поверх не встанет. Имя пакета зашито ещё и в имена
JNI-символов (`Java_com_quantumaes_citadelpqvpn_CitadelVpnService_…` в `app/rust/src/android_jni.rs`),
причём связываются они в рантайме — расхождение даст собравшийся APK, который падает при
старте VpnService. Инвариант сторожит `tools/check-android-jni.py` (гоняется в CI).

Keystore Gradle ищет в двух местах, ни одно из них не в репозитории:

1. `app/android/key.properties` (в `.gitignore`):

   ```properties
   storeFile=/абсолютный/путь/citadel-release.jks
   storePassword=…
   keyAlias=citadel
   keyPassword=…
   ```

2. переменные окружения — так делает CI:
   `CITADEL_KEYSTORE`, `CITADEL_KEYSTORE_PASSWORD`, `CITADEL_KEY_ALIAS`, `CITADEL_KEY_PASSWORD`.

Создать keystore (**сделайте офлайн-бэкап: потеря = невозможность выпускать обновления**):

```sh
keytool -genkeypair -v -keystore citadel-release.jks -alias citadel \
        -keyalg RSA -keysize 4096 -validity 10000
```

Ключа нет — Gradle откатывается на debug-ключ и говорит об этом в логе сборки. Такой APK
годится только для локальной проверки, и `tools/mk-client-release.sh` откажется класть его в
релиз (обход для своих сборок — `CITADEL_ALLOW_DEBUG_APK=1`).

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

**Свои порты** (значения по умолчанию узнаваемы: 4433/7000 — «подпись» Citadel):
```sh
./install-citadel-server.sh vX.Y.Z --udp-port 5443 --issuer-port 7300
# то же через env: CITADEL_UDP_PORT / CITADEL_TCP_PORT / CITADEL_ISSUER_PORT / CITADEL_ADMIN_PORT
./install-citadel-server.sh --help      # полный список флагов
```
Клиент берёт порты **из ссылки** — на устройствах ничего настраивать не нужно; после смены портов
нужно раздать новые ссылки (установщик их печатает). Порт `--tcp-port` стоит оставить **443**:
obfs-fallback маскируется именно под HTTPS. Установщик проверяет диапазон, конфликты портов между
собой и предупреждает, если порт уже занят на хосте.

> **Firewall:** открой на VDS входящие **`--udp-port`/udp** (PQ-QUIC, по умолчанию 4433),
> **`--tcp-port`/tcp** (obfs-fallback, 443) и **`--issuer-port`/tcp** (издатель токенов, 7000) —
> в облачной security-group провайдера и, при наличии, в `ufw`/`nftables`. Иначе клиент увидит
> «ни один exit недоступен». Порт admin-канала (`--admin-port`, 7001) наружу **не открывать**:
> он достижим только из туннеля.

**Полоса на абонента** (F7/D3): `--rate-limit` / `--rate-burst` — вверх, `--rate-limit-down` /
`--rate-burst-down` — вниз. По умолчанию вниз симметрично вверх (10 MiB/с, всплеск 20 MiB);
`--rate-limit-down 0` снимает лимит только на скачивание. До аудита-4 (M-3-bis) обратное
направление не ограничивалось вовсе, хотя именно на нём живёт и основная нагрузка релея, и
амплификация «мало запросил — много получил».

**Ротация ключа L1 (H-3)** включается сама, когда есть издатель: установщик генерит
`$DIR/keys/obfs.master` — серверный секрет, из которого выводится ключ обфускации каждой эпохи.
Абонент получает ключ текущей эпохи у издателя после Layer-1, вместе с токеном; PSK из ссылки
теперь открывает только канал к издателю. Практические следствия: **ссылки перевыпускать не
нужно**, а `revoke` абонента гасит и его L1-доступ (со следующей эпохи). В установке
`--no-issuer` ротации нет — раздавать ключ некому.

Ссылку `citadel://` из вывода — вставить в клиент.

#### Один сервер или два (exit и издатель)

Установка бывает в двух схемах. Обе рабочие; выбор — про то, чем платить.

| | **Один сервер** (`--role all`, умолчание) | **Два сервера** (`--role issuer` + `--role exit`) |
|---|---|---|
| Что стоит | exit + издатель на одной машине, общий том `keys/` | издатель отдельно, exit отдельно |
| Кража диска даёт | идентичность туннеля **и** издателя сразу | только одну из двух половин |
| Ключ эпохи (СЕКРЕТ, схема токенов v2) | издатель пишет его в общий том (0640, группа exit'а) | exit тянет по сети (сайдкар `citadel-keysync`, аутентифицируется своим seed'ом из bundle) |
| Цена | — | вторая машина, порядок установки, bundle между ними |

**Один сервер** — команда выше, больше ничего не нужно.

**Два сервера.** Сначала издатель:

```sh
# машина A (издатель)
./install-citadel-server.sh vX.Y.Z --role issuer --issuer-port 7300
```

Он напечатает **bundle** (`KEY=VALUE`: адрес, TLS-pin, PQ-обязательство, obfs-PSK, seed'ы абонента
и админа). Bundle — секрет уровня «доступ к сервису»: копировать `scp`, а не мессенджером, и
удалить после установки. Дальше exit:

```sh
# машина B (exit): положить bundle в issuer.env
./install-citadel-server.sh vX.Y.Z --role exit --issuer-bundle issuer.env
```

Ссылки печатает **машина B** — только у неё есть cert-pin и ML-DSA-ключ туннеля. Реестр абонентов и
`admin_id` остаются на **машине A**: выдача и отзыв идут туда (через туннель, как обычно).

Что нужно от firewall в этой схеме:

* на машине A: `--issuer-port` открыт для клиентов; `--admin-port` — **только** для адреса машины B
  (`ufw allow from <IP_EXIT> to any port <admin-port> proto tcp`). С аудита-4 (L-14) это не только
  инструкция: `--admin-peer <IP машины B>` **обязателен** при `--role issuer`, и сам издатель
  закрывает чужие адреса до TLS. Открыть всем осознанно — `--admin-peer any`;
* на машине B: `--udp-port` и `--tcp-port` для клиентов; входящих от издателя не требуется —
  `citadel-keysync` ходит исходящим соединением сам.

Установка exit'а не завершится «успешно» вслепую: она ждёт первую синхронизацию ключа эпохи с
издателем и падает с понятной причиной, если порт закрыт, PSK не совпал или pin/обязательство не те.

> Bundle издателя после аудита-4 несёт два новых поля — `CITADEL_KEYSYNC_SEED` (идентичность
> exit'а для получения секретного ключа эпохи) и `CITADEL_OBFS_MASTER` (мастер L1). Bundle,
> снятый с прежней версии, для новой установки не годится — сними его заново на машине A.

#### Если сервер скомпрометирован

Узел спроектирован **расходным**: восстановление — это переустановка, а не «чистка». Повторный
запуск установщика меняет всю идентичность (obfs-PSK, cert-pin, ML-DSA, ключи издателя), прежние
ссылки после этого мертвы — нужно раздать новые. Записанный ранее трафик расшифровать нельзя:
сессионные ключи эфемерны, а ключ подписи токенов живёт только в памяти издателя и ротируется
каждую эпоху. Разбор того, что даёт украденный диск и почему шифрование каталога ключей помогает
не от всего, — [`docs/SERVER-KEY-PROTECTION.md`](SERVER-KEY-PROTECTION.md).
