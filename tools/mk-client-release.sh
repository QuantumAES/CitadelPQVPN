#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Сборка и упаковка КЛИЕНТОВ CitadelPQVPN (Android APK + Linux desktop + Linux CLI) в релиз.
#
# Дополняет tools/mk-release.sh (серверные бинари) клиентскими артефактами того же релиза:
#   - CitadelPQVPN-<version>.apk            — Android (fat APK, все ABI; debug-подпись, см. NB);
#   - citadel-desktop-linux-<arch>.tar.zst  — Linux GUI: flutter-бандл + citadel-helper + polkit
#     .policy + самодостаточный install.sh (ставит helper/polkit/app одной командой);
#   - citadel-cli-linux-<arch>.tar.zst      — Linux консольный клиент (трек L): citadel-vpnd +
#     citadel-engine + citadel-cli + systemd-юниты + install.sh (аналог tools/install-cli.sh,
#     но ставит из бандла, без cargo и без исходников на целевой машине).
# Складывает в dist/<version>/, пере-генерит sha256sums по ВСЕМ артефактам (сервер+клиент) и
# подписывает релизным minisign-ключом (как mk-release.sh). Публикация — tools/publish-release.sh.
#
#   tools/mk-client-release.sh [version] [--no-sign] [--no-apk] [--no-cli]
#
# Env: FLUTTER=/path/to/flutter/bin/flutter (по умолч. ~/flutter/bin/flutter),
#      CITADEL_RELEASE_KEY_DIR (секрет minisign), CITADEL_RELEASE_PUB (self-verify).
#
# NB (подпись APK): сейчас Gradle подписывает release debug-ключом (app/android/app/build.gradle.kts).
# Для pre это ок (переустановка поверх работает на той же машине сборки), но источник «не проверен».
# Доверенный источник — release-keystore (follow-up).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

NO_SIGN=0
NO_APK=0
NO_CLI=0
ARGS=()
for a in "$@"; do
  case "$a" in
    --no-sign) NO_SIGN=1 ;;
    --no-apk)  NO_APK=1 ;;   # только Linux-бандл (машина без Android SDK / экономия памяти)
    --no-cli)  NO_CLI=1 ;;   # без консольного клиента (трек L)
    *) ARGS+=("$a") ;;
  esac
done
VERSION="${ARGS[0]:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"

FLUTTER="${FLUTTER:-$HOME/flutter/bin/flutter}"
SEC="${CITADEL_RELEASE_KEY_DIR:-$HOME/.citadel/release}/citadel-release.key"
PUB="${CITADEL_RELEASE_PUB:-$REPO_ROOT/packaging/release/citadel-release.pub}"
OUT="$REPO_ROOT/dist/$VERSION"

die() { printf 'ОШИБКА: %s\n' "$*" >&2; exit 1; }
[[ -x "$FLUTTER" ]] || die "flutter не найден: $FLUTTER (задай FLUTTER=/путь/к/flutter/bin/flutter)"
for t in cargo zstd sha256sum tar; do command -v "$t" >/dev/null 2>&1 || die "$t не установлен"; done

case "$(uname -m)" in
  x86_64|amd64)  SUFFIX=x86_64 ;;
  aarch64|arm64) SUFFIX=aarch64 ;;
  *) die "неподдерживаемая арка: $(uname -m)" ;;
esac

echo "[mk-client] version=$VERSION arch=$SUFFIX out=$OUT flutter=$FLUTTER"
mkdir -p "$OUT"

# ── 1. привилегированный хелпер (release) ──
echo "[mk-client] сборка citadel-helper (release)…"
cargo build --release -p citadel-helper

# ── 2. Linux desktop-бандл (flutter build linux) ──
echo "[mk-client] flutter build linux --release…"
( cd "$REPO_ROOT/app" && "$FLUTTER" build linux --release --dart-define=CITADEL_VERSION="$VERSION" )
BUNDLE="$REPO_ROOT/app/build/linux/x64/release/bundle"
[[ -d "$BUNDLE" ]] || die "нет linux-бандла: $BUNDLE"

STAGE_ROOT="$(mktemp -d)"
STAGE="$STAGE_ROOT/citadel-desktop-linux-$SUFFIX"
mkdir -p "$STAGE"
cp -r "$BUNDLE" "$STAGE/bundle"
cp "$REPO_ROOT/target/release/citadel-helper" "$STAGE/citadel-helper"
cp "$REPO_ROOT/packaging/dev.citadelpqvpn.helper.policy" "$STAGE/dev.citadelpqvpn.helper.policy"
cp "$REPO_ROOT/packaging/49-citadel-pqvpn.rules" "$STAGE/49-citadel-pqvpn.rules"
# П.5: брендовые иконки (hicolor) в тарбол — install.sh поставит их в /usr/share/icons/hicolor.
if [[ -d "$REPO_ROOT/app_icons/Linux" ]]; then
  for sz in 16 24 32 48 64 128 256 512; do
    isrc="$REPO_ROOT/app_icons/Linux/${sz}x${sz}/apps/app.png"
    [[ -f "$isrc" ]] && install -Dm644 "$isrc" "$STAGE/icons/hicolor/${sz}x${sz}/apps/citadelpqvpn.png"
  done
fi

# самодостаточный установщик внутри тарбола
cat > "$STAGE/install.sh" <<'INSTALL'
#!/usr/bin/env bash
# Установка Linux-клиента CitadelPQVPN из этого бандла:
#   helper → /usr/lib/citadel-pqvpn/ (root:root 755); polkit-политика; app → /opt/citadel-pqvpn/.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER_DIR=/usr/lib/citadel-pqvpn
POLICY=/usr/share/polkit-1/actions/dev.citadelpqvpn.helper.policy
RULES=/etc/polkit-1/rules.d/49-citadel-pqvpn.rules
CTL_GROUP=citadel-vpn
APP_DIR=/opt/citadel-pqvpn
SUDO=""; [[ "${EUID}" -eq 0 ]] || SUDO="sudo"
log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

log "Runtime-зависимости (iproute2, iptables, polkit/pkexec)…"
if command -v apt-get >/dev/null; then
  $SUDO apt-get update -qq
  $SUDO apt-get install -y -qq iproute2 iptables
  $SUDO apt-get install -y -qq pkexec || $SUDO apt-get install -y -qq policykit-1 || true
else
  echo "  поставь вручную: iproute2 iptables policykit-1(pkexec)" >&2
fi

log "Хелпер → $HELPER_DIR/citadel-helper (root:root 755)…"
$SUDO install -d -m 755 "$HELPER_DIR"
$SUDO install -m 755 -o root -g root "$HERE/citadel-helper" "$HELPER_DIR/citadel-helper"

log "polkit-политика → $POLICY…"
$SUDO install -m 644 -o root -g root "$HERE/dev.citadelpqvpn.helper.policy" "$POLICY"

# Правило «без пароля для группы citadel-vpn»: иначе polkit просит пароль на каждое поднятие
# туннеля, включая автоматические реконнекты. Право управлять VPN даёт членство в группе —
# та же модель, что у консольного клиента. В группу установщик НИКОГО не добавляет.
log "polkit-правило → $RULES (без пароля для группы $CTL_GROUP)…"
getent group "$CTL_GROUP" >/dev/null || $SUDO groupadd --system "$CTL_GROUP"
$SUDO install -d -m 755 "$(dirname "$RULES")"
$SUDO install -m 644 -o root -g root "$HERE/49-citadel-pqvpn.rules" "$RULES"

log "App-бандл → $APP_DIR…"
$SUDO rm -rf "$APP_DIR"
$SUDO cp -r "$HERE/bundle" "$APP_DIR"
# П.5: брендовые иконки (hicolor) из тарбола → системная тема.
if [[ -d "$HERE/icons/hicolor" ]]; then
  $SUDO cp -r "$HERE/icons/hicolor/." /usr/share/icons/hicolor/
  $SUDO gtk-update-icon-cache -q /usr/share/icons/hicolor 2>/dev/null || true
fi
$SUDO tee /usr/share/applications/citadel-pqvpn.desktop >/dev/null <<DESKTOP
[Desktop Entry]
Type=Application
Name=CitadelPQVPN
Comment=Постквантовый VPN
Exec=$APP_DIR/app
Icon=citadelpqvpn
Categories=Network;
Terminal=false
DESKTOP

echo
echo
log "Готово. Запуск: $APP_DIR/app (или меню «CitadelPQVPN»)."
echo "Чтобы туннель поднимался без запроса пароля, добавьте себя в группу и ПЕРЕЛОГИНЬТЕСЬ:"
echo "    sudo usermod -aG $CTL_GROUP \$USER"
echo "Без группы всё работает, но polkit будет спрашивать пароль администратора."
INSTALL
chmod +x "$STAGE/install.sh"

echo "[mk-client] упаковка Linux-бандла → citadel-desktop-linux-$SUFFIX.tar.zst…"
tar -C "$STAGE_ROOT" -cf - "citadel-desktop-linux-$SUFFIX" \
  | zstd -q -19 -f -o "$OUT/citadel-desktop-linux-$SUFFIX.tar.zst"
rm -rf "$STAGE_ROOT"
printf '  %-34s %s\n' "citadel-desktop-linux-$SUFFIX.tar.zst" "$(du -h "$OUT/citadel-desktop-linux-$SUFFIX.tar.zst" | cut -f1)"

# ── 3. Linux консольный клиент (трек L): vpnd + engine + cli + юниты ──
# Тарбол самодостаточен: на целевой машине не нужны ни cargo, ни исходники — install.sh лишь
# раскладывает бинари по правам (root / uid citadel-vpn / пользователь) и включает юнит.
if [[ "$NO_CLI" -eq 1 ]]; then
  echo "[mk-client] --no-cli: консольный клиент пропущен."
else
  echo "[mk-client] сборка citadel-vpnd + citadel-engine + citadel-cli (release)…"
  cargo build --release -p citadel-vpnd -p citadel-engine -p citadel-cli

  CLI_ROOT="$(mktemp -d)"
  CLI_STAGE="$CLI_ROOT/citadel-cli-linux-$SUFFIX"
  mkdir -p "$CLI_STAGE"
  for b in citadel-vpnd citadel-engine citadel-cli; do
    [[ -x "$REPO_ROOT/target/release/$b" ]] || die "нет бинаря: target/release/$b"
    cp "$REPO_ROOT/target/release/$b" "$CLI_STAGE/$b"
  done
  cp "$REPO_ROOT/packaging/linux/citadel-vpnd.service"     "$CLI_STAGE/citadel-vpnd.service"
  cp "$REPO_ROOT/packaging/linux/citadel-lockdown.service" "$CLI_STAGE/citadel-lockdown.service"

  cat > "$CLI_STAGE/install.sh" <<'CLIINSTALL'
#!/usr/bin/env bash
# Установка КОНСОЛЬНОГО клиента CitadelPQVPN (трек L) из этого бандла.
#
# Три компонента с разными правами — в этом вся модель безопасности (docs/LINUX-CLI.md):
#   /usr/lib/citadel-pqvpn/citadel-vpnd    root, systemd-юнит  — плумбер: TUN/маршруты/kill-switch
#   /usr/lib/citadel-pqvpn/citadel-engine  uid citadel-vpn     — движок: весь недоверенный ввод
#   /usr/bin/citadel-cli                   обычный юзер        — TUI, хранилище профилей
#
# Создаёт системного пользователя и группу citadel-vpn, но В ГРУППУ НИКОГО НЕ ДОБАВЛЯЕТ: её член
# управляет маршрутизацией всей машины (L3) — это решение администратора, а не побочный эффект
# установки.  Запуск:  ./install.sh [--user ИМЯ]
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR=/usr/lib/citadel-pqvpn
BIN_DIR=/usr/bin
UNIT_DIR=/etc/systemd/system
SVC_USER=citadel-vpn
SVC_GROUP=citadel-vpn

ADD_USER=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --user) ADD_USER="${2:-}"; shift ;;
    *) echo "неизвестный аргумент: $1" >&2; exit 1 ;;
  esac
  shift
done

SUDO=""; [[ "${EUID}" -eq 0 ]] || SUDO="sudo"
log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

log "Runtime-зависимости (iproute2, iptables)…"
if command -v apt-get >/dev/null; then
  $SUDO apt-get update -qq
  $SUDO apt-get install -y -qq iproute2 iptables
else
  echo "  apt-get не найден — поставь вручную: iproute2 iptables" >&2
fi

if ! getent group "$SVC_GROUP" >/dev/null; then
  log "Создаю группу $SVC_GROUP…"
  $SUDO groupadd --system "$SVC_GROUP"
fi
if ! getent passwd "$SVC_USER" >/dev/null; then
  log "Создаю системного пользователя $SVC_USER (без домашнего каталога и без шелла)…"
  $SUDO useradd --system --gid "$SVC_GROUP" --no-create-home \
                --home-dir /nonexistent --shell /usr/sbin/nologin "$SVC_USER"
fi

log "Установка бинарей (root:root, без setuid — привилегии даёт systemd, а не бит на файле)…"
$SUDO install -d -m 755 "$LIB_DIR"
$SUDO install -m 755 -o root -g root "$HERE/citadel-vpnd"   "$LIB_DIR/citadel-vpnd"
$SUDO install -m 755 -o root -g root "$HERE/citadel-engine" "$LIB_DIR/citadel-engine"
$SUDO install -m 755 -o root -g root "$HERE/citadel-cli"    "$BIN_DIR/citadel-cli"

log "Установка systemd-юнитов…"
$SUDO install -m 644 -o root -g root "$HERE/citadel-vpnd.service"     "$UNIT_DIR/citadel-vpnd.service"
$SUDO install -m 644 -o root -g root "$HERE/citadel-lockdown.service" "$UNIT_DIR/citadel-lockdown.service"
$SUDO systemctl daemon-reload
$SUDO systemctl enable --now citadel-vpnd.service

if [[ -n "$ADD_USER" ]]; then
  log "Добавляю $ADD_USER в группу $SVC_GROUP…"
  $SUDO usermod -aG "$SVC_GROUP" "$ADD_USER"
  echo "    Членство вступит в силу после перелогина (или: newgrp $SVC_GROUP)."
fi

cat <<EOF

Готово. Демон: systemctl status citadel-vpnd

Дальше:
  1. дайте себе право управлять туннелем:
       sudo usermod -aG $SVC_GROUP \$USER   # затем перелогиньтесь
     ВНИМАНИЕ: член этой группы управляет маршрутизацией всей машины — добавляйте
     только тех, кому доверяете как администратору сети (docs/LINUX-CLI.md, L3).
  2. запустите настройку:      citadel-cli
  3. журнал демона:            journalctl -u citadel-vpnd -f

Режим «без утечек при загрузке» (по умолчанию выключен, читайте ограничения в юните):
     sudo systemctl enable --now citadel-lockdown.service
EOF
CLIINSTALL
  chmod +x "$CLI_STAGE/install.sh"

  echo "[mk-client] упаковка консольного клиента → citadel-cli-linux-$SUFFIX.tar.zst…"
  tar -C "$CLI_ROOT" -cf - "citadel-cli-linux-$SUFFIX" \
    | zstd -q -19 -f -o "$OUT/citadel-cli-linux-$SUFFIX.tar.zst"
  rm -rf "$CLI_ROOT"
  printf '  %-34s %s\n' "citadel-cli-linux-$SUFFIX.tar.zst" "$(du -h "$OUT/citadel-cli-linux-$SUFFIX.tar.zst" | cut -f1)"
fi

# ── 4. Android APK (fat, все ABI) ──
if [[ "$NO_APK" -eq 1 ]]; then
  echo "[mk-client] --no-apk: сборка APK пропущена (Linux-бандл собран)."
else
  echo "[mk-client] flutter build apk --release…"
  ( cd "$REPO_ROOT/app" && "$FLUTTER" build apk --release --dart-define=CITADEL_VERSION="$VERSION" )
  APK="$REPO_ROOT/app/build/app/outputs/flutter-apk/app-release.apk"
  [[ -f "$APK" ]] || die "нет APK: $APK"
  cp "$APK" "$OUT/CitadelPQVPN-$VERSION.apk"
  printf '  %-34s %s\n' "CitadelPQVPN-$VERSION.apk" "$(du -h "$OUT/CitadelPQVPN-$VERSION.apk" | cut -f1)"
fi

# ── 5. sha256sums по ВСЕМ артефактам релиза (сервер .zst + клиент .tar.zst/.apk) + подпись ──
cd "$OUT"
shopt -s nullglob
sha256sum ./*.zst ./*.apk 2>/dev/null | sed 's#\./##' > sha256sums
shopt -u nullglob
echo "[mk-client] sha256sums:"; sed 's/^/  /' sha256sums

if [[ "$NO_SIGN" -eq 1 ]]; then
  echo "[mk-client] --no-sign: подпись пропущена. Подпиши перед публикацией:"
  echo "    minisign -S -s \"$SEC\" -m \"$OUT/sha256sums\" -t \"CitadelPQVPN $VERSION clients\""
else
  [[ -f "$SEC" ]] || die "секрет релиза не найден: $SEC (или запусти с --no-sign и подпиши сам)"
  [[ -f "$PUB" ]] || die "публичный ключ не найден: $PUB"
  echo "[mk-client] подпись sha256sums релизным ключом (minisign может спросить пароль)…"
  minisign -S -s "$SEC" -m sha256sums \
    -t "CitadelPQVPN $VERSION $SUFFIX clients $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "[mk-client] self-verify публичным ключом…"
  minisign -V -p "$PUB" -m sha256sums
fi

cat <<EOF

=== ГОТОВО: клиенты в $OUT ===
  CitadelPQVPN-$VERSION.apk, citadel-desktop-linux-$SUFFIX.tar.zst,
  citadel-cli-linux-$SUFFIX.tar.zst
Публикация в GitHub Release: tools/publish-release.sh $VERSION
EOF
