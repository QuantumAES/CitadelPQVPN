#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Сборка и упаковка КЛИЕНТОВ CitadelPQVPN (Android APK + Linux desktop-бандл) в релиз.
#
# Дополняет tools/mk-release.sh (серверные бинари) клиентскими артефактами того же релиза:
#   - CitadelPQVPN-<version>.apk            — Android (fat APK, все ABI; debug-подпись, см. NB);
#   - citadel-desktop-linux-<arch>.tar.zst  — Linux: flutter-бандл + citadel-helper + polkit
#     .policy + самодостаточный install.sh (ставит helper/polkit/app одной командой).
# Складывает в dist/<version>/, пере-генерит sha256sums по ВСЕМ артефактам (сервер+клиент) и
# подписывает релизным minisign-ключом (как mk-release.sh). Публикация — tools/publish-release.sh.
#
#   tools/mk-client-release.sh [version] [--no-sign]
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
ARGS=()
for a in "$@"; do
  case "$a" in
    --no-sign) NO_SIGN=1 ;;
    --no-apk)  NO_APK=1 ;;   # только Linux-бандл (машина без Android SDK / экономия памяти)
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

# самодостаточный установщик внутри тарбола
cat > "$STAGE/install.sh" <<'INSTALL'
#!/usr/bin/env bash
# Установка Linux-клиента CitadelPQVPN из этого бандла:
#   helper → /usr/lib/citadel-pqvpn/ (root:root 755); polkit-политика; app → /opt/citadel-pqvpn/.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER_DIR=/usr/lib/citadel-pqvpn
POLICY=/usr/share/polkit-1/actions/dev.citadelpqvpn.helper.policy
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

log "App-бандл → $APP_DIR…"
$SUDO rm -rf "$APP_DIR"
$SUDO cp -r "$HERE/bundle" "$APP_DIR"
$SUDO tee /usr/share/applications/citadel-pqvpn.desktop >/dev/null <<DESKTOP
[Desktop Entry]
Type=Application
Name=CitadelPQVPN
Comment=Постквантовый VPN
Exec=$APP_DIR/app
Icon=network-vpn
Categories=Network;
Terminal=false
DESKTOP

echo
log "Готово. Запуск: $APP_DIR/app (или меню «CitadelPQVPN»). polkit спросит пароль один раз."
INSTALL
chmod +x "$STAGE/install.sh"

echo "[mk-client] упаковка Linux-бандла → citadel-desktop-linux-$SUFFIX.tar.zst…"
tar -C "$STAGE_ROOT" -cf - "citadel-desktop-linux-$SUFFIX" \
  | zstd -q -19 -f -o "$OUT/citadel-desktop-linux-$SUFFIX.tar.zst"
rm -rf "$STAGE_ROOT"
printf '  %-34s %s\n' "citadel-desktop-linux-$SUFFIX.tar.zst" "$(du -h "$OUT/citadel-desktop-linux-$SUFFIX.tar.zst" | cut -f1)"

# ── 3. Android APK (fat, все ABI) ──
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

# ── 4. sha256sums по ВСЕМ артефактам релиза (сервер .zst + клиент .tar.zst/.apk) + подпись ──
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
  CitadelPQVPN-$VERSION.apk, citadel-desktop-linux-$SUFFIX.tar.zst
Публикация в GitHub Release: tools/publish-release.sh $VERSION
EOF
