#!/usr/bin/env bash
# =============================================================================
# CitadelPQVPN — установка desktop-компонентов (для тестовой QEMU-VM или реальной машины).
#
# Ставит:
#   - runtime-зависимости (iproute2, iptables, polkit);
#   - привилегированный citadel-helper → /usr/lib/citadel-pqvpn/ (root:root 755);
#   - polkit-политику (кастомный action, exec.path → helper, auth_admin_keep);
#   - опционально (--with-app) app-бандл → /opt/citadel-pqvpn/ + .desktop launcher.
#
# Запуск: от обычного пользователя (apt/install через sudo) ИЛИ от root.
#   ./tools/install-desktop.sh [--with-app]
#
# citadel-helper берётся из target/release (если собран) — иначе собирается `cargo`
# (нужен Rust-тулчейн). Для clean-VM без Rust: собери на dev-хосте
#   cargo build --release -p citadel-helper
# и скопируй target/release/citadel-helper в репозиторий внутри VM перед запуском.
# =============================================================================
set -euo pipefail

HELPER_DIR=/usr/lib/citadel-pqvpn
HELPER="$HELPER_DIR/citadel-helper"
POLICY=/usr/share/polkit-1/actions/dev.citadelpqvpn.helper.policy
APP_DIR=/opt/citadel-pqvpn
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

WITH_APP=0
for a in "$@"; do [[ "$a" == "--with-app" ]] && WITH_APP=1; done

SUDO=""
[[ "${EUID}" -eq 0 ]] || SUDO="sudo"
log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

# 1. runtime-зависимости
log "Runtime-зависимости (iproute2, iptables, polkit)…"
if command -v apt-get >/dev/null; then
  $SUDO apt-get update -qq
  $SUDO apt-get install -y -qq iproute2 iptables
  # polkit/pkexec: имя пакета разнится (trixie: pkexec+polkitd; bookworm: policykit-1)
  $SUDO apt-get install -y -qq pkexec || $SUDO apt-get install -y -qq policykit-1
else
  echo "  apt-get не найден — поставь вручную: iproute2 iptables policykit-1(pkexec)" >&2
fi

# 2. citadel-helper (prebuilt или собрать)
BIN="$REPO/target/release/citadel-helper"
if [[ ! -x "$BIN" ]]; then
  if command -v cargo >/dev/null; then
    log "Сборка citadel-helper (release)…"
    ( cd "$REPO" && cargo build --release -p citadel-helper )
  else
    echo "Нет $BIN и нет cargo — собери на dev-хосте: cargo build --release -p citadel-helper" >&2
    exit 1
  fi
fi
log "Установка хелпера → $HELPER (root:root 755)…"
$SUDO install -d -m 755 "$HELPER_DIR"
$SUDO install -m 755 -o root -g root "$BIN" "$HELPER"

# 3. polkit-политика
log "Установка polkit-политики → $POLICY…"
$SUDO install -m 644 -o root -g root "$REPO/packaging/dev.citadelpqvpn.helper.policy" "$POLICY"

# 4. опционально app-бандл + .desktop
if [[ "$WITH_APP" -eq 1 ]]; then
  BUNDLE="$REPO/app/build/linux/x64/release/bundle"
  [[ -d "$BUNDLE" ]] || BUNDLE="$REPO/app/build/linux/x64/debug/bundle"
  if [[ -d "$BUNDLE" ]]; then
    log "Установка app-бандла → $APP_DIR…"
    $SUDO rm -rf "$APP_DIR"
    $SUDO cp -r "$BUNDLE" "$APP_DIR"
    # П.5: брендовая иконка (hicolor) из app_icons/Linux — все размеры как citadelpqvpn.png.
    ICONSRC="$REPO/app_icons/Linux"
    if [[ -d "$ICONSRC" ]]; then
      for sz in 16 24 32 48 64 128 256 512; do
        src="$ICONSRC/${sz}x${sz}/apps/app.png"
        [[ -f "$src" ]] && $SUDO install -Dm644 "$src" "/usr/share/icons/hicolor/${sz}x${sz}/apps/citadelpqvpn.png"
      done
      $SUDO gtk-update-icon-cache -q /usr/share/icons/hicolor 2>/dev/null || true
    fi
    $SUDO tee /usr/share/applications/citadel-pqvpn.desktop >/dev/null <<EOF
[Desktop Entry]
Type=Application
Name=CitadelPQVPN
Comment=Постквантовый VPN
Exec=$APP_DIR/app
Icon=citadelpqvpn
Categories=Network;
Terminal=false
EOF
    log "App установлен (запуск: $APP_DIR/app или через меню «CitadelPQVPN»)"
  else
    echo "  app-бандл не найден ($BUNDLE) — собери: cd app && flutter build linux" >&2
  fi
fi

echo
log "Готово."
echo "    helper : $HELPER"
echo "    policy : $POLICY  (action dev.citadelpqvpn.helper)"
echo "GUI поднимет туннель через pkexec — polkit спросит пароль один раз (auth_admin_keep)."
