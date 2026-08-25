#!/usr/bin/env bash
# =============================================================================
# CitadelPQVPN — установка desktop-компонентов (для тестовой QEMU-VM или реальной машины).
#
# Ставит:
#   - runtime-зависимости (iproute2, iptables, polkit);
#   - привилегированный citadel-helper → /usr/lib/citadel-pqvpn/ (root:root 755);
#   - polkit-политику (кастомный action, exec.path → helper, auth_admin_keep);
#   - polkit-правило «без пароля для группы citadel-vpn» (отключается --ask-password);
#   - опционально (--with-app) app-бандл → /opt/citadel-pqvpn/ + .desktop launcher.
#
# Запуск: от обычного пользователя (apt/install через sudo) ИЛИ от root.
#   ./tools/install-desktop.sh [--with-app] [--user ИМЯ] [--ask-password]
#
#   --user ИМЯ       добавить пользователя в группу citadel-vpn (нужен перелогин)
#   --ask-password   НЕ ставить правило «без пароля»: polkit будет спрашивать пароль
#                    администратора на каждое поднятие туннеля, включая реконнекты
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
RULES=/etc/polkit-1/rules.d/49-citadel-pqvpn.rules
CTL_GROUP=citadel-vpn
APP_DIR=/opt/citadel-pqvpn
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

WITH_APP=0
PASSWORDLESS=1
ADD_USER=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-app)     WITH_APP=1 ;;
    --ask-password) PASSWORDLESS=0 ;;
    --user)         ADD_USER="${2:-}"; shift ;;
    *)              echo "неизвестный аргумент: $1" >&2; exit 2 ;;
  esac
  shift
done

SUDO=""
[[ "${EUID}" -eq 0 ]] || SUDO="sudo"
log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

# Сбросить кеши меню и темы иконок.
#
# Почему обязательно `-f`: без него `gtk-update-icon-cache` отказывается работать, когда в теме нет
# `index.theme`, и молча оставляет СТАРЫЙ `icon-theme.cache`. А GTK, увидев кеш, файлы на диске уже
# не читает — новая иконка не появляется ни в меню, ни на рабочем столе, хотя лежит на месте
# (ровно этот симптом ловили после обновления клиента).
refresh_desktop_caches() {
  $SUDO gtk-update-icon-cache -f -t -q /usr/share/icons/hicolor 2>/dev/null || true
  command -v xdg-icon-resource >/dev/null && $SUDO xdg-icon-resource forceupdate --theme hicolor 2>/dev/null || true
  command -v update-desktop-database >/dev/null && $SUDO update-desktop-database /usr/share/applications 2>/dev/null || true
  # KDE держит свой сводный кеш меню; без пересборки запись остаётся с прежней иконкой.
  for kb in kbuildsycoca6 kbuildsycoca5; do
    command -v "$kb" >/dev/null && "$kb" --noincremental >/dev/null 2>&1 && break
  done
  true
}

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

# 3b. правило «без пароля для группы citadel-vpn».
# Без него polkit спрашивает пароль на КАЖДОЕ поднятие туннеля, в том числе на автоматических
# реконнектах — для VPN-клиента это нерабочий сценарий. Право управлять туннелем при этом не
# «раздаётся всем»: его даёт членство в группе, ровно как у консольного клиента (сокет демона).
if [[ "$PASSWORDLESS" -eq 1 ]]; then
  if ! getent group "$CTL_GROUP" >/dev/null; then
    log "Создание группы $CTL_GROUP…"
    $SUDO groupadd --system "$CTL_GROUP"
  fi
  log "Установка polkit-правила → $RULES (без пароля для группы $CTL_GROUP)…"
  $SUDO install -d -m 755 "$(dirname "$RULES")"
  $SUDO install -m 644 -o root -g root "$REPO/packaging/49-citadel-pqvpn.rules" "$RULES"
else
  log "Правило «без пароля» НЕ ставится (--ask-password): polkit будет спрашивать пароль."
  $SUDO rm -f "$RULES"
fi

if [[ -n "$ADD_USER" ]]; then
  if id "$ADD_USER" >/dev/null 2>&1; then
    log "Добавляю $ADD_USER в группу $CTL_GROUP…"
    $SUDO usermod -aG "$CTL_GROUP" "$ADD_USER"
    echo "    ВАЖНО: членство в группе появится после ПЕРЕЛОГИНА пользователя $ADD_USER."
  else
    echo "  пользователя $ADD_USER нет — пропускаю добавление в группу" >&2
  fi
fi

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
      # Запасная копия для окружений, читающих только /usr/share/pixmaps.
      [[ -f "$ICONSRC/256x256/apps/app.png" ]] \
        && $SUDO install -Dm644 "$ICONSRC/256x256/apps/app.png" /usr/share/pixmaps/citadelpqvpn.png
      refresh_desktop_caches
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
# Привязка ОКНА к этому лаунчеру: WM_CLASS приложения = APPLICATION_ID (g_set_prgname в
# linux/runner/my_application.cc). Без строки панель/док показывают запущенному окну
# generic-иконку, хотя в меню иконка уже брендовая.
StartupWMClass=com.quantumaes.citadelpqvpn
EOF
    refresh_desktop_caches
    log "App установлен (запуск: $APP_DIR/app или через меню «CitadelPQVPN»)"
  else
    echo "  app-бандл не найден ($BUNDLE) — собери: cd app && flutter build linux" >&2
  fi
fi

echo
log "Готово."
echo "    helper : $HELPER"
echo "    policy : $POLICY  (action dev.citadelpqvpn.helper)"
if [[ "$PASSWORDLESS" -eq 1 ]]; then
  echo "    rules  : $RULES  (без пароля для группы $CTL_GROUP)"
  echo
  echo "Чтобы GUI не спрашивал пароль, добавьте себя в группу и ПЕРЕЛОГИНЬТЕСЬ:"
  echo "    sudo usermod -aG $CTL_GROUP \$USER"
  echo "Кто не в группе — поднимет туннель по паролю администратора, как раньше."
else
  echo "GUI поднимет туннель через pkexec — polkit будет спрашивать пароль администратора."
fi
