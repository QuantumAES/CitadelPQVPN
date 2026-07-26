#!/usr/bin/env bash
# =============================================================================
# CitadelPQVPN — установка консольного клиента Linux (трек L).
#
# Ставит три компонента с разными правами — в этом вся модель безопасности:
#   /usr/lib/citadel-pqvpn/citadel-vpnd    root, systemd-юнит  — плумбер: TUN/маршруты/kill-switch
#   /usr/lib/citadel-pqvpn/citadel-engine  uid citadel-vpn     — движок: весь недоверенный ввод
#   /usr/bin/citadel-cli                   обычный юзер        — TUI, хранилище профилей
#
# Создаёт системного пользователя и группу citadel-vpn. В группу НИКОГО не добавляет:
# её член может управлять маршрутизацией всей машины (см. L3 в docs/LINUX-CLI.md) — это
# осознанное решение администратора, а не побочный эффект установки.
#
# Запуск:  ./tools/install-cli.sh [--no-build] [--user ИМЯ]
#   --no-build   не собирать, взять готовые бинари из target/release
#   --user ИМЯ   сразу добавить пользователя ИМЯ в группу citadel-vpn
# =============================================================================
set -euo pipefail

LIB_DIR=/usr/lib/citadel-pqvpn
BIN_DIR=/usr/bin
UNIT_DIR=/etc/systemd/system
SVC_USER=citadel-vpn
SVC_GROUP=citadel-vpn
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BUILD=1
ADD_USER=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-build) BUILD=0 ;;
    --user) ADD_USER="${2:-}"; shift ;;
    *) echo "неизвестный аргумент: $1" >&2; exit 1 ;;
  esac
  shift
done

SUDO=""
[[ "${EUID}" -eq 0 ]] || SUDO="sudo"
log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

# 1. runtime-зависимости
log "Runtime-зависимости (iproute2, iptables)…"
if command -v apt-get >/dev/null; then
  $SUDO apt-get update -qq
  $SUDO apt-get install -y -qq iproute2 iptables
else
  echo "  apt-get не найден — поставь вручную: iproute2 iptables" >&2
fi

# 2. сборка
if [[ "$BUILD" -eq 1 ]]; then
  log "Сборка (release): citadel-vpnd, citadel-engine, citadel-cli…"
  ( cd "$REPO" && cargo build --release -p citadel-vpnd -p citadel-engine -p citadel-cli )
fi
for b in citadel-vpnd citadel-engine citadel-cli; do
  [[ -x "$REPO/target/release/$b" ]] || { echo "нет $REPO/target/release/$b — собери без --no-build" >&2; exit 1; }
done

# 3. системные пользователь и группа
if ! getent group "$SVC_GROUP" >/dev/null; then
  log "Создаю группу $SVC_GROUP…"
  $SUDO groupadd --system "$SVC_GROUP"
fi
if ! getent passwd "$SVC_USER" >/dev/null; then
  log "Создаю системного пользователя $SVC_USER (без домашнего каталога и без шелла)…"
  $SUDO useradd --system --gid "$SVC_GROUP" --no-create-home \
                --home-dir /nonexistent --shell /usr/sbin/nologin "$SVC_USER"
fi

# 4. бинари (root:root, никаких setuid — привилегии даёт systemd, а не бит на файле)
log "Установка бинарей…"
$SUDO install -d -m 755 "$LIB_DIR"
$SUDO install -m 755 -o root -g root "$REPO/target/release/citadel-vpnd"   "$LIB_DIR/citadel-vpnd"
$SUDO install -m 755 -o root -g root "$REPO/target/release/citadel-engine" "$LIB_DIR/citadel-engine"
$SUDO install -m 755 -o root -g root "$REPO/target/release/citadel-cli"    "$BIN_DIR/citadel-cli"

# 5. юниты
log "Установка systemd-юнитов…"
$SUDO install -m 644 -o root -g root "$REPO/packaging/linux/citadel-vpnd.service"     "$UNIT_DIR/citadel-vpnd.service"
$SUDO install -m 644 -o root -g root "$REPO/packaging/linux/citadel-lockdown.service" "$UNIT_DIR/citadel-lockdown.service"
$SUDO systemctl daemon-reload
$SUDO systemctl enable citadel-vpnd.service
# ВАЖНО, апгрейд: `enable --now` на УЖЕ запущенном юните — no-op (`start` активный юнит не
# трогает), а `daemon-reload` не перечитывает песочницу работающего процесса. То есть после
# обновления в системе продолжал жить СТАРЫЙ демон: старый бинарь и старый `ProtectSystem`
# без `ReadWritePaths=/etc`. Ровно так «уже исправленный» EROFS на /etc/resolv.conf валил
# сессию у пользователя, у которого фикс давно стоял на диске. Поэтому — безусловный restart.
# Активную сессию он рвёт, но чисто: по SIGTERM демон снимает kill-switch (teardown clean).
if $SUDO systemctl is-active --quiet citadel-vpnd.service; then
  log "Демон уже работает — перезапускаю на новую версию (активная сессия будет разорвана)…"
fi
$SUDO systemctl restart citadel-vpnd.service

# 6. доступ пользователю (только по явной просьбе)
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
