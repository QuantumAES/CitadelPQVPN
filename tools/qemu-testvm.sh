#!/usr/bin/env bash
# =============================================================================
# CitadelPQVPN — провижининг QEMU/KVM тестовой VM для привилегированного E2E
# десктоп-клиента (создание TUN + polkit + туннель). Хост без CAP_NET_ADMIN —
# поэтому привилегированный путь проверяем здесь, в одноразовой VM со снапшотом.
#
# Что делает:
#   - поднимает Debian-generic + xfce через startx (KVM, окно через -display gtk;
#     БЕЗ display manager — на cloud-образе lightdm уходил в restart-loop);
#   - шарит репозиторий по virtio-9p (готовые артефакты с хоста — Rust/Flutter в VM НЕ нужны);
#   - в VM ставишь клиент: sudo /mnt/citadel/tools/install-desktop.sh --with-app.
#
# Использование:
#   tools/qemu-testvm.sh setup     # deps + сборка хелпера + образ + диск + cloud-init
#   tools/qemu-testvm.sh run       # запуск VM (окно QEMU)
#   tools/qemu-testvm.sh snapshot  # сделать снапшот диска (qcow2) перед инвазивным тестом
#
# В VM (xfce-терминал; логин citadel/citadel, autologin):
#   sudo /mnt/citadel/tools/install-desktop.sh --with-app
#   /opt/citadel-pqvpn/app                 # запустить GUI (или меню «CitadelPQVPN»)
# Exit для подключения: запусти на ХОСТЕ exit с публикацией портов; в VM (user-net)
#   хост доступен как 10.0.2.2 — ссылка citadel:// должна указывать на 10.0.2.2:<порт>.
# =============================================================================
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VM_DIR="${CITADEL_VM_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/citadel-testvm}"
# ВАЖНО: 'generic' (полное ядро linux-image-amd64), НЕ 'genericcloud' —
# cloud-ядро собрано без 9p (CONFIG_NET_9P off), virtio-9p там не примонтировать.
# trixie (13), НЕ bookworm (12): bookworm несёт GLib 2.74, а Flutter-бандл,
# собранный на хосте (GLib 2.8x), требует g_once_init_enter_pointer (есть с 2.80).
IMG_URL="${CITADEL_VM_IMG:-https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2}"
BASE="$VM_DIR/base.qcow2"
DISK="$VM_DIR/disk.qcow2"
SEED="$VM_DIR/seed.iso"
RAM_MB="${CITADEL_VM_RAM:-4096}"
CPUS="${CITADEL_VM_CPUS:-2}"
DISK_SIZE="${CITADEL_VM_DISK:-20G}"

c_b=$'\033[1;34m'; c_y=$'\033[1;33m'; c_off=$'\033[0m'
log()  { printf '%s==>%s %s\n' "$c_b" "$c_off" "$*"; }
warn() { printf '%swarn%s %s\n' "$c_y" "$c_off" "$*" >&2; }
die()  { printf 'err  %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

check_deps() {
  local miss=()
  for t in qemu-system-x86_64 qemu-img cloud-localds wget; do have "$t" || miss+=("$t"); done
  if [[ ${#miss[@]} -gt 0 ]]; then
    warn "не хватает: ${miss[*]}"
    echo "  поставь: sudo apt-get install -y qemu-system-x86 qemu-utils cloud-image-utils wget" >&2
    die "доустанови зависимости и повтори"
  fi
  [[ -e /dev/kvm ]] || warn "/dev/kvm нет — VM будет медленной (без KVM); добавь себя в группу kvm"
}

build_artifacts() {
  # хелпер (release) собирается на хосте — в VM попадёт через 9p
  if [[ ! -x "$REPO/target/release/citadel-helper" ]]; then
    log "Сборка citadel-helper (release)…"
    ( cd "$REPO" && cargo build --release -p citadel-helper )
  fi
  if [[ ! -d "$REPO/app/build/linux/x64/debug/bundle" && ! -d "$REPO/app/build/linux/x64/release/bundle" ]]; then
    warn "app-бандл не найден — собери на хосте: (cd app && flutter build linux)"
    warn "без бандла install-desktop.sh --with-app не поставит GUI (только хелпер+polkit)"
  fi
}

gen_cloud_init() {
  log "cloud-init (xfce + runtime-deps + autologin + 9p-mount)…"
  mkdir -p "$VM_DIR"
  cat > "$VM_DIR/user-data" <<'YAML'
#cloud-config
hostname: citadel-test
users:
  - name: citadel
    groups: [sudo]
    shell: /bin/bash
    lock_passwd: false
    plain_text_passwd: citadel
    sudo: "ALL=(ALL) NOPASSWD:ALL"
ssh_pwauth: true
package_update: true
packages:
  - xserver-xorg
  - xserver-xorg-video-qxl
  - xinit
  - xfce4
  - xfce4-terminal
  - mate-polkit       # GUI-агент polkit (autostart в сессии) — policykit-1-gnome удалён в trixie
  - spice-vdagent     # общий буфер обмена host<->guest через qemu-vdagent
  - dbus-x11
  - iproute2
  - iptables
  - polkitd           # в trixie polkit разнесён: polkitd + pkexec (был policykit-1)
  - pkexec
  - libgtk-3-0t64     # t64-переименование в trixie (был libgtk-3-0)
  - dnsutils
  - curl
write_files:
  # Без display manager: autologin citadel на tty1 → ~/.bash_profile стартует X.
  # lightdm/accountsservice на cloud-образе уходили в restart-loop (гонка
  # старта пакетом до создания /var/lib/lightdm/data + сработавший rate-limiter).
  - path: /etc/systemd/system/getty@tty1.service.d/override.conf
    content: |
      [Service]
      ExecStart=
      ExecStart=-/sbin/agetty --autologin citadel --noclear %I $TERM
  # write-files в cloud-init выполняется РАНЬШЕ users-groups, поэтому кладём в
  # /etc/skel — файлы скопируются в /home/citadel при создании пользователя.
  - path: /etc/skel/.bash_profile
    content: |
      [[ -f ~/.bashrc ]] && . ~/.bashrc
      # X только на физической консоли tty1; serial (ttyS0) остаётся shell'ом для диагностики
      if [[ -z $DISPLAY && $(tty) == /dev/tty1 ]]; then exec startx; fi
  - path: /etc/skel/.xinitrc
    content: |
      #!/bin/sh
      spice-vdagent &        # сессионный агент общего буфера обмена (демон socket-активируется сам)
      exec startxfce4
  - path: /etc/modules-load.d/9p.conf
    content: |
      9p
      9pnet_virtio
runcmd:
  - [ modprobe, 9pnet_virtio ]
  - mkdir -p /mnt/citadel
  - mount -t 9p -o trans=virtio,version=9p2000.L,ro citadel /mnt/citadel || true
  - grep -q citadel /etc/fstab || echo 'citadel /mnt/citadel 9p trans=virtio,version=9p2000.L,ro,_netdev,nofail 0 0' >> /etc/fstab
  # подстраховка, если skel не скопировался в уже существующий home
  - bash -c 'for f in .bash_profile .xinitrc; do [ -f /home/citadel/$f ] || install -o citadel -g citadel -m 644 /etc/skel/$f /home/citadel/$f; done'
  - [ systemctl, set-default, multi-user.target ]
  - [ systemctl, daemon-reload ]
  - [ systemctl, restart, getty@tty1 ]
final_message: "CitadelPQVPN test VM готова. На tty1 поднимется xfce (autologin citadel). Терминал → sudo /mnt/citadel/tools/install-desktop.sh --with-app"
YAML
  printf 'instance-id: citadel-test\nlocal-hostname: citadel-test\n' > "$VM_DIR/meta-data"
  cloud-localds "$SEED" "$VM_DIR/user-data" "$VM_DIR/meta-data"
}

setup() {
  check_deps
  build_artifacts
  mkdir -p "$VM_DIR"
  if [[ ! -f "$BASE" ]]; then
    log "Скачиваю базовый образ Debian-cloud…"
    wget -O "$BASE" "$IMG_URL"
  fi
  log "Создаю диск VM (overlay поверх базового, $DISK_SIZE)…"
  qemu-img create -f qcow2 -F qcow2 -b "$BASE" "$DISK" "$DISK_SIZE" >/dev/null
  gen_cloud_init
  log "Готово. Запуск: tools/qemu-testvm.sh run"
}

run() {
  [[ -f "$DISK" && -f "$SEED" ]] || die "сначала: tools/qemu-testvm.sh setup"
  local kvm=()
  [[ -e /dev/kvm ]] && kvm=(-enable-kvm -cpu host)
  log "Запуск VM (окно QEMU; первый буст ставит xfce — несколько минут)…"
  log "Репозиторий шарится в VM как 9p '/mnt/citadel' (ro)."
  log "SERIAL-КОНСОЛЬ в ЭТОМ терминале (логин citadel/citadel) — работает даже если GUI висит."
  log "  Ctrl-A C — монитор QEMU; Ctrl-A X — выход. Если xfce не поднялся: на ttyS0 как citadel → 'startx' вручную; логи X в ~/.local/share/xorg/Xorg.0.log."
  log "Окно адаптируется под размер (zoom-to-fit) — тяни мышью; общий буфер обмена через spice-vdagent."
  # qxl надёжнее virtio для Linux-десктопа; serial mon:stdio даёт текстовый вход+логи как fallback.
  # qemu-vdagent (clipboard=on) + virtserialport com.redhat.spice.0 → spice-vdagent в гостье = общий clipboard.
  exec qemu-system-x86_64 \
    "${kvm[@]}" -m "$RAM_MB" -smp "$CPUS" \
    -drive file="$DISK",if=virtio,format=qcow2 \
    -drive file="$SEED",if=virtio,format=raw \
    -netdev user,id=n0,hostfwd=tcp::2222-:22 \
    -device virtio-net-pci,netdev=n0 \
    -virtfs local,path="$REPO",mount_tag=citadel,security_model=mapped-xattr,id=citadel \
    -device virtio-serial-pci \
    -chardev qemu-vdagent,id=vdagent,name=vdagent,clipboard=on \
    -device virtserialport,chardev=vdagent,name=com.redhat.spice.0 \
    -vga qxl -display gtk,zoom-to-fit=on \
    -serial mon:stdio
}

snapshot() {
  [[ -f "$DISK" ]] || die "нет диска VM"
  local tag="${1:-pre-test-$(date +%H%M%S)}"
  qemu-img snapshot -c "$tag" "$DISK"
  log "Снапшот '$tag' создан (откат: qemu-img snapshot -a '$tag' \"$DISK\")"
}

case "${1:-help}" in
  setup) setup ;;
  run) run ;;
  snapshot) shift; snapshot "${1:-}" ;;
  *) sed -n '2,33p' "$0" ;;
esac
