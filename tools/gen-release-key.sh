#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Генерация РЕЛИЗНОГО ключа подписи CitadelPQVPN (minisign / Ed25519).
# Запускает МЕЙНТЕЙНЕР один раз. Этим ключом подписываются бинари релиза
# (tools/mk-release.sh); установщик сервера (install-citadel-server.sh) верифицирует
# скачанный бинарь публичным ключом — это ядро supply-chain-защиты (см. §8).
#
# ПРИНЦИПЫ НАДЁЖНОСТИ:
#   • секрет ШИФРУЕТСЯ ПАРОЛЕМ (minisign без -W) и живёт ВНЕ репозитория;
#   • в git попадает ТОЛЬКО публичный ключ (.pub);
#   • скрипт НЕ перезаписывает существующий ключ (потеря/смена = катастрофа для
#     верификации уже выданных релизов).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PUB_DIR="$REPO_ROOT/packaging/release"
PUB="$PUB_DIR/citadel-release.pub"
# Секрет вне репо; путь переопределяется $CITADEL_RELEASE_KEY_DIR (для внешнего носителя).
SEC_DIR="${CITADEL_RELEASE_KEY_DIR:-$HOME/.citadel/release}"
SEC="$SEC_DIR/citadel-release.key"

die() { printf 'ОШИБКА: %s\n' "$*" >&2; exit 1; }

command -v minisign >/dev/null 2>&1 || die "minisign не установлен (напр. apt install minisign)"

# ── защита от перезаписи ──────────────────────────────────────────────────────
if [[ -e "$SEC" || -e "$PUB" ]]; then
  die "ключ уже существует ($SEC / $PUB).
Перегенерация СМЕНИТ ключ подписи — старые релизы перестанут проходить verify новым pub.
Если это осознанно: удали файлы вручную и запусти снова."
fi

mkdir -p "$PUB_DIR"
mkdir -p "$SEC_DIR"
chmod 700 "$SEC_DIR"

# ── очистка полу-созданных файлов при сбое/отмене (чтобы re-run не спотыкался) ──
GEN_OK=0
cleanup() { [[ "$GEN_OK" == "1" ]] || rm -f "$SEC" "$PUB" 2>/dev/null || true; }
trap cleanup EXIT

cat <<EOF
Генерация minisign-ключа релиза CitadelPQVPN (Ed25519).
  секрет (шифруется паролем): $SEC
  публичный (в репозиторий):  $PUB

Придумай СИЛЬНЫЙ пароль — им шифруется секретный ключ (minisign спросит дважды).
EOF
echo

# password-protected (без -W), без -f (не затираем)
minisign -G -p "$PUB" -s "$SEC"
GEN_OK=1

chmod 600 "$SEC"
chmod 644 "$PUB"

cat <<EOF

=== ГОТОВО ===
Публичный ключ ($PUB):
$(cat "$PUB")

ДАЛЬШЕ (важно):
  1) ОФЛАЙН-БЭКАП секрета: $SEC
     (потеря = невозможно подписывать новые релизы; компрометация = злоумышленник
      подпишет вредоносный бинарь, который пройдёт verify на серверах).
  2) НИКОГДА не коммить секрет. Коммить только публичный:
        git add packaging/release/citadel-release.pub
  3) Публичный ключ будет вшит в install-citadel-server.sh (verify бинаря на сервере).
  4) Подпись релиза (шаг 2): tools/mk-release.sh возьмёт секрет из
        \${CITADEL_RELEASE_KEY_DIR:-\$HOME/.citadel/release}/citadel-release.key
EOF
