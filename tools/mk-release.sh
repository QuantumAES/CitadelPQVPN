#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Сборка и ПОДПИСЬ релизных артефактов CitadelPQVPN (шаг 2 installer-трека, §8.1).
#
# Собирает release-бинари (citadel-m1, citadel-linkgen, citadel-token) под арку хоста, стрипает,
# жмёт zstd, считает sha256sums и подписывает их релизным minisign-секретом.
# Артефакты → dist/<version>/. Их выкладывают в GitHub Release; сервер-инсталлер
# тянет .zst + sha256sums + .minisig и проверяет подпись публичным ключом (supply-chain).
#
#   tools/mk-release.sh [version] [--no-sign]
#     version   по умолчанию из git describe
#     --no-sign только собрать и посчитать хеши. Нужно в конвейере релиза: следом идёт
#               mk-client-release.sh, который пере-считывает sha256sums по ВСЕМ артефактам
#               (сервер + клиенты + Windows-установщик) и подписывает их ОДИН раз. Две подписи
#               подряд — это лишний ввод пароля и промежуточный .minisig, который всё равно
#               перезапишется.
#
# Ключи (совпадают с tools/gen-release-key.sh):
#   секрет: $CITADEL_RELEASE_KEY_DIR|~/.citadel/release/citadel-release.key (пароль спросит)
#   pub:    $CITADEL_RELEASE_PUB|packaging/release/citadel-release.pub  (self-verify)
# Multi-arch — запускать на каждой арке (или CI, C4.5) и объединять sha256sums перед подписью.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# aws-lc-rs требует cmake; на dev-хосте он в .venv (pip). Делаем сборку самодостаточной (как
# run-demo.sh): если .venv есть — первой в PATH (иначе системный/flutter cmake может конфликтовать).
[ -d "$REPO_ROOT/.venv/bin" ] && export PATH="$REPO_ROOT/.venv/bin:$PATH"

NO_SIGN=0
ARGS=()
for a in "$@"; do
  case "$a" in
    --no-sign) NO_SIGN=1 ;;
    *) ARGS+=("$a") ;;
  esac
done

VERSION="${ARGS[0]:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
SEC="${CITADEL_RELEASE_KEY_DIR:-$HOME/.citadel/release}/citadel-release.key"
PUB="${CITADEL_RELEASE_PUB:-$REPO_ROOT/packaging/release/citadel-release.pub}"
OUT="$REPO_ROOT/dist/$VERSION"

die() { printf 'ОШИБКА: %s\n' "$*" >&2; exit 1; }
for t in zstd sha256sum cargo; do
  command -v "$t" >/dev/null 2>&1 || die "$t не установлен"
done
[[ $NO_SIGN -eq 1 ]] || command -v minisign >/dev/null 2>&1 || die "minisign не установлен"
if [[ $NO_SIGN -eq 0 ]]; then
  [[ -f "$SEC" ]] || die "секрет релиза не найден: $SEC (сгенерируй tools/gen-release-key.sh)"
  [[ -f "$PUB" ]] || die "публичный ключ не найден: $PUB"
fi

# арка → суффикс артефакта (совпадает с ServerArch::artifact_suffix в citadel-client)
case "$(uname -m)" in
  x86_64|amd64)   SUFFIX=x86_64 ;;
  aarch64|arm64)  SUFFIX=aarch64 ;;
  *) die "неподдерживаемая арка: $(uname -m)" ;;
esac

echo "[mk-release] version=$VERSION arch=$SUFFIX out=$OUT"

# ── сборка release ──
cargo build --release -p citadel-quic --bin citadel-m1
cargo build --release -p citadel-client --bin citadel-linkgen
cargo build --release -p citadel-token --bin citadel-token   # C5.4b: issuer-контейнер (Layer-1 + epoch-токены)

rm -rf "$OUT"
mkdir -p "$OUT"

# ── strip + zstd, имя с суффиксом арки ──
package() {
  local name="$1"
  local staged="$OUT/${name}-${SUFFIX}"
  cp "target/release/$name" "$staged"
  if command -v strip >/dev/null 2>&1; then strip "$staged"; else echo "  (strip нет — без стрипа)"; fi
  zstd -q -19 --rm -f "$staged"        # → ${staged}.zst, несжатый удаляется
  printf '  %-24s %s\n' "${name}-${SUFFIX}.zst" "$(du -h "${staged}.zst" | cut -f1)"
}
echo "[mk-release] упаковка:"
package citadel-m1
package citadel-linkgen
package citadel-token

# ── sha256sums + подпись + self-verify ──
cd "$OUT"
sha256sum ./*.zst | sed 's#\./##' > sha256sums
echo "[mk-release] sha256sums:"; sed 's/^/  /' sha256sums

if [[ $NO_SIGN -eq 1 ]]; then
  echo "[mk-release] --no-sign: подпись НЕ ставится (её поставит mk-client-release.sh по всем артефактам)"
else
  echo "[mk-release] подпись sha256sums релизным ключом (minisign может спросить пароль)…"
  minisign -S -s "$SEC" -m sha256sums \
    -t "CitadelPQVPN $VERSION $SUFFIX $(date -u +%Y-%m-%dT%H:%M:%SZ)"

  echo "[mk-release] self-verify публичным ключом…"
  minisign -V -p "$PUB" -m sha256sums
fi

cat <<EOF

=== ГОТОВО: $OUT ===
  citadel-m1-${SUFFIX}.zst, citadel-linkgen-${SUFFIX}.zst, citadel-token-${SUFFIX}.zst, sha256sums, sha256sums.minisig
Выложить в GitHub Release тега $VERSION (шаг 4). Сервер-инсталлер проверит подпись
публичным ключом (packaging/release/citadel-release.pub, вшит в install-citadel-server.sh).
EOF
