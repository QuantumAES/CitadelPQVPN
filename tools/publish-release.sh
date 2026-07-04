#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Выкладка ПОДПИСАННОГО релиза CitadelPQVPN на GitHub Release (шаг 4, §8.1).
# Предполагает, что артефакты уже собраны и подписаны tools/mk-release.sh → dist/<tag>/.
#
#   tools/publish-release.sh vX.Y.Z
#
# Перед публикацией ПЕРЕ-ПРОВЕРЯЕТ подпись+хеши (не выкладываем битое). Идемпотентно:
# повторный запуск обновляет ассеты существующего релиза (--clobber).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TAG="${1:-}"
REPO="${CITADEL_REPO:-QuantumAES/CitadelPQVPN}"
PUB="packaging/release/citadel-release.pub"
DIST="dist/$TAG"
INSTALLER="tools/install-citadel-server.sh"
PUBKEY_B64="RWSErwVVdH0bhg9dQViFezkqCQPfWpZt18rK0irjOOpNfUW3G4hkoNp4"

die() { printf 'ОШИБКА: %s\n' "$*" >&2; exit 1; }

[[ -n "$TAG" ]] || die "укажи тег: tools/publish-release.sh vX.Y.Z"
command -v gh       >/dev/null || die "gh не установлен"
command -v minisign >/dev/null || die "minisign не установлен"
[[ -d "$DIST" ]] || die "нет $DIST — собери релиз: tools/mk-release.sh $TAG"
[[ -f "$PUB" ]] || die "нет $PUB"
[[ -f "$INSTALLER" ]] || die "нет $INSTALLER"
gh auth status >/dev/null 2>&1 || die "gh не авторизован: gh auth login"

# ── обязательные артефакты ──
[[ -f "$DIST/sha256sums" && -f "$DIST/sha256sums.minisig" ]] || die "нет sha256sums(.minisig) в $DIST"
shopt -s nullglob; zst=("$DIST"/*.zst); shopt -u nullglob
((${#zst[@]})) || die "в $DIST нет *.zst — пере-собери mk-release.sh"

# ── ПЕРЕ-ПРОВЕРКА перед публикацией ──
( cd "$DIST" && minisign -V -p "$REPO_ROOT/$PUB" -m sha256sums >/dev/null ) \
  || die "подпись sha256sums НЕ проходит verify — не публикую"
( cd "$DIST" && sha256sum -c --ignore-missing sha256sums >/dev/null ) \
  || die "sha256 артефактов не сходится — не публикую"
echo "[publish] подпись + хеши OK"

# ── предупреждение о незакоммиченном дереве (релиз должен быть из чистого коммита) ──
if [[ -n "$(git status --porcelain)" ]]; then
  echo "[publish] ВНИМАНИЕ: рабочее дерево не чистое — релиз собран из незакоммиченного кода."
  echo "          Для канонического релиза сначала закоммить и протегай. Для pre — ок."
fi

# ── prerelease по суффиксу тега ──
PRE=(); case "$TAG" in *-pre*|*-rc*|*-beta*|*-alpha*) PRE=(--prerelease) ;; esac

INSTALLER_SHA="$(sha256sum "$INSTALLER" | cut -d' ' -f1)"
assets=("${zst[@]}" "$DIST/sha256sums" "$DIST/sha256sums.minisig" "$INSTALLER")

# ── notes (без backtick'ов: код-блоки 4 пробелами; heredoc раскрывает $… ) ──
notes="$(cat <<EOF
CitadelPQVPN $TAG — подписанные бинари exit-сервера.

Развёртывание (на СЕРВЕРЕ, root):

    curl -fsSLO https://github.com/$REPO/releases/download/$TAG/install-citadel-server.sh
    CITADEL_VERSION=$TAG bash install-citadel-server.sh

Установщик проверяет подпись бинаря вшитым ключом. Канонический (ревьюнутый) источник
установщика — репозиторий tools/install-citadel-server.sh на теге $TAG,
sha256(install-citadel-server.sh) = $INSTALLER_SHA

Ручная проверка бинарей:

    minisign -V -P $PUBKEY_B64 -m sha256sums
    sha256sum -c sha256sums

sha256sums:

$(sed 's/^/    /' "$DIST/sha256sums")
EOF
)"

# ── target: HEAD только если он ЗАПУШЕН (иначе GitHub отвергнет commitish);
#    не запушен → пусть gh создаст тег на default-ветке remote (для pre — ок) ──
target_args=()
if git branch -r --contains HEAD 2>/dev/null | grep -q .; then
  target_args=(--target "$(git rev-parse HEAD)")
  echo "[publish] target = HEAD $(git rev-parse --short HEAD) (на remote)"
else
  echo "[publish] HEAD $(git rev-parse --short HEAD) НЕ запушен → тег создастся на default-ветке remote."
  echo "          (для канонического релиза сначала push ветки/тега; для pre — ок)"
fi

# ── создать или обновить релиз (идемпотентно) ──
if gh release view "$TAG" >/dev/null 2>&1; then
  echo "[publish] релиз $TAG уже существует → обновляю ассеты (--clobber)"
  gh release upload "$TAG" "${assets[@]}" --clobber
else
  echo "[publish] создаю релиз $TAG"
  gh release create "$TAG" "${assets[@]}" \
    --title "CitadelPQVPN $TAG" --notes "$notes" "${target_args[@]}" "${PRE[@]}"
fi

echo "[publish] готово:"
gh release view "$TAG" --json url --jq .url
