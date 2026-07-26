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
shopt -s nullglob; zst=("$DIST"/*.zst); apk=("$DIST"/*.apk); shopt -u nullglob
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
assets=("${zst[@]}" "${apk[@]}" "$DIST/sha256sums" "$DIST/sha256sums.minisig" "$INSTALLER")

# ── клиентские артефакты (если собраны mk-client-release.sh) — для notes ──
#
# Сами файлы уходят в релиз и так (glob *.zst / *.apk выше). Здесь — человекочитаемая часть:
# артефакт, не описанный в notes, на странице релиза выглядит как безымянный архив, и им никто
# не пользуется. Ровно так до этого выпадал консольный клиент (трек L): тарбол выкладывался,
# но в notes его не было.
APK_NAME=""; GUI_NAME=""; CLI_NAME=""
for f in "${apk[@]}"; do APK_NAME="$(basename "$f")"; done
shopt -s nullglob
for f in "$DIST"/citadel-desktop-linux-*.tar.zst; do GUI_NAME="$(basename "$f")"; done
for f in "$DIST"/citadel-cli-linux-*.tar.zst;     do CLI_NAME="$(basename "$f")"; done
shopt -u nullglob

# Пропущенный клиент — почти всегда забытый флаг сборки (--no-apk/--no-cli), а не замысел.
[[ -n "$CLI_NAME" ]] || echo "[publish] NB: в $DIST нет citadel-cli-linux-*.tar.zst (собран с --no-cli?)"
[[ -n "$GUI_NAME" ]] || echo "[publish] NB: в $DIST нет citadel-desktop-linux-*.tar.zst"
[[ -n "$APK_NAME" ]] || echo "[publish] NB: в $DIST нет APK (собран с --no-apk?)"

CLIENTS_BLOCK=""
add() { CLIENTS_BLOCK+="$1"$'\n'; }
if [[ -n "$APK_NAME" || -n "$GUI_NAME" || -n "$CLI_NAME" ]]; then
  add ""
  add "Клиенты:"
  if [[ -n "$APK_NAME" ]]; then
    add ""
    add "  Android — $APK_NAME (fat APK, все ABI; разреши установку из неизвестных источников)."
  fi
  if [[ -n "$GUI_NAME" ]]; then
    add ""
    add "  Linux, графический — $GUI_NAME:"
    add ""
    add "      tar --zstd -xf $GUI_NAME && cd citadel-desktop-linux-* && ./install.sh"
  fi
  if [[ -n "$CLI_NAME" ]]; then
    add ""
    add "  Linux, консольный — $CLI_NAME (citadel-cli + демон citadel-vpnd,"
    add "  разделение привилегий: плумбер под root, движок под отдельным uid, TUI под юзером):"
    add ""
    add "      tar --zstd -xf $CLI_NAME && cd citadel-cli-linux-* && sudo ./install.sh"
    add "      sudo usermod -aG citadel-vpn \$USER      # затем ПЕРЕЛОГИНЬТЕСЬ"
    add "      citadel-cli"
    add ""
    add "  Право управлять туннелем даёт членство в группе citadel-vpn, и установщик НИКОГО в неё"
    add "  не добавляет сам: её член управляет маршрутизацией всей машины (docs/LINUX-CLI.md, L3)."
    add "  Без членства citadel-cli скажет «нет доступа к сокету» — это не поломка."
    add "  Установка поверх прежней версии сама перезапускает демон: без этого в памяти оставался"
    add "  бы старый процесс, и обновление не вступило бы в силу. Активная сессия при этом рвётся"
    add "  чисто — kill-switch снимается."
  fi
fi

# ── notes (без backtick'ов: код-блоки 4 пробелами; heredoc раскрывает $… ) ──
notes="$(cat <<EOF
CitadelPQVPN $TAG — подписанные бинари exit-сервера + клиенты
(Android, Linux графический, Linux консольный).
$CLIENTS_BLOCK

Развёртывание СЕРВЕРА (root):

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
  echo "[publish] релиз $TAG уже существует → обновляю ассеты (--clobber) и notes"
  gh release upload "$TAG" "${assets[@]}" --clobber
  # Notes обновляем тоже: раньше их писал только `create`, и добавленный в существующий релиз
  # артефакт (как консольный клиент) навсегда оставался неописанным — файл есть, инструкции нет.
  # Плюс sha256sums в notes обязаны совпадать с выложенными, иначе ручная проверка не сойдётся.
  gh release edit "$TAG" --notes "$notes" >/dev/null
else
  echo "[publish] создаю релиз $TAG"
  gh release create "$TAG" "${assets[@]}" \
    --title "CitadelPQVPN $TAG" --notes "$notes" "${target_args[@]}" "${PRE[@]}"
fi

echo "[publish] готово:"
gh release view "$TAG" --json url --jq .url
