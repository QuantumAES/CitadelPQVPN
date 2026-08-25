#!/usr/bin/env bash
# =============================================================================
# CitadelPQVPN — чистка кешей сборки.
#
# Удаляет ТОЛЬКО регенерируемое: артефакты cargo/flutter/gradle и мусор docker.
# Ничего из исходников, ключей, хранилищ профилей и готовых релизов (`dist/`) не
# трогает — эти пути перечислены в НЕ-удаляемых явно, чтобы правки скрипта
# случайно не превратили его в «rm -rf проект».
#
# Уровни (по нарастанию цены следующей сборки):
#   --light   (по умолчанию) incremental-кеши cargo + docker-мусор.
#             Освобождает больше всего на гигабайт риска, полная пересборка НЕ нужна.
#   --deep    + cargo clean (оба воркспейса) + flutter clean + gradle transforms.
#             Следующая сборка полная: cargo ~10–15 мин (aws-lc-rs), APK ~6–8 мин.
#   --all     то же, что --deep (алиас).
#
# Флаги:
#   -n | --dry-run   только показать, что было бы удалено, и сколько это весит
#   --keep-docker    не трогать docker (образы/кеш сборки/остановленные стенды)
#
# Запуск:  bash tools/clean-caches.sh [--light|--deep] [-n] [--keep-docker]
# =============================================================================
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

# Санити-проверка: без неё скрипт, запущенный не из репозитория, чистил бы чужие пути.
[[ -f "$REPO/Cargo.toml" && -d "$REPO/crates" ]] || {
    echo "не похоже на репозиторий CitadelPQVPN: $REPO" >&2
    exit 1
}

LEVEL=light
DRY=0
DOCKER=1
while [[ $# -gt 0 ]]; do
    case "$1" in
        --light)            LEVEL=light ;;
        --deep|--all)       LEVEL=deep ;;
        -n|--dry-run)       DRY=1 ;;
        --keep-docker)      DOCKER=0 ;;
        -h|--help)          sed -n '3,26p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *)                  echo "неизвестный аргумент: $1 (см. --help)" >&2; exit 2 ;;
    esac
    shift
done

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }

free_kb() { df -Pk "$REPO" | awk 'NR==2{print $4}'; }
BEFORE_KB="$(free_kb)"

# Размер пути (0, если его нет) — чтобы отчёт был честным и в dry-run тоже.
size_of() { [[ -e "$1" ]] && du -sh "$1" 2>/dev/null | cut -f1 || echo "-"; }

# Удалить путь (или показать в dry-run). Пути принимаются только внутри $REPO или $HOME/.gradle:
# это защита от опечатки вида `/` или `$HOME`.
drop() {
    local path="$1" why="$2"
    case "$path" in
        "$REPO"/*|"$HOME"/.gradle/*) ;;
        *) echo "ОТКАЗ: $path вне разрешённых каталогов" >&2; return 0 ;;
    esac
    [[ -e "$path" ]] || return 0
    note "$(printf '%-8s %s — %s' "$(size_of "$path")" "${path#"$REPO"/}" "$why")"
    [[ "$DRY" -eq 1 ]] || rm -rf "$path"
}

log "Кеши сборки${DRY:+ (dry-run)}: уровень $LEVEL, каталог $REPO"

# ── 1. cargo: инкрементальные кеши (самый крупный «дешёвый» кусок) ────────────
# incremental — только ускорение повторной сборки; удаление ничего не ломает.
log "cargo: инкрементальные кеши"
for t in "$REPO/target" "$REPO/app/rust/target"; do
    drop "$t/debug/incremental"   "инкрементальный кеш (пересоздаётся сам)"
    drop "$t/debug/examples"      "артефакты примеров/бенчей"
done

# ── 2. мусор в корне ─────────────────────────────────────────────────────────
drop "$REPO/tmp.tmp" "пустой файл-артефакт"

# ── 3. docker: остановить стенды, снять их тома, почистить кеш сборки ─────────
# Образы citadel-* НЕ удаляем: их пересборка — минуты, а места они занимают немного.
if [[ "$DOCKER" -eq 1 ]] && command -v docker >/dev/null; then
    log "docker: стенды и кеш сборки"
    for f in docker/compose.cli.yml docker/compose.e2e.yml docker/compose.yml; do
        [[ -f "$REPO/$f" ]] || continue
        note "down -v: $f"
        [[ "$DRY" -eq 1 ]] || docker compose -f "$REPO/$f" down -v >/dev/null 2>&1 || true
    done
    if [[ "$DRY" -eq 1 ]]; then
        docker system df 2>/dev/null | sed 's/^/    /'
    else
        docker builder prune -f >/dev/null 2>&1 || true
        docker image prune -f   >/dev/null 2>&1 || true
    fi
fi

# ── 4. глубокая чистка ───────────────────────────────────────────────────────
if [[ "$LEVEL" == "deep" ]]; then
    log "cargo clean (следующая сборка — полная, ~10–15 мин из-за aws-lc-rs)"
    if [[ "$DRY" -eq 1 ]]; then
        note "$(size_of "$REPO/target")     target/"
        note "$(size_of "$REPO/app/rust/target") app/rust/target/"
    else
        cargo clean 2>/dev/null || rm -rf "$REPO/target"
        ( cd "$REPO/app/rust" && cargo clean 2>/dev/null ) || rm -rf "$REPO/app/rust/target"
    fi

    log "flutter clean (следующая сборка APK — ~6–8 мин: Rust под 4 ABI)"
    if [[ "$DRY" -eq 1 ]]; then
        note "$(size_of "$REPO/app/build") app/build/"
    elif command -v flutter >/dev/null; then
        ( cd "$REPO/app" && flutter clean >/dev/null ) || rm -rf "$REPO/app/build"
    else
        rm -rf "$REPO/app/build"
    fi

    # Gradle: удаляем только transforms (перевычисляются из уже скачанных модулей) и
    # логи демона. modules-2 (скачанные зависимости) НЕ трогаем — иначе следующая
    # сборка полезет в сеть, а это уже не «чистка кеша», а потеря офлайн-сборки.
    log "gradle: артефакт-трансформы и логи демона"
    if [[ "$DRY" -eq 0 ]]; then
        pkill -f 'GradleDaemo[n]' 2>/dev/null || true   # [n] — чтобы не убить сам себя по своей же строке
        sleep 1
    fi
    for d in "$HOME"/.gradle/caches/*/transforms; do drop "$d" "AGP-трансформы (перевычислятся)"; done
    drop "$HOME/.gradle/daemon" "логи gradle-демона"
fi

# ── итог ─────────────────────────────────────────────────────────────────────
AFTER_KB="$(free_kb)"
FREED_MB=$(( (AFTER_KB - BEFORE_KB) / 1024 ))
echo
if [[ "$DRY" -eq 1 ]]; then
    log "dry-run: ничего не удалено. Запусти без -n, чтобы применить."
else
    log "Готово. Освобождено: ${FREED_MB} МБ. Свободно сейчас: $(df -Ph "$REPO" | awk 'NR==2{print $4}')"
fi
echo "    НЕ трогалось: исходники, dist/ (релизы), .venv, ~/.cargo/registry, ~/.pub-cache,"
echo "    хранилища профилей (~/.config/citadel-pqvpn), ключи и docker-образы citadel-*."
