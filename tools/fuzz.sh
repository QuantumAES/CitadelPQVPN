#!/usr/bin/env bash
# Ф1 (docs/CWE-REVIEW-PLAN-2026-08.md §5): прогон фаззеров по разборщикам недоверенного ввода.
#
# Правило целей: фаззатся функция, которая читает байты ОТ ПРОТИВНИКА и не имеет права паниковать.
# Противник у каждой цели разный и назван в её заголовке — это не формальность: приоритет цели
# задаёт не «сложность парсера», а то, кем нужно быть, чтобы подать в неё ввод. Отдельно учтены
# случаи «скомпрометирован клиент», «скомпрометирован издатель», «скомпрометирован exit» и
# «скомпрометированы оба сервера сразу» (docs/THREAT-MODEL-STRIDE.md).
#
#   bash tools/fuzz.sh                # все цели по 60 с (гейт smoke)
#   bash tools/fuzz.sh 600            # все цели по 600 с (месячная кампания, §5 Ф6)
#   bash tools/fuzz.sh vpnd_frame 900 # одна цель
#   bash tools/fuzz.sh cmin           # сжать корпус до минимального по покрытию — ПЕРЕД коммитом
#
# Находки libFuzzer кладёт в fuzz/artifacts/<цель>/ — каждая обязана переехать в обычный тест
# крейта (`tests/`), чтобы регрессия ловилась и без nightly, а входной файл — в
# fuzz/seeds/<цель>/ под именем `regression-<чем-была>` (только `regression-*` переживают
# пересборку семян, см. режим `cmin`).
set -uo pipefail
cd "$(dirname "$0")/.."

# Цели перечислены явно (а не вычитаны из Cargo.toml): порядок здесь — это приоритет, и он
# начинается с границ привилегий, где противнику достаточно быть локальным пользователем.
TARGETS=(
    vpnd_frame          # D. граница привилегий Linux  — подаёт локальный пользователь
    winnet_decode       # D. граница привилегий Windows — подаёт локальный пользователь
    obfs_open           # A. провод L1                  — подаёт кто угодно в сети
    capsule_decode      # A. капсулы туннеля            — подаёт пир, т.е. и скомпрометированный exit
    capsule_address     # A. назначение адреса          — подаёт exit
    ip_parse            # A. inner-IP                   — подают обе стороны
    varint_decode       # A. примитив под всеми кадрами
    token_client_frame  # B. кадры Layer-1              — подаёт клиент (в т.ч. скомпрометированный)
    gate_frame          # B. гейт эпохи                 — подаёт клиент
    registry_parse      # B. реестр                     — файл на скомпрометированном сервере
    admin_request       # B. admin-канал                — подаёт абонент ДО проверки подписи
    issuer_hello        # C. hello издателя             — подаёт скомпрометированный издатель
    link_from_uri       # C. ссылка                     — подаёт тот, кто дал её человеку
    masterlink_unwrap   # C. парольный конверт          — подаёт канал доставки
    vault_header        # C. файл хранилища             — подаёт тот, кто подменил бэкап
)

if ! rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
    echo "нужен nightly: rustup toolchain install nightly" >&2
    exit 1
fi
if ! command -v cargo-fuzz >/dev/null 2>&1; then
    echo "нужен cargo-fuzz: cargo install --locked cargo-fuzz" >&2
    exit 1
fi

# Сжатие рабочего корпуса и пересбор семян. Кампания раздувает fuzz/corpus до сотен мегабайт
# (десятки тысяч входов, почти все — вариации уже покрытого); `cmin` оставляет минимальный набор,
# сохраняющий покрытие, а затем сюда же переносится выжимка в fuzz/seeds — то единственное, что
# едет в репозиторий. Гонять после длинной кампании, перед коммитом.
#
# Почему выжимка «самые короткие», а не весь минимизированный корпус: даже после cmin это десятки
# мегабайт, из которых почти весь объём дают несколько длинных входов. Короткие несут ту же
# структуру, стоят килобайты и одинаково хорошо разгоняют холодный старт.
SEED_KEEP="${SEED_KEEP:-40}"
if [ "${1:-}" = "cmin" ]; then
    for t in "${TARGETS[@]}"; do
        before=$(find "fuzz/corpus/$t" -type f 2>/dev/null | wc -l)
        cargo +nightly fuzz cmin "$t" >/dev/null 2>&1 || { echo "::error::cmin $t"; exit 1; }
        after=$(find "fuzz/corpus/$t" -type f 2>/dev/null | wc -l)
        # Семена пересобираются, но НЕ затираются: файлы с говорящими именами (регрессии по
        # находкам — `regression-*`) добавлены руками и обязаны пережить любую пересборку.
        mkdir -p "fuzz/seeds/$t"
        find "fuzz/seeds/$t" -type f ! -name 'regression-*' -delete
        find "fuzz/corpus/$t" -type f -printf '%s %p\n' 2>/dev/null | sort -n | head -n "$SEED_KEEP" \
            | cut -d' ' -f2- | while read -r f; do cp -f "$f" "fuzz/seeds/$t/"; done
        echo "$t: $before → $after входов (семян: $(find "fuzz/seeds/$t" -type f | wc -l))"
    done
    echo "рабочий корпус: $(du -sh fuzz/corpus | cut -f1) · семена в репозитории: $(du -sh --apparent-size fuzz/seeds | cut -f1)"
    exit 0
fi

SECS=60
LIST=("${TARGETS[@]}")
if [ $# -ge 1 ]; then
    if [[ "$1" =~ ^[0-9]+$ ]]; then
        SECS="$1"
    else
        LIST=("$1")
        [ $# -ge 2 ] && SECS="$2"
    fi
fi

rc=0
for t in "${LIST[@]}"; do
    echo "── $t (${SECS} с) ──"
    mkdir -p "fuzz/corpus/$t" "fuzz/seeds/$t"
    # Два каталога входов, и порядок важен: первый — рабочий корпус (туда libFuzzer ПИШЕТ новые
    # входы, он локальный и в git не едет), второй — семена из репозитория (только чтение).
    # Благодаря этому холодный прогон в CI стартует не с пустого места, а клон проекта не тащит
    # сотни мегабайт кампании.
    #
    # -max_len: пакет туннеля и кадр демона живут в килобайтах; без потолка libFuzzer уходит в
    # мегабайтные входы и тратит бюджет на длину вместо структуры.
    if ! cargo +nightly fuzz run "$t" "fuzz/corpus/$t" "fuzz/seeds/$t" -- \
        -max_total_time="$SECS" -max_len=4096 -print_final_stats=1 2>&1 | tail -5; then
        echo "::error::фаззер $t упал — разбор в fuzz/artifacts/$t/"
        rc=1
    fi
done
exit $rc
