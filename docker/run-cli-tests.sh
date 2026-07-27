#!/usr/bin/env bash
# =============================================================================
# Проверка консольного Linux-клиента (трек L) в контейнерах.
#
# Два прогона:
#   [A] юнит-тесты воркспейса в ЧИСТОМ контейнере (без окружения разработчика: своих env,
#       конфигов, ~/.config) — тестовые бинари собираются на хосте и запускаются внутри;
#   [B] e2e против настоящих exit+issuer: демон под root, движок под отдельным uid,
#       реальные iptables/TUN, поведение kill-switch при аварии и восстановление.
#
# Запуск:  bash docker/run-cli-tests.sh [--unit-only|--e2e-only]
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
export PATH="$ROOT/.venv/bin:$PATH"   # cmake для aws-lc-rs
BASE_IMAGE="debian:trixie-slim@sha256:28de0877c2189802884ccd20f15ee41c203573bd87bb6b883f5f46362d24c5c2"

MODE="${1:-all}"

run_unit() {
    echo "[A/1] сборка тестовых бинарей воркспейса…"
    cargo test --workspace --no-run --message-format=json 2>/dev/null \
        | python3 -c '
import json,sys
for line in sys.stdin:
    try: m=json.loads(line)
    except Exception: continue
    if m.get("profile",{}).get("test") and m.get("executable"):
        print(m["executable"])
' | sort -u > /tmp/citadel-test-bins.txt
    echo "      тестовых бинарей: $(wc -l < /tmp/citadel-test-bins.txt)"

    echo "[A/2] прогон в чистом контейнере ($BASE_IMAGE)…"
    # Бинари динамически слинкованы с glibc; базовый образ — тот же trixie, что и на хосте,
    # поэтому их достаточно смонтировать, а не пересобирать внутри (иначе прогон занимал бы
    # минуты на пересборку aws-lc-rs/quinn ради того же результата).
    local bins
    bins=$(sed "s|^$ROOT/|/repo/|" /tmp/citadel-test-bins.txt | tr '\n' ' ')
    docker run --rm -v "$ROOT:/repo:ro" -w /tmp "$BASE_IMAGE" /bin/sh -c "
        rc=0
        for t in $bins; do
          echo \"── \$(basename \$t)\"
          \$t --test-threads=4 || rc=1
        done
        exit \$rc
    "
}

run_e2e() {
    echo "[B/1] сборка бинарей клиента и демо-узлов…"
    cargo build -q -p citadel-quic --bin citadel-m1
    cargo build -q -p citadel-token --bin citadel-token
    cargo build -q -p citadel-client --bin citadel-linkgen
    cargo build -q -p citadel-vpnd -p citadel-engine -p citadel-cli
    cp -f target/debug/citadel-m1 target/debug/citadel-token docker/
    cp -f target/debug/citadel-linkgen target/debug/citadel-vpnd \
          target/debug/citadel-engine target/debug/citadel-cli docker/

    echo "[B/2] docker compose build…"
    docker compose -f docker/compose.cli.yml build

    echo "[B/3] поднимаю issuer + exit + консольный клиент…"
    docker compose -f docker/compose.cli.yml up -d

    echo "[B/4] жду завершения прогона (до ~240с)…"
    for _ in $(seq 1 240); do
        docker compose -f docker/compose.cli.yml logs client-cli 2>/dev/null | grep -q "Готово." && break
        sleep 1
    done

    echo
    echo "===== КЛИЕНТ (консольный, трек L) ====="
    docker compose -f docker/compose.cli.yml logs --no-log-prefix client-cli | sed -n '/L-ТЕСТ 1/,/ИТОГ/p'
    echo
    echo "===== ЖУРНАЛ ДЕМОНА (хвост) ====="
    docker compose -f docker/compose.cli.yml exec -T client-cli tail -40 /var/log/vpnd.log 2>/dev/null || true
    echo
    echo "===== EXIT (дропы egress-фильтра, если были) ====="
    docker compose -f docker/compose.cli.yml logs --no-log-prefix exit 2>/dev/null \
        | grep -E "S0.2|F2:|F7:" | tail -15 || true

    # Стенд гасим ВСЕГДА (в т.ч. при провале тестов): оставленные контейнеры держат сеть,
    # TUN-устройства и iptables-правила, а следующий прогон получает не чистое окружение.
    if [ "${KEEP_STAND:-0}" = "1" ]; then
        echo
        echo "KEEP_STAND=1 — стенд оставлен. Погасить: docker compose -f docker/compose.cli.yml down -v"
    else
        echo
        echo "[B/5] гашу стенд…"
        docker compose -f docker/compose.cli.yml down -v --remove-orphans >/dev/null 2>&1
        echo "      стенд погашен (KEEP_STAND=1 — оставить поднятым)"
    fi
}

case "$MODE" in
    --unit-only) run_unit ;;
    --e2e-only)  run_e2e ;;
    *)           run_unit; run_e2e ;;
esac
