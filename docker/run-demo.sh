#!/usr/bin/env bash
# Полный прогон M1-демо: сборка бинаря, образа, подъём exit+client, вывод тестов.
set -euo pipefail
cd "$(dirname "$0")/.."  # корень проекта
ROOT="$PWD"
export PATH="$ROOT/.venv/bin:$PATH"   # cmake для aws-lc-rs

echo "[1/5] сборка citadel-m1 + citadel-token…"
cargo build -q -p citadel-quic --bin citadel-m1
cargo build -q -p citadel-token --bin citadel-token
cp -f target/debug/citadel-m1 docker/citadel-m1
cp -f target/debug/citadel-token docker/citadel-token

echo "[2/5] docker compose build…"
docker compose -f docker/compose.yml build

echo "[3/5] поднимаю exit + client…"
docker compose -f docker/compose.yml up -d

echo "[4/5] жду тестов (issuance + миграция + fallback + failover + agility + PQ-auth + admin-plane, ~130с)…"
for _ in $(seq 1 280); do
    docker compose -f docker/compose.yml logs client 2>/dev/null | grep -q "Готово." && break
    sleep 1
done

CLIENT_LOG="$(docker compose -f docker/compose.yml logs --no-log-prefix client 2>/dev/null || true)"

echo "[5/5] логи:"
echo "===== EXIT (F2/F7 дропы) ====="
docker compose -f docker/compose.yml logs --no-log-prefix exit | grep -E "F2:|F7:" | tail -n 12 || true
echo "===== EXIT (хвост) ====="
docker compose -f docker/compose.yml logs --no-log-prefix exit | tail -n 6 || true
echo "===== ISSUER (M5 split — слепое подписание; C7 admin-канал) ====="
docker compose -f docker/compose.yml logs --no-log-prefix issuer | grep -E "ключ сгенерирован|слепая выдача|выдано вслепую|keysync|admin" | tail -n 10 || true
echo "===== CLIENT ====="
docker compose -f docker/compose.yml logs --no-log-prefix client | sed -n '/ТЕСТ 1/,/Готово/p' || true


# ── ВЕРДИКТ ────────────────────────────────────────────────────────────────────────────────
# Раньше скрипт всегда завершался успешно: он печатал логи, а решение «прошло или нет» человек
# принимал глазами. В CI глаз нет — жёлтый прогон с провалившимся туннелем выглядел зелёным,
# то есть гейт docker-e2e не гейтил ничего. Теперь вердикт считается здесь:
#   * стенд обязан дойти до конца сценария ("Готово." от клиента) — иначе это таймаут/падение;
#   * ни одной строки-провала: entrypoint-client.sh печатает их как "[!] … ✗".
FAILED="$(printf '%s\n' "$CLIENT_LOG" | grep -F '✗' || true)"
PASSED="$(printf '%s\n' "$CLIENT_LOG" | grep -cF 'OK ✔' || true)"
RC=0

echo
echo "===== ВЕРДИКТ ====="
if ! printf '%s\n' "$CLIENT_LOG" | grep -q "Готово."; then
    echo "ПРОВАЛ: клиент не дошёл до конца сценария (нет «Готово.») — таймаут или падение стенда"
    RC=1
elif [ -n "$FAILED" ]; then
    echo "ПРОВАЛ: провалившиеся проверки:"
    printf '%s\n' "$FAILED" | sed 's/^/  /'
    RC=1
else
    echo "УСПЕХ: пройдено проверок — $PASSED, провалов нет"
fi

# Стенд гасим ВСЕГДА (в т.ч. если тесты провалились): оставленные контейнеры держат сети, TUN и
# iptables-правила, а следующий прогон должен стартовать в чистом окружении.
if [ "${KEEP_STAND:-0}" = "1" ]; then
    echo
    echo "KEEP_STAND=1 — стенд оставлен. Погасить: docker compose -f docker/compose.yml down -v"
else
    echo
    echo "[6/6] гашу стенд…"
    docker compose -f docker/compose.yml down -v --remove-orphans >/dev/null 2>&1
    echo "      стенд погашен (KEEP_STAND=1 — оставить поднятым)"
fi

exit "$RC"
