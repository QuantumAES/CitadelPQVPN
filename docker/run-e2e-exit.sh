#!/usr/bin/env bash
# Поднимает token-less exit с публикацией портов (для E2E десктоп-клиента из QEMU-VM)
# и печатает citadel://-ссылку под него. Запускать с ХОСТА.
#   servers в ссылке = $VM_HOST:4433 (по умолчанию 10.0.2.2 — хост как видно из VM user-net).
#   routes = что туннелировать (по умолчанию 1.1.1.1/32 1.0.0.1/32 — для теста ping/curl).
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
export PATH="$ROOT/.venv/bin:$PATH"   # cmake для aws-lc-rs (сборка бинаря/linkgen)

PSK="citadel-e2e-psk"
VM_HOST="${VM_HOST:-10.0.2.2}"
ROUTES="${ROUTES:-1.1.1.1/32 1.0.0.1/32}"

echo "[e2e] сборка citadel-m1 + образ…"
cargo build -q -p citadel-quic --bin citadel-m1
cp -f target/debug/citadel-m1 docker/citadel-m1
docker compose -f docker/compose.e2e.yml up -d --build

echo "[e2e] жду pin сертификата exit…"
PIN=""
for _ in $(seq 1 60); do
  PIN=$(docker exec citadel-e2e-exit cat /shared/exit.pin 2>/dev/null || true)
  [ -n "$PIN" ] && break
  sleep 1
done
[ -n "$PIN" ] || { echo "не дождался /shared/exit.pin" >&2; exit 1; }
echo "[e2e] exit поднят (4433/udp + 443/tcp опубликованы), pin=$PIN"
echo

echo "=== citadel://-ссылка для GUI (вставь в приложение во VM) ==="
cargo run -q -p citadel-client --example linkgen -- \
  --servers "$VM_HOST:4433" --psk "$PSK" --pin "$PIN" --kx all --tcp-port 443 --routes "$ROUTES"

echo
echo "Останов exit: docker compose -f docker/compose.e2e.yml down"
echo "NB: маршрут $ROUTES уйдёт в туннель — проверка из VM: ping/curl 1.1.1.1 после Подключить."
