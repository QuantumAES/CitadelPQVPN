#!/usr/bin/env bash
# exit-узел для E2E десктоп-клиента: token-less (без issuer), известный PSK, без PQ-auth —
# чтобы клиент из QEMU-VM подключался по простой citadel://-ссылке. Порты публикуются в compose.
set -e
export Citadel_ROLE=server
export Citadel_LISTEN=0.0.0.0:4433
export Citadel_TUN=Citadel0
export Citadel_TUN_ADDR=10.7.0.1/16
export Citadel_MTU=1100
export Citadel_NAT_SRC=10.7.0.0/16
export Citadel_PIN_FILE=/shared/exit.pin
export Citadel_OBFS_PSK="${Citadel_OBFS_PSK:-citadel-e2e-psk}"
export Citadel_TCP_LISTEN=0.0.0.0:443
export Citadel_KX=all
# НЕ задаём Citadel_ISSUER_PUB → анонимные токены НЕ требуются (token-less E2E);
# НЕ задаём Citadel_MLDSA → сервер не подписывает, клиент без PQ-auth (mldsa=None в ссылке).
rm -f /shared/exit.pin
echo "[exit-e2e] token-less exit; PSK='$Citadel_OBFS_PSK'; listen 4433/udp + 443/tcp"
exec citadel-m1
