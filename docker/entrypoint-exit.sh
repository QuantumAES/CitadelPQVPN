#!/usr/bin/env bash
# exit-узел (сервер): TUN 10.7.0.1/24, ip_forward + MASQUERADE → интернет.
# Пишет pin своего сертификата в /shared/exit.pin (F1, клиент его пиннит).
set -e
export Citadel_ROLE=server
export Citadel_LISTEN=0.0.0.0:4433
export Citadel_TUN=Citadel0
export Citadel_TUN_ADDR=10.7.0.1/24
export Citadel_MTU=1100
export Citadel_NAT_SRC=10.7.0.0/24
export Citadel_PIN_FILE=${Citadel_PIN_FILE:-/shared/exit.pin}   # exit2 переопределяет (multi-server, M5)
export Citadel_OBFS_PSK=$(cat /shared/obfs.psk)   # общий PSK сгенерирован издателем (не хардкод)
export Citadel_ISSUER_PUB=/shared/issuer.pub   # F-M4: проверка анонимных токенов
export Citadel_RATE_LIMIT=131072   # F7/D3: 128 KiB/с на клиента (анти-абуз/исчерпание ресурсов)
export Citadel_RATE_BURST=262144   # допустимый всплеск 256 KiB
export Citadel_TCP_LISTEN=0.0.0.0:443   # M4: obfs-over-TCP fallback (когда UDP/QUIC заблокирован)
export Citadel_KX=all   # M6 crypto-agility: exit принимает PQ и classical (negotiate с клиентом)
export Citadel_MLDSA=1   # M7 PQ-auth: гибрид Ed25519 + ML-DSA-65 (квантово-стойкая подпись сервера)
export Citadel_MLDSA_PUB_FILE=${Citadel_MLDSA_PUB_FILE:-/shared/exit.mldsa}   # exit2 переопределяет
rm -f /shared/exit.pin   # убрать устаревший pin от прошлого запуска
echo "[exit] старт citadel-m1 (server, PQ X25519MLKEM768)…"
exec citadel-m1
