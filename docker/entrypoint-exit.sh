#!/usr/bin/env bash
# exit-узел (сервер): TUN 10.7.0.1/16, ip_forward + MASQUERADE → интернет.
# Пишет pin своего сертификата в /shared/exit.pin (F1, клиент его пиннит).
set -e
export Citadel_ROLE=server
# ДЕМО/E2E-стенд: включаем диагностический вывод. В проде (env от AdminDeployer) его НЕТ —
# серверные роли по умолчанию молчат о клиентах и их трафике (no-logs, citadel_quic::debug_logs).
export Citadel_DEBUG_LOG=1
export Citadel_LISTEN=0.0.0.0:4433
export Citadel_TUN=Citadel0
export Citadel_TUN_ADDR=10.7.0.1/16
export Citadel_MTU=1161   # = citadel_quic::INNER_MTU: ровно то, что влезает в одну QUIC-датаграмму (выше — тихий дроп, ниже — дроп крупных UDP от клиента)
export Citadel_NAT_SRC=10.7.0.0/16
export Citadel_PIN_FILE=${Citadel_PIN_FILE:-/shared/exit.pin}   # exit2 переопределяет (multi-server, M5)
export Citadel_OBFS_PSK=$(cat /shared/obfs.psk)   # общий PSK сгенерирован издателем (не хардкод)
export Citadel_ISSUER_PUB=/shared/issuer.pub   # F-M4: проверка анонимных токенов
export Citadel_EPOCH_SECS=3600   # C5.1: epoch-scoped — exit читает issuer-<epoch>.pub (current±prev)
export Citadel_RATE_LIMIT=131072   # F7/D3: 128 KiB/с на клиента (анти-абуз/исчерпание ресурсов)
export Citadel_RATE_BURST=262144   # допустимый всплеск 256 KiB
export Citadel_TCP_LISTEN=0.0.0.0:443   # M4: obfs-over-TCP fallback (когда UDP/QUIC заблокирован)
export Citadel_KX=all   # M6 crypto-agility: exit принимает PQ и classical (negotiate с клиентом)
export Citadel_MLDSA=1   # M7 PQ-auth: гибрид Ed25519 + ML-DSA-65 (квантово-стойкая подпись сервера)
export Citadel_MLDSA_PUB_FILE=${Citadel_MLDSA_PUB_FILE:-/shared/exit.mldsa}   # exit2 переопределяет
# C7.2 admin-плоскость: data-plane пропускает TCP к ADMIN_VIP:7001 из туннеля (после анти-спуфинга),
# ядро DNAT'ит на issuer (-i Citadel0 → порт на ВНЕШНЕМ интерфейсе exit НЕ открывается — ТЕСТ 22).
export Citadel_ADMIN_VIP=10.7.0.1   # = шлюз Citadel_TUN_ADDR (инвариант ADMIN_VIP)
export Citadel_ADMIN_PORT=7001
ISSUER_IP=$(getent hosts issuer | awk '{print $1; exit}')
export Citadel_ADMIN_DNAT="${ISSUER_IP}:7001"
echo "[exit] admin-plane: DNAT ${Citadel_ADMIN_VIP}:${Citadel_ADMIN_PORT} -> ${Citadel_ADMIN_DNAT} (только из туннеля)"
rm -f /shared/exit.pin   # убрать устаревший pin от прошлого запуска
echo "[exit] старт citadel-m1 (server, PQ X25519MLKEM768)…"
exec citadel-m1
