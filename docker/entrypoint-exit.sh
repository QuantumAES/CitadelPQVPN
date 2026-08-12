#!/usr/bin/env bash
# exit-узел (сервер): TUN 10.7.0.1/16, ip_forward + MASQUERADE → интернет.
# Пишет pin своего сертификата в /shared/exit.pin (F1, клиент его пиннит).
set -e
export Citadel_ROLE=server
# ДЕМО/E2E-стенд: включаем диагностический вывод. В проде (env от AdminDeployer) его НЕТ —
# серверные роли по умолчанию молчат о клиентах и их трафике (no-logs, citadel_quic::debug_logs).
export Citadel_DEBUG_LOG=1
# L-10 (аудит-4): ЭТО ДЕМО-СТЕНД, НЕ ПРОД. Флаг разрешает то, что в проде запрещено: слабые
# seed'ы из повторяющегося шаблона (c5c5…/adad…) и диагностический лог без предупреждения.
# Прод-установщик (tools/install-citadel-server.sh) его НЕ выставляет — скопированный отсюда
# entrypoint без правок просто не запустится.
export Citadel_DEMO_STAND=1
# Порты стенда параметризованы (п.2 «порты первым классом»): CLI-стенд поднимается на
# НЕСТАНДАРТНЫХ портах, и это постоянная проверка, что 4433/443/7000 нигде не захардкожены
# на пути клиента. Дефолты — прежние.
export Citadel_LISTEN=0.0.0.0:${CITADEL_UDP_PORT:-4433}
export Citadel_TUN=Citadel0
export Citadel_TUN_ADDR=10.7.0.1/16
export Citadel_MTU=1161   # = citadel_quic::INNER_MTU: ровно то, что влезает в одну QUIC-датаграмму (выше — тихий дроп, ниже — дроп крупных UDP от клиента)
export Citadel_NAT_SRC=10.7.0.0/16
export Citadel_PIN_FILE=${Citadel_PIN_FILE:-/shared/exit.pin}   # exit2 переопределяет (multi-server, M5)
export Citadel_OBFS_PSK=$(cat /shared/obfs.psk)   # общий PSK сгенерирован издателем (не хардкод)
# H-3: канал данных принимает ТОЛЬКО ключи эпох, выведенные из мастера (PSK из ссылки его больше
# не открывает). Мастер кладёт издатель; ждём его появления так же, как ключа эпохи.
for _ in $(seq 1 60); do [ -f /shared/obfs.master ] && break; sleep 1; done
[ -f /shared/obfs.master ] && export Citadel_OBFS_MASTER=$(cat /shared/obfs.master)
export Citadel_ISSUER_KEY=/shared/issuer.key   # F-M4: проверка анонимных токенов (M-6: ключ эпохи СЕКРЕТЕН)
export Citadel_EPOCH_SECS=3600   # C5.1: epoch-scoped — exit читает issuer-<epoch>.key (current±prev)
export Citadel_RATE_LIMIT=131072   # F7/D3: 128 KiB/с на клиента вверх (анти-абуз/исчерпание ресурсов)
export Citadel_RATE_BURST=262144   # допустимый всплеск 256 KiB
# M-3-bis: направление «вниз» намеренно НЕ задано — стенд проверяет дефолт «симметрично вверх»
# (Citadel_RATE_LIMIT_DOWN не задан ⇒ тот же bucket-конфиг на return-трафик).
export Citadel_TCP_LISTEN=0.0.0.0:${CITADEL_TCP_PORT:-443}   # M4: obfs-over-TCP fallback (когда UDP/QUIC заблокирован)
export Citadel_KX=all   # M6 crypto-agility: exit принимает PQ и classical (negotiate с клиентом)
export Citadel_MLDSA=1   # M7 PQ-auth: гибрид Ed25519 + ML-DSA-65 (квантово-стойкая подпись сервера)
export Citadel_MLDSA_PUB_FILE=${Citadel_MLDSA_PUB_FILE:-/shared/exit.mldsa}   # exit2 переопределяет
# C7.2 admin-плоскость: data-plane пропускает TCP к ADMIN_VIP:7001 из туннеля (после анти-спуфинга),
# ядро DNAT'ит на issuer (-i Citadel0 → порт на ВНЕШНЕМ интерфейсе exit НЕ открывается — ТЕСТ 22).
export Citadel_ADMIN_VIP=10.7.0.1   # = шлюз Citadel_TUN_ADDR (инвариант ADMIN_VIP)
export Citadel_ADMIN_PORT=${CITADEL_ADMIN_PORT:-7001}
ISSUER_IP=$(getent hosts issuer | awk '{print $1; exit}')
export Citadel_ADMIN_DNAT="${ISSUER_IP}:${Citadel_ADMIN_PORT}"
echo "[exit] admin-plane: DNAT ${Citadel_ADMIN_VIP}:${Citadel_ADMIN_PORT} -> ${Citadel_ADMIN_DNAT} (только из туннеля)"
# G1/G2 (аудит-5): запрет форварда из туннеля на инфраструктурные адреса. На живом деплое сюда
# установщик кладёт публичный IP машины и адрес издателя; на стенде публичного адреса у контейнера
# нет, поэтому механизм проверяется на паре публичных адресов Cloudflare (ТЕСТ 25): 1.0.0.1
# закрыт целиком, кроме TCP :80 — ровно так же, как на деплое закрыт хост, кроме token-порта.
export Citadel_DENY_DSTS=${CITADEL_DENY_DSTS:-1.0.0.1}
export Citadel_ALLOW_DSTS=${CITADEL_ALLOW_DSTS:-1.0.0.1:80}
rm -f /shared/exit.pin   # убрать устаревший pin от прошлого запуска
echo "[exit] старт citadel-m1 (server, PQ X25519MLKEM768)…"
exec citadel-m1
