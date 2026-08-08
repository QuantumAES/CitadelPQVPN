#!/usr/bin/env bash
# Издатель (биллинг, M5 issuer↔exit split): держит ключ эпохи, вычисляет ВСЛЕПУЮ по TCP.
# Long-running сервис. Клиент получает токены интерактивно (издатель не видит сам токен →
# unlinkability даже при сговоре издателя и exit). Кладёт issuer.key в /shared для exit
# (M-6: схема токенов v2 — VOPRF; ключ эпохи стал СЕКРЕТОМ, файл 0640 с группой exit'а).
set -e
rm -f /shared/issuer.key /shared/issuer-*.key /shared/issuer.pub /shared/issuer-*.pub /shared/tokens
# ДЕМО: чистим и реестр — харнес должен стартовать с чистого состояния (иначе revoked-абонент из
# прошлого прогона TEST 18 переживает рестарт из-за bootstrap-merge и ломает повторный прогон).
# В installer (install-citadel-server.sh) реестр НЕ трётся — там revoke обязан переживать рестарт.
rm -f /shared/registry
# Общий obfs-PSK для exit↔client генерируем здесь (а не хардкодим в репозитории).
# Для прода PSK доставляется в конфиге по аутентифицированному каналу (см. docs/PHASE0-OBFS §8).
[ -f /shared/obfs.psk ] || { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /shared/obfs.psk; }
echo "[issuer] общий obfs-PSK → /shared/obfs.psk"
# S2.1/A1-остаток: issuer оборачивает token- и admin-каналы в obfs тем же PSK (probe-resistance:
# issuer-порт молчит на не-obfs пробу и на проводе неотличим от туннеля). Клиент берёт PSK из ссылки.
export Citadel_OBFS_PSK=$(cat /shared/obfs.psk)
# H-3: МАСТЕР-секрет L1 (в ссылки не попадает!). Из него издатель выдаёт абоненту ключ ТЕКУЩЕЙ
# эпохи — после Layer-1 и ровно на эпоху; exit тем же мастером выводит ключи, которыми принимает.
# Бутстрапный obfs.psk остаётся обёрткой канала К ИЗДАТЕЛЮ (его адрес и так лежит в ссылке).
[ -f /shared/obfs.master ] || { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /shared/obfs.master; }
chmod 640 /shared/obfs.master
export Citadel_OBFS_MASTER=$(cat /shared/obfs.master)
export Citadel_TOKEN_ROLE=issuer
# ДЕМО/E2E-стенд: включаем диагностический вывод. В проде (env от AdminDeployer) его НЕТ —
# серверные роли по умолчанию молчат о клиентах и их трафике (no-logs, citadel_quic::debug_logs).
export Citadel_DEBUG_LOG=1
# L-10 (аудит-4): ЭТО ДЕМО-СТЕНД, НЕ ПРОД. Флаг разрешает то, что в проде запрещено: слабые
# seed'ы из повторяющегося шаблона (c5c5…/adad…) и диагностический лог без предупреждения.
# Прод-установщик (tools/install-citadel-server.sh) его НЕ выставляет — скопированный отсюда
# entrypoint без правок просто не запустится.
export Citadel_DEMO_STAND=1
export Citadel_TOKEN_DIR=/shared
export Citadel_TOKEN_LISTEN=0.0.0.0:${CITADEL_ISSUER_PORT:-7000}
export Citadel_EPOCH_SECS=3600   # C5.1: длина эпохи (ДОЛЖНА совпадать с exit) — токены epoch-scoped
# C5.2 Layer-1: регистрируем демо-абонента (в проде реестром управляет админ, C5.5).
export Citadel_REGISTER_SEEDS=$(printf 'c5%.0s' {1..32})   # 32×c5 = ровно 64 hex = 32-байтный seed
# C7: admin-плоскость — отдельный listener (реестр по туннелю; exit DNAT'ит ADMIN_VIP:7001 сюда).
# admin_id = pub демо-admin-seed'а ('ad'×32; в проде seed генерит installer и кладёт в мастер-ссылку);
# secure default: без файла admin_id канал никого не пускает.
export Citadel_ADMIN_LISTEN=0.0.0.0:${CITADEL_ADMIN_PORT:-7001}
# M-6/P1: keysync — раздача ключа эпохи exit-узлу на ДРУГОЙ машине. Ключ секретен, поэтому запрос
# аутентифицируется своей идентичностью; здесь демо-seed 'ec'×32, в проде его генерит установщик.
KEYSYNC_SEED=$(printf 'ec%.0s' {1..32})
ADMIN_SEED=$(printf 'ad%.0s' {1..32})
# NB: Citadel_TOKEN_ROLE=issuer уже экспортирован, а env-роль приоритетнее arg[1] → для pubkey
# роль переопределяем явно (иначе вызов запустил бы второй issuer и завис).
Citadel_TOKEN_ROLE=pubkey Citadel_CLIENT_SEED=$ADMIN_SEED citadel-token > /shared/admin_id
# admin.client_id — Layer-1 client_id самого админа (= демо-абонент 'c5'): его отзыв по каналу
# issuer отклоняет (анти-self-lockout, R6) — негатив проверяется в ТЕСТ 21.
Citadel_TOKEN_ROLE=pubkey Citadel_CLIENT_SEED=$Citadel_REGISTER_SEEDS citadel-token > /shared/admin.client_id
export Citadel_KEYSYNC_ID=$(Citadel_TOKEN_ROLE=pubkey Citadel_CLIENT_SEED=$KEYSYNC_SEED citadel-token)
echo "[issuer] admin-плоскость: admin_id=$(cut -c1-16 /shared/admin_id)… (канал :${CITADEL_ADMIN_PORT:-7001}, только из туннеля)"
# M-4 (аудит-4): привилегии издателя режет compose (cap_drop: ALL + read_only + no-new-privileges) —
# capability у процесса не остаётся ни одной. Смену uid здесь НЕ делаем: том общий с exit'ом, и в
# него как root пишут ещё и exit, и (при раздельной установке) pubsync — переразметка владения
# затронула бы три роли сразу. Для запуска издателя вне докера есть Citadel_DROP_UID.
echo "[issuer] старт слепой выдачи (VOPRF ristretto255, TCP :${CITADEL_ISSUER_PORT:-7000})…"
exec citadel-token
