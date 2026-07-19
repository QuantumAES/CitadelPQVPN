#!/usr/bin/env bash
# Издатель (биллинг, M5 issuer↔exit split): держит sk, СЛЕПО подписывает токены по TCP.
# Long-running сервис. Клиент получает токены интерактивно (издатель не видит сам токен →
# unlinkability даже при сговоре издателя и exit). Публикует issuer.pub в /shared для exit.
set -e
rm -f /shared/issuer.pub /shared/issuer-*.pub /shared/tokens   # C5.1: чистим и epoch-pub'ы прошлого запуска
# ДЕМО: чистим и реестр — харнес должен стартовать с чистого состояния (иначе revoked-абонент из
# прошлого прогона TEST 18 переживает рестарт из-за bootstrap-merge и ломает повторный прогон).
# В installer (install-citadel-server.sh) реестр НЕ трётся — там revoke обязан переживать рестарт.
rm -f /shared/registry
# Общий obfs-PSK для exit↔client генерируем здесь (а не хардкодим в репозитории).
# Для прода PSK доставляется в конфиге по аутентифицированному каналу (см. docs/PHASE0-OBFS §8).
[ -f /shared/obfs.psk ] || { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /shared/obfs.psk; }
echo "[issuer] общий obfs-PSK → /shared/obfs.psk"
export Citadel_TOKEN_ROLE=issuer
export Citadel_TOKEN_DIR=/shared
export Citadel_TOKEN_LISTEN=0.0.0.0:7000
export Citadel_EPOCH_SECS=3600   # C5.1: длина эпохи (ДОЛЖНА совпадать с exit) — токены epoch-scoped
# C5.2 Layer-1: регистрируем демо-абонента (в проде реестром управляет админ, C5.5).
export Citadel_REGISTER_SEEDS=$(printf 'c5%.0s' {1..32})   # 32×c5 = ровно 64 hex = 32-байтный seed
# C7: admin-плоскость — отдельный listener (реестр по туннелю; exit DNAT'ит ADMIN_VIP:7001 сюда).
# admin_id = pub демо-admin-seed'а ('ad'×32; в проде seed генерит installer и кладёт в мастер-ссылку);
# secure default: без файла admin_id канал никого не пускает.
export Citadel_ADMIN_LISTEN=0.0.0.0:7001
ADMIN_SEED=$(printf 'ad%.0s' {1..32})
# NB: Citadel_TOKEN_ROLE=issuer уже экспортирован, а env-роль приоритетнее arg[1] → для pubkey
# роль переопределяем явно (иначе вызов запустил бы второй issuer и завис).
Citadel_TOKEN_ROLE=pubkey Citadel_CLIENT_SEED=$ADMIN_SEED citadel-token > /shared/admin_id
# admin.client_id — Layer-1 client_id самого админа (= демо-абонент 'c5'): его отзыв по каналу
# issuer отклоняет (анти-self-lockout, R6) — негатив проверяется в ТЕСТ 21.
Citadel_TOKEN_ROLE=pubkey Citadel_CLIENT_SEED=$Citadel_REGISTER_SEEDS citadel-token > /shared/admin.client_id
echo "[issuer] admin-плоскость: admin_id=$(cut -c1-16 /shared/admin_id)… (канал :7001, только из туннеля)"
echo "[issuer] старт слепого подписания (генерация RSA-ключа, затем TCP :7000)…"
exec citadel-token
