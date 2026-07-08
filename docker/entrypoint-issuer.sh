#!/usr/bin/env bash
# Издатель (биллинг, M5 issuer↔exit split): держит sk, СЛЕПО подписывает токены по TCP.
# Long-running сервис. Клиент получает токены интерактивно (издатель не видит сам токен →
# unlinkability даже при сговоре издателя и exit). Публикует issuer.pub в /shared для exit.
set -e
rm -f /shared/issuer.pub /shared/issuer-*.pub /shared/tokens   # C5.1: чистим и epoch-pub'ы прошлого запуска
# Общий obfs-PSK для exit↔client генерируем здесь (а не хардкодим в репозитории).
# Для прода PSK доставляется в конфиге по аутентифицированному каналу (см. docs/PHASE0-OBFS §8).
[ -f /shared/obfs.psk ] || { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /shared/obfs.psk; }
echo "[issuer] общий obfs-PSK → /shared/obfs.psk"
export Citadel_TOKEN_ROLE=issuer
export Citadel_TOKEN_DIR=/shared
export Citadel_TOKEN_LISTEN=0.0.0.0:7000
export Citadel_EPOCH_SECS=3600   # C5.1: длина эпохи (ДОЛЖНА совпадать с exit) — токены epoch-scoped
echo "[issuer] старт слепого подписания (генерация RSA-ключа, затем TCP :7000)…"
exec citadel-token
