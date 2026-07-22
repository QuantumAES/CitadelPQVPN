#!/usr/bin/env bash
# ═════════════════════════════════════════════════════════════════════════════
#  CitadelPQVPN — установщик exit-сервера. ЗАПУСКАТЬ НА СЕРВЕРЕ ОТ ROOT.
#
#    ssh root@СЕРВЕР 'bash -s' -- vX.Y.Z  < tools/install-citadel-server.sh
#    # или скопировать на сервер и:  CITADEL_VERSION=vX.Y.Z ./install-citadel-server.sh
#    # локально (без скачивания релиза, dev/air-gapped): собрать бинари и указать каталог с ними —
#    #   cargo build --release -p citadel-quic -p citadel-token -p citadel-client
#    #   sudo CITADEL_LOCAL_BIN=$PWD/target/release ./install-citadel-server.sh
#    #   (нужны citadel-m1, citadel-token, citadel-linkgen в этом каталоге; подпись НЕ проверяется)
#
#  Делает: авто-Docker → скачивает ПОДПИСАННЫЕ бинари релиза и ВЕРИФИЦИРУЕТ их
#  (minisign вшитым ключом → sha256 → распаковка) → keygen на сервере →
#  собирает образ + docker compose up → печатает админскую citadel://-ссылку.
#  Первая установка без GUI-клиента (§8).
#
#  C5.4b двухслойная идентичность (по умолчанию, CITADEL_ISSUER=1):
#    • рядом с exit поднимается ИЗДАТЕЛЬ (citadel-token) — Layer-1 реестр «абонентов»
#      + слепая выдача epoch-токенов; exit требует epoch-токен текущей эпохи (отзыв по времени);
#    • генерится client_seed «абонента»; в реестре issuer'а регистрируется ЕГО PUB (client_id) —
#      издатель НЕ узнаёт seed (в ссылку он идёт только клиенту);
#    • на exit включается ML-DSA-65 (M7), в ссылку кладётся обязательство H(pub).
#    CITADEL_ISSUER=0 → прежний token-less exit (одна bearer-ссылка, без issuer).
#
#  Supply-chain: бинари принимаются ТОЛЬКО если подпись сходится с вшитым ниже ключом.
#  Приватные ключи exit (cert/pin, ML-DSA) генерятся В КОНТЕЙНЕРЕ и наружу не уходят.
# ═════════════════════════════════════════════════════════════════════════════
set -euo pipefail

# ─── ВШИТЫЙ публичный ключ релиза (см. packaging/release/citadel-release.pub) ───
RELEASE_PUBKEY="RWSErwVVdH0bhg9dQViFezkqCQPfWpZt18rK0irjOOpNfUW3G4hkoNp4"

# ─── параметры (env или $1=version) ───
VERSION="${1:-${CITADEL_VERSION:-}}"
REPO="${CITADEL_REPO:-QuantumAES/CitadelPQVPN}"
BASE_URL="${CITADEL_BASE_URL:-https://github.com/$REPO/releases/download}"
SERVER_HOST="${CITADEL_SERVER_HOST:-}"       # публичный host/IP для ссылки; пусто → автодетект
UDP_PORT="${CITADEL_UDP_PORT:-4433}"
TCP_PORT="${CITADEL_TCP_PORT:-443}"
ROUTES="${CITADEL_ROUTES:-0.0.0.0/0}"        # что гнать в туннель (full-tunnel по умолчанию)
DNS="${CITADEL_DNS:-1.1.1.1}"                # DNS, проталкиваемый клиенту (через туннель; анти-leak F6)
DIR="${CITADEL_DIR:-/opt/citadel}"
LOCAL_BIN="${CITADEL_LOCAL_BIN:-}"           # dir с УЖЕ СОБРАННЫМИ citadel-m1/token/linkgen →
                                             # локальная установка БЕЗ скачивания релиза (dev/air-gapped;
                                             # подпись НЕ проверяется). Пусто = штатно тянем релиз с GitHub.
ISSUER_ON="${CITADEL_ISSUER:-1}"             # 1 = двухслойная идентичность (issuer+токены+ML-DSA); 0 = token-less
ISSUER_PORT="${CITADEL_ISSUER_PORT:-7000}"   # публичный порт издателя (клиент фетчит токены сюда)
ADMIN_PORT="${CITADEL_ADMIN_PORT:-7001}"     # C7.2: порт admin-канала — НЕ публикуется наружу (только из туннеля)
ADMIN_VIP="${CITADEL_ADMIN_VIP:-10.7.0.1}"   # C7.2: admin-VIP = шлюз туннеля (= Citadel_TUN_ADDR exit'а)
EPOCH_SECS="${CITADEL_EPOCH_SECS:-3600}"     # длина эпохи токенов (exit и issuer ДОЛЖНЫ совпадать)
LEASE_SECS="${CITADEL_LEASE_SECS:-0}"        # задача 4/B: single-session — окно аренды на абонента (с);
                                             # 0 = выкл. >0 ⇒ одна ссылка открывает новую сессию не чаще
                                             # раза в N с (ограничивает шеринг; реконнект в окне ждёт)

log()  { printf '\033[1;36m[citadel]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[citadel] ⚠ %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[1;31m[citadel] ОШИБКА: %s\033[0m\n' "$*" >&2; exit 1; }

# ─── 0. преконды ───
[[ "$(id -u)" == "0" ]] || die "запусти от root (sudo)"
if [[ -n "$LOCAL_BIN" ]]; then
  [[ -d "$LOCAL_BIN" ]] || die "CITADEL_LOCAL_BIN не каталог: $LOCAL_BIN"
  VERSION="${VERSION:-local-$(date +%Y%m%d%H%M%S)}"   # версия = тег образа (не для скачивания)
else
  [[ -n "$VERSION" ]] || die "укажи версию релиза: аргументом или CITADEL_VERSION=vX.Y.Z (pin версии, не «latest»); ИЛИ CITADEL_LOCAL_BIN=<dir> для локальной установки"
fi
case "$(uname -m)" in
  x86_64|amd64)  ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
  *) die "неподдерживаемая арка: $(uname -m)" ;;
esac
[[ -e /dev/net/tun ]] || { modprobe tun 2>/dev/null || true; }
[[ -e /dev/net/tun ]] || die "нет /dev/net/tun — TUN недоступен на этом сервере"
log "версия=$VERSION арка=$ARCH каталог=$DIR issuer=$ISSUER_ON"

# ─── 1. базовые утилиты (curl/minisign/zstd) ───
# minisign/zstd нужны ТОЛЬКО для скачивания+верификации релиза; при LOCAL_BIN их не ставим.
pkgs=()
command -v curl     >/dev/null || pkgs+=(curl ca-certificates)
if [[ -z "$LOCAL_BIN" ]]; then
  command -v minisign >/dev/null || pkgs+=(minisign)
  command -v zstd     >/dev/null || pkgs+=(zstd)
fi
if ((${#pkgs[@]})); then
  log "ставлю утилиты: ${pkgs[*]}"
  if   command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y -qq "${pkgs[@]}"
  elif command -v dnf     >/dev/null; then dnf install -y -q "${pkgs[@]}"
  else die "нет apt-get/dnf — поставь вручную: ${pkgs[*]}"; fi
fi

# ─── 2. Docker: CLI+compose v2 (нет → авто-install) И запущенный ДЕМОН (лежит → старт) ───
if ! docker compose version >/dev/null 2>&1; then
  log "Docker не найден — авто-установка (get.docker.com)…"
  curl -fsSL https://get.docker.com | sh || die "установка Docker не удалась (дистрибутив не поддержан?)"
  systemctl enable --now docker 2>/dev/null || true
  docker compose version >/dev/null 2>&1 || die "docker compose недоступен после установки"
fi
# CLI может отвечать, а демон быть остановлен → `docker info` это ловит (иначе `up` падает невнятно)
if ! docker info >/dev/null 2>&1; then
  log "Docker-демон недоступен — запускаю…"
  systemctl start docker 2>/dev/null || systemctl restart docker 2>/dev/null || true
  for _ in $(seq 1 10); do docker info >/dev/null 2>&1 && break; sleep 1; done
  docker info >/dev/null 2>&1 || die "Docker-демон не поднялся (проверь: systemctl status docker)"
fi
log "Docker: $(docker --version)"

# ─── 3. получить бинари: скачать+ВЕРИФИЦИРОВАТЬ релиз ЛИБО скопировать локальные (LOCAL_BIN) ───
# citadel-token нужен для issuer-контейнера; берём всегда (образ общий), задействуем при ISSUER_ON.
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
mkdir -p "$DIR/bin" "$DIR/keys" "$DIR/etc"
# 711 (не 700!): exit сбрасывает привилегии до nobody (F4) и per-auth ЧИТАЕТ публичные issuer-<epoch>.pub
# из этого каталога. При 700 nobody не может войти в каталог → чтение падает → verify_token видит
# пустой список ключей → ВСЕ токены «невалидны» (тихо, docker-демо это не ловит — named volume там 0755).
# 711 даёт traverse без листинга; секреты (obfs.psk/client.seed) остаются 600 и nobody недоступны.
chmod 711 "$DIR/keys"
# Q4: citadel-linkgen НЕ кладём на бокс (только tmp) — после установки нет инструмента минта ссылок.
LINKGEN="$work/citadel-linkgen"

if [[ -z "$LOCAL_BIN" ]]; then
  # штатно: скачать подписанный релиз → проверить подпись+sha256 → распаковать .zst
  ( cd "$work"
    log "скачиваю релиз $VERSION ($ARCH)…"
    for f in "citadel-m1-$ARCH.zst" "citadel-linkgen-$ARCH.zst" "citadel-token-$ARCH.zst" sha256sums sha256sums.minisig; do
      curl -fsSL -o "$f" "$BASE_URL/$VERSION/$f" || die "не скачался: $f"
    done
    log "проверяю подпись sha256sums вшитым ключом…"
    minisign -V -P "$RELEASE_PUBKEY" -m sha256sums >/dev/null \
      || die "ПОДПИСЬ НЕ ПРОШЛА — артефакт подделан/повреждён. Остановка."
    log "проверяю sha256 бинарей…"
    sha256sum -c --ignore-missing sha256sums >/dev/null || die "sha256 не совпал. Остановка."
  )
  log "подпись и хеши OK — распаковываю"
  for name in citadel-m1 citadel-token; do
    zstd -q -d -f "$work/$name-$ARCH.zst" -o "$DIR/bin/$name"
    chmod +x "$DIR/bin/$name"
  done
  zstd -q -d -f "$work/citadel-linkgen-$ARCH.zst" -o "$LINKGEN"
  chmod +x "$LINKGEN"
else
  # локально: копируем УЖЕ СОБРАННЫЕ бинари из LOCAL_BIN (без скачивания/подписи). Для dev/air-gapped:
  # cargo build --release -p citadel-quic -p citadel-token -p citadel-client → бинари в target/release.
  warn "ЛОКАЛЬНАЯ установка из '$LOCAL_BIN' — БЕЗ проверки подписи (доверяй источнику; dev/air-gapped)."
  for name in citadel-m1 citadel-token; do
    [[ -x "$LOCAL_BIN/$name" ]] || die "нет исполняемого $LOCAL_BIN/$name (собери: cargo build --release)"
    install -m 0755 "$LOCAL_BIN/$name" "$DIR/bin/$name"
  done
  [[ -x "$LOCAL_BIN/citadel-linkgen" ]] || die "нет исполняемого $LOCAL_BIN/citadel-linkgen"
  install -m 0755 "$LOCAL_BIN/citadel-linkgen" "$LINKGEN"   # linkgen тоже в tmp (Q4), не на бокс
  log "локальные бинари скопированы из '$LOCAL_BIN'"
fi

# ─── 3.5 ротация идентичности при ОБНОВЛЕНИИ (задача 2) ───
# Обновление сервера ОБЯЗАНO инвалидировать ВСЕ ранее розданные ссылки — и клиентские, и мастер:
# перегенерим все вшитые-в-ссылку секреты (obfs_psk, cert/pin, ML-DSA, issuer-TLS-pin, epoch-RSA,
# client.seed, admin.seed) + сотрём реестр. Старая ссылка после этого не пройдёт НИ obfs (новый PSK
# → probe-reject), НИ cert-pin (новый серт), НИ Layer-1 (client_id не в новом реестре) — туннель не
# поднимется ни у клиента, ни у админа. Персист (A7) защищает только docker-restart/ребут VPS (том
# цел, ключи те же); СМЕНА ключей происходит РОВНО при (пере)запуске installer. Opt-out:
# CITADEL_KEEP_KEYS=1 — сохранить ТРАНСПОРТНУЮ идентичность (obfs/cert-pin/mldsa/issuer-tls) + реестр,
# чтобы уже розданные КЛИЕНТСКИЕ ссылки пережили обновление бинаря. NB (§8): seed'ы абонента/админа
# теперь ВСЕГДА эфемерны — стираются после печати; мастер-ссылка и показанная клиентская генерятся
# заново на каждый запуск (воспроизведения одной и той же ссылки нет, Q2/Q4).
if [[ -f "$DIR/keys/obfs.psk" && "${CITADEL_KEEP_KEYS:-0}" != 1 ]]; then
  warn "ОБНОВЛЕНИЕ: ротирую идентичность сервера — ВСЕ прежние ссылки (клиентские и мастер) станут"
  warn "недействительны. Раздай новые ссылки из вывода ниже. (CITADEL_KEEP_KEYS=1 — сохранить старые.)"
  # остановить контейнеры, держащие старые ключи в RAM — при up перечитают свежие из тома
  [[ -f "$DIR/etc/compose.yml" ]] && docker compose -f "$DIR/etc/compose.yml" down >/dev/null 2>&1 || true
  rm -f "$DIR/keys/"obfs.psk "$DIR/keys/"client.seed "$DIR/keys/"admin.seed \
        "$DIR/keys/"admin_id "$DIR/keys/"admin.client_id "$DIR/keys/"registry "$DIR/keys/"tokens \
        "$DIR/keys/"exit.pin "$DIR/keys/"exit-cert.der "$DIR/keys/"exit-key.der \
        "$DIR/keys/"exit-mldsa.seed "$DIR/keys/"exit.mldsa "$DIR/keys/"exit2.pin "$DIR/keys/"exit2.mldsa \
        "$DIR/keys/"issuer-tls.crt "$DIR/keys/"issuer-tls.key "$DIR/keys/"issuer-tls.pin \
        "$DIR/keys/"issuer.pub "$DIR"/keys/issuer-*.pub 2>/dev/null || true
fi

# ─── 4. keygen на сервере: obfs PSK + (issuer) client_seed «абонента» ───
PSK_FILE="$DIR/keys/obfs.psk"
if [[ ! -f "$PSK_FILE" ]]; then
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$PSK_FILE"
  chmod 600 "$PSK_FILE"
fi
PSK="$(cat "$PSK_FILE")"

CLIENT_SEED=""; CLIENT_PUB=""
ADMIN_SEED=""; ADMIN_PUB=""
if [[ "$ISSUER_ON" == 1 ]]; then
  # client_seed = приватный Ed25519 «абонента» (Layer-1); хранится ТОЛЬКО у админа (в ссылке).
  SEED_FILE="$DIR/keys/client.seed"
  if [[ ! -f "$SEED_FILE" ]]; then
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$SEED_FILE"
    chmod 600 "$SEED_FILE"
  fi
  CLIENT_SEED="$(cat "$SEED_FILE")"
  # В реестр издателя пишем PUB (client_id), а НЕ seed → издатель не знает секрет абонента.
  CLIENT_PUB="$(Citadel_CLIENT_SEED="$CLIENT_SEED" "$DIR/bin/citadel-token" pubkey)" \
    || die "не удалось вывести client_id абонента (citadel-token pubkey)"
  log "Layer-1 абонент: client_id=${CLIENT_PUB:0:16}… (seed остаётся только в ссылке)"

  # C7.2 admin-плоскость: ОТДЕЛЬНЫЙ Ed25519 админа (не равен client.seed — домен-разделение auth).
  # admin.seed уходит ТОЛЬКО в мастер-ссылку; на сервере (том issuer) остаётся лишь pub (admin_id).
  ADMIN_SEED_FILE="$DIR/keys/admin.seed"
  if [[ ! -f "$ADMIN_SEED_FILE" ]]; then
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$ADMIN_SEED_FILE"
    chmod 600 "$ADMIN_SEED_FILE"
  fi
  ADMIN_SEED="$(cat "$ADMIN_SEED_FILE")"
  ADMIN_PUB="$(Citadel_CLIENT_SEED="$ADMIN_SEED" "$DIR/bin/citadel-token" pubkey)" \
    || die "не удалось вывести admin_id (citadel-token pubkey)"
  # admin_id — pub, по которому issuer пускает в admin-канал. admin.client_id — Layer-1 client_id
  # самого админа: issuer запрещает его отзыв (анти-self-lockout, R6). Оба файла читает issuer из /shared.
  printf '%s' "$ADMIN_PUB"  > "$DIR/keys/admin_id"
  printf '%s' "$CLIENT_PUB" > "$DIR/keys/admin.client_id"
  chmod 644 "$DIR/keys/admin_id" "$DIR/keys/admin.client_id"  # публичные id (не секрет), nobody читает
  log "admin-плоскость: admin_id=${ADMIN_PUB:0:16}… (admin.seed только в мастер-ссылке)"
fi

# ─── 5. образ (Dockerfile) + entrypoints + compose ───
cat > "$DIR/etc/Dockerfile" <<'EOF'
# S1.5: digest-pin базового образа (OCI index, мульти-арч) — supply-chain/воспроизводимость
FROM debian:trixie-slim@sha256:28de0877c2189802884ccd20f15ee41c203573bd87bb6b883f5f46362d24c5c2
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iptables iputils-ping curl ca-certificates dnsutils \
    && rm -rf /var/lib/apt/lists/*
COPY bin/citadel-m1 /usr/local/bin/citadel-m1
COPY bin/citadel-token /usr/local/bin/citadel-token
COPY etc/entrypoint-exit.sh /usr/local/bin/entrypoint-exit.sh
COPY etc/entrypoint-issuer.sh /usr/local/bin/entrypoint-issuer.sh
RUN chmod +x /usr/local/bin/citadel-m1 /usr/local/bin/citadel-token \
        /usr/local/bin/entrypoint-exit.sh /usr/local/bin/entrypoint-issuer.sh
EOF

# entrypoint exit-узла. При ISSUER_ON — требует epoch-токен и включает ML-DSA (M7).
{
  cat <<'EOF'
#!/usr/bin/env bash
set -e
export Citadel_ROLE=server
export Citadel_LISTEN=0.0.0.0:4433
export Citadel_TUN=Citadel0
export Citadel_TUN_ADDR=10.7.0.1/16
export Citadel_MTU=1100
export Citadel_NAT_SRC=10.7.0.0/16
export Citadel_PIN_FILE=/shared/exit.pin
export Citadel_KEY_DIR=/shared   # A7: постоянная идентичность exit (cert/pin + ML-DSA seed) → рестарт НЕ ломает розданные ссылки
export Citadel_OBFS_PSK="${Citadel_OBFS_PSK:-}"
export Citadel_TCP_LISTEN=0.0.0.0:443
export Citadel_KX=pq   # S1.1/M4: PQ-only (анти-HNDL) — classical не принимаем
rm -f /shared/exit.pin   # pin перезапишется тем же значением из постоянного серта (A7)
EOF
  if [[ "$ISSUER_ON" == 1 ]]; then
    cat <<EOF
# C5.4b: exit требует анонимный epoch-токен текущей эпохи (отзыв по времени, M6).
export Citadel_ISSUER_PUB=/shared/issuer.pub
export Citadel_EPOCH_SECS=$EPOCH_SECS
# M7 PQ-auth: гибрид Ed25519 + ML-DSA-65 (квантово-стойкая подпись сервера); pub → /shared/exit.mldsa.
export Citadel_MLDSA=1
export Citadel_MLDSA_PUB_FILE=/shared/exit.mldsa
rm -f /shared/exit.mldsa
# C7.2 admin-плоскость: пропуск в data-plane к admin-VIP:порт + DNAT на issuer (реестр по туннелю).
# VIP = шлюз туннеля (Citadel_TUN_ADDR); порт наружу НЕ опубликован → admin-канал только из туннеля.
# Резолвим issuer по docker-DNS в IP (iptables DNAT принимает адрес, не имя).
export Citadel_ADMIN_VIP=$ADMIN_VIP
export Citadel_ADMIN_PORT=$ADMIN_PORT
ISSUER_IP="\$(getent hosts issuer | awk '{print \$1}' | head -n1)"
if [ -n "\$ISSUER_IP" ]; then
  export Citadel_ADMIN_DNAT="\$ISSUER_IP:$ADMIN_PORT"
  echo "[citadel-exit] admin-plane: DNAT $ADMIN_VIP:$ADMIN_PORT -> \$ISSUER_IP:$ADMIN_PORT (только из туннеля)"
else
  echo "[citadel-exit] ⚠ admin-plane: issuer не резолвится — DNAT не поднят (admin по туннелю недоступен)"
fi
echo "[citadel-exit] token-required (epoch=${EPOCH_SECS}s) + ML-DSA; listen 4433/udp + 443/tcp"
EOF
  else
    echo 'echo "[citadel-exit] token-less; listen 4433/udp + 443/tcp"'
  fi
  echo 'exec citadel-m1'
} > "$DIR/etc/entrypoint-exit.sh"
chmod +x "$DIR/etc/entrypoint-exit.sh"

# entrypoint издателя (генерируется всегда; задействуется только при ISSUER_ON).
# Реестр (/shared/registry) НЕ удаляем — admin-revoke переживает рестарт (bootstrap лишь досевает).
cat > "$DIR/etc/entrypoint-issuer.sh" <<EOF
#!/usr/bin/env bash
set -e
export Citadel_TOKEN_ROLE=issuer
export Citadel_TOKEN_DIR=/shared
export Citadel_TOKEN_LISTEN=0.0.0.0:7000
# C7.2 admin-канал: тот же PQ-TLS+pin, отдельный порт. НЕ публикуется наружу (compose без ports:7001)
# → достижим только из туннеля (exit DNAT'ит). admin_id/admin.client_id читаются из /shared.
export Citadel_ADMIN_LISTEN=0.0.0.0:$ADMIN_PORT
export Citadel_EPOCH_SECS=$EPOCH_SECS
export Citadel_TOKEN_LEASE_SECS=$LEASE_SECS   # задача 4/B: single-session (0=выкл; см. CITADEL_LEASE_SECS)
export Citadel_REGISTER_PUBS="$CLIENT_PUB"   # client_id админа (issuer НЕ получает seed)
rm -f /shared/issuer.pub /shared/issuer-*.pub /shared/tokens
echo "[citadel-issuer] Layer-1 registry + слепая выдача epoch-токенов (epoch=${EPOCH_SECS}s, :7000) + admin-канал :$ADMIN_PORT…"
exec citadel-token
EOF
chmod +x "$DIR/etc/entrypoint-issuer.sh"

# compose: exit (+ issuer при ISSUER_ON). Образ собираем отдельным `docker build` (ниже) — сервисы
# только ссылаются на image, поэтому порядок build/start однозначен.
{
cat <<EOF
name: citadel
services:
EOF
if [[ "$ISSUER_ON" == 1 ]]; then
cat <<EOF
  issuer:
    image: citadel-exit:$VERSION
    container_name: citadel-issuer
    entrypoint: ["/usr/local/bin/entrypoint-issuer.sh"]
    read_only: true                    # S1.5: неизменяемый rootfs (пишет только в /shared + tmpfs)
    tmpfs: ["/tmp"]
    security_opt: ["no-new-privileges:true"]
    restart: unless-stopped
    environment:
      Citadel_OBFS_PSK: "$PSK"         # S2.1/A1-остаток: obfs-обёртка token-/admin-каналов (probe-resistance)
    ports:
      - "$ISSUER_PORT:7000/tcp"        # клиент фетчит epoch-токены сюда (Layer-1)
    volumes:
      - "$DIR/keys:/shared"
    healthcheck:                       # готов, когда RSA-ключ эпохи сгенерирован и issuer.pub опубликован
      test: ["CMD-SHELL", "test -f /shared/issuer.pub"]
      interval: 2s
      timeout: 2s
      retries: 30
      start_period: 3s
EOF
fi
cat <<EOF
  exit:
    image: citadel-exit:$VERSION
    container_name: citadel-exit
    entrypoint: ["/usr/local/bin/entrypoint-exit.sh"]
    read_only: true                    # S1.5: неизменяемый rootfs (пишем только в /shared + tmpfs)
    tmpfs: ["/tmp", "/run"]             # /run — xtables.lock (iptables); /tmp — runtime-scratch
    cap_add: ["NET_ADMIN"]
    security_opt: ["no-new-privileges:true"]
    devices: ["/dev/net/tun:/dev/net/tun"]
    sysctls: ["net.ipv4.ip_forward=1"]
    restart: unless-stopped
    environment:
      Citadel_OBFS_PSK: "$PSK"
    ports:
      - "$UDP_PORT:4433/udp"
      - "$TCP_PORT:443/tcp"
    volumes:
      - "$DIR/keys:/shared"
EOF
if [[ "$ISSUER_ON" == 1 ]]; then
cat <<EOF
    depends_on:
      issuer: { condition: service_healthy }   # нужен issuer.pub для верификации токенов
EOF
fi
} > "$DIR/etc/compose.yml"

# ─── 6. сборка образа + up + health ───
log "собираю образ citadel-exit:$VERSION…"
docker build -t "citadel-exit:$VERSION" -f "$DIR/etc/Dockerfile" "$DIR"

log "поднимаю контейнер(ы) (docker compose up)…"
docker compose -f "$DIR/etc/compose.yml" up -d

log "жду готовности exit (cert/pin)…"
for _ in $(seq 1 90); do [[ -s "$DIR/keys/exit.pin" ]] && break; sleep 1; done
[[ -s "$DIR/keys/exit.pin" ]] || {
  docker compose -f "$DIR/etc/compose.yml" logs --tail 40 || true
  die "exit не поднялся за 90с (см. лог выше)"
}
PIN="$(cat "$DIR/keys/exit.pin")"

MLDSA_ARGS=()
ISSUER_TLS_PIN=""
if [[ "$ISSUER_ON" == 1 ]]; then
  log "жду издателя (issuer.pub, issuer-tls.pin) и ML-DSA pub exit'а…"
  for _ in $(seq 1 90); do [[ -s "$DIR/keys/issuer.pub" && -s "$DIR/keys/issuer-tls.pin" && -s "$DIR/keys/exit.mldsa" ]] && break; sleep 1; done
  [[ -s "$DIR/keys/issuer.pub" ]] || { docker compose -f "$DIR/etc/compose.yml" logs --tail 40 issuer || true; die "издатель не опубликовал issuer.pub за 90с"; }
  [[ -s "$DIR/keys/issuer-tls.pin" ]] || die "издатель не опубликовал issuer-tls.pin (PQ-TLS канал, A1) за 90с"
  [[ -s "$DIR/keys/exit.mldsa" ]] || die "exit не опубликовал ML-DSA pub (exit.mldsa) за 90с"
  MLDSA_ARGS=(--mldsa-pub "$DIR/keys/exit.mldsa")
  ISSUER_TLS_PIN="$(cat "$DIR/keys/issuer-tls.pin")"   # S2.1/A1: pin PQ-TLS канала издателя → в ссылку
fi

# ─── 7. публичный адрес + citadel:// (секрет) ───
if [[ -z "$SERVER_HOST" ]]; then
  SERVER_HOST="$(curl -fsS --max-time 8 https://api.ipify.org 2>/dev/null || true)"
fi
[[ -n "$SERVER_HOST" ]] || die "не удалось определить публичный IP — задай CITADEL_SERVER_HOST=<ip/host>"

LINKARGS=(--servers "$SERVER_HOST:$UDP_PORT" --psk "$PSK" --pin "$PIN"
          --kx pq --tcp-port "$TCP_PORT" --routes "$ROUTES" --dns "$DNS" "${MLDSA_ARGS[@]}")
if [[ "$ISSUER_ON" == 1 ]]; then
  # Layer-1: клиент авто-фетчит epoch-токен у издателя перед коннектом (issuer host:port + seed).
  # S2.1/A1: --issuer-pin → клиент пиннит PQ-TLS канал фетча (анти-MITM + скрытие client_id).
  LINKARGS+=(--issuer "$SERVER_HOST:$ISSUER_PORT" --issuer-pin "$ISSUER_TLS_PIN" --client-seed "$CLIENT_SEED")
fi
# Клиентская ссылка (для раздачи абонентам) — БЕЗ admin-seed. Генерим ДО добавления admin-полей.
# $LINKGEN — во временном каталоге (на бокс не кладётся, Q4).
CLIENT_LINK="$("$LINKGEN" "${LINKARGS[@]}" 2>/dev/null)" \
  || die "citadel-linkgen не сгенерировал клиентскую ссылку"

# C7.2: МАСТЕР-ссылка = клиентская + admin-плоскость (управление реестром по туннелю). ТОЛЬКО админу.
if [[ "$ISSUER_ON" == 1 ]]; then
  LINKARGS+=(--admin-seed "$ADMIN_SEED" --admin-port "$ADMIN_PORT")
fi
LINK="$("$LINKGEN" "${LINKARGS[@]}" 2>/dev/null)" \
  || die "citadel-linkgen не сгенерировал мастер-ссылку"

# Задача 3: ссылки НЕ сохраняем на диск сервера — печатаем ОДИН РАЗ здесь. Секретные креды
# (obfs_psk/pin/issuer_pin/seed'ы инлайн) не должны лежать в файле на VPS (кража диска/бэкапа =
# кража доступа). Забыл скопировать / нужно вспомнить → переустановка (задача 2: ротация даст НОВЫЕ
# ссылки, старые всё равно мертвы). На диске остаются только серверные секреты в keys/ (600/711).
cat <<EOF

╔══════════════════════════════════════════════════════════════════╗
║  CitadelPQVPN exit развёрнут ✓   ($SERVER_HOST:$UDP_PORT udp / $TCP_PORT tcp)
╚══════════════════════════════════════════════════════════════════╝

⚠ Ссылки печатаются ЗДЕСЬ и НИГДЕ не сохраняются. Скопируй их СЕЙЧАС. Забыл / потерял →
  запусти скрипт снова: он ротирует идентичность и выдаст НОВЫЕ ссылки (прежние, розданные до
  этого, всё равно уже недействительны — obfs/pin/Layer-1 сменились). docker-рестарт/ребут VPS
  ключи НЕ меняет; сохранить прежние при повторном запуске: CITADEL_KEEP_KEYS=1.

МАСТЕР-ссылка (СЕКРЕТ, ТОЛЬКО АДМИНУ — даёт управление реестром абонентов по туннелю):

$LINK

НЕ раздавать абонентам. Управление: docker compose -f $DIR/etc/compose.yml {ps,logs,down}
EOF

if [[ "$ISSUER_ON" == 1 ]]; then
cat <<EOF

Клиентская ссылка (для абонента — без admin-прав):

$CLIENT_LINK
EOF
fi

if [[ "$ISSUER_ON" == 1 ]]; then
cat <<EOF

Двухслойная идентичность включена:
  • Издатель (Layer-1 реестр + epoch-токены) слушает $SERVER_HOST:$ISSUER_PORT/tcp —
    ОТКРОЙ этот порт в firewall/облачной security-group, иначе клиент не получит токен.
  • Управление абонентами — ИЗ ПРИЛОЖЕНИЯ по мастер-ссылке (C7): подключись мастер-ссылкой,
    меню «Абоненты» → добавить/отозвать. Канал идёт по туннелю → PQ-TLS(pin) → admin-подпись;
    порт :$ADMIN_PORT НАРУЖУ НЕ ОТКРЫТ (в firewall его открывать НЕ нужно — доступ только из туннеля).
  • Break-glass ОТЗЫВ/аудит на сервере (добавление/минт — НЕ на сервере):
      отозвать:  Citadel_TOKEN_DIR=$DIR/keys $DIR/bin/citadel-token registry revoke <client_id>
      список:    Citadel_TOKEN_DIR=$DIR/keys $DIR/bin/citadel-token registry list
    Отзыв действует ≤ длины эпохи (${EPOCH_SECS}s), переживает рестарт контейнера. Массовый отзыв —
    сменить эпоху. ДОБАВЛЕНИЕ абонентов — ТОЛЬКО из приложения по мастер-ссылке (admin-канал по
    туннелю, C7). На сервере после установки НЕТ ни linkgen, ни seed'ов → «нарисовать» рабочую
    ссылку на боксе нельзя (Q4). Потеря мастер-ссылки / ротация admin-доступа → РЕИНСТАЛЛ:
    свежая идентичность, ВСЕ прежние ссылки (клиентские и мастер) становятся нерабочими.
  • Издатель на :$ISSUER_PORT работает поверх PQ-TLS с пиннингом серта (S2.1/A1): Layer-1 и слепая
    выдача идут в шифре с целостностью, client_id скрыт, серт издателя пиннится клиентом (анти-MITM).
    Token- и admin-каналы обёрнуты в obfs тем же PSK, что туннель (A1-остаток): TLS-хендшейк на
    проводе не виден, issuer-порт молчит на не-obfs пробу и неотличим от туннельного трафика.
EOF
fi

# ─── 8. Q2/Q4: стереть seed'ы «абонента» и админа — они нужны ТОЛЬКО для печати ссылок выше ───
# После установки на боксе НЕ должно оставаться ничего, из чего пересобирается клиентская или
# мастер-ссылка. Runtime это не ломает: issuer держит в реестре PUB абонента (Citadel_REGISTER_PUBS,
# уже вшит в entrypoint-issuer.sh), admin-канал проверяет admin_id (PUB, файл остаётся) — ни одному
# сервису seed НЕ нужен. Секреты подключения (obfs.psk/cert-pin/issuer-pin) остаются на диске (их
# требует туннель), но БЕЗ seed'ов и БЕЗ linkgen собрать рабочую ссылку на боксе нельзя.
# Воспроизведения ссылок при реинсталле НЕТ (осознанно): новый инсталл генерит идентичность заново,
# все прежние ссылки — мертвы. shred -u перетирает и удаляет; fallback rm, если shred недоступен.
if [[ "$ISSUER_ON" == 1 ]]; then
  for s in "$DIR/keys/admin.seed" "$DIR/keys/client.seed"; do
    [[ -f "$s" ]] || continue
    shred -u "$s" 2>/dev/null || rm -f "$s"
  done
  log "seed'ы абонента и админа стёрты с сервера (пересоздать ссылку на боксе нельзя; забыл → реинсталл)"
fi
