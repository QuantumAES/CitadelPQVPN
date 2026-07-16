#!/usr/bin/env bash
# ═════════════════════════════════════════════════════════════════════════════
#  CitadelPQVPN — установщик exit-сервера. ЗАПУСКАТЬ НА СЕРВЕРЕ ОТ ROOT.
#
#    ssh root@СЕРВЕР 'bash -s' -- vX.Y.Z  < tools/install-citadel-server.sh
#    # или скопировать на сервер и:  CITADEL_VERSION=vX.Y.Z ./install-citadel-server.sh
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
ISSUER_ON="${CITADEL_ISSUER:-1}"             # 1 = двухслойная идентичность (issuer+токены+ML-DSA); 0 = token-less
ISSUER_PORT="${CITADEL_ISSUER_PORT:-7000}"   # публичный порт издателя (клиент фетчит токены сюда)
EPOCH_SECS="${CITADEL_EPOCH_SECS:-3600}"     # длина эпохи токенов (exit и issuer ДОЛЖНЫ совпадать)

log()  { printf '\033[1;36m[citadel]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[citadel] ⚠ %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[1;31m[citadel] ОШИБКА: %s\033[0m\n' "$*" >&2; exit 1; }

# ─── 0. преконды ───
[[ "$(id -u)" == "0" ]] || die "запусти от root (sudo)"
[[ -n "$VERSION" ]] || die "укажи версию релиза: аргументом или CITADEL_VERSION=vX.Y.Z (pin версии, не «latest»)"
case "$(uname -m)" in
  x86_64|amd64)  ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
  *) die "неподдерживаемая арка: $(uname -m)" ;;
esac
[[ -e /dev/net/tun ]] || { modprobe tun 2>/dev/null || true; }
[[ -e /dev/net/tun ]] || die "нет /dev/net/tun — TUN недоступен на этом сервере"
log "версия=$VERSION арка=$ARCH каталог=$DIR issuer=$ISSUER_ON"

# ─── 1. базовые утилиты (curl/minisign/zstd) ───
pkgs=()
command -v curl     >/dev/null || pkgs+=(curl ca-certificates)
command -v minisign >/dev/null || pkgs+=(minisign)
command -v zstd     >/dev/null || pkgs+=(zstd)
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

# ─── 3. скачать + ВЕРИФИЦИРОВАТЬ релиз (подпись → sha256 → распаковка) ───
# citadel-token нужен для issuer-контейнера; тянем всегда (образ общий), задействуем при ISSUER_ON.
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
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
mkdir -p "$DIR/bin" "$DIR/keys" "$DIR/etc"
# 711 (не 700!): exit сбрасывает привилегии до nobody (F4) и per-auth ЧИТАЕТ публичные issuer-<epoch>.pub
# из этого каталога. При 700 nobody не может войти в каталог → чтение падает → verify_token видит
# пустой список ключей → ВСЕ токены «невалидны» (тихо, docker-демо это не ловит — named volume там 0755).
# 711 даёт traverse без листинга; секреты (obfs.psk/client.seed) остаются 600 и nobody недоступны.
chmod 711 "$DIR/keys"
for name in citadel-m1 citadel-linkgen citadel-token; do
  zstd -q -d -f "$work/$name-$ARCH.zst" -o "$DIR/bin/$name"
  chmod +x "$DIR/bin/$name"
done

# ─── 4. keygen на сервере: obfs PSK + (issuer) client_seed «абонента» ───
PSK_FILE="$DIR/keys/obfs.psk"
if [[ ! -f "$PSK_FILE" ]]; then
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$PSK_FILE"
  chmod 600 "$PSK_FILE"
fi
PSK="$(cat "$PSK_FILE")"

CLIENT_SEED=""; CLIENT_PUB=""
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
export Citadel_EPOCH_SECS=$EPOCH_SECS
export Citadel_REGISTER_PUBS="$CLIENT_PUB"   # client_id админа (issuer НЕ получает seed)
rm -f /shared/issuer.pub /shared/issuer-*.pub /shared/tokens
echo "[citadel-issuer] Layer-1 registry + слепая выдача epoch-токенов (epoch=${EPOCH_SECS}s, :7000)…"
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
LINK="$("$DIR/bin/citadel-linkgen" "${LINKARGS[@]}" 2>/dev/null)" \
  || die "citadel-linkgen не сгенерировал ссылку"

umask 077
printf '%s\n' "$LINK" > "$DIR/admin-link.txt"

cat <<EOF

╔══════════════════════════════════════════════════════════════════╗
║  CitadelPQVPN exit развёрнут ✓   ($SERVER_HOST:$UDP_PORT udp / $TCP_PORT tcp)
╚══════════════════════════════════════════════════════════════════╝

Админская ссылка (СЕКРЕТ — кто её имеет, тот подключается):

$LINK

Сохранена: $DIR/admin-link.txt (chmod 600). Раздавай по защищённому каналу.
Управление: docker compose -f $DIR/etc/compose.yml {ps,logs,down}
EOF

if [[ "$ISSUER_ON" == 1 ]]; then
cat <<EOF

Двухслойная идентичность включена:
  • Издатель (Layer-1 реестр + epoch-токены) слушает $SERVER_HOST:$ISSUER_PORT/tcp —
    ОТКРОЙ этот порт в firewall/облачной security-group, иначе клиент не получит токен.
  • Управление абонентами (admin-CLI, действует со следующего коннекта, C5.5):
      добавить:  Citadel_TOKEN_DIR=$DIR/keys $DIR/bin/citadel-token registry add-seed <seed> [+30d]
      отозвать:  Citadel_TOKEN_DIR=$DIR/keys $DIR/bin/citadel-token registry revoke <client_id>
      список:    Citadel_TOKEN_DIR=$DIR/keys $DIR/bin/citadel-token registry list
    Новому абоненту: сгенерируй seed → citadel-linkgen --client-seed <seed> … (его ссылка) +
    registry add-seed <seed> (в реестр идёт только pub — seed остаётся у абонента). Отзыв действует
    ≤ длины эпохи (${EPOCH_SECS}s), переживает рестарт контейнера. Массовый отзыв — сменить эпоху.
  • Издатель на :$ISSUER_PORT работает поверх PQ-TLS с пиннингом серта (S2.1/A1): Layer-1 и слепая
    выдача идут в шифре с целостностью, client_id скрыт, серт издателя пиннится клиентом (анти-MITM).
    ⚠ Остаётся: TLS-хендшейк на выделенном порту фингерпринтируем цензором (obfs-обёртка — follow-up).
EOF
fi
