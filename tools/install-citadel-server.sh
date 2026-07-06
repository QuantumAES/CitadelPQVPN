#!/usr/bin/env bash
# ═════════════════════════════════════════════════════════════════════════════
#  CitadelPQVPN — установщик exit-сервера. ЗАПУСКАТЬ НА СЕРВЕРЕ ОТ ROOT.
#
#    ssh root@СЕРВЕР 'bash -s' -- vX.Y.Z  < tools/install-citadel-server.sh
#    # или скопировать на сервер и:  CITADEL_VERSION=vX.Y.Z ./install-citadel-server.sh
#
#  Делает: авто-Docker → скачивает ПОДПИСАННЫЙ бинарь релиза и ВЕРИФИЦИРУЕТ его
#  (minisign вшитым ключом → sha256 → распаковка) → keygen на сервере → docker compose up
#  → печатает админскую citadel://-ссылку. Первая установка без GUI-клиента (§8).
#
#  Supply-chain: бинарь принимается ТОЛЬКО если подпись сходится с вшитым ниже ключом.
#  Приватные ключи exit (cert/pin) генерятся В КОНТЕЙНЕРЕ и наружу не уходят.
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
DIR="${CITADEL_DIR:-/opt/citadel}"

log()  { printf '\033[1;36m[citadel]\033[0m %s\n' "$*"; }
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
log "версия=$VERSION арка=$ARCH каталог=$DIR"

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
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
( cd "$work"
  log "скачиваю релиз $VERSION ($ARCH)…"
  for f in "citadel-m1-$ARCH.zst" "citadel-linkgen-$ARCH.zst" sha256sums sha256sums.minisig; do
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
chmod 700 "$DIR/keys"
for name in citadel-m1 citadel-linkgen; do
  zstd -q -d -f "$work/$name-$ARCH.zst" -o "$DIR/bin/$name"
  chmod +x "$DIR/bin/$name"
done

# ─── 4. keygen на сервере: obfs PSK (cert/pin exit генерит сам в entrypoint) ───
PSK_FILE="$DIR/keys/obfs.psk"
if [[ ! -f "$PSK_FILE" ]]; then
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$PSK_FILE"
  chmod 600 "$PSK_FILE"
fi
PSK="$(cat "$PSK_FILE")"

# ─── 5. образ + entrypoint + compose ───
cat > "$DIR/etc/Dockerfile" <<'EOF'
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iptables iputils-ping curl ca-certificates dnsutils \
    && rm -rf /var/lib/apt/lists/*
COPY bin/citadel-m1 /usr/local/bin/citadel-m1
COPY etc/entrypoint-exit.sh /usr/local/bin/entrypoint-exit.sh
RUN chmod +x /usr/local/bin/citadel-m1 /usr/local/bin/entrypoint-exit.sh
EOF

cat > "$DIR/etc/entrypoint-exit.sh" <<'EOF'
#!/usr/bin/env bash
set -e
export Citadel_ROLE=server
export Citadel_LISTEN=0.0.0.0:4433
export Citadel_TUN=Citadel0
export Citadel_TUN_ADDR=10.7.0.1/16
export Citadel_MTU=1100
export Citadel_NAT_SRC=10.7.0.0/16
export Citadel_PIN_FILE=/shared/exit.pin
export Citadel_OBFS_PSK="${Citadel_OBFS_PSK:-}"
export Citadel_TCP_LISTEN=0.0.0.0:443
export Citadel_KX=pq   # S1.1/M4: PQ-only (анти-HNDL) — classical не принимаем; миграция сьютов = явный override
rm -f /shared/exit.pin
echo "[citadel-exit] token-less; listen 4433/udp + 443/tcp"
exec citadel-m1
EOF
chmod +x "$DIR/etc/entrypoint-exit.sh"

cat > "$DIR/etc/compose.yml" <<EOF
name: citadel
services:
  exit:
    build: { context: $DIR, dockerfile: etc/Dockerfile }
    image: citadel-exit:$VERSION
    container_name: citadel-exit
    entrypoint: ["/usr/local/bin/entrypoint-exit.sh"]
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

# ─── 6. up + health ───
log "поднимаю контейнер (docker compose up --build)…"
docker compose -f "$DIR/etc/compose.yml" up -d --build

log "жду готовности exit (cert/pin)…"
for _ in $(seq 1 60); do [[ -s "$DIR/keys/exit.pin" ]] && break; sleep 1; done
[[ -s "$DIR/keys/exit.pin" ]] || {
  docker compose -f "$DIR/etc/compose.yml" logs --tail 30 exit || true
  die "exit не поднялся за 60с (см. лог выше)"
}
PIN="$(cat "$DIR/keys/exit.pin")"

# ─── 7. публичный адрес + citadel:// (секрет) ───
if [[ -z "$SERVER_HOST" ]]; then
  SERVER_HOST="$(curl -fsS --max-time 8 https://api.ipify.org 2>/dev/null || true)"
fi
[[ -n "$SERVER_HOST" ]] || die "не удалось определить публичный IP — задай CITADEL_SERVER_HOST=<ip/host>"

LINK="$("$DIR/bin/citadel-linkgen" \
  --servers "$SERVER_HOST:$UDP_PORT" --psk "$PSK" --pin "$PIN" \
  --kx pq --tcp-port "$TCP_PORT" --routes "$ROUTES" 2>/dev/null)" \
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
