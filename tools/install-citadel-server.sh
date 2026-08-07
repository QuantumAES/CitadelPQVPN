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

# ─── параметры (env, флаги или $1=version) ───
VERSION="${CITADEL_VERSION:-}"
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
# F7/D3 (M-3, аудит-4): per-client token-bucket на входящее направление exit'а. До аудита-4 эти
# переменные выставлял только docker-демостенд, а установщик — нет: в реальном деплое лимит был
# ВЫКЛЮЧЕН, и один абонент мог насытить аплинк exit'а (отказ в обслуживании для остальных + счёт
# за трафик). Дефолт щедрый (~84 Мбит/с на абонента) — режет злоупотребление, а не нормальное
# пользование. 0 = выключить осознанно.
RATE_LIMIT="${CITADEL_RATE_LIMIT:-10485760}" # байт/с на клиента (10 MiB/с); 0 = без лимита
RATE_BURST="${CITADEL_RATE_BURST:-20971520}" # допустимый всплеск, байт (20 MiB ≈ 2 с)

log()  { printf '\033[1;36m[citadel]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[citadel] ⚠ %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[1;31m[citadel] ОШИБКА: %s\033[0m\n' "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
CitadelPQVPN — установщик exit-сервера (запускать на сервере от root).

  install-citadel-server.sh [vX.Y.Z] [флаги]

Порты (значение по умолчанию в скобках; каждый флаг дублируется env-переменной):
  --udp-port    N   (4433)  QUIC/UDP туннеля            [CITADEL_UDP_PORT]
  --tcp-port    N   (443)   obfs-over-TCP fallback      [CITADEL_TCP_PORT]
  --issuer-port N   (7000)  издатель токенов (публичный)[CITADEL_ISSUER_PORT]
  --admin-port  N   (7001)  admin-канал, НАРУЖУ НЕ ОТКРЫТ — только из туннеля [CITADEL_ADMIN_PORT]

Ограничение полосы на абонента (F7/D3 — чтобы один клиент не съел аплинк exit'а):
  --rate-limit  N   (10485760) байт/с на клиента; 0 = без лимита [CITADEL_RATE_LIMIT]
  --rate-burst  N   (20971520) допустимый всплеск, байт          [CITADEL_RATE_BURST]

Порты по умолчанию узнаваемы (4433/7000 — «подпись» Citadel). На сети, где это важно,
задавай свои: клиент берёт их из ссылки, менять на нём ничего не нужно. Единственный порт,
который стоит оставить как есть, — TCP 443: obfs-fallback маскируется под HTTPS.

Роль установки (P1 — разнести exit и издателя по разным машинам):
  --role all        (умолчание) exit и издатель на ОДНОМ сервере
  --role issuer     только издатель: реестр абонентов + выдача токенов + admin-канал
  --role exit       только exit-узел; параметры издателя берутся из его bundle
  --issuer-bundle F файл `KEY=VALUE`, напечатанный установкой издателя (для --role exit)

Одна кража диска не должна давать обе идентичности сразу, поэтому на серьёзной установке
издателя выносят на отдельную машину. Порядок: сначала `--role issuer` (он напечатает bundle),
затем на другой машине `--role exit --issuer-bundle …`. Публичный ключ эпохи exit подтягивает
сам (контейнер `citadel-pubsync`), общий том между машинами не нужен.

Прочее:
  --host HOST       публичный адрес для ссылки (по умолчанию — автодетект)  [CITADEL_SERVER_HOST]
  --routes "CIDR…"  что гнать в туннель (0.0.0.0/0)                          [CITADEL_ROUTES]
  --dns IP          DNS, проталкиваемый клиенту (1.1.1.1)                    [CITADEL_DNS]
  --dir PATH        каталог установки (/opt/citadel)                         [CITADEL_DIR]
  --no-issuer       token-less exit без издателя (по умолчанию издатель включён) [CITADEL_ISSUER=0]
  --keep-keys       не ротировать идентичность при повторном запуске         [CITADEL_KEEP_KEYS=1]
  -h, --help        эта справка
USAGE
}

# Разбор флагов. Позиционный аргумент (версия релиза) поддержан как раньше.
while (($#)); do
  case "$1" in
    --role)           CITADEL_ROLE="${2:-}";          shift 2 ;;
    --issuer-bundle)  CITADEL_ISSUER_BUNDLE="${2:-}"; shift 2 ;;
    --issuer-addr)    CITADEL_ISSUER_ADDR="${2:-}";   shift 2 ;;
    --issuer-pin)     CITADEL_ISSUER_PIN="${2:-}";    shift 2 ;;
    --issuer-mldsa)   CITADEL_ISSUER_MLDSA="${2:-}";  shift 2 ;;
    --obfs-psk)       CITADEL_OBFS_PSK="${2:-}";      shift 2 ;;
    --client-seed)    CITADEL_CLIENT_SEED="${2:-}";   shift 2 ;;
    --admin-seed)     CITADEL_ADMIN_SEED="${2:-}";    shift 2 ;;
    --udp-port)     CITADEL_UDP_PORT="${2:-}";     shift 2 ;;
    --tcp-port)     CITADEL_TCP_PORT="${2:-}";     shift 2 ;;
    --issuer-port)  CITADEL_ISSUER_PORT="${2:-}";  shift 2 ;;
    --admin-port)   CITADEL_ADMIN_PORT="${2:-}";   shift 2 ;;
    --rate-limit)   CITADEL_RATE_LIMIT="${2:-}";   shift 2 ;;
    --rate-burst)   CITADEL_RATE_BURST="${2:-}";   shift 2 ;;
    --host)         CITADEL_SERVER_HOST="${2:-}";  shift 2 ;;
    --routes)       CITADEL_ROUTES="${2:-}";       shift 2 ;;
    --dns)          CITADEL_DNS="${2:-}";          shift 2 ;;
    --dir)          CITADEL_DIR="${2:-}";          shift 2 ;;
    --no-issuer)    CITADEL_ISSUER=0;              shift ;;
    --keep-keys)    CITADEL_KEEP_KEYS=1;           shift ;;
    -h|--help)      usage; exit 0 ;;
    -*)             die "неизвестный флаг: $1 (см. --help)" ;;
    *)              VERSION="$1";                  shift ;;
  esac
done
# Флаги выставляют те же переменные, что и env, поэтому значения перечитываем ПОСЛЕ разбора.
SERVER_HOST="${CITADEL_SERVER_HOST:-$SERVER_HOST}"
UDP_PORT="${CITADEL_UDP_PORT:-$UDP_PORT}"
TCP_PORT="${CITADEL_TCP_PORT:-$TCP_PORT}"
ISSUER_PORT="${CITADEL_ISSUER_PORT:-$ISSUER_PORT}"
ADMIN_PORT="${CITADEL_ADMIN_PORT:-$ADMIN_PORT}"
ROUTES="${CITADEL_ROUTES:-$ROUTES}"
DNS="${CITADEL_DNS:-$DNS}"
DIR="${CITADEL_DIR:-$DIR}"
ISSUER_ON="${CITADEL_ISSUER:-$ISSUER_ON}"
ROLE="${CITADEL_ROLE:-all}"
RATE_LIMIT="${CITADEL_RATE_LIMIT:-$RATE_LIMIT}"
RATE_BURST="${CITADEL_RATE_BURST:-$RATE_BURST}"
# Нечисловое значение молча уехало бы в entrypoint, а `RateCfg::from_env` разобрал бы его как
# «лимита нет» — то есть опечатка в флаге тихо отключала бы защиту. Отваливаемся здесь.
for spec in "RATE_LIMIT:--rate-limit" "RATE_BURST:--rate-burst"; do
  var="${spec%%:*}"; flag="${spec##*:}"
  [[ "${!var}" =~ ^[0-9]+$ ]] || die "$flag: '${!var}' — ожидается целое число байт (0 = без лимита)"
done
(( RATE_LIMIT == 0 || RATE_BURST >= RATE_LIMIT )) \
  || die "--rate-burst ($RATE_BURST) меньше --rate-limit ($RATE_LIMIT): всплеск не может быть меньше секундного пополнения"

# ─── 0a-bis. роль установки (P1: exit и издатель на разных машинах) ───
case "$ROLE" in
  all|issuer|exit) ;;
  *) die "--role: '$ROLE' — допустимо all | issuer | exit" ;;
esac
# Файл-bundle от установки издателя: те же имена, что и env-переменные (KEY=VALUE, без экспорта).
if [[ -n "${CITADEL_ISSUER_BUNDLE:-}" ]]; then
  [[ -r "$CITADEL_ISSUER_BUNDLE" ]] || die "--issuer-bundle: файл не читается: $CITADEL_ISSUER_BUNDLE"
  # Только известные ключи и только hex/host:port — файл приходит с другой машины, доверять ему
  # как shell-скрипту («source») нельзя: одна строка `rm -rf /` выполнилась бы от root.
  while IFS='=' read -r k v; do
    k="${k%%[[:space:]]*}"; v="${v%%[[:space:]]*}"
    [[ -z "$k" || "$k" == \#* ]] && continue
    case "$k" in
      CITADEL_ISSUER_ADDR|CITADEL_ISSUER_PIN|CITADEL_ISSUER_MLDSA|CITADEL_OBFS_PSK|\
      CITADEL_CLIENT_SEED|CITADEL_ADMIN_SEED|CITADEL_ADMIN_PORT|CITADEL_EPOCH_SECS|CITADEL_ISSUER_PORT)
        # уже заданный флаг/env приоритетнее файла (позволяет точечно переопределить)
        [[ -n "${!k:-}" ]] || printf -v "$k" '%s' "$v" ;;
      *) warn "issuer-bundle: неизвестный ключ '$k' пропущен" ;;
    esac
  done < "$CITADEL_ISSUER_BUNDLE"
  ADMIN_PORT="${CITADEL_ADMIN_PORT:-$ADMIN_PORT}"
  ISSUER_PORT="${CITADEL_ISSUER_PORT:-$ISSUER_PORT}"
  EPOCH_SECS="${CITADEL_EPOCH_SECS:-$EPOCH_SECS}"
fi
ISSUER_ADDR="${CITADEL_ISSUER_ADDR:-}"     # host:port издателя (только --role exit)
ISSUER_PIN_IN="${CITADEL_ISSUER_PIN:-}"    # его TLS-pin
ISSUER_MLDSA_IN="${CITADEL_ISSUER_MLDSA:-}" # обязательство его PQ-идентичности
PSK_IN="${CITADEL_OBFS_PSK:-}"             # общий obfs-PSK (генерит установка издателя)
CLIENT_SEED_IN="${CITADEL_CLIENT_SEED:-}"  # seed абонента (ссылку минтит exit-машина)
ADMIN_SEED_IN="${CITADEL_ADMIN_SEED:-}"    # seed админа (мастер-ссылка)
if [[ "$ROLE" == exit && "$ISSUER_ON" == 1 ]]; then
  hex64() { [[ "$1" =~ ^[0-9a-fA-F]{64}$ ]]; }
  [[ -n "$ISSUER_ADDR" ]] || die "--role exit: нужен --issuer-addr host:port (или --issuer-bundle)"
  [[ "$ISSUER_ADDR" == *:* ]] || die "--issuer-addr: ожидается host:port, получено '$ISSUER_ADDR'"
  for spec in "ISSUER_PIN_IN:--issuer-pin" "ISSUER_MLDSA_IN:--issuer-mldsa" "PSK_IN:--obfs-psk" \
              "CLIENT_SEED_IN:--client-seed" "ADMIN_SEED_IN:--admin-seed"; do
    var="${spec%%:*}"; flag="${spec##*:}"
    [[ -n "${!var}" ]] || die "--role exit: нужен $flag (или --issuer-bundle с ним)"
    hex64 "${!var}" || die "$flag: ожидается 64 hex-символа"
  done
fi

# ─── 0a. валидация портов ───
# Кривой порт обязан отвалиться ЗДЕСЬ, а не через 5 минут установки в невнятной ошибке docker/netsh:
# `ports: "70000:4433/udp"` compose примет за строку и упадёт уже на `up`, а занятый порт даст
# «address already in use» после сборки образа.
valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (($1 >= 1 && $1 <= 65535)); }
for spec in "UDP_PORT:--udp-port" "TCP_PORT:--tcp-port" "ISSUER_PORT:--issuer-port" "ADMIN_PORT:--admin-port"; do
  var="${spec%%:*}"; flag="${spec##*:}"
  valid_port "${!var}" || die "$flag: '${!var}' — порт должен быть числом 1..65535"
done
# Публичные порты не должны совпадать между собой (иначе docker молча возьмёт последний биндинг),
# а admin-порт — не совпадать с портом издателя: они слушаются ОДНИМ процессом.
[[ "$UDP_PORT" != "$TCP_PORT" ]] || die "--udp-port и --tcp-port совпадают ($UDP_PORT): это разные протоколы, но публикуются разными правилами — задай разные значения"
if [[ "$ISSUER_ON" == 1 ]]; then
  [[ "$ISSUER_PORT" != "$TCP_PORT" ]] || die "--issuer-port и --tcp-port совпадают ($TCP_PORT) — оба TCP на одном хосте не поднимутся"
  [[ "$ISSUER_PORT" != "$ADMIN_PORT" ]] || die "--issuer-port и --admin-port совпадают ($ISSUER_PORT) — издатель слушает оба, bind не пройдёт"
fi
# Занятость порта на хосте (docker publish упадёт на bind). Проверяем только публикуемые порты:
# admin-порт живёт внутри compose-сети и наружу не публикуется.
if command -v ss >/dev/null; then
  busy() { ss -Hln"$1" "sport = :$2" 2>/dev/null | grep -q . ; }
  busy u "$UDP_PORT" && warn "UDP-порт $UDP_PORT уже кем-то занят на хосте — publish может не пройти"
  busy t "$TCP_PORT" && warn "TCP-порт $TCP_PORT уже кем-то занят на хосте — publish может не пройти"
  [[ "$ISSUER_ON" == 1 ]] && busy t "$ISSUER_PORT" && warn "TCP-порт издателя $ISSUER_PORT уже кем-то занят на хосте"
fi
# 443 у obfs-fallback — не «просто дефолт», а маскировка под HTTPS: смена ломает камуфляж.
[[ "$TCP_PORT" == "443" ]] || warn "obfs-fallback переехал на TCP $TCP_PORT: маскировка под HTTPS работает именно на 443 — менять его стоит только осознанно"

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
        "$DIR/keys/"issuer-mldsa.seed "$DIR/keys/"issuer-mldsa.pin \
        "$DIR/keys/"admin_id "$DIR/keys/"admin.client_id "$DIR/keys/"registry "$DIR/keys/"tokens \
        "$DIR/keys/"exit.pin "$DIR/keys/"exit-cert.der "$DIR/keys/"exit-key.der \
        "$DIR/keys/"exit-mldsa.seed "$DIR/keys/"exit.mldsa "$DIR/keys/"exit2.pin "$DIR/keys/"exit2.mldsa \
        "$DIR/keys/"issuer-tls.crt "$DIR/keys/"issuer-tls.key "$DIR/keys/"issuer-tls.pin \
        "$DIR/keys/"issuer.pub "$DIR"/keys/issuer-*.pub 2>/dev/null || true
fi

# ─── 4. keygen на сервере: obfs PSK + (issuer) client_seed «абонента» ───
# PSK общий для туннеля и каналов издателя, поэтому при раздельном деплое его генерит установка
# ИЗДАТЕЛЯ и передаёт exit-машине bundle'ом — иначе обфускация у сторон не сойдётся.
PSK_FILE="$DIR/keys/obfs.psk"
if [[ "$ROLE" == exit && -n "$PSK_IN" ]]; then
  printf '%s' "$PSK_IN" > "$PSK_FILE"
  chmod 600 "$PSK_FILE"
elif [[ ! -f "$PSK_FILE" ]]; then
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$PSK_FILE"
  chmod 600 "$PSK_FILE"
fi
PSK="$(cat "$PSK_FILE")"

CLIENT_SEED=""; CLIENT_PUB=""
ADMIN_SEED=""; ADMIN_PUB=""
if [[ "$ROLE" == exit && "$ISSUER_ON" == 1 ]]; then
  # Раздельный деплой: seed'ы сгенерированы на машине ИЗДАТЕЛЯ (там же они зарегистрированы в
  # реестре и в admin_id). Здесь они нужны ровно для одного — собрать ссылки, потому что только у
  # exit-машины есть его cert-pin и ML-DSA pub. Сразу после печати стираются (§8).
  CLIENT_SEED="$CLIENT_SEED_IN"
  ADMIN_SEED="$ADMIN_SEED_IN"
  CLIENT_PUB="$(Citadel_CLIENT_SEED="$CLIENT_SEED" "$DIR/bin/citadel-token" pubkey)" \
    || die "не удалось вывести client_id абонента (citadel-token pubkey)"
  log "Layer-1 абонент из bundle издателя: client_id=${CLIENT_PUB:0:16}…"
elif [[ "$ISSUER_ON" == 1 ]]; then
  # client_seed = приватный Ed25519 «абонента» (Layer-1); хранится ТОЛЬКО у админа (в ссылке).
  SEED_FILE="$DIR/keys/client.seed"
  if [[ ! -f "$SEED_FILE" ]]; then
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$SEED_FILE"
    chmod 600 "$SEED_FILE"
  fi
  CLIENT_SEED="$(cat "$SEED_FILE")"
  # В реестр издателя пишем client_id (публичный идентификатор гибридной Ed25519+ML-DSA
  # идентичности абонента), а НЕ seed → издатель не знает секрет абонента.
  CLIENT_PUB="$(Citadel_CLIENT_SEED="$CLIENT_SEED" "$DIR/bin/citadel-token" pubkey)" \
    || die "не удалось вывести client_id абонента (citadel-token pubkey)"
  log "Layer-1 абонент: client_id=${CLIENT_PUB:0:16}… (seed остаётся только в ссылке)"

  # C7.2 admin-плоскость: ОТДЕЛЬНЫЙ seed админа (не равен client.seed — домен-разделение auth);
  # из него выводится та же гибридная пара Ed25519+ML-DSA, что и у абонента.
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
# Где exit ищет издателя: в общей установке — по docker-DNS имени сервиса, при раздельной — по
# хосту из bundle (DNAT работает по адресу, поэтому имя резолвится в entrypoint при старте).
if [[ "$ROLE" == exit ]]; then
  ISSUER_DNS_NAME="${ISSUER_ADDR%%:*}"
  ISSUER_TOKEN_PORT="${ISSUER_ADDR##*:}"
else
  ISSUER_DNS_NAME="issuer"
  ISSUER_TOKEN_PORT="$ISSUER_PORT"
fi
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
COPY etc/entrypoint-pubsync.sh /usr/local/bin/entrypoint-pubsync.sh
RUN chmod +x /usr/local/bin/citadel-m1 /usr/local/bin/citadel-token \
        /usr/local/bin/entrypoint-exit.sh /usr/local/bin/entrypoint-issuer.sh \
        /usr/local/bin/entrypoint-pubsync.sh
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
  if [[ "$RATE_LIMIT" != 0 ]]; then
    cat <<EOF
# F7/D3 (M-3, аудит-4): per-client token-bucket на входящее направление. Без него один абонент
# насыщал аплинк exit'а — отказ в обслуживании остальным. Мелкие пакеты тоже считаются
# (MIN_PACKET_COST), поэтому PPS-абуз режется наравне с полосой.
export Citadel_RATE_LIMIT=$RATE_LIMIT
export Citadel_RATE_BURST=$RATE_BURST
echo "[citadel-exit] F7 rate-limit: $RATE_LIMIT б/с на абонента (всплеск $RATE_BURST б)"
EOF
  else
    echo 'echo "[citadel-exit] ⚠ F7 rate-limit ВЫКЛЮЧЕН (--rate-limit 0): один абонент может занять весь аплинк"'
  fi
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
# Издатель может быть задан именем (docker-DNS в общей установке) ИЛИ голым IP (bundle при
# раздельной). getent hosts на адрес без обратной DNS-записи возвращает ПУСТО — поэтому
# литеральный IPv4 берём как есть и резолвим только имена.
ISSUER_IP="$ISSUER_DNS_NAME"
case "\$ISSUER_IP" in
  *[!0-9.]*) ISSUER_IP="\$(getent hosts $ISSUER_DNS_NAME | awk '{print \$1}' | head -n1)" ;;
esac
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

# entrypoint pubsync-сайдкара (P1, раздельный деплой): держит публичный ключ ТЕКУЩЕЙ эпохи в томе
# exit'а. При установке «всё на одном сервере» не задействуется — там ключ пишет сам издатель.
cat > "$DIR/etc/entrypoint-pubsync.sh" <<EOF
#!/usr/bin/env bash
set -e
export Citadel_TOKEN_ROLE=pubsync
export Citadel_TOKEN_DIR=/shared
export Citadel_TOKEN_ISSUER=$ISSUER_ADDR
export Citadel_ISSUER_PIN=$ISSUER_PIN_IN
export Citadel_ISSUER_MLDSA=$ISSUER_MLDSA_IN
export Citadel_EPOCH_SECS=$EPOCH_SECS
export Citadel_OBFS_PSK=\$(cat /shared/obfs.psk)
echo "[citadel-pubsync] слежу за ключом эпохи у издателя $ISSUER_ADDR (эпоха ${EPOCH_SECS}с)…"
exec citadel-token
EOF
chmod +x "$DIR/etc/entrypoint-pubsync.sh"

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
if [[ "$ISSUER_ON" == 1 && "$ROLE" != exit ]]; then
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
      - "$ISSUER_PORT:7000/tcp"        # клиент фетчит epoch-токены сюда (Layer-1)$(
      if [[ "$ROLE" == issuer ]]; then printf '\n      - "%s:%s/tcp"   # admin-канал: НУЖЕН только exit-машине — закрой его firewall\x27ом для всех остальных' "$ADMIN_PORT" "$ADMIN_PORT"; fi)
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
if [[ "$ROLE" != issuer ]]; then
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
if [[ "$ISSUER_ON" == 1 && "$ROLE" == all ]]; then
cat <<EOF
    depends_on:
      issuer: { condition: service_healthy }   # нужен issuer.pub для верификации токенов
EOF
fi
# P1: при раздельном деплое ключ эпохи на exit-машину приносит сайдкар (общего тома с издателем
# нет, а ключ ротируется каждую эпоху).
if [[ "$ISSUER_ON" == 1 && "$ROLE" == exit ]]; then
cat <<EOF
  pubsync:
    image: citadel-exit:$VERSION
    container_name: citadel-pubsync
    entrypoint: ["/usr/local/bin/entrypoint-pubsync.sh"]
    read_only: true
    tmpfs: ["/tmp"]
    security_opt: ["no-new-privileges:true"]
    restart: unless-stopped
    volumes:
      - "$DIR/keys:/shared"
EOF
fi
fi
} > "$DIR/etc/compose.yml"

# ─── 6. сборка образа + up + health ───
log "собираю образ citadel-exit:$VERSION…"
docker build -t "citadel-exit:$VERSION" -f "$DIR/etc/Dockerfile" "$DIR"

log "поднимаю контейнер(ы) (docker compose up)…"
docker compose -f "$DIR/etc/compose.yml" up -d

PIN=""
if [[ "$ROLE" != issuer ]]; then
  log "жду готовности exit (cert/pin)…"
  for _ in $(seq 1 90); do [[ -s "$DIR/keys/exit.pin" ]] && break; sleep 1; done
  [[ -s "$DIR/keys/exit.pin" ]] || {
    docker compose -f "$DIR/etc/compose.yml" logs --tail 40 || true
    die "exit не поднялся за 90с (см. лог выше)"
  }
  PIN="$(cat "$DIR/keys/exit.pin")"
fi

MLDSA_ARGS=()
ISSUER_TLS_PIN=""
if [[ "$ISSUER_ON" == 1 && "$ROLE" == exit ]]; then
  # Раздельный деплой: TLS-pin и PQ-обязательство издателя пришли bundle'ом, а ключ эпохи должен
  # ПРИЙТИ ПО СЕТИ — это и есть проверка, что связка exit↔издатель собрана верно (порт открыт,
  # PSK совпал, pin/обязательство те самые). Без неё установка «прошла бы успешно», а туннель
  # молча отвергал бы все токены.
  ISSUER_TLS_PIN="$ISSUER_PIN_IN"
  ISSUER_MLDSA="$ISSUER_MLDSA_IN"
  log "жду ML-DSA pub exit'а и первую синхронизацию ключа эпохи с издателем $ISSUER_ADDR…"
  for _ in $(seq 1 90); do [[ -s "$DIR/keys/exit.mldsa" && -s "$DIR/keys/issuer.pub" ]] && break; sleep 1; done
  [[ -s "$DIR/keys/exit.mldsa" ]] || die "exit не опубликовал ML-DSA pub (exit.mldsa) за 90с"
  [[ -s "$DIR/keys/issuer.pub" ]] || {
    docker compose -f "$DIR/etc/compose.yml" logs --tail 30 pubsync || true
    die "не удалось получить ключ эпохи у издателя $ISSUER_ADDR за 90с — проверь: порт $ISSUER_TOKEN_PORT открыт с этой машины, obfs-PSK/pin/обязательство из bundle те самые (лог выше)"
  }
  MLDSA_ARGS=(--mldsa-pub "$DIR/keys/exit.mldsa")
  log "ключ эпохи получен от издателя ✓ (дальше сайдкар citadel-pubsync держит его свежим)"
elif [[ "$ISSUER_ON" == 1 ]]; then
  log "жду издателя (issuer.pub, issuer-tls.pin, issuer-mldsa.pin) и ML-DSA pub exit'а…"
  for _ in $(seq 1 90); do [[ -s "$DIR/keys/issuer.pub" && -s "$DIR/keys/issuer-tls.pin" && -s "$DIR/keys/issuer-mldsa.pin" && -s "$DIR/keys/exit.mldsa" ]] && break; sleep 1; done
  [[ -s "$DIR/keys/issuer.pub" ]] || { docker compose -f "$DIR/etc/compose.yml" logs --tail 40 issuer || true; die "издатель не опубликовал issuer.pub за 90с"; }
  [[ -s "$DIR/keys/issuer-tls.pin" ]] || die "издатель не опубликовал issuer-tls.pin (PQ-TLS канал, A1) за 90с"
  [[ -s "$DIR/keys/issuer-mldsa.pin" ]] || die "издатель не опубликовал issuer-mldsa.pin (PQ-аутентификация издателя) за 90с"
  [[ -s "$DIR/keys/exit.mldsa" ]] || die "exit не опубликовал ML-DSA pub (exit.mldsa) за 90с"
  MLDSA_ARGS=(--mldsa-pub "$DIR/keys/exit.mldsa")
  ISSUER_TLS_PIN="$(cat "$DIR/keys/issuer-tls.pin")"   # S2.1/A1: pin PQ-TLS канала издателя → в ссылку
  # PQ: обязательство к ML-DSA-идентичности издателя. Без него клиент откажется и фетчить токены,
  # и открывать admin-канал: pin серта — классическая привязка, против CRQC она не держит.
  ISSUER_MLDSA="$(cat "$DIR/keys/issuer-mldsa.pin")"
fi

# ─── 7. публичный адрес + citadel:// (секрет) ───
if [[ -z "$SERVER_HOST" ]]; then
  SERVER_HOST="$(curl -fsS --max-time 8 https://api.ipify.org 2>/dev/null || true)"
fi
[[ -n "$SERVER_HOST" ]] || die "не удалось определить публичный IP — задай CITADEL_SERVER_HOST=<ip/host>"

# ── роль issuer: ссылок здесь нет (у машины нет exit-идентичности) — печатаем bundle для exit'а ──
if [[ "$ROLE" == issuer ]]; then
  BUNDLE="$(mktemp)"
  cat > "$BUNDLE" <<EOF
CITADEL_ISSUER_ADDR=$SERVER_HOST:$ISSUER_PORT
CITADEL_ISSUER_PIN=$ISSUER_TLS_PIN
CITADEL_ISSUER_MLDSA=$ISSUER_MLDSA
CITADEL_OBFS_PSK=$PSK
CITADEL_CLIENT_SEED=$CLIENT_SEED
CITADEL_ADMIN_SEED=$ADMIN_SEED
CITADEL_ADMIN_PORT=$ADMIN_PORT
CITADEL_EPOCH_SECS=$EPOCH_SECS
EOF
  cat <<EOF

╔══════════════════════════════════════════════════════════════════╗
║  CitadelPQVPN ИЗДАТЕЛЬ развёрнут ✓   ($SERVER_HOST:$ISSUER_PORT tcp)
╚══════════════════════════════════════════════════════════════════╝

Это половина установки: exit-узел ставится ОТДЕЛЬНОЙ командой на другой машине. Ссылок здесь нет
и быть не может — их собирает exit-машина (только у неё есть cert-pin и ML-DSA-ключ туннеля).

Порты этой машины:
  • $ISSUER_PORT/tcp  — выдача токенов          → ОТКРЫТЬ для клиентов
  • $ADMIN_PORT/tcp  — admin-канал            → открыть ТОЛЬКО для адреса exit-машины, например:
      ufw allow from <IP_EXIT> to any port $ADMIN_PORT proto tcp
    (канал и сам защищён PQ-TLS+pin и подписью админа, но лишней публичности ему не нужно)

────────────────── СЕКРЕТ: bundle для установки exit-узла ──────────────────
Скопируй в файл на exit-машине (например issuer.env) и поставь exit так:

  ./install-citadel-server.sh $VERSION --role exit --issuer-bundle issuer.env

$(cat "$BUNDLE")
─────────────────────────────────────────────────────────────────────────────
Bundle содержит seed'ы абонента и админа — это секрет уровня «доступ к сервису». Передавай его
на exit-машину защищённым каналом (scp), не через мессенджер, и удали файл после установки.

Реестр Layer-1 и admin_id остаются ЗДЕСЬ: абонентов выдаёт и отзывает эта машина.
Управление: docker compose -f $DIR/etc/compose.yml {ps,logs,down}

ЕСЛИ ЭТА МАШИНА СКОМПРОМЕТИРОВАНА: переустанови издателя этим же скриптом (сменится его
TLS-идентичность и PQ-идентичность) и следом переустанови exit с новым bundle — прежние ссылки
станут нерабочими, раздай новые. Смысл раздельного деплоя в том, что кража ЭТОЙ машины не даёт
идентичность туннеля (она на exit-узле) — и наоборот. Подробнее: docs/SERVER-KEY-PROTECTION.md.
EOF
  rm -f "$BUNDLE"
  # Seed'ы напечатаны — на диске издателя их не оставляем (Q2/Q4, как в общей установке).
  for sfile in "$DIR/keys/admin.seed" "$DIR/keys/client.seed"; do
    [[ -f "$sfile" ]] || continue
    shred -u "$sfile" 2>/dev/null || rm -f "$sfile"
  done
  log "seed'ы абонента и админа стёрты с машины издателя (они уехали в bundle)"
  exit 0
fi

LINKARGS=(--servers "$SERVER_HOST:$UDP_PORT" --psk "$PSK" --pin "$PIN"
          --kx pq --tcp-port "$TCP_PORT" --routes "$ROUTES" --dns "$DNS" "${MLDSA_ARGS[@]}")
if [[ "$ISSUER_ON" == 1 ]]; then
  # Layer-1: клиент авто-фетчит epoch-токен у издателя перед коннектом (issuer host:port + seed).
  # S2.1/A1: --issuer-pin → клиент пиннит PQ-TLS канал фетча (анти-MITM + скрытие client_id).
  # При раздельном деплое издатель живёт на ДРУГОЙ машине — в ссылку идёт его адрес из bundle.
  LINK_ISSUER="$SERVER_HOST:$ISSUER_PORT"
  [[ "$ROLE" == exit ]] && LINK_ISSUER="$ISSUER_ADDR"
  LINKARGS+=(--issuer "$LINK_ISSUER" --issuer-pin "$ISSUER_TLS_PIN" \
             --issuer-mldsa "$ISSUER_MLDSA" --client-seed "$CLIENT_SEED")
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

Порты (клиент берёт их из ссылки — на устройствах ничего настраивать не нужно):
  • $UDP_PORT/udp  — основной туннель (PQ-QUIC)          → ОТКРЫТЬ в firewall/security-group
  • $TCP_PORT/tcp  — obfs-fallback, когда UDP режут      → ОТКРЫТЬ
$(if [[ "$ROLE" == exit ]]; then cat <<PORTS
  • издатель — на ОТДЕЛЬНОЙ машине ($ISSUER_ADDR): порт открывается там, здесь не нужен.
    Ключ эпохи подтягивает сайдкар citadel-pubsync (исходящее соединение к издателю).
  • admin-канал ($ADMIN_PORT/tcp) слушает издатель; этой машине его открывать не нужно.
PORTS
else cat <<PORTS
  • $ISSUER_PORT/tcp  — издатель токенов                    → ОТКРЫТЬ (при выключенном издателе не нужен)
  • $ADMIN_PORT/tcp  — admin-канал                        → НЕ открывать: доступен только из туннеля
PORTS
fi)
  Свои значения: ./install-citadel-server.sh --udp-port N --tcp-port N --issuer-port N (см. --help).

⚠ Ссылки печатаются ЗДЕСЬ и НИГДЕ не сохраняются. Скопируй их СЕЙЧАС. Забыл / потерял →
  запусти скрипт снова: он ротирует идентичность и выдаст НОВЫЕ ссылки (прежние, розданные до
  этого, всё равно уже недействительны — obfs/pin/Layer-1 сменились). docker-рестарт/ребут VPS
  ключи НЕ меняет; сохранить прежние при повторном запуске: CITADEL_KEEP_KEYS=1.

МАСТЕР-ссылка (СЕКРЕТ, ТОЛЬКО АДМИНУ — даёт управление реестром абонентов по туннелю):

$LINK

НЕ раздавать абонентам. Управление: docker compose -f $DIR/etc/compose.yml {ps,logs,down}

ЕСЛИ СЕРВЕР СКОМПРОМЕТИРОВАН (или есть подозрение). Узел спроектирован расходным: восстановление
— это переустановка, а не «чистка». Запусти этот же скрипт заново — он сменит ВСЮ идентичность
(obfs-PSK, cert-pin, ML-DSA, ключи издателя), после чего прежние ссылки мертвы, и раздай новые.
Перехваченный ранее трафик расшифровать нельзя: сессионные ключи эфемерны (forward secrecy), а
ключ подписи токенов живёт только в памяти издателя и меняется каждую эпоху (${EPOCH_SECS}s).
Что даёт злоумышленнику украденный диск и почему шифрование каталога ключей помогает не от всего
— docs/SERVER-KEY-PROTECTION.md.
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
