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
# M-8 (аудит-4): портов «по умолчанию» у туннеля и издателя больше нет — пусто означает «выбрать
# случайный при первой установке и запомнить». Фиксированные 4433/7000 были подписью Citadel: по
# ним деплой опознавался сканером без единого пакета в туннель. TCP-порт — исключение: 443 не
# «дефолт», а камуфляж под HTTPS, и он остаётся.
UDP_PORT="${CITADEL_UDP_PORT:-}"
TCP_PORT="${CITADEL_TCP_PORT:-443}"
ROUTES="${CITADEL_ROUTES:-0.0.0.0/0}"        # что гнать в туннель (full-tunnel по умолчанию)
DNS="${CITADEL_DNS:-1.1.1.1}"                # DNS, проталкиваемый клиенту (через туннель; анти-leak F6)
DIR="${CITADEL_DIR:-/opt/citadel}"
LOCAL_BIN="${CITADEL_LOCAL_BIN:-}"           # dir с УЖЕ СОБРАННЫМИ citadel-m1/token/linkgen →
                                             # локальная установка БЕЗ скачивания релиза (dev/air-gapped;
                                             # подпись НЕ проверяется). Пусто = штатно тянем релиз с GitHub.
ISSUER_ON="${CITADEL_ISSUER:-1}"             # 1 = двухслойная идентичность (issuer+токены+ML-DSA); 0 = token-less
ISSUER_PORT="${CITADEL_ISSUER_PORT:-}"       # публичный порт издателя (клиент фетчит токены сюда);
                                             # пусто → случайный при первой установке (M-8)
ADMIN_PORT="${CITADEL_ADMIN_PORT:-7001}"     # C7.2: порт admin-канала — НЕ публикуется наружу (только из туннеля)
ADMIN_VIP="${CITADEL_ADMIN_VIP:-10.7.0.1}"   # C7.2: admin-VIP = шлюз туннеля (= Citadel_TUN_ADDR exit'а)
EPOCH_SECS="${CITADEL_EPOCH_SECS:-3600}"     # длина эпохи токенов (exit и issuer ДОЛЖНЫ совпадать)
# M-9: окно активации МАСТЕР-ссылки, которую печатает установщик. Ссылка одноразовая: первое
# устройство админа забирает её себе (подписка переезжает на ключ устройства), копия становится
# бесполезной. Просроченную ссылку не активирует уже никто — это и есть защита напечатанной в
# терминал ссылки, которая иначе живёт вечно и работает с любого числа устройств.
ACTIVATE_SECS="${CITADEL_ACTIVATE_SECS:-86400}"
LEASE_SECS="${CITADEL_LEASE_SECS:-0}"        # задача 4/B: single-session — окно аренды на абонента (с);
                                             # 0 = выкл. >0 ⇒ одна ссылка открывает новую сессию не чаще
                                             # раза в N с (ограничивает шеринг; реконнект в окне ждёт)
# L-4 (аудит-4): дефолт 0 — ОСОЗНАННЫЙ, а не забытый. Издатель не может отличить «второе устройство
# с той же ссылки» от «то же устройство переехало с Wi-Fi на LTE»: и то, и другое — новый запрос
# токена от того же client_id, а различить их можно только связав сессии на exit'е, то есть сломав
# ровно ту неразличимость, ради которой сделан весь Layer-2. Поэтому включённая аренда бьёт в первую
# очередь по честному мобильному абоненту (реконнект в окне = «нет доступа на N секунд»), а шеринг
# ограничивает лишь мягко. Включать имеет смысл там, где абонент стационарный, и с окном 60–120 с.
# F7/D3 (M-3, аудит-4): per-client token-bucket на ОБА направления exit'а. До аудита-4 эти
# переменные выставлял только docker-демостенд, а установщик — нет: в реальном деплое лимит был
# ВЫКЛЮЧЕН, и один абонент мог насытить аплинк exit'а (отказ в обслуживании для остальных + счёт
# за трафик). Дефолт щедрый (~84 Мбит/с на абонента) — режет злоупотребление, а не нормальное
# пользование. 0 = выключить осознанно.
# M-3-bis: направление «вниз» (интернет → абонент) до этого не ограничивалось ВООБЩЕ, хотя именно
# оно несёт основную нагрузку релея и амплификацию «мало запросил — много получил». Пусто ⇒ тот же
# лимит, что и вверх; отдельные CITADEL_RATE_LIMIT_DOWN/BURST_DOWN — если каналы асимметричны.
RATE_LIMIT="${CITADEL_RATE_LIMIT:-10485760}" # байт/с на клиента вверх (10 MiB/с); 0 = без лимита
RATE_BURST="${CITADEL_RATE_BURST:-20971520}" # допустимый всплеск, байт (20 MiB ≈ 2 с)
RATE_LIMIT_DOWN="${CITADEL_RATE_LIMIT_DOWN:-$RATE_LIMIT}" # байт/с вниз; 0 = не резать вниз
RATE_BURST_DOWN="${CITADEL_RATE_BURST_DOWN:-$RATE_BURST}"

log()  { printf '\033[1;36m[citadel]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[citadel] ⚠ %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[1;31m[citadel] ОШИБКА: %s\033[0m\n' "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
CitadelPQVPN — установщик exit-сервера (запускать на сервере от root).

  install-citadel-server.sh [vX.Y.Z] [флаги]

Порты (значение по умолчанию в скобках; каждый флаг дублируется env-переменной):
  --udp-port    N   (случайный) QUIC/UDP туннеля       [CITADEL_UDP_PORT]
  --tcp-port    N   (443)   obfs-over-TCP fallback      [CITADEL_TCP_PORT]
  --issuer-port N   (случайный) издатель токенов (публичный) [CITADEL_ISSUER_PORT]
  --admin-port  N   (7001)  admin-канал, НАРУЖУ НЕ ОТКРЫТ — только из туннеля [CITADEL_ADMIN_PORT]
  --ufw / --no-ufw  синхронизировать правила ufw без вопроса / не трогать их вовсе.
                    По умолчанию: если ufw активен и порты разошлись — спросить [CITADEL_UFW=yes|no]
  --activate-secs N (86400) окно активации мастер-ссылки, сек [CITADEL_ACTIVATE_SECS]
  --admin-peer  IP  адрес exit-машины, которому разрешён admin-канал (L-14).
                    ОБЯЗАТЕЛЕН при --role issuer (там порт публикуется наружу);
                    'any' — открыть всем осознанно                [CITADEL_ADMIN_PEER]

Мастер-ссылка (B-2 — как её доставлять админу):
  --master-password F  файл с паролем: мастер-ссылка печатается не голым текстом, а
                    ПАРОЛЬНЫМ КОНВЕРТОМ (Argon2id+AES-GCM). Блок можно переслать чем
                    угодно — без пароля он бесполезен; пароль передавай ДРУГИМ каналом.
                    Приложение спросит его при импорте.       [CITADEL_MASTER_PASSWORD_FILE]

Ограничение полосы на абонента (F7/D3 — чтобы один клиент не съел аплинк exit'а):
  --rate-limit  N   (10485760) байт/с на клиента вверх; 0 = без лимита [CITADEL_RATE_LIMIT]
  --rate-burst  N   (20971520) допустимый всплеск, байт          [CITADEL_RATE_BURST]
  --rate-limit-down N  (= --rate-limit) байт/с вниз; 0 = без лимита [CITADEL_RATE_LIMIT_DOWN]
  --rate-burst-down N  (= --rate-burst) всплеск вниз, байт        [CITADEL_RATE_BURST_DOWN]

Порты туннеля и издателя ВЫБИРАЮТСЯ СЛУЧАЙНО при первой установке (M-8: прежние 4433/7000
были узнаваемой «подписью» Citadel) и запоминаются в $DIR/etc/ports.env — повторный запуск
берёт их оттуда, поэтому выданные ссылки не ломаются. Клиент берёт порты из ссылки, менять на
нём ничего не нужно. Единственный порт с фиксированным значением — TCP 443: obfs-fallback
маскируется под HTTPS, и это не дефолт, а камуфляж.

Роль установки (P1 — разнести exit и издателя по разным машинам):
  --role all        (умолчание) exit и издатель на ОДНОМ сервере
  --role issuer     только издатель: реестр абонентов + выдача токенов + admin-канал
  --role exit       только exit-узел; параметры издателя берутся из его bundle
  --issuer-bundle F файл `KEY=VALUE`, напечатанный установкой издателя (для --role exit);
                    `-` — прочитать со stdin (вставить копипастом, без файла на диске)
  --keysync-seed H  идентичность exit-узла для получения ключа эпохи (обычно из --issuer-bundle)

`--role all` удобен для личной установки, но у него есть цена, которую не закрывает никакая
криптография: издатель видит `client_id`+IP+время (Layer-1), exit видит трафик, и на одной машине
эти два наблюдения сводит воедино её root. Для сервиса «для других» роли обязаны жить под РАЗНЫМИ
администрациями. Одна кража диска не должна давать обе идентичности сразу, поэтому на серьёзной
установке издателя выносят на отдельную машину. Порядок: сначала `--role issuer` (он напечатает bundle),
затем на другой машине `--role exit --issuer-bundle …`. Публичный ключ эпохи exit подтягивает
сам (контейнер `citadel-keysync`), общий том между машинами не нужен.

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
    --keysync-seed)   CITADEL_KEYSYNC_SEED="${2:-}";  shift 2 ;;
    --obfs-psk)       CITADEL_OBFS_PSK="${2:-}";      shift 2 ;;
    --client-seed)    CITADEL_CLIENT_SEED="${2:-}";   shift 2 ;;
    --admin-seed)     CITADEL_ADMIN_SEED="${2:-}";    shift 2 ;;
    --master-password) CITADEL_MASTER_PASSWORD_FILE="${2:-}"; shift 2 ;;
    --udp-port)     CITADEL_UDP_PORT="${2:-}";     shift 2 ;;
    --tcp-port)     CITADEL_TCP_PORT="${2:-}";     shift 2 ;;
    --issuer-port)  CITADEL_ISSUER_PORT="${2:-}";  shift 2 ;;
    --admin-port)   CITADEL_ADMIN_PORT="${2:-}";   shift 2 ;;
    --admin-peer)   CITADEL_ADMIN_PEER="${2:-}";   shift 2 ;;
    --activate-secs) CITADEL_ACTIVATE_SECS="${2:-}"; shift 2 ;;
    --ufw)          CITADEL_UFW=yes;               shift ;;
    --no-ufw)       CITADEL_UFW=no;                shift ;;
    --rate-limit)   CITADEL_RATE_LIMIT="${2:-}";   shift 2 ;;
    --rate-burst)   CITADEL_RATE_BURST="${2:-}";   shift 2 ;;
    --rate-limit-down) CITADEL_RATE_LIMIT_DOWN="${2:-}"; shift 2 ;;
    --rate-burst-down) CITADEL_RATE_BURST_DOWN="${2:-}"; shift 2 ;;
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
ACTIVATE_SECS="${CITADEL_ACTIVATE_SECS:-$ACTIVATE_SECS}"
[[ "$ACTIVATE_SECS" =~ ^[0-9]+$ ]] && ((ACTIVATE_SECS > 0)) \
  || die "--activate-secs: ожидаются секунды > 0 (окно активации мастер-ссылки), получено '$ACTIVATE_SECS'"
ACTIVATE_UNTIL=$(( $(date +%s) + ACTIVATE_SECS ))
# Firewall: yes|no|ask. `ask` (по умолчанию) — при активном ufw спросить и синхронизировать порты.
UFW_MODE="${CITADEL_UFW:-ask}"
ROLE="${CITADEL_ROLE:-all}"
RATE_LIMIT="${CITADEL_RATE_LIMIT:-$RATE_LIMIT}"
RATE_BURST="${CITADEL_RATE_BURST:-$RATE_BURST}"
# M-3-bis: «вниз» по умолчанию симметрично «вверх» — в том числе когда лимит вверх задан флагом.
RATE_LIMIT_DOWN="${CITADEL_RATE_LIMIT_DOWN:-$RATE_LIMIT}"
RATE_BURST_DOWN="${CITADEL_RATE_BURST_DOWN:-$RATE_BURST}"
# Нечисловое значение молча уехало бы в entrypoint, а `RateCfg::from_env` разобрал бы его как
# «лимита нет» — то есть опечатка в флаге тихо отключала бы защиту. Отваливаемся здесь.
for spec in "RATE_LIMIT:--rate-limit" "RATE_BURST:--rate-burst" \
            "RATE_LIMIT_DOWN:--rate-limit-down" "RATE_BURST_DOWN:--rate-burst-down"; do
  var="${spec%%:*}"; flag="${spec##*:}"
  [[ "${!var}" =~ ^[0-9]+$ ]] || die "$flag: '${!var}' — ожидается целое число байт (0 = без лимита)"
done
(( RATE_LIMIT == 0 || RATE_BURST >= RATE_LIMIT )) \
  || die "--rate-burst ($RATE_BURST) меньше --rate-limit ($RATE_LIMIT): всплеск не может быть меньше секундного пополнения"
(( RATE_LIMIT_DOWN == 0 || RATE_BURST_DOWN >= RATE_LIMIT_DOWN )) \
  || die "--rate-burst-down ($RATE_BURST_DOWN) меньше --rate-limit-down ($RATE_LIMIT_DOWN)"

# ─── 0a-bis. роль установки (P1: exit и издатель на разных машинах) ───
case "$ROLE" in
  all|issuer|exit) ;;
  *) die "--role: '$ROLE' — допустимо all | issuer | exit" ;;
esac
# A-1 (§7.1) / R5.1: совмещённая установка — это НЕ «просто дешевле». Издатель по построению видит
# Layer-1 (client_id + IP + время, раз в эпоху), exit видит трафик; анонимность абонента держится на
# том, что эти два наблюдения принадлежат РАЗНЫМ администрациям. На одной машине их сводит воедино
# кто угодно с root'ом на ней — и владелец, и тот, кто её изымет. Криптографией это не лечится
# (см. §7.1: разнесение ролей — продуктовое решение), поэтому здесь — громкое предупреждение, а не
# тихий дефолт: для личной/семейной установки совмещение нормально, для сервиса «для других» — нет.
if [[ "$ROLE" == all ]]; then
  warn "--role all: издатель и exit на ОДНОЙ машине. Root этой машины (или тот, кто её изымет)
        видит и связку client_id↔IP↔время (Layer-1 издателя), и сам трафик exit'а — то есть может
        сопоставить абонента с его сессией. Разделение ролей — единственная защита: сначала
        \`--role issuer\` на одной машине, затем \`--role exit --issuer-bundle …\` на другой,
        желательно у другого провайдера и под другой администрацией. Подробности — docs/SECURITY-AUDIT-4-2026-08.md §7.1."
fi
# Файл-bundle от установки издателя: те же имена, что и env-переменные (KEY=VALUE, без экспорта).
if [[ -n "${CITADEL_ISSUER_BUNDLE:-}" ]]; then
  # `-` = читать со stdin: bundle несёт seed'ы и мастер L1, и класть его файлом на exit-машину
  # необязательно — оператор вставляет строки прямо в терминал (Ctrl-D в конце), секрет остаётся
  # в памяти процесса. Файл по-прежнему поддержан: он удобнее при автоматизации (scp + прогон).
  if [[ "$CITADEL_ISSUER_BUNDLE" == - ]]; then
    log "жду bundle издателя на stdin: вставь строки и заверши Ctrl-D"
    BUNDLE_SRC=/dev/stdin
  else
    [[ -r "$CITADEL_ISSUER_BUNDLE" ]] || die "--issuer-bundle: файл не читается: $CITADEL_ISSUER_BUNDLE"
    BUNDLE_SRC="$CITADEL_ISSUER_BUNDLE"
  fi
  # Только известные ключи и только hex/host:port — файл приходит с другой машины, доверять ему
  # как shell-скрипту («source») нельзя: одна строка `rm -rf /` выполнилась бы от root.
  while IFS='=' read -r k v; do
    k="${k%%[[:space:]]*}"; v="${v%%[[:space:]]*}"
    [[ -z "$k" || "$k" == \#* ]] && continue
    case "$k" in
      CITADEL_ISSUER_ADDR|CITADEL_ISSUER_PIN|CITADEL_ISSUER_MLDSA|CITADEL_OBFS_PSK|CITADEL_OBFS_MASTER|\
      CITADEL_CLIENT_SEED|CITADEL_ADMIN_SEED|CITADEL_ADMIN_PORT|CITADEL_EPOCH_SECS|CITADEL_ISSUER_PORT|\
      CITADEL_KEYSYNC_SEED)
        # уже заданный флаг/env приоритетнее файла (позволяет точечно переопределить)
        [[ -n "${!k:-}" ]] || printf -v "$k" '%s' "$v" ;;
      *) warn "issuer-bundle: неизвестный ключ '$k' пропущен" ;;
    esac
  done < "$BUNDLE_SRC"
  [[ -n "${CITADEL_ISSUER_ADDR:-}" ]] || die "--issuer-bundle: в bundle нет CITADEL_ISSUER_ADDR (вставился пустой/не тот текст?)"
  ADMIN_PORT="${CITADEL_ADMIN_PORT:-$ADMIN_PORT}"
  ISSUER_PORT="${CITADEL_ISSUER_PORT:-$ISSUER_PORT}"
  EPOCH_SECS="${CITADEL_EPOCH_SECS:-$EPOCH_SECS}"
fi
ISSUER_ADDR="${CITADEL_ISSUER_ADDR:-}"     # host:port издателя (только --role exit)
ISSUER_PIN_IN="${CITADEL_ISSUER_PIN:-}"    # его TLS-pin
ISSUER_MLDSA_IN="${CITADEL_ISSUER_MLDSA:-}" # обязательство его PQ-идентичности
PSK_IN="${CITADEL_OBFS_PSK:-}"             # общий obfs-PSK (генерит установка издателя)
# M-6: идентичность exit-узла для получения СЕКРЕТНОГО ключа эпохи (keysync). Раньше ключ был
# публичным и синхронизировался без аутентификации — в схеме v2 так нельзя: получивший ключ
# чеканит токены. Генерит установка издателя, едет в bundle.
KEYSYNC_SEED_IN="${CITADEL_KEYSYNC_SEED:-}"
CLIENT_SEED_IN="${CITADEL_CLIENT_SEED:-}"  # seed абонента (ссылку минтит exit-машина)
ADMIN_SEED_IN="${CITADEL_ADMIN_SEED:-}"    # seed админа (мастер-ссылка)
# B-2/R4.2: файл с паролем для конверта мастер-ссылки. Пароль берётся ИЗ ФАЙЛА, а не аргументом:
# аргумент виден в `ps` любому пользователю машины и остаётся в истории шелла.
MASTER_PASSWORD_FILE="${CITADEL_MASTER_PASSWORD_FILE:-}"
if [[ -n "$MASTER_PASSWORD_FILE" ]]; then
  [[ -r "$MASTER_PASSWORD_FILE" ]] || die "--master-password: файл не читается: $MASTER_PASSWORD_FILE"
  [[ -s "$MASTER_PASSWORD_FILE" ]] || die "--master-password: файл пуст — конверт без пароля не имеет смысла"
fi
if [[ "$ROLE" == exit && "$ISSUER_ON" == 1 ]]; then
  hex64() { [[ "$1" =~ ^[0-9a-fA-F]{64}$ ]]; }
  [[ -n "$ISSUER_ADDR" ]] || die "--role exit: нужен --issuer-addr host:port (или --issuer-bundle)"
  [[ "$ISSUER_ADDR" == *:* ]] || die "--issuer-addr: ожидается host:port, получено '$ISSUER_ADDR'"
  for spec in "ISSUER_PIN_IN:--issuer-pin" "ISSUER_MLDSA_IN:--issuer-mldsa" "PSK_IN:--obfs-psk" \
              "CLIENT_SEED_IN:--client-seed" "ADMIN_SEED_IN:--admin-seed" \
              "KEYSYNC_SEED_IN:--keysync-seed"; do
    var="${spec%%:*}"; flag="${spec##*:}"
    [[ -n "${!var}" ]] || die "--role exit: нужен $flag (или --issuer-bundle с ним)"
    hex64 "${!var}" || die "$flag: ожидается 64 hex-символа"
  done
fi

# ─── 0a-ter. L-14: кто имеет право стучаться в admin-канал издателя ───
# При раздельном деплое admin-порт приходится публиковать наружу (его дёргает exit-машина через
# DNAT из туннеля), и до аудита-4 его «закрывала» строчка в выводе установщика — то есть контроль
# существовал только в голове оператора и исчезал при первой же переустановке хоста. Теперь адрес
# exit-машины обязателен и уезжает в сам процесс издателя (`Citadel_ADMIN_PEER`), который закрывает
# чужие коннекты ДО TLS. Осознанный отказ — `--admin-peer any` (тогда порт открыт всем, как раньше).
ADMIN_PEER="${CITADEL_ADMIN_PEER:-}"
if [[ "$ROLE" == issuer ]]; then
  [[ -n "$ADMIN_PEER" ]] || die \
    "--role issuer: нужен --admin-peer <IP exit-машины> — admin-порт $ADMIN_PORT публикуется наружу,
   и без списка разрешённых адресов он открыт всему интернету. Осознанно открыть: --admin-peer any"
  if [[ "$ADMIN_PEER" != "any" ]]; then
    for a in ${ADMIN_PEER//,/ }; do
      [[ "$a" =~ ^[0-9a-fA-F:.]+$ ]] || die "--admin-peer: '$a' не похоже на IP-адрес"
    done
  fi
fi

# ─── 0a-pre. случайные порты вместо «подписи Citadel» (M-8, аудит-4) ───
# Приоритет: явный флаг/env > уже выбранное прошлой установкой > свежий случайный.
# Запоминать обязательно: порт уезжает в КАЖДУЮ выданную ссылку, и повторный запуск установщика с
# новым случайным портом молча оборвал бы всех абонентов (в т.ч. при CITADEL_KEEP_KEYS=1, где
# ссылки обязаны пережить обновление).
PORTS_FILE="$DIR/etc/ports.env"
# Переустановка БЕЗ `CITADEL_KEEP_KEYS` ротирует идентичность (§3.5), и все розданные ссылки
# умирают в любом случае. Держаться в этом сценарии за прежние порты незачем: это бесплатно
# оставляло бы деплою прежнюю примету — а именно так и сохранялись исторические 4433/7000 на
# серверах, поставленных до M-8. С `CITADEL_KEEP_KEYS=1` всё наоборот: ссылки живут, значит порты
# обязаны остаться теми же. Явный флаг/env сильнее любого из правил.
ROTATING=0
[[ -f "$DIR/keys/obfs.psk" && "${CITADEL_KEEP_KEYS:-0}" != 1 ]] && ROTATING=1

# Порты ПРЕЖНЕЙ установки — нужны, даже когда мы их не наследуем: по ним в firewall стоят
# разрешающие правила, и при смене портов их надо снять (иначе на сервере годами висят открытые
# порты, которых уже никто не слушает — лишняя примета деплоя и лишняя поверхность).
PREV_UDP_PORT=""; PREV_ISSUER_PORT=""
if [[ -r "$PORTS_FILE" ]]; then
  while IFS='=' read -r k v; do
    case "$k" in
      UDP_PORT)    PREV_UDP_PORT="$v" ;;
      ISSUER_PORT) PREV_ISSUER_PORT="$v" ;;
    esac
  done < "$PORTS_FILE"
elif [[ -f "$DIR/etc/compose.yml" ]]; then
  # Установка до M-8 (ports.env ещё не было) — исторические значения.
  PREV_UDP_PORT=4433; PREV_ISSUER_PORT=7000
fi
if [[ -r "$PORTS_FILE" && "$ROTATING" != 1 ]]; then
  [[ -n "$UDP_PORT"    ]] || UDP_PORT="$PREV_UDP_PORT"
  [[ -n "$ISSUER_PORT" ]] || ISSUER_PORT="$PREV_ISSUER_PORT"
fi
# Обновление УЖЕ СТОЯЩЕЙ установки, сделанной до M-8 (ports.env ещё нет): порты обязаны остаться
# прежними — исторические 4433/7000, — но ТОЛЬКО когда идентичность сохраняется. Иначе
# `CITADEL_KEEP_KEYS=1`, который существует ровно затем, чтобы выданные ссылки пережили обновление,
# молча уводил бы сервер на случайный порт, и все абоненты получили бы «ни один exit недоступен».
# Кто ставил со своими портами — передаёт их тем же флагом, что и раньше.
if [[ ! -r "$PORTS_FILE" && -f "$DIR/etc/compose.yml" && "$ROTATING" != 1 ]]; then
  [[ -n "$UDP_PORT"    ]] || { UDP_PORT=4433; LEGACY_PORTS=1; }
  [[ -n "$ISSUER_PORT" ]] || { ISSUER_PORT=7000; LEGACY_PORTS=1; }
  if [[ "${LEGACY_PORTS:-0}" == 1 ]]; then
    warn "обновление прежней установки: порты оставлены историческими ($UDP_PORT/udp, $ISSUER_PORT/tcp),"
    warn "чтобы выданные ссылки продолжали работать. Сменить их (M-8) — --udp-port/--issuer-port + новые ссылки."
  fi
fi
# Диапазон 10000..31999: выше «интересных» сервисных портов и НИЖЕ эфемерного (32768+), иначе
# сервер соревновался бы за порт с исходящими соединениями самой машины.
rand_port() { echo $(( 10000 + $(od -An -N2 -tu2 /dev/urandom | tr -d ' ') % 22000 )); }
PORTS_PICKED=0
[[ -n "$UDP_PORT"    ]] || { UDP_PORT="$(rand_port)";    PORTS_PICKED=1; }
[[ -n "$ISSUER_PORT" ]] || { ISSUER_PORT="$(rand_port)"; PORTS_PICKED=1; }
# Совпали два случайных — переберём (проверка ниже всё равно отвалила бы установку).
while [[ "$ISSUER_PORT" == "$UDP_PORT" || "$ISSUER_PORT" == "$TCP_PORT" || "$ISSUER_PORT" == "$ADMIN_PORT" ]]; do
  ISSUER_PORT="$(rand_port)"; PORTS_PICKED=1
done

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
# N-7 (supply chain): ставим из РЕПОЗИТОРИЯ ДИСТРИБУТИВА — пакеты подписаны, подпись проверяет сам
# apt/dnf. Прежний путь (`curl https://get.docker.com | sh`) исполнял на свежей машине скачанный
# скрипт без единой проверки — планка ниже, чем у собственных бинарей проекта, которые тут же
# рядом верифицируются minisign'ом по вшитому ключу.
#
# Если в дистрибутиве нет compose v2, установка НЕ уходит молча на сторонний скрипт: это решение
# оператора, и принимается оно явно — `CITADEL_ALLOW_DOCKER_SCRIPT=1`.
if ! docker compose version >/dev/null 2>&1; then
  log "Docker не найден — ставлю из репозитория дистрибутива (подпись проверяет пакетный менеджер)…"
  if   command -v apt-get >/dev/null; then
    apt-get update -qq && apt-get install -y -qq docker.io docker-compose-v2 || true
  elif command -v dnf >/dev/null; then
    dnf install -y -q moby-engine docker-compose || true
  fi
  systemctl enable --now docker 2>/dev/null || true
  if ! docker compose version >/dev/null 2>&1; then
    if [[ "${CITADEL_ALLOW_DOCKER_SCRIPT:-0}" == 1 ]]; then
      log "⚠ compose v2 нет в репозитории дистрибутива — по явному разрешению ставлю get.docker.com"
      curl -fsSL https://get.docker.com | sh || die "установка Docker не удалась"
      systemctl enable --now docker 2>/dev/null || true
    else
      die "нет docker с compose v2. Поставь его из репозитория дистрибутива (docker.io + \
docker-compose-v2 / moby-engine + docker-compose) либо из официального репозитория Docker с GPG. \
Если осознанно согласен на исполнение скачанного скрипта get.docker.com — CITADEL_ALLOW_DOCKER_SCRIPT=1"
    fi
    docker compose version >/dev/null 2>&1 || die "docker compose недоступен после установки"
  fi
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
# M-8: запомнить выбранные порты — следующая установка/обновление возьмёт их отсюда, и уже
# розданные ссылки не «переедут» на новый случайный порт.
printf 'UDP_PORT=%s\nISSUER_PORT=%s\n' "$UDP_PORT" "$ISSUER_PORT" > "$PORTS_FILE"
chmod 644 "$PORTS_FILE"
if [[ "$PORTS_PICKED" == 1 ]]; then
  # Роль решает, какой из портов этой машине вообще нужен: exit не поднимает издателя, издатель —
  # туннель. Печатать оба значило бы отправить оператора открывать в firewall лишнее.
  case "$ROLE" in
    exit)   log "порт туннеля выбран случайно (M-8: не «подпись Citadel»): QUIC/UDP $UDP_PORT" ;;
    issuer) log "порт издателя выбран случайно (M-8: не «подпись Citadel»): TCP $ISSUER_PORT" ;;
    *)      log "порты выбраны случайно (M-8: не «подпись Citadel»): QUIC/UDP $UDP_PORT, издатель TCP $ISSUER_PORT" ;;
  esac
  log "запомнены в $PORTS_FILE и попадут в ссылки; открой их в firewall/security-group; свои — --udp-port/--issuer-port"
  # Переустановка с ротацией: прежние порты у оператора уже открыты, новые — ещё нет, и это самая
  # частая причина «поставил заново, а туннель не поднимается». Говорим об этом прямо.
  [[ "$ROTATING" == 1 ]] && warn "переустановка с ротацией идентичности: порты выбраны ЗАНОВО — открой новые в firewall (прежние можно закрыть)"
fi
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
  rm -f "$DIR/keys/"obfs.psk "$DIR/keys/"obfs.master "$DIR/keys/"client.seed "$DIR/keys/"admin.seed \
        "$DIR/keys/"issuer-mldsa.seed "$DIR/keys/"issuer-mldsa.pin \
        "$DIR/keys/"admin_id "$DIR/keys/"admin.client_id "$DIR/keys/"registry "$DIR/keys/"tokens \
        "$DIR/keys/"exit.pin "$DIR/keys/"exit-cert.der "$DIR/keys/"exit-key.der \
        "$DIR/keys/"exit-mldsa.seed "$DIR/keys/"exit.mldsa "$DIR/keys/"exit2.pin "$DIR/keys/"exit2.mldsa \
        "$DIR/keys/"issuer-tls.crt "$DIR/keys/"issuer-tls.key "$DIR/keys/"issuer-tls.pin \
        "$DIR/keys/"issuer.key "$DIR"/keys/issuer-*.key "$DIR/keys/"keysync.seed \
        "$DIR"/keys/exit-*.key \
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

# H-3 (аудит-4): МАСТЕР-секрет L1 — из него выводится ключ obfs КАЖДОЙ эпохи. В отличие от
# $PSK он в ссылки НЕ попадает и машину не покидает: абонент получает ключ текущей эпохи у
# издателя после Layer-1, ровно на одну эпоху. Отсюда два свойства, которых не было:
#   * отзыв абонента (admin-канал) гасит и L1-доступ (со следующей эпохи), а не только выдачу;
#   * утёкшая ссылка перестаёт быть бессрочным классификатором трафика этого деплоя.
# Бутстрапный $PSK остаётся тем, чем и был, — обёрткой канала К ИЗДАТЕЛЮ (его адрес и так в ссылке).
# Мастер нужен ОБЕИМ серверным ролям: издатель раздаёт ключи эпох, exit ими принимает.
MASTER_FILE="$DIR/keys/obfs.master"
if [[ "$ROLE" == exit && -n "${CITADEL_OBFS_MASTER:-}" ]]; then
  printf '%s' "$CITADEL_OBFS_MASTER" > "$MASTER_FILE"
  chmod 600 "$MASTER_FILE"
elif [[ ! -f "$MASTER_FILE" ]]; then
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$MASTER_FILE"
  chmod 600 "$MASTER_FILE"
fi
MASTER="$(cat "$MASTER_FILE")"
# Ротация L1 живёт на канале издателя: без него ключ эпохи некому раздать, и exit обязан
# остаться на бутстрапном PSK (иначе token-less деплой просто перестал бы принимать клиентов).
[[ "$ISSUER_ON" == 1 ]] || MASTER=""

CLIENT_SEED=""; CLIENT_PUB=""
ADMIN_SEED=""; ADMIN_PUB=""
# M-6: идентичность keysync — ею exit-узел (на ДРУГОЙ машине) забирает секретный ключ эпохи.
# Живёт на машине издателя, уезжает в bundle. Издатель знает только её id, не seed.
KEYSYNC_SEED="$KEYSYNC_SEED_IN"; KEYSYNC_ID=""
if [[ "$ISSUER_ON" == 1 && "$ROLE" != exit ]]; then
  KEYSYNC_FILE="$DIR/keys/keysync.seed"
  if [[ ! -f "$KEYSYNC_FILE" ]]; then
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$KEYSYNC_FILE"
    chmod 600 "$KEYSYNC_FILE"
  fi
  KEYSYNC_SEED="$(cat "$KEYSYNC_FILE")"
  KEYSYNC_ID="$(Citadel_CLIENT_SEED="$KEYSYNC_SEED" "$DIR/bin/citadel-token" pubkey)" \
    || die "не удалось вывести id keysync-идентичности (citadel-token pubkey)"
fi
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
  # B-2/R4.2 (восстановление доступа): ПРЕЖНЮЮ Layer-1 запись админа запоминаем ДО перезаписи —
  # ниже она гасится в реестре. Иначе устройство с потерянной/скомпрометированной мастер-ссылкой
  # хоть и лишалось admin-прав (admin_id сменился), но продолжало ходить в туннель как обычный
  # абонент. Перевыпуск мастер-доступа обязан отбирать доступ целиком, иначе это не перевыпуск.
  OLD_ADMIN_CID=""
  [[ -s "$DIR/keys/admin.client_id" ]] && OLD_ADMIN_CID="$(cat "$DIR/keys/admin.client_id")"
  # admin_id — pub, по которому issuer пускает в admin-канал. admin.client_id — Layer-1 client_id
  # самого админа: issuer запрещает его отзыв (анти-self-lockout, R6). Оба файла читает issuer из /shared.
  printf '%s' "$ADMIN_PUB"  > "$DIR/keys/admin_id"
  printf '%s' "$CLIENT_PUB" > "$DIR/keys/admin.client_id"
  chmod 644 "$DIR/keys/admin_id" "$DIR/keys/admin.client_id"  # публичные id (не секрет), nobody читает
  log "admin-плоскость: admin_id=${ADMIN_PUB:0:16}… (admin.seed только в мастер-ссылке)"
fi

# M-9: как посеять запись админа в реестр. Одноразовой её делает суффикс со сроком активации —
# см. `Citadel_REGISTER_PUBS` в entrypoint издателя.
REGISTER_PUBS="$CLIENT_PUB"
[[ "$ISSUER_ON" == 1 ]] && REGISTER_PUBS="$CLIENT_PUB:$ACTIVATE_UNTIL"

# Публичный адрес машины. Определяем ЗДЕСЬ, а не перед печатью ссылки: он нужен уже entrypoint'у
# exit'а (G1: свой публичный адрес из туннеля недостижим). Заодно установка падает до сборки
# образа, а не после неё, если адрес не определить.
#
# N-8: спрашиваем СНАЧАЛА у самой машины (адрес интерфейса, через который уходит маршрут по
# умолчанию). Обращение к чужому сервису — только если локальный адрес непубличный (NAT/CGNAT):
# оно сообщает третьей стороне факт и время установки, а при недоступности сервиса ещё и роняет
# установку на ровном месте. `CITADEL_NO_EXTERNAL_IP=1` запрещает такой запрос совсем.
is_public_ip() {
  case "$1" in
    ""|10.*|127.*|169.254.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 1 ;;
    100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 1 ;;  # CGNAT 100.64/10
    *) return 0 ;;
  esac
}
if [[ -z "$SERVER_HOST" ]]; then
  SERVER_HOST="$(ip -4 route get 1.1.1.1 2>/dev/null |
    awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  if is_public_ip "$SERVER_HOST"; then
    log "публичный адрес взят с интерфейса машины: $SERVER_HOST"
  elif [[ "${CITADEL_NO_EXTERNAL_IP:-0}" == 1 ]]; then
    die "локальный адрес непубличный (${SERVER_HOST:-нет}), а внешний запрос запрещён \
(CITADEL_NO_EXTERNAL_IP=1) — задай CITADEL_SERVER_HOST=<ip/host>"
  else
    log "локальный адрес непубличный (${SERVER_HOST:-нет}) — спрашиваю внешний сервис"
    SERVER_HOST="$(curl -fsS --max-time 8 https://api.ipify.org 2>/dev/null || true)"
  fi
fi
[[ -n "$SERVER_HOST" ]] || die "не удалось определить публичный IP — задай CITADEL_SERVER_HOST=<ip/host>"

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
# G1/G2: что именно закрыть у exit'а со стороны туннеля (подставляется в entrypoint ниже).
#   * своя машина закрывается ВСЕГДА; при совмещённой установке на ней же опубликован token-порт
#     издателя — его оставляем открытым (§7.1: дозаправка кошелька идёт сквозь туннель нарочно);
#   * при раздельной установке закрывается ещё и машина издателя — с тем же единственным
#     исключением на её token-порт (admin-порт с неё закрыт: в admin ходят через VIP, C7.2).
G1_OWN_TOKEN_PORT=""; G1_ISSUER_HOST=""; G1_ISSUER_PORT=""
if [[ "$ISSUER_ON" == 1 ]]; then
  if [[ "$ROLE" == exit ]]; then
    G1_ISSUER_HOST="$ISSUER_DNS_NAME"
    G1_ISSUER_PORT="$ISSUER_TOKEN_PORT"
  else
    G1_OWN_TOKEN_PORT="$ISSUER_PORT"
  fi
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
COPY etc/entrypoint-keysync.sh /usr/local/bin/entrypoint-keysync.sh
RUN chmod +x /usr/local/bin/citadel-m1 /usr/local/bin/citadel-token \
        /usr/local/bin/entrypoint-exit.sh /usr/local/bin/entrypoint-issuer.sh \
        /usr/local/bin/entrypoint-keysync.sh
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
# H-3: мастер L1 (если издатель есть) — канал данных принимает только ключи эпох, не PSK из ссылок.
export Citadel_OBFS_MASTER="${Citadel_OBFS_MASTER:-}"
export Citadel_EPOCH_SECS=$EPOCH_SECS   # та же эпоха, что у токенов: ключ L1 ротируется с ней
export Citadel_TCP_LISTEN=0.0.0.0:443
export Citadel_KX=pq   # S1.1/M4: PQ-only (анти-HNDL) — classical не принимаем
rm -f /shared/exit.pin   # pin перезапишется тем же значением из постоянного серта (A7)
EOF
  if [[ "$RATE_LIMIT" != 0 ]]; then
    cat <<EOF
# F7/D3 (M-3, аудит-4): per-client token-bucket. Без него один абонент насыщал аплинк exit'а —
# отказ в обслуживании остальным. Мелкие пакеты тоже считаются (MIN_PACKET_COST), поэтому
# PPS-абуз режется наравне с полосой. M-3-bis: направления считаются раздельно.
export Citadel_RATE_LIMIT=$RATE_LIMIT
export Citadel_RATE_BURST=$RATE_BURST
export Citadel_RATE_LIMIT_DOWN=$RATE_LIMIT_DOWN
export Citadel_RATE_BURST_DOWN=$RATE_BURST_DOWN
echo "[citadel-exit] F7 rate-limit на абонента: ↑ $RATE_LIMIT б/с (всплеск $RATE_BURST) · ↓ $RATE_LIMIT_DOWN б/с (всплеск $RATE_BURST_DOWN)"
EOF
  else
    cat <<EOF
export Citadel_RATE_LIMIT_DOWN=$RATE_LIMIT_DOWN
export Citadel_RATE_BURST_DOWN=$RATE_BURST_DOWN
echo "[citadel-exit] ⚠ F7 rate-limit вверх ВЫКЛЮЧЕН (--rate-limit 0): один абонент может занять весь аплинк"
EOF
  fi
  if [[ "$ISSUER_ON" == 1 ]]; then
    cat <<EOF
# C5.4b: exit требует анонимный epoch-токен текущей эпохи (отзыв по времени, M6).
# M-6: схема токенов v2 (VOPRF) — ключ эпохи СЕКРЕТЕН, файл issuer.key (0640, группа exit'а).
export Citadel_ISSUER_KEY=/shared/issuer.key
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
  # G1/G2 (аудит-5): инфраструктурные адреса из туннеля недостижимы.
  #
  # F2 в движке режет приватные и служебные сети, но публичный адрес САМОЙ машины для него —
  # обычный публичный адрес. Ядровый `INPUT -i Citadel0 -j DROP` его тоже не ловит: он стоит в
  # netns КОНТЕЙНЕРА, а пакет с dst = публичный IP хоста в этот INPUT не попадает — контейнер
  # форвардит его наружу (MASQUERADE), и в INPUT он приходит уже у ХОЗЯЙСКОГО ядра, как локальный
  # трафик с docker-бриджа, то есть мимо облачной security-group. Без этого списка любой абонент
  # дотягивался из туннеля до всего, что хост слушает на 0.0.0.0 (sshd, агенты мониторинга,
  # published-порты соседних контейнеров), и до admin-порта издателя напрямую — там SNAT exit'а
  # выдавал его за разрешённый адрес exit-машины (Citadel_ADMIN_PEER, L-14) — это G2.
  #
  # Исключение ровно одно и точечное: token-порт издателя. Фоновая дозаправка кошелька (§7.1,
  # заход 7) идёт СКВОЗЬ туннель нарочно — чтобы издатель видел адрес exit'а, а не абонента.
  cat <<EOF
resolve_ip() {   # имя → IP; литеральный IPv4 отдаём как есть (getent на него вернёт пусто)
  case "\$1" in
    *[!0-9.]*) getent hosts "\$1" | awk '{print \$1}' | head -n1 ;;
    *) printf '%s' "\$1" ;;
  esac
}
DENY=""; ALLOW=""
# \$1 — адрес/имя, \$2 — единственный TCP-порт, который на нём остаётся открытым (пусто — ни одного).
# Явный \`return 0\`: без него пустой \$2 сделал бы последним неуспешный test, и \`set -e\` убил бы старт.
add_deny() {
  [ -n "\$1" ] || return 0
  DENY="\${DENY:+\$DENY,}\$1"
  [ -n "\$2" ] && ALLOW="\${ALLOW:+\$ALLOW,}\$1:\$2"
  return 0
}
add_deny "\$(resolve_ip '$SERVER_HOST')" '$G1_OWN_TOKEN_PORT'
add_deny "\$(resolve_ip '$G1_ISSUER_HOST')" '$G1_ISSUER_PORT'
export Citadel_DENY_DSTS="\$DENY"
export Citadel_ALLOW_DSTS="\$ALLOW"
if [ -n "\$DENY" ]; then
  echo "[citadel-exit] G1: из туннеля закрыты \$DENY (открыт из них только: \${ALLOW:-ничего})"
else
  echo "[citadel-exit] ⚠ G1: публичный адрес не резолвится — инфраструктурный запрет НЕ поднят"
fi
EOF
  echo 'exec citadel-m1'
} > "$DIR/etc/entrypoint-exit.sh"
chmod +x "$DIR/etc/entrypoint-exit.sh"

# entrypoint keysync-сайдкара (P1, раздельный деплой): держит ключ ТЕКУЩЕЙ эпохи в томе exit'а.
# При установке «всё на одном сервере» не задействуется — там ключ пишет сам издатель.
# M-6: ключ эпохи секретен, поэтому сайдкар доказывает издателю свою keysync-идентичность
# (seed приехал в bundle; издатель знает только его id).
cat > "$DIR/etc/entrypoint-keysync.sh" <<EOF
#!/usr/bin/env bash
set -e
export Citadel_TOKEN_ROLE=keysync
export Citadel_TOKEN_DIR=/shared
export Citadel_TOKEN_ISSUER=$ISSUER_ADDR
export Citadel_ISSUER_PIN=$ISSUER_PIN_IN
export Citadel_ISSUER_MLDSA=$ISSUER_MLDSA_IN
export Citadel_KEYSYNC_SEED=$KEYSYNC_SEED_IN
export Citadel_EPOCH_SECS=$EPOCH_SECS
# B-1: ключ эпохи выводится ПОД КОНКРЕТНЫЙ узел, поэтому сайдкар обязан назвать издателю pin своего
# exit'а. Файл пишет сам exit при старте (Citadel_PIN_FILE); пока его нет, сайдкар просто ждёт.
export Citadel_EXIT_PIN_FILE=/shared/exit.pin
export Citadel_OBFS_PSK=\$(cat /shared/obfs.psk)
echo "[citadel-keysync] слежу за ключом эпохи у издателя $ISSUER_ADDR (эпоха ${EPOCH_SECS}с)…"
exec citadel-token
EOF
chmod +x "$DIR/etc/entrypoint-keysync.sh"

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
# client_id админа (issuer НЕ получает seed). M-9: суффикс `:<unix>` делает запись ОДНОРАЗОВОЙ —
# мастер-ссылка активируется на первом устройстве админа и до этого момента, дальше мертва.
# Отпечаток ссылки (`linkh`) здесь ещё неизвестен — TLS-идентичность издателя рождается при первом
# старте контейнера, то есть ПОСЛЕ генерации этого файла; его дописывает установщик сразу после
# того, как соберёт ссылку (см. ниже `registry add --linkh`). Если реестр когда-нибудь потеряется,
# этот bootstrap пересоздаст запись одноразовой и просроченной — то есть fail-closed, а не
# «внезапно снова многоразовая».
export Citadel_REGISTER_PUBS="$REGISTER_PUBS"
# M-6/P1: кому отдавать секретный ключ эпохи по сети (роль keysync у exit-машины). При установке
# «всё на одном сервере» ключ читается с общего тома и раздача по сети не нужна — но id всё равно
# задан, чтобы `--role issuer` и `--role all` вели себя одинаково.
export Citadel_KEYSYNC_ID=$KEYSYNC_ID
# L-14: при раздельном деплое admin-порт публикуется наружу — процесс сам закрывает всех, кроме
# exit-машины (до TLS, до слота гейта). Пусто = совмещённая установка, порт наружу не смотрит.
export Citadel_ADMIN_PEER="$ADMIN_PEER"
# H-3: мастер L1 — из него абоненту выдаётся ключ текущей эпохи (после Layer-1, ровно на эпоху).
# \$ ОБЯЗАТЕЛЕН: этот heredoc — не в кавычках, и без экранирования переменную раскрывал бы САМ
# установщик (у него её нет — мастер лежит в \$MASTER), зашивая в скрипт `=""`. Тогда издатель
# молча уходил в legacy «ротации нет», exit при этом принимал ТОЛЬКО ключи эпох, и туннель не
# поднимался ни по QUIC, ни по obfs-TCP — оба транспорта выглядели как «порт закрыт».
export Citadel_OBFS_MASTER="\${Citadel_OBFS_MASTER:-}"
rm -f /shared/issuer.key /shared/issuer-*.key /shared/issuer.pub /shared/issuer-*.pub /shared/tokens
# M-4 (аудит-4): привилегии издателя режет compose (cap_drop: ALL + read_only + no-new-privileges).
# Смена uid здесь не делается — том общий с exit'ом (и с keysync при раздельной установке), и
# переразметка владения затронула бы три роли сразу. Вне докера есть Citadel_DROP_UID.
echo "[citadel-issuer] Layer-1 registry + слепая выдача epoch-токенов (epoch=${EPOCH_SECS}s, :7000) + admin-канал :$ADMIN_PORT…"
exec citadel-token
EOF
chmod +x "$DIR/etc/entrypoint-issuer.sh"

# ─── гейт H-3: обе роли обязаны ПОЛУЧИТЬ мастер L1 из compose ───
# Мастер в сами скрипты не подставляется намеренно: entrypoint'ы уезжают слоями образа (Dockerfile
# COPY), а мастер — серверный секрет. Значит единственный корректный вид строки — ссылка на
# переменную, раскрываемая в контейнере. Если генерация раскроет её сама (heredoc без кавычек), в
# файл попадёт `=""`, издатель молча уйдёт в legacy «ротации нет», exit останется на ключах эпох —
# и туннель не поднимется НИ по QUIC, НИ по obfs-TCP, причём оба транспорта будут выглядеть как
# «порт закрыт/firewall». Такой деплой обязан падать здесь, а не у абонента.
if [[ -n "$MASTER" ]]; then
  for f in "$DIR/etc/entrypoint-issuer.sh" "$DIR/etc/entrypoint-exit.sh"; do
    [[ -f "$f" ]] || continue
    grep -qF 'Citadel_OBFS_MASTER="${Citadel_OBFS_MASTER:-}"' "$f" \
      || die "внутренняя ошибка генерации: $(basename "$f") не пробрасывает Citadel_OBFS_MASTER — L1 у издателя и exit'а разойдётся (H-3)"
  done
fi

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
    # M-4 (аудит-4): издателю не нужна НИ ОДНА capability — он слушает порты >1024, не трогает
    # сеть ядра и работает только со своим томом. Ни одной не оставляем. До этого он шёл с полным
    # дефолтным набором docker — и это процесс, который разбирает ВЕСЬ недоверенный сетевой ввод и
    # держит все ключи (RSA-sk эпохи, TLS-приватник, ML-DSA-seed, реестр, PSK).
    cap_drop: ["ALL"]
    restart: unless-stopped
    environment:
      Citadel_OBFS_PSK: "$PSK"         # S2.1/A1-остаток: obfs-обёртка token-/admin-каналов (probe-resistance)
      Citadel_OBFS_MASTER: "$MASTER"   # H-3: из него издатель выводит ключ L1 текущей эпохи для абонентов
    # M-6: ключ эпохи — секрет (0640 на общем томе). Группа файла обязана совпасть с той, в которую
    # садится exit после сброса привилегий, иначе он не прочитает ключ и откажет всем токенам.
    # Через chown это не сделать: у издателя cap_drop ALL (M-4), CAP_CHOWN нет.
    user: "0:65534"
    ports:
      - "$ISSUER_PORT:7000/tcp"        # клиент фетчит epoch-токены сюда (Layer-1)$(
      if [[ "$ROLE" == issuer ]]; then printf '\n      - "%s:%s/tcp"   # admin-канал: нужен только exit-машине (%s). L-14: посторонние адреса режет сам издатель (Citadel_ADMIN_PEER), firewall — второй рубеж' "$ADMIN_PORT" "$ADMIN_PORT" "$ADMIN_PEER"; fi)
    volumes:
      - "$DIR/keys:/shared"
    healthcheck:                       # готов, когда ключ эпохи сгенерирован и issuer.key лежит на томе
      test: ["CMD-SHELL", "test -f /shared/issuer.key"]
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
    # M-4: минимальный набор вместо дефолтного docker-набора (уходят DAC_OVERRIDE, FOWNER, MKNOD,
    # SYS_CHROOT, AUDIT_WRITE, SETPCAP, SETFCAP, KILL). NET_ADMIN — TUN/iptables/ip route;
    # NET_BIND_SERVICE — obfs-TCP на :443; NET_RAW — iptables; SETUID/SETGID — сброс привилегий (F4).
    cap_drop: ["ALL"]
    cap_add: ["NET_ADMIN", "NET_BIND_SERVICE", "NET_RAW", "SETUID", "SETGID"]
    security_opt: ["no-new-privileges:true"]
    devices: ["/dev/net/tun:/dev/net/tun"]
    sysctls: ["net.ipv4.ip_forward=1"]
    restart: unless-stopped
    environment:
      Citadel_OBFS_PSK: "$PSK"
      Citadel_OBFS_MASTER: "$MASTER"   # H-3: пусто = ротации нет (token-less деплой)
    ports:
      - "$UDP_PORT:4433/udp"
      - "$TCP_PORT:443/tcp"
    volumes:
      - "$DIR/keys:/shared"
EOF
if [[ "$ISSUER_ON" == 1 && "$ROLE" == all ]]; then
cat <<EOF
    depends_on:
      issuer: { condition: service_healthy }   # нужен issuer.key для верификации токенов
EOF
fi
# P1: при раздельном деплое ключ эпохи на exit-машину приносит сайдкар (общего тома с издателем
# нет, а ключ ротируется каждую эпоху).
if [[ "$ISSUER_ON" == 1 && "$ROLE" == exit ]]; then
cat <<EOF
  keysync:
    image: citadel-exit:$VERSION
    container_name: citadel-keysync
    entrypoint: ["/usr/local/bin/entrypoint-keysync.sh"]
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
  # B-1: сайдкар кладёт СВОЙ ключ узла (`exit-<эпоха>.key`), а не мастер эпохи — мастер остаётся у
  # издателя. Поэтому ждём именно этот файл; наличие `issuer.key` на exit-машине после B-1 означало
  # бы, что на неё уехал мастер (то есть ровно то, чего быть не должно).
  have_exit_key() { compgen -G "$DIR/keys/exit-*.key" >/dev/null 2>&1; }
  for _ in $(seq 1 90); do [[ -s "$DIR/keys/exit.mldsa" ]] && have_exit_key && break; sleep 1; done
  [[ -s "$DIR/keys/exit.mldsa" ]] || die "exit не опубликовал ML-DSA pub (exit.mldsa) за 90с"
  have_exit_key || {
    docker compose -f "$DIR/etc/compose.yml" logs --tail 30 keysync || true
    die "не удалось получить ключ эпохи у издателя $ISSUER_ADDR за 90с — проверь: порт $ISSUER_TOKEN_PORT открыт с этой машины, obfs-PSK/pin/обязательство из bundle те самые (лог выше)"
  }
  MLDSA_ARGS=(--mldsa-pub "$DIR/keys/exit.mldsa")
  log "ключ эпохи получен от издателя ✓ (дальше сайдкар citadel-keysync держит его свежим)"
elif [[ "$ISSUER_ON" == 1 ]]; then
  log "жду издателя (issuer.key, issuer-tls.pin, issuer-mldsa.pin) и ML-DSA pub exit'а…"
  for _ in $(seq 1 90); do [[ -s "$DIR/keys/issuer.key" && -s "$DIR/keys/issuer-tls.pin" && -s "$DIR/keys/issuer-mldsa.pin" && -s "$DIR/keys/exit.mldsa" ]] && break; sleep 1; done
  [[ -s "$DIR/keys/issuer.key" ]] || { docker compose -f "$DIR/etc/compose.yml" logs --tail 40 issuer || true; die "издатель не положил ключ эпохи (issuer.key) за 90с"; }
  [[ -s "$DIR/keys/issuer-tls.pin" ]] || die "издатель не опубликовал issuer-tls.pin (PQ-TLS канал, A1) за 90с"
  [[ -s "$DIR/keys/issuer-mldsa.pin" ]] || die "издатель не опубликовал issuer-mldsa.pin (PQ-аутентификация издателя) за 90с"
  [[ -s "$DIR/keys/exit.mldsa" ]] || die "exit не опубликовал ML-DSA pub (exit.mldsa) за 90с"
  MLDSA_ARGS=(--mldsa-pub "$DIR/keys/exit.mldsa")
  ISSUER_TLS_PIN="$(cat "$DIR/keys/issuer-tls.pin")"   # S2.1/A1: pin PQ-TLS канала издателя → в ссылку
  # PQ: обязательство к ML-DSA-идентичности издателя. Без него клиент откажется и фетчить токены,
  # и открывать admin-канал: pin серта — классическая привязка, против CRQC она не держит.
  ISSUER_MLDSA="$(cat "$DIR/keys/issuer-mldsa.pin")"
fi

# ─── гейт H-3 (вживую): издатель ДЕЙСТВИТЕЛЬНО раздаёт ключ эпохи ───
# Статическая проверка выше ловит потерю переменной при генерации, эта — любой другой путь к тому
# же итогу (правка compose руками, старый контейнер, не перечитавший окружение). Проверяем то, что
# процесс сам сказал о себе при старте: рассинхрон L1 не виден ни по одному health-признаку —
# ключи, pin'ы и порты в порядке, а туннель не поднимается вообще.
if [[ "$ISSUER_ON" == 1 && "$ROLE" != exit && -n "$MASTER" ]]; then
  ISSUER_L1="$(docker compose -f "$DIR/etc/compose.yml" logs issuer 2>/dev/null | grep -m1 'L1-ключ для абонентов' || true)"
  case "$ISSUER_L1" in
    *"ротация по эпохам"*) : ;;   # издатель раздаёт ключ эпохи — exit его и ждёт
    *) docker compose -f "$DIR/etc/compose.yml" logs --tail 20 issuer || true
       die "издатель поднялся БЕЗ мастера L1 (${ISSUER_L1:-строка о ключе не найдена}), а exit принимает только ключи эпох — туннель не поднимется ни по QUIC, ни по obfs-TCP (H-3)" ;;
  esac
fi

# ─── 7. citadel:// (секрет) ─── (публичный адрес уже определён до генерации entrypoint'ов, §5)

# ── роль issuer: ссылок здесь нет (у машины нет exit-идентичности) — печатаем bundle для exit'а ──
if [[ "$ROLE" == issuer ]]; then
  # Bundle держим ТОЛЬКО в переменной: он несёт seed'ы абонента и админа и мастер L1, а временный
  # файл (пусть и на минуту) — это тот самый секрет на диске, которого установщик избегает везде
  # ещё (ссылки не сохраняются, seed'ы шредятся). Оператору он и не нужен: ниже bundle печатается
  # на экран, а exit-машина принимает его копипастом (`--issuer-bundle -` читает со stdin).
  BUNDLE="$(cat <<EOF
CITADEL_ISSUER_ADDR=$SERVER_HOST:$ISSUER_PORT
CITADEL_ISSUER_PIN=$ISSUER_TLS_PIN
CITADEL_ISSUER_MLDSA=$ISSUER_MLDSA
CITADEL_OBFS_PSK=$PSK
CITADEL_OBFS_MASTER=$MASTER
CITADEL_CLIENT_SEED=$CLIENT_SEED
CITADEL_ADMIN_SEED=$ADMIN_SEED
CITADEL_ADMIN_PORT=$ADMIN_PORT
CITADEL_EPOCH_SECS=$EPOCH_SECS
CITADEL_KEYSYNC_SEED=$KEYSYNC_SEED
EOF
)"
  cat <<EOF

╔══════════════════════════════════════════════════════════════════╗
║  CitadelPQVPN ИЗДАТЕЛЬ развёрнут ✓   ($SERVER_HOST:$ISSUER_PORT tcp)
╚══════════════════════════════════════════════════════════════════╝

Это половина установки: exit-узел ставится ОТДЕЛЬНОЙ командой на другой машине. Ссылок здесь нет
и быть не может — их собирает exit-машина (только у неё есть cert-pin и ML-DSA-ключ туннеля).

Порты этой машины:
  • $ISSUER_PORT/tcp  — выдача токенов          → ОТКРЫТЬ для клиентов
  • $ADMIN_PORT/tcp  — admin-канал            → разрешён только адресу: $ADMIN_PEER (L-14, режет сам издатель)
    Второй рубеж — firewall хоста, например:
      ufw allow from $ADMIN_PEER to any port $ADMIN_PORT proto tcp
    (канал и сам защищён PQ-TLS+pin и подписью админа, но лишней публичности ему не нужно)

────────────────── СЕКРЕТ: bundle для установки exit-узла ──────────────────
Скопируй в файл на exit-машине (например issuer.env) и поставь exit так:

  ./install-citadel-server.sh $VERSION --role exit --issuer-bundle issuer.env

Либо БЕЗ файла — вставить прямо в терминал exit-машины (bundle не ляжет на её диск):

  ./install-citadel-server.sh $VERSION --role exit --issuer-bundle -   # затем вставь строки и Ctrl-D

$BUNDLE
─────────────────────────────────────────────────────────────────────────────
Bundle содержит seed'ы абонента и админа — это секрет уровня «доступ к сервису». Передавай его
на exit-машину защищённым каналом (scp), не через мессенджер, и удали файл после установки.

Реестр Layer-1 и admin_id остаются ЗДЕСЬ, но управляющих команд на этой машине НЕТ: выдача,
отзыв и список абонентов идут только по admin-каналу под мастер-ссылкой (её здесь не остаётся).
Управление процессами: docker compose -f $DIR/etc/compose.yml {ps,logs,down}

ЕСЛИ ЭТА МАШИНА СКОМПРОМЕТИРОВАНА: переустанови издателя этим же скриптом (сменится его
TLS-идентичность и PQ-идентичность) и следом переустанови exit с новым bundle — прежние ссылки
станут нерабочими, раздай новые. Смысл раздельного деплоя в том, что кража ЭТОЙ машины не даёт
идентичность туннеля (она на exit-узле) — и наоборот. Подробнее: docs/SERVER-KEY-PROTECTION.md.
EOF
  unset BUNDLE   # секрет жил только в памяти этого процесса — на диск он не ложился
  # Seed'ы напечатаны — на диске издателя их не оставляем (Q2/Q4, как в общей установке).
  for sfile in "$DIR/keys/admin.seed" "$DIR/keys/client.seed"; do
    [[ -f "$sfile" ]] || continue
    shred -u "$sfile" 2>/dev/null || rm -f "$sfile"
  done
  log "seed'ы абонента и админа стёрты с машины издателя (они уехали в bundle)"
  exit 0
fi

# ─── 7.5. firewall: синхронизировать порты в ufw (обнаружение прежней установки) ───
#
# Самая частая живая поломка после переустановки: порты выбраны заново (M-8), в ufw открыты
# ПРЕЖНИЕ — сервер исправен, а у всех абонентов «сервер недоступен». Раньше установщик про это
# только писал текстом. Теперь: если ufw активен, предлагаем добавить нужные правила и снять
# правила прежних портов. Спрашиваем всегда (кроме `--ufw`/`--no-ufw`), потому что правила
# firewall — это изменение конфигурации машины, а не нашего каталога.
#
# NB: docker публикует порты через свою цепочку в nat/FORWARD и ufw их, как правило, НЕ режет.
# Это не повод не приводить правила в порядок: (а) на серверах с ufw-docker и на iptables-политике
# DROP это уже не так; (б) висящие разрешения на портах, которые никто не слушает, — лишняя
# поверхность и лишняя примета деплоя.
ufw_sync() {
  command -v ufw >/dev/null 2>&1 || return 0
  ufw status 2>/dev/null | head -1 | grep -qi 'active' || return 0   # неактивный ufw не трогаем

  # Что должно быть открыто в этой роли (admin-порт — НИКОГДА: он только из туннеля).
  local -a want=()
  case "$ROLE" in
    issuer) want+=("$ISSUER_PORT/tcp") ;;
    exit)   want+=("$UDP_PORT/udp" "$TCP_PORT/tcp") ;;
    *)      want+=("$UDP_PORT/udp" "$TCP_PORT/tcp"); [[ "$ISSUER_ON" == 1 ]] && want+=("$ISSUER_PORT/tcp") ;;
  esac
  # Что осталось от прежней установки и больше не нужно.
  local -a stale=()
  [[ -n "$PREV_UDP_PORT"    && "$PREV_UDP_PORT"    != "$UDP_PORT"    ]] && stale+=("$PREV_UDP_PORT/udp")
  [[ -n "$PREV_ISSUER_PORT" && "$PREV_ISSUER_PORT" != "$ISSUER_PORT" ]] && stale+=("$PREV_ISSUER_PORT/tcp")

  # Уже открытые правила (ufw печатает `12345/udp   ALLOW  Anywhere`).
  local rules; rules="$(ufw status 2>/dev/null || true)"
  local -a add=()
  local p
  for p in "${want[@]}"; do
    grep -qE "^${p//\//\\/}[[:space:]]+ALLOW" <<<"$rules" || add+=("$p")
  done
  local -a del=()
  for p in "${stale[@]}"; do
    grep -qE "^${p//\//\\/}[[:space:]]+ALLOW" <<<"$rules" && del+=("$p")
  done
  ((${#add[@]} + ${#del[@]})) || { log "ufw активен, порты уже в порядке"; return 0; }

  echo
  echo "Обнаружен активный ufw. Предлагаю привести правила в соответствие с этой установкой:"
  ((${#add[@]})) && printf '  открыть:  %s\n' "${add[*]}"
  ((${#del[@]})) && printf '  закрыть:  %s   (порты прежней установки)\n' "${del[*]}"
  case "$UFW_MODE" in
    yes) : ;;
    no)  log "ufw не трогаю (--no-ufw). Открой порты сам, иначе абоненты получат «сервер недоступен»."; return 0 ;;
    *)
      # Без tty (curl | bash в чужом скрипте) ничего молча не меняем — только подсказываем.
      if [[ ! -t 0 ]]; then
        warn "нет терминала для вопроса — правила ufw НЕ меняю. Повтори с --ufw либо сделай вручную:"
        for p in "${add[@]}"; do echo "    ufw allow ${p%/*}/${p#*/}"; done
        for p in "${del[@]}"; do echo "    ufw delete allow ${p%/*}/${p#*/}"; done
        return 0
      fi
      local ans=""
      read -r -p "Применить? [y/N] " ans || true
      [[ "$ans" =~ ^[YyДд]$ ]] || { log "ufw оставлен как есть (порты открой сам)"; return 0; }
      ;;
  esac
  for p in "${add[@]}"; do
    ufw allow "$p" >/dev/null 2>&1 && log "ufw: открыт $p" || warn "ufw: не удалось открыть $p"
  done
  for p in "${del[@]}"; do
    ufw delete allow "$p" >/dev/null 2>&1 && log "ufw: закрыт прежний $p" || warn "ufw: не удалось закрыть $p"
  done
}
ufw_sync

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
# M-9: установка печатает ТОЛЬКО мастер-ссылку, и та — ОДНОРАЗОВАЯ.
#
# Отдельной клиентской ссылки здесь больше нет. Она была ровно тем, чем аудит назвал суть находки
# M-9: бессрочным предъявительским доступом, напечатанным в терминал, — и вживую оказалось, что по
# ней поднимается туннель с любого числа устройств. После установки она и не нужна: абонентов
# выдаёт админ из приложения («Абоненты» → выдать), и каждая такая ссылка уже одноразовая.
#
# Мастер-ссылка активируется на ПЕРВОМ устройстве администратора (окно $ACTIVATE_SECS), после чего
# её копия бесполезна. Следствие принято сознательно: у админа одно устройство; второе — это
# переустановка сервера (или выдача себе абонентской ссылки для обычного доступа).
if [[ "$ISSUER_ON" == 1 ]]; then
  LINKARGS+=(--admin-seed "$ADMIN_SEED" --admin-port "$ADMIN_PORT"
             --activate-secs "$ACTIVATE_SECS" --meta-out "$work/link.meta")
fi
# B-2/R4.2: с паролем печатаем не саму ссылку, а парольный конверт вокруг неё. Голый текст
# мастер-ссылки — предъявительский секрет: он остаётся в скролбэке SSH, в логе терминала и в том
# мессенджере, куда его «отправили себе, чтобы открыть на телефоне». Конверт это окно закрывает.
[[ -n "$MASTER_PASSWORD_FILE" ]] && LINKARGS+=(--wrap-password "$MASTER_PASSWORD_FILE")
# $LINKGEN — во временном каталоге (на бокс не кладётся, Q4).
LINK="$("$LINKGEN" "${LINKARGS[@]}" 2>/dev/null)" \
  || die "citadel-linkgen не сгенерировал мастер-ссылку"
LINK_HASH=""; VERIFY_CODE=""
if [[ -r "$work/link.meta" ]]; then
  LINK_HASH="$(sed -n 's/^linkh=//p' "$work/link.meta")"
  VERIFY_CODE="$(sed -n 's/^code=//p' "$work/link.meta")"
  rm -f "$work/link.meta"
fi
if [[ "$ISSUER_ON" == 1 ]]; then
  [[ -n "$LINK_HASH" ]] \
    || die "citadel-linkgen не отдал отпечаток ссылки (--meta-out): без него издатель не сможет заверить активацию"
  [[ "$REGISTER_PUBS" == "$CLIENT_PUB:"* ]] \
    || die "внутренняя ошибка: bootstrap реестра не помечен как одноразовый"
  # Заверяем ссылку в реестре: одноразовая запись + отпечаток именно ЭТОЙ ссылки. Если её подменят
  # по дороге (мессенджер, чужой Wi-Fi), издатель откажет в активации, а не молча пустит чужого.
  # Запись идёт прямо в том издателя (реестр перечитывается на КАЖДЫЙ auth — рестарт не нужен).
  Citadel_TOKEN_DIR="$DIR/keys" "$DIR/bin/citadel-token" registry add \
      "$CLIENT_PUB" "+3650d" --enroll "$ACTIVATE_UNTIL" --linkh "$LINK_HASH" >/dev/null 2>&1 \
    || die "не удалось заверить мастер-ссылку в реестре (citadel-token registry add --enroll)"
  # B-2: гасим Layer-1 запись ПРЕЖНЕГО админа (перевыпуск мастер-доступа). Срок «1» = unix 1970,
  # то есть запись просрочена: издатель откажет в выдаче токенов, и старое устройство теряет и
  # управление, и туннель. При полной ротации ключей реестр и так стёрт — тогда это no-op.
  if [[ -n "${OLD_ADMIN_CID:-}" && "$OLD_ADMIN_CID" != "$CLIENT_PUB" ]]; then
    if Citadel_TOKEN_DIR="$DIR/keys" "$DIR/bin/citadel-token" registry add \
        "$OLD_ADMIN_CID" 1 >/dev/null 2>&1; then
      log "прежний admin-доступ отозван: старая мастер-ссылка больше не даёт ни управления, ни туннеля"
    else
      warn "не удалось погасить прежнюю Layer-1 запись админа ($OLD_ADMIN_CID) — проверь реестр вручную"
    fi
  fi
fi

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
    Ключ эпохи подтягивает сайдкар citadel-keysync (исходящее соединение к издателю).
  • admin-канал ($ADMIN_PORT/tcp) слушает издатель; этой машине его открывать не нужно.
PORTS
else cat <<PORTS
  • $ISSUER_PORT/tcp  — издатель токенов                    → ОТКРЫТЬ (при выключенном издателе не нужен)
  • $ADMIN_PORT/tcp  — admin-канал                        → НЕ открывать: доступен только из туннеля
PORTS
fi)
  Свои значения: ./install-citadel-server.sh --udp-port N --tcp-port N --issuer-port N (см. --help).
$(if [[ "$PORTS_PICKED" == 1 ]]; then cat <<PORTSWARN

⚠ ПОРТЫ ВЫБРАНЫ ЗАНОВО этой установкой (M-8: фиксированные 4433/7000 опознают деплой сканером).
  Открой их в firewall/security-group ПРЯМО СЕЙЧАС — иначе абоненты получат «сервер недоступен»,
  хотя сервер исправен. Прежние, если были открыты, можно закрыть.
PORTSWARN
fi)

⚠ Ссылки печатаются ЗДЕСЬ и НИГДЕ не сохраняются. Скопируй их СЕЙЧАС. Забыл / потерял →
  запусти скрипт снова: он ротирует идентичность и выдаст НОВЫЕ ссылки (прежние, розданные до
  этого, всё равно уже недействительны — obfs/pin/Layer-1 сменились). docker-рестарт/ребут VPS
  ключи НЕ меняет; сохранить прежние при повторном запуске: CITADEL_KEEP_KEYS=1.

МАСТЕР-ссылка (СЕКРЕТ, ТОЛЬКО АДМИНУ — даёт управление реестром абонентов по туннелю):

$LINK
$(if [[ -n "$MASTER_PASSWORD_FILE" ]]; then cat <<WRAPPED

  Это ПАРОЛЬНЫЙ КОНВЕРТ (B-2): блок выше без пароля бесполезен, поэтому его можно переслать
  обычным каналом. Пароль назови АДМИНУ ОТДЕЛЬНО (голосом) — блок и пароль вместе равны голой
  ссылке. Приложение спросит пароль при импорте. Файл пароля на этой машине удали:
  shred -u $MASTER_PASSWORD_FILE
WRAPPED
else cat <<PLAIN

  Ссылка напечатана ГОЛЫМ ТЕКСТОМ и останется в скролбэке этой сессии, в логе терминала и всюду,
  куда её скопируют. Хочешь безопаснее — перезапусти с --master-password ФАЙЛ: тогда вместо
  ссылки печатается парольный конверт (B-2), который бесполезен без пароля.
PLAIN
fi)
$(if [[ "$ISSUER_ON" == 1 ]]; then cat <<ONETIME

⚠ ССЫЛКА ОДНОРАЗОВАЯ. Она активируется на ПЕРВОМ устройстве, которое по ней подключится, и
  привязывается к нему; вторая копия после этого не работает — так утёкшая или пересланная
  ссылка перестаёт давать доступ. Активировать нужно до $(date -d "@$ACTIVATE_UNTIL" '+%F %T %Z' 2>/dev/null || echo "$ACTIVATE_UNTIL (unix)");
  позже она мертва, и потребуется переустановка. Сменить окно: --activate-secs СЕКУНД.
  Код сверки этой ссылки: $VERIFY_CODE
  (приложение спросит его при импорте — так ловится подмена ссылки по дороге).

  Абонентов дальше выдавай ИЗ ПРИЛОЖЕНИЯ: «Абоненты» → выдать. Отдельной клиентской ссылки
  установщик больше не печатает — она была бессрочной и работала с любого числа устройств.
ONETIME
fi)

НЕ раздавать абонентам. Управление: docker compose -f $DIR/etc/compose.yml {ps,logs,down}

ПОТЕРЯНО УСТРОЙСТВО АДМИНА (или мастер-ссылка утекла) — B-2. Переустанавливать сервер НЕ нужно и
абонентов это не касается. Перевыпуск мастер-доступа:

    CITADEL_KEEP_KEYS=1 ./install-citadel-server.sh $VERSION [--master-password ФАЙЛ]

Транспортная идентичность (obfs-PSK, cert-pin, ML-DSA) и реестр абонентов сохраняются — уже
розданные абонентские ссылки продолжают работать. Admin-доступ выпускается заново: печатается
НОВАЯ мастер-ссылка, а прежняя перестаёт и управлять, и пускать в туннель (её Layer-1 запись
гасится этим же запуском). Утерянное устройство после этого не может ничего.

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

Двухслойная идентичность включена:
  • Издатель (Layer-1 реестр + epoch-токены) слушает $SERVER_HOST:$ISSUER_PORT/tcp —
    ОТКРОЙ этот порт в firewall/облачной security-group, иначе клиент не получит токен.
  • Управление абонентами — ИЗ ПРИЛОЖЕНИЯ по мастер-ссылке (C7): подключись мастер-ссылкой,
    меню «Абоненты» → добавить/отозвать. Канал идёт по туннелю → PQ-TLS(pin) → admin-подпись;
    порт :$ADMIN_PORT НАРУЖУ НЕ ОТКРЫТ (в firewall его открывать НЕ нужно — доступ только из туннеля).
  • На сервере НЕТ управляющих операций — ни выдачи, ни отзыва, ни списка абонентов.
    \`registry revoke\` и \`registry list\` убраны из серверного CLI (тот же принцип, что и
    отсутствие linkgen: боксу не выдаётся инструмент управления). Отзыв действует ≤ длины
    эпохи (${EPOCH_SECS}s) и переживает рестарт контейнера; массовый отзыв — сменить эпоху.
    Всё управление — ТОЛЬКО из приложения по мастер-ссылке (admin-канал по туннелю, C7)
    либо \`citadel-token admin <list|add|revoke>\` с машины, где эта ссылка есть.
    На сервере после установки нет ни linkgen, ни seed'ов, ни admin-ключа → «нарисовать»
    рабочую ссылку и отозвать абонента на боксе нечем (Q4). Потеря мастер-ссылки, ротация
    admin-доступа, self-lockout (R6) → ПЕРЕВЫПУСК: \`CITADEL_KEEP_KEYS=1\` + этот скрипт
    (B-2, см. блок «ПОТЕРЯНО УСТРОЙСТВО АДМИНА» выше) — абонентская база и уже розданные
    ссылки при этом ЖИВЫ; мёртвой становится только прежняя мастер-ссылка. Полный реинсталл
    (без KEEP_KEYS) остаётся ответом на компрометацию самого сервера: он меняет ВСЮ
    идентичность, и тогда нерабочими становятся все ссылки без исключения.
    ⚠ Это снимает ИНСТРУМЕНТ, а не полномочия: root на этой машине правит файл реестра
    напрямую и видит его содержимое. Мера рассчитана на то, что у сервера не остаётся
    штатного пути управления — компрометация сервера не даёт готовой кнопки.
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
