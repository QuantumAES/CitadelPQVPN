#!/usr/bin/env bash
# client-узел: адрес получает динамически капсулой (M2), сервер пиннит (F1).
# После подъёма — ping/curl через туннель + проверка egress-фильтра (F2).
set -e
# L-10: демо-стенд (см. entrypoint-issuer.sh) — разрешает демо-seed'ы клиента.
export Citadel_DEMO_STAND=1
export Citadel_ROLE=client
export Citadel_SERVERS="exit:4433 exit2:4433"   # M5 multi-server: клиент выбирает (shuffle+failover)
export Citadel_CONNECT=exit:4433                # single-target для probe/auth-probe (ТЕСТ 4/8)
export Citadel_SERVER_NAME=Citadel.exit
export Citadel_TUN=Citadel0
export Citadel_MTU=1161   # = citadel_quic::INNER_MTU: ровно то, что влезает в одну QUIC-датаграмму (выше — тихий дроп, ниже — дроп крупных UDP от клиента)
export Citadel_ROUTES="1.1.1.1/32 1.0.0.1/32 10.99.0.1/32"
export Citadel_PIN_DIR=/shared                  # M5: pin per-host — /shared/<host>.pin
export Citadel_OBFS_PSK=$(cat /shared/obfs.psk)   # общий PSK от издателя (генерируется, не хардкод)
export Citadel_DNS=1.1.1.1
export Citadel_TOKENS=/shared/tokens   # анонимный токен для предъявления exit (M4/M5)
# H-3: ключ L1 ТЕКУЩЕЙ эпохи для канала данных. Его отдаёт издатель вместе с токеном (после
# Layer-1) — `citadel-token` кладёт файлом, `citadel-m1` читает. Бутстрапный Citadel_OBFS_PSK
# остаётся только для канала к издателю: сам туннель он больше не открывает.
export Citadel_OBFS_EPOCH_FILE=/shared/obfs.epoch
# obfs-over-TCP fallback (M4): порт derive из host выбранного exit (Citadel_TCP_PORT, по умолчанию 443)

# резолвим IP exit ДО того, как citadel-m1 заблокирует DNS (F6) — нужен для auth-probe позже
EXIT_IP=$(getent hosts exit 2>/dev/null | awk '{print $1; exit}')
EXIT_IP=${EXIT_IP:-exit}
echo "[client] exit резолвится в $EXIT_IP"
# IP второго exit'а — для ТЕСТА 26 (B-1: токен одного узла не проходит на другом), там DNS уже закрыт
EXIT2_IP=$(getent hosts exit2 2>/dev/null | awk '{print $1; exit}')
EXIT2_IP=${EXIT2_IP:-exit2}
echo "[client] exit2 резолвится в $EXIT2_IP"
# IP issuer — для ТЕСТ 20 (фетч токенов новым абонентом ПОСЛЕ DNS-lock: hostname уже не резолвится)
ISSUER_IP=$(getent hosts issuer 2>/dev/null | awk '{print $1; exit}')
ISSUER_IP=${ISSUER_IP:-issuer}
echo "[client] issuer резолвится в $ISSUER_IP"

# S2.1/A1: pin TLS-серта издателя для PQ-TLS канала фетча токенов (издатель пишет его в /shared).
for _ in $(seq 1 30); do [ -s /shared/issuer-tls.pin ] && [ -s /shared/issuer-mldsa.pin ] && break; sleep 1; done
ISSUER_PIN=$(cat /shared/issuer-tls.pin 2>/dev/null || echo "")
# PQ: обязательство к ML-DSA-идентичности издателя (клиент требует его и для токенов, и для admin)
ISSUER_MLDSA=$(cat /shared/issuer-mldsa.pin 2>/dev/null || echo "")
[ -n "$ISSUER_MLDSA" ] || echo "[client] WARN: нет issuer-mldsa.pin — PQ-аутентификация издателя не пройдёт"
[ -n "$ISSUER_PIN" ] && echo "[client] issuer TLS-pin: ${ISSUER_PIN:0:16}… (PQ-TLS+pin канал, A1)" \
    || echo "[client] WARN: нет issuer-tls.pin — фетч токенов не пройдёт (A1 fail-closed)"

# M5 split: получить анонимные токены ИНТЕРАКТИВНО от издателя (blind issuance) — ДО блокировки DNS.
# Издатель подписывает вслепую, токен в файл; издатель не видит токен → unlinkable от сессии на exit.
# S2.1/A1: канал к издателю — PQ-TLS с пиннингом (Citadel_ISSUER_PIN).
echo "[client] получаю токены от издателя (M5 issuer↔exit split, PQ-TLS+pin)…"
Citadel_TOKEN_ROLE=client Citadel_TOKEN_ISSUER=issuer:7000 Citadel_ISSUER_PIN=$ISSUER_PIN Citadel_ISSUER_MLDSA=$ISSUER_MLDSA Citadel_TOKEN_DIR=/shared Citadel_TOKEN_COUNT=10 \
    Citadel_CLIENT_SEED=$(printf 'c5%.0s' {1..32}) \
    citadel-token || echo "[client] WARN: не удалось получить токены от издателя"

# ── Layer-1 auth-тесты (C5.2): ДО туннеля — issuer доступен по hostname (нет DNS-lock/full-tunnel).
#    Проверяют аутентификацию «абонента» у issuer; сам туннель им не нужен. ──
echo
echo "===================================================================="
echo "  ТЕСТ 17 (C5.2 Layer-1) — НЕзарегистрированный абонент не получает токены (M5)"
echo "===================================================================="
rm -rf /tmp/t17; mkdir -p /tmp/t17
Citadel_TOKEN_ROLE=client Citadel_TOKEN_ISSUER=issuer:7000 Citadel_ISSUER_PIN=$ISSUER_PIN Citadel_ISSUER_MLDSA=$ISSUER_MLDSA Citadel_TOKEN_DIR=/tmp/t17 Citadel_TOKEN_COUNT=1 \
    Citadel_CLIENT_SEED=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef \
    timeout 15 citadel-token >/tmp/t17/out 2>&1 || true
if [ ! -s /tmp/t17/tokens ]; then
    echo "  OK ✔ незарегистрированный seed отклонён issuer'ом — токены не выданы (Layer-1 auth ✔)"
else
    echo "  [!] незарегистрированный клиент ПОЛУЧИЛ токены ✗"
fi

echo
echo "===================================================================="
echo "  ТЕСТ 18 (C5.2 Layer-1) — ОТЗЫВ абонента (status=revoked) → отказ в выдаче (M5)"
echo "===================================================================="
SEED_C=$(printf 'ab%.0s' {1..32})
PUB_C=$(Citadel_CLIENT_SEED=$SEED_C citadel-token pubkey 2>/dev/null)
echo "$PUB_C 99999999999 active" >> /shared/registry   # добавить активного абонента в реестр
rm -rf /tmp/t18; mkdir -p /tmp/t18
Citadel_TOKEN_ROLE=client Citadel_TOKEN_ISSUER=issuer:7000 Citadel_ISSUER_PIN=$ISSUER_PIN Citadel_ISSUER_MLDSA=$ISSUER_MLDSA Citadel_TOKEN_DIR=/tmp/t18 Citadel_TOKEN_COUNT=1 \
    Citadel_CLIENT_SEED=$SEED_C timeout 15 citadel-token >/tmp/t18/o1 2>&1 || true
GOT1=$([ -s /tmp/t18/tokens ] && echo yes || echo no)
sed -i "s#^$PUB_C .*#$PUB_C 99999999999 revoked#" /shared/registry   # ОТЗЫВ (issuer перечитывает реестр)
rm -f /tmp/t18/tokens
Citadel_TOKEN_ROLE=client Citadel_TOKEN_ISSUER=issuer:7000 Citadel_ISSUER_PIN=$ISSUER_PIN Citadel_ISSUER_MLDSA=$ISSUER_MLDSA Citadel_TOKEN_DIR=/tmp/t18 Citadel_TOKEN_COUNT=1 \
    Citadel_CLIENT_SEED=$SEED_C timeout 15 citadel-token >/tmp/t18/o2 2>&1 || true
GOT2=$([ -s /tmp/t18/tokens ] && echo yes || echo no)
if [ "$GOT1" = yes ] && [ "$GOT2" = no ]; then
    echo "  OK ✔ активный получил токены; после revoke — отказ (отзыв действует ≤ длины эпохи, M5)"
else
    echo "  [!] revoke: до=$GOT1 после=$GOT2 (ожидалось yes/no) ✗"
fi

rm -f /tmp/Citadel-ready
echo "[client] старт citadel-m1 (client)…"
citadel-m1 &
M1=$!

for _ in $(seq 1 80); do
    [ -f /tmp/Citadel-ready ] && break
    kill -0 "$M1" 2>/dev/null || { echo "[client] citadel-m1 завершился преждевременно"; exit 1; }
    sleep 0.5
done
[ -f /tmp/Citadel-ready ] || { echo "[client] туннель не поднялся вовремя"; exit 1; }
sleep 1

echo
echo "===================================================================="
echo "  ТЕСТ 1 — ping 1.1.1.1 ЧЕРЕЗ постквантовый туннель"
echo "===================================================================="
ping -c 3 -W 3 1.1.1.1 || echo "  [!] ping не прошёл"

echo
echo "===================================================================="
echo "  ТЕСТ 2 — HTTP GET http://1.1.1.1 ЧЕРЕЗ постквантовый туннель"
echo "===================================================================="
curl -sS --max-time 15 http://1.1.1.1 -o /dev/null \
    -w "  ответ из интернета через туннель: HTTP %{http_code}, %{size_download} байт за %{time_total}s\n" \
    || echo "  [!] curl не прошёл"

echo
echo "===================================================================="
echo "  ТЕСТ 3 (STRIDE F2) — приватный 10.99.0.1 через туннель"
echo "  ожидаем: exit ДРОПАЕТ (анти-пивот во внутреннюю сеть)"
echo "===================================================================="
if ping -c 2 -W 2 10.99.0.1 >/dev/null 2>&1; then
    echo "  [!] НЕОЖИДАННО: 10.99.0.1 ответил — egress-фильтр не сработал"
else
    echo "  OK ✔ ответа нет — exit дропнул пакет (см. лог exit: 'F2: заблокирован…')"
fi

echo
echo "===================================================================="
echo "  ТЕСТ 4 (M3 / STRIDE F3) — obfs L1: проба БЕЗ PSK"
echo "  ожидаем: exit молчит на не-obfs трафик (probe-resistance, анти-DPI)"
echo "===================================================================="
# по IP (как ТЕСТ 8): hostname не резолвится — основной туннель уже включил F6 DNS fail-closed
Citadel_ROLE=probe Citadel_CONNECT="${EXIT_IP}:4433" citadel-m1 || true

echo
echo "===================================================================="
echo "  ТЕСТ 5 (STRIDE F4) — citadel-m1 после настройки работает БЕЗ root"
echo "===================================================================="
if [ -r "/proc/$M1/status" ]; then
    grep -E '^(Uid|Gid):' "/proc/$M1/status" | sed 's/^/  /'
    euid=$(awk '/^Uid:/{print $3}' "/proc/$M1/status")
    if [ "$euid" = "0" ]; then echo "  [!] процесс всё ещё root"; else echo "  OK ✔ effective uid=$euid (привилегии сброшены)"; fi
else
    echo "  (нет доступа к /proc/$M1)"
fi

echo
echo "===================================================================="
echo "  ТЕСТ 6 (STRIDE F6) — DNS: резолюция через туннель + защита от утечки"
echo "===================================================================="
ans=$(dig +short +time=3 +tries=1 @1.1.1.1 example.com A 2>/dev/null | grep -E '^[0-9]' | head -1)
[ -n "$ans" ] && echo "  через туннель (dig @1.1.1.1): OK ✔ example.com → $ans" || echo "  [!] резолюция через туннель не удалась"
if dig +time=2 +tries=1 @8.8.8.8 example.com >/dev/null 2>&1; then
    echo "  мимо туннеля  (dig @8.8.8.8): [!] LEAK — ответ получен"
else
    echo "  мимо туннеля  (dig @8.8.8.8): OK ✔ заблокирован (fail-closed, no-leak)"
fi

echo
echo "===================================================================="
echo "  ТЕСТ 7 (F6) — DoH (DNS-over-HTTPS) через туннель"
echo "  (exit видит только TLS к cloudflare-dns.com, не содержимое запроса)"
echo "===================================================================="
doh=$(curl -s --max-time 12 --resolve cloudflare-dns.com:443:1.1.1.1 \
    'https://cloudflare-dns.com/dns-query?name=example.com&type=A' \
    -H 'accept: application/dns-json' 2>/dev/null)
if echo "$doh" | grep -q '"data"'; then
    ip=$(echo "$doh" | grep -oE '"data":"[0-9.]+"' | head -1)
    echo "  OK ✔ DoH-ответ через туннель: $ip"
else
    echo "  [!] DoH не удался"
fi

echo
echo "===================================================================="
echo "  ТЕСТ 8 (M4) — per-user токен: ПОДДЕЛЬНЫЙ токен должен быть отклонён"
echo "  (транспорт валиден: obfs+PQ+pin, но токен фальшивый)"
echo "===================================================================="
Citadel_ROLE=auth-probe Citadel_CONNECT="${EXIT_IP}:4433" citadel-m1 || true

echo
echo "===================================================================="
echo "  ТЕСТ 9 (STRIDE D3 / F7) — rate-limit на exit: флуд от клиента режется"
echo "  exit лимитирует входящее ~128 KiB/с (burst 256 KiB); шлём preload-всплеск ~2.8 МБ"
echo "  ожидаем: высокие потери — exit пропускает burst, остальное дропает (анти-абуз)"
echo "===================================================================="
# -l 2000: preload — пакеты уходят back-to-back (всплеск), а не по RTT, иначе лимит не превысить.
loss=$(ping -f -l 2000 -c 2000 -s 1400 -W 1 1.1.1.1 2>&1 | grep -oE '[0-9.]+% packet loss' | head -1 || true)
echo "  preload-флуд 2000×1400 б через туннель: ${loss:-(нет статистики)}"
echo "  → высокие потери = exit дропнул превышение (см. лог exit: '[exit] F7: rate-limit …')"

echo
echo "===================================================================="
echo "  ТЕСТ 10 (M4) — миграция соединения: rebind исходящего сокета на лету"
echo "  клиент через 6с меняет UDP-сокет (эмуляция WiFi↔LTE/NAT-rebind) — туннель должен пережить"
echo "===================================================================="
kill "$M1" 2>/dev/null || true
wait "$M1" 2>/dev/null || true   # дождаться смерти → закрыть сессию клиента на exit
sleep 1
sed -i '1d' /shared/tokens 2>/dev/null || true   # свежий токен (прошлый spent)
rm -f /tmp/Citadel-ready
# по IP (DNS fail-closed); MIGRATE_AFTER_MS=6000 → клиент сделает rebind через 6с
Citadel_SERVERS="${EXIT_IP}:4433" Citadel_PIN="$(cat /shared/exit.pin)" Citadel_MIGRATE_AFTER_MS=6000 citadel-m1 &
M1B=$!
for _ in $(seq 1 40); do [ -f /tmp/Citadel-ready ] && break; kill -0 "$M1B" 2>/dev/null || break; sleep 0.5; done
if [ -f /tmp/Citadel-ready ]; then
    ping -c 2 -W 3 1.1.1.1 >/dev/null 2>&1 && echo "  до миграции: туннель работает ✔"
    echo "  жду rebind сокета (через 6с после старта)…"
    sleep 7
    if ping -c 3 -W 3 1.1.1.1 >/dev/null 2>&1; then
        echo "  OK ✔ после rebind сокета туннель ЖИВ (QUIC migration; см. лог client '[obfs] rebind')"
    else
        echo "  [!] туннель не пережил миграцию"
    fi
else
    echo "  [!] клиент (миграция) не поднялся"
fi

echo
echo "===================================================================="
echo "  ТЕСТ 11 (M4) — TCP/443-fallback при блокировке UDP"
echo "  блокируем исходящий UDP к exit:4433 → клиент должен уйти в obfs-over-TCP"
echo "===================================================================="
kill "$M1B" 2>/dev/null || true
wait "$M1B" 2>/dev/null || true   # дождаться смерти → закрыть сессию клиента на exit
sleep 1
iptables -A OUTPUT -p udp --dport 4433 -j DROP   # эмуляция UDP-цензуры (QUIC/UDP недоступен)
rm -f /tmp/Citadel-ready
sed -i '1d' /shared/tokens 2>/dev/null || true   # свежий токен
echo "  UDP к exit:4433 заблокирован; перезапускаю клиент (уйдёт в TCP после таймаута QUIC)…"
Citadel_SERVERS="${EXIT_IP}:4433" Citadel_PIN="$(cat /shared/exit.pin)" citadel-m1 &
M1C=$!
for _ in $(seq 1 70); do
    [ -f /tmp/Citadel-ready ] && break
    kill -0 "$M1C" 2>/dev/null || break
    sleep 0.5
done
if [ -f /tmp/Citadel-ready ]; then
    sleep 2
    ok=0
    for _ in $(seq 1 10); do
        ping -c 2 -W 3 1.1.1.1 >/dev/null 2>&1 && { ok=1; break; }
        sleep 1
    done
    [ "$ok" = 1 ] && echo "  OK ✔ туннель поднялся через TCP/443-fallback и работает (UDP заблокирован)" \
                  || echo "  [~] fallback поднялся, но ping не прошёл"
else
    echo "  [!] TCP-fallback не поднялся вовремя"
fi

# восстановить UDP к exit:4433 — иначе DROP из ТЕСТ 11 протекает в T12/T14 и форсит
# obfs-TCP вместо тестируемого QUIC-пути (давало ложные ~флаки failover/agility)
iptables -D OUTPUT -p udp --dport 4433 -j DROP 2>/dev/null || true

echo
echo "===================================================================="
echo "  ТЕСТ 12 (M5) — multi-server failover: первый exit мёртв → берётся следующий"
echo "  список: нероутируемый адрес + живой exit; клиент должен пропустить мёртвый"
echo "===================================================================="
kill "$M1C" 2>/dev/null || true
wait "$M1C" 2>/dev/null || true   # дождаться смерти → закрыть сессию клиента на exit (иначе её pump крадёт ответные пакеты)
sleep 1
sed -i '1d' /shared/tokens 2>/dev/null || true   # свежий токен
rm -f /tmp/Citadel-ready
Citadel_SERVERS="10.255.255.1:4433 ${EXIT_IP}:4433" Citadel_PIN="$(cat /shared/exit.pin)" citadel-m1 &
M1D=$!
for _ in $(seq 1 60); do [ -f /tmp/Citadel-ready ] && break; kill -0 "$M1D" 2>/dev/null || break; sleep 0.5; done
if [ -f /tmp/Citadel-ready ]; then
    # стартовые пинги «дренируют» застрявшие TUN-читатели мёртвых сессий на exit
    # (shared exit-TUN: поток убитого клиента крадёт 1–2 ответных пакета) → щедрый retry
    sleep 2
    ok=0; for _ in $(seq 1 10); do ping -c 2 -W 3 1.1.1.1 >/dev/null 2>&1 && { ok=1; break; }; sleep 1; done
    [ "$ok" = 1 ] \
        && echo "  OK ✔ failover: клиент пропустил мёртвый exit и подключился к живому (см. лог 'ВЫБРАН exit')" \
        || echo "  [~] failover поднялся, ping не прошёл"
else
    echo "  [!] failover не сработал вовремя"
fi

echo
echo "===================================================================="
echo "  ТЕСТ 13 (M5) — issuer↔exit split: анонимные токены слепым issuance"
echo "===================================================================="
echo "  токены получены ИНТЕРАКТИВНО от издателя при старте (см. начало лога client)"
echo "  издатель подписал ВСЛЕПУЮ (видел blind_msg, НЕ токен) — см. лог issuer 'подписано вслепую'"
echo "  → unlinkability: издатель не может связать выданное с сессией клиента на exit"

echo
echo "===================================================================="
echo "  ТЕСТ 14 (M6) — crypto-agility: смена KX-suite (classical) negotiate с PQ-capable exit"
echo "  exit принимает 'all' (PQ+classical); клиент просит classical → negotiate без смены сервера"
echo "===================================================================="
kill "$M1D" 2>/dev/null || true
wait "$M1D" 2>/dev/null || true   # дождаться смерти → закрыть сессию клиента на exit
sleep 1
sed -i '1d' /shared/tokens 2>/dev/null || true   # свежий токен
rm -f /tmp/Citadel-ready
# M-2 (аудит-4): не-PQ suite теперь fail-closed в клиенте — этот тест намеренно проверяет
# negotiate-ветку, поэтому явно поднимает dev-флаг. Из ссылки/бандла его выставить нельзя.
Citadel_SERVERS="${EXIT_IP}:4433" Citadel_PIN="$(cat /shared/exit.pin)" Citadel_KX=classical \
  Citadel_INSECURE_CLASSICAL_KX=1 citadel-m1 &
M1E=$!
for _ in $(seq 1 50); do [ -f /tmp/Citadel-ready ] && break; kill -0 "$M1E" 2>/dev/null || break; sleep 0.5; done
if [ -f /tmp/Citadel-ready ]; then
    sleep 2
    ok=0; for _ in $(seq 1 10); do ping -c 2 -W 3 1.1.1.1 >/dev/null 2>&1 && { ok=1; break; }; sleep 1; done
    [ "$ok" = 1 ] \
        && echo "  OK ✔ туннель на classical KX (X25519) к PQ-capable exit — agility/negotiate (см. лог 'KX=')" \
        || echo "  [~] поднялся, ping не прошёл"
else
    echo "  [!] classical KX не поднялся"
fi

echo
echo "===================================================================="
echo "  ТЕСТ 15 (M7) — PQ-auth: гибрид Ed25519 + ML-DSA-65 (квантово-стойкая подпись сервера)"
echo "  основной клиент проверил ML-DSA подпись exit (см. лог 'PQ-auth ✔'); ниже — НЕГАТИВ:"
echo "  коннект к exit с ЧУЖИМ ML-DSA pk (от exit2) → подпись не сойдётся → клиент отвергает"
echo "===================================================================="
sed -i '1d' /shared/tokens 2>/dev/null || true   # свежий токен
# отдельный TUN (Citadel1), чтобы не конфликтовать с работающим туннелем
out=$(Citadel_TUN=Citadel1 Citadel_SERVERS="${EXIT_IP}:4433" Citadel_PIN="$(cat /shared/exit.pin)" \
      Citadel_MLDSA_PUB=/shared/exit2.mldsa timeout 25 citadel-m1 2>&1 || true)
if echo "$out" | grep -q "ML-DSA подпись сервера НЕ прошла"; then
    echo "  OK ✔ PQ-auth отверг сервер с неверной ML-DSA-65 подписью (анти-MITM, квантово-стойко)"
else
    echo "  [!] PQ-auth негатив не сработал"
fi

echo
echo "===================================================================="
echo "  ТЕСТ 16 (S0.1/H2) — БЕЗ серт-pin клиент ОТКАЗЫВАЕТ (fail-closed, не MITM-режим)"
echo "  (раньше AcceptAnyServerCert молча принимал любой серт → MITM; теперь — жёсткий отказ)"
echo "===================================================================="
# env -u снимает Citadel_PIN* (PIN_DIR экспортирован глобально) → PinSource::None → NoPin → отказ
out=$(env -u Citadel_PIN_DIR -u Citadel_PIN -u Citadel_PIN_FILE \
      Citadel_TUN=Citadel2 Citadel_SERVERS="${EXIT_IP}:4433" timeout 15 citadel-m1 2>&1 || true)
if echo "$out" | grep -qi "fail-closed"; then
    echo "  OK ✔ без pin клиент отказал (fail-closed), а не принял любой серт"
else
    echo "  [!] без pin клиент НЕ отказал (fail-open?) ✗"
fi

echo
echo "===================================================================="
echo "  ТЕСТ 19 (§S3) — commitment-fetch: ссылка несёт лишь H(pub); клиент дотягивает pub с exit"
echo "  ПОЗИТИВ: верный commit → принимает; НЕГАТИВ: чужой commit → отвергает (анти-MITM через ссылку)"
echo "===================================================================="
# ПОЗИТИВ: commit = H(pub) НАСТОЯЩЕГО exit. ROUTES пусты + kill сразу по логу establish → второй
# (проверочный) туннель не конфликтует с рабочим M1E; нужен лишь лог проверки подписи.
sed -i '1d' /shared/tokens 2>/dev/null || true   # свежий токен (позитив)
CF_OK=$(sha256sum /shared/exit.mldsa | cut -d' ' -f1)
Citadel_TUN=Citadel1 Citadel_ROUTES="" Citadel_SERVERS="${EXIT_IP}:4433" \
    Citadel_PIN="$(cat /shared/exit.pin)" Citadel_MLDSA_COMMIT="$CF_OK" citadel-m1 >/tmp/t19p 2>&1 &
T19=$!
for _ in $(seq 1 40); do grep -q 'commitment-fetch' /tmp/t19p 2>/dev/null && break; kill -0 "$T19" 2>/dev/null || break; sleep 0.5; done
kill "$T19" 2>/dev/null || true; wait "$T19" 2>/dev/null || true
if grep -q 'commitment-fetch: H(pub)==commit' /tmp/t19p; then
    echo "  OK ✔ ПОЗИТИВ: клиент дотянул pub с exit, H(pub)==commit из ссылки → PQ-auth ✔"
else
    echo "  [!] ПОЗИТИВ commitment-fetch не сработал"
fi
# НЕГАТИВ: commit = H(pub) ЧУЖОГО exit2 ≠ pub, который пришлёт exit → отказ (анти-MITM).
sed -i '1d' /shared/tokens 2>/dev/null || true   # свежий токен (негатив)
CF_BAD=$(sha256sum /shared/exit2.mldsa | cut -d' ' -f1)
out=$(Citadel_TUN=Citadel1 Citadel_ROUTES="" Citadel_SERVERS="${EXIT_IP}:4433" \
      Citadel_PIN="$(cat /shared/exit.pin)" Citadel_MLDSA_COMMIT="$CF_BAD" timeout 25 citadel-m1 2>&1 || true)
if echo "$out" | grep -q "не соответствует обязательству"; then
    echo "  OK ✔ НЕГАТИВ: H(pub) exit ≠ commit из ссылки → клиент отверг (анти-MITM через ссылку)"
else
    echo "  [!] НЕГАТИВ commitment-fetch не сработал"
fi

echo
echo "===================================================================="
echo "  ТЕСТ 20 (C7) — admin-плоскость ПО ТУННЕЛЮ: add → новый абонент получает токены; revoke → отказ"
echo "  канал: TCP 10.7.0.1:7001 из-под туннеля → exit DNAT → issuer (PQ-TLS+pin, Ed25519 домен+EKM)"
echo "===================================================================="
ADMIN_SEED=$(printf 'ad%.0s' {1..32})
export Citadel_ADMIN_ADDR=10.7.0.1:7001
# 20a: list по каналу — демо-абонент (c5) виден в реестре
DEMO_PUB=$(Citadel_CLIENT_SEED=$(printf 'c5%.0s' {1..32}) citadel-token pubkey)
if Citadel_ISSUER_PIN=$ISSUER_PIN Citadel_ISSUER_MLDSA=$ISSUER_MLDSA Citadel_ADMIN_SEED=$ADMIN_SEED timeout 20 citadel-token admin list 2>/dev/null | grep -q "^$DEMO_PUB .* active"; then
    echo "  OK ✔ list по туннелю: реестр читается, демо-абонент active"
else
    echo "  [!] list по admin-каналу не прошёл ✗"
fi
# 20b: add НОВОГО абонента по каналу (только pub — seed остаётся «у абонента») → Layer-1 пускает:
# новый seed получает epoch-токены у issuer = пропуск на exit (токены универсальны per-epoch)
NEW_SEED=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
NEW_PUB=$(Citadel_CLIENT_SEED=$NEW_SEED citadel-token pubkey)
Citadel_ISSUER_PIN=$ISSUER_PIN Citadel_ISSUER_MLDSA=$ISSUER_MLDSA Citadel_ADMIN_SEED=$ADMIN_SEED timeout 20 citadel-token admin add "$NEW_PUB" 2>/dev/null \
    && echo "  add ${NEW_PUB:0:12}… по каналу: OK" || echo "  [!] add по каналу не прошёл ✗"
rm -rf /tmp/t20; mkdir -p /tmp/t20
Citadel_TOKEN_ROLE=client Citadel_TOKEN_ISSUER=$ISSUER_IP:7000 Citadel_ISSUER_PIN=$ISSUER_PIN Citadel_ISSUER_MLDSA=$ISSUER_MLDSA Citadel_TOKEN_DIR=/tmp/t20 Citadel_TOKEN_COUNT=1 \
    Citadel_CLIENT_SEED=$NEW_SEED timeout 15 citadel-token >/tmp/t20/o1 2>&1 || true
if [ -s /tmp/t20/tokens ]; then
    echo "  OK ✔ добавленный по туннелю абонент получил epoch-токен (допущен к exit)"
else
    echo "  [!] новый абонент НЕ получил токены после add ✗"
fi
# 20c: revoke по каналу → отказ в выдаче (действует ≤ длины эпохи)
Citadel_ISSUER_PIN=$ISSUER_PIN Citadel_ISSUER_MLDSA=$ISSUER_MLDSA Citadel_ADMIN_SEED=$ADMIN_SEED timeout 20 citadel-token admin revoke "$NEW_PUB" 2>/dev/null || true
rm -f /tmp/t20/tokens
Citadel_TOKEN_ROLE=client Citadel_TOKEN_ISSUER=$ISSUER_IP:7000 Citadel_ISSUER_PIN=$ISSUER_PIN Citadel_ISSUER_MLDSA=$ISSUER_MLDSA Citadel_TOKEN_DIR=/tmp/t20 Citadel_TOKEN_COUNT=1 \
    Citadel_CLIENT_SEED=$NEW_SEED timeout 15 citadel-token >/tmp/t20/o2 2>&1 || true
if [ ! -s /tmp/t20/tokens ]; then
    echo "  OK ✔ после revoke по туннелю — отказ в токенах (отзыв ≤ длины эпохи)"
else
    echo "  [!] отозванный абонент ПОЛУЧИЛ токены ✗"
fi

echo
echo "===================================================================="
echo "  ТЕСТ 21 (C7 негатив) — чужой ключ в admin-кадре → отказ; self-revoke админа → отказ (R6)"
echo "===================================================================="
# клиентский Layer-1 seed (c5 — валидный АБОНЕНТ) в роли admin-ключа: домен-разделение auth —
# подписка не даёт админских прав; issuer рвёт канал без ack (не оракул)
if Citadel_ISSUER_PIN=$ISSUER_PIN Citadel_ISSUER_MLDSA=$ISSUER_MLDSA Citadel_ADMIN_SEED=$(printf 'c5%.0s' {1..32}) timeout 20 citadel-token admin list >/dev/null 2>&1; then
    echo "  [!] КЛИЕНТСКИЙ ключ прошёл в admin-канал ✗"
else
    echo "  OK ✔ клиентский (не-admin) ключ отвергнут admin-каналом"
fi
# R6: отзыв Layer-1 client_id САМОГО админа настоящим админом → сервер отклоняет (анти-self-lockout)
if Citadel_ISSUER_PIN=$ISSUER_PIN Citadel_ISSUER_MLDSA=$ISSUER_MLDSA Citadel_ADMIN_SEED=$ADMIN_SEED timeout 20 citadel-token admin revoke "$DEMO_PUB" >/dev/null 2>&1; then
    echo "  [!] self-revoke client_id админа ПРОШЁЛ ✗"
else
    echo "  OK ✔ self-revoke отклонён сервером (R6 — админ не может запереть сам себя)"
fi

echo
echo "===================================================================="
echo "  ТЕСТ 22 (C7.2) — admin-порт СНАРУЖИ туннеля ЗАКРЫТ (DNAT только -i Citadel0)"
echo "===================================================================="
# прямой TCP к внешнему интерфейсу exit (docker-bridge, мимо туннеля): m1 на :7001 не слушает,
# DNAT-правило матчит только пакеты ИЗ туннельного интерфейса → извне порт закрыт.
# (доступность того же порта ИЗ туннеля доказана операциями ТЕСТ 20)
if timeout 3 bash -c "echo > /dev/tcp/$EXIT_IP/7001" 2>/dev/null; then
    echo "  [!] admin-порт exit ОТКРЫТ снаружи туннеля ✗"
else
    echo "  OK ✔ TCP $EXIT_IP:7001 снаружи туннеля недоступен (публичная поверхность не выросла)"
fi

echo
echo "===================================================================="
echo "  ТЕСТ 23 (P1) — раздельный деплой: exit-узел получает ключ эпохи ПО СЕТИ (keysync)"
echo "===================================================================="
# Когда издатель стоит на другой машине, общего тома нет, а ключ эпохи ротируется каждый час —
# exit подтягивает его сам, по тому же obfs+PQ-TLS каналу с проверкой PQ-идентичности издателя.
# M-6: ключ эпохи стал СЕКРЕТОМ, поэтому exit ещё и доказывает СВОЮ keysync-идентичность.
# Здесь это гоняется «как на отдельной машине»: свой пустой каталог, только сетевой путь.
# B-1: узел просит СВОЙ ключ эпохи (k_exit = KDF(мастер, эпоха, pin)), поэтому называет свой pin.
KEYSYNC_SEED=$(printf 'ec%.0s' {1..32})   # тот же демо-seed, что знает issuer-entrypoint ('ec'×32 — обязан быть валидным hex)
SYNCDIR=/tmp/keysync; rm -rf "$SYNCDIR"; mkdir -p "$SYNCDIR"
Citadel_TOKEN_ROLE=keysync Citadel_TOKEN_DIR="$SYNCDIR" Citadel_TOKEN_ISSUER="$ISSUER_IP:7000" \
  Citadel_ISSUER_PIN=$ISSUER_PIN Citadel_ISSUER_MLDSA=$ISSUER_MLDSA Citadel_OBFS_PSK=$(cat /shared/obfs.psk) \
  Citadel_KEYSYNC_SEED=$KEYSYNC_SEED Citadel_EXIT_PIN_FILE=/shared/exit.pin \
  Citadel_EPOCH_SECS=3600 Citadel_KEYSYNC_INTERVAL=5 timeout 20 citadel-token >/tmp/keysync.log 2>&1 || true
# Ключ узла кладётся как exit-<эпоха>.key. Мастер эпохи (issuer.key) на exit-машину НЕ уезжает —
# в этом весь смысл B-1, поэтому проверяем и то, и другое.
if ls "$SYNCDIR"/exit-*.key >/dev/null 2>&1 && ! [ -f "$SYNCDIR/issuer.key" ]; then
    echo "  OK ✔ ключ ЭТОГО узла получен по сети (мастер эпохи остался у издателя — B-1)"
else
    echo "  [!] keysync не принёс ключ узла (или принёс мастер) ✗"; tail -3 /tmp/keysync.log
fi
# Негатив 1: чужое обязательство PQ-идентичности издателя → синхронизация обязана отказать,
# иначе подставной издатель навязал бы exit'у свой ключ и тот верил бы чужим токенам.
rm -rf "$SYNCDIR"; mkdir -p "$SYNCDIR"
Citadel_TOKEN_ROLE=keysync Citadel_TOKEN_DIR="$SYNCDIR" Citadel_TOKEN_ISSUER="$ISSUER_IP:7000" \
  Citadel_ISSUER_PIN=$ISSUER_PIN Citadel_ISSUER_MLDSA=$(printf 'ab%.0s' {1..32}) \
  Citadel_KEYSYNC_SEED=$KEYSYNC_SEED Citadel_EXIT_PIN_FILE=/shared/exit.pin \
  Citadel_OBFS_PSK=$(cat /shared/obfs.psk) Citadel_EPOCH_SECS=3600 Citadel_KEYSYNC_INTERVAL=5 \
  timeout 15 citadel-token >/tmp/keysync-mitm.log 2>&1 || true
if ls "$SYNCDIR"/exit-*.key >/dev/null 2>&1; then
    echo "  [!] ключ принят от «издателя» с чужой PQ-идентичностью ✗"
else
    echo "  OK ✔ чужая PQ-идентичность издателя отклонена — ключ на диск не попал"
fi
# Негатив 2 (M-6, главное): СЕКРЕТ эпохи не отдаётся тому, кто не доказал keysync-идентичность.
# Абонентский seed (он есть у каждого владельца ссылки) здесь не годится — другой домен подписи;
# иначе любой абонент забирал бы ключ и чеканил токены сам.
rm -rf "$SYNCDIR"; mkdir -p "$SYNCDIR"
Citadel_TOKEN_ROLE=keysync Citadel_TOKEN_DIR="$SYNCDIR" Citadel_TOKEN_ISSUER="$ISSUER_IP:7000" \
  Citadel_ISSUER_PIN=$ISSUER_PIN Citadel_ISSUER_MLDSA=$ISSUER_MLDSA \
  Citadel_KEYSYNC_SEED=$(printf 'c5%.0s' {1..32}) Citadel_EXIT_PIN_FILE=/shared/exit.pin \
  Citadel_OBFS_PSK=$(cat /shared/obfs.psk) Citadel_EPOCH_SECS=3600 Citadel_KEYSYNC_INTERVAL=5 \
  timeout 15 citadel-token >/tmp/keysync-foreign.log 2>&1 || true
if ls "$SYNCDIR"/exit-*.key >/dev/null 2>&1; then
    echo "  [!] секрет эпохи выдан по ЧУЖОЙ идентичности ✗ (любой абонент смог бы чеканить токены)"
else
    echo "  OK ✔ чужая keysync-идентичность отклонена — секрет эпохи не выдан"
fi

echo
echo "===================================================================="
echo "  ТЕСТ 24 (M-9) — ОДНОРАЗОВАЯ ссылка: активируется на одном устройстве, копия мертва"
echo "===================================================================="
# Выдаём «первичную» запись: окно активации + заверенный отпечаток ссылки. Адрес издателя берём
# ЧИСЛОМ ($ISSUER_IP): тест идёт при поднятом туннеле, и DNS-имя контейнера через протолкнутый
# резолвер (F6) уже не разрешается — ровно как в ТЕСТЕ 20.
BOOT_SEED=$(printf 'e1%.0s' {1..32})
DEV_SEED=$(printf 'e2%.0s' {1..32})
DEV2_SEED=$(printf 'e3%.0s' {1..32})
BOOT_PUB=$(Citadel_CLIENT_SEED=$BOOT_SEED citadel-token pubkey)
LINK_HASH=$(printf 'a7%.0s' {1..32})
# Реестр правим напрямую на общем томе (роль админа тут — сам стенд): одноразовая запись.
printf '%s %s active enroll=%s,linkh=%s\n' "$BOOT_PUB" "$(( $(date +%s) + 3600 ))" \
    "$(( $(date +%s) + 600 ))" "$LINK_HASH" >> /shared/registry
rm -rf /tmp/t24; mkdir -p /tmp/t24
# 24a: пока не активировано — токенов не дают (гейт требует активации)
Citadel_TOKEN_ROLE=client Citadel_TOKEN_ISSUER=$ISSUER_IP:7000 Citadel_ISSUER_PIN=$ISSUER_PIN \
    Citadel_ISSUER_MLDSA=$ISSUER_MLDSA Citadel_TOKEN_DIR=/tmp/t24 Citadel_TOKEN_COUNT=1 \
    Citadel_CLIENT_SEED=$BOOT_SEED timeout 15 citadel-token >/tmp/t24/a 2>&1 || true
if [ ! -s /tmp/t24/tokens ] && grep -q "активац" /tmp/t24/a; then
    echo "  OK ✔ до активации токены не выдаются — издатель требует активировать ссылку"
else
    echo "  [!] первичная ссылка выдала токены без активации ✗"; tail -2 /tmp/t24/a
fi
# 24b: активация на «устройстве 1» — подписка переезжает на его ключ
Citadel_TOKEN_ROLE=enroll Citadel_TOKEN_ISSUER=$ISSUER_IP:7000 Citadel_ISSUER_PIN=$ISSUER_PIN \
    Citadel_ISSUER_MLDSA=$ISSUER_MLDSA Citadel_CLIENT_SEED=$BOOT_SEED \
    Citadel_DEVICE_SEED=$DEV_SEED Citadel_LINK_HASH=$LINK_HASH \
    timeout 15 citadel-token >/tmp/t24/b 2>&1 || true
DEV_PUB=$(Citadel_CLIENT_SEED=$DEV_SEED citadel-token pubkey)
rm -f /tmp/t24/tokens
Citadel_TOKEN_ROLE=client Citadel_TOKEN_ISSUER=$ISSUER_IP:7000 Citadel_ISSUER_PIN=$ISSUER_PIN \
    Citadel_ISSUER_MLDSA=$ISSUER_MLDSA Citadel_TOKEN_DIR=/tmp/t24 Citadel_TOKEN_COUNT=1 \
    Citadel_CLIENT_SEED=$DEV_SEED timeout 15 citadel-token >/tmp/t24/c 2>&1 || true
if grep -q "ссылка активирована" /tmp/t24/b && [ -s /tmp/t24/tokens ]; then
    echo "  OK ✔ активация прошла: устройство получило подписку и токены"
else
    echo "  [!] активация не прошла ✗"; tail -2 /tmp/t24/b
fi
# 24c: ГЛАВНОЕ — та же ссылка на ВТОРОМ устройстве больше не работает
Citadel_TOKEN_ROLE=enroll Citadel_TOKEN_ISSUER=$ISSUER_IP:7000 Citadel_ISSUER_PIN=$ISSUER_PIN \
    Citadel_ISSUER_MLDSA=$ISSUER_MLDSA Citadel_CLIENT_SEED=$BOOT_SEED \
    Citadel_DEVICE_SEED=$DEV2_SEED Citadel_LINK_HASH=$LINK_HASH \
    timeout 15 citadel-token >/tmp/t24/d 2>&1 || true
rm -f /tmp/t24/tokens
Citadel_TOKEN_ROLE=client Citadel_TOKEN_ISSUER=$ISSUER_IP:7000 Citadel_ISSUER_PIN=$ISSUER_PIN \
    Citadel_ISSUER_MLDSA=$ISSUER_MLDSA Citadel_TOKEN_DIR=/tmp/t24 Citadel_TOKEN_COUNT=1 \
    Citadel_CLIENT_SEED=$DEV2_SEED timeout 15 citadel-token >/tmp/t24/e 2>&1 || true
# NB: ищем ИМЕННО отказ — слово «активирована» есть и в нём («уже активирована на другом
# устройстве»), поэтому проверять его отсутствие нельзя.
if grep -q "уже активирована на другом" /tmp/t24/d && [ ! -s /tmp/t24/tokens ]; then
    echo "  OK ✔ второе устройство по той же ссылке отвергнуто (украденная копия бесполезна)"
else
    echo "  [!] вторая активация по той же ссылке прошла ✗"; tail -2 /tmp/t24/d
fi
# 24d: заверение — подменённый отпечаток ссылки не активируется
BOOT2_SEED=$(printf 'e4%.0s' {1..32})
BOOT2_PUB=$(Citadel_CLIENT_SEED=$BOOT2_SEED citadel-token pubkey)
printf '%s %s active enroll=%s,linkh=%s\n' "$BOOT2_PUB" "$(( $(date +%s) + 3600 ))" \
    "$(( $(date +%s) + 600 ))" "$LINK_HASH" >> /shared/registry
Citadel_TOKEN_ROLE=enroll Citadel_TOKEN_ISSUER=$ISSUER_IP:7000 Citadel_ISSUER_PIN=$ISSUER_PIN \
    Citadel_ISSUER_MLDSA=$ISSUER_MLDSA Citadel_CLIENT_SEED=$BOOT2_SEED \
    Citadel_DEVICE_SEED=$DEV2_SEED Citadel_LINK_HASH=$(printf 'bb%.0s' {1..32}) \
    timeout 15 citadel-token >/tmp/t24/f 2>&1 || true
if grep -qE "подменили|не совпал" /tmp/t24/f; then
    echo "  OK ✔ подменённая при доставке ссылка не активируется (заверение издателем)"
else
    echo "  [!] ссылка с чужим отпечатком активировалась ✗"; tail -2 /tmp/t24/f
fi

echo
echo "===================================================================="
echo "  ТЕСТ 25 (G1/G2) — инфраструктурные адреса из туннеля закрыты, кроме одного TCP-порта"
echo "===================================================================="
# На живом деплое в Citadel_DENY_DSTS лежат публичный IP самой машины и адрес издателя: F2 их не
# режет (адреса публичные), а ядровый `INPUT -i Citadel0 -j DROP` до них не достаёт — он в netns
# КОНТЕЙНЕРА, а пакет уходит через FORWARD+MASQUERADE и попадает в INPUT ХОЗЯЙСКОГО ядра.
# У стендового контейнера публичного адреса нет, поэтому механизм проверяется на 1.0.0.1
# (DENY целиком, ALLOW ровно :80) — точная модель «хост закрыт, кроме token-порта издателя».
if curl -sS --max-time 12 http://1.0.0.1 -o /dev/null 2>/dev/null; then
    echo "  OK ✔ исключение работает: TCP :80 на закрытый адрес проходит (аналог token-порта, §7.1)"
else
    echo "  [!] исключение ALLOW не пропустило TCP :80 ✗ (дозаправка кошелька сквозь туннель сломана бы)"
fi
if timeout 8 curl -sS --max-time 6 https://1.0.0.1 -o /dev/null 2>/dev/null; then
    echo "  [!] другой порт закрытого адреса ОТКРЫТ ✗ (admin-порт издателя был бы достижим — G2)"
else
    echo "  OK ✔ другой порт того же адреса закрыт (прямой путь к admin-порту издателя отрезан)"
fi
if ping -c 2 -W 3 1.0.0.1 >/dev/null 2>&1; then
    echo "  [!] ICMP на закрытый адрес прошёл ✗ (исключение обязано быть только по TCP-порту)"
else
    echo "  OK ✔ не-TCP на закрытый адрес не проходит (исключение точечное, fail-closed)"
fi
if ping -c 2 -W 3 1.1.1.1 >/dev/null 2>&1; then
    echo "  OK ✔ обычный трафик не задет (over-block'а нет)"
else
    echo "  [!] запрет задел посторонний адрес ✗"
fi

echo
echo "===================================================================="
echo "  ТЕСТ 26 (B-1) — ключ эпохи выводится ПОД УЗЕЛ: токен для exit не проходит на exit2"
echo "===================================================================="
# До B-1 все exit'ы одного издателя работали на общем секрете эпохи: один и тот же токен принимали
# все узлы по очереди (spent-множество локально для узла), а взятый под контроль exit чеканил
# токены, годные везде. Теперь абонент называет издателю pin узла, и ключ выводится под него.
kill "$M1E" 2>/dev/null || true
wait "$M1E" 2>/dev/null || true
sleep 1
rm -rf /tmp/t26; mkdir -p /tmp/t26
# Пачка, привязанная к pin'у ПЕРВОГО exit'а (адрес издателя — числом: DNS уже fail-closed).
Citadel_TOKEN_ROLE=client Citadel_TOKEN_ISSUER=$ISSUER_IP:7000 Citadel_ISSUER_PIN=$ISSUER_PIN \
    Citadel_ISSUER_MLDSA=$ISSUER_MLDSA Citadel_TOKEN_DIR=/tmp/t26 Citadel_TOKEN_COUNT=2 \
    Citadel_EXIT_PIN_FILE=/shared/exit.pin \
    Citadel_CLIENT_SEED=$(printf 'c5%.0s' {1..32}) timeout 20 citadel-token >/tmp/t26/fetch 2>&1 || true
if [ ! -s /tmp/t26/tokens ]; then
    echo "  [!] не удалось получить привязанную пачку ✗"; tail -3 /tmp/t26/fetch
else
    # Позитив: на СВОЁМ узле привязанный токен принимается.
    rm -f /tmp/Citadel-ready
    Citadel_TOKENS=/tmp/t26/tokens Citadel_SERVERS="${EXIT_IP}:4433" Citadel_PIN="$(cat /shared/exit.pin)" \
        citadel-m1 >/tmp/t26/own 2>&1 &
    M1F=$!
    for _ in $(seq 1 50); do [ -f /tmp/Citadel-ready ] && break; kill -0 "$M1F" 2>/dev/null || break; sleep 0.5; done
    if [ -f /tmp/Citadel-ready ]; then
        echo "  OK ✔ токен, взятый ПОД ЭТОТ узел, принят своим exit'ом"
    else
        echo "  [!] свой exit не принял привязанный к нему токен ✗"; tail -3 /tmp/t26/own
    fi
    kill "$M1F" 2>/dev/null || true; wait "$M1F" 2>/dev/null || true; sleep 1
    # Негатив (суть B-1): тот же издатель, другой узел — токен не годится.
    sed -i '1d' /tmp/t26/tokens 2>/dev/null || true   # второй токен пачки (первый уже потрачен)
    rm -f /tmp/Citadel-ready
    Citadel_TOKENS=/tmp/t26/tokens Citadel_SERVERS="${EXIT2_IP}:4433" Citadel_PIN="$(cat /shared/exit2.pin)" \
        timeout 25 citadel-m1 >/tmp/t26/foreign 2>&1 || true
    if [ -f /tmp/Citadel-ready ]; then
        echo "  [!] чужой exit ПРИНЯЛ токен другого узла ✗ (кросс-exit реплей не закрыт)"
    else
        echo "  OK ✔ второй exit отверг токен, выданный под первый (кросс-exit реплей закрыт)"
    fi
fi

echo
echo "===================================================================="
echo "  ТЕСТ 27 (Ф0.4) — секреты на общем томе недоступны посторонним (нет прав для others)"
echo "===================================================================="
# Класс CWE-732/276. Ключ эпохи, мастер L1 и бутстрапный PSK лежат на томе, который видят все роли
# деплоя. Группа — то, чем exit читает ключ после сброса привилегий; биты «для остальных» не нужны
# НИКОМУ и означают ровно одно: любой процесс на машине (в модели «сервер скомпрометирован» — любой
# захваченный сервис) читает секрет, не будучи ни владельцем, ни членом группы.
#
# Проверка нарочно смотрит на права, а не на содержимое: 0644 у секрета — это не «почти 0640»,
# это разные модели доступа, и разница видна только так.
PERM_BAD=""
for f in /shared/issuer.key /shared/issuer-*.key /shared/exit-*.key /shared/obfs.psk /shared/obfs.master; do
    [ -e "$f" ] || continue
    mode="$(stat -c '%a' "$f" 2>/dev/null || echo 000)"
    # последняя цифра восьмеричного режима — права «для остальных»
    if [ "${mode: -1}" != "0" ]; then
        PERM_BAD="$PERM_BAD $f($mode)"
    fi
done
if [ -n "$PERM_BAD" ]; then
    echo "  [!] секреты доступны посторонним:$PERM_BAD ✗"
else
    echo "  OK ✔ ни один секрет на /shared не читается «остальными»"
fi

echo
echo "===================================================================="
echo "  Готово. M1-M7 + STRIDE F1-F7: pinning, egress, obfs L1, drop-priv, DNS-leak, rate-limit,"
echo "  миграция, TCP-fallback, split-issuance, multi-server, crypto-agility, PQ-auth, commitment-fetch,"
echo "  admin-plane по туннелю (C7: add/revoke, домен-auth, порт снаружи закрыт),"
echo "  синхронизация ключа эпохи по сети (P1: exit и издатель на разных машинах),"
echo "  запрет инфраструктурных адресов из туннеля (G1/G2: хост и издатель закрыты, кроме token-порта),
  per-exit вывод ключа эпохи (B-1: токен одного узла не принимается другим),
  права на секреты общего тома (Ф0.4)."
echo "===================================================================="
wait "$M1E" 2>/dev/null || true
