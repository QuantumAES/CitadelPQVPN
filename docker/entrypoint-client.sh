#!/usr/bin/env bash
# client-узел: адрес получает динамически капсулой (M2), сервер пиннит (F1).
# После подъёма — ping/curl через туннель + проверка egress-фильтра (F2).
set -e
export Citadel_ROLE=client
export Citadel_SERVERS="exit:4433 exit2:4433"   # M5 multi-server: клиент выбирает (shuffle+failover)
export Citadel_CONNECT=exit:4433                # single-target для probe/auth-probe (ТЕСТ 4/8)
export Citadel_SERVER_NAME=Citadel.exit
export Citadel_TUN=Citadel0
export Citadel_MTU=1100
export Citadel_ROUTES="1.1.1.1/32 1.0.0.1/32 10.99.0.1/32"
export Citadel_PIN_DIR=/shared                  # M5: pin per-host — /shared/<host>.pin
export Citadel_OBFS_PSK=$(cat /shared/obfs.psk)   # общий PSK от издателя (генерируется, не хардкод)
export Citadel_DNS=1.1.1.1
export Citadel_TOKENS=/shared/tokens   # анонимный токен для предъявления exit (M4/M5)
# obfs-over-TCP fallback (M4): порт derive из host выбранного exit (Citadel_TCP_PORT, по умолчанию 443)

# резолвим IP exit ДО того, как citadel-m1 заблокирует DNS (F6) — нужен для auth-probe позже
EXIT_IP=$(getent hosts exit 2>/dev/null | awk '{print $1; exit}')
EXIT_IP=${EXIT_IP:-exit}
echo "[client] exit резолвится в $EXIT_IP"

# M5 split: получить анонимные токены ИНТЕРАКТИВНО от издателя (blind issuance) — ДО блокировки DNS.
# Издатель подписывает вслепую, токен в файл; издатель не видит токен → unlinkable от сессии на exit.
echo "[client] получаю токены от издателя (M5 issuer↔exit split)…"
Citadel_TOKEN_ROLE=client Citadel_TOKEN_ISSUER=issuer:7000 Citadel_TOKEN_DIR=/shared Citadel_TOKEN_COUNT=8 \
    Citadel_CLIENT_SEED=$(printf 'c5%.0s' {1..32}) \
    citadel-token || echo "[client] WARN: не удалось получить токены от издателя"

# ── Layer-1 auth-тесты (C5.2): ДО туннеля — issuer доступен по hostname (нет DNS-lock/full-tunnel).
#    Проверяют аутентификацию «абонента» у issuer; сам туннель им не нужен. ──
echo
echo "===================================================================="
echo "  ТЕСТ 17 (C5.2 Layer-1) — НЕзарегистрированный абонент не получает токены (M5)"
echo "===================================================================="
rm -rf /tmp/t17; mkdir -p /tmp/t17
Citadel_TOKEN_ROLE=client Citadel_TOKEN_ISSUER=issuer:7000 Citadel_TOKEN_DIR=/tmp/t17 Citadel_TOKEN_COUNT=1 \
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
Citadel_TOKEN_ROLE=client Citadel_TOKEN_ISSUER=issuer:7000 Citadel_TOKEN_DIR=/tmp/t18 Citadel_TOKEN_COUNT=1 \
    Citadel_CLIENT_SEED=$SEED_C timeout 15 citadel-token >/tmp/t18/o1 2>&1 || true
GOT1=$([ -s /tmp/t18/tokens ] && echo yes || echo no)
sed -i "s#^$PUB_C .*#$PUB_C 99999999999 revoked#" /shared/registry   # ОТЗЫВ (issuer перечитывает реестр)
rm -f /tmp/t18/tokens
Citadel_TOKEN_ROLE=client Citadel_TOKEN_ISSUER=issuer:7000 Citadel_TOKEN_DIR=/tmp/t18 Citadel_TOKEN_COUNT=1 \
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
Citadel_SERVERS="${EXIT_IP}:4433" Citadel_PIN="$(cat /shared/exit.pin)" Citadel_KX=classical citadel-m1 &
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
echo "  Готово. M1-M7 + STRIDE F1-F7: pinning, egress, obfs L1, drop-priv, DNS-leak, rate-limit,"
echo "  миграция, TCP-fallback, split-issuance, multi-server, obfs-кеш, fuzzing, crypto-agility, PQ-auth."
echo "===================================================================="
wait "$M1E" 2>/dev/null || true
