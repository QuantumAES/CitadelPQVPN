#!/usr/bin/env bash
# =============================================================================
# e2e-прогон консольного Linux-клиента (трек L) против настоящего exit'а и issuer'а.
#
# Проверяется то, что на хосте разработчика проверить нельзя: демон под root, разделение
# привилегий (движок под отдельным uid), реальные iptables/TUN, поведение kill-switch при
# аварийном разрыве и восстановление после него.
#
# Внутри контейнера мы одновременно и «система» (создаём пользователя/группу, запускаем демон,
# как это сделал бы systemd), и «человек за терминалом» (citadel-cli).
# =============================================================================
set -u

PASS=0
FAIL=0
ok()   { echo "  OK ✔ $*"; PASS=$((PASS + 1)); }
bad()  { echo "  ✗  $*";   FAIL=$((FAIL + 1)); }
head1() { echo; echo "===================================================================="; echo "  $*"; echo "===================================================================="; }

VPND=/usr/lib/citadel-pqvpn/citadel-vpnd
ENGINE=/usr/lib/citadel-pqvpn/citadel-engine
PASSWD=testpassword123
SEED=$(printf 'c5%.0s' $(seq 1 32))   # тот же seed, что issuer регистрирует в реестре (Layer-1)

echo "[client-cli] жду артефакты exit/issuer в /shared…"
for f in /shared/exit.pin /shared/obfs.psk /shared/issuer.pub /shared/issuer-tls.pin /shared/exit.mldsa; do
    for _ in $(seq 1 90); do [ -s "$f" ] && break; sleep 1; done
    [ -s "$f" ] || echo "  [!] нет $f — часть тестов упадёт"
done

EXIT_IP=$(getent hosts exit 2>/dev/null | awk '{print $1; exit}')
ISSUER_IP=$(getent hosts issuer 2>/dev/null | awk '{print $1; exit}')
echo "[client-cli] exit=$EXIT_IP issuer=$ISSUER_IP"

# Ссылка строится по IP (не по имени): именно так и должно быть при включённом kill-switch —
# резолвер закрыт, а адрес в ссылке работает всегда.
LINK=$(citadel-linkgen \
    --servers "$EXIT_IP:4433" \
    --server-name Citadel.exit \
    --psk "$(cat /shared/obfs.psk)" \
    --pin "$(cat /shared/exit.pin)" \
    --mldsa-pub /shared/exit.mldsa \
    --routes "1.1.1.1/32 10.99.0.1/32" \
    --dns 1.1.1.1 \
    --issuer "$ISSUER_IP:7000" \
    --issuer-pin "$(cat /shared/issuer-tls.pin)" \
    --client-seed "$SEED" 2>/dev/null | grep -m1 '^citadel://')
[ -n "$LINK" ] || { echo "[client-cli] ФАТАЛЬНО: не удалось построить ссылку"; sleep infinity; }
echo "[client-cli] ссылка построена (${#LINK} символов)"

# ── подготовка системы (то, что делает установщик) ────────────────────────────
groupadd --system citadel-vpn 2>/dev/null
useradd --system --gid citadel-vpn --no-create-home --shell /usr/sbin/nologin citadel-vpn 2>/dev/null
useradd -m -s /bin/bash eve 2>/dev/null   # посторонний пользователь машины (проверка доступа)

head1 "L-ТЕСТ 1 — движок отказывается работать от root (разделение привилегий)"
out=$($ENGINE 2>&1); rc=$?
if [ $rc -ne 0 ] && echo "$out" | grep -q "не должен работать от root"; then
    ok "запуск движка из-под root отклонён: $(echo "$out" | head -1)"
else
    bad "движок не отказался работать от root (rc=$rc): $out"
fi

head1 "L-ТЕСТ 2 — демон стартует и создаёт управляющий сокет с правами 0660 root:citadel-vpn"
$VPND >/var/log/vpnd.log 2>&1 &
VPND_PID=$!
for _ in $(seq 1 30); do [ -S /run/citadel-vpn/ctl.sock ] && break; sleep 0.5; done
if [ -S /run/citadel-vpn/ctl.sock ]; then
    perm=$(stat -c '%a %U:%G' /run/citadel-vpn/ctl.sock)
    dperm=$(stat -c '%a %U:%G' /run/citadel-vpn)
    [ "$perm" = "660 root:citadel-vpn" ] && ok "сокет: $perm" || bad "сокет: $perm (ожидалось 660 root:citadel-vpn)"
    [ "$dperm" = "750 root:citadel-vpn" ] && ok "каталог: $dperm" || bad "каталог: $dperm (ожидалось 750 root:citadel-vpn)"
else
    bad "демон не создал сокет; журнал:"; cat /var/log/vpnd.log
fi

head1 "L-ТЕСТ 3 — посторонний пользователь НЕ управляет туннелем (L1: confused deputy)"
out=$(su eve -c 'citadel-cli status' 2>&1); rc=$?
if [ $rc -ne 0 ] && echo "$out" | grep -qi "нет доступа\|Permission denied"; then
    ok "пользователь вне группы отклонён ядром"
else
    bad "посторонний получил доступ (rc=$rc): $out"
fi

head1 "L-ТЕСТ 4 — мусорная ссылка отклоняется, демон остаётся жив"
printf 'не-ссылка\n%s\n%s\n' "$PASSWD" "$PASSWD" | citadel-cli add --stdin >/dev/null 2>&1
out=$(citadel-cli status 2>&1)
if kill -0 $VPND_PID 2>/dev/null && echo "$out" | grep -q "не подключено"; then
    ok "демон жив, состояние: не подключено"
else
    bad "демон в неожиданном состоянии: $out"
fi

head1 "L-ТЕСТ 5 — профиль в хранилище (Argon2id) + права файла 0600"
printf '%s\n%s\n%s\n' "$LINK" "$PASSWD" "$PASSWD" | citadel-cli add --stdin 2>&1 | tail -1
vperm=$(stat -c '%a' /root/.config/citadel-pqvpn/vault.bin 2>/dev/null)
[ "$vperm" = "600" ] && ok "vault.bin: $vperm" || bad "vault.bin: $vperm (ожидалось 600)"
printf '%s\n' "$PASSWD" | citadel-cli profiles 2>&1 | tail -2

head1 "L-ТЕСТ 6 — подключение с kill-switch: туннель поднимается"
citadel-cli killswitch on >/dev/null
printf '%s\n' "$PASSWD" | citadel-cli connect 2>&1 | tail -6
state=""
for _ in $(seq 1 60); do
    state=$(citadel-cli status 2>/dev/null | awk '/Состояние/{print $2}')
    [ "$state" = "подключено" ] && break
    sleep 1
done
if [ "$state" = "подключено" ]; then
    ok "сессия поднялась"
    citadel-cli status
else
    bad "сессия не поднялась (состояние: $state); журнал демона:"
    tail -30 /var/log/vpnd.log
fi

head1 "L-ТЕСТ 7 — движок работает под непривилегированным пользователем (L13)"
euser=$(ps -o user= -C citadel-engine | head -1 | tr -d ' ')
[ "$euser" = "citadel-" ] || [ "$euser" = "citadel-vpn" ] \
    && ok "движок под uid: $euser (не root)" \
    || bad "движок под пользователем: '$euser'"
ecaps=$(grep CapEff /proc/$(pgrep -n citadel-engine)/status 2>/dev/null | awk '{print $2}')
[ "$ecaps" = "0000000000000000" ] && ok "у движка нет capabilities (CapEff=$ecaps)" || bad "CapEff движка: $ecaps"
nnp=$(grep NoNewPrivs /proc/$(pgrep -n citadel-engine)/status 2>/dev/null | awk '{print $2}')
[ "$nnp" = "1" ] && ok "NoNewPrivs=1" || bad "NoNewPrivs=$nnp"

head1 "L-ТЕСТ 8 — интерфейс, маршруты и kill-switch применены"
ip -brief addr show citadel0 2>/dev/null && ok "интерфейс citadel0 поднят" || bad "нет интерфейса citadel0"
ip route | grep -q "1.1.1.1.*citadel0" && ok "маршрут 1.1.1.1 → citadel0" || bad "нет маршрута в туннель"
# Резолвер настроен ХОТЬ КАКИМ-ТО способом из лестницы (файл / systemd-resolved / resolvconf /
# принудительный заворот :53). В контейнере /etc/resolv.conf — bind-mount, поэтому проверяем и
# запасной путь: раньше невозможность записать файл валила всю сессию.
if grep -q "nameserver 1.1.1.1" /etc/resolv.conf 2>/dev/null; then
    ok "resolv.conf указывает на резолвер туннеля"
elif iptables -t nat -S CITADEL_DNS >/dev/null 2>&1; then
    ok "резолвер настроен заворотом :53 в туннель (запасной способ лестницы)"
else
    bad "DNS туннеля не настроен ни одним способом"
fi
if iptables -S CITADEL_KS >/dev/null 2>&1; then
    ok "цепочка CITADEL_KS создана"
    iptables -S CITADEL_KS | sed 's/^/      /'
    iptables -S CITADEL_KS | tail -1 | grep -q "\-j DROP" && ok "последнее правило — DROP (fail-closed)" || bad "финальный DROP не последний"
    iptables -S CITADEL_KS | grep -q "uid-owner" && ok "доступ к exit'у привязан к uid движка" || echo "      (owner-match недоступен — фолбэк без uid, это допустимо)"
else
    bad "kill-switch не армирован"
fi
iptables -S CITADEL_KS 2>/dev/null | grep -q "$EXIT_IP" && ok "exit $EXIT_IP разрешён точечно" || bad "нет исключения для exit'а"

head1 "L-ТЕСТ 9 — трафик реально идёт через постквантовый туннель"
if ping -c 3 -W 3 1.1.1.1 >/dev/null 2>&1; then
    ok "ping 1.1.1.1 через туннель проходит"
else
    bad "ping через туннель не прошёл"
fi
if ping -c 2 -W 2 8.8.8.8 >/dev/null 2>&1; then
    bad "8.8.8.8 доступен в обход туннеля — kill-switch пропускает лишнее"
else
    ok "адрес вне туннеля заблокирован kill-switch'ем (fail-closed)"
fi

head1 "L-ТЕСТ 10 — аварийный разрыв (kill -9 движка): защита ОСТАЁТСЯ (утечки нет)"
pkill -9 -f citadel-engine
sleep 3
if iptables -S CITADEL_KS >/dev/null 2>&1; then
    ok "после краха движка kill-switch остался армирован"
else
    bad "kill-switch снялся при аварийном разрыве — это утечка"
fi
citadel-cli status 2>&1 | sed 's/^/      /'

head1 "L-ТЕСТ 11 — реконнект ПОВЕРХ армированного kill-switch (AllowExits)"
printf '%s\n' "$PASSWD" | citadel-cli connect 2>&1 | tail -3
state=""
for _ in $(seq 1 60); do
    state=$(citadel-cli status 2>/dev/null | awk '/Состояние/{print $2}')
    [ "$state" = "подключено" ] && break
    sleep 1
done
if [ "$state" = "подключено" ]; then
    ok "сессия поднялась, хотя защита была армирована (движок пробился к exit/issuer)"
else
    bad "залипание: при армированном kill-switch подключиться не удалось (состояние: $state)"
    tail -20 /var/log/vpnd.log
fi

head1 "L-ТЕСТ 12 — чистое отключение снимает защиту и возвращает сеть"
citadel-cli disconnect 2>&1 | tail -2
sleep 2
iptables -S CITADEL_KS >/dev/null 2>&1 && bad "kill-switch не снят после чистого disconnect" || ok "kill-switch снят"
ip link show citadel0 >/dev/null 2>&1 && bad "интерфейс citadel0 остался" || ok "интерфейс убран"
grep -q "nameserver 1.1.1.1" /etc/resolv.conf 2>/dev/null && bad "resolv.conf не восстановлен" || ok "resolv.conf восстановлен"
# Сессия выше переживала реконнект (L-ТЕСТ 11): правила F6 не должны копиться и обязаны сняться
# ВСЕ. Иначе после отключения в OUTPUT остаётся DROP на :53 к мёртвому интерфейсу — DNS не
# работает вовсе, а причина неочевидна.
n53=$(iptables -S OUTPUT 2>/dev/null | grep -c "dport 53" || true)
[ "${n53:-0}" = "0" ] && ok "правила F6 (:53) сняты полностью" \
    || bad "в OUTPUT осталось правил :53: $n53 (копились на реконнектах)"
iptables -t nat -S CITADEL_DNS >/dev/null 2>&1 && bad "цепочка заворота DNS не снята" || ok "заворот DNS снят"
ping -c 2 -W 3 1.1.1.1 >/dev/null 2>&1 && ok "обычная сеть работает" || bad "сеть не восстановилась"

head1 "L-ТЕСТ 13 — аварийное снятие защиты (citadel-cli killswitch --disarm)"
$VPND --lockdown >/dev/null 2>&1
iptables -S CITADEL_KS >/dev/null 2>&1 && ok "режим блокировки армирован" || bad "--lockdown не сработал"
citadel-cli killswitch --disarm 2>&1 | tail -1
iptables -S CITADEL_KS >/dev/null 2>&1 && bad "защита не снялась" || ok "защита снята командой пользователя"

echo
echo "===================================================================="
echo "  ИТОГ e2e консольного клиента: успешно $PASS, провалено $FAIL"
echo "===================================================================="
echo "Готово."
sleep infinity
