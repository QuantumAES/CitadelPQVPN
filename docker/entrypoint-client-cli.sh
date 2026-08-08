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
for f in /shared/exit.pin /shared/obfs.psk /shared/issuer.key /shared/issuer-tls.pin /shared/issuer-mldsa.pin /shared/exit.mldsa; do
    for _ in $(seq 1 90); do [ -s "$f" ] && break; sleep 1; done
    [ -s "$f" ] || echo "  [!] нет $f — часть тестов упадёт"
done

# Порты стенда (п.2): нестандартные значения приходят из compose — клиент обязан взять их
# из ССЫЛКИ и нигде не подставлять 4433/7000 сам.
UDP_PORT=${CITADEL_UDP_PORT:-4433}
ISSUER_PORT=${CITADEL_ISSUER_PORT:-7000}
EXIT_IP=$(getent hosts exit 2>/dev/null | awk '{print $1; exit}')
ISSUER_IP=$(getent hosts issuer 2>/dev/null | awk '{print $1; exit}')
echo "[client-cli] exit=$EXIT_IP:$UDP_PORT issuer=$ISSUER_IP:$ISSUER_PORT"

# Ссылка строится по IP (не по имени): именно так и должно быть при включённом kill-switch —
# резолвер закрыт, а адрес в ссылке работает всегда.
LINK=$(citadel-linkgen \
    --servers "$EXIT_IP:$UDP_PORT" \
    --server-name Citadel.exit \
    --psk "$(cat /shared/obfs.psk)" \
    --pin "$(cat /shared/exit.pin)" \
    --mldsa-pub /shared/exit.mldsa \
    --routes "1.1.1.1/32 10.99.0.1/32" \
    --dns 1.1.1.1 \
    --issuer "$ISSUER_IP:$ISSUER_PORT" \
    --issuer-pin "$(cat /shared/issuer-tls.pin)" \
    --issuer-mldsa "$(cat /shared/issuer-mldsa.pin)" \
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

# ─────────────────────────────────────────────────────────────────────────────
# ПОЛНЫЙ ТУННЕЛЬ (0.0.0.0/0) + split-обход локальной подсети.
#
# Тесты 1–13 гоняют туннель на узких маршрутах (`1.1.1.1/32`), а у пользователя он ПОЛНЫЙ —
# и ровно на нём вылезло «подключается, но интернета нет, локальные адреса пингуются». Это
# другой режим кода: половинки `0.0.0.0/1`, выбор source-адреса ядром, bypass к exit'у,
# NAT-заворот DNS. Без этого сценария в стенде класс дефектов «полный туннель не носит
# трафик» не ловится вовсе.
# ─────────────────────────────────────────────────────────────────────────────
head1 "L-ТЕСТ 14 — ПОЛНЫЙ туннель (0.0.0.0/0): интернет идёт через exit"
# Подсеть контейнера = «локалка» пользователя: её и просим обойти сплитом.
LAN=$(ip -o -4 route show scope link | awk '/eth0/{print $1; exit}')
LAN_GW=$(getent hosts exit | awk '{print $1; exit}')   # сосед по мосту (проверка обхода)
echo "  локальная подсеть (обход): ${LAN:-нет} ; сосед: $LAN_GW"
LINK_FULL=$(citadel-linkgen \
    --servers "$EXIT_IP:$UDP_PORT" \
    --server-name Citadel.exit \
    --psk "$(cat /shared/obfs.psk)" \
    --pin "$(cat /shared/exit.pin)" \
    --mldsa-pub /shared/exit.mldsa \
    --routes "0.0.0.0/0" \
    --dns 1.1.1.1 \
    --issuer "$ISSUER_IP:$ISSUER_PORT" \
    --issuer-pin "$(cat /shared/issuer-tls.pin)" \
    --issuer-mldsa "$(cat /shared/issuer-mldsa.pin)" \
    --client-seed "$SEED" 2>/dev/null | grep -m1 '^citadel://')
printf '%s\n%s\n' "$LINK_FULL" "$PASSWD" | citadel-cli add --name full --stdin 2>&1 | tail -1
[ -n "$LAN" ] && citadel-cli split exclude "$LAN" >/dev/null
citadel-cli killswitch on >/dev/null
printf '%s\n' "$PASSWD" | citadel-cli connect full 2>&1 | tail -4
state=""
for _ in $(seq 1 60); do
    state=$(citadel-cli status 2>/dev/null | awk '/Состояние/{print $2}')
    [ "$state" = "подключено" ] && break
    sleep 1
done
if [ "$state" != "подключено" ]; then
    bad "полный туннель не поднялся (состояние: $state)"
    tail -30 /var/log/vpnd.log
else
    ok "полный туннель поднялся"
    ip route | sed 's/^/      /'
    ip route | grep -q "^0.0.0.0/1 .*citadel0" && ok "половинка 0.0.0.0/1 → citadel0" || bad "нет 0.0.0.0/1 в туннеле"
    ip route | grep -q "^128.0.0.0/1 .*citadel0" && ok "половинка 128.0.0.0/1 → citadel0" || bad "нет 128.0.0.0/1 в туннеле"
    # Анти-петля к exit'у: либо явный /32 мимо туннеля, либо exit on-link (в стенде он сосед по
    # мосту — connected-route уже специфичнее половинок /1, и трогать его ВРЕДНО).
    if ip route | grep -q "^$EXIT_IP.*via" || ip route get "$EXIT_IP" | grep -q "dev eth0"; then
        ok "путь к exit'у идёт мимо туннеля (анти-петля): $(ip route get "$EXIT_IP" | head -1)"
    else
        bad "трафик к exit'у заворачивается в туннель — петля"
    fi

    # Главная проверка: адрес, которого НЕТ в маршрутах ссылки, обязан ходить через туннель.
    if ping -c 3 -W 4 8.8.8.8 >/dev/null 2>&1; then
        ok "ping 8.8.8.8 через полный туннель проходит"
    else
        bad "НЕТ ИНТЕРНЕТА через полный туннель (ping 8.8.8.8): ровно замечание пользователя"
    fi
    if ping -c 2 -W 4 1.1.1.1 >/dev/null 2>&1; then
        ok "ping 1.1.1.1 (он же резолвер) проходит"
    else
        bad "1.1.1.1 недостижим через полный туннель"
    fi
    # TCP поверх туннеля: ловит MTU/MSS-дефекты, которые ICMP не показывает.
    if curl -sS -m 15 -o /dev/null https://1.1.1.1/ 2>/dev/null; then
        ok "TCP/TLS через туннель работает (curl https://1.1.1.1)"
    else
        bad "TCP/TLS через туннель не работает (MTU/MSS?)"
    fi
    # DNS: имена обязаны резолвиться (это и есть «интернета нет» для большинства).
    if getent hosts example.com >/dev/null 2>&1; then
        ok "имена резолвятся через туннель"
    else
        bad "DNS не работает при полном туннеле"
        echo "      resolv.conf: $(tr '\n' ' ' < /etc/resolv.conf)"
        iptables -t nat -S CITADEL_DNS 2>/dev/null | sed 's/^/      /'
    fi
    # Сплит: сосед по локальной подсети обязан оставаться доступным мимо туннеля.
    if [ -n "$LAN_GW" ] && ping -c 2 -W 3 "$LAN_GW" >/dev/null 2>&1; then
        ok "локальный адрес $LAN_GW доступен (сплит-обход работает)"
    else
        bad "локальный адрес $LAN_GW недоступен при полном туннеле"
    fi
fi
citadel-cli disconnect >/dev/null 2>&1

# ─────────────────────────────────────────────────────────────────────────────
# Последняя ступень лестницы DNS: «резолвер системы настроить нечем — заворачиваем :53 NAT'ом».
# Именно она включается там, где /etc только для чтения (systemd-песочница, immutable-дистрибутив,
# контейнер) — и именно она НИ РАЗУ не проигрывалась в стенде, потому что в контейнере
# /etc/resolv.conf пишется. Форсируем ступень (CITADEL_DNS_FORCE) и ставим системным резолвером
# адрес ЛОКАЛЬНОЙ подсети — так же, как у пользователя: только в этой комбинации виден дефект
# «DNAT меняет назначение, но не источник» (пакет уходит в туннель с адресом локалки → exit
# дропает его анти-спуфингом → «подключено, а интернета нет»).
# ─────────────────────────────────────────────────────────────────────────────
head1 "L-ТЕСТ 15 — DNS через принудительный заворот :53 (ступень «нечем настроить резолвер»)"
kill "$VPND_PID" 2>/dev/null; sleep 2
: > /var/log/vpnd-redirect.log
CITADEL_DNS_FORCE=redirect $VPND >/var/log/vpnd-redirect.log 2>&1 &
VPND_PID=$!
for _ in $(seq 1 30); do [ -S /run/citadel-vpn/ctl.sock ] && break; sleep 0.5; done
# «Резолвер провайдера» в локальной подсети — шлюз моста. Важно, что это НЕ резолвер туннеля:
# запрос к 1.1.1.1 ушёл бы в туннель сам (host-route) и с правильным src, не проверив заворот.
LAN_DNS=$(ip route show default | awk '{print $3; exit}')
LAN_DNS="${LAN_DNS:-172.18.0.1}"
cp /etc/resolv.conf /tmp/resolv.orig 2>/dev/null
printf 'nameserver %s\noptions timeout:2 attempts:1\n' "$LAN_DNS" > /etc/resolv.conf
echo "  системный резолвер на время теста: $LAN_DNS (адрес локальной подсети)"
printf '%s\n' "$PASSWD" | citadel-cli connect full 2>&1 | tail -3
state=""
for _ in $(seq 1 60); do
    state=$(citadel-cli status 2>/dev/null | awk '/Состояние/{print $2}')
    [ "$state" = "подключено" ] && break
    sleep 1
done
if [ "$state" != "подключено" ]; then
    bad "сессия с заворотом DNS не поднялась (состояние: $state)"
    tail -30 /var/log/vpnd-redirect.log
else
    grep -q "заворот :53" /var/log/vpnd-redirect.log \
        && ok "выбрана ступень «заворот :53 в туннель»" \
        || bad "ступень не выбрана — тест проверяет не то, что нужно"
    iptables -t nat -S CITADEL_DNS >/dev/null 2>&1 && ok "цепочка заворота создана" || bad "нет цепочки CITADEL_DNS"
    if iptables -t nat -S CITADEL_DNS_SNAT 2>/dev/null | grep -q MASQUERADE; then
        ok "источник завёрнутых запросов подменяется на адрес туннеля (SNAT)"
        iptables -t nat -S CITADEL_DNS_SNAT | sed 's/^/      /'
    else
        bad "нет SNAT для завёрнутых запросов — пакеты уйдут с адресом локалки"
    fi
    # Главное: имена обязаны резолвиться, хотя resolv.conf указывает в локальную подсеть.
    if getent hosts example.com >/dev/null 2>&1; then
        ok "имена резолвятся через заворот (запрос к $LAN_DNS уехал в туннель)"
    else
        bad "DNS не работает на ступени заворота: ровно замечание пользователя"
        iptables -t nat -S CITADEL_DNS | sed 's/^/      /'
    fi
    # Клиентская диагностика: пакетов с чужим src быть НЕ должно (они гибнут на exit'е молча).
    if grep -q "ЧУЖИМ адресом источника" /var/log/vpnd-redirect.log; then
        bad "движок сообщил о пакетах с чужим src — заворот всё ещё калечит адрес источника:"
        grep -m1 "ЧУЖИМ адресом источника" /var/log/vpnd-redirect.log | sed 's/^/      /'
    else
        ok "движок не видел пакетов с чужим адресом источника"
    fi

    # НЕГАТИВНЫЙ контроль: снимаем ровно SNAT — и всё обязано сломаться так же, как у
    # пользователя. Так тест доказывает причинно-следственную связь, а не просто «сейчас работает»:
    # если однажды SNAT снова потеряется, упадёт не абстрактный assert, а этот сценарий.
    echo "  — контроль: снимаю SNAT и проверяю, что дефект возвращается…"
    iptables -t nat -D POSTROUTING -j CITADEL_DNS_SNAT 2>/dev/null
    if getent hosts example.net >/dev/null 2>&1; then
        bad "без SNAT DNS всё равно работает — значит тест не проверяет причину дефекта"
    else
        ok "без SNAT имена не резолвятся (дефект воспроизводится ⇒ лечит именно SNAT)"
    fi
    sleep 10   # окно watchdog'а (8с) — движок должен успеть назвать причину
    if grep -q "ЧУЖИМ адресом источника" /var/log/vpnd-redirect.log; then
        ok "движок назвал причину вслух: $(grep -m1 -o 'последний [0-9.]*, а назначен нам [0-9.]*' /var/log/vpnd-redirect.log)"
    else
        bad "движок промолчал о пакетах с чужим src — диагностика не работает"
    fi
    iptables -t nat -I POSTROUTING 1 -j CITADEL_DNS_SNAT 2>/dev/null
    getent hosts example.org >/dev/null 2>&1 \
        && ok "SNAT возвращён — имена снова резолвятся" \
        || bad "после возврата SNAT DNS не восстановился"
fi
citadel-cli disconnect >/dev/null 2>&1
sleep 1
iptables -t nat -S CITADEL_DNS >/dev/null 2>&1 && bad "цепочка заворота не снята" || ok "заворот снят при отключении"
iptables -t nat -S CITADEL_DNS_SNAT >/dev/null 2>&1 && bad "цепочка SNAT не снята" || ok "SNAT-цепочка снята"
cp /tmp/resolv.orig /etc/resolv.conf 2>/dev/null

echo
echo "===================================================================="
echo "  ИТОГ e2e консольного клиента: успешно $PASS, провалено $FAIL"
echo "===================================================================="
echo "Готово."
sleep infinity
