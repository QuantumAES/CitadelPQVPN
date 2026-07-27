//! Генерация сетевых правил — **чистые функции**, тестируемые без root.
//!
//! Тот же приём, что `killswitch_rules` в `citadel-helper`: демон отдельно СЧИТАЕТ, что нужно
//! сделать, и отдельно ЭТО ИСПОЛНЯЕТ (`main.rs`). Так порядок правил (fail-closed: финальный
//! `DROP` после всех `RETURN`) проверяется юнит-тестом, а не «на живой машине».
//!
//! Отличие от helper'а — правила строятся из **типизированных** значений ([`crate::valid`]) и
//! kill-switch умеет привязку к uid движка (`-m owner --uid-owner`): к exit'у пускается только
//! процесс движка, а не любой локальный процесс, случайно попавший на тот же адрес.

use std::net::Ipv4Addr;

use crate::valid::{TunSetup, V4Net};

/// Имя цепочки kill-switch (IPv4). Совместимо с `citadel-helper` — осиротевшую цепочку от
/// GUI-клиента снимет и `citadel-cli killswitch --disarm`, и наоборот.
pub const KS_CHAIN: &str = "CITADEL_KS";
/// Цепочка блока IPv6 (S2.2/A2): туннель IPv4-only ⇒ нативный IPv6 — утечка мимо него.
pub const KS6_CHAIN: &str = "CITADEL_KS6";

fn a(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// Правила kill-switch (аргументы `iptables`, по одному вектору на вызов).
///
/// Разрешено (RETURN): loopback, сам туннель, путь к exit'ам, назначения «в обход» (C8.1/C8.3)
/// и DHCP-аренда. Всё остальное — финальный DROP. Хук ставится в начало `OUTPUT` отдельной
/// цепочкой, чтобы не трогать чужую политику.
///
/// `engine_uid`: если задан, доступ к exit'ам разрешается **только** процессу движка
/// (`-m owner --uid-owner`). Это сужает исключение с «любой локальный процесс может слать пакеты
/// на IP exit'а» до «только движок» — важно на многопользовательской машине, где адрес exit'а
/// известен всем из `status`. Вызывающий обязан уметь откатиться на правило без owner-match, если
/// в ядре нет модуля `xt_owner` (см. `main.rs`).
/// `dns_guarded` — для `:53` установлен рубеж [`dns_rules`] (то есть в ссылке задан резолвер
/// туннеля). Тогда DNS выпускается из цепочки **без проверки интерфейса**: при принудительном
/// завороте (`DNAT` в `OUTPUT`, [`dns_redirect_rules`]) ядро перемаршрутизирует пакет в туннель,
/// но `-o` в этом же проходе хуков остаётся прежним — фильтр видит физический интерфейс, и
/// завёрнутый запрос падал в финальный `DROP` («подключено, а имена не резолвятся»). Настоящий
/// fail-closed для `:53` живёт в `mangle POSTROUTING`, где интерфейс уже настоящий.
pub fn killswitch_rules(
    ifn: &str,
    exit_ips: &[Ipv4Addr],
    bypass: &[V4Net],
    engine_uid: Option<u32>,
    dns_guarded: bool,
) -> Vec<Vec<String>> {
    let mut r = vec![
        a(&["-N", KS_CHAIN]),
        a(&["-A", KS_CHAIN, "-o", "lo", "-j", "RETURN"]),
        a(&["-A", KS_CHAIN, "-o", ifn, "-j", "RETURN"]),
    ];
    if dns_guarded {
        for proto in ["udp", "tcp"] {
            r.push(a(&["-A", KS_CHAIN, "-p", proto, "--dport", "53", "-j", "RETURN"]));
        }
    }
    for eip in exit_ips {
        let dst = format!("{eip}/32");
        match engine_uid {
            Some(uid) => r.push(a(&[
                "-A", KS_CHAIN, "-d", &dst, "-m", "owner", "--uid-owner", &uid.to_string(), "-j",
                "RETURN",
            ])),
            None => r.push(a(&["-A", KS_CHAIN, "-d", &dst, "-j", "RETURN"])),
        }
    }
    for b in bypass {
        r.push(a(&["-A", KS_CHAIN, "-d", &b.to_string(), "-j", "RETURN"]));
    }
    // DHCP-аренда: иначе на full-tunnel можно потерять адрес на физическом линке.
    r.push(a(&["-A", KS_CHAIN, "-p", "udp", "--dport", "67:68", "-j", "RETURN"]));
    r.push(a(&["-A", KS_CHAIN, "-j", "DROP"]));
    r.push(a(&["-I", "OUTPUT", "1", "-j", KS_CHAIN]));
    r
}

/// Снятие kill-switch: хук из OUTPUT, затем очистка и удаление цепочки. Идемпотентно —
/// на несуществующей цепочке `iptables` просто вернёт ошибку, которую вызывающий игнорирует.
pub fn killswitch_teardown() -> Vec<Vec<String>> {
    vec![
        a(&["-D", "OUTPUT", "-j", KS_CHAIN]),
        a(&["-F", KS_CHAIN]),
        a(&["-X", KS_CHAIN]),
    ]
}

/// S2.2/A2: fail-closed блок исходящего IPv6. RETURN только для loopback и link-local ND
/// (ICMPv6 133–136 — иначе ломается локальный IPv6-стек), остальное DROP.
pub fn ipv6_block_rules() -> Vec<Vec<String>> {
    let mut r = vec![
        a(&["-N", KS6_CHAIN]),
        a(&["-A", KS6_CHAIN, "-o", "lo", "-j", "RETURN"]),
    ];
    for t in ["133", "134", "135", "136"] {
        r.push(a(&["-A", KS6_CHAIN, "-p", "ipv6-icmp", "--icmpv6-type", t, "-j", "RETURN"]));
    }
    r.push(a(&["-A", KS6_CHAIN, "-j", "DROP"]));
    r.push(a(&["-I", "OUTPUT", "1", "-j", KS6_CHAIN]));
    r
}

/// Снятие блока IPv6.
pub fn ipv6_block_teardown() -> Vec<Vec<String>> {
    vec![
        a(&["-D", "OUTPUT", "-j", KS6_CHAIN]),
        a(&["-F", KS6_CHAIN]),
        a(&["-X", KS6_CHAIN]),
    ]
}

/// F6 (DNS fail-closed): резолвер достижим только через туннель, прочий `:53` дропается.
/// Возвращает аргументы `iptables` для **установки**; снятие — [`dns_rules_teardown`].
///
/// `allow_loopback` — пускать `:53` на `lo`. Нужно, когда резолвером системы остаётся локальный
/// stub (systemd-resolved на 127.0.0.53) или когда весь `:53` заворачивается NAT'ом: сам запрос к
/// stub'у машину не покидает, а его апстрим уже идёт по нашим правилам — то есть через туннель.
/// Когда мы переписали `resolv.conf` сами, stub не задействован и loopback остаётся закрытым.
///
/// **Почему рубеж стоит в `mangle POSTROUTING`, а не в `filter OUTPUT`.** Для локально
/// сгенерированного пакета netfilter вычисляет выходной интерфейс ОДИН раз, ДО прохода хуков
/// `OUTPUT`. Если внутри этого прохода пакет получил новое назначение (`DNAT`-заворот `:53`,
/// [`dns_redirect_rules`]), ядро честно перемаршрутизирует его в туннель — но `-o` для всех
/// последующих правил того же прохода остаётся ПРЕЖНИМ, физическим. Проверка `! -o citadel0` в
/// `OUTPUT` из-за этого дропала ровно те запросы, которые сама же система и завернула в туннель:
/// «подключено, а имена не резолвятся» (ловили вживую). В `POSTROUTING` интерфейс уже
/// фактический, поэтому проверка там и корректна, и строже: она ловит любой `:53` мимо туннеля,
/// как бы он там ни оказался.
pub fn dns_rules(ifn: &str, allow_loopback: bool) -> Vec<Vec<String>> {
    let mut r = Vec::new();
    for proto in ["udp", "tcp"] {
        if allow_loopback {
            // ACCEPT идёт ПЕРЕД DROP: правила добавляются в цепочку по порядку.
            r.push(a(&[
                "-t", "mangle", "-A", "POSTROUTING", "-p", proto, "--dport", "53", "-o", "lo", "-j",
                "ACCEPT",
            ]));
        }
        r.push(a(&[
            "-t", "mangle", "-A", "POSTROUTING", "-p", proto, "--dport", "53", "!", "-o", ifn, "-j",
            "DROP",
        ]));
    }
    r
}

/// Снятие F6-правил (те же правила с `-D`).
///
/// Снимаем ОБА варианта (с loopback-исключением и без) независимо от того, какой применялся:
/// удаление отсутствующего правила — не ошибка, зато снятие идемпотентно и переживает смену
/// способа настройки резолвера между реконнектами. Это же делает установку безопасной для
/// повторов: перед каждым `-A` вызывающий сначала снимает старое, иначе на каждом реконнекте
/// копился бы ещё один DROP — и после disconnect резолвер остался бы заблокирован.
///
/// Снимаются и УСТАРЕВШИЕ правила из `filter OUTPUT` (там рубеж стоял до переноса в
/// `POSTROUTING`): иначе после обновления в системе остался бы DROP, убивающий завёрнутый DNS,
/// а человек видел бы «обновился — стало хуже» без понятного способа это снять.
pub fn dns_rules_teardown(ifn: &str) -> Vec<Vec<String>> {
    let mut r: Vec<Vec<String>> = dns_rules(ifn, true)
        .into_iter()
        .map(|mut v| {
            let i = v.iter().position(|x| x == "-A").expect("в правиле установки есть -A");
            v[i] = "-D".into();
            v
        })
        .collect();
    for proto in ["udp", "tcp"] {
        r.push(a(&["-D", "OUTPUT", "-p", proto, "--dport", "53", "-o", "lo", "-j", "ACCEPT"]));
        r.push(a(&["-D", "OUTPUT", "-p", proto, "--dport", "53", "!", "-o", ifn, "-j", "DROP"]));
    }
    r
}

/// Цепочка принудительного заворота DNS в туннель (таблица `nat`).
pub const DNS_NAT_CHAIN: &str = "CITADEL_DNS";
/// Цепочка SNAT для завёрнутых DNS-пакетов (таблица `nat`, хук POSTROUTING). Без неё завёрнутый
/// запрос уходит в туннель с адресом ЛОКАЛЬНОГО интерфейса и гибнет на анти-спуфинге exit'а —
/// см. [`dns_redirect_rules`].
pub const DNS_SNAT_CHAIN: &str = "CITADEL_DNS_SNAT";

/// Последний рубеж настройки DNS: весь исходящий `:53` переписывается на резолвер туннеля.
///
/// Применяется, когда системный резолвер настроить нечем — `/etc` только для чтения, а ни
/// systemd-resolved, ни resolvconf на машине нет. Содержимое `resolv.conf` тогда вообще
/// перестаёт иметь значение: куда бы приложение ни спросило, запрос уедет в туннель.
///
/// Исключения (RETURN до DNAT): сам резолвер туннеля (иначе NAT зациклился бы на себе) и `lo` —
/// переписывать адрес у петлевого пакета нельзя (после реврайта ядру пришлось бы менять и
/// источник 127.0.0.1, пакет улетел бы «марсианином»). Локальный stub при этом продолжает
/// работать: его собственный апстрим-запрос — уже не петлевой и заворачивается этими правилами.
///
/// **Обязательный SNAT (без него способ не работает вовсе).** DNAT в `OUTPUT` меняет только
/// назначение: адрес источника ядро выбрало ДО него — по маршруту к ПЕРВОНАЧАЛЬНОМУ резолверу,
/// то есть взяло адрес физического интерфейса (`nf_ip_route_me_harder` сохраняет уже выбранный
/// локальный `saddr`, лишь переспрашивая маршрут). После реврайта пакет уезжает в туннель с
/// адресом локалки, а exit дропает его анти-спуфингом (S0.2/H3: inner-src обязан быть
/// назначенным адресом) — снаружи это выглядит как «подключено, но имена не резолвятся».
/// Поэтому источник переписывается на адрес туннеля MASQUERADE'ом на выходном интерфейсе: он
/// берёт адрес самого `ifn` (переживает смену адреса на реконнекте), а conntrack разворачивает
/// и DNAT, и SNAT на ответе — приложение видит ответ от того резолвера, о котором спрашивало.
///
/// Порядок: цепочка сначала подвешивается в хук, и только потом наполняется. Так надо для
/// `iptables-legacy`: `DNAT`/`MASQUERADE` разрешены только из своих хуков, а для user-цепочки
/// ядро считает набор хуков по достижимости — в неподвешенную цепочку такое правило не встанет
/// (`used from hooks ..., but only usable from ...`). На nft-бэкенде проверки нет, поэтому
/// дефект был бы «работает у меня, не работает у него».
pub fn dns_redirect_rules(dns: Ipv4Addr, ifn: &str) -> Vec<Vec<String>> {
    let to = format!("{dns}:53");
    let self_dst = format!("{dns}/32");
    let mut r = vec![a(&["-t", "nat", "-N", DNS_NAT_CHAIN])];
    for proto in ["udp", "tcp"] {
        r.push(a(&["-t", "nat", "-I", "OUTPUT", "1", "-p", proto, "--dport", "53", "-j", DNS_NAT_CHAIN]));
    }
    r.push(a(&["-t", "nat", "-A", DNS_NAT_CHAIN, "-d", &self_dst, "-j", "RETURN"]));
    r.push(a(&["-t", "nat", "-A", DNS_NAT_CHAIN, "-o", "lo", "-j", "RETURN"]));
    for proto in ["udp", "tcp"] {
        r.push(a(&[
            "-t", "nat", "-A", DNS_NAT_CHAIN, "-p", proto, "--dport", "53", "-j", "DNAT",
            "--to-destination", &to,
        ]));
    }
    // Источник → адрес туннеля. Отдельная цепочка (а не правила прямо в POSTROUTING) — чтобы
    // снятие не требовало знать ни резолвер, ни интерфейс: осиротевшее правило от убитого демона
    // снимается `--disarm` по одному имени цепочки.
    r.push(a(&["-t", "nat", "-N", DNS_SNAT_CHAIN]));
    r.push(a(&["-t", "nat", "-I", "POSTROUTING", "1", "-j", DNS_SNAT_CHAIN]));
    for proto in ["udp", "tcp"] {
        r.push(a(&[
            "-t", "nat", "-A", DNS_SNAT_CHAIN, "-o", ifn, "-d", &self_dst, "-p", proto, "--dport",
            "53", "-j", "MASQUERADE",
        ]));
    }
    r
}

/// Снятие заворота DNS (идемпотентно, не требует ни резолвера, ни имени интерфейса).
pub fn dns_redirect_teardown() -> Vec<Vec<String>> {
    let mut r = Vec::new();
    for proto in ["udp", "tcp"] {
        r.push(a(&["-t", "nat", "-D", "OUTPUT", "-p", proto, "--dport", "53", "-j", DNS_NAT_CHAIN]));
    }
    r.push(a(&["-t", "nat", "-F", DNS_NAT_CHAIN]));
    r.push(a(&["-t", "nat", "-X", DNS_NAT_CHAIN]));
    r.push(a(&["-t", "nat", "-D", "POSTROUTING", "-j", DNS_SNAT_CHAIN]));
    r.push(a(&["-t", "nat", "-F", DNS_SNAT_CHAIN]));
    r.push(a(&["-t", "nat", "-X", DNS_SNAT_CHAIN]));
    r
}

/// Маршруты туннеля (аргументы `ip`). `0.0.0.0/0` раскрывается в две половинки `/1`: они
/// специфичнее default'а и перекрывают его, но физический `default via GW` остаётся на месте —
/// он нужен как nexthop для bypass-маршрутов и для восстановления связи после disconnect.
pub fn tunnel_route_cmds(setup: &TunSetup, ifn: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    for r in &setup.routes {
        if r.is_default() {
            out.push(a(&["route", "replace", "0.0.0.0/1", "dev", ifn]));
            out.push(a(&["route", "replace", "128.0.0.0/1", "dev", ifn]));
        } else {
            out.push(a(&["route", "replace", &r.to_string(), "dev", ifn]));
        }
    }
    if let Some(dns) = setup.dns {
        out.push(a(&["route", "replace", &format!("{dns}/32"), "dev", ifn]));
    }
    out
}

/// Как ядро маршрутизирует назначение СЕЙЧАС (до подмены таблицы туннелем).
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PathKind {
    /// Достижимо напрямую по подсети — bypass-маршрут не нужен и ВРЕДЕН: connected-route уже
    /// специфичнее половинок `/1`, а `replace via gw` сломал бы доставку по L2 (баг сплита
    /// для локальной подсети, ловили вживую).
    Onlink { dev: String },
    /// За шлюзом — нужен явный bypass `via <nh> dev <dev>`.
    Via { nh: String, dev: String },
}

/// Разобрать первую строку `ip route get <dst>`: `<dst> [via <nh>] dev <dev> …`.
pub fn parse_route_get(first_line: &str) -> Option<PathKind> {
    let t: Vec<&str> = first_line.split_whitespace().collect();
    let dev = t.iter().position(|x| *x == "dev").and_then(|i| t.get(i + 1)).map(|s| s.to_string())?;
    match t.iter().position(|x| *x == "via").and_then(|i| t.get(i + 1)) {
        Some(nh) => Some(PathKind::Via { nh: (*nh).to_string(), dev }),
        None => Some(PathKind::Onlink { dev }),
    }
}

/// Разобрать первую строку `ip route show default`: `default via <gw> dev <dev> …`.
pub fn parse_default_route(first_line: &str) -> Option<(String, String)> {
    let t: Vec<&str> = first_line.split_whitespace().collect();
    let via = t.iter().position(|x| *x == "via")?;
    let dev = t.iter().position(|x| *x == "dev")?;
    Some((t.get(via + 1)?.to_string(), t.get(dev + 1)?.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::TunSetupReq;

    fn s(v: &[String]) -> Vec<&str> {
        v.iter().map(String::as_str).collect()
    }

    fn drop_after_all_returns(rules: &[Vec<String>]) {
        let drop_idx = rules.iter().position(|x| x.last().map(String::as_str) == Some("DROP"));
        let last_return = rules.iter().rposition(|x| x.last().map(String::as_str) == Some("RETURN"));
        assert!(
            drop_idx.unwrap() > last_return.unwrap(),
            "fail-closed нарушен: DROP должен идти после всех RETURN"
        );
    }

    #[test]
    fn killswitch_shape_and_fail_closed() {
        let ips = [Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8)];
        let r = killswitch_rules("citadel0", &ips, &[], None, false);
        assert_eq!(s(r.first().unwrap()), vec!["-N", KS_CHAIN]);
        assert_eq!(s(r.last().unwrap()), vec!["-I", "OUTPUT", "1", "-j", KS_CHAIN]);
        assert!(r.iter().any(|x| s(x) == vec!["-A", KS_CHAIN, "-o", "lo", "-j", "RETURN"]));
        assert!(r.iter().any(|x| s(x) == vec!["-A", KS_CHAIN, "-o", "citadel0", "-j", "RETURN"]));
        let flat: Vec<&str> = r.iter().flatten().map(String::as_str).collect();
        assert!(flat.contains(&"1.2.3.4/32") && flat.contains(&"5.6.7.8/32"));
        drop_after_all_returns(&r);
    }

    /// Привязка к uid движка: к exit'у пускается только он, а не любой локальный процесс.
    #[test]
    fn killswitch_binds_exit_exception_to_engine_uid() {
        let ips = [Ipv4Addr::new(1, 2, 3, 4)];
        let r = killswitch_rules("citadel0", &ips, &[], Some(996), false);
        let rule = r
            .iter()
            .find(|x| x.contains(&"1.2.3.4/32".to_string()))
            .expect("правило для exit'а");
        assert_eq!(
            s(rule),
            vec!["-A", KS_CHAIN, "-d", "1.2.3.4/32", "-m", "owner", "--uid-owner", "996", "-j", "RETURN"]
        );
        drop_after_all_returns(&r);
    }

    /// C8.1: split-обход сосуществует с kill-switch — RETURN по dst, fail-closed сохранён.
    #[test]
    fn killswitch_allows_split_bypass() {
        let bypass = [V4Net::parse("192.168.1.0/24").unwrap(), V4Net::parse("203.0.113.7").unwrap()];
        let r = killswitch_rules("citadel0", &[Ipv4Addr::new(1, 2, 3, 4)], &bypass, None, false);
        for b in ["192.168.1.0/24", "203.0.113.7/32"] {
            assert!(
                r.iter().any(|x| s(x) == vec!["-A", KS_CHAIN, "-d", b, "-j", "RETURN"]),
                "обход {b} должен быть разрешён"
            );
        }
        drop_after_all_returns(&r);
    }

    #[test]
    fn ipv6_block_shape() {
        let r = ipv6_block_rules();
        assert_eq!(s(r.first().unwrap()), vec!["-N", KS6_CHAIN]);
        assert_eq!(s(r.last().unwrap()), vec!["-I", "OUTPUT", "1", "-j", KS6_CHAIN]);
        for t in ["133", "134", "135", "136"] {
            assert!(r.iter().any(|x| s(x)
                == vec!["-A", KS6_CHAIN, "-p", "ipv6-icmp", "--icmpv6-type", t, "-j", "RETURN"]));
        }
        drop_after_all_returns(&r);
    }

    /// Full-tunnel не затирает физический default: ставятся две половинки `/1`, а `0.0.0.0/0`
    /// как таковой не трогается (иначе после disconnect связь не восстановить).
    #[test]
    fn full_tunnel_uses_two_halves() {
        let req = TunSetupReq {
            addr: [10, 8, 0, 2],
            prefix: 24,
            mtu: "1280".into(),
            routes: vec!["0.0.0.0/0".into()],
            dns: Some("10.8.0.1".into()),
            exit_ips: vec![],
            killswitch: false,
            bypass: vec![],
        };
        let setup = TunSetup::parse(&req).unwrap();
        let cmds = tunnel_route_cmds(&setup, "citadel0");
        let flat: Vec<Vec<&str>> = cmds.iter().map(|c| s(c)).collect();
        assert!(flat.contains(&vec!["route", "replace", "0.0.0.0/1", "dev", "citadel0"]));
        assert!(flat.contains(&vec!["route", "replace", "128.0.0.0/1", "dev", "citadel0"]));
        assert!(!flat.iter().any(|c| c.contains(&"0.0.0.0/0")), "физический default не трогаем");
        // DNS уходит в туннель отдельным host-route (F6)
        assert!(flat.contains(&vec!["route", "replace", "10.8.0.1/32", "dev", "citadel0"]));
    }

    #[test]
    fn dns_teardown_mirrors_setup() {
        let down = dns_rules_teardown("citadel0");
        // Снятие обязано покрывать ОБА варианта установки (с loopback-исключением и без): иначе
        // смена способа настройки резолвера между реконнектами оставила бы висеть чужой DROP.
        for lo in [true, false] {
            for rule in dns_rules("citadel0", lo) {
                let as_del: Vec<String> = rule
                    .iter()
                    .map(|x| if x == "-A" { "-D".to_string() } else { x.clone() })
                    .collect();
                assert!(down.contains(&as_del), "снятие не покрывает правило {rule:?}");
            }
        }
        // …и УСТАРЕВШИЕ правила прежних версий (рубеж стоял в filter OUTPUT): после обновления
        // они должны сниматься, иначе оставшийся DROP убивает завёрнутый DNS.
        assert!(
            down.iter().any(|x| s(x)
                == vec!["-D", "OUTPUT", "-p", "udp", "--dport", "53", "!", "-o", "citadel0", "-j", "DROP"]),
            "снятие не покрывает правило старого формата (filter OUTPUT)"
        );
    }

    /// Рубеж `:53` обязан стоять в `mangle POSTROUTING`: только там выходной интерфейс —
    /// фактический. В `filter OUTPUT` он ещё прежний, если пакет завернули DNAT'ом в этом же
    /// проходе хуков, и правило `! -o citadel0` убивало собственный завёрнутый DNS.
    #[test]
    fn dns_rules_guard_at_postrouting() {
        for lo in [true, false] {
            for rule in dns_rules("citadel0", lo) {
                let f = s(&rule);
                assert_eq!(&f[..4], &["-t", "mangle", "-A", "POSTROUTING"], "правило {f:?}");
            }
        }
    }

    /// Разрешение `:53` на `lo` обязано идти ДО общего DROP для ТОГО ЖЕ протокола — иначе
    /// локальный stub-резолвер (systemd-resolved) отрезан и DNS не работает вовсе.
    #[test]
    fn dns_loopback_accept_precedes_drop() {
        let r = dns_rules("citadel0", true);
        for proto in ["udp", "tcp"] {
            let of_proto: Vec<&Vec<String>> =
                r.iter().filter(|x| x.contains(&proto.to_string())).collect();
            let accept = of_proto.iter().position(|x| x.last().map(String::as_str) == Some("ACCEPT"));
            let drop = of_proto.iter().position(|x| x.last().map(String::as_str) == Some("DROP"));
            assert!(accept.unwrap() < drop.unwrap(), "{proto}: ACCEPT для lo должен идти раньше DROP");
        }
        // строгий режим: никаких исключений, весь не-туннельный :53 в DROP
        assert!(dns_rules("citadel0", false).iter().all(|x| x.last().map(String::as_str) == Some("DROP")));
    }

    /// Kill-switch выпускает `:53` без проверки интерфейса ТОЛЬКО когда рубеж для DNS поставлен
    /// (`dns_guarded`): иначе цепочка стала бы дырой для любого DNS мимо туннеля.
    #[test]
    fn killswitch_dns_exception_only_when_guarded() {
        let dns_return = |r: &[Vec<String>]| {
            r.iter().any(|x| {
                x.contains(&"53".to_string()) && x.last().map(String::as_str) == Some("RETURN")
            })
        };
        let guarded = killswitch_rules("citadel0", &[], &[], None, true);
        assert!(dns_return(&guarded), "с рубежом DNS обязан выпускаться (иначе заворот мёртв)");
        drop_after_all_returns(&guarded);
        let bare = killswitch_rules("citadel0", &[], &[], None, false);
        assert!(
            !bare.iter().any(|x| x.contains(&"53".to_string())),
            "без рубежа никаких исключений для :53"
        );
        drop_after_all_returns(&bare);
    }

    /// Заворот DNS: исключения (сам резолвер и `lo`) обязаны стоять до DNAT, иначе NAT зациклит
    /// себя на себе, а петлевой пакет уйдёт с чужим адресом источника.
    #[test]
    fn dns_redirect_shape() {
        let dns = Ipv4Addr::new(10, 7, 0, 1);
        let r = dns_redirect_rules(dns, "citadel0");
        assert_eq!(s(r.first().unwrap()), vec!["-t", "nat", "-N", DNS_NAT_CHAIN]);
        let first_dnat =
            r.iter().position(|x| x.contains(&"DNAT".to_string())).expect("правило DNAT");
        let last_return =
            r.iter().rposition(|x| x.last().map(String::as_str) == Some("RETURN")).unwrap();
        assert!(last_return < first_dnat, "исключения должны идти до DNAT");
        assert!(r.iter().any(|x| x.contains(&"10.7.0.1/32".to_string())), "резолвер сам себя не NAT'ит");
        assert!(r.iter().any(|x| x.contains(&"lo".to_string())), "петлевой :53 не переписываем");
        // цель DNAT — именно резолвер туннеля
        assert!(r.iter().filter(|x| x.contains(&"DNAT".to_string())).all(|x| x.contains(&"10.7.0.1:53".to_string())));
        assert_eq!(r.iter().filter(|x| x.contains(&"OUTPUT".to_string())).count(), 2, "обе транспортные ветки");
        // всё уходит в таблицу nat, а не в filter (иначе снесли бы фильтрующие правила)
        assert!(r.iter().all(|x| x[0] == "-t" && x[1] == "nat"));
    }

    /// Цепочка обязана быть подвешена в хук ДО того, как в неё добавят DNAT/MASQUERADE:
    /// `iptables-legacy` считает допустимые хуки по достижимости цепочки и отвергает такое
    /// правило в «висящей» цепочке. Проверяем оба хука (OUTPUT для DNAT, POSTROUTING для SNAT).
    #[test]
    fn dns_redirect_hooks_precede_nat_targets() {
        let r = dns_redirect_rules(Ipv4Addr::new(10, 7, 0, 1), "citadel0");
        let pos = |pred: &dyn Fn(&Vec<String>) -> bool| r.iter().position(pred).unwrap();
        let hook_out = pos(&|x: &Vec<String>| x.contains(&"OUTPUT".to_string()));
        let first_dnat = pos(&|x: &Vec<String>| x.contains(&"DNAT".to_string()));
        assert!(hook_out < first_dnat, "хук в OUTPUT должен стоять до правил DNAT");
        let hook_post = pos(&|x: &Vec<String>| x.contains(&"POSTROUTING".to_string()));
        let first_masq = pos(&|x: &Vec<String>| x.contains(&"MASQUERADE".to_string()));
        assert!(hook_post < first_masq, "хук в POSTROUTING должен стоять до MASQUERADE");
    }

    /// Главный дефект способа-заворота: без SNAT завёрнутый запрос уходит в туннель с адресом
    /// физического интерфейса (DNAT не меняет источник) и гибнет на анти-спуфинге exit'а.
    /// SNAT обязан быть точечным: только `:53` к резолверу туннеля и только на его интерфейсе.
    #[test]
    fn dns_redirect_snats_source_to_tunnel() {
        let r = dns_redirect_rules(Ipv4Addr::new(10, 7, 0, 1), "citadel0");
        let masq: Vec<&Vec<String>> =
            r.iter().filter(|x| x.contains(&"MASQUERADE".to_string())).collect();
        assert_eq!(masq.len(), 2, "SNAT нужен и для udp, и для tcp");
        for m in masq {
            let f = s(m);
            assert!(f.contains(&"-o") && f.contains(&"citadel0"), "только на интерфейсе туннеля");
            assert!(f.contains(&"10.7.0.1/32"), "только к резолверу туннеля");
            assert!(f.contains(&"53"), "только :53");
            assert!(f.contains(&DNS_SNAT_CHAIN), "правило живёт в своей цепочке");
        }
    }

    #[test]
    fn dns_redirect_teardown_removes_hook_and_chain() {
        let down = dns_redirect_teardown();
        assert!(down.iter().all(|x| x[0] == "-t" && x[1] == "nat"));
        // хуки: два из OUTPUT (udp/tcp) + один из POSTROUTING
        assert_eq!(down.iter().filter(|x| x.contains(&"-D".to_string())).count(), 3);
        for chain in [DNS_NAT_CHAIN, DNS_SNAT_CHAIN] {
            assert!(
                down.iter().any(|x| s(x) == vec!["-t", "nat", "-X", chain]),
                "цепочка {chain} должна удаляться"
            );
        }
        // Снятие обязано покрывать ровно то, что ставится (иначе на реконнектах копится/висит).
        let up = dns_redirect_rules(Ipv4Addr::new(10, 7, 0, 1), "citadel0");
        for hook in up.iter().filter(|x| x.contains(&"-I".to_string())) {
            let as_del: Vec<String> = hook
                .iter()
                .filter(|a| a.as_str() != "1") // позиция вставки в `-D` не указывается
                .map(|a| if a == "-I" { "-D".to_string() } else { a.clone() })
                .collect();
            assert!(down.contains(&as_del), "снятие не покрывает хук {hook:?}");
        }
    }

    #[test]
    fn route_get_onlink_vs_via() {
        assert_eq!(
            parse_route_get("192.168.1.50 dev eth0 src 192.168.1.10 uid 1000"),
            Some(PathKind::Onlink { dev: "eth0".into() })
        );
        assert_eq!(
            parse_route_get("8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.10"),
            Some(PathKind::Via { nh: "192.168.1.1".into(), dev: "eth0".into() })
        );
        assert_eq!(parse_route_get("мусор"), None);
        assert_eq!(
            parse_default_route("default via 192.168.1.1 dev eth0 proto dhcp metric 100"),
            Some(("192.168.1.1".into(), "eth0".into()))
        );
        assert_eq!(parse_default_route("default dev ppp0"), None); // без via — nexthop неизвестен
    }
}
