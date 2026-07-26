//! `citadel-helper` — привилегированный TUN-хелпер для desktop-GUI.
//!
//! Запускается из непривилегированного приложения через **polkit/pkexec** (трек C2.3).
//! Делает привилегированную часть: создаёт TUN, настраивает адрес/маршруты/DNS (нужен
//! root/CAP_NET_ADMIN), затем **передаёт fd туннеля** обратно приложению через `SCM_RIGHTS`.
//! Приложение оборачивает fd `citadel_tun::Tun::from_raw_fd` и гоняет data-plane без root.
//!
//! Конфиг приходит **аргументами** (переживают pkexec, в отличие от fd/env):
//! ```text
//! citadel-helper --sock <path> --tun <name> --addr A.B.C.D --prefix N --mtu M \
//!                --routes "r1 r2 ..." [--dns X]
//! ```
//! `--sock` — unix-сокет, который приложение создало и слушает; хелпер подключается и шлёт fd.
//! Держит привилегии до EOF сокета (приложение закрыло = disconnect) → teardown сети.
//!
//! NB: реально работает только под root с CAP_NET_ADMIN — тестируется в QEMU-VM (хост без cap).
//! Юнит-тест ниже проверяет лишь механизм передачи fd (SCM_RIGHTS) — без root/TUN.

use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::process::Command;

use anyhow::{bail, Context, Result};
use citadel_tun::Tun;
use sendfd::SendWithFd;

const RESOLV: &str = "/etc/resolv.conf";
const RESOLV_BAK: &str = "/run/citadel-helper-resolv.bak";

struct Args {
    sock: String,
    tun: String,
    cidr: String,
    mtu: String,
    routes: String,
    dns: Option<String>,
    /// IP exit'ов (через пробел) для bypass-маршрута — исключить из туннеля (анти-петля).
    exit_ips: String,
    /// C8.3 split-tunnel «в обход»: CIDR назначений (через пробел), которые роутятся мимо туннеля
    /// (через физический шлюз) — напр. локальная подсеть/домен/IP. Пусто, если exclude не задан.
    bypass: String,
}

fn parse_args() -> Result<Args> {
    let argv: Vec<String> = std::env::args().collect();
    let mut map = std::collections::HashMap::new();
    let mut i = 1;
    while i < argv.len() {
        // бинарные флаги без значения (обрабатываются в main через argv-скан) — не ломать парность пар
        if argv[i] == "--killswitch" || argv[i] == "--disarm-killswitch" {
            i += 1;
            continue;
        }
        if i + 1 < argv.len() {
            map.insert(argv[i].clone(), argv[i + 1].clone());
        }
        i += 2;
    }
    let get = |k: &str| map.get(k).cloned();
    // S1.2/M1: helper — root (pkexec) от НЕпривилегированного приложения. Валидируем ВСЕ входы
    // (в т.ч. из импортированной citadel://-ссылки) здесь, на границе привилегий: битая/вредоносная
    // строка не должна инъектировать произвольное в ip/iptables/resolv.conf или удалить чужой iface.
    let addr = get("--addr").context("нужен --addr A.B.C.D")?;
    if !is_ip(&addr) {
        bail!("--addr не IP-адрес: {addr:?}");
    }
    let prefix = get("--prefix").unwrap_or_else(|| "24".into());
    if prefix.parse::<u8>().map(|n| n > 32).unwrap_or(true) {
        bail!("--prefix вне 0..=32: {prefix:?}");
    }
    let tun = get("--tun").unwrap_or_else(|| "citadel0".into());
    if !tun.strip_prefix("citadel").is_some_and(|r| r.chars().all(|c| c.is_ascii_digit())) {
        bail!("--tun должен быть citadel<N> (не даём удалить чужой интерфейс): {tun:?}");
    }
    let mtu = get("--mtu").unwrap_or_else(|| "1280".into());
    if mtu.parse::<u32>().is_err() {
        bail!("--mtu не число: {mtu:?}");
    }
    let routes = get("--routes").unwrap_or_default();
    for r in routes.split_whitespace() {
        if !is_cidr(r) {
            bail!("--routes: невалидный CIDR {r:?}");
        }
    }
    let dns = get("--dns");
    if let Some(d) = &dns {
        if !is_ip(d) {
            bail!("--dns не IP-адрес: {d:?} (защита от инъекции в resolv.conf)");
        }
    }
    let exit_ips = get("--exit-ips").unwrap_or_default();
    for e in exit_ips.split_whitespace() {
        if !is_ip(e) {
            bail!("--exit-ips: невалидный IP {e:?}");
        }
    }
    // C8.3: обход по назначению — валидируем как CIDR (та же граница привилегий, что --routes).
    let bypass = get("--bypass").unwrap_or_default();
    for b in bypass.split_whitespace() {
        if !is_cidr(b) {
            bail!("--bypass: невалидный CIDR {b:?}");
        }
        // Охват, а не только форма: «в обход» шире /8 — это уже не исключение, а тихое
        // отключение kill-switch при включённом индикаторе защиты. Тот же порог, что в
        // citadel-vpnd (`valid::MIN_BYPASS_PREFIX`), чтобы у GUI и CLI была одна граница.
        let prefix = b.split_once('/').map(|(_, p)| p).unwrap_or("32");
        if prefix.parse::<u8>().unwrap_or(32) < 8 {
            bail!("--bypass слишком широкий ({b:?}): минимум /8 — иначе это гасит kill-switch");
        }
    }
    Ok(Args {
        sock: get("--sock").context("нужен --sock <path>")?,
        tun,
        cidr: format!("{addr}/{prefix}"),
        mtu,
        routes,
        dns,
        exit_ips,
        bypass,
    })
}

/// S1.2/M1: `s` — один IP-адрес (v4/v6). Отсекает перевод строки/мусор (анти-инъекция).
fn is_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

/// S1.2/M1: `s` — валидный CIDR `IP/prefix` или голый IP (=host-route).
fn is_cidr(s: &str) -> bool {
    match s.split_once('/') {
        Some((a, p)) => {
            let Ok(ip) = a.parse::<std::net::IpAddr>() else { return false };
            p.parse::<u8>().map(|n| n <= if ip.is_ipv4() { 32 } else { 128 }).unwrap_or(false)
        }
        None => is_ip(s),
    }
}

fn ip(args: &[&str]) {
    // stderr в null: команды идемпотентны и fire-and-forget (удаление осиротевшего iface/маршрута
    // на несуществующем — норма); иначе лог засоряется «Cannot find device»/«No such process».
    let _ = Command::new("ip").args(args).stderr(std::process::Stdio::null()).status();
}

/// Текущий default-маршрут `(gateway, dev)` ДО подмены туннелем. Нужен для bypass-маршрутов
/// к exit'ам (иначе full-tunnel заворачивает пакеты к exit обратно в туннель → петля).
fn default_route() -> Option<(String, String)> {
    let out = Command::new("ip").args(["route", "show", "default"]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let toks: Vec<String> = text.lines().next()?.split_whitespace().map(String::from).collect();
    let via = toks.iter().position(|t| t == "via")?;
    let dev = toks.iter().position(|t| t == "dev")?;
    Some((toks.get(via + 1)?.clone(), toks.get(dev + 1)?.clone()))
}

/// Как ядро реально маршрутизирует `probe` СЕЙЧАС (до подмены routes туннелем).
#[derive(Debug, PartialEq)]
enum PathKind {
    /// Назначение достижимо напрямую по подсети (on-link) через `dev` — bypass-маршрут НЕ нужен:
    /// connected-route уже специфичнее /1-половин full-tunnel и держит назначение мимо туннеля.
    /// Перезапись его на `via gw` СЛОМАЛА бы доставку (пакеты локальной подсети ушли бы шлюзу, а не
    /// напрямую по L2) — это и был баг сплита «в обход» для локальной подсети при full-tunnel/KS.
    Onlink { dev: String },
    /// Назначение за шлюзом (`nh`) через `dev` — нужен явный bypass-маршрут /32|CIDR мимо туннеля.
    Via { nh: String, dev: String },
}

/// Разобрать первую строку `ip route get <probe>`: `<dst> [via <nh>] dev <dev> …` (числа локаль-
/// независимы). `via` есть → off-link через шлюз; только `dev` → on-link по подсети. Чистая функция.
fn parse_route_get(first_line: &str) -> Option<PathKind> {
    let t: Vec<&str> = first_line.split_whitespace().collect();
    let dev = t.iter().position(|x| *x == "dev").and_then(|i| t.get(i + 1)).map(|s| s.to_string())?;
    match t.iter().position(|x| *x == "via").and_then(|i| t.get(i + 1)) {
        Some(nh) => Some(PathKind::Via { nh: nh.to_string(), dev }),
        None => Some(PathKind::Onlink { dev }),
    }
}

/// Спросить ядро, как достигается `probe` (до подмены routes туннелем).
fn path_to(probe: &str) -> Option<PathKind> {
    let out = Command::new("ip").args(["route", "get", probe]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    parse_route_get(String::from_utf8_lossy(&out.stdout).lines().next()?)
}

/// Установить bypass-маршрут для `dst` (CIDR/IP) мимо туннеля, СОХРАНИВ фактический nexthop:
/// off-link → `via <nh> dev <dev>`; on-link (локальная подсеть) → НЕ трогаем (connected-route уже
/// держит его мимо туннеля как более специфичный; `replace via gw` сломал бы локалку). Путь берём
/// `ip route get` ДО подмены routes туннелем (иначе вернётся citadel0). Добавленное пишем в `added`
/// для teardown; on-link НЕ добавляем — там нечего откатывать, а `route del` снёс бы connected-route.
fn add_bypass(dst: &str, fallback_gw: &str, fallback_dev: &str, added: &mut Vec<String>) {
    let probe = dst.split('/').next().unwrap_or(dst);
    match path_to(probe) {
        Some(PathKind::Onlink { dev }) => {
            eprintln!("[helper] bypass {dst}: on-link (dev {dev}) — маршрут не нужен (connected-route)");
        }
        Some(PathKind::Via { nh, dev }) => {
            ip(&["route", "replace", dst, "via", &nh, "dev", &dev]);
            added.push(dst.to_string());
        }
        None => {
            // путь не определён — фолбэк на default-шлюз (не регрессим удалённое назначение)
            ip(&["route", "replace", dst, "via", fallback_gw, "dev", fallback_dev]);
            added.push(dst.to_string());
        }
    }
}
fn iptables(args: &[&str]) {
    // stderr в null: idempotent-очистка (напр. teardown_killswitch на несуществующей цепочке при
    // первом арминге) шумит «Chain does not exist» — это ожидаемо, не ошибка.
    let _ = Command::new("iptables").args(args).stderr(std::process::Stdio::null()).status();
}

/// S2.2/A2: то же для IPv6 (`ip6tables`). Туннель — IPv4-only, поэтому нативный IPv6 нигде не
/// заворачивается и без блока утекал бы мимо туннеля И мимо IPv4-kill-switch (деанон на dual-stack).
fn ip6tables(args: &[&str]) {
    let _ = Command::new("ip6tables").args(args).stderr(std::process::Stdio::null()).status();
}

/// F6: резолвер только через туннель + fail-closed на прочий :53 (анти-leak). Бэкапит resolv.conf.
fn setup_dns(ifn: &str, dns: &str) {
    ip(&["route", "replace", &format!("{dns}/32"), "dev", ifn]);
    let _ = std::fs::copy(RESOLV, RESOLV_BAK);
    let _ = std::fs::write(RESOLV, format!("nameserver {dns}\noptions edns0\n"));
    iptables(&["-A", "OUTPUT", "-p", "udp", "--dport", "53", "!", "-o", ifn, "-j", "DROP"]);
    iptables(&["-A", "OUTPUT", "-p", "tcp", "--dport", "53", "!", "-o", ifn, "-j", "DROP"]);
}

/// Свернуть F6 при disconnect: снять DROP-правила и восстановить resolv.conf.
fn teardown_dns(ifn: &str) {
    iptables(&["-D", "OUTPUT", "-p", "udp", "--dport", "53", "!", "-o", ifn, "-j", "DROP"]);
    iptables(&["-D", "OUTPUT", "-p", "tcp", "--dport", "53", "!", "-o", ifn, "-j", "DROP"]);
    let _ = std::fs::copy(RESOLV_BAK, RESOLV);
    let _ = std::fs::remove_file(RESOLV_BAK);
}

/// C6/M9 kill-switch — правила fail-closed firewall (отдельными списками аргументов iptables, чтобы
/// тестировать генерацию без root). Блокируем ВЕСЬ не-туннельный OUTPUT, кроме: lo, самого туннеля
/// (`ifn`), зашифрованного пути к exit'ам (`-d <eip>`), **split-tunnel «в обход» назначений**
/// (`bypass`, C8.1) и DHCP-аренды. Отдельная цепочка `CITADEL_KS` с хуком в начало `OUTPUT` —
/// не трогаем чужую политику. RETURN = разрешено (продолжить OUTPUT), финальный DROP = утечка
/// заблокирована.
///
/// C8.1 (kill-switch ⇄ split-tunnel): назначения из `--bypass` (SplitMode::Exclude) роутятся мимо
/// туннеля через ФИЗИЧЕСКИЙ шлюз, поэтому без RETURN-исключения упёрлись бы в финальный DROP — и
/// сплит «не работал», пока пользователь не гасил kill-switch. RETURN по `-d <cidr>` пускает трафик
/// именно к этим (и только этим) назначениям в обход, сохраняя fail-closed для всего остального.
fn killswitch_rules(ifn: &str, exit_ips: &[&str], bypass: &[&str]) -> Vec<Vec<String>> {
    let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let mut r = vec![
        a(&["-N", "CITADEL_KS"]),
        a(&["-A", "CITADEL_KS", "-o", "lo", "-j", "RETURN"]),
        a(&["-A", "CITADEL_KS", "-o", ifn, "-j", "RETURN"]),
    ];
    for eip in exit_ips {
        r.push(a(&["-A", "CITADEL_KS", "-d", &format!("{eip}/32"), "-j", "RETURN"]));
    }
    // C8.1: split-tunnel «в обход» — разрешить физический путь ТОЛЬКО к выбранным назначениям.
    // `bypass` — уже-валидированные CIDR/host (parse_args); `-d` iptables принимает и CIDR, и голый IP.
    for b in bypass {
        r.push(a(&["-A", "CITADEL_KS", "-d", b, "-j", "RETURN"]));
    }
    // DHCP-аренда (иначе можно потерять IP на физическом линке при full-tunnel)
    r.push(a(&["-A", "CITADEL_KS", "-p", "udp", "--dport", "67:68", "-j", "RETURN"]));
    r.push(a(&["-A", "CITADEL_KS", "-j", "DROP"]));
    r.push(a(&["-I", "OUTPUT", "1", "-j", "CITADEL_KS"]));
    r
}

/// Армировать kill-switch: сперва снять осиротевшую цепочку прошлой сессии (idempotent), затем
/// применить правила.
fn setup_killswitch(ifn: &str, exit_ips: &[&str], bypass: &[&str]) {
    teardown_killswitch();
    for rule in killswitch_rules(ifn, exit_ips, bypass) {
        let args: Vec<&str> = rule.iter().map(String::as_str).collect();
        iptables(&args);
    }
}

/// Снять kill-switch (хук из OUTPUT + цепочка). На ЧИСТЫЙ disconnect или явным `--disarm-killswitch`.
fn teardown_killswitch() {
    iptables(&["-D", "OUTPUT", "-j", "CITADEL_KS"]);
    iptables(&["-F", "CITADEL_KS"]);
    iptables(&["-X", "CITADEL_KS"]);
}

/// S2.2/A2 — правила fail-closed блока IPv6 (`ip6tables`). Туннель IPv4-only ⇒ весь исходящий IPv6
/// (данные + DNS) — это утечка мимо туннеля. RETURN разрешаем только: lo и link-local ND (RS/RA/NS/NA,
/// ICMPv6 133–136 — чтобы не ломать локальный IPv6-стек), всё остальное — DROP. Отдельная цепочка
/// `CITADEL_KS6` с хуком в начало OUTPUT (чужую политику не трогаем).
fn ipv6_block_rules() -> Vec<Vec<String>> {
    let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let mut r = vec![
        a(&["-N", "CITADEL_KS6"]),
        a(&["-A", "CITADEL_KS6", "-o", "lo", "-j", "RETURN"]),
    ];
    for t in ["133", "134", "135", "136"] {
        r.push(a(&["-A", "CITADEL_KS6", "-p", "ipv6-icmp", "--icmpv6-type", t, "-j", "RETURN"]));
    }
    r.push(a(&["-A", "CITADEL_KS6", "-j", "DROP"]));
    r.push(a(&["-I", "OUTPUT", "1", "-j", "CITADEL_KS6"]));
    r
}

/// Армировать IPv6-блок (сперва снять осиротевшую цепочку — idempotent).
fn setup_ipv6_block() {
    teardown_ipv6_block();
    for rule in ipv6_block_rules() {
        let args: Vec<&str> = rule.iter().map(String::as_str).collect();
        ip6tables(&args);
    }
}

/// Снять IPv6-блок (хук из OUTPUT + цепочка). Логика та же, что у kill-switch.
fn teardown_ipv6_block() {
    ip6tables(&["-D", "OUTPUT", "-j", "CITADEL_KS6"]);
    ip6tables(&["-F", "CITADEL_KS6"]);
    ip6tables(&["-X", "CITADEL_KS6"]);
}

fn main() -> Result<()> {
    // Аварийный режим: снять «залипший» kill-switch (остался fail-closed после краха движка) и выйти.
    // Escape hatch для юзера, у которого после краха нет интернета (весь не-туннельный OUTPUT в DROP).
    if std::env::args().any(|a| a == "--disarm-killswitch") {
        teardown_killswitch();
        teardown_ipv6_block(); // S2.2/A2: снять и IPv6-блок (мог остаться fail-closed после краха)
        eprintln!("[helper] kill-switch + IPv6-блок сняты (--disarm-killswitch)");
        return Ok(());
    }
    let args = parse_args()?;
    let killswitch = std::env::args().any(|a| a == "--killswitch");
    // S2.2/A2: full-tunnel (0.0.0.0/0) или kill-switch ⇒ блокируем IPv6 (иначе он утекает мимо
    // IPv4-only туннеля). Split-tunnel без killswitch не трогаем (там IPv6 вне туннеля — намеренно).
    let full_tunnel = args.routes.split_whitespace().any(|r| r == "0.0.0.0/0");
    let block_ipv6 = killswitch || full_tunnel;

    // привилегированная часть: создать TUN + настроить интерфейс (нужен root/CAP_NET_ADMIN).
    // Идемпотентность: снять возможный осиротевший интерфейс от прошлой сессии, иначе
    // TUNSETIFF на занятое имя вернёт EBUSY и реконнект упадёт (ошибку игнорируем — если
    // интерфейса нет, `ip` просто вернёт non-zero).
    ip(&["link", "delete", &args.tun]);
    let tun = Tun::create(&args.tun).context("создать TUN (нужен root/CAP_NET_ADMIN)")?;
    let ifn = tun.name().to_string();
    ip(&["link", "set", &ifn, "mtu", &args.mtu, "up"]);
    ip(&["addr", "add", &args.cidr, "dev", &ifn]);

    // bypass-маршруты к exit'ам ДО применения routes: собственный QUIC/obfs-трафик клиента к
    // exit должен идти физическим шлюзом, а не в citadel0 — иначе при full-tunnel (0.0.0.0/0)
    // пакеты к exit заворачиваются в туннель (петля) и egress встаёт. Захватываем шлюз ДО того,
    // как routes подменят default. Только IPv4 (деплой v4); IPv6-exit пропускаем.
    // bypass-список хранит УЖЕ ГОТОВЫЕ CIDR-строки (для teardown). Нужен физический шлюз, если есть
    // exit'ы (анти-петля) ИЛИ назначения «в обход» (C8.3). Захватываем default ДО подмены routes.
    let mut bypass: Vec<String> = Vec::new();
    let need_gw = args.exit_ips.split_whitespace().next().is_some()
        || args.bypass.split_whitespace().next().is_some();
    if need_gw {
        match default_route() {
            Some((gw, dev)) => {
                // exit-IP (IPv4) → host-route /32 мимо туннеля (nexthop сохраняем per-dst)
                for eip in args.exit_ips.split_whitespace().filter(|e| !e.contains(':')) {
                    add_bypass(&format!("{eip}/32"), &gw, &dev, &mut bypass);
                }
                // C8.3 «в обход»: CIDR назначений (IPv4) мимо туннеля; локальная подсеть = on-link,
                // её connected-route держит мимо туннеля сама — add_bypass её НЕ трогает (иначе баг).
                for b in args.bypass.split_whitespace().filter(|b| !b.contains(':')) {
                    add_bypass(b, &gw, &dev, &mut bypass);
                }
                eprintln!("[helper] bypass (gw {gw} dev {dev}) добавлено via-маршрутов: {:?}", bypass);
            }
            None => eprintln!("[helper] WARN: нет default-route — bypass не добавлен (риск петли/утечки)"),
        }
    }

    for r in args.routes.split_whitespace() {
        if r == "0.0.0.0/0" {
            // full-tunnel БЕЗ клоббера физического default: две /1-половины перекрывают default
            // (более специфичны), но `default via GW dev <phys>` остаётся — он нужен как nexthop
            // для bypass-маршрутов к exit И для восстановления связи после disconnect (иначе
            // `replace 0.0.0.0/0 dev citadel0` затирал бы физический default безвозвратно).
            ip(&["route", "replace", "0.0.0.0/1", "dev", &ifn]);
            ip(&["route", "replace", "128.0.0.0/1", "dev", &ifn]);
        } else {
            ip(&["route", "replace", r, "dev", &ifn]);
        }
    }
    if let Some(dns) = &args.dns {
        setup_dns(&ifn, dns);
    }
    if killswitch {
        let eips: Vec<&str> = args.exit_ips.split_whitespace().collect();
        // C8.1: split-tunnel «в обход» (Exclude) сосуществует с kill-switch — эти назначения идут
        // физическим шлюзом и получают RETURN-исключение (иначе упёрлись бы в финальный DROP).
        let bypass_dsts: Vec<&str> = args.bypass.split_whitespace().collect();
        setup_killswitch(&ifn, &eips, &bypass_dsts);
        eprintln!(
            "[helper] kill-switch АРМИРОВАН (fail-closed): не-туннельный OUTPUT заблокирован{}",
            if bypass_dsts.is_empty() {
                String::new()
            } else {
                format!(" (сплит-обход разрешён к: {})", bypass_dsts.join(" "))
            }
        );
    }
    if block_ipv6 {
        setup_ipv6_block();
        eprintln!(
            "[helper] S2.2/A2: IPv6 заблокирован (fail-closed) — туннель IPv4-only, IPv6 не утечёт (причина: {})",
            if killswitch { "kill-switch" } else { "full-tunnel" }
        );
    }
    eprintln!("[helper] TUN '{ifn}' {} up; передаю fd приложению", args.cidr);

    // передать fd туннеля непривилегированному приложению (SCM_RIGHTS)
    let mut stream = UnixStream::connect(&args.sock)
        .with_context(|| format!("подключиться к управляющему сокету {}", args.sock))?;
    stream
        .send_with_fd(b"T", &[tun.as_raw_fd()])
        .context("передать TUN-fd по SCM_RIGHTS")?;

    // держим привилегии (и tun-fd) до EOF: приложение закрыло сокет = disconnect/выход
    eprintln!("[helper] fd передан; держу сеть до disconnect");
    // Читаем управляющий сокет до EOF. Чистый disconnect: приложение шлёт байт 'Q' ПЕРЕД закрытием
    // → снимаем kill-switch. Краш/аварийный разрыв (EOF без 'Q') → kill-switch ОСТАЁТСЯ (fail-closed:
    // трафик заблокирован, не утекает). Прочий teardown (DNS/bypass/TUN) выполняется всегда.
    let mut clean = false;
    let mut buf = [0u8; 16];
    while let Ok(n) = stream.read(&mut buf) {
        if n == 0 {
            break; // EOF
        }
        if buf[..n].contains(&b'Q') {
            clean = true;
        }
    }
    if args.dns.is_some() {
        teardown_dns(&ifn);
    }
    for cidr in &bypass {
        ip(&["route", "del", cidr]);
    }
    if killswitch {
        if clean {
            teardown_killswitch();
            eprintln!("[helper] чистый disconnect — kill-switch снят");
        } else {
            eprintln!("[helper] АВАРИЙНЫЙ разрыв (без 'Q') — kill-switch ОСТАВЛЕН (fail-closed). \
                       Снять вручную: pkexec citadel-helper --disarm-killswitch");
        }
    }
    // S2.2/A2: IPv6-блок снимаем на чистый disconnect ВСЕГДА; на аварийный (краш) — оставляем
    // ТОЛЬКО при killswitch (fail-closed, как KS). Без killswitch (блок был из-за full-tunnel) —
    // снимаем, чтобы после падения движка IPv6-связность восстановилась (как и IPv4 без KS).
    if block_ipv6 {
        if killswitch && !clean {
            eprintln!("[helper] IPv6-блок ОСТАВЛЕН (fail-closed, аварийный разрыв). \
                       Снять вручную: pkexec citadel-helper --disarm-killswitch");
        } else {
            teardown_ipv6_block();
        }
    }
    // TUN-интерфейс исчезает сам, когда приложение закрывает свой (переданный) fd.
    eprintln!("[helper] disconnect — сеть свёрнута, выход");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sendfd::RecvWithFd;
    use std::io::Write as _; // Read приходит из super::* (main импортит std::io::Read)
    use std::os::fd::FromRawFd;

    #[test]
    fn ip_cidr_validation() {
        assert!(is_ip("1.1.1.1") && is_ip("2606:4700:4700::1111"));
        assert!(!is_ip("1.1.1.1\nnameserver 6.6.6.6")); // инъекция перевода строки → отказ
        assert!(!is_ip("not-ip"));
        assert!(is_cidr("10.0.0.0/8") && is_cidr("1.1.1.1"));
        assert!(!is_cidr("1.1.1.1/40") && !is_cidr("junk"));
    }

    /// `ip route get`: on-link (только `dev`) vs off-link (`via <nh> dev`). On-link bypass-назначения
    /// (локальная подсеть) НЕ должны получать `via gw` — иначе рвётся доставка по подсети (баг сплита).
    #[test]
    fn route_get_onlink_vs_via() {
        assert_eq!(
            parse_route_get("192.168.1.50 dev eth0 src 192.168.1.10 uid 1000"),
            Some(PathKind::Onlink { dev: "eth0".into() })
        );
        assert_eq!(
            parse_route_get("8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.10 uid 1000"),
            Some(PathKind::Via { nh: "192.168.1.1".into(), dev: "eth0".into() })
        );
        assert_eq!(parse_route_get("unreachable-garbage"), None); // нет dev → None
    }

    /// SCM_RIGHTS round-trip БЕЗ root/TUN: передаём read-конец pipe через socketpair и
    /// убеждаемся, что принятый fd указывает на ту же трубу (механизм передачи fd работает).
    #[test]
    fn scm_rights_fd_roundtrip() {
        let (sender, receiver) = UnixStream::pair().unwrap();

        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (r, w) = (fds[0], fds[1]);

        sender.send_with_fd(b"X", &[r]).unwrap();

        let mut buf = [0u8; 8];
        let mut rfds = [0i32; 1];
        let (n, fdn) = receiver.recv_with_fd(&mut buf, &mut rfds).unwrap();
        assert_eq!((n, fdn), (1, 1));

        // пишем в исходный конец трубы, читаем из ПРИНЯТОГО fd — должно совпасть
        let mut wf = unsafe { std::fs::File::from_raw_fd(w) };
        wf.write_all(b"hi").unwrap();
        let mut rf = unsafe { std::fs::File::from_raw_fd(rfds[0]) };
        let mut got = [0u8; 2];
        rf.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"hi");

        unsafe { libc::close(r) }; // оригинальный r (приёмник получил dup); wf/rf закроются при drop
    }

    /// C6/M9: правила kill-switch — форма и fail-closed порядок (DROP ПОСЛЕ всех RETURN; хук в OUTPUT).
    #[test]
    fn killswitch_rules_shape() {
        let r = killswitch_rules("citadel0", &["1.2.3.4", "5.6.7.8"], &[]);
        fn s(v: &[String]) -> Vec<&str> {
            v.iter().map(String::as_str).collect()
        }
        // цепочка создаётся первой, хук в OUTPUT — последним
        assert_eq!(s(r.first().unwrap()), vec!["-N", "CITADEL_KS"]);
        assert_eq!(s(r.last().unwrap()), vec!["-I", "OUTPUT", "1", "-j", "CITADEL_KS"]);
        // lo + туннель + оба exit'а разрешены (RETURN)
        assert!(r.iter().any(|x| s(x) == vec!["-A", "CITADEL_KS", "-o", "lo", "-j", "RETURN"]));
        assert!(r.iter().any(|x| s(x) == vec!["-A", "CITADEL_KS", "-o", "citadel0", "-j", "RETURN"]));
        let flat: Vec<&str> = r.iter().flatten().map(String::as_str).collect();
        assert!(flat.contains(&"1.2.3.4/32") && flat.contains(&"5.6.7.8/32"));
        // fail-closed: финальный DROP идёт ПОСЛЕ всех RETURN (иначе трафик утёк бы)
        let drop_idx = r.iter().position(|x| x.last().map(String::as_str) == Some("DROP")).unwrap();
        let last_return =
            r.iter().rposition(|x| x.last().map(String::as_str) == Some("RETURN")).unwrap();
        assert!(drop_idx > last_return, "DROP должен быть после всех RETURN (fail-closed)");
    }

    /// C8.1: kill-switch ⇄ split-tunnel. Назначения «в обход» (Exclude) получают RETURN по `-d <cidr>`
    /// (пускаются физическим шлюзом), при этом fail-closed сохранён (финальный DROP после всех RETURN).
    #[test]
    fn killswitch_bypass_coexists_with_split() {
        let bypass = ["192.168.1.0/24", "203.0.113.7"];
        let r = killswitch_rules("citadel0", &["1.2.3.4"], &bypass);
        fn s(v: &[String]) -> Vec<&str> {
            v.iter().map(String::as_str).collect()
        }
        // каждое split-назначение — отдельное RETURN-исключение по dst
        for b in bypass {
            assert!(
                r.iter().any(|x| s(x) == vec!["-A", "CITADEL_KS", "-d", b, "-j", "RETURN"]),
                "split-обход {b} должен быть RETURN (иначе сплит не работает при KS)"
            );
        }
        // exit-IP по-прежнему разрешён; fail-closed не нарушен: DROP после всех RETURN (в т.ч. bypass)
        let flat: Vec<&str> = r.iter().flatten().map(String::as_str).collect();
        assert!(flat.contains(&"1.2.3.4/32"));
        let drop_idx = r.iter().position(|x| x.last().map(String::as_str) == Some("DROP")).unwrap();
        let last_return =
            r.iter().rposition(|x| x.last().map(String::as_str) == Some("RETURN")).unwrap();
        assert!(drop_idx > last_return, "DROP должен быть после всех RETURN, включая split-обход");
    }

    /// S2.2/A2: правила IPv6-блока — своя цепочка `CITADEL_KS6`, хук в OUTPUT, RETURN только для lo
    /// и link-local ND (ICMPv6 133–136), финальный DROP ПОСЛЕ всех RETURN (fail-closed, без утечки).
    #[test]
    fn ipv6_block_rules_shape() {
        let r = ipv6_block_rules();
        fn s(v: &[String]) -> Vec<&str> {
            v.iter().map(String::as_str).collect()
        }
        assert_eq!(s(r.first().unwrap()), vec!["-N", "CITADEL_KS6"]);
        assert_eq!(s(r.last().unwrap()), vec!["-I", "OUTPUT", "1", "-j", "CITADEL_KS6"]);
        assert!(r.iter().any(|x| s(x) == vec!["-A", "CITADEL_KS6", "-o", "lo", "-j", "RETURN"]));
        // ND-типы разрешены (иначе локальный IPv6-стек ломается)
        for t in ["133", "134", "135", "136"] {
            assert!(
                r.iter().any(|x| s(x)
                    == vec!["-A", "CITADEL_KS6", "-p", "ipv6-icmp", "--icmpv6-type", t, "-j", "RETURN"]),
                "ICMPv6 {t} (ND) должен быть RETURN"
            );
        }
        // fail-closed: DROP после всех RETURN
        let drop_idx = r.iter().position(|x| x.last().map(String::as_str) == Some("DROP")).unwrap();
        let last_return =
            r.iter().rposition(|x| x.last().map(String::as_str) == Some("RETURN")).unwrap();
        assert!(drop_idx > last_return, "DROP должен быть после всех RETURN (fail-closed IPv6)");
    }
}
