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
    Ok(Args {
        sock: get("--sock").context("нужен --sock <path>")?,
        tun,
        cidr: format!("{addr}/{prefix}"),
        mtu,
        routes,
        dns,
        exit_ips,
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
    let _ = Command::new("ip").args(args).status();
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
fn iptables(args: &[&str]) {
    let _ = Command::new("iptables").args(args).status();
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
/// (`ifn`), зашифрованного пути к exit'ам (`-d <eip>`) и DHCP-аренды. Отдельная цепочка `CITADEL_KS`
/// с хуком в начало `OUTPUT` — не трогаем чужую политику. RETURN = разрешено (продолжить OUTPUT),
/// финальный DROP = утечка заблокирована.
fn killswitch_rules(ifn: &str, exit_ips: &[&str]) -> Vec<Vec<String>> {
    let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let mut r = vec![
        a(&["-N", "CITADEL_KS"]),
        a(&["-A", "CITADEL_KS", "-o", "lo", "-j", "RETURN"]),
        a(&["-A", "CITADEL_KS", "-o", ifn, "-j", "RETURN"]),
    ];
    for eip in exit_ips {
        r.push(a(&["-A", "CITADEL_KS", "-d", &format!("{eip}/32"), "-j", "RETURN"]));
    }
    // DHCP-аренда (иначе можно потерять IP на физическом линке при full-tunnel)
    r.push(a(&["-A", "CITADEL_KS", "-p", "udp", "--dport", "67:68", "-j", "RETURN"]));
    r.push(a(&["-A", "CITADEL_KS", "-j", "DROP"]));
    r.push(a(&["-I", "OUTPUT", "1", "-j", "CITADEL_KS"]));
    r
}

/// Армировать kill-switch: сперва снять осиротевшую цепочку прошлой сессии (idempotent), затем
/// применить правила.
fn setup_killswitch(ifn: &str, exit_ips: &[&str]) {
    teardown_killswitch();
    for rule in killswitch_rules(ifn, exit_ips) {
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

fn main() -> Result<()> {
    // Аварийный режим: снять «залипший» kill-switch (остался fail-closed после краха движка) и выйти.
    // Escape hatch для юзера, у которого после краха нет интернета (весь не-туннельный OUTPUT в DROP).
    if std::env::args().any(|a| a == "--disarm-killswitch") {
        teardown_killswitch();
        eprintln!("[helper] kill-switch снят (--disarm-killswitch)");
        return Ok(());
    }
    let args = parse_args()?;
    let killswitch = std::env::args().any(|a| a == "--killswitch");

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
    let mut bypass: Vec<String> = Vec::new();
    if args.exit_ips.split_whitespace().next().is_some() {
        match default_route() {
            Some((gw, dev)) => {
                for eip in args.exit_ips.split_whitespace().filter(|e| !e.contains(':')) {
                    ip(&["route", "replace", &format!("{eip}/32"), "via", &gw, "dev", &dev]);
                    bypass.push(eip.to_string());
                }
                eprintln!("[helper] bypass exit'ов {:?} via {gw} dev {dev}", bypass);
            }
            None => eprintln!("[helper] WARN: нет default-route — bypass к exit не добавлен (риск петли)"),
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
        setup_killswitch(&ifn, &eips);
        eprintln!("[helper] kill-switch АРМИРОВАН (fail-closed): не-туннельный OUTPUT заблокирован");
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
    for eip in &bypass {
        ip(&["route", "del", &format!("{eip}/32")]);
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
        let r = killswitch_rules("citadel0", &["1.2.3.4", "5.6.7.8"]);
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
}
