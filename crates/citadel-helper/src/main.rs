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

use anyhow::{Context, Result};
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
}

fn parse_args() -> Result<Args> {
    let argv: Vec<String> = std::env::args().collect();
    let mut map = std::collections::HashMap::new();
    let mut i = 1;
    while i + 1 < argv.len() {
        map.insert(argv[i].clone(), argv[i + 1].clone());
        i += 2;
    }
    let get = |k: &str| map.get(k).cloned();
    let addr = get("--addr").context("нужен --addr A.B.C.D")?;
    let prefix = get("--prefix").unwrap_or_else(|| "24".into());
    Ok(Args {
        sock: get("--sock").context("нужен --sock <path>")?,
        tun: get("--tun").unwrap_or_else(|| "citadel0".into()),
        cidr: format!("{addr}/{prefix}"),
        mtu: get("--mtu").unwrap_or_else(|| "1280".into()),
        routes: get("--routes").unwrap_or_default(),
        dns: get("--dns"),
    })
}

fn ip(args: &[&str]) {
    let _ = Command::new("ip").args(args).status();
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

fn main() -> Result<()> {
    let args = parse_args()?;

    // привилегированная часть: создать TUN + настроить интерфейс (нужен root/CAP_NET_ADMIN).
    // Идемпотентность: снять возможный осиротевший интерфейс от прошлой сессии, иначе
    // TUNSETIFF на занятое имя вернёт EBUSY и реконнект упадёт (ошибку игнорируем — если
    // интерфейса нет, `ip` просто вернёт non-zero).
    ip(&["link", "delete", &args.tun]);
    let tun = Tun::create(&args.tun).context("создать TUN (нужен root/CAP_NET_ADMIN)")?;
    let ifn = tun.name().to_string();
    ip(&["link", "set", &ifn, "mtu", &args.mtu, "up"]);
    ip(&["addr", "add", &args.cidr, "dev", &ifn]);
    for r in args.routes.split_whitespace() {
        ip(&["route", "replace", r, "dev", &ifn]);
    }
    if let Some(dns) = &args.dns {
        setup_dns(&ifn, dns);
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
    let mut buf = [0u8; 16];
    while let Ok(n) = stream.read(&mut buf) {
        if n == 0 {
            break; // EOF
        }
    }
    if args.dns.is_some() {
        teardown_dns(&ifn);
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
}
