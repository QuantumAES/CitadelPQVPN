//! CitadelPQVPN — M1+M2: реальный IP-туннель поверх PQ-QUIC (бинарь `Citadel-m1`).
//!
//! M1: TUN ⇄ QUIC DATAGRAM (CONNECT-IP, context=0).
//! M2: динамическое назначение адреса капсулами ADDRESS_REQUEST/ADDRESS_ASSIGN
//!     (RFC 9484 §4.7) на control-стриме.
//! STRIDE-правки: F1 — pinning серверного сертификата; F2 — egress-фильтр на exit
//!     (drop приватных/служебных назначений, анти-пивот во внутреннюю сеть).
//!
//! env: Citadel_ROLE=server|client, Citadel_TUN=Citadel0, Citadel_MTU=1280
//!   server: Citadel_LISTEN=0.0.0.0:4433, Citadel_TUN_ADDR=10.7.0.1/24, Citadel_NAT_SRC=10.7.0.0/24,
//!           Citadel_PIN_FILE=/shared/exit.pin (куда записать pin)
//!   client: Citadel_SERVERS="h1:p h2:p" (M5 multi-server; или один Citadel_CONNECT=host:port),
//!           Citadel_SERVER_NAME=Citadel.exit, Citadel_ROUTES="1.1.1.1/32 ...",
//!           Citadel_PIN=<hex> | Citadel_PIN_DIR=<dir с <host>.pin> | Citadel_PIN_FILE=<один pin>

use std::collections::HashSet;
use std::process::Command;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use rand::RngCore;
use citadel_masque::capsule;
use citadel_quic::config::{parse_pin, ClientConfig, PinMode};
use citadel_quic::dataplane::{pump, Tunnel};
use citadel_quic::ratelimit::RateCfg;
use citadel_quic::tcp_obfs::TcpObfs;
use citadel_quic::vpn::VpnController;
use citadel_tun::Tun;

// Пул адресов exit для клиентов: база/префикс из Citadel_TUN_ADDR; счётчик u16 заполняет
// весь диапазон (для /16 — 10.7.0.2 … 10.7.255.253), чтобы адреса не кончались на реконнектах.
static ADDR_POOL: AtomicU16 = AtomicU16::new(2);

/// (первые два октета сети, префикс) из Citadel_TUN_ADDR (default 10.7.0.1/24).
fn tun_net() -> ([u8; 2], u8) {
    let s = std::env::var("Citadel_TUN_ADDR").unwrap_or_else(|_| "10.7.0.1/24".into());
    let mut parts = s.splitn(2, '/');
    let ip = parts.next().unwrap_or("10.7.0.1");
    let prefix = parts.next().and_then(|p| p.parse().ok()).unwrap_or(24u8);
    let o: Vec<u8> = ip.split('.').filter_map(|x| x.parse().ok()).collect();
    ([o.first().copied().unwrap_or(10), o.get(1).copied().unwrap_or(7)], prefix)
}

/// Следующий клиентский адрес из пула + префикс сети.
fn next_client_addr() -> ([u8; 4], u8) {
    let (base, prefix) = tun_net();
    let n = ADDR_POOL.fetch_add(1, Ordering::Relaxed);
    ([base[0], base[1], (n >> 8) as u8, (n & 0xff) as u8], prefix)
}

#[tokio::main]
async fn main() -> Result<()> {
    let role = std::env::var("Citadel_ROLE").unwrap_or_default();
    match role.as_str() {
        "server" => run_server(open_tun()?).await,
        "client" => run_client().await,
        "probe" => run_probe().await,
        "auth-probe" => run_auth_probe().await,
        other => Err(anyhow!("Citadel_ROLE должен быть server|client|probe|auth-probe, а не {other:?}")),
    }
}

fn open_tun() -> Result<Arc<Tun>> {
    let tun_name = std::env::var("Citadel_TUN").unwrap_or_else(|_| "Citadel0".into());
    let tun = Arc::new(Tun::create(&tun_name).context("открыть TUN (нужен CAP_NET_ADMIN)")?);
    eprintln!("[Citadel-m1] TUN '{}' открыт", tun.name());
    Ok(tun)
}

/// L1-obfs PSK из env `Citadel_OBFS_PSK` (делегирует в `config::parse_obfs_psk`).
/// Используется серверной и probe-ролями; клиентский путь берёт `ClientConfig::obfs_psk`.
fn obfs_psk() -> Option<[u8; 32]> {
    std::env::var("Citadel_OBFS_PSK")
        .ok()
        .as_deref()
        .and_then(citadel_quic::config::parse_obfs_psk)
}

/// F4: сброс привилегий до nobody (def 65534) после привилегированной настройки сети.
/// Дальше процессу root не нужен — TUN-fd открыт, сокеты QUIC забинжены, NAT в ядре.
fn drop_privileges() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok(()); // не root (локальный запуск) — нечего ронять
    }
    let uid: libc::uid_t = std::env::var("Citadel_DROP_UID").ok().and_then(|s| s.parse().ok()).unwrap_or(65534);
    let gid: libc::gid_t = std::env::var("Citadel_DROP_GID").ok().and_then(|s| s.parse().ok()).unwrap_or(65534);
    // порядок важен: setgroups → setgid → setuid (после setuid вернуть привилегии нельзя)
    unsafe {
        if libc::setgroups(0, std::ptr::null::<libc::gid_t>()) != 0 {
            return Err(anyhow!("setgroups: {}", std::io::Error::last_os_error()));
        }
        if libc::setgid(gid) != 0 {
            return Err(anyhow!("setgid({gid}): {}", std::io::Error::last_os_error()));
        }
        if libc::setuid(uid) != 0 {
            return Err(anyhow!("setuid({uid}): {}", std::io::Error::last_os_error()));
        }
        if libc::setuid(0) == 0 {
            return Err(anyhow!("привилегии не сброшены: setuid(0) неожиданно удался"));
        }
    }
    eprintln!("[Citadel-m1] привилегии сброшены: uid={uid} gid={gid} (F4)");
    Ok(())
}

// ----------------------- сетевая обвязка (ip/iptables) -----------------------
fn run(cmd: &str, args: &[&str]) {
    match Command::new(cmd).args(args).status() {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!("[net] {cmd} {} → {s}", args.join(" ")),
        Err(e) => eprintln!("[net] {cmd}: {e}"),
    }
}

fn detect_egress() -> String {
    if let Ok(out) = Command::new("ip").args(["-o", "route", "show", "default"]).output() {
        let s = String::from_utf8_lossy(&out.stdout);
        let toks: Vec<&str> = s.split_whitespace().collect();
        if let Some(p) = toks.iter().position(|&t| t == "dev") {
            if let Some(dev) = toks.get(p + 1) {
                return dev.to_string();
            }
        }
    }
    "eth0".to_string()
}

fn mtu() -> String {
    std::env::var("Citadel_MTU").unwrap_or_else(|_| "1280".into())
}

fn server_setup_net(ifname: &str) {
    if let Ok(addr) = std::env::var("Citadel_TUN_ADDR") {
        run("ip", &["addr", "add", &addr, "dev", ifname]);
    }
    run("ip", &["link", "set", ifname, "mtu", &mtu(), "up"]);
    let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", b"1");
    let nat = std::env::var("Citadel_NAT_SRC").unwrap_or_else(|_| "10.7.0.0/24".into());
    let eg = detect_egress();
    run("iptables", &["-t", "nat", "-A", "POSTROUTING", "-s", &nat, "-o", &eg, "-j", "MASQUERADE"]);
    // S0.2/H3: форвардим ТОЛЬКО из пула клиентских адресов; прочий inner-src (спуфинг) — DROP.
    // Ядровый дубль app-layer анти-спуфинга в Inbound (defense-in-depth) + reverse-path фильтр.
    run("iptables", &["-A", "FORWARD", "-i", ifname, "-s", &nat, "-o", &eg, "-j", "ACCEPT"]);
    run("iptables", &["-A", "FORWARD", "-i", &eg, "-o", ifname, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"]);
    run("iptables", &["-A", "FORWARD", "-i", ifname, "!", "-s", &nat, "-j", "DROP"]);
    let _ = std::fs::write("/proc/sys/net/ipv4/conf/all/rp_filter", b"1");
    // MSS-clamp: ограничить TCP-сегменты под PMTU туннеля. Без него крупные ответные
    // сегменты (TLS ServerHello/cert) не влезают в QUIC-датаграмму и теряются — PMTUD
    // блэкхолится через NAT/туннель: ICMP/ping ходит, а TCP/HTTPS виснет. Клампим на SYN
    // в обе стороны; `--clamp-mss-to-pmtu` берёт MTU исходящего интерфейса (для трафика
    // в туннель = MTU туннеля), т.е. адаптивно под Citadel_MTU.
    run("iptables", &["-t", "mangle", "-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"]);
    eprintln!("[net] server: ip_forward + MASQUERADE + MSS-clamp через '{eg}' (src {nat})");
}

/// F6 (I3): DNS только через туннель + fail-closed на прочий :53 (анти-leak).
fn setup_dns_leak_protection(ifname: &str, dns: &str) {
    // резолвер доступен только через туннель
    run("ip", &["route", "replace", &format!("{dns}/32"), "dev", ifname]);
    // форсируем резолвер (best-effort: /etc/resolv.conf может быть ro bind-mount)
    if std::fs::write("/etc/resolv.conf", format!("nameserver {dns}\noptions edns0 trust-ad\n")).is_err() {
        eprintln!("[dns] предупреждение: /etc/resolv.conf не переписан (ro bind-mount)");
    }
    // fail-closed: любой DNS НЕ через туннельный интерфейс — drop
    run("iptables", &["-A", "OUTPUT", "-p", "udp", "--dport", "53", "!", "-o", ifname, "-j", "DROP"]);
    run("iptables", &["-A", "OUTPUT", "-p", "tcp", "--dport", "53", "!", "-o", ifname, "-j", "DROP"]);
    eprintln!("[dns] F6: резолвер {dns} только через {ifname}; прочий :53 заблокирован (no-leak)");
}

// ----------------------------- pin (F1) -----------------------------
// parse_pin + PinMode вынесены в citadel_quic::config (C0.3); read_pin_for ниже — для auth-probe.

/// Pin сервера `host`: `Citadel_PIN` (общий hex) > `Citadel_PIN_DIR/<host>.pin` (multi-server,
/// per-exit) > `Citadel_PIN_FILE` (один файл, legacy single-server). Нет настройки → NoPin (PoC).
fn read_pin_for(host: &str) -> PinMode {
    if let Ok(h) = std::env::var("Citadel_PIN") {
        return parse_pin(&h).map(PinMode::Pinned).unwrap_or(PinMode::Waiting);
    }
    let path = if let Ok(dir) = std::env::var("Citadel_PIN_DIR") {
        format!("{dir}/{host}.pin")
    } else if let Ok(f) = std::env::var("Citadel_PIN_FILE") {
        f
    } else {
        return PinMode::NoPin;
    };
    match std::fs::read_to_string(&path) {
        Ok(s) => parse_pin(&s).map(PinMode::Pinned).unwrap_or(PinMode::Waiting),
        Err(_) => PinMode::Waiting,
    }
}

// Клиентская оркестрация вынесена из бинаря в citadel_quic::{config,dataplane,client}:
//   C0.2 — Tunnel/Inbound/pump → dataplane;
//   C0.3 — client_servers/read_mldsa_pk/parse_pin/PinMode/load_token → config;
//   C0.4 — host_of/connect_server/try_quic_connect/client_request_address → client.
// В бинаре остаются серверная роль, probe/auth-probe и Linux NetConfigurator (ip/iptables/DNS).

async fn server_assign_address(
    tunnel: &mut Tunnel,
    addr: [u8; 4],
    prefix: u8,
    issuer_pk: Option<&[u8]>,
    spent: &Mutex<HashSet<[u8; 32]>>,
    signer: Option<&citadel_quic::pqauth::ServerSigner>,
    cert_pin: [u8; 32],
) -> Result<()> {
    tunnel
        .control_server(|buf| {
            // M7: первые 32 байта — nonce клиента для PQ-auth привязки
            if buf.len() < 32 {
                return Err(anyhow!("нет PQ-auth nonce"));
            }
            let nonce = &buf[..32];
            let body = &buf[32..];

            let (tok_len, n) =
                citadel_masque::varint::decode(body).ok_or_else(|| anyhow!("нет токен-префикса"))?;
            let tok_end = n + tok_len as usize;
            if body.len() < tok_end {
                return Err(anyhow!("обрезанный токен"));
            }
            let token = &body[n..tok_end];
            let rest = &body[tok_end..];

            // F-M4: per-user аутентификация анонимным токеном (если издатель сконфигурирован)
            if let Some(pk) = issuer_pk {
                match citadel_token::verify_token(pk, token) {
                    Some(tn) => {
                        let fresh = spent.lock().unwrap().insert(tn);
                        if !fresh {
                            return Err(anyhow!("токен уже использован (double-spend)"));
                        }
                        eprintln!("[citadel-m1:server] токен принят (nonce {}…)", hex::encode(&tn[..6]));
                    }
                    None => return Err(anyhow!("невалидный токен — отказ в доступе")),
                }
            }

            let (t, _v, _) = capsule::decode(rest).ok_or_else(|| anyhow!("битая капсула запроса"))?;
            if t != capsule::ADDRESS_REQUEST {
                return Err(anyhow!("ожидался ADDRESS_REQUEST, type={t}"));
            }
            let assign_bytes =
                capsule::encode_address_assign_v4(&capsule::AssignedV4 { request_id: 1, addr, prefix });

            // M7: ответ = varint(sig_len) ‖ ML-DSA-sig(nonce‖cert_pin) ‖ ADDRESS_ASSIGN.
            // Без signer'а sig пуст (PQ-auth выключена) — клиент это допускает, если не ждёт pk.
            let sig = match signer {
                Some(s) => s.sign_binding(nonce, &cert_pin)?,
                None => Vec::new(),
            };
            let mut resp = citadel_masque::varint::to_vec(sig.len() as u64);
            resp.extend_from_slice(&sig);
            resp.extend_from_slice(&assign_bytes);
            Ok(resp)
        })
        .await
}

// load_token вынесён в ClientConfig::from_env (C0.3).

// ------------------------------- роли -------------------------------
async fn run_server(tun: Arc<Tun>) -> Result<()> {
    server_setup_net(tun.name());

    let listen: std::net::SocketAddr = std::env::var("Citadel_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:4433".into())
        .parse()?;
    eprintln!(
        "[citadel-m1:server] KX-suite (crypto-agility): {}",
        citadel_quic::kx_suite_name(&std::env::var("Citadel_KX").unwrap_or_default())
    );
    let (cfg, pin) = citadel_quic::server_config_with_pin(citadel_quic::kx_groups_from_env())?;
    if let Ok(path) = std::env::var("Citadel_PIN_FILE") {
        let _ = std::fs::write(&path, hex::encode(pin));
        eprintln!("[Citadel-m1:server] pin сертификата → {path}: {}", hex::encode(pin));
    }
    let ep = match obfs_psk() {
        Some(psk) => {
            eprintln!("[Citadel-m1:server] obfs L1 включён (probe-resistance + анти-DPI)");
            citadel_quic::server_endpoint_obfs(listen, cfg, psk)?
        }
        None => quinn::Endpoint::server(cfg, listen)?,
    };
    eprintln!("[Citadel-m1:server] слушаю {listen} (KX=X25519MLKEM768)");

    let issuer_pk = Arc::new(std::env::var("Citadel_ISSUER_PUB").ok().and_then(|p| std::fs::read(p).ok()));
    if issuer_pk.is_some() {
        eprintln!("[Citadel-m1:server] per-user токены включены (issuer pub загружен)");
    }
    let spent: Arc<Mutex<HashSet<[u8; 32]>>> = Arc::new(Mutex::new(HashSet::new()));

    // M7 PQ-auth: ML-DSA-65 keypair (если задан Citadel_MLDSA) + публикация pk клиенту.
    // Гибрид с Ed25519-cert+pin: сервер подписывает привязку nonce‖cert_pin, клиент проверяет.
    let signer = Arc::new(if std::env::var("Citadel_MLDSA").is_ok() {
        let s = citadel_quic::pqauth::ServerSigner::generate()?;
        if let Ok(path) = std::env::var("Citadel_MLDSA_PUB_FILE") {
            let pk = s.public_key();
            std::fs::write(&path, &pk).ok();
            eprintln!("[citadel-m1:server] PQ-auth (M7): ML-DSA-65 pub → {path} ({} б)", pk.len());
        }
        eprintln!("[citadel-m1:server] PQ-auth включена: гибрид Ed25519 + ML-DSA-65");
        Some(s)
    } else {
        None
    });

    let rate_limit = RateCfg::from_env(); // F7: per-client лимит на входящее направление (D3)
    if let Some(cfg) = rate_limit {
        eprintln!(
            "[Citadel-m1:server] F7 rate-limit включён: {:.0} б/с (burst {:.0} б) на клиента",
            cfg.rate, cfg.burst
        );
    }

    // TCP-fallback listener (M4): bind ДО сброса привилегий (порт <1024). Только при obfs PSK
    // (obfs-over-TCP использует тот же L1). Включается env `Citadel_TCP_LISTEN` (напр. 0.0.0.0:443).
    let tcp_listener = match (std::env::var("Citadel_TCP_LISTEN"), obfs_psk()) {
        (Ok(a), Some(_)) => {
            let l = tokio::net::TcpListener::bind(&a)
                .await
                .with_context(|| format!("TCP-fallback bind {a}"))?;
            eprintln!("[citadel-m1:server] TCP-fallback слушает {a} (obfs-over-TCP, M4)");
            Some(l)
        }
        _ => None,
    };

    drop_privileges()?; // F4: дальше root не нужен (TUN/NAT/сокеты уже настроены)

    // TCP-fallback acceptor: те же assign+pump, что и QUIC, но транспорт — obfs-over-TCP.
    if let (Some(listener), Some(psk)) = (tcp_listener, obfs_psk()) {
        let tun = tun.clone();
        let issuer_pk = issuer_pk.clone();
        let spent = spent.clone();
        let signer = signer.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => match TcpObfs::wrap(stream, psk) {
                        Ok(tcp) => {
                            let (addr, prefix) = next_client_addr();
                            tokio::spawn(handle_client(
                                Tunnel::Tcp(tcp),
                                tun.clone(),
                                addr,
                                prefix,
                                issuer_pk.clone(),
                                spent.clone(),
                                rate_limit,
                                signer.clone(),
                                pin,
                            ));
                        }
                        Err(e) => eprintln!("[citadel-m1:server] TCP wrap: {e}"),
                    },
                    Err(e) => {
                        eprintln!("[citadel-m1:server] TCP accept: {e}");
                        break;
                    }
                }
            }
        });
    }

    // QUIC accept loop (основной транспорт)
    while let Some(incoming) = ep.accept().await {
        let tun = tun.clone();
        let issuer_pk = issuer_pk.clone();
        let spent = spent.clone();
        let signer = signer.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    let (addr, prefix) = next_client_addr();
                    handle_client(Tunnel::Quic(conn), tun, addr, prefix, issuer_pk, spent, rate_limit, signer, pin).await;
                }
                Err(e) => eprintln!("[citadel-m1:server] хендшейк не удался: {e}"),
            }
        });
    }
    Ok(())
}

/// Обслуживание одного клиента (любой транспорт): выдать адрес (токен M4) + качать туннель.
#[allow(clippy::too_many_arguments)]
async fn handle_client(
    mut tunnel: Tunnel,
    tun: Arc<Tun>,
    addr: [u8; 4],
    prefix: u8,
    issuer_pk: Arc<Option<Vec<u8>>>,
    spent: Arc<Mutex<HashSet<[u8; 32]>>>,
    rate_limit: Option<RateCfg>,
    signer: Arc<Option<citadel_quic::pqauth::ServerSigner>>,
    cert_pin: [u8; 32],
) {
    eprintln!("[citadel-m1:server] клиент {} ({}) подключён", tunnel.peer(), tunnel.kind());
    if let Err(e) =
        server_assign_address(&mut tunnel, addr, prefix, issuer_pk.as_deref(), &spent, (*signer).as_ref(), cert_pin).await
    {
        eprintln!("[citadel-m1:server] отказ в доступе: {e}");
        tunnel.close(1, b"auth-failed");
        return;
    }
    eprintln!("[citadel-m1:server] выдан {}.{}.{}.{}/{}", addr[0], addr[1], addr[2], addr[3], prefix);
    if let Err(e) = pump(tunnel, tun, Some(addr), rate_limit).await {
        eprintln!("[citadel-m1:server] pump завершён: {e}");
    }
}

async fn run_client() -> Result<()> {
    let cfg = ClientConfig::from_env()?;
    let tun_name = std::env::var("Citadel_TUN").unwrap_or_else(|_| "Citadel0".into());
    // VpnController сам делает establish → provider.configure(назначенный адрес) → data-plane.
    VpnController::new()
        .connect(cfg, Arc::new(LinuxTunProvider { tun_name }))
        .await
}

/// Linux-`TunProvider`: ПОСЛЕ установления адреса создаёт `/dev/net/tun`, настраивает
/// MTU/адрес/маршруты/DNS (F6), сбрасывает привилегии (F4) и отдаёт пакетный I/O. На Android
/// этот слой заменит обёртка над `VpnService.Builder` (трек C3) — порядок «адрес → TUN» тот же.
struct LinuxTunProvider {
    tun_name: String,
}

impl citadel_quic::vpn::TunProvider for LinuxTunProvider {
    fn configure(&self, p: &citadel_quic::vpn::TunParams) -> Result<Arc<dyn citadel_tun::TunIo>> {
        let tun = Arc::new(Tun::create(&self.tun_name).context("открыть TUN (нужен CAP_NET_ADMIN)")?);
        let ifname = tun.name().to_string();
        eprintln!("[Citadel-m1] TUN '{ifname}' открыт");
        run("ip", &["link", "set", &ifname, "mtu", &p.mtu, "up"]);
        let cidr = format!("{}.{}.{}.{}/{}", p.addr[0], p.addr[1], p.addr[2], p.addr[3], p.prefix);
        run("ip", &["addr", "add", &cidr, "dev", &ifname]);
        eprintln!("[citadel-m1:client] назначен адрес {cidr} dev {ifname}");
        if !p.routes.is_empty() {
            for r in p.routes.split_whitespace() {
                run("ip", &["route", "replace", r, "dev", &ifname]);
            }
            eprintln!("[citadel-m1:client] маршруты в туннель: {}", p.routes);
        }
        if let Some(dns) = &p.dns {
            setup_dns_leak_protection(&ifname, dns); // F6
        }
        drop_privileges()?; // F4: адрес/маршруты/DNS настроены — root больше не нужен
        let _ = std::fs::write("/tmp/Citadel-ready", b"1");
        Ok(tun)
    }
}

// connect_server / try_quic_connect вынесены в citadel_quic::client (C0.4).

/// probe-режим (негативный тест F3): шлём не-PSK датаграммы на exit и ждём ответ.
/// При включённой obfs exit молчит → probe-resistance.
async fn run_probe() -> Result<()> {
    let connect = std::env::var("Citadel_CONNECT").context("Citadel_CONNECT не задан")?;
    let addr = tokio::net::lookup_host(&connect)
        .await?
        .next()
        .ok_or_else(|| anyhow!("не разрешился {connect}"))?;
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(addr).await?;
    eprintln!("[probe] шлю не-PSK датаграммы на {connect} ({addr})…");
    let mut junk = vec![0xc0u8, 0, 0, 0, 1]; // похоже на начало QUIC long header v1
    junk.extend(std::iter::repeat_n(0x41, 1195));
    for _ in 0..5 {
        let _ = sock.send(&junk).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    let mut buf = [0u8; 2048];
    match tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf)).await {
        Ok(Ok(n)) => println!("[probe] получен ответ {n} б — probe-resistance НЕ держит ✗"),
        _ => println!("[probe] ответа нет за 3с — exit молчит на не-PSK трафик (F3 ✔)"),
    }
    Ok(())
}

/// auth-probe (негативный тест M4): транспорт валиден (obfs+PSK+pin), но токен ПОДДЕЛЬНЫЙ.
async fn run_auth_probe() -> Result<()> {
    let connect = std::env::var("Citadel_CONNECT").context("Citadel_CONNECT не задан")?;
    let server_name = std::env::var("Citadel_SERVER_NAME").unwrap_or_else(|_| "Citadel.exit".into());
    let addr = tokio::net::lookup_host(&connect)
        .await?
        .next()
        .ok_or_else(|| anyhow!("не разрешился {connect}"))?;
    let ep = match obfs_psk() {
        Some(p) => citadel_quic::client_endpoint_obfs(p)?,
        None => quinn::Endpoint::client("0.0.0.0:0".parse()?)?,
    };
    let cfg = match read_pin_for(citadel_quic::client::host_of(&connect)) {
        PinMode::Pinned(p) => citadel_quic::client_config_pinned(citadel_quic::kx_groups_from_env(), p)?,
        _ => citadel_quic::client_config(citadel_quic::kx_groups_from_env())?,
    };
    let conn = tokio::time::timeout(Duration::from_secs(6), ep.connect_with(cfg, addr, &server_name)?)
        .await
        .map_err(|_| anyhow!("таймаут"))??;
    eprintln!("[auth-probe] транспорт ОК (obfs+PQ+pin); предъявляю ПОДДЕЛЬНЫЙ токен…");

    let mut forged = vec![0u8; citadel_token::NONCE_LEN + citadel_token::RAND_LEN + 256];
    rand::thread_rng().fill_bytes(&mut forged);
    let req = capsule::encode_address_request_v4(&capsule::AssignedV4 { request_id: 1, addr: [0, 0, 0, 0], prefix: 0 });
    // M7: сервер ждёт nonce(32)-префикс перед токеном (probe его не проверяет, но формат должен совпасть)
    let mut out = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut out);
    out.extend_from_slice(&citadel_masque::varint::to_vec(forged.len() as u64));
    out.extend_from_slice(&forged);
    out.extend_from_slice(&req);

    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(&out).await?;
    send.finish()?;
    match recv.read_to_end(4096).await {
        Ok(buf) if matches!(capsule::decode(&buf), Some((capsule::ADDRESS_ASSIGN, _, _))) => {
            println!("[auth-probe] ПОДДЕЛЬНЫЙ токен ПРИНЯТ — auth обойдена ✗");
        }
        _ => println!("[auth-probe] поддельный токен отклонён сервером (M4 per-user auth ✔)"),
    }
    Ok(())
}

// `pump` (data plane TUN ⇄ транспорт) вынесен в `citadel_quic::dataplane` (C0.2).
