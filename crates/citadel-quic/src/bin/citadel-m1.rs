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
use std::net::SocketAddr;
use std::process::Command;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use rand::RngCore;
use citadel_masque::{capsule, datagram, ip};
use citadel_quic::ratelimit::{RateCfg, TokenBucket};
use citadel_quic::tcp_obfs::TcpObfs;
use citadel_tun::Tun;

// Пул адресов exit для клиентов: 10.7.0.{2,3,...}/24.
static ADDR_POOL: AtomicU8 = AtomicU8::new(2);

#[tokio::main]
async fn main() -> Result<()> {
    let role = std::env::var("Citadel_ROLE").unwrap_or_default();
    match role.as_str() {
        "server" => run_server(open_tun()?).await,
        "client" => run_client(open_tun()?).await,
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

/// L1-obfs PSK из env Citadel_OBFS_PSK (64 hex = 32 байта, иначе BLAKE3-derive из строки).
fn obfs_psk() -> Option<[u8; 32]> {
    let v = std::env::var("Citadel_OBFS_PSK").ok()?;
    let v = v.trim();
    if v.is_empty() {
        return None;
    }
    if v.len() == 64 {
        if let Ok(bytes) = hex::decode(v) {
            if let Ok(a) = bytes.try_into() {
                return Some(a);
            }
        }
    }
    Some(blake3::derive_key("CitadelPQVPN/obfs/v1/psk", v.as_bytes()))
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
    run("iptables", &["-A", "FORWARD", "-i", ifname, "-o", &eg, "-j", "ACCEPT"]);
    run("iptables", &["-A", "FORWARD", "-i", &eg, "-o", ifname, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"]);
    eprintln!("[net] server: ip_forward + MASQUERADE через '{eg}' (src {nat})");
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
fn parse_pin(s: &str) -> Option<[u8; 32]> {
    hex::decode(s.trim()).ok().and_then(|v| v.try_into().ok())
}

enum PinMode {
    Pinned([u8; 32]),
    Waiting, // pinning настроен, но pin ещё не доступен (ждём, пока exit его запишет)
    NoPin,   // pinning не настроен (PoC-режим)
}

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

/// Хост-часть `host:port` (для pin-файла и TCP-fallback цели).
fn host_of(server: &str) -> &str {
    server.rsplit_once(':').map(|(h, _)| h).unwrap_or(server)
}

/// Список exit-серверов: `Citadel_SERVERS` (через пробел/`;`/`,`) или один `Citadel_CONNECT`.
/// Перемешан для балансировки нагрузки; клиент идёт по нему failover'ом (M5 multi-server).
fn client_servers() -> Result<Vec<String>> {
    let mut servers: Vec<String> = match std::env::var("Citadel_SERVERS") {
        Ok(s) => s
            .split([' ', ';', ','])
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .map(String::from)
            .collect(),
        Err(_) => vec![std::env::var("Citadel_CONNECT")
            .context("ни Citadel_SERVERS, ни Citadel_CONNECT не заданы")?],
    };
    use rand::seq::SliceRandom;
    servers.shuffle(&mut rand::thread_rng());
    Ok(servers)
}

/// ML-DSA-65 pk выбранного exit для PQ-auth (M7): `Citadel_MLDSA_PUB` (файл) или
/// `Citadel_PIN_DIR/<host>.mldsa`. `None` → PQ-auth не запрашивается (только Ed25519+pin).
fn read_mldsa_pk(host: &str) -> Option<Vec<u8>> {
    if let Ok(f) = std::env::var("Citadel_MLDSA_PUB") {
        return std::fs::read(f).ok();
    }
    if let Ok(dir) = std::env::var("Citadel_PIN_DIR") {
        return std::fs::read(format!("{dir}/{host}.mldsa")).ok();
    }
    None
}

// ----------------- абстракция транспорта: QUIC или obfs-over-TCP (M4 fallback) -----------------
/// Туннель данных: основной — PQ-QUIC; fallback — obfs-over-TCP (когда UDP/QUIC заблокирован).
/// Унифицирует control-обмен (токен→адрес) и datagram-перекачку, чтобы `pump` не знал транспорт.
enum Tunnel {
    Quic(quinn::Connection),
    Tcp(TcpObfs),
}

impl Tunnel {
    fn peer(&self) -> SocketAddr {
        match self {
            Tunnel::Quic(c) => c.remote_address(),
            Tunnel::Tcp(t) => t.peer(),
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Tunnel::Quic(_) => "QUIC/UDP",
            Tunnel::Tcp(_) => "obfs-TCP",
        }
    }

    fn close(&self, code: u32, reason: &[u8]) {
        if let Tunnel::Quic(c) = self {
            c.close(code.into(), reason);
        }
        // TCP закрывается при drop
    }

    /// Клиент: послать один control-запрос и получить ответ (reliable message).
    async fn control_client(&mut self, req: &[u8]) -> Result<Vec<u8>> {
        match self {
            Tunnel::Quic(conn) => {
                let (mut send, mut recv) = conn.open_bi().await?;
                send.write_all(req).await?;
                send.finish()?;
                Ok(recv.read_to_end(4096).await?)
            }
            Tunnel::Tcp(t) => {
                t.send_msg(req).await?;
                Ok(t.recv_msg().await?)
            }
        }
    }

    /// Сервер: принять один control-запрос, обработать `handle` и ответить.
    async fn control_server<F>(&mut self, handle: F) -> Result<()>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>>,
    {
        match self {
            Tunnel::Quic(conn) => {
                let (mut send, mut recv) = conn.accept_bi().await?;
                let req = recv.read_to_end(8192).await?;
                let resp = handle(&req)?;
                send.write_all(&resp).await?;
                send.finish()?;
                Ok(())
            }
            Tunnel::Tcp(t) => {
                let req = t.recv_msg().await?;
                let resp = handle(&req)?;
                t.send_msg(&resp).await?;
                Ok(())
            }
        }
    }
}

/// Обработка входящего (от клиента) пакета на exit: egress-фильтр (F2) + rate-limit (F7).
/// `accept` → `true` пропустить в TUN, `false` дропнуть. Состояние bucket/счётчики — per-connection.
struct Inbound {
    egress_filter: bool,
    bucket: Option<TokenBucket>,
    dropped: u64,
    dropped_bytes: u64,
}

impl Inbound {
    fn new(egress_filter: bool, rate_limit: Option<RateCfg>) -> Self {
        Self {
            egress_filter,
            bucket: rate_limit.map(|c| TokenBucket::new(c, Instant::now())),
            dropped: 0,
            dropped_bytes: 0,
        }
    }

    fn accept(&mut self, pkt: &[u8]) -> bool {
        if self.egress_filter {
            if let Some(v) = ip::parse_ipv4(pkt) {
                if ip::is_blocked_dst(v.dst) {
                    eprintln!(
                        "[exit] F2: заблокирован inner-dst {}.{}.{}.{}",
                        v.dst[0], v.dst[1], v.dst[2], v.dst[3]
                    );
                    return false;
                }
            }
        }
        if let Some(b) = self.bucket.as_mut() {
            if !b.allow(TokenBucket::packet_cost(pkt.len()), Instant::now()) {
                self.dropped += 1;
                self.dropped_bytes += pkt.len() as u64;
                if self.dropped == 1 || self.dropped % 50 == 0 {
                    eprintln!(
                        "[exit] F7: rate-limit — дропнуто {} пакетов / {} б (клиент превысил лимит)",
                        self.dropped, self.dropped_bytes
                    );
                }
                return false;
            }
        }
        true
    }
}

// ----------------- капсульный обмен адресами (M2) -----------------
// Control-stream: [varint(token_len) ‖ token] ‖ ADDRESS_REQUEST → ADDRESS_ASSIGN.
async fn client_request_address(
    tunnel: &mut Tunnel,
    token: &[u8],
    mldsa_pk: Option<&[u8]>,
    cert_pin: [u8; 32],
) -> Result<capsule::AssignedV4> {
    // M7 PQ-auth: nonce(32) для привязки подписи сервера; далее токен + ADDRESS_REQUEST
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let req = capsule::AssignedV4 { request_id: 1, addr: [0, 0, 0, 0], prefix: 0 };
    let mut out = nonce.to_vec();
    out.extend_from_slice(&citadel_masque::varint::to_vec(token.len() as u64));
    out.extend_from_slice(token);
    out.extend_from_slice(&capsule::encode_address_request_v4(&req));

    let buf = tunnel.control_client(&out).await?;
    // ответ: varint(sig_len) ‖ ML-DSA-sig ‖ ADDRESS_ASSIGN
    let (sig_len, m) =
        citadel_masque::varint::decode(&buf).ok_or_else(|| anyhow!("нет sig-префикса"))?;
    let sig_end = m + sig_len as usize;
    if buf.len() < sig_end {
        return Err(anyhow!("обрезанная PQ-подпись"));
    }
    let sig = &buf[m..sig_end];
    let rest = &buf[sig_end..];

    // M7: проверяем ML-DSA-65 подпись сервера, если его pk провижирован (гибрид с Ed25519+pin)
    if let Some(pk) = mldsa_pk {
        if !citadel_quic::pqauth::verify_binding(pk, &nonce, &cert_pin, sig) {
            return Err(anyhow!("PQ-auth: ML-DSA подпись сервера НЕ прошла — возможен MITM"));
        }
        eprintln!("[citadel-m1:client] PQ-auth ✔ ML-DSA-65 подпись сервера верна (гибрид Ed25519+ML-DSA)");
    }

    let (t, val, _) = capsule::decode(rest).ok_or_else(|| anyhow!("битая капсула в ответе"))?;
    if t != capsule::ADDRESS_ASSIGN {
        return Err(anyhow!("ожидался ADDRESS_ASSIGN, получен type={t}"));
    }
    capsule::decode_assigned_v4(val).ok_or_else(|| anyhow!("битое тело ADDRESS_ASSIGN"))
}

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

fn load_token() -> Vec<u8> {
    std::env::var("Citadel_TOKENS")
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| s.lines().next().map(|l| l.trim().to_string()))
        .and_then(|l| hex::decode(l).ok())
        .unwrap_or_default()
}

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
                            let octet = ADDR_POOL.fetch_add(1, Ordering::Relaxed);
                            let addr = [10, 7, 0, octet];
                            tokio::spawn(handle_client(
                                Tunnel::Tcp(tcp),
                                tun.clone(),
                                addr,
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
                    let octet = ADDR_POOL.fetch_add(1, Ordering::Relaxed);
                    let addr = [10, 7, 0, octet];
                    handle_client(Tunnel::Quic(conn), tun, addr, issuer_pk, spent, rate_limit, signer, pin).await;
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
    issuer_pk: Arc<Option<Vec<u8>>>,
    spent: Arc<Mutex<HashSet<[u8; 32]>>>,
    rate_limit: Option<RateCfg>,
    signer: Arc<Option<citadel_quic::pqauth::ServerSigner>>,
    cert_pin: [u8; 32],
) {
    eprintln!("[citadel-m1:server] клиент {} ({}) подключён", tunnel.peer(), tunnel.kind());
    if let Err(e) =
        server_assign_address(&mut tunnel, addr, 24, issuer_pk.as_deref(), &spent, (*signer).as_ref(), cert_pin).await
    {
        eprintln!("[citadel-m1:server] отказ в доступе: {e}");
        tunnel.close(1, b"auth-failed");
        return;
    }
    eprintln!("[citadel-m1:server] выдан {}.{}.{}.{}/24", addr[0], addr[1], addr[2], addr[3]);
    if let Err(e) = pump(tunnel, tun, true, rate_limit).await {
        eprintln!("[citadel-m1:server] pump завершён: {e}");
    }
}

async fn run_client(tun: Arc<Tun>) -> Result<()> {
    let ifname = tun.name().to_string();
    run("ip", &["link", "set", &ifname, "mtu", &mtu(), "up"]); // адрес — позже, из капсулы

    let server_name = std::env::var("Citadel_SERVER_NAME").unwrap_or_else(|_| "Citadel.exit".into());
    let psk = obfs_psk();
    let servers = client_servers()?;
    eprintln!("[citadel-m1:client] exit-серверы (перемешаны): {}", servers.join(", "));

    // M5 multi-server: идём по списку failover'ом — первый поднявшийся exit (QUIC или TCP-fallback).
    let mut tunnel = None;
    let mut chosen = String::new();
    for server in &servers {
        match connect_server(server, &server_name, psk, servers.len() > 1).await {
            Ok(Some(t)) => {
                eprintln!("[citadel-m1:client] ВЫБРАН exit {server} (транспорт {})", t.kind());
                tunnel = Some(t);
                chosen = server.clone();
                break;
            }
            Ok(None) => eprintln!("[citadel-m1:client] exit {server} недоступен — пробую следующий"),
            Err(e) => eprintln!("[citadel-m1:client] exit {server}: {e} — пробую следующий"),
        }
    }
    let mut tunnel = tunnel
        .ok_or_else(|| anyhow!("ни один exit недоступен: {}", servers.join(", ")))?;

    // M7 PQ-auth: pin (Ed25519-cert) + ML-DSA-65 pk выбранного exit (если провижированы)
    let host = host_of(&chosen);
    let cert_pin = match read_pin_for(host) {
        PinMode::Pinned(p) => p,
        _ => [0u8; 32],
    };
    let mldsa_pk = read_mldsa_pk(host);
    if mldsa_pk.is_some() {
        eprintln!("[citadel-m1:client] PQ-auth (M7): буду проверять ML-DSA-65 подпись exit {host}");
    }

    // M2+M4/M5: предъявляем анонимный токен и получаем адрес капсулой
    let token = load_token();
    if token.is_empty() {
        eprintln!("[citadel-m1:client] WARN: токен (Citadel_TOKENS) не задан — exit может отказать");
    } else {
        eprintln!("[citadel-m1:client] предъявляю анонимный токен ({} б)", token.len());
    }
    let a = client_request_address(&mut tunnel, &token, mldsa_pk.as_deref(), cert_pin).await?;
    let cidr = format!("{}.{}.{}.{}/{}", a.addr[0], a.addr[1], a.addr[2], a.addr[3], a.prefix);
    run("ip", &["addr", "add", &cidr, "dev", &ifname]);
    eprintln!("[citadel-m1:client] назначен адрес {cidr} (ADDRESS_ASSIGN, транспорт {})", tunnel.kind());
    if let Ok(routes) = std::env::var("Citadel_ROUTES") {
        for r in routes.split_whitespace() {
            run("ip", &["route", "replace", r, "dev", &ifname]);
        }
        eprintln!("[citadel-m1:client] маршруты в туннель: {routes}");
    }

    if let Ok(dns) = std::env::var("Citadel_DNS") {
        setup_dns_leak_protection(&ifname, &dns); // F6
    }

    drop_privileges()?; // F4: адрес/маршруты/DNS настроены — root больше не нужен

    let _ = std::fs::write("/tmp/Citadel-ready", b"1");
    pump(tunnel, tun, false, None).await // клиент себя не лимитирует (F7 — забота exit)
}

/// Подключиться к ОДНОМУ exit'у: основной путь PQ-QUIC, при недоступности — obfs-over-TCP fallback
/// (M4, порт `Citadel_TCP_PORT`, по умолчанию 443). `None` — exit недоступен → вызывающий пробует
/// следующий из списка (M5 failover).
async fn connect_server(
    server: &str,
    server_name: &str,
    psk: Option<[u8; 32]>,
    multi: bool,
) -> Result<Option<Tunnel>> {
    let host = host_of(server);
    let addr = match tokio::net::lookup_host(server).await.map(|mut it| it.next()) {
        Ok(Some(a)) => a,
        _ => return Ok(None),
    };
    // failover/fallback хотят быстрый QUIC-timeout; один сервер без fallback — ждём дольше.
    let attempts = if multi || psk.is_some() { 5 } else { 60 };
    if let Some(conn) = try_quic_connect(server, addr, server_name, attempts, host).await? {
        eprintln!("[citadel-m1:client] PQ-туннель (QUIC/UDP) к {server} ✔");
        return Ok(Some(Tunnel::Quic(conn)));
    }
    if let Some(psk) = psk {
        let tcp_port = std::env::var("Citadel_TCP_PORT").unwrap_or_else(|_| "443".into());
        let tcp_target = format!("{host}:{tcp_port}");
        if let Ok(Some(taddr)) = tokio::net::lookup_host(&tcp_target).await.map(|mut it| it.next()) {
            eprintln!("[citadel-m1:client] QUIC к {server} недоступен → obfs-TCP к {tcp_target}");
            // таймаут: мёртвый host иначе висит на TCP connect (~минуты) и ломает failover
            if let Ok(Ok(tcp)) =
                tokio::time::timeout(Duration::from_secs(3), TcpObfs::connect(taddr, psk)).await
            {
                eprintln!("[citadel-m1:client] obfs-TCP туннель к {tcp_target} ✔");
                return Ok(Some(Tunnel::Tcp(tcp)));
            }
        }
    }
    Ok(None)
}

/// Попытаться поднять PQ-QUIC к одному серверу. `None` — не удалось за `attempts` попыток
/// (UDP/QUIC заблокирован или exit недоступен). Pin берётся per-host (`read_pin_for`).
async fn try_quic_connect(
    connect: &str,
    addr: SocketAddr,
    server_name: &str,
    attempts: u32,
    pin_host: &str,
) -> Result<Option<quinn::Connection>> {
    let ep = match obfs_psk() {
        Some(psk) => citadel_quic::client_endpoint_obfs(psk)?,
        None => quinn::Endpoint::client("0.0.0.0:0".parse()?)?,
    };
    eprintln!(
        "[citadel-m1:client] QUIC: пробую {connect} ({addr}), server_name={server_name}, KX={}",
        citadel_quic::kx_suite_name(&std::env::var("Citadel_KX").unwrap_or_default())
    );
    let mut logged_pin = false;
    for attempt in 1..=attempts {
        let cfg = match read_pin_for(pin_host) {
            PinMode::Pinned(p) => {
                if !logged_pin {
                    eprintln!("[citadel-m1:client] pinning {pin_host}: {}", hex::encode(p));
                    logged_pin = true;
                }
                citadel_quic::client_config_pinned(citadel_quic::kx_groups_from_env(), p)?
            }
            PinMode::NoPin => {
                if !logged_pin {
                    eprintln!("[citadel-m1:client] WARN: pin не настроен — принимаю любой серт (PoC)");
                    logged_pin = true;
                }
                citadel_quic::client_config(citadel_quic::kx_groups_from_env())?
            }
            PinMode::Waiting => {
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }
        };
        match tokio::time::timeout(Duration::from_secs(3), ep.connect_with(cfg, addr, server_name)?).await {
            Ok(Ok(c)) => return Ok(Some(c)),
            Ok(Err(e)) => eprintln!("[citadel-m1:client] QUIC попытка {attempt}: {e}"),
            Err(_) => eprintln!("[citadel-m1:client] QUIC попытка {attempt}: таймаут (exit/UDP недоступен?)"),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Ok(None)
}

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
    junk.extend(std::iter::repeat(0x41).take(1195));
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
    let cfg = match read_pin_for(host_of(&connect)) {
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

/// Двунаправленная перекачка TUN ⇄ QUIC DATAGRAM. `egress_filter` (на exit) дропает
/// inner-пакеты во внутренние/служебные сети (F2). `rate_limit` (на exit) ограничивает
/// входящее от клиента направление token-bucket'ом (F7 / D3); `None` → без лимита.
async fn pump(
    tunnel: Tunnel,
    tun: Arc<Tun>,
    egress_filter: bool,
    rate_limit: Option<RateCfg>,
) -> Result<()> {
    use tokio::sync::mpsc;
    let (tun_to_net_tx, mut tun_to_net_rx) = mpsc::channel::<Vec<u8>>(1024);
    let (net_to_tun_tx, mut net_to_tun_rx) = mpsc::channel::<Vec<u8>>(1024);

    // TUN → сеть (блокирующее чтение TUN в отдельном потоке)
    {
        let tun = tun.clone();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            loop {
                match tun.recv(&mut buf) {
                    Ok(n) if n > 0 => {
                        if tun_to_net_tx.blocking_send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });
    }
    // сеть → TUN
    {
        let tun = tun.clone();
        std::thread::spawn(move || {
            while let Some(pkt) = net_to_tun_rx.blocking_recv() {
                let _ = tun.send(&pkt);
            }
        });
    }

    match tunnel {
        Tunnel::Quic(conn) => {
            let send_conn = conn.clone();
            let sender = tokio::spawn(async move {
                while let Some(pkt) = tun_to_net_rx.recv().await {
                    let dg = datagram::encode(datagram::CTX_RAW_IP, &pkt);
                    if let Err(e) = send_conn.send_datagram(bytes::Bytes::from(dg)) {
                        eprintln!("[pump] датаграмма отброшена ({} б): {e}", pkt.len());
                    }
                }
            });
            let recv_conn = conn.clone();
            let receiver = tokio::spawn(async move {
                let mut inb = Inbound::new(egress_filter, rate_limit);
                loop {
                    match recv_conn.read_datagram().await {
                        Ok(dg) => {
                            if let Some((datagram::CTX_RAW_IP, pkt)) = datagram::decode(&dg) {
                                if inb.accept(pkt) && net_to_tun_tx.send(pkt.to_vec()).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("[pump] соединение закрыто: {e}");
                            break;
                        }
                    }
                }
            });
            let _ = tokio::try_join!(sender, receiver);
        }
        Tunnel::Tcp(tcp) => {
            let (mut tx, mut rx) = tcp.into_split();
            let sender = tokio::spawn(async move {
                while let Some(pkt) = tun_to_net_rx.recv().await {
                    if let Err(e) = tx.send_packet(&pkt).await {
                        eprintln!("[pump:tcp] отправка не удалась ({} б): {e}", pkt.len());
                        break;
                    }
                }
            });
            let receiver = tokio::spawn(async move {
                let mut inb = Inbound::new(egress_filter, rate_limit);
                loop {
                    match rx.recv_packet().await {
                        Ok(pkt) => {
                            if inb.accept(&pkt) && net_to_tun_tx.send(pkt).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            eprintln!("[pump:tcp] соединение закрыто: {e}");
                            break;
                        }
                    }
                }
            });
            let _ = tokio::try_join!(sender, receiver);
        }
    }
    Ok(())
}
