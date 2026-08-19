//! CitadelPQVPN — M1+M2: реальный IP-туннель поверх PQ-QUIC (бинарь `Citadel-m1`).
//!
//! M1: TUN ⇄ QUIC DATAGRAM (CONNECT-IP, context=0).
//! M2: динамическое назначение адреса капсулами ADDRESS_REQUEST/ADDRESS_ASSIGN
//!     (RFC 9484 §4.7) на control-стриме.
//! STRIDE-правки: F1 — pinning серверного сертификата; F2 — egress-фильтр на exit
//!     (drop приватных/служебных назначений, анти-пивот во внутреннюю сеть).
//!
//! env: Citadel_ROLE=server|client, Citadel_TUN=Citadel0, Citadel_MTU=1280
//!   server: Citadel_LISTEN=0.0.0.0:4433, Citadel_TUN_ADDR=10.7.0.1/16, Citadel_NAT_SRC=10.7.0.0/16,
//!           Citadel_PIN_FILE=/shared/exit.pin (куда записать pin)
//!   client: Citadel_SERVERS="h1:p h2:p" (M5 multi-server; или один Citadel_CONNECT=host:port),
//!           Citadel_SERVER_NAME=Citadel.exit, Citadel_ROUTES="1.1.1.1/32 ...",
//!           Citadel_PIN=<hex> | Citadel_PIN_DIR=<dir с <host>.pin> | Citadel_PIN_FILE=<один pin>

use std::collections::{HashMap, HashSet};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use rand::RngCore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use citadel_masque::capsule;
use citadel_quic::config::{parse_pin, ClientConfig, PinMode};
use citadel_quic::dataplane::{pump, ExitTunRouter, Tunnel};
use citadel_quic::ratelimit::RateCfg;
use citadel_quic::vpn::VpnController;
use citadel_tun::Tun;

// S2.5/A5: потолок ОДНОВРЕМЕННЫХ pre-auth хендшейков TCP-fallback (анти-DoS: без него флуд
// «молчаливыми» коннектами копит quinn-Endpoint'ы/задачи/fd). Слот держится только на хендшейк.
const TCP_FALLBACK_MAX_INFLIGHT: usize = 256;
// Таймаут на весь TCP-fallback хендшейк (obfs-gate + PQ-QUIC): idle/битый коннект не висит вечно.
const TCP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
// C6/аудит-3: потолок ОДНОВРЕМЕННЫХ pre-auth QUIC/UDP-хендшейков (симметрично A5 на TCP). Флуд
// хендшейками (даже с общим obfs-PSK) без cap'а копил бы задачи/память до токен-гейта. Слот держится
// только на хендшейк (established-сессия не занимает).
const UDP_MAX_INFLIGHT: usize = 512;

/// C4/аудит-3: пул клиентских адресов exit. Выделяет свободный host-адрес из подсети `Citadel_TUN_ADDR`
/// и ОСВОБОЖДАЕТ на disconnect. Заменяет монотонный `AtomicU16` (wraparound после 65534 коннектов →
/// коллизия адресов живых клиентов = вытеснение return-маршрута/перехват + выдача сетевого/шлюзового
/// адреса). Пропускает зарезервированные: network (host 0), gateway (host 1 = `Citadel_TUN_ADDR`),
/// broadcast (последний). Исчерпание → `None` (клиенту отказ, а не тихая коллизия).
struct AddrPool {
    net: u32,   // сетевой адрес (host-order u32)
    prefix: u8,
    hosts: u32, // размер host-пространства = 2^(32-prefix)
    /// Host-индекс шлюза — адреса самого exit'а из `Citadel_TUN_ADDR` (он же ADMIN_VIP, C7.2).
    ///
    /// Именно индекс, а не «единица»: при `10.7.0.1/16` шлюз действительно идёт первым в сети,
    /// но стоит расширить подсеть до `10.7.0.1/12` — сеть становится `10.0.0.0/12`, а шлюз
    /// оказывается в её глубине (host-индекс 458753). Пул, считающий шлюзом «сеть+1», выдал бы
    /// `10.7.0.1` очередному клиенту: коллизия с самим exit'ом и с admin-каналом «Абоненты».
    gw: u32,
    used: HashSet<u32>,
    next: u32, // hint (host-индекс)
}

impl AddrPool {
    fn from_env() -> Self {
        const DEFAULT_PREFIX: u8 = 16;
        let s = std::env::var("Citadel_TUN_ADDR").unwrap_or_else(|_| "10.7.0.1/16".into());
        let (ip_s, prefix) = match s.split_once('/') {
            Some((i, p)) => (i.to_string(), p.parse::<u8>().unwrap_or(DEFAULT_PREFIX)),
            None => (s, DEFAULT_PREFIX),
        };
        let prefix = prefix.min(32);
        let ip = ip_s.parse::<std::net::Ipv4Addr>().unwrap_or(std::net::Ipv4Addr::new(10, 7, 0, 1));
        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) };
        let net = u32::from(ip) & mask;
        let hosts = 1u32.checked_shl(32 - prefix as u32).unwrap_or(0);
        AddrPool { net, prefix, hosts, gw: u32::from(ip) - net, used: HashSet::new(), next: 1 }
    }

    /// Число адресов, которые пул вообще может выдать: всё host-пространство минус network,
    /// broadcast и шлюз.
    fn capacity(&self) -> usize {
        if self.hosts < 4 {
            return 0;
        }
        let last = self.hosts - 1; // индекс broadcast
        let candidates = (last - 1) as usize; // индексы 1..=last-1
        candidates - usize::from((1..last).contains(&self.gw))
    }

    /// Выделить свободный host-индекс из `[1, hosts-2]`, пропустив шлюз. `None` — пул исчерпан.
    fn alloc(&mut self) -> Option<[u8; 4]> {
        // Проверка «пул полон» ДО сканирования — иначе на исчерпанной подсети каждый запрос
        // прочёсывал бы всё host-пространство под общим мьютексом. Для /24 это незаметно, для
        // /12 (миллион адресов) — готовая точка отказа: заняв пул, его можно было бы держать
        // заклиненным дешёвыми повторными коннектами.
        if self.used.len() >= self.capacity() {
            return None;
        }
        let last = self.hosts - 1;
        // Цикл покрывает весь диапазон кандидатов ровно один раз: `next` идёт по кругу
        // 1..=last-1, а свободный индекс гарантированно есть — его наличие проверено выше.
        for _ in 1..last {
            let idx = self.next;
            self.next = if self.next + 1 >= last { 1 } else { self.next + 1 };
            if idx == self.gw {
                continue; // адрес самого exit'а (ADMIN_VIP) клиенту не выдаём
            }
            if self.used.insert(idx) {
                return Some((self.net + idx).to_be_bytes());
            }
        }
        None
    }

    /// Вернуть адрес в пул (на disconnect).
    fn free(&mut self, addr: [u8; 4]) {
        let idx = u32::from_be_bytes(addr).wrapping_sub(self.net);
        self.used.remove(&idx);
    }
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

/// L1-obfs PSK из env `Citadel_OBFS_PSK` (делегирует в `config::env_obfs_psk`).
/// Используется серверной и probe-ролями; клиентский путь берёт `ClientConfig::obfs_psk`.
///
/// M-7: негодное значение — ошибка, а не «obfs выключен». Иначе опечатка в PSK поднимала бы
/// сервер БЕЗ L1-слоя, и это выглядело бы как штатный запуск.
fn obfs_psk() -> Result<Option<[u8; 32]>> {
    citadel_quic::config::env_obfs_psk()
}

/// **H-3/аудит-4: чем exit шифрует L1 канала данных.**
///
/// `Citadel_OBFS_MASTER` (64 hex) — мастер-секрет, из которого выводится ключ КАЖДОЙ эпохи. Он
/// **не покидает сервер**: абоненту издатель отдаёт только ключ текущей эпохи, и только после
/// Layer-1. Отсюда и весь смысл H-3 — утёкшая ссылка перестаёт быть бессрочным пропуском в L1, а
/// отзыв абонента (admin-канал) начинает действовать и на этом слое (со следующей эпохи).
///
/// Не задан — прежнее поведение: единый `Citadel_OBFS_PSK` (token-less деплой, где раздавать ключ
/// эпохи попросту некому). Обе переменные пусты — obfs выключен.
///
/// **Мастер и бутстрапный PSK — РАЗНЫЕ секреты, и это принципиально.** `Citadel_OBFS_PSK` лежит в
/// каждой ссылке; если бы ключи эпох выводились из него, любой владелец ссылки считал бы их сам, и
/// ротация не значила бы ничего. Поэтому мастер генерится отдельно и в ссылки не попадает.
fn obfs_source() -> Result<Option<citadel_quic::PskSource>> {
    if let Some(master) = citadel_quic::config::parse_env_psk("Citadel_OBFS_MASTER")? {
        let epoch_secs: u64 = std::env::var("Citadel_EPOCH_SECS")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(3600);
        return Ok(Some(citadel_quic::PskSource::Epoch { master, epoch_secs }));
    }
    Ok(obfs_psk()?.map(citadel_quic::PskSource::Fixed))
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

/// L-3: открыть журнал потраченных токенов ДО [`drop_privileges`] — на чтение И запись.
///
/// Открывать надо именно здесь: после F4 процесс работает под nobody, а каталог `/shared`
/// принадлежит root'у; отдать каталог сброшенному uid тоже нельзя — `cap_drop: ALL` (M-4) снимает
/// с exit'а CAP_CHOWN. Дескриптор же проверяется на `open`, поэтому запись через него переживает
/// смену uid, а ротация делается перезаписью того же файла, без обращений к каталогу.
fn open_spent_log(path: &std::path::Path) -> Result<std::fs::File> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("журнал {}", path.display()))?;
    set_key_perms(&path.to_string_lossy()); // 0600 — постороннему процессу читать незачем
    Ok(f)
}

// ----------------------- сетевая обвязка (ip/iptables) -----------------------
fn run(cmd: &str, args: &[&str]) {
    let _ = run_ok(cmd, args);
}

/// То же, но с ответом «получилось ли». Нужно там, где у правила есть запасной вариант: матч
/// `-m conntrack` требует модуля ядра, которого на чужом хосте может не оказаться, и разницу
/// между «правило стоит» и «iptables ругнулся в stderr» надо видеть в коде, а не глазами.
fn run_ok(cmd: &str, args: &[&str]) -> bool {
    match Command::new(cmd).args(args).status() {
        Ok(s) if s.success() => true,
        Ok(s) => {
            eprintln!("[net] {cmd} {} → {s}", args.join(" "));
            false
        }
        Err(e) => {
            eprintln!("[net] {cmd}: {e}");
            false
        }
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

/// MTU туннельного интерфейса exit'а. Дефолт — [`citadel_quic::INNER_MTU`], т.е. ровно то, что
/// влезает в одну QUIC-датаграмму. Выше ставить нельзя: ядро отдало бы в `pump` пакет из интернета
/// размером до MTU, а датаграмма его не унесла бы → тихий дроп (для TCP это маскирует MSS-clamp,
/// но крупный UDP — QUIC/HTTP3, видео, игры — просто пропадал бы). Заодно MSS-clamp и ICMP
/// «fragmentation needed» от ядра теперь считаются от честного значения — PMTUD у отправителей
/// в интернете работает вместо чёрной дыры.
fn mtu() -> String {
    std::env::var("Citadel_MTU").unwrap_or_else(|_| citadel_quic::INNER_MTU.to_string())
}

/// C7.2: admin-VIP:порт для точечного пропуска в data-plane (`Citadel_ADMIN_VIP` = IPv4 шлюза
/// туннеля, `Citadel_ADMIN_PORT`). `None` (нет env) → admin-плоскость по туннелю выключена.
/// Значения должны совпадать с DNAT-правилом (`server_setup_net`), иначе пакет пройдёт фильтр,
/// но не будет перенаправлен на issuer.
fn admin_dst_from_env() -> Option<([u8; 4], u16)> {
    let vip = std::env::var("Citadel_ADMIN_VIP").ok()?;
    let port = std::env::var("Citadel_ADMIN_PORT").ok()?;
    let octs: Vec<u8> = vip.trim().split('.').filter_map(|o| o.parse().ok()).collect();
    let ip: [u8; 4] = octs.try_into().ok()?;
    Some((ip, port.trim().parse().ok()?))
}

/// Разобрать список адресов через запятую/пробел в IPv4-октеты. Мусор — ОШИБКА, а не пропуск
/// записи: опечатка в адресе обязана уронить старт, иначе фильтр молча окажется уже, чем думает
/// оператор (тот же fail-closed, что у `Citadel_ADMIN_PEER`/L-14 и `Citadel_OBFS_PSK`/M-7).
fn parse_v4_list(var: &str) -> Result<Vec<[u8; 4]>> {
    let Ok(raw) = std::env::var(var) else { return Ok(Vec::new()) };
    raw.split([',', ' ', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<std::net::Ipv4Addr>()
                .map(|a| a.octets())
                .map_err(|_| anyhow::anyhow!("{var}: '{s}' — не IPv4-адрес"))
        })
        .collect()
}

/// То же для `addr:port` (исключения из запрета).
fn parse_v4_port_list(var: &str) -> Result<Vec<([u8; 4], u16)>> {
    let Ok(raw) = std::env::var(var) else { return Ok(Vec::new()) };
    raw.split([',', ' ', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            let (a, p) = s
                .rsplit_once(':')
                .ok_or_else(|| anyhow::anyhow!("{var}: '{s}' — ожидается addr:port"))?;
            let addr: std::net::Ipv4Addr =
                a.parse().map_err(|_| anyhow::anyhow!("{var}: '{a}' — не IPv4-адрес"))?;
            let port: u16 = p.parse().map_err(|_| anyhow::anyhow!("{var}: '{p}' — не порт"))?;
            Ok((addr.octets(), port))
        })
        .collect()
}

/// Политика exit'а для трафика из туннеля: admin-VIP (C7.2) + запреты G1/G2.
///
/// `Citadel_DENY_DSTS` — адреса, к которым из туннеля не форвардим (публичный IP самой машины,
/// адрес издателя); `Citadel_ALLOW_DSTS` — точечные исключения `addr:port` (token-порт издателя,
/// §7.1). Оба пустые — прежнее поведение. Установщик заполняет их сам; отдельные env оставлены и
/// для ручных деплоев (несколько публичных адресов, отдельный сервис на том же хосте).
fn egress_policy_from_env() -> Result<citadel_quic::dataplane::EgressPolicy> {
    Ok(citadel_quic::dataplane::EgressPolicy {
        admin_dst: admin_dst_from_env(),
        deny_dsts: parse_v4_list("Citadel_DENY_DSTS")?,
        allow_dsts: parse_v4_port_list("Citadel_ALLOW_DSTS")?,
    })
}

fn server_setup_net(ifname: &str, policy: &citadel_quic::dataplane::EgressPolicy) {
    if let Ok(addr) = std::env::var("Citadel_TUN_ADDR") {
        run("ip", &["addr", "add", &addr, "dev", ifname]);
    }
    run("ip", &["link", "set", ifname, "mtu", &mtu(), "up"]);
    let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", b"1");
    let nat = std::env::var("Citadel_NAT_SRC").unwrap_or_else(|_| "10.7.0.0/16".into());
    let eg = detect_egress();
    run("iptables", &["-t", "nat", "-A", "POSTROUTING", "-s", &nat, "-o", &eg, "-j", "MASQUERADE"]);
    // S0.2/H3: форвардим ТОЛЬКО из пула клиентских адресов; прочий inner-src (спуфинг) — DROP.
    // Ядровый дубль app-layer анти-спуфинга в Inbound (defense-in-depth) + reverse-path фильтр.
    run("iptables", &["-A", "FORWARD", "-i", ifname, "-s", &nat, "-o", &eg, "-j", "ACCEPT"]);
    run("iptables", &["-A", "FORWARD", "-i", &eg, "-o", ifname, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"]);
    // Изоляция клиентов (defense-in-depth): трафик клиент→клиент — это `-i ifname -o ifname`. На
    // app-слое он уже дропается F2 (is_blocked_dst блокирует всю tun-подсеть 10.x как приватную), но
    // ядровый FORWARD сам по себе перекинул бы такой пакет обратно в TUN (падает в default-policy,
    // не матчит правила egress выше). Явный DROP гарантирует изоляцию даже если F2 будет ослаблен/
    // обойдён (напр. будущее исключение приватного диапазона). Ставим ДО анти-спуфинг-DROP —
    // назначение внутри пула ловится раньше, независимо от src.
    run("iptables", &["-A", "FORWARD", "-i", ifname, "-o", ifname, "-j", "DROP"]);
    run("iptables", &["-A", "FORWARD", "-i", ifname, "!", "-s", &nat, "-j", "DROP"]);
    // S2.3/A4: клиент НЕ должен достукиваться до самого exit-хоста через туннель. Пакет с dst =
    // локальный адрес exit (его ПУБЛИЧНЫЙ IP, SSH:22, issuer:7000, docker-API, published-порты) идёт
    // в INPUT — не в FORWARD и не в NAT — поэтому egress-фильтр (F2/is_blocked_dst) его не ловит
    // (F2 покрывает RFC1918/10.x — приватные, но не публичный IP самого exit). Data-plane читает
    // TUN через userspace-fd, ядровый INPUT с туннеля ему не нужен ⇒ дропаем весь INPUT с ifname.
    // Закрывает пивот туннельного клиента на сервисы exit-хоста (аудит-2/A4).
    // `-I INPUT 1` (в НАЧАЛО цепочки, не `-A`): на хосте с уже существующим firewall (типовой VPS,
    // где SSH:22 разрешён правилом без `-i`-фильтра) append встал бы ПОСЛЕ такого ACCEPT и пакет из
    // туннеля сматчил бы его раньше нашего DROP. Insert гарантирует fail-closed независимо от
    // окружения (как `-I OUTPUT 1` в kill-switch). Admin-DNAT (C7.2) этим не задет: он в PREROUTING
    // до routing-decision → DNAT'нутый пакет уходит в FORWARD, а не в INPUT.
    run("iptables", &["-I", "INPUT", "1", "-i", ifname, "-j", "DROP"]);
    // G1/G2 (аудит-5): ядровый дубль запрета инфраструктурных адресов. Именно ЗДЕСЬ у INPUT-правила
    // выше кончается зона действия: пакет из туннеля с dst = ПУБЛИЧНЫЙ адрес хоста в INPUT этого
    // netns не попадает вовсе — контейнер форвардит его наружу (MASQUERADE), и в INPUT он приходит
    // уже у ХОЗЯЙСКОГО ядра, как локальный трафик с docker-бриджа, мимо облачной security-group.
    // Правила ставятся `-I FORWARD 1` (в НАЧАЛО): выше уже добавлен `-A FORWARD -i tun -s pool
    // -o eg -j ACCEPT`, и append встал бы ПОСЛЕ него — то есть никогда не сработал бы. Сначала
    // DROP'ы, потом исключения — вставка в позицию 1 переворачивает порядок, и итог такой:
    // [ACCEPT исключений] → [DROP запретов] → [прежние правила].
    for d in &policy.deny_dsts {
        let dst = format!("{}.{}.{}.{}", d[0], d[1], d[2], d[3]);
        run("iptables", &["-I", "FORWARD", "1", "-i", ifname, "-d", &dst, "-j", "DROP"]);
    }
    for (a, port) in &policy.allow_dsts {
        let dst = format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]);
        let p = port.to_string();
        run("iptables", &["-I", "FORWARD", "1", "-i", ifname, "-p", "tcp", "-d", &dst,
            "--dport", &p, "-j", "ACCEPT"]);
    }
    if !policy.is_empty() {
        eprintln!(
            "[net] G1: из туннеля закрыто {} инфраструктурных адрес(ов), исключений (addr:port): {}",
            policy.deny_dsts.len(),
            policy.allow_dsts.len()
        );
    }
    let _ = std::fs::write("/proc/sys/net/ipv4/conf/all/rp_filter", b"1");
    // MSS-clamp: ограничить TCP-сегменты под PMTU туннеля. Без него крупные ответные
    // сегменты (TLS ServerHello/cert) не влезают в QUIC-датаграмму и теряются — PMTUD
    // блэкхолится через NAT/туннель: ICMP/ping ходит, а TCP/HTTPS виснет. Клампим на SYN
    // в обе стороны; `--clamp-mss-to-pmtu` берёт MTU исходящего интерфейса (для трафика
    // в туннель = MTU туннеля), т.е. адаптивно под Citadel_MTU.
    run("iptables", &["-t", "mangle", "-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"]);
    eprintln!("[net] server: ip_forward + MASQUERADE + MSS-clamp через '{eg}' (src {nat})");

    // C7.2 admin-плоскость: пакеты из туннеля на admin-VIP:порт DNAT'им на issuer. Правило —
    // ТОЛЬКО `-i ifname` (из туннеля): admin-канал недостижим с WAN (порт не опубликован наружу).
    // Требует пропуска этого dst в data-plane (`policy.admin_dst` → Inbound), иначе egress-фильтр
    // дропнул бы его до ядра. `Citadel_ADMIN_DNAT` = "issuer_host:port" (entrypoint резолвит issuer).
    if let (Some((vip, port)), Ok(target)) =
        (policy.admin_dst, std::env::var("Citadel_ADMIN_DNAT"))
    {
        let vip_s = format!("{}.{}.{}.{}", vip[0], vip[1], vip[2], vip[3]);
        let port_s = port.to_string();
        let target = target.trim().to_string();
        run("iptables", &["-t", "nat", "-A", "PREROUTING", "-i", ifname, "-p", "tcp",
            "-d", &vip_s, "--dport", &port_s, "-j", "DNAT", "--to-destination", &target]);
        eprintln!("[net] C7.2 admin-plane: DNAT {vip_s}:{port_s} → {target} (только -i {ifname})");
        // G2 × C7.2 (раздельный деплой): FORWARD видит УЖЕ DNAT'нутый пакет, то есть dst =
        // адрес ИЗДАТЕЛЯ — а он при `--role exit` лежит в deny_dsts (G1/G2), и DROP выше съедал
        // ровно тот поток, ради которого DNAT и стоит. Снаружи это выглядело как «admin-канал
        // 10.7.0.1:7001 недоступен» при исправном туннеле: SYN уходил в туннель, проходил
        // userspace-фильтр (там dst ещё VIP) и умирал в ядре.
        //
        // Возвращаем ровно этот поток и ровно его: `--ctorigdst VIP --ctorigdstport port` матчит
        // только соединения, ПРИШЕДШИЕ на admin-VIP. Прямой путь абонента к `ISSUER:порт` (G2)
        // остаётся закрытым обоими рубежами — userspace-фильтром (dst издателя в deny) и этим же
        // DROP'ом (у такого соединения ctorigdst = адрес издателя, а не VIP).
        let denied_target = target
            .rsplit_once(':')
            .and_then(|(a, p)| Some((a.parse::<std::net::Ipv4Addr>().ok()?, a, p)))
            .filter(|(ip, _, _)| policy.deny_dsts.contains(&ip.octets()));
        if let Some((_, tip, tport)) = denied_target {
            let conntrack = run_ok("iptables", &["-I", "FORWARD", "1", "-i", ifname, "-p", "tcp",
                "-d", tip, "--dport", tport, "-m", "conntrack",
                "--ctorigdst", &vip_s, "--ctorigdstport", &port_s, "-j", "ACCEPT"]);
            if conntrack {
                eprintln!("[net] C7.2: admin-поток VIP→{target} пропущен мимо запрета G1 (только DNAT'нутые соединения)");
            } else {
                // xt_conntrack на хосте нет: ставим более широкое исключение (TCP из туннеля на
                // admin-порт издателя). G2 при этом держится userspace-фильтром — он режет прямой
                // путь ДО ядра, — но ядрового дубля у этого запрета уже нет: это видно в логе.
                run("iptables", &["-I", "FORWARD", "1", "-i", ifname, "-p", "tcp",
                    "-d", tip, "--dport", tport, "-j", "ACCEPT"]);
                eprintln!("[net] ⚠ C7.2: conntrack-матч недоступен — исключение для {target} шире (ядровый дубль G2 на этом порту снят, userspace-фильтр держит)");
            }
        }
    }
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

/// C5.1: как exit проверяет анонимный токен. `Epoch` читает ключи текущей±прошлой эпохи из dir
/// (токен «гаснет» к концу эпохи → отзыв по времени, M6). `Legacy` — единый ключ (не-epoch).
/// `Disabled` — токены выключены (`Citadel_ISSUER_KEY` не задан).
///
/// **M-6:** ключ эпохи стал секретом (схема v2, VOPRF), а переменная — `Citadel_ISSUER_KEY`.
/// Старое имя `Citadel_ISSUER_PUB` намеренно не работает молча: тихо проигнорировать его значило
/// бы «токены выключены» — то есть exit, пускающий кого угодно, при внешне исправном конфиге.
enum IssuerAuth {
    Disabled,
    /// Единый ключ вне схемы эпох (офлайн-пачка `citadel-token batch`). **Привязки к узлу здесь нет**
    /// (B-1): режим существует для стенда и одиночного token-less деплоя, где exit ровно один;
    /// в мультиэкзитной установке пользоваться им нельзя — общий ключ вернёт кросс-exit реплей.
    Legacy(Vec<u8>),
    Epoch {
        dir: String,
        epoch_secs: u64,
        /// B-1: pin ЭТОГО узла — по нему выводится его ключ эпохи (`k_exit`).
        exit_pin: [u8; 32],
        /// B-1: принимать ли токены «без привязки к узлу» (`Citadel_TOKEN_UNBOUND=1`).
        unbound: bool,
    },
}

impl IssuerAuth {
    /// `exit_pin` — pin собственного сертификата узла (B-1: ключ эпохи выводится per-exit).
    fn from_env(exit_pin: [u8; 32]) -> Result<Self> {
        let key_path = match std::env::var("Citadel_ISSUER_KEY") {
            Ok(p) => p,
            Err(_) => {
                if std::env::var_os("Citadel_ISSUER_PUB").is_some() {
                    return Err(anyhow!(
                        "Citadel_ISSUER_PUB больше не поддерживается: ключ эпохи стал секретом \
                         (схема токенов v2, M-6). Переименуйте переменную в Citadel_ISSUER_KEY и \
                         укажите путь к issuer.key — иначе exit молча перестал бы требовать токены"
                    ));
                }
                return Ok(IssuerAuth::Disabled);
            }
        };
        Ok(match std::env::var("Citadel_EPOCH_SECS").ok().and_then(|s| s.parse::<u64>().ok()) {
            Some(epoch_secs) => {
                let dir = std::path::Path::new(&key_path)
                    .parent()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|| ".".into());
                // B-1: стендовый режим — принимать и токены, выданные «без привязки к узлу»
                // (клиент без пиннинга не может назвать издателю exit). В деплое НЕ включается:
                // непривязанный ключ общий для всех узлов, то есть ровно та дыра, которую B-1
                // закрывает (кросс-exit реплей + компрометация одного узла бьёт по всем).
                let unbound = matches!(std::env::var("Citadel_TOKEN_UNBOUND").as_deref(), Ok("1"));
                if unbound {
                    eprintln!(
                        "[Citadel-m1:server] ⚠ Citadel_TOKEN_UNBOUND=1: принимаются токены без \
                         привязки к узлу (стендовый режим, в деплое не включать — B-1)"
                    );
                }
                IssuerAuth::Epoch { dir, epoch_secs, exit_pin, unbound }
            }
            None => match std::fs::read(&key_path) {
                Ok(k) => IssuerAuth::Legacy(k),
                Err(e) => {
                    // Fail-closed: путь задан, а файла нет — это ошибка конфигурации, а не «токены
                    // не нужны». Прежний код в этом случае возвращал Disabled (M-1 того же рода).
                    return Err(anyhow!("Citadel_ISSUER_KEY={key_path}: {e}"));
                }
            },
        })
    }

    fn enabled(&self) -> bool {
        !matches!(self, IssuerAuth::Disabled)
    }

    /// Номер эпохи «сейчас» (Legacy/Disabled — бакет 0, он же не истекает).
    fn epoch_now(&self) -> u64 {
        match self {
            IssuerAuth::Epoch { epoch_secs, .. } => citadel_token::current_epoch(*epoch_secs),
            _ => 0,
        }
    }

    /// L-3: где вести журнал потраченных токенов. `Citadel_SPENT_LOG` — явно (пустое значение или
    /// `off` = осознанный отказ, только RAM); иначе `<каталог ключей эпохи>/spent.bin`, то есть
    /// рядом с тем, что exit и так обязан иметь на диске. Токены выключены → журнал не нужен вовсе.
    fn spent_log_path(&self) -> Option<std::path::PathBuf> {
        if !self.enabled() {
            return None;
        }
        match std::env::var("Citadel_SPENT_LOG") {
            Ok(v) if v.trim().is_empty() || v.trim() == "off" => None,
            Ok(v) => Some(std::path::PathBuf::from(v)),
            Err(_) => {
                let dir = match self {
                    IssuerAuth::Epoch { dir, .. } => Some(std::path::PathBuf::from(dir)),
                    IssuerAuth::Legacy(_) => std::env::var("Citadel_ISSUER_KEY")
                        .ok()
                        .and_then(|k| std::path::Path::new(&k).parent().map(|p| p.to_path_buf())),
                    IssuerAuth::Disabled => None,
                };
                dir.map(|d| d.join("spent.bin"))
            }
        }
    }

    /// Проверить предъявление токена → `(nonce для double-spend, epoch-бакет для prune)` или None
    /// (невалид/чужая эпоха/чужая сессия). Legacy → бакет `0` (не истекает, не чистится); Epoch →
    /// текущая эпоха (C5: бакеты старше current-1 можно чистить — токен той эпохи всё равно не
    /// пройдёт проверку под current±prev ключами).
    ///
    /// `ctx` — контекст ЭТОЙ сессии (`citadel_token::redeem_context`): без него предъявление не
    /// проверяется вовсе, поэтому привязка к сессии не может быть «забыта» на вызывающей стороне.
    fn verify(&self, redeem: &[u8], ctx: &[u8]) -> Option<([u8; 32], u64)> {
        match self {
            IssuerAuth::Disabled => None,
            IssuerAuth::Legacy(raw) => citadel_token::EpochKey::from_secret(raw)
                .ok()?
                .verify_redemption(redeem, ctx)
                .map(|n| (n, 0)),
            IssuerAuth::Epoch { dir, epoch_secs, exit_pin, unbound } => {
                let e = citadel_token::current_epoch(*epoch_secs);
                // current + prev (grace на границе эпохи / скью часов); старее — не принимаем.
                let keys: Vec<citadel_token::EpochKey> = [e, e.wrapping_sub(1)]
                    .iter()
                    .flat_map(|ep| epoch_keys_for(dir, *ep, exit_pin, *unbound))
                    .collect();
                citadel_token::verify_redemption_multi(&keys, redeem, ctx).map(|n| (n, e))
            }
        }
    }
}

/// B-1: ключи эпохи `ep`, которыми ЭТОТ узел вправе проверять предъявления.
///
/// Два источника, оба законны и живут рядом:
///
///  * `exit-<ep>.key` — **раздельный деплой**: keysync-сайдкар получил у издателя ключ, выведенный
///    для pin'а этого узла. Мастера эпохи на машине нет вовсе — в этом и смысл.
///  * `issuer-<ep>.key` — **совмещённый деплой**: на общем томе лежит МАСТЕР, и узел выводит свой
///    ключ сам (издатель и exit тут одна машина, скрывать мастер не от кого).
///
/// `unbound` (стенд) добавляет ключ «без привязки к узлу» — им проверяются токены клиента, который
/// не знал pin exit'а заранее (TOFU/без пиннинга). Вывести его можно только из мастера, поэтому в
/// раздельном деплое этот режим не работает — и правильно: там он и не нужен.
fn epoch_keys_for(
    dir: &str,
    ep: u64,
    exit_pin: &[u8; 32],
    unbound: bool,
) -> Vec<citadel_token::EpochKey> {
    let mut keys = Vec::new();
    if let Ok(raw) = std::fs::read(format!("{dir}/{}", citadel_token::exit_key_name(ep))) {
        if let Ok(k) = citadel_token::EpochKey::from_secret(&raw) {
            keys.push(k);
        }
    }
    if let Ok(raw) = std::fs::read(format!("{dir}/{}", citadel_token::epoch_key_name(ep))) {
        if let Ok(master) = <[u8; 32]>::try_from(raw.as_slice()) {
            if let Ok(k) = citadel_token::EpochKey::derive_for_exit(&master, ep, exit_pin) {
                keys.push(k);
            }
            if unbound {
                if let Ok(k) = citadel_token::EpochKey::derive_for_exit(
                    &master,
                    ep,
                    &citadel_token::EXIT_PIN_UNBOUND,
                ) {
                    keys.push(k);
                }
            }
        }
    }
    keys
}

/// C5/аудит-3 + L-3/аудит-4: множество потраченных токенов по epoch-бакетам.
///
/// **Почему на диске (L-3).** До аудита-4 множество жило только в RAM процесса, поэтому рестарт
/// exit'а (передеплой, крэш, OOM-killer) обнулял его — и КАЖДЫЙ выданный в текущей эпохе токен
/// становился годен второй раз. Квота издателя (64/эпоха) при этом остаётся соблюдённой, так что
/// снаружи это выглядит как штатная работа: тихое умножение доступа на число рестартов.
///
/// **Что при этом появляется на диске и почему это приемлемо.** Файл `spent-<epoch>.bin` — это
/// список 32-байтных nonce'ов, случайных и ни с чем не связанных: ни `client_id`, ни адреса, ни
/// назначения в нём нет и быть не может (exit их и не знает — в этом смысл слепой выдачи). Что из
/// него читается — «сколько сессий было в эту эпоху»; файлы старше `epoch-1` удаляются, поэтому
/// горизонт артефакта ≤ 2 эпох. Это осознанный размен: анти-double-spend против почти нулевого
/// прироста наблюдаемости у противника, который и так снял бы RAM живого процесса.
///
/// **Границы.** Второй exit с тем же ключом эпохи по-прежнему примет уже потраченный токен —
/// множество локально для узла. Закрывается per-exit выводом ключа эпохи (см. отчёт §13),
/// который всё равно обязателен перед первым мультиэкзитным деплоем.
///
/// **Почему ОДИН файл, открытый заранее, а не каталог с файлом на эпоху.** Exit сбрасывает
/// привилегии до nobody (F4) и живёт так до конца, а `cap_drop: ALL` в compose (M-4) отбирает у
/// него ещё и CAP_CHOWN — то есть отдать каталог во владение сброшенному uid нечем, и создать в
/// нём файл на новой эпохе процесс уже не сможет. Поэтому дескриптор открывается ОДИН раз, root'ом,
/// до сброса: права проверяются на `open`, а не на `write`, поэтому дальше запись работает под
/// любым uid. Ротация бакетов — перезапись того же файла на месте (`set_len` + запись с нуля),
/// она тоже не требует прав на каталог. Формат записи: `epoch(8 BE) ‖ nonce(32)`.
struct SpentStore {
    seen: HashMap<u64, HashSet<[u8; 32]>>,
    /// Журнал; `None` — только RAM (токены выключены либо файл недоступен).
    log: Option<std::fs::File>,
}

const SPENT_REC: usize = 8 + 32;

impl SpentStore {
    fn ram_only() -> Self {
        Self { seen: HashMap::new(), log: None }
    }

    /// Поднять журнал из уже открытого дескриптора: подхватить бакеты `epoch` и `epoch-1` (ровно
    /// те, что exit ещё проверяет ключами current±prev) плюс legacy-бакет 0; остальное отбросить и
    /// сразу переписать файл, чтобы горизонт артефакта не рос.
    fn open(mut log: std::fs::File, epoch: u64) -> Self {
        use std::io::Read;
        let mut raw = Vec::new();
        let read_ok = log.read_to_end(&mut raw).is_ok();
        let mut seen: HashMap<u64, HashSet<[u8; 32]>> = HashMap::new();
        let mut total = 0usize;
        for rec in raw.chunks_exact(SPENT_REC) {
            total += 1;
            let e = u64::from_be_bytes(rec[..8].try_into().expect("8 байт"));
            if e != 0 && e + 1 < epoch {
                continue; // бакет, который уже не проверяется ни одним ключом эпохи
            }
            seen.entry(e)
                .or_default()
                .insert(rec[8..].try_into().expect("32 байта"));
        }
        let restored: usize = seen.values().map(|s| s.len()).sum();
        let mut s = Self { seen, log: Some(log) };
        if !read_ok {
            eprintln!("[citadel-m1:server] ⚠ L-3: журнал не читается — продолжаю только в RAM");
            s.log = None;
        } else if restored != total {
            s.rewrite(); // отбросили просроченные бакеты — не тащить их на диске дальше
        }
        eprintln!(
            "[citadel-m1:server] L-3: журнал потраченных токенов подхвачен ({restored} записей) — \
             рестарт больше не обнуляет защиту от повторной траты"
        );
        s
    }

    /// Переписать файл целиком по текущему состоянию `seen` (ротация бакетов).
    fn rewrite(&mut self) {
        let Some(f) = self.log.as_mut() else { return };
        use std::io::{Seek, Write};
        let mut buf = Vec::with_capacity(self.seen.values().map(|s| s.len()).sum::<usize>() * SPENT_REC);
        for (e, set) in &self.seen {
            for n in set {
                buf.extend_from_slice(&e.to_be_bytes());
                buf.extend_from_slice(n);
            }
        }
        let ok = f.set_len(0).is_ok()
            && f.seek(std::io::SeekFrom::Start(0)).is_ok()
            && f.write_all(&buf).is_ok();
        if !ok {
            eprintln!("[citadel-m1:server] ⚠ L-3: журнал не перезаписан — продолжаю только в RAM");
            self.log = None;
        }
    }

    /// Дописать запись. Ошибка записи не отменяет приём токена: журнал — защита от повторной
    /// траты, а не условие доступа, и ронять из-за него живые сессии незачем. `fsync` намеренно
    /// нет: потеря последних записей при внезапном питании возвращает ровно сегодняшнее поведение,
    /// а платить fsync за каждое подключение — заметно.
    fn append(&mut self, nonce: &[u8; 32], epoch: u64) {
        let Some(f) = self.log.as_mut() else { return };
        use std::io::Write;
        let mut rec = [0u8; SPENT_REC];
        rec[..8].copy_from_slice(&epoch.to_be_bytes());
        rec[8..].copy_from_slice(nonce);
        if f.write_all(&rec).is_err() {
            eprintln!("[citadel-m1:server] ⚠ L-3: журнал недоступен на запись — дальше только RAM");
            self.log = None;
        }
    }
}

/// C5/аудит-3: учесть потраченный токен в epoch-бакете + prune бакетов старше `epoch-1`. Без prune
/// `spent` рос бы со ВСЕМИ когда-либо принятыми токенами (утечка памяти на долгом exit). Legacy
/// (эпоха 0) не чистится (не истекает). Возвращает `true`, если токен свежий (не double-spend).
fn spend_token(spent: &Mutex<SpentStore>, nonce: [u8; 32], epoch: u64) -> bool {
    let mut st = spent.lock().unwrap();
    if epoch > 1 {
        // токен эпохи e принимается ТОЛЬКО ключами current±prev ⇒ бакеты < epoch-1 бесполезны
        let stale = st.seen.keys().any(|&e| e != 0 && e + 1 < epoch);
        st.seen.retain(|&e, _| e == 0 || e + 1 >= epoch);
        if stale {
            st.rewrite(); // эпоха сменилась — просроченные бакеты уходят и с диска
        }
    }
    if !st.seen.entry(epoch).or_default().insert(nonce) {
        return false;
    }
    st.append(&nonce, epoch);
    true
}

/// Control-обмен серверной стороны — **два шага** (H-2/аудит-4).
///
/// Раньше это был один round-trip: клиент присылал `nonce‖токен‖ADDRESS_REQUEST`, а сервер лишь
/// В ОТВЕТЕ доказывал подлинность ML-DSA-подписью. То есть анонимный токен уходил пиру, чья
/// подлинность подтверждена ТОЛЬКО классически (pin на Ed25519-серте) — ровно то, что ML-DSA и
/// введена компенсировать: CRQC подделывает CertVerify под тем же pin, проходит хендшейк и
/// забирает неиспользованный токен. Канал издателя эту же задачу решает правильно (`IssuerHello`
/// первым кадром, см. `citadel_token::pqid`), а канал exit'а — нет.
///
/// Теперь порядок симметричен канналу издателя:
///   * шаг 1 — клиент шлёт только `nonce(32)`, сервер отвечает `pub‖sig(DOMAIN‖nonce‖cert_pin‖EKM)`;
///   * шаг 2 — клиент, ПРОВЕРИВ подпись, шлёт `varint(len)‖токен‖ADDRESS_REQUEST`.
///
/// Цена — один дополнительный round-trip по уже поднятому QUIC. Побочная польза: крупный ответ
/// (pub 1952 + sig 3309 Б) теперь уходит ДО предъявления токена, поэтому «мобильная» MTU-чёрная
/// дыра на нём больше не сжигает токен впустую — эскалация на obfs-TCP идёт с нетронутым токеном.
///
/// **Слом wire-формата:** старый клиент и новый сервер (и наоборот) несовместимы — обновляются
/// согласованно, как при obfs v1→v2 и бандле v3→v4.
async fn server_assign_address(
    tunnel: &mut Tunnel,
    pool: &Mutex<AddrPool>,
    issuer: &IssuerAuth,
    spent: &Mutex<SpentStore>,
    signer: Option<&citadel_quic::pqauth::ServerSigner>,
    cert_pin: [u8; 32],
) -> Result<([u8; 4], u8)> {
    // S2.6/A3: TLS exporter серверной сессии для channel-binding ML-DSA-подписи. Считаем ДО
    // control_server (он берёт &mut tunnel) и заносим в замыкание.
    let exporter = tunnel.exporter()?;

    // ── Шаг 1: сервер представляется. Токена здесь нет и быть не может. ──
    tunnel
        .control_server(|buf| {
            // Ровно nonce: длина фиксирована, чтобы старый клиент (славший nonce‖токен‖капсулу)
            // получил внятный отказ, а не «обрезанную капсулу» на следующем шаге.
            if buf.len() != 32 {
                return Err(anyhow!(
                    "PQ-auth: ожидался nonce ровно 32 Б, получено {} (старый клиент? обновите приложение)",
                    buf.len()
                ));
            }
            // M7/§S3: pub прикладывается всегда (commitment-fetch: клиент со ссылки держит лишь
            // H(pub) и сверяет его с этим pub). Без signer'а pub и sig пусты (PQ-auth выкл).
            let (pub_bytes, sig) = match signer {
                Some(s) => (s.public_key(), s.sign_binding(buf, &cert_pin, &exporter)?),
                None => (Vec::new(), Vec::new()),
            };
            let mut resp = citadel_masque::varint::to_vec(pub_bytes.len() as u64);
            resp.extend_from_slice(&pub_bytes);
            resp.extend_from_slice(&citadel_masque::varint::to_vec(sig.len() as u64));
            resp.extend_from_slice(&sig);
            Ok((resp, ()))
        })
        .await?;

    // ── Шаг 2: клиент проверил подпись и только теперь предъявляет токен. ──
    tunnel
        .control_server(|body| {
            let (tok_len, n) =
                citadel_masque::varint::decode(body).ok_or_else(|| anyhow!("нет токен-префикса"))?;
            let tok_end = n + tok_len as usize;
            if body.len() < tok_end {
                return Err(anyhow!("обрезанный токен"));
            }
            let token = &body[n..tok_end];
            let rest = &body[tok_end..];

            // F-M4/C5.1: per-user auth анонимным epoch-scoped токеном (если издатель задан).
            // M-6: предъявление проверяется В КОНТЕКСТЕ ЭТОЙ сессии (TLS-exporter), поэтому
            // перехваченное на другом плече релея сюда не подойдёт (остаток H-2).
            if issuer.enabled() {
                let ctx = citadel_token::redeem_context(&exporter);
                match issuer.verify(token, &ctx) {
                    Some((tn, epoch)) => {
                        if !spend_token(spent, tn, epoch) {
                            return Err(anyhow!("токен уже использован (double-spend)"));
                        }
                        // no-logs: nonce токена — псевдоним сессии; в лог только при Citadel_DEBUG_LOG
                        citadel_quic::dlog!("[citadel-m1:server] токен принят (nonce {}…)", hex::encode(&tn[..6]));
                    }
                    None => return Err(anyhow!("невалидный токен — отказ в доступе")),
                }
            }

            let (t, _v, _) = capsule::decode(rest).ok_or_else(|| anyhow!("битая капсула запроса"))?;
            if t != capsule::ADDRESS_REQUEST {
                return Err(anyhow!("ожидался ADDRESS_REQUEST, type={t}"));
            }

            // C6: адрес выделяем ТОЛЬКО ПОСЛЕ верификации токена — неавториз. флуд не жжёт пул.
            let (addr, prefix) = {
                let mut p = pool.lock().unwrap();
                let a = p.alloc().ok_or_else(|| anyhow!("пул адресов exit исчерпан — отказ"))?;
                (a, p.prefix)
            };
            // П5 (батарея): к назначению прикладываем СВОЙ `max_idle_timeout`. Только по нему
            // клиент вправе разредить keep-alive: эффективный idle-таймаут — минимум из
            // объявленных сторонами, и старый exit (15 с) рвал бы редкий маячок в простое.
            // Старый клиент этот хвост не читает — провод остаётся совместимым.
            let assign_bytes = capsule::encode_address_assign_v4_hint(
                &capsule::AssignedV4 { request_id: 1, addr, prefix },
                Some(citadel_quic::IDLE_TIMEOUT.as_millis() as u64),
            );
            Ok((assign_bytes, (addr, prefix))) // aux = выделенный адрес (после токена)
        })
        .await
}

// load_token вынесён в ClientConfig::from_env (C0.3).

// ---------------------- A7: персистентная идентичность exit ----------------------
/// chmod 600 (unix) — приватные ключи не должны читаться dropped-uid/другими.
fn set_key_perms(path: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}

/// A7: постоянная Ed25519-идентичность exit (стабильный pin между рестартами). Каталог из
/// `Citadel_KEY_DIR`; не задан → `None` (эфемерная идентичность — демо/back-compat). Загружает
/// `<dir>/exit-cert.der`+`exit-key.der` либо генерит и сохраняет (ключ 600). Без этого каждый
/// рестарт менял бы pin → все розданные `citadel://`-ссылки переставали бы подключаться.
fn persistent_cert() -> Result<Option<(CertificateDer<'static>, PrivateKeyDer<'static>)>> {
    let Ok(dir) = std::env::var("Citadel_KEY_DIR") else {
        return Ok(None);
    };
    let crt = format!("{dir}/exit-cert.der");
    let key = format!("{dir}/exit-key.der");
    match (std::fs::read(&crt), std::fs::read(&key)) {
        (Ok(c), Ok(k)) if !c.is_empty() && !k.is_empty() => {
            eprintln!("[citadel-m1:server] A7: постоянный серт загружен из {dir}");
            Ok(Some((CertificateDer::from(c), PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(k)))))
        }
        _ => {
            let (c, k) = citadel_quic::self_signed_ed25519()?;
            std::fs::write(&crt, c.as_ref()).with_context(|| format!("запись {crt}"))?;
            std::fs::write(&key, k.secret_der()).with_context(|| format!("запись {key}"))?;
            set_key_perms(&key);
            eprintln!("[citadel-m1:server] A7: постоянный серт сгенерирован → {dir}");
            Ok(Some((c, k)))
        }
    }
}

/// A7: постоянный ML-DSA-65 seed (32 б) из `<dir>/exit-mldsa.seed` либо генерит+сохраняет (600).
/// Стабильный seed → стабильный ML-DSA pub → обязательство `H(pub)` в ссылках не ломается.
fn persistent_mldsa_seed(dir: &str) -> Result<[u8; citadel_quic::pqauth::MLDSA_SEED_LEN]> {
    let path = format!("{dir}/exit-mldsa.seed");
    if let Ok(b) = std::fs::read(&path) {
        if let Ok(seed) = <[u8; citadel_quic::pqauth::MLDSA_SEED_LEN]>::try_from(b.as_slice()) {
            eprintln!("[citadel-m1:server] A7: ML-DSA seed загружен из {dir}");
            return Ok(seed);
        }
    }
    let mut seed = [0u8; citadel_quic::pqauth::MLDSA_SEED_LEN];
    rand::thread_rng().fill_bytes(&mut seed);
    std::fs::write(&path, seed).with_context(|| format!("запись {path}"))?;
    set_key_perms(&path);
    eprintln!("[citadel-m1:server] A7: ML-DSA seed сгенерирован → {dir}");
    Ok(seed)
}

// ------------------------------- роли -------------------------------
async fn run_server(tun: Arc<Tun>) -> Result<()> {
    // Политика egress разбирается ДО подъёма сети: опечатка в списке адресов обязана уронить старт,
    // а не оставить exit с фильтром шире, чем задумано (fail-closed, как L-14/M-7).
    let policy = egress_policy_from_env()?;
    server_setup_net(tun.name(), &policy);

    // Демукс общего exit-TUN: единый reader маршрутизирует return-пакеты нужному клиенту по inner-dst.
    // Без него несколько клиентских pump'ов на ОДНОМ TUN воруют пакеты друг у друга (multi-client
    // гонка → потеря/медленно/watchdog-шторм при >1 клиента). Создаётся один раз на весь exit.
    let router = ExitTunRouter::new(tun.clone() as Arc<dyn citadel_tun::TunIo>);

    let listen: std::net::SocketAddr = std::env::var("Citadel_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:4433".into())
        .parse()?;
    eprintln!(
        "[citadel-m1:server] KX-suite (crypto-agility): {}",
        citadel_quic::kx_suite_name(&std::env::var("Citadel_KX").unwrap_or_default())
    );
    // A7: постоянная идентичность (Citadel_KEY_DIR) → стабильный pin; иначе эфемерный серт (демо).
    let (cfg, pin) = match persistent_cert()? {
        Some((cert, key)) => {
            citadel_quic::server_config_with_cert(citadel_quic::kx_groups_from_env(), cert, key)?
        }
        None => citadel_quic::server_config_with_pin(citadel_quic::kx_groups_from_env())?,
    };
    if let Ok(path) = std::env::var("Citadel_PIN_FILE") {
        let _ = std::fs::write(&path, hex::encode(pin));
        eprintln!("[Citadel-m1:server] pin сертификата → {path}: {}", hex::encode(pin));
    }
    // S0.3/H1: клон серверного QUIC-конфига (тот же серт/pin!) для endpoint'ов поверх obfs-TCP.
    let tcp_server_cfg = cfg.clone();
    let obfs = obfs_source()?;
    let ep = match obfs {
        Some(src) => {
            // H-3: в epoch-режиме exit принимает ключи текущей и прошлой эпохи, и то же кольцо
            // используется для obfs-TCP. Fixed — прежний единый PSK (token-less деплой).
            eprintln!(
                "[Citadel-m1:server] obfs L1 включён (probe-resistance + анти-DPI), ключ: {}",
                match src {
                    citadel_quic::PskSource::Epoch { epoch_secs, .. } =>
                        format!("ротация по эпохам ({epoch_secs}с, H-3) — ссылка L1-доступа не даёт"),
                    citadel_quic::PskSource::Fixed(_) =>
                        "единый PSK из ссылок (ротации нет — token-less деплой)".to_string(),
                }
            );
            citadel_quic::server_endpoint_obfs(listen, cfg, src)?
        }
        None => quinn::Endpoint::server(cfg, listen)?,
    };
    eprintln!("[Citadel-m1:server] слушаю {listen} (KX=X25519MLKEM768)");

    // B-1: свой pin — идентификатор узла при выводе ключа эпохи (тот же, что абонент видит в ссылке).
    let issuer_auth = Arc::new(IssuerAuth::from_env(pin)?);
    if issuer_auth.enabled() {
        eprintln!(
            "[Citadel-m1:server] per-user epoch-токены включены (C5.1, VOPRF v2; ключ эпохи \
             выводится per-exit — B-1)"
        );
    }
    // C5: spent-токены по epoch-бакетам (prune старых эпох → без утечки памяти на долгом exit).
    // L-3: множество переживает рестарт — журнал поднимается ЗДЕСЬ, до `drop_privileges`, потому
    // что каталог создаётся root'ом и передаётся во владение сбрасываемому uid (после setuid
    // создать его уже нельзя, а эпоха сменится и файл понадобится новый).
    let spent = Arc::new(Mutex::new(match issuer_auth.spent_log_path() {
        Some(path) => match open_spent_log(&path) {
            Ok(f) => SpentStore::open(f, issuer_auth.epoch_now()),
            Err(e) => {
                eprintln!(
                    "[citadel-m1:server] ⚠ L-3: {e:#} — spent-множество только в RAM: рестарт \
                     exit'а снова позволит потратить токен второй раз"
                );
                SpentStore::ram_only()
            }
        },
        None => SpentStore::ram_only(),
    }));
    // C4: пул адресов с освобождением на disconnect (замена монотонного AtomicU16).
    let pool = Arc::new(Mutex::new(AddrPool::from_env()));

    // M7 PQ-auth: ML-DSA-65 keypair (если задан Citadel_MLDSA) + публикация pk клиенту.
    // Гибрид с Ed25519-cert+pin: сервер подписывает привязку nonce‖cert_pin, клиент проверяет.
    let signer = Arc::new(if std::env::var("Citadel_MLDSA").is_ok() {
        // A7: постоянный seed (Citadel_KEY_DIR) → стабильный ML-DSA pub (commitment в ссылках цел);
        // иначе эфемерный ключ (демо/back-compat).
        let s = match std::env::var("Citadel_KEY_DIR") {
            Ok(dir) => citadel_quic::pqauth::ServerSigner::from_seed(&persistent_mldsa_seed(&dir)?)?,
            Err(_) => citadel_quic::pqauth::ServerSigner::generate()?,
        };
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

    // F7/D3: per-client лимит. M-3-bis — по ОБОИМ направлениям (вниз лимита не было вовсе, а
    // именно вниз идёт основная нагрузка релея и амплификация «мало запросил — много получил»).
    let rate_limit = citadel_quic::ratelimit::RateLimits::from_env();
    match (rate_limit.up, rate_limit.down) {
        (None, None) => {}
        (up, down) => {
            let show = |c: Option<RateCfg>| match c {
                Some(c) => format!("{:.0} б/с (burst {:.0} б)", c.rate, c.burst),
                None => "без лимита".to_string(),
            };
            eprintln!(
                "[Citadel-m1:server] F7 rate-limit на клиента: ↑ {} · ↓ {}",
                show(up),
                show(down)
            );
        }
    }

    // C7.2: admin-VIP:порт (пропуск в data-plane к admin-каналу issuer'а по туннелю). Политика
    // клонируется в per-client задачи наравне с rate_limit; ядровые правила (DNAT, G1-запреты)
    // ставит server_setup_net по ней же. Нет admin-env → admin-плоскость по туннелю выключена.
    if let Some((ip, port)) = policy.admin_dst {
        eprintln!(
            "[citadel-m1:server] C7.2 admin-plane: пропуск в data-plane к {}.{}.{}.{}:{port} (DNAT → issuer)",
            ip[0], ip[1], ip[2], ip[3]
        );
    }
    for d in &policy.deny_dsts {
        eprintln!(
            "[citadel-m1:server] G1: {}.{}.{}.{} из туннеля недостижим{}",
            d[0], d[1], d[2], d[3],
            match policy.allow_dsts.iter().find(|(a, _)| a == d) {
                Some((_, p)) => format!(" (кроме TCP :{p})"),
                None => String::new(),
            }
        );
    }

    // TCP-fallback listener (M4): bind ДО сброса привилегий (порт <1024). Только при obfs PSK
    // (obfs-over-TCP использует тот же L1). Включается env `Citadel_TCP_LISTEN` (напр. 0.0.0.0:443).
    let tcp_listener = match (std::env::var("Citadel_TCP_LISTEN"), obfs) {
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

    // TCP-fallback acceptor (S0.3/H1): каждый accept'нутый obfs-TCP стрим → свой quinn-Endpoint
    // (single-conn); клиент делает обычный PQ-QUIC хендшейк поверх TCP. Та же крипта/pin/токены.
    if let (Some(listener), Some(src)) = (tcp_listener, obfs) {
        let tun = tun.clone();
        let issuer_auth = issuer_auth.clone();
        let spent = spent.clone();
        let signer = signer.clone();
        let router = router.clone();
        let pool = pool.clone();
        let policy = policy.clone();
        // S2.5/A5: каждый accept'нутый TCP-стрим аллоцирует quinn-Endpoint + задачи ДО обфс/PQ-auth;
        // флуд «молчаливыми» коннектами (ничего не шлют) копил бы их безлимитно (DoS-исчерпание
        // fd/памяти). Ограничиваем число ОДНОВРЕМЕННЫХ pre-auth хендшейков семафором (нет слота →
        // мгновенный дроп) + таймаут на сам хендшейк (idle-коннект не висит вечно). Слот держим
        // только на время хендшейка — established-сессии его не занимают.
        let tcp_sema = Arc::new(tokio::sync::Semaphore::new(TCP_FALLBACK_MAX_INFLIGHT));
        // A5: лог отклонений throttl'им (агрегат раз в секунду). Иначе TCP-флуд, упёршийся в
        // семафор, породил бы строку stderr на КАЖДЫЙ отбитый коннект → лог-амплификация (рост
        // docker json-log/диска) = вторичный DoS поверх уже закрытого исчерпания endpoint'ов.
        let mut rejected: u64 = 0;
        let mut last_reject_log = Instant::now();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let permit = match tcp_sema.clone().try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                drop(stream); // мгновенно закрываем — pre-auth слотов нет
                                rejected += 1;
                                if last_reject_log.elapsed() >= Duration::from_secs(1) {
                                    eprintln!("[citadel-m1:server] TCP-fallback: лимит {TCP_FALLBACK_MAX_INFLIGHT} одновременных хендшейков — отклонено {rejected} соединений за последнюю секунду (A5)");
                                    rejected = 0;
                                    last_reject_log = Instant::now();
                                }
                                continue;
                            }
                        };
                        let (tun, issuer_auth, spent, signer, scfg, router, pool, policy) = (
                            tun.clone(),
                            issuer_auth.clone(),
                            spent.clone(),
                            signer.clone(),
                            tcp_server_cfg.clone(),
                            router.clone(),
                            pool.clone(),
                            policy.clone(),
                        );
                        tokio::spawn(async move {
                            // H-3: те же ключи, что у UDP-кольца — текущая и прошлая эпоха.
                            let keys = src.accepted_keys();
                            let ep = match citadel_quic::server_endpoint_obfs_tcp(stream, scfg, &keys).await {
                                Ok(ep) => ep,
                                Err(e) => {
                                    eprintln!("[citadel-m1:server] obfs-TCP endpoint: {e}");
                                    return;
                                }
                            };
                            // A5: таймаут на весь хендшейк (obfs-gate + PQ-QUIC). Молчаливый/битый
                            // коннект → таймаут → ep и задачи дропаются, слот освобождается.
                            let handshake = async {
                                match ep.accept().await {
                                    Some(incoming) => incoming.await.ok(),
                                    None => None,
                                }
                            };
                            let conn = match tokio::time::timeout(TCP_HANDSHAKE_TIMEOUT, handshake).await {
                                Ok(Some(c)) => c,
                                Ok(None) => {
                                    eprintln!("[citadel-m1:server] obfs-TCP хендшейк не удался");
                                    return;
                                }
                                Err(_) => {
                                    eprintln!("[citadel-m1:server] obfs-TCP хендшейк: таймаут — соединение отклонено (A5)");
                                    return;
                                }
                            };
                            // Хендшейк прошёл (obfs+PQ+токен впереди) → освобождаем pre-auth слот:
                            // established-сессия лимит одновременных хендшейков больше не держит.
                            drop(permit);
                            handle_client(Tunnel::new(conn, true), tun, issuer_auth, spent, rate_limit, policy, signer, pin, router, pool).await;
                            // ep жив до конца handle_client (в scope) → соединение не рвётся
                        });
                    }
                    Err(e) => {
                        eprintln!("[citadel-m1:server] TCP accept: {e}");
                        break;
                    }
                }
            }
        });
    }

    // QUIC accept loop (основной транспорт). C6: семафор ограничивает ОДНОВРЕМЕННЫЕ pre-auth QUIC/UDP-
    // хендшейки (симметрично A5 на TCP) — флуд хендшейками не копит задачи/память до токен-гейта. Слот
    // держится только на хендшейк (established-сессия не занимает). Лог отклонений throttl'им (как A5).
    let udp_sema = Arc::new(tokio::sync::Semaphore::new(UDP_MAX_INFLIGHT));
    let mut udp_rejected: u64 = 0;
    let mut udp_last_log = Instant::now();
    while let Some(incoming) = ep.accept().await {
        let permit = match udp_sema.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                incoming.ignore(); // над лимитом pre-auth → тихо отклонить (без ответа/состояния)
                udp_rejected += 1;
                if udp_last_log.elapsed() >= Duration::from_secs(1) {
                    eprintln!("[citadel-m1:server] QUIC: лимит {UDP_MAX_INFLIGHT} одновременных хендшейков — отклонено {udp_rejected} за секунду (C6)");
                    udp_rejected = 0;
                    udp_last_log = Instant::now();
                }
                continue;
            }
        };
        let tun = tun.clone();
        let issuer_auth = issuer_auth.clone();
        let spent = spent.clone();
        let signer = signer.clone();
        let router = router.clone();
        let pool = pool.clone();
        let policy = policy.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    drop(permit); // хендшейк прошёл → освободить pre-auth слот (established не держит)
                    handle_client(Tunnel::new(conn, false), tun, issuer_auth, spent, rate_limit, policy, signer, pin, router, pool).await;
                }
                // L-15: сообщение об ошибке несёт reason-фразу КЛИЕНТА (недоверенный пир) —
                // без обеззараживания он вписывал бы свои строки в лог exit'а.
                Err(e) => eprintln!(
                    "[citadel-m1:server] хендшейк не удался: {}",
                    citadel_quic::peer_text(e)
                ),
            }
        });
    }
    Ok(())
}

/// Обслуживание одного клиента (любой транспорт): выдать адрес (токен M4, адрес из пула ПОСЛЕ
/// токена — C6) + качать туннель. Адрес освобождается в пул по завершении (C4).
#[allow(clippy::too_many_arguments)]
async fn handle_client(
    mut tunnel: Tunnel,
    tun: Arc<Tun>,
    issuer_auth: Arc<IssuerAuth>,
    spent: Arc<Mutex<SpentStore>>,
    rate_limit: citadel_quic::ratelimit::RateLimits,
    policy: citadel_quic::dataplane::EgressPolicy,
    signer: Arc<Option<citadel_quic::pqauth::ServerSigner>>,
    cert_pin: [u8; 32],
    router: ExitTunRouter,
    pool: Arc<Mutex<AddrPool>>,
) {
    // no-logs: IP клиента + время подключения = деанонимизирующая пара; см. citadel_quic::debug_logs
    citadel_quic::dlog!("[citadel-m1:server] клиент {} ({}) подключён", tunnel.peer(), tunnel.kind());
    let (addr, prefix) = match server_assign_address(
        &mut tunnel, &pool, &issuer_auth, &spent, (*signer).as_ref(), cert_pin,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => {
            citadel_quic::dlog!("[citadel-m1:server] отказ в доступе: {e}");
            tunnel.close(1, b"auth-failed");
            return;
        }
    };
    citadel_quic::dlog!("[citadel-m1:server] выдан {}.{}.{}.{}/{}", addr[0], addr[1], addr[2], addr[3], prefix);
    // Регистрируем адрес в демуксе на время сессии → return-пакеты пойдут ИМЕННО этому клиенту
    // (не «украдёт» соседний pump). Снимаем регистрацию + освобождаем пул по завершении pump.
    let return_rx = router.register(addr);
    let res = pump(tunnel, tun, Some(addr), None, rate_limit, policy, Some(return_rx)).await;
    router.unregister(addr);
    pool.lock().unwrap().free(addr); // C4: вернуть адрес в пул
    if let Err(e) = res {
        citadel_quic::dlog!("[citadel-m1:server] pump завершён: {}", citadel_quic::peer_text(e));
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
    // P-1: диагностический сокет — тоже сокет движка, и маршрут у него явный (мимо туннеля:
    // probe проверяет реакцию exit'а из обычной сети, а не изнутри собственного туннеля).
    let std_sock = citadel_quic::protect::bind_udp_ephemeral(citadel_quic::protect::Route::Bypass)?;
    std_sock.set_nonblocking(true)?;
    let sock = tokio::net::UdpSocket::from_std(std_sock)?;
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
    // H-3: проба идёт по тому же L1, что и настоящий клиент — ключом эпохи, если он выдан
    // (`Citadel_OBFS_EPOCH_FILE`), иначе бутстрапным PSK. Иначе auth-probe стучалась бы в exit
    // ключом, который тот больше не принимает, и «отказ» означал бы не то, что проверяется.
    let ep = match citadel_quic::config::ClientConfig::from_env()?.transport_psk() {
        Some(p) => citadel_quic::client_endpoint_obfs(p, citadel_quic::pacing_profile(None))?,
        None => citadel_quic::client_endpoint_plain()?,
    };
    let cfg = match read_pin_for(citadel_quic::client::host_of(&connect)) {
        PinMode::Pinned(p) => citadel_quic::client_config_pinned(citadel_quic::kx_groups_from_env(), p)?,
        _ => citadel_quic::client_config(citadel_quic::kx_groups_from_env())?,
    };
    let conn = tokio::time::timeout(Duration::from_secs(6), ep.connect_with(cfg, addr, &server_name)?)
        .await
        .map_err(|_| anyhow!("таймаут"))??;
    eprintln!("[auth-probe] транспорт ОК (obfs+PQ+pin); предъявляю ПОДДЕЛЬНЫЙ токен…");

    let mut forged = vec![0u8; citadel_token::voprf::REDEEM_LEN];
    rand::thread_rng().fill_bytes(&mut forged);
    let req = capsule::encode_address_request_v4(&capsule::AssignedV4 { request_id: 1, addr: [0, 0, 0, 0], prefix: 0 });

    // H-2: обмен теперь двухшаговый. Шаг 1 — только nonce (проба ответ сервера не проверяет:
    // её предмет — реакция на ПОДДЕЛЬНЫЙ ТОКЕН, а PQ-auth сервера покрыта ТЕСТом 15).
    let mut nonce = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(&nonce).await?;
    send.finish()?;
    if recv.read_to_end(8192).await.is_err() {
        println!("[auth-probe] сервер не прошёл шаг 1 (PQ-auth) — до токена дело не дошло");
        return Ok(());
    }

    // Шаг 2 — предъявляем поддельный токен.
    let mut out = citadel_masque::varint::to_vec(forged.len() as u64);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// AddrPool из адреса шлюза с префиксом (без env) — для тестов пула.
    fn pool_gw(gw: [u8; 4], prefix: u8) -> AddrPool {
        let ip = u32::from(std::net::Ipv4Addr::new(gw[0], gw[1], gw[2], gw[3]));
        let net = ip & (u32::MAX << (32 - prefix as u32));
        let hosts = 1u32 << (32 - prefix as u32);
        AddrPool { net, prefix, hosts, gw: ip - net, used: HashSet::new(), next: 1 }
    }

    /// Штатная раскладка: шлюз — первый адрес подсети (10.7.0.1/prefix).
    fn pool(prefix: u8) -> AddrPool {
        pool_gw([10, 7, 0, 1], prefix)
    }

    /// C4: пул выдаёт РАЗНЫЕ адреса, пропускает reserved (network/gateway/broadcast), исчерпание →
    /// None (а не тихая коллизия), free возвращает адрес в пул.
    #[test]
    fn addr_pool_alloc_free_exhaust() {
        let mut p = pool(29); // /29 = 8 адресов; usable host-idx [2,6] = 5 (пропуск .0/.1/.7)
        let mut all = Vec::new();
        for _ in 0..5 {
            let a = p.alloc().expect("выдача");
            assert!((2..=6).contains(&a[3]), "reserved не должен выдаваться: {a:?}");
            all.push(a);
        }
        let uniq: HashSet<_> = all.iter().collect();
        assert_eq!(uniq.len(), 5, "все выданные адреса различны");
        assert!(p.alloc().is_none(), "пул /29 исчерпан после 5 выдач");
        p.free(all[0]); // освободили один → снова доступен ровно один
        assert!(p.alloc().is_some());
        assert!(p.alloc().is_none(), "снова исчерпан");
    }

    /// C4-регрессия: адреса НЕ вылезают за /24 (старый AtomicU16 давал 10.7.1.x после 253 коннектов).
    #[test]
    fn addr_pool_24_stays_in_subnet() {
        let mut p = pool(24); // 10.7.0.0/24, usable .2..254 = 253
        for _ in 0..253 {
            let a = p.alloc().unwrap();
            assert_eq!([a[0], a[1], a[2]], [10, 7, 0], "адрес вне /24: {a:?}");
            assert!((2..=254).contains(&a[3]));
        }
        assert!(p.alloc().is_none(), "/24 исчерпан на 253 адресах");
    }

    /// Штатная сеть /16: пул остаётся внутри подсети и не выдаёт адрес шлюза.
    #[test]
    fn addr_pool_16_is_default_shape() {
        let mut p = pool(16);
        assert_eq!(p.capacity(), 65533, "/16: 65536 минус network, broadcast и шлюз");
        for _ in 0..1000 {
            let a = p.alloc().unwrap();
            assert_eq!([a[0], a[1]], [10, 7], "адрес вне /16: {a:?}");
            assert_ne!(a, [10, 7, 0, 1], "выдан адрес шлюза");
        }
    }

    /// Запас на расширение до /12. Здесь ломался бы прежний пул: сеть становится 10.0.0.0/12,
    /// шлюз 10.7.0.1 лежит НЕ первым адресом, и «пропускаем сеть+1» его больше не защищает —
    /// он достался бы клиенту (коллизия с exit'ом и с admin-каналом ADMIN_VIP).
    #[test]
    fn addr_pool_12_never_hands_out_gateway() {
        let mut p = pool_gw([10, 7, 0, 1], 12);
        assert_eq!(p.capacity(), (1 << 20) - 3);
        // Гоним пул через окрестность шлюза: индекс 458753 должен быть пропущен.
        let gw_idx = 0x0007_0001u32;
        p.next = gw_idx - 2;
        let got: Vec<[u8; 4]> = (0..5).map(|_| p.alloc().unwrap()).collect();
        assert!(!got.contains(&[10, 7, 0, 1]), "выдан адрес шлюза: {got:?}");
        assert!(got.contains(&[10, 7, 0, 0]) && got.contains(&[10, 7, 0, 2]), "соседи выданы: {got:?}");
        for a in &got {
            assert!(a[0] == 10 && a[1] < 16, "адрес вне 10.0.0.0/12: {a:?}");
        }
    }

    /// Исчерпанный пул отвечает `None` сразу, не прочёсывая host-пространство (анти-DoS: на /12
    /// такой скан — миллион итераций под общим мьютексом на каждый коннект).
    #[test]
    fn addr_pool_exhausted_is_cheap() {
        let mut p = pool(29); // 8 адресов → capacity 5
        assert_eq!(p.capacity(), 5);
        for _ in 0..5 {
            p.alloc().unwrap();
        }
        let before = p.next;
        assert!(p.alloc().is_none());
        assert_eq!(p.next, before, "исчерпанный пул не должен даже двигать курсор");
    }

    /// C5: double-spend ловится; prune чистит бакеты старше current-1; Legacy (эпоха 0) не чистится.
    #[test]
    fn spend_token_double_spend_and_prune() {
        let spent = Mutex::new(SpentStore::ram_only());
        let (n1, n2) = ([1u8; 32], [2u8; 32]);
        assert!(spend_token(&spent, n1, 100));
        assert!(!spend_token(&spent, n1, 100), "double-spend в той же эпохе");
        assert!(spend_token(&spent, n2, 100));
        // эпоха 101 (current) — prev-бакет 100 остаётся (grace)
        assert!(spend_token(&spent, [3u8; 32], 101));
        assert!(spent.lock().unwrap().seen.contains_key(&100), "prev-эпоха цела");
        // эпоха 103 → prune бакетов < 102 (100 и 101 удаляются)
        assert!(spend_token(&spent, [4u8; 32], 103));
        let m = spent.lock().unwrap();
        assert!(!m.seen.contains_key(&100) && !m.seen.contains_key(&101), "старые эпохи очищены");
        assert!(m.seen.contains_key(&103));
        drop(m);

        // Legacy (эпоха 0) — не чистится даже при больших эпохах; double-spend всё равно ловится
        let legacy = Mutex::new(SpentStore::ram_only());
        assert!(spend_token(&legacy, [9u8; 32], 0));
        assert!(spend_token(&legacy, [8u8; 32], 500));
        assert!(legacy.lock().unwrap().seen.contains_key(&0), "Legacy-бакет цел");
        assert!(!spend_token(&legacy, [9u8; 32], 0), "Legacy double-spend ловится");
    }

    /// L-3: журнал переживает «рестарт» exit'а — потраченный токен не проходит второй раз в новом
    /// процессе, а бакеты старше current-1 (которые всё равно не проверить ключами) удаляются.
    #[test]
    fn spent_log_survives_restart_and_prunes_old_epochs() {
        let path = std::env::temp_dir().join(format!("citadel-spent-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let reopen = |epoch: u64| Mutex::new(SpentStore::open(open_spent_log(&path).unwrap(), epoch));
        let (n1, n2) = ([0xa1u8; 32], [0xa2u8; 32]);

        // «первый запуск»: потратили два токена в эпохе 100
        {
            let s = reopen(100);
            assert!(spend_token(&s, n1, 100));
            assert!(spend_token(&s, n2, 100));
            assert!(!spend_token(&s, n1, 100));
        }
        // «рестарт» в той же эпохе: множество поднялось с диска — повторная трата не проходит
        {
            let s = reopen(100);
            assert!(!spend_token(&s, n1, 100), "рестарт обнулил spent — токен потрачен дважды");
            assert!(!spend_token(&s, n2, 100));
            assert!(spend_token(&s, [0xa3u8; 32], 100), "новый токен по-прежнему принимается");
        }
        // grace: в эпохе 101 бакет 100 ещё проверяется (ключ prev-эпохи жив)
        {
            let s = reopen(101);
            assert!(!spend_token(&s, n1, 100));
        }
        // эпоха 103: бакет 100 уже не проверить ни одним ключом ⇒ он уходит и из файла
        {
            let s = reopen(103);
            assert!(spend_token(&s, [0xa4u8; 32], 103));
            assert!(spend_token(&s, n1, 103), "тот же nonce в НОВОЙ эпохе — другой бакет");
        }
        let raw = std::fs::read(&path).unwrap();
        assert_eq!(raw.len() % SPENT_REC, 0);
        assert!(
            raw.chunks_exact(SPENT_REC)
                .all(|r| u64::from_be_bytes(r[..8].try_into().unwrap()) >= 102),
            "просроченные бакеты не должны оставаться на диске"
        );
        // …и после ротации файл читается обратно без мусора
        let s = reopen(103);
        assert!(!spend_token(&s, [0xa4u8; 32], 103));
        std::fs::remove_file(&path).ok();
    }
}
