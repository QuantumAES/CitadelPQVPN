//! CitadelPQVPN — клиентская оркестрация движка: установка сессии и data-plane.
//!
//! [`establish_session`] поднимает транспорт (failover по списку exit'ов, M5) и делает
//! control-обмен (анонимный токен → назначенный адрес, PQ-auth M7) — **без TUN и без
//! сетевой настройки**. [`run_data_plane`] гоняет пакеты между TUN и транспортом.
//!
//! Разделение `establish` / `data_plane` — предпосылка мобильной совместимости: ОС
//! (Android `VpnService.Builder`) требует адрес туннеля ДО выдачи fd, поэтому сначала
//! получаем адрес (establish), затем конфигурируем TUN, затем качаем (data_plane).
//! Сетевую настройку интерфейса (адрес/маршруты/DNS) делает вызывающий: на Linux —
//! `NetConfigurator` в бинаре, на Android — `VpnService.Builder`. См. docs/CLIENT-ARCH.md §4.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use rand::RngCore;

use citadel_masque::{capsule, datagram, ip};
use citadel_tun::TunIo;

use crate::config::{ClientConfig, MldsaExpect, PinMode};
use crate::dataplane::{pump, ClientPath, Tunnel};

/// Установленная клиентская сессия: поднятый транспорт + назначенный сервером адрес.
/// Сетевую настройку интерфейса делает вызывающий (Linux `NetConfigurator`, Android
/// `VpnService.Builder` — адрес скармливается ДО получения fd).
pub struct Session {
    tunnel: Tunnel, // приватный: транспорт целиком уходит в run_data_plane
    /// Назначенный exit'ом IPv4-адрес клиента.
    pub addr: [u8; 4],
    /// Длина префикса назначенного адреса.
    pub prefix: u8,
    /// Выбранный exit `host:port` (для логов/диагностики).
    pub chosen: String,
}

impl Session {
    /// Транспорт сессии: `"QUIC/UDP"` или `"obfs-TCP"`.
    pub fn transport(&self) -> &'static str {
        self.tunnel.kind()
    }
    /// Фактический адрес exit'а, с которым говорит транспорт (для bypass-маршрута на Linux —
    /// исключить собственные пакеты к exit из full-tunnel, иначе петля маршрутизации).
    pub fn peer_addr(&self) -> SocketAddr {
        self.tunnel.peer()
    }

    /// Максимальный размер inner-IP-пакета (TUN MTU), влезающий в одну QUIC-датаграмму:
    /// `max_datagram_size` − 1 байт на context-varint (CTX_RAW_IP=0). `None` для obfs-TCP
    /// (record-фрейминг несёт любой размер) или если датаграммы недоступны. Вызывающий
    /// клампит TUN MTU под это значение — иначе полноразмерные пакеты дропаются в `pump`
    /// («datagram too large») и трафик не идёт.
    pub fn quic_datagram_mtu(&self) -> Option<usize> {
        self.tunnel.conn().max_datagram_size().map(|m| m.saturating_sub(1))
    }
    /// Назначенный адрес в форме CIDR (например, `"10.7.0.3/24"`).
    pub fn cidr(&self) -> String {
        format!(
            "{}.{}.{}.{}/{}",
            self.addr[0], self.addr[1], self.addr[2], self.addr[3], self.prefix
        )
    }

    /// Диагностическая **egress-проба** (только QUIC-транспорт): собирает DNS-запрос A-записи
    /// `qname` к резолверу `resolver`, отправляет сырым IPv4/UDP-пакетом прямо в туннель
    /// (минуя ОС-роутинг и TUN) и ждёт ответ. Так проверяется, что exit реально форвардит и
    /// NAT'ит наружу — **без** поднятия TUN/маршрутов/root, поэтому изолирует «сервер egress
    /// сломан» от «клиентский роутинг сломан» (петля на full-tunnel и т.п.).
    ///
    /// `Ok(Some(addrs))` — резолвер ответил (egress+NAT работают); `Ok(None)` — транспорт
    /// obfs-TCP (проба не поддержана); `Err` — таймаут/ошибка отправки.
    pub async fn egress_dns_probe(
        &self,
        resolver: [u8; 4],
        qname: &str,
        timeout: Duration,
    ) -> Result<Option<Vec<[u8; 4]>>> {
        let conn = self.tunnel.conn();
        let id: u16 = rand::random();
        let sport: u16 = 20000 + (rand::random::<u16>() % 20000);
        let query = ip::build_dns_query(id, qname, 1); // A-запись
        let pkt = ip::build_udp4(self.addr, sport, resolver, 53, &query);
        let dg = datagram::encode(datagram::CTX_RAW_IP, &pkt);
        conn.send_datagram(bytes::Bytes::from(dg))
            .map_err(|e| anyhow!("egress-проба: не отправить датаграмму: {e}"))?;

        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(anyhow!("egress-проба: нет DNS-ответа за {}с (exit не форвардит?)", timeout.as_secs()));
            }
            let dg = match tokio::time::timeout(remaining, conn.read_datagram()).await {
                Ok(Ok(dg)) => dg,
                Ok(Err(e)) => {
                    // L-15: reason-фраза закрытия — текст пира
                    return Err(anyhow!("egress-проба: транспорт закрыт: {}", crate::peer_text(e)));
                }
                Err(_) => return Err(anyhow!("egress-проба: нет DNS-ответа за {}с (exit не форвардит?)", timeout.as_secs())),
            };
            let Some((datagram::CTX_RAW_IP, inner)) = datagram::decode(&dg) else { continue };
            let Some(u) = ip::parse_udp4(inner) else { continue };
            if u.src != resolver || u.dport != sport {
                continue; // не наш ответ
            }
            if let Some((rid, _an, addrs)) = ip::parse_dns_response(u.payload) {
                if rid == id {
                    return Ok(Some(addrs));
                }
            }
        }
    }

    /// Диагностическая **admin-проба** (C7.2): TCP-SYN на `vip:port` сырым пакетом прямо в туннель
    /// (минуя ОС-роутинг и TUN) и ожидание ответа. Отделяет два разных диагноза одной жалобы
    /// «не открывается список абонентов»:
    ///   * нет ответа → admin-плоскость на стороне exit'а не доходит до issuer (egress-исключение
    ///     C7.2 не настроено / DNAT не стоит / issuer не слушает);
    ///   * `Ok(true)` (SYN-ACK) → канал по туннелю ЖИВ, значит проблема в маршрутизации ОС клиента
    ///     до `vip` (split-tunnel/route/EHOSTUNREACH) либо выше — в TLS/аутентификации admin-канала.
    ///
    /// `Ok(false)` — пришёл RST: пакет дошёл до стека, но порт закрыт (issuer не поднят/DNAT в никуда).
    /// Полуоткрытое соединение на issuer'е закрываем RST'ом (не оставляем висеть до таймаута).
    pub async fn admin_syn_probe(
        &self,
        vip: [u8; 4],
        port: u16,
        timeout: Duration,
    ) -> Result<bool> {
        let conn = self.tunnel.conn();
        let sport: u16 = 40000 + (rand::random::<u16>() % 20000);
        let seq: u32 = rand::random();
        let syn = ip::build_tcp4(self.addr, sport, vip, port, seq, 0, ip::TCP_SYN, 64240);
        conn.send_datagram(bytes::Bytes::from(datagram::encode(datagram::CTX_RAW_IP, &syn)))
            .map_err(|e| anyhow!("admin-проба: не отправить датаграмму: {e}"))?;

        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(anyhow!(
                    "admin-проба: нет ответа от {}.{}.{}.{}:{port} за {}с",
                    vip[0], vip[1], vip[2], vip[3], timeout.as_secs()
                ));
            }
            let dg = match tokio::time::timeout(remaining, conn.read_datagram()).await {
                Ok(Ok(dg)) => dg,
                Ok(Err(e)) => {
                    return Err(anyhow!("admin-проба: транспорт закрыт: {}", crate::peer_text(e)));
                }
                Err(_) => continue, // истечёт на следующей проверке deadline
            };
            let Some((datagram::CTX_RAW_IP, inner)) = datagram::decode(&dg) else { continue };
            let Some(t) = ip::parse_tcp4(inner) else { continue };
            if t.src != vip || t.sport != port || t.dport != sport {
                continue; // не наш ответ
            }
            if t.flags & ip::TCP_RST != 0 {
                return Ok(false); // порт закрыт (issuer не слушает / DNAT в никуда)
            }
            if t.flags & (ip::TCP_SYN | ip::TCP_ACK) == (ip::TCP_SYN | ip::TCP_ACK) {
                // закрываем полуоткрытое соединение на issuer'е (иначе висит до его таймаута)
                let rst = ip::build_tcp4(
                    self.addr, sport, vip, port,
                    seq.wrapping_add(1), t.seq.wrapping_add(1),
                    ip::TCP_RST | ip::TCP_ACK, 0,
                );
                let _ = conn
                    .send_datagram(bytes::Bytes::from(datagram::encode(datagram::CTX_RAW_IP, &rst)));
                return Ok(true);
            }
        }
    }
}

/// Хост-часть `host:port` (для pin-файла и TCP-fallback цели).
pub fn host_of(server: &str) -> &str {
    server.rsplit_once(':').map(|(h, _)| h).unwrap_or(server)
}

/// Порт-часть `host:port` (для диагностических сообщений); по умолчанию `4433`.
pub fn port_of(server: &str) -> &str {
    server.rsplit_once(':').map(|(_, p)| p).unwrap_or("4433")
}

/// S0.1/H2 fail-closed: без активного серт-pin QUIC поднимать нельзя (AcceptAnyServerCert =
/// открытый MITM). Отказ, кроме явного dev-флага `allow_insecure_no_pin`. `Waiting` (pin-источник
/// задан, файл ещё не готов) — не отказ: вызывающий подождёт/переберёт.
fn require_pin_or_insecure(mode: &PinMode, allow_insecure_no_pin: bool) -> Result<()> {
    if matches!(mode, PinMode::NoPin) && !allow_insecure_no_pin {
        return Err(anyhow!(
            "серт-pin не настроен — отказ (fail-closed, S0.1/H2). Провижинь pin или задай \
             Citadel_INSECURE_NO_PIN=1 для dev/PoC"
        ));
    }
    Ok(())
}

/// M-2/аудит-4 fail-closed: сессия обязана быть пост-квантовой. `classical`/`all` пропускаются
/// только явным dev-флагом (`Citadel_INSECURE_CLASSICAL_KX=1`) — им пользуется харнес
/// crypto-agility, но ни ссылка, ни бандл его выставить не могут.
fn require_pq_kx(suite: &str, allow_classical: bool) -> Result<()> {
    if crate::kx_is_pq(suite) {
        return Ok(());
    }
    if allow_classical {
        eprintln!(
            "[citadel-m1:client] ⚠ INSECURE: KX={} — сессия НЕ пост-квантовая (нет защиты от \
             Harvest-Now-Decrypt-Later), разрешено флагом Citadel_INSECURE_CLASSICAL_KX",
            crate::kx_suite_name(suite)
        );
        return Ok(());
    }
    Err(anyhow!(
        "KX={} не гарантирует пост-квантовую сессию — отказ (fail-closed, M-2). Профиль требует \
         kx_suite=pq; если ссылка пришла с другим значением, запросите новую у администратора",
        crate::kx_suite_name(suite)
    ))
}

/// Поднять сессию: failover по списку exit'ов (M5) + control-обмен (токен→адрес, PQ-auth M7).
/// **Без TUN и без сетевой настройки** — только транспорт и назначенный адрес. `force_tcp` — идти
/// сразу obfs-TCP (минуя QUIC/UDP): эскалация VpnController'а, когда QUIC-хендшейк проходит, но
/// мобильный/NAT64-путь не несёт крупные пакеты через QUIC (MTU: хендшейк ок, но большой ML-DSA-ответ
/// сервера чёрнодырится) — TCP решает сегментацией/MSS.
pub async fn establish_session(cfg: &ClientConfig, force_tcp: bool) -> Result<Session> {
    eprintln!("[citadel-m1:client] exit-серверы (перемешаны): {}", cfg.servers.join(", "));
    // M-2/аудит-4: не-PQ suite — ОТКАЗ, а не предупреждение.
    //
    // `kx_suite` приходит из ССЫЛКИ (`CredentialLink::to_client_config`), то есть подменённая при
    // доставке или злонамеренно выпущенная ссылка со значением `classical` понижала бы сессию до
    // чистого X25519 — без всякой защиты от Harvest-Now-Decrypt-Later. Раньше единственной
    // реакцией был `eprintln!`, который не превращается в `VpnEvent` и до интерфейса не доходит:
    // пользователь видел «Защищено» над классическим хендшейком. `all` тоже не гарантия — он
    // молча откатывается на X25519, если сервер не PQ (см. `kx_is_pq`).
    require_pq_kx(&cfg.kx_suite, cfg.allow_classical_kx)?;

    // M5 multi-server: идём по списку failover'ом — первый поднявшийся exit (QUIC или TCP-fallback).
    // Копим причины отказа по каждому exit — уходят в итоговую ошибку (видно в UI/лог-панели на
    // Android, где per-attempt eprintln иначе не разглядеть).
    let mut tunnel = None;
    let mut chosen = String::new();
    let mut reasons: Vec<String> = Vec::new();
    for server in &cfg.servers {
        match connect_server(server, cfg, force_tcp).await {
            Ok(Some(t)) => {
                eprintln!("[citadel-m1:client] ВЫБРАН exit {server} (транспорт {})", t.kind());
                tunnel = Some(t);
                chosen = server.clone();
                break;
            }
            Ok(None) => {
                let why = if cfg.obfs_psk.is_some() {
                    format!("{server}: QUIC/UDP:{} и obfs-TCP:{} недоступны", port_of(server), cfg.tcp_port)
                } else {
                    format!("{server}: QUIC/UDP:{} недоступен (obfs-fallback не настроен)", port_of(server))
                };
                eprintln!("[citadel-m1:client] {why} — пробую следующий");
                reasons.push(why);
            }
            Err(e) => {
                let why = format!("{server}: {e}");
                eprintln!("[citadel-m1:client] {why} — пробую следующий");
                reasons.push(why);
            }
        }
    }
    let mut tunnel = tunnel
        .ok_or_else(|| anyhow!("ни один exit недоступен:\n{}", reasons.join("\n")))?;

    // M7 PQ-auth: pin (Ed25519-cert) + ML-DSA-65 pk выбранного exit — полный pub (провижирован)
    // ЛИБО обязательство H(pub) из ссылки (полный pub дотянем по каналу, commitment-fetch §S3).
    let host = host_of(&chosen);
    let mldsa = cfg.mldsa_expect(host)?; // M-1: нечитаемый провижированный ML-DSA pub — отказ
    let pq_active = !matches!(mldsa, MldsaExpect::None);
    // S0.1/H2: cert_pin для ML-DSA-привязки = АКТИВНЫЙ pin. При Pinned rustls уже заставил живой
    // серт совпасть с pin ⇒ привязка идёт к живой сессии. Без активного pin привязывать не к чему
    // (иначе подпись над константой [0;32] — бесполезна против MITM) → отказ.
    let cert_pin = match cfg.pin_for(host) {
        PinMode::Pinned(p) => p,
        _ => {
            if pq_active {
                return Err(anyhow!(
                    "PQ-auth: ML-DSA (pub/commit) провижирован для {host}, но серт-pin не активен — \
                     отказ (fail-closed, S0.1/H2)"
                ));
            }
            [0u8; 32]
        }
    };
    if pq_active {
        eprintln!("[citadel-m1:client] PQ-auth (M7): буду проверять ML-DSA-65 подпись exit {host}");
    }

    // M2+M4/M5: предъявляем анонимный токен и получаем адрес капсулой
    if cfg.token.is_empty() {
        eprintln!("[citadel-m1:client] WARN: токен (Citadel_TOKENS) не задан — exit может отказать");
    } else {
        eprintln!("[citadel-m1:client] предъявляю анонимный токен ({} б)", cfg.token.len());
    }
    let a = client_request_address(&mut tunnel, &cfg.token, &mldsa, cert_pin).await?;
    Ok(Session {
        tunnel,
        addr: a.addr,
        prefix: a.prefix,
        chosen,
    })
}

/// Запустить data-plane: перекачка пакетов TUN ⇄ транспорт. Клиент себя не лимитирует
/// (rate-limit F7 — забота exit). Поглощает `session` (транспорт уходит в `pump`).
pub async fn run_data_plane(session: Session, tun: Arc<dyn TunIo>) -> Result<()> {
    // клиент: egress-фильтр/rate-limit/admin-VIP выключены (это политика exit-стороны).
    // return_rx=None — у клиента один TUN и одно соединение, читает свой TUN сам (демукс — только exit).
    // ClientPath — чистая диагностика (pump ничего не фильтрует): назначенный адрес, чтобы назвать
    // пакеты с чужим src (exit дропнет их молча), и адрес exit'а, чтобы отдельно назвать петлю
    // собственного транспорта в собственный туннель.
    let exit = match session.peer_addr().ip() {
        std::net::IpAddr::V4(v4) => Some(v4.octets()),
        std::net::IpAddr::V6(_) => None,
    };
    let path = ClientPath { assigned: session.addr, exit };
    pump(session.tunnel, tun, None, Some(path), None, None, None).await
}

/// Подключиться к ОДНОМУ exit'у: основной путь PQ-QUIC, при недоступности — obfs-over-TCP
/// fallback (M4, порт `cfg.tcp_port`, по умолчанию 443). `force_tcp` — пропустить QUIC/UDP и идти
/// сразу obfs-TCP (MTU-эскалация: QUIC-хендшейк проходит, но мобильный/NAT64-путь не несёт крупные
/// QUIC-пакеты). `None` — exit недоступен → вызывающий пробует следующий из списка (M5 failover).
async fn connect_server(server: &str, cfg: &ClientConfig, force_tcp: bool) -> Result<Option<Tunnel>> {
    let host = host_of(server);
    let Some(addr) = resolve_prefer_v4(server).await else {
        return Ok(None);
    };
    // failover/fallback хотят быстрый QUIC-timeout; один сервер без fallback — ждём дольше.
    if !force_tcp {
        let multi = cfg.servers.len() > 1;
        let attempts = if multi || cfg.obfs_psk.is_some() { 5 } else { 60 };
        if let Some(conn) = try_quic_connect(server, addr, cfg, attempts, host).await? {
            eprintln!("[citadel-m1:client] PQ-туннель (QUIC/UDP) к {server} ✔");
            return Ok(Some(Tunnel::new(conn, false)));
        }
    }
    // S0.3/H1: fallback (или форсированный force_tcp) — PQ-QUIC ПОВЕРХ obfs-TCP (не «голый» PSK).
    // Та же TLS/pin/KX/токены; TCP-транспорт снимает QUIC-MTU-проблему на мобильном/NAT64-пути (MSS).
    if let Some(psk) = cfg.obfs_psk {
        let tcp_target = format!("{host}:{}", cfg.tcp_port);
        if let Some(taddr) = resolve_prefer_v4(&tcp_target).await {
            eprintln!(
                "[citadel-m1:client] {} → PQ-QUIC поверх obfs-TCP к {tcp_target}",
                if force_tcp { format!("MTU-эскалация {server}") } else { format!("QUIC/UDP к {server} недоступен") }
            );
            // таймаут: мёртвый host иначе висит на connect (~минуты) и ломает failover. 8с — запас
            // под высокий RTT мобильных сетей (частый Android-путь при заблокированном UDP).
            match tokio::time::timeout(Duration::from_secs(8), quic_over_tcp_connect(taddr, psk, cfg, host)).await {
                Ok(Ok(conn)) => {
                    eprintln!("[citadel-m1:client] PQ-туннель (QUIC/obfs-TCP) к {tcp_target} ✔");
                    return Ok(Some(Tunnel::new(conn, true)));
                }
                Ok(Err(e)) => eprintln!("[citadel-m1:client] obfs-TCP не удался: {}", crate::peer_text(e)),
                Err(_) => eprintln!("[citadel-m1:client] obfs-TCP: таймаут"),
            }
        }
    }
    Ok(None)
}

/// Резолв `host:port` с ПРЕДПОЧТЕНИЕМ IPv4.
///
/// Клиентский QUIC-эндпоинт биндится на `0.0.0.0:0` (IPv4), а туннель IPv4-only по построению
/// (S2.2/A2). Если у exit'а есть и AAAA, и A, а система вернула первым IPv6, `connect_with` падал
/// сразу на каждой попытке — «UDP:4433 недоступен», хотя недоступен он только по v6. При этом
/// obfs-TCP поднимался (там семейство сокета выбирается по адресу), и снаружи это выглядело как
/// «QUIC не работает, TCP работает» — на мобильных сетях с IPv6 куда чаще, чем на домашнем ПК.
/// Берём v4, если он есть; иначе — первый, что дала система (поведение как раньше).
pub(crate) async fn resolve_prefer_v4(target: &str) -> Option<SocketAddr> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(target).await.ok()?.collect();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .copied()
        .or_else(|| addrs.first().copied())
}

/// S0.3/H1: PQ-QUIC поверх obfs-TCP к exit (fallback при заблокированном UDP). Та же TLS-1.3/
/// hybrid-KEX/pin-логика, что и UDP-путь (`try_quic_connect`) — просто транспорт по TCP.
/// Fail-closed по pin (S0.1): без активного pin — отказ.
async fn quic_over_tcp_connect(
    taddr: SocketAddr,
    psk: [u8; 32],
    cfg: &ClientConfig,
    pin_host: &str,
) -> Result<quinn::Connection> {
    require_pin_or_insecure(&cfg.pin_for(pin_host), cfg.allow_insecure_no_pin)?;
    // Анти-петля (Android): сокет транспорта помечается «мимо туннеля» ДО connect. Без этого
    // obfs-TCP сессия, поднятая до создания TUN, после `establish()` начинала маршрутизироваться
    // в НАШ ЖЕ туннель: её сегменты приходили на exit с адресом источника локальной сети, тот
    // дропал их анти-спуфингом (S0.2) — транспорт умирал за секунды, и клиент падал в бесконечный
    // реконнект. UDP-путь был защищён с C3.3, TCP — нет (на Android этот путь вживую не гоняли).
    let tcp = crate::protect::connect_tcp(taddr).await?;
    let ep = crate::client_endpoint_obfs_tcp(tcp, psk)?;
    let qcfg = match cfg.pin_for(pin_host) {
        PinMode::Pinned(p) => crate::client_config_pinned(crate::kx_groups_for(&cfg.kx_suite), p)?,
        PinMode::NoPin => crate::client_config(crate::kx_groups_for(&cfg.kx_suite))?, // только при insecure-флаге
        PinMode::Waiting => return Err(anyhow!("pin ещё не готов (файл не записан)")),
    };
    let conn = ep.connect_with(qcfg, taddr, &cfg.server_name)?.await?;
    Ok(conn)
}

/// Попытаться поднять PQ-QUIC к одному серверу. `None` — не удалось за `attempts` попыток
/// (UDP/QUIC заблокирован или exit недоступен). Pin берётся per-host (`cfg.pin_for`).
/// `pub(crate)` — переиспользуется диагностикой ([`crate::diag`]) как быстрая проба.
pub(crate) async fn try_quic_connect(
    connect: &str,
    addr: SocketAddr,
    cfg: &ClientConfig,
    attempts: u32,
    pin_host: &str,
) -> Result<Option<quinn::Connection>> {
    let ep = match cfg.obfs_psk {
        Some(psk) => crate::client_endpoint_obfs(psk)?,
        None => quinn::Endpoint::client("0.0.0.0:0".parse()?)?,
    };
    eprintln!(
        "[citadel-m1:client] QUIC: пробую {connect} ({addr}), server_name={}, KX={}",
        cfg.server_name,
        crate::kx_suite_name(&cfg.kx_suite)
    );
    // S0.1/H2: без активного pin — fail-closed (кроме явного insecure-флага). NoPin статичен
    // (PinSource::None), в Pinned по ходу цикла не превратится → проверяем один раз до цикла.
    require_pin_or_insecure(&cfg.pin_for(pin_host), cfg.allow_insecure_no_pin)?;
    let mut logged_pin = false;
    for attempt in 1..=attempts {
        let qcfg = match cfg.pin_for(pin_host) {
            PinMode::Pinned(p) => {
                if !logged_pin {
                    // Сам pin (hex) в журнал НЕ пишем: это стабильный идентификатор сертификата
                    // конкретного exit'а — по нему журнал, отданный в поддержку/утёкший с
                    // устройства, связывает пользователя с сервером. Для диагностики достаточно
                    // факта «pin активен»: несовпадение и так видно по отказу TLS.
                    eprintln!("[citadel-m1:client] pinning {pin_host}: серт-pin активен");
                    logged_pin = true;
                }
                crate::client_config_pinned(crate::kx_groups_for(&cfg.kx_suite), p)?
            }
            PinMode::NoPin => {
                // сюда попадаем только при allow_insecure_no_pin=true (иначе отказ выше)
                if !logged_pin {
                    eprintln!("[citadel-m1:client] ⚠ INSECURE: pin не настроен — принимаю ЛЮБОЙ серт, MITM-открыто (только dev)");
                    logged_pin = true;
                }
                crate::client_config(crate::kx_groups_for(&cfg.kx_suite))?
            }
            PinMode::Waiting => {
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }
        };
        match tokio::time::timeout(Duration::from_secs(3), ep.connect_with(qcfg, addr, &cfg.server_name)?).await {
            Ok(Ok(c)) => return Ok(Some(c)),
            Ok(Err(e)) => eprintln!(
                "[citadel-m1:client] QUIC попытка {attempt}: {}",
                crate::peer_text(e)
            ),
            Err(_) => eprintln!("[citadel-m1:client] QUIC попытка {attempt}: таймаут (exit/UDP недоступен?)"),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Ok(None)
}

/// Control-обмен (M2) в **два шага** — H-2/аудит-4.
///
/// Шаг 1: клиент шлёт только `nonce(32)` и получает `varint(pub_len)‖pub‖varint(sig_len)‖sig`;
/// подпись проверяется НЕМЕДЛЕННО. Шаг 2: лишь после успешной проверки уходит
/// `varint(token_len)‖token‖ADDRESS_REQUEST`, в ответ — `ADDRESS_ASSIGN`.
///
/// Раньше всё это был один round-trip, и токен уходил вместе с nonce — то есть ДО того, как
/// сервер доказал подлинность пост-квантово. Пир, подтверждённый только классически (pin на
/// Ed25519-серте), получал неиспользованный анонимный токен: под CRQC-MITM (ровно тот противник,
/// ради которого введена ML-DSA-привязка) это кража доступа и отказ в обслуживании легитимному
/// абоненту через double-spend. Канал издателя всегда делал наоборот — сервер представляется
/// первым кадром (`citadel_token::pqid::verify_hello`), и exit теперь симметричен.
async fn client_request_address(
    tunnel: &mut Tunnel,
    token: &[u8],
    expect: &MldsaExpect,
    cert_pin: [u8; 32],
) -> Result<capsule::AssignedV4> {
    // ── Шаг 1: заставляем сервер представиться. Ничего своего, кроме случайного nonce. ──
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let buf = tunnel.control_client(&nonce).await?;
    // S2.6/A3: TLS exporter клиентской сессии для channel-binding ML-DSA-подписи (см. verify ниже).
    let exporter = tunnel.exporter()?;
    let (server_pub, sig) = parse_server_auth(&buf)?;

    // M7/§S3: проверяем ML-DSA-65 подпись сервера согласно ожиданию (полный pub / commitment-fetch).
    // Не сошлось — выходим ЗДЕСЬ, не показав токен (в этом весь смысл разделения на два шага).
    verify_server_mldsa(expect, server_pub, &nonce, &cert_pin, &exporter, sig)?;
    match expect {
        MldsaExpect::Pub(_) => eprintln!(
            "[citadel-m1:client] PQ-auth ✔ ML-DSA-65 подпись сервера верна (pub провижирован)"
        ),
        MldsaExpect::Commit(_) => eprintln!(
            "[citadel-m1:client] PQ-auth ✔ commitment-fetch: H(pub)==commit из ссылки + подпись верна"
        ),
        MldsaExpect::None => {}
    }

    // ── Шаг 2: сервер доказан — предъявляем токен и просим адрес. ──
    //
    // M-6: на провод уходит не сам токен, а **предъявление, привязанное к этой сессии**:
    // `nonce ‖ MAC_y(домен ‖ TLS-exporter)`. Секрет `y` остаётся на устройстве, поэтому
    // перехваченный кадр не работает ни в чьей чужой сессии (в прежней схеме blind RSA на провод
    // уходила сама подпись — bearer, и это было неисправимо).
    let redeem = match token.is_empty() {
        true => Vec::new(), // токены выключены на сервере — предъявлять нечего
        false => citadel_token::Token::from_bytes(token)
            .context("сохранённый токен непригоден (устаревший формат? перезапросите у издателя)")?
            .redeem(&citadel_token::redeem_context(&exporter)),
    };
    let req = capsule::AssignedV4 { request_id: 1, addr: [0, 0, 0, 0], prefix: 0 };
    let mut out = citadel_masque::varint::to_vec(redeem.len() as u64);
    out.extend_from_slice(&redeem);
    out.extend_from_slice(&capsule::encode_address_request_v4(&req));
    let buf = tunnel.control_client(&out).await?;

    let (t, val, _) = capsule::decode(&buf).ok_or_else(|| anyhow!("битая капсула в ответе"))?;
    if t != capsule::ADDRESS_ASSIGN {
        return Err(anyhow!("ожидался ADDRESS_ASSIGN, получен type={t}"));
    }
    let assigned =
        capsule::decode_assigned_v4(val).ok_or_else(|| anyhow!("битое тело ADDRESS_ASSIGN"))?;
    validate_assignment(&assigned)?;
    Ok(assigned)
}

/// H-4 (остаток): проверить назначенные сервером адрес и префикс.
///
/// Это **единственное**, что сервер вообще может сказать клиенту по control-плоскости (4 байта
/// адреса и 1 байт префикса), и до сих пор оно принималось как есть. Между тем префикс задаёт, что
/// клиент считает «своей подсетью» — то есть какие адреса пойдут в туннель и с каких он готов
/// принимать (F8 сверяет dst с назначенным). Недобросовестный exit, выдав `10.7.0.5/8`, втягивал бы
/// в туннель весь `10.0.0.0/8` абонента вместе с его домашней/корпоративной сетью, а `/0` — вообще
/// всё. Граница привилегий (`vpnd::valid`, `citadel-helper`) пропускает любой префикс `0..=32`:
/// её задача — не дать инъекцию в `ip`/`netsh`, а не судить о разумности значения.
///
/// Правило: адрес обязан быть приватным (RFC 1918 / CGNAT RFC 6598 — exit по построению NAT'ит,
/// `Citadel_NAT_SRC`), префикс — в `12..=30`. `/31` и `/32` отсекаются как «сеть без пригодных
/// адресов», `<12` — как заведомо чрезмерный захват.
fn validate_assignment(a: &capsule::AssignedV4) -> Result<()> {
    let [b0, b1, ..] = a.addr;
    let private = b0 == 10
        || (b0 == 172 && (16..=31).contains(&b1))
        || (b0 == 192 && b1 == 168)
        || (b0 == 100 && (64..=127).contains(&b1)); // CGNAT
    if !private {
        return Err(anyhow!(
            "сервер назначил неприватный адрес {}.{}.{}.{} — отказ (адрес туннеля обязан быть \
             из RFC1918/CGNAT: exit NAT'ит трафик наружу)",
            a.addr[0], a.addr[1], a.addr[2], a.addr[3]
        ));
    }
    if !(12..=30).contains(&a.prefix) {
        return Err(anyhow!(
            "сервер назначил префикс /{} — отказ (допустимо /12../30; более широкий втянул бы в \
             туннель чужие подсети абонента, /31 и /32 не дают пригодных адресов)",
            a.prefix
        ));
    }
    Ok(())
}

/// Разобрать ответ шага 1: `varint(pub_len)‖ML-DSA-pub‖varint(sig_len)‖ML-DSA-sig`.
/// Оба поля пусты, если PQ-auth на сервере выключена (тогда `verify_server_mldsa` решает, беда ли это).
fn parse_server_auth(buf: &[u8]) -> Result<(&[u8], &[u8])> {
    let (pub_len, p0) =
        citadel_masque::varint::decode(buf).ok_or_else(|| anyhow!("нет pub-префикса"))?;
    let pub_end = p0
        .checked_add(pub_len as usize)
        .filter(|e| *e <= buf.len())
        .ok_or_else(|| anyhow!("обрезанный ML-DSA pub"))?;
    let server_pub = &buf[p0..pub_end];
    let tail = &buf[pub_end..];
    let (sig_len, s0) =
        citadel_masque::varint::decode(tail).ok_or_else(|| anyhow!("нет sig-префикса"))?;
    let sig_end = s0
        .checked_add(sig_len as usize)
        .filter(|e| *e <= tail.len())
        .ok_or_else(|| anyhow!("обрезанная PQ-подпись"))?;
    Ok((server_pub, &tail[s0..sig_end]))
}

/// SHA-256 (для сверки `H(pub)` с обязательством ссылки) — тем же алго, что `citadel_client` считает
/// commit (aws-lc-rs, тот же стандартный SHA-256).
fn sha256(data: &[u8]) -> [u8; 32] {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Проверить ML-DSA-65 привязку сервера согласно ожиданию клиента. `server_pub` — pub, присланный
/// сервером по control-каналу (пуст, если PQ-auth у сервера выкл).
///
/// - `None` — PQ-auth не запрошена: не проверяем (сервер мог не прислать pub/sig).
/// - `Pub(p)` — верифицируем провижированным pub (присланный игнорируем: подпись обязана сойтись
///   именно под провижированным ключом ⇒ подменённый pub не поможет MITM).
/// - `Commit(c)` — commitment-fetch: сверяем `sha256(server_pub)==c`, затем верифицируем им подпись.
fn verify_server_mldsa(
    expect: &MldsaExpect,
    server_pub: &[u8],
    nonce: &[u8; 32],
    cert_pin: &[u8; 32],
    exporter: &[u8],
    sig: &[u8],
) -> Result<()> {
    let pk: &[u8] = match expect {
        MldsaExpect::None => return Ok(()),
        MldsaExpect::Pub(p) => p,
        MldsaExpect::Commit(c) => {
            if server_pub.is_empty() {
                return Err(anyhow!(
                    "PQ-auth: exit не прислал ML-DSA pub, а ссылка требует его (commit) — отказ"
                ));
            }
            if &sha256(server_pub) != c {
                return Err(anyhow!(
                    "PQ-auth: ML-DSA pub exit не соответствует обязательству H(pub) из ссылки — MITM?"
                ));
            }
            server_pub
        }
    };
    // S2.6/A3: exporter входит в привязку → relay-MITM (иной TLS-канал) даёт иной exporter ⇒ отказ.
    if !crate::pqauth::verify_binding(pk, nonce, cert_pin, exporter, sig) {
        return Err(anyhow!("PQ-auth: ML-DSA подпись сервера НЕ прошла — возможен MITM"));
    }
    Ok(())
}

#[cfg(test)]
mod resolve_tests {
    use super::resolve_prefer_v4;

    /// Exit с обеими записями (A и AAAA) обязан дать IPv4: клиентский QUIC-эндпоинт биндится на
    /// `0.0.0.0`, и выбранный системой IPv6 ронял бы каждую попытку QUIC при живом obfs-TCP.
    /// `localhost` резолвится в 127.0.0.1 и ::1 (порядок зависит от системы) — то, что нужно.
    #[tokio::test]
    async fn prefers_ipv4_when_both_families_resolve() {
        let a = resolve_prefer_v4("localhost:4433").await;
        // Если в окружении localhost вообще не резолвится — тест не о чем, пропускаем.
        if let Some(a) = a {
            assert!(a.is_ipv4(), "выбран {a}, а нужен IPv4");
            assert_eq!(a.port(), 4433);
        }
    }

    /// Литерал IPv6 остаётся собой (v4 не выдумываем — поведение как раньше).
    #[tokio::test]
    async fn keeps_v6_when_nothing_else() {
        let a = resolve_prefer_v4("[::1]:443").await.expect("литерал резолвится");
        assert!(a.is_ipv6());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// H-4 (остаток): недобросовестный exit не может ни выдать клиенту чужой (публичный) адрес,
    /// ни расширить «свою подсеть» до размеров, втягивающих в туннель домашнюю сеть абонента.
    #[test]
    fn assignment_from_server_is_validated() {
        let mk = |addr: [u8; 4], prefix| capsule::AssignedV4 { request_id: 1, addr, prefix };
        // штатные назначения
        assert!(validate_assignment(&mk([10, 7, 0, 5], 16)).is_ok());
        assert!(validate_assignment(&mk([172, 16, 0, 2], 24)).is_ok());
        assert!(validate_assignment(&mk([192, 168, 9, 3], 30)).is_ok());
        assert!(validate_assignment(&mk([100, 64, 0, 7], 12)).is_ok()); // CGNAT
        // адрес обязан быть приватным: exit NAT'ит, публичный адрес на TUN — либо ошибка, либо
        // попытка заставить клиента считать своим чужой диапазон
        for a in [[8, 8, 8, 8], [1, 1, 1, 1], [172, 32, 0, 1], [100, 128, 0, 1], [192, 169, 0, 1]] {
            assert!(validate_assignment(&mk(a, 24)).is_err(), "адрес {a:?} не приватный");
        }
        // префикс: /8 втянул бы весь 10/8 абонента, /0 — вообще всё; /31 и /32 бесполезны
        for p in [0, 8, 11, 31, 32, 33, 255] {
            assert!(validate_assignment(&mk([10, 7, 0, 5], p)).is_err(), "префикс /{p}");
        }
    }

    /// S0.1/H2: без pin — отказ (fail-closed), кроме явного insecure-флага; Pinned/Waiting — ок.
    #[test]
    fn fail_closed_requires_pin() {
        assert!(require_pin_or_insecure(&PinMode::Pinned([0u8; 32]), false).is_ok());
        assert!(require_pin_or_insecure(&PinMode::Waiting, false).is_ok()); // ждёт pin, не fail-open
        assert!(require_pin_or_insecure(&PinMode::NoPin, false).is_err()); // ключевое: отказ
        assert!(require_pin_or_insecure(&PinMode::NoPin, true).is_ok()); // dev override
    }

    /// **H-2/аудит-4 — главный инвариант порядка:** анонимный токен НЕ должен уходить серверу,
    /// чья ML-DSA-подпись не сошлась.
    ///
    /// Сервер в тесте моделирует ровно CRQC-MITM: предъявляет НАСТОЯЩИЙ ML-DSA pub (обязательство
    /// `H(pub)` из ссылки сходится, как сошёлся бы и подделанный классический CertVerify под тем же
    /// pin), но подписать привязку он не может — подпись ставится чужим ключом. До правки токен
    /// улетал в одном пакете с nonce, то есть ещё ДО всякой проверки; теперь клиент обязан
    /// оборваться на шаге 1 и второй стрим не открывать.
    #[tokio::test]
    async fn token_is_not_disclosed_before_server_pq_auth_verifies() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Mutex;

        let psk = [0x5eu8; 32];
        let real = crate::pqauth::ServerSigner::generate().unwrap();
        let real_pk = real.public_key();
        let commit = sha256(&real_pk);
        let impostor = crate::pqauth::ServerSigner::generate().unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let saw_token_stream = Arc::new(AtomicBool::new(false));
        // ВСЁ, что клиент сказал серверу до момента проверки подписи. Именно по этому буферу и
        // проверяется свойство: проверять «не открыл ли он второй стрим» недостаточно — при старом
        // однопакетном обмене второго стрима тоже не было, а токен уже утёк в первом.
        let heard = Arc::new(Mutex::new(Vec::<u8>::new()));
        let (flag, heard_srv) = (saw_token_stream.clone(), heard.clone());

        let srv = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let scfg = crate::server_config(crate::kx_groups_for("pq")).unwrap();
            let ep = crate::server_endpoint_obfs_tcp(stream, scfg, psk).unwrap();
            let conn = ep.accept().await.unwrap().await.unwrap();
            let mut t = Tunnel::new(conn, true);
            let exporter = t.exporter().unwrap();
            // Шаг 1: настоящий pub + подпись ЧУЖИМ ключом.
            t.control_server(|first| {
                heard_srv.lock().unwrap().extend_from_slice(first);
                let sig = impostor.sign_binding(first, &[0u8; 32], &exporter).unwrap();
                let mut resp = citadel_masque::varint::to_vec(real_pk.len() as u64);
                resp.extend_from_slice(&real_pk);
                resp.extend_from_slice(&citadel_masque::varint::to_vec(sig.len() as u64));
                resp.extend_from_slice(&sig);
                Ok((resp, ()))
            })
            .await
            .unwrap();
            // Шаг 2 наступить не должен. `Ok(Ok(_))` — стрим реально открыли; закрытие соединения
            // клиентом даёт `Ok(Err(_))` и за предъявление токена не считается.
            let second = tokio::time::timeout(Duration::from_secs(1), t.conn().accept_bi()).await;
            if matches!(second, Ok(Ok(_))) {
                flag.store(true, Ordering::SeqCst);
            }
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let ep = crate::client_endpoint_obfs_tcp(stream, psk).unwrap();
        let ccfg = crate::client_config(crate::kx_groups_for("pq")).unwrap();
        let conn = ep.connect_with(ccfg, addr, "Citadel.exit").unwrap().await.unwrap();
        let mut t = Tunnel::new(conn, true);

        const SECRET_TOKEN: &[u8] = b"anonymous-token-must-not-leak";
        let err = client_request_address(&mut t, SECRET_TOKEN, &MldsaExpect::Commit(commit), [0u8; 32])
            .await
            .expect_err("подпись самозванца не должна проходить");
        assert!(format!("{err:#}").contains("ML-DSA"), "err: {err:#}");

        srv.await.unwrap();

        // Главная проверка: в том, что клиент успел сказать, токена нет ни в каком виде.
        let heard = heard.lock().unwrap();
        assert!(
            heard.windows(SECRET_TOKEN.len()).all(|w| w != SECRET_TOKEN),
            "токен предъявлен серверу ДО проверки его PQ-подписи (H-2)"
        );
        assert_eq!(heard.len(), 32, "на шаге 1 клиент шлёт ровно nonce, и ничего больше");
        assert!(
            !saw_token_stream.load(Ordering::SeqCst),
            "клиент открыл второй стрим после провала PQ-auth (H-2)"
        );
    }

    /// Разбор ответа шага 1 не паникует и не выходит за границы на обрезанных/мусорных данных
    /// (он читает недоверенную сеть до всякой верификации).
    #[test]
    fn parse_server_auth_rejects_truncated() {
        assert!(parse_server_auth(&[]).is_err());
        // varint обещает 100 байт pub, а их нет
        let mut buf = citadel_masque::varint::to_vec(100);
        buf.extend_from_slice(&[0u8; 10]);
        assert!(parse_server_auth(&buf).is_err());
        // pub есть, sig-префикса нет
        let mut buf = citadel_masque::varint::to_vec(2);
        buf.extend_from_slice(&[1, 2]);
        assert!(parse_server_auth(&buf).is_err());
        // корректная пара пустых полей (PQ-auth выключена на сервере)
        let mut ok = citadel_masque::varint::to_vec(0);
        ok.extend_from_slice(&citadel_masque::varint::to_vec(0));
        assert_eq!(parse_server_auth(&ok).unwrap(), (&[][..], &[][..]));
    }

    /// M-2/аудит-4: не-PQ suite отвергается. Ключевое — что `classical` приходит ИЗ ССЫЛКИ, то есть
    /// подменённая ссылка иначе понижала бы сессию до X25519 при «Защищено» в интерфейсе.
    /// `all` тоже не гарантия: он молча откатывается на классику против не-PQ сервера.
    #[test]
    fn non_pq_kx_is_refused_unless_dev_flag() {
        for pq in ["", "pq"] {
            assert!(require_pq_kx(pq, false).is_ok(), "PQ-suite {pq:?} обязан проходить");
        }
        for weak in ["classical", "x25519", "all", "hybrid"] {
            let err = require_pq_kx(weak, false)
                .expect_err("не-PQ suite обязан отвергаться (fail-closed)");
            assert!(format!("{err:#}").contains("пост-квантов"), "err: {err:#}");
            // dev-флаг (харнес crypto-agility) — единственный способ пропустить
            assert!(require_pq_kx(weak, true).is_ok(), "{weak}: dev-флаг обязан пропускать");
        }
    }

    /// §S3 commitment-fetch: клиент с обязательством H(pub) из ссылки принимает подпись сервера
    /// ТОЛЬКО если присланный pub сходится с commit; полный provisioned pub тоже работает; None —
    /// пропускает; подмена pub/commit/подписи — отказ (анти-MITM).
    #[test]
    fn verify_server_mldsa_expectations() {
        let signer = crate::pqauth::ServerSigner::generate().unwrap();
        let pk = signer.public_key();
        let nonce = [7u8; 32];
        let pin = [9u8; 32];
        let exporter = [0x5cu8; 32];
        let sig = signer.sign_binding(&nonce, &pin, &exporter).unwrap();

        // None — не проверяем (даже без pub/sig)
        assert!(verify_server_mldsa(&MldsaExpect::None, &[], &nonce, &pin, &exporter, &[]).is_ok());
        // Pub провижирован — верифицируем им (server_pub игнорируется)
        assert!(verify_server_mldsa(&MldsaExpect::Pub(pk.clone()), &[], &nonce, &pin, &exporter, &sig).is_ok());
        // Commit совпал с H(server_pub) — принимаем (commitment-fetch)
        let commit = sha256(&pk);
        assert!(verify_server_mldsa(&MldsaExpect::Commit(commit), &pk, &nonce, &pin, &exporter, &sig).is_ok());
        // Commit не совпал (подменённый pub) — отказ
        assert!(verify_server_mldsa(&MldsaExpect::Commit([0u8; 32]), &pk, &nonce, &pin, &exporter, &sig).is_err());
        // Commit есть, а pub не прислан — отказ
        assert!(verify_server_mldsa(&MldsaExpect::Commit(commit), &[], &nonce, &pin, &exporter, &sig).is_err());
        // Правильный commit, но подпись под ЧУЖИМ pin (MITM переиграл привязку) — отказ
        assert!(verify_server_mldsa(&MldsaExpect::Commit(commit), &pk, &nonce, &[1u8; 32], &exporter, &sig).is_err());
        // S2.6/A3: правильный commit, но подпись под ЧУЖИМ exporter (relay-MITM) — отказ
        assert!(verify_server_mldsa(&MldsaExpect::Commit(commit), &pk, &nonce, &pin, &[0x5du8; 32], &sig).is_err());
        // Pub провижирован, но подпись битая — отказ
        assert!(verify_server_mldsa(&MldsaExpect::Pub(pk), &[], &nonce, &pin, &exporter, b"tampered").is_err());
    }
}
