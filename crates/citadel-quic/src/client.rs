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

use anyhow::{anyhow, Result};
use rand::RngCore;

use citadel_masque::{capsule, datagram, ip};
use citadel_tun::TunIo;

use crate::config::{ClientConfig, MldsaExpect, PinMode};
use crate::dataplane::{pump, Tunnel};
use tokio::net::TcpStream;

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
                Ok(Err(e)) => return Err(anyhow!("egress-проба: транспорт закрыт: {e}")),
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
                Ok(Err(e)) => return Err(anyhow!("admin-проба: транспорт закрыт: {e}")),
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

/// Поднять сессию: failover по списку exit'ов (M5) + control-обмен (токен→адрес, PQ-auth M7).
/// **Без TUN и без сетевой настройки** — только транспорт и назначенный адрес. `force_tcp` — идти
/// сразу obfs-TCP (минуя QUIC/UDP): эскалация VpnController'а, когда QUIC-хендшейк проходит, но
/// мобильный/NAT64-путь не несёт крупные пакеты через QUIC (MTU: хендшейк ок, но большой ML-DSA-ответ
/// сервера чёрнодырится) — TCP решает сегментацией/MSS.
pub async fn establish_session(cfg: &ClientConfig, force_tcp: bool) -> Result<Session> {
    eprintln!("[citadel-m1:client] exit-серверы (перемешаны): {}", cfg.servers.join(", "));
    // S1.1/M4: не-PQ suite (classical/all) не гарантирует анти-HNDL — предупреждаем явно.
    if !crate::kx_is_pq(&cfg.kx_suite) {
        eprintln!(
            "[citadel-m1:client] ⚠ KX={} — сессия может быть НЕ пост-квантовой (нет защиты от Harvest-Now-Decrypt-Later); безопасный дефолт — pq",
            crate::kx_suite_name(&cfg.kx_suite)
        );
    }

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
    let mldsa = cfg.mldsa_expect(host);
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
    // client_src = назначенный адрес: pump не фильтрует по нему (это политика exit'а), но
    // говорит вслух, если в туннель ушёл пакет с чужим src — иначе такой трафик умирает на exit'е
    // молча и выглядит как «отправлено много, принято 0».
    pump(session.tunnel, tun, None, Some(session.addr), None, None, None).await
}

/// Подключиться к ОДНОМУ exit'у: основной путь PQ-QUIC, при недоступности — obfs-over-TCP
/// fallback (M4, порт `cfg.tcp_port`, по умолчанию 443). `force_tcp` — пропустить QUIC/UDP и идти
/// сразу obfs-TCP (MTU-эскалация: QUIC-хендшейк проходит, но мобильный/NAT64-путь не несёт крупные
/// QUIC-пакеты). `None` — exit недоступен → вызывающий пробует следующий из списка (M5 failover).
async fn connect_server(server: &str, cfg: &ClientConfig, force_tcp: bool) -> Result<Option<Tunnel>> {
    let host = host_of(server);
    let addr = match tokio::net::lookup_host(server).await.map(|mut it| it.next()) {
        Ok(Some(a)) => a,
        _ => return Ok(None),
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
        if let Ok(Some(taddr)) = tokio::net::lookup_host(&tcp_target).await.map(|mut it| it.next()) {
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
                Ok(Err(e)) => eprintln!("[citadel-m1:client] obfs-TCP не удался: {e}"),
                Err(_) => eprintln!("[citadel-m1:client] obfs-TCP: таймаут"),
            }
        }
    }
    Ok(None)
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
    let tcp = TcpStream::connect(taddr).await?;
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
                    eprintln!("[citadel-m1:client] pinning {pin_host}: {}", hex::encode(p));
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
            Ok(Err(e)) => eprintln!("[citadel-m1:client] QUIC попытка {attempt}: {e}"),
            Err(_) => eprintln!("[citadel-m1:client] QUIC попытка {attempt}: таймаут (exit/UDP недоступен?)"),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Ok(None)
}

/// Control-обмен (M2): nonce(32)‖varint(token_len)‖token‖ADDRESS_REQUEST → проверка ML-DSA
/// подписи сервера (M7/§S3, согласно `expect`) → ADDRESS_ASSIGN. Возвращает назначенный адрес.
async fn client_request_address(
    tunnel: &mut Tunnel,
    token: &[u8],
    expect: &MldsaExpect,
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
    // S2.6/A3: TLS exporter клиентской сессии для channel-binding ML-DSA-подписи (см. verify ниже).
    let exporter = tunnel.exporter()?;
    // ответ: varint(pub_len)‖ML-DSA-pub ‖ varint(sig_len)‖ML-DSA-sig ‖ ADDRESS_ASSIGN (§S3)
    let (pub_len, p0) =
        citadel_masque::varint::decode(&buf).ok_or_else(|| anyhow!("нет pub-префикса"))?;
    let pub_end = p0 + pub_len as usize;
    if buf.len() < pub_end {
        return Err(anyhow!("обрезанный ML-DSA pub"));
    }
    let server_pub = &buf[p0..pub_end];
    let tail = &buf[pub_end..];
    let (sig_len, s0) =
        citadel_masque::varint::decode(tail).ok_or_else(|| anyhow!("нет sig-префикса"))?;
    let sig_end = s0 + sig_len as usize;
    if tail.len() < sig_end {
        return Err(anyhow!("обрезанная PQ-подпись"));
    }
    let sig = &tail[s0..sig_end];
    let rest = &tail[sig_end..];

    // M7/§S3: проверяем ML-DSA-65 подпись сервера согласно ожиданию (полный pub / commitment-fetch).
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

    let (t, val, _) = capsule::decode(rest).ok_or_else(|| anyhow!("битая капсула в ответе"))?;
    if t != capsule::ADDRESS_ASSIGN {
        return Err(anyhow!("ожидался ADDRESS_ASSIGN, получен type={t}"));
    }
    capsule::decode_assigned_v4(val).ok_or_else(|| anyhow!("битое тело ADDRESS_ASSIGN"))
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
mod tests {
    use super::*;

    /// S0.1/H2: без pin — отказ (fail-closed), кроме явного insecure-флага; Pinned/Waiting — ок.
    #[test]
    fn fail_closed_requires_pin() {
        assert!(require_pin_or_insecure(&PinMode::Pinned([0u8; 32]), false).is_ok());
        assert!(require_pin_or_insecure(&PinMode::Waiting, false).is_ok()); // ждёт pin, не fail-open
        assert!(require_pin_or_insecure(&PinMode::NoPin, false).is_err()); // ключевое: отказ
        assert!(require_pin_or_insecure(&PinMode::NoPin, true).is_ok()); // dev override
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
