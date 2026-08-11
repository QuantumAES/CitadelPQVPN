//! Диагностика подключения (задача 3): последовательность проб от DNS-резолва до egress через
//! туннель, отдаёт результат пошагово через колбэк `emit`. Гоняет тот же путь, что реальный
//! коннект (`establish_session`), поэтому локализует, где именно рвётся связь:
//! DNS → UDP/QUIC:4433 → TCP:443(obfs) → PQ-handshake+адрес → egress через exit.
//!
//! Egress-проба (см. [`crate::client::Session::egress_dns_probe`]) шлёт DNS-запрос сырым
//! IP-пакетом прямо в туннель — минуя ОС-роутинг/TUN/root — и тем отделяет «exit не форвардит»
//! от «клиентский роутинг сломан» (петля на full-tunnel, отсутствие bypass-маршрута и т.п.).

use std::time::{Duration, Instant};

use crate::client::{establish_session, host_of, try_quic_connect};
use crate::config::ClientConfig;

/// H-3: приписка к «порт недоступен», когда транспорт идёт под БУТСТРАПНЫМ PSK, а ключа L1
/// текущей эпохи у нас нет. Exit с включённой ротацией такой пакет даже не разбирает и молча
/// отбрасывает — на проводе это неотличимо от закрытого порта, и человек уходит чинить firewall
/// вместо выдачи токенов. Пустая строка, когда ключ эпохи есть (или obfs не используется вовсе).
fn missing_epoch_key_hint(cfg: &ClientConfig) -> &'static str {
    if cfg.data_psk.is_none() && cfg.obfs_psk.is_some() {
        ". NB: ключ L1 текущей эпохи не получен (идём под бутстрапным PSK) — при включённой на \
         сервере ротации H-3 exit молча отбрасывает такие пакеты, и это выглядит ровно как \
         закрытый порт. Сперва разберись с шагом «Токен»"
    } else {
        ""
    }
}

/// Один шаг диагностики для UI: имя, вердикт, детали.
pub struct DiagStep {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

impl DiagStep {
    fn ok(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self { name: name.into(), ok: true, detail: detail.into() }
    }
    fn fail(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self { name: name.into(), ok: false, detail: detail.into() }
    }
}

/// Прогнать все пробы против `cfg`, стримя результат через `emit`. Никогда не паникует;
/// каждый провал — просто шаг с `ok=false`. Резолвер egress-пробы — Cloudflare 1.1.1.1.
///
/// `admin` — `Some((ADMIN_VIP, порт))` для мастер-профиля: добавляет пробу admin-канала (C7.2)
/// сырым TCP-SYN по туннелю. Это единственная проба, отвечающая на жалобу «не открывается список
/// абонентов»: она проверяет путь до issuer'а МИМО ОС-роутинга, отделяя поломку на exit'е от
/// поломки маршрута/split-tunnel на устройстве. `None` (клиентская ссылка) — шаг пропускается.
pub async fn run_diagnostics(
    cfg: &ClientConfig,
    admin: Option<([u8; 4], u16)>,
    mut emit: impl FnMut(DiagStep),
) {
    // ── 1. конфигурация ──
    emit(DiagStep::ok(
        "Конфигурация",
        format!(
            "серверы: {}; server_name={}; KX={}; obfs={}; token={}",
            cfg.servers.join(", "),
            cfg.server_name,
            crate::kx_suite_name(&cfg.kx_suite),
            match (cfg.data_psk.is_some(), cfg.obfs_psk.is_some()) {
                (true, _) => "да (ключ эпохи, H-3)",
                (false, true) => "да (бутстрапный PSK)",
                (false, false) => "нет",
            },
            if cfg.token.is_empty() { "нет" } else { "есть" },
        ),
    ));
    if cfg.servers.is_empty() {
        emit(DiagStep::fail("Серверы", "список exit'ов пуст — нечего проверять"));
        return;
    }

    // ── 2–4. по каждому exit: DNS-резолв, QUIC/UDP-проба, TCP-проба (obfs-fallback) ──
    for server in &cfg.servers {
        let host = host_of(server);

        // 2. DNS-резолв (v4-first — как в боевом connect_server: QUIC-эндпоинт IPv4)
        let addr = match crate::client::resolve_prefer_v4(server).await {
            Some(a) => {
                emit(DiagStep::ok(format!("DNS · {server}"), format!("резолвится в {a}")));
                a
            }
            _ => {
                emit(DiagStep::fail(format!("DNS · {server}"), "не удалось разрезолвить host:port"));
                continue;
            }
        };

        // 3. QUIC/UDP-проба (одна попытка; внутренний таймаут 3с)
        let t0 = Instant::now();
        match try_quic_connect(server, addr, cfg, 1, host).await {
            Ok(Some(conn)) => {
                emit(DiagStep::ok(
                    format!("QUIC/UDP · {server}"),
                    format!("PQ-хендшейк за {} мс", t0.elapsed().as_millis()),
                ));
                conn.close(0u32.into(), b"diag");
            }
            // Порт берём из адреса сервера: раньше здесь стояло литеральное «UDP:4433», и после
            // перехода на случайные порты (M-8) диагностика называла порт, которого в деплое нет.
            Ok(None) => emit(DiagStep::fail(
                format!("QUIC/UDP · {server}"),
                format!(
                    "UDP:{} недоступен или блокируется (порт закрыт/firewall/NAT){}",
                    addr.port(),
                    missing_epoch_key_hint(cfg)
                ),
            )),
            Err(e) => emit(DiagStep::fail(format!("QUIC/UDP · {server}"), format!("ошибка: {e:#}"))),
        }

        // 4. TCP-проба к obfs-fallback порту. Сокет — через тот же защищённый connect, что и боевой
        // транспорт: на Android незащищённая проба при поднятом туннеле ушла бы в него самого и
        // соврала бы «порт недоступен» там, где он доступен.
        let tcp_target = format!("{host}:{}", cfg.tcp_port);
        let taddr = crate::client::resolve_prefer_v4(&tcp_target).await;
        match taddr {
            None => emit(DiagStep::fail(format!("TCP · {tcp_target}"), "не удалось разрезолвить host:port")),
            Some(taddr) => match tokio::time::timeout(
                Duration::from_secs(3),
                crate::protect::connect_tcp(taddr),
            )
            .await
            {
                Ok(Ok(_)) => emit(DiagStep::ok(
                    format!("TCP · {tcp_target}"),
                    "порт принимает соединения (obfs-fallback доступен)",
                )),
                Ok(Err(e)) => emit(DiagStep::fail(
                    format!("TCP · {tcp_target}"),
                    format!("connect: {e}{}", crate::local_block_hint(&e)),
                )),
                Err(_) => emit(DiagStep::fail(format!("TCP · {tcp_target}"), "таймаут connect (3с)")),
            },
        }
    }

    // ── 5. полный establish (PQ-handshake + токен → назначенный адрес). Диагностика тестирует
    // основной QUIC/UDP-путь (force_tcp=false); реальный connect при провале эскалирует на obfs-TCP. ──
    let session = match establish_session(cfg, false).await {
        Ok(s) => {
            emit(DiagStep::ok(
                "Сессия (establish)",
                format!("exit {}; транспорт {}; адрес {}", s.chosen, s.transport(), s.cidr()),
            ));
            // MTU: сверяем сконфигурированный TUN MTU с бюджетом QUIC-датаграммы — если больше,
            // полноразмерные пакеты дропались бы («datagram too large»); клиент клампит под бюджет.
            if let Some(budget) = s.quic_datagram_mtu() {
                let cur: usize = cfg.mtu.parse().unwrap_or(1280);
                if cur > budget {
                    emit(DiagStep::ok(
                        "MTU",
                        format!("cfg MTU {cur} > бюджет QUIC-датаграммы {budget} — TUN ужимается до {budget} (иначе дроп)"),
                    ));
                } else {
                    emit(DiagStep::ok("MTU", format!("cfg MTU {cur} ≤ бюджет {budget} — ок")));
                }
            }
            s
        }
        Err(e) => {
            // `{e:#}` (не `{e}`): у quinn причина лежит в `source` — без альтернативной формы
            // видно лишь бесполезное «read error: connection lost», а не сам разрыв
            // («timed out» / «closed by peer: code 1» = отказ exit'а по токену/пулу адресов).
            emit(DiagStep::fail("Сессия (establish)", format!("{e:#}")));
            return; // без сессии egress не проверить
        }
    };

    // ── 6. egress-проба: DNS через туннель (обход ОС-роутинга) ──
    match session.egress_dns_probe([1, 1, 1, 1], "example.com", Duration::from_secs(6)).await {
        Ok(Some(addrs)) if !addrs.is_empty() => {
            let list: Vec<String> = addrs
                .iter()
                .map(|a| format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]))
                .collect();
            emit(DiagStep::ok(
                "Egress через туннель",
                format!("exit форвардит+NAT: example.com → {}", list.join(", ")),
            ));
        }
        Ok(Some(_)) => emit(DiagStep::fail(
            "Egress через туннель",
            "DNS-ответ без A-записей (частичный egress?)",
        )),
        Ok(None) => emit(DiagStep::ok(
            "Egress через туннель",
            "пропущена (obfs-TCP транспорт — проба только для QUIC)",
        )),
        Err(e) => emit(DiagStep::fail(
            "Egress через туннель",
            format!("{e:#} — сессия поднялась, но трафик наружу не проходит"),
        )),
    }

    // ── 7. admin-канал (C7.2): TCP-SYN на ADMIN_VIP:порт сырым пакетом по туннелю ──
    // Проба идёт МИМО ОС-роутинга, поэтому чётко делит диагноз «список абонентов не открывается»:
    // ✔ — путь до issuer'а по туннелю жив (ищи причину в маршруте ОС/split-tunnel или в TLS/авторизации);
    // ✗ — до issuer'а не доходит сам туннельный путь (C7.2-исключение/DNAT/issuer).
    if let Some((vip, port)) = admin {
        let vip_s = format!("{}.{}.{}.{}:{port}", vip[0], vip[1], vip[2], vip[3]);
        match session.admin_syn_probe(vip, port, Duration::from_secs(6)).await {
            Ok(true) => emit(DiagStep::ok(
                format!("Admin-канал · {vip_s}"),
                "SYN-ACK по туннелю — плоскость управления достижима",
            )),
            Ok(false) => emit(DiagStep::fail(
                format!("Admin-канал · {vip_s}"),
                "RST — порт закрыт (issuer не слушает / DNAT указывает в никуда)",
            )),
            Err(e) => emit(DiagStep::fail(
                format!("Admin-канал · {vip_s}"),
                format!("{e:#} — exit не пропускает/не DNAT'ит admin-трафик (C7.2)"),
            )),
        }
    }

    // ── 8. teardown ──
    drop(session);
    emit(DiagStep::ok("Готово", "сессия закрыта"));
}
