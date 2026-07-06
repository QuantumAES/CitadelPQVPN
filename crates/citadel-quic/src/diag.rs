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
pub async fn run_diagnostics(cfg: &ClientConfig, mut emit: impl FnMut(DiagStep)) {
    // ── 1. конфигурация ──
    emit(DiagStep::ok(
        "Конфигурация",
        format!(
            "серверы: {}; server_name={}; KX={}; obfs={}; token={}",
            cfg.servers.join(", "),
            cfg.server_name,
            crate::kx_suite_name(&cfg.kx_suite),
            if cfg.obfs_psk.is_some() { "да" } else { "нет" },
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

        // 2. DNS-резолв
        let addr = match tokio::net::lookup_host(server).await.map(|mut it| it.next()) {
            Ok(Some(a)) => {
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
            Ok(None) => emit(DiagStep::fail(
                format!("QUIC/UDP · {server}"),
                "UDP:4433 недоступен или блокируется (порт закрыт/firewall/NAT)",
            )),
            Err(e) => emit(DiagStep::fail(format!("QUIC/UDP · {server}"), format!("ошибка: {e}"))),
        }

        // 4. TCP-проба к obfs-fallback порту
        let tcp_target = format!("{host}:{}", cfg.tcp_port);
        match tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::TcpStream::connect(&tcp_target),
        )
        .await
        {
            Ok(Ok(_)) => emit(DiagStep::ok(
                format!("TCP · {tcp_target}"),
                "порт принимает соединения (obfs-fallback доступен)",
            )),
            Ok(Err(e)) => emit(DiagStep::fail(format!("TCP · {tcp_target}"), format!("connect: {e}"))),
            Err(_) => emit(DiagStep::fail(format!("TCP · {tcp_target}"), "таймаут connect (3с)")),
        }
    }

    // ── 5. полный establish (PQ-handshake + токен → назначенный адрес) ──
    let session = match establish_session(cfg).await {
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
            emit(DiagStep::fail("Сессия (establish)", format!("{e}")));
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
            format!("{e} — сессия поднялась, но трафик наружу не проходит"),
        )),
    }

    // ── 7. teardown ──
    drop(session);
    emit(DiagStep::ok("Готово", "сессия закрыта"));
}
