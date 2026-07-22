//! `winnet` — платформо-нейтральное ядро Windows-модели W2 (сервис-плумбер + пакет-пайп).
//!
//! Windows-аналог Linux-helper'а: **привилегированная служба** (`citadel-svc`, ставится elevated)
//! создаёт WinTUN-адаптер, ставит маршруты/DNS/WFP-kill-switch и гоняет **пакет-насос** ↔
//! неприв. приложение по **named pipe**; движок (QUIC/obfs) остаётся в приложении, как на Linux.
//! Named pipe играет роль fd из Linux-SCM_RIGHTS: `WindowsTunProvider` (cfg(windows)) оборачивает
//! пайп в `TunIo` (read/write IP-пакет).
//!
//! Здесь — ТОЛЬКО чистая логика (сериализация конфига, кадрирование пайпа, план WFP-фильтров и
//! маршрутов), поэтому модуль компилируется и тестируется на ЛЮБОЙ ОС (юнит-тесты гоняются на
//! Linux, как `killswitch_rules` в `citadel-helper`). Реальные WinAPI-вызовы (WinTUN/WFP/IP Helper/
//! Service Control Manager) живут в cfg(windows)-коде провайдера и службы и потребляют эти планы.

use citadel_quic::config::SplitMode;
use serde::{Deserialize, Serialize};

/// Байт-тег управляющего кадра фазы конфигурации (app → служба): `TAG_CONFIG ‖ u32(len,BE) ‖ cbor`.
pub const TAG_CONFIG: u8 = 0x01;
/// Байт-тег ответа готовности (служба → app): `TAG_READY ‖ status(u8) ‖ u32(len,BE) ‖ cbor(TunReady)`.
/// `status`: 0 = ок (адаптер поднят, дальше фаза данных); ≠0 = ошибка (тело — UTF-8 текст).
pub const TAG_READY: u8 = 0x02;

/// Верхняя граница кадра пакета в фазе данных (WinTUN MTU ≤ 1500; берём с запасом на джамбо-огрызки).
pub const MAX_PACKET: usize = 1600;

/// Конфиг, который приложение шлёт службе для поднятия адаптера (подмножество `TunParams`, нужное
/// привилегированной части). Split-tunnel УЖЕ развёрнут провайдером в `routes`/`bypass` (та же
/// функция `split_routes`, что на Linux) — служба получает готовые списки, как helper через `--routes`
/// и `--bypass`. Все адреса — IPv4 (деплой v4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunSetup {
    /// Адрес, назначенный клиенту в туннеле (напр. `10.7.0.5`).
    pub addr: [u8; 4],
    /// Длина префикса (обычно 16 для /16-пула).
    pub prefix: u8,
    /// MTU адаптера.
    pub mtu: u32,
    /// Маршруты В туннель (`0.0.0.0/0` = full-tunnel; служба раскроет в две /1-половины — см.
    /// [`tunnel_route_entries`] — чтобы физический default выжил как nexthop для bypass/exit).
    pub routes: Vec<String>,
    /// DNS, проталкиваемый клиенту (через туннель; None = не трогать резолвер). Один IPv4.
    pub dns: Option<String>,
    /// IP exit'ов — bypass мимо туннеля (анти-петля) И permit в WFP-kill-switch (зашифрованный
    /// путь к серверу обязан оставаться достижим, пока туннель поднимается). Аналог `--exit-ips`.
    pub exit_ips: Vec<String>,
    /// C8.1/Q5 split-tunnel «в обход» (Exclude): CIDR назначений мимо туннеля через физический шлюз.
    /// В kill-switch они получают permit (иначе fail-closed их бы заблокировал). Аналог `--bypass`.
    pub bypass: Vec<String>,
    /// Армировать WFP-kill-switch (fail-closed: не-туннельный трафик блокируется, пока адаптер жив).
    pub killswitch: bool,
}

/// Ответ службы приложению после попытки поднять адаптер.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunReady {
    /// LUID WinTUN-адаптера (для диагностики/повторного открытия; 0 если неактуально).
    pub adapter_luid: u64,
}

/// Сериализовать конфиг в управляющий кадр `TAG_CONFIG ‖ u32(len,BE) ‖ cbor(TunSetup)`.
pub fn encode_config(setup: &TunSetup) -> Vec<u8> {
    let mut body = Vec::new();
    ciborium::into_writer(setup, &mut body).expect("cbor TunSetup");
    let mut out = Vec::with_capacity(5 + body.len());
    out.push(TAG_CONFIG);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// Разобрать управляющий кадр конфига (без ведущего тега — тег читает транспорт-цикл).
pub fn decode_config(body: &[u8]) -> anyhow::Result<TunSetup> {
    Ok(ciborium::from_reader(body)?)
}

/// Верхняя граница тела READY-ответа (анти-DoS при чтении из пайпа).
pub const MAX_READY_BODY: usize = 4096;

/// Кадр готовности «ОК» (служба → app): `TAG_READY ‖ 0 ‖ u32(len,BE) ‖ cbor(TunReady)`.
pub fn encode_ready_ok(ready: &TunReady) -> Vec<u8> {
    let mut body = Vec::new();
    ciborium::into_writer(ready, &mut body).expect("cbor TunReady");
    let mut out = Vec::with_capacity(6 + body.len());
    out.push(TAG_READY);
    out.push(0); // status ок
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// Кадр готовности «ошибка»: `TAG_READY ‖ status(≠0) ‖ u32(len,BE) ‖ utf8(текст)`. Тело — не CBOR,
/// а человекочитаемая причина (её покажет провайдер). Служба не поднимает адаптер → фаза данных не идёт.
pub fn encode_ready_err(msg: &str) -> Vec<u8> {
    let body = msg.as_bytes();
    let mut out = Vec::with_capacity(6 + body.len());
    out.push(TAG_READY);
    out.push(1); // status ошибка
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Разобрать тело READY-«ОК» (CBOR TunReady). Провайдер зовёт только при status==0.
pub fn decode_ready(body: &[u8]) -> anyhow::Result<TunReady> {
    Ok(ciborium::from_reader(body)?)
}

/// C8.3: из режима «по назначению» → `(маршруты В туннель, CIDR В обход)`. **Единый источник** для
/// Linux (`citadel-helper --routes/--bypass`) и Windows (`TunSetup.routes/bypass`): split-семантика
/// (включая Q5 kill-switch⇄split) одна на все платформы. Include → в туннель ТОЛЬКО выбранные CIDR
/// (default физический); Exclude → маршруты ссылки как есть + выбранные в обход; Off → маршруты ссылки.
pub fn split_routes(mode: SplitMode, link_routes: &str, dest_routes: &[String]) -> (Vec<String>, Vec<String>) {
    let link: Vec<String> = link_routes.split_whitespace().map(String::from).collect();
    match mode {
        SplitMode::Include => (dest_routes.to_vec(), Vec::new()),
        SplitMode::Exclude => (link, dest_routes.to_vec()),
        SplitMode::Off => (link, Vec::new()),
    }
}

/// Кадр пакета в фазе данных: `u16(len,BE) ‖ payload`. `len == 0` — маркер ЧИСТОГО disconnect
/// (аналог байта `'Q'` от Linux-GuiTun): служба снимает kill-switch. Обрыв пайпа БЕЗ этого маркера
/// (краш app) → kill-switch ОСТАЁТСЯ (fail-closed), как helper держит iptables при EOF-без-'Q'.
pub fn encode_packet(pkt: &[u8]) -> Vec<u8> {
    debug_assert!(pkt.len() <= MAX_PACKET);
    let mut out = Vec::with_capacity(2 + pkt.len());
    out.extend_from_slice(&(pkt.len() as u16).to_be_bytes());
    out.extend_from_slice(pkt);
    out
}

/// Маркер чистого disconnect (кадр нулевой длины).
pub fn clean_disconnect_marker() -> [u8; 2] {
    [0, 0]
}

/// Результат разбора потока пайпа: сколько байт от начала `buf` уже потреблено и что извлечено.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Framed {
    /// Полные пакеты (payload без длины). Пустой вектор — данных нет.
    pub packets: Vec<Vec<u8>>,
    /// Встречен маркер чистого disconnect (len==0) — дальше поток можно закрывать.
    pub clean_disconnect: bool,
    /// Сколько ведущих байт `buf` разобрано (вызывающий их отбрасывает; хвост — недокадр).
    pub consumed: usize,
}

/// Извлечь из накопленного буфера все ПОЛНЫЕ кадры пакетов (`u16-len ‖ payload`). Частичный кадр в
/// хвосте не трогается (останется до следующего чтения). Кадр `len==0` = чистый disconnect (стоп,
/// хвост после него игнорируется вызывающим). Кадр `len>MAX_PACKET` → ошибка (защита от мусора/DoS).
pub fn parse_stream(buf: &[u8]) -> anyhow::Result<Framed> {
    let mut out = Framed::default();
    let mut i = 0;
    while i + 2 <= buf.len() {
        let len = u16::from_be_bytes([buf[i], buf[i + 1]]) as usize;
        if len == 0 {
            out.clean_disconnect = true;
            out.consumed = i + 2;
            return Ok(out);
        }
        if len > MAX_PACKET {
            anyhow::bail!("winnet: кадр пакета {len} > MAX_PACKET {MAX_PACKET} (мусор/DoS)");
        }
        if i + 2 + len > buf.len() {
            break; // недокадр — ждём дочитки
        }
        out.packets.push(buf[i + 2..i + 2 + len].to_vec());
        i += 2 + len;
    }
    out.consumed = i;
    Ok(out)
}

// ─────────────────────────── маршруты ───────────────────────────

/// Раскрыть маршруты В туннель для установки службой. `0.0.0.0/0` (full-tunnel) → две /1-половины
/// (`0.0.0.0/1` + `128.0.0.0/1`): они специфичнее физического default и перекрывают его, НЕ затирая
/// сам `default` — он нужен как nexthop для bypass-маршрутов к exit и для восстановления связи после
/// disconnect. Ровно поведение Linux-helperّа. Прочие CIDR — как есть.
pub fn tunnel_route_entries(routes: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for r in routes {
        if r == "0.0.0.0/0" {
            out.push("0.0.0.0/1".to_string());
            out.push("128.0.0.0/1".to_string());
        } else {
            out.push(r.clone());
        }
    }
    out
}

/// Есть ли среди маршрутов full-tunnel (`0.0.0.0/0`). Управляет блоком IPv6 (туннель IPv4-only ⇒
/// нативный IPv6 при full-tunnel/kill-switch — утечка мимо туннеля, как на Linux).
pub fn is_full_tunnel(routes: &[String]) -> bool {
    routes.iter().any(|r| r == "0.0.0.0/0")
}

// ─────────────────────── WFP kill-switch план ───────────────────────

/// Действие WFP-фильтра. Прямой аналог RETURN/DROP в цепочке `CITADEL_KS` (iptables).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpAction {
    /// Разрешить (продолжить). Аналог `-j RETURN`.
    Permit,
    /// Заблокировать. Финальный catch-all = fail-closed. Аналог `-j DROP`.
    Block,
}

/// Условие сопоставления WFP-фильтра. Служба маппит это в реальные `FWPM_FILTER_CONDITION`
/// на слое `FWPM_LAYER_ALE_AUTH_CONNECT_V4` (исходящие соединения).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WfpMatch {
    /// Любой трафик (catch-all для финального Block). Условий нет.
    Any,
    /// Локальный loopback (127.0.0.0/8) — не рвать локальные сокеты.
    Loopback,
    /// Трафик, уходящий через сам туннель-адаптер (условие по LUID адаптера — подставляется службой
    /// в рантайме). Аналог `-o citadel0 -j RETURN`.
    TunnelInterface,
    /// Удалённый адрес = IP/CIDR (exit-эндпоинты и split-обход). Аналог `-d <ip> -j RETURN`.
    RemoteHost(String),
    /// DHCP-аренда (UDP 67/68) — иначе теряется IP на физ.линке при full-tunnel. Аналог DHCP-RETURN.
    Dhcp,
}

/// Один WFP-фильтр плана. `weight` — приоритет: чем выше, тем раньше матчится (permit'ы обязаны
/// стоять ВЫШЕ финального Block, иначе трафик был бы заблокирован — как «DROP после всех RETURN»).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpFilter {
    pub action: WfpAction,
    pub match_: WfpMatch,
    pub weight: u8,
}

/// Вес финального Block (самый низкий): любой permit его перебивает.
pub const WFP_WEIGHT_BLOCK: u8 = 0;
/// Вес permit-правил (выше блока).
pub const WFP_WEIGHT_PERMIT: u8 = 8;
/// Вес критичных permit (loopback/туннель) — на всякий случай выше обычных permit.
pub const WFP_WEIGHT_PERMIT_HI: u8 = 12;

/// Построить план WFP-kill-switch (fail-closed): блокировать ВЕСЬ исходящий трафик, кроме loopback,
/// самого туннеля, зашифрованного пути к `exit_ips`, split-обхода `bypass` (C8.1/Q5) и DHCP.
///
/// Один-в-один модель `citadel-helper::killswitch_rules`, включая **исправление Q5**: без permit для
/// split-`bypass` эти назначения (идут физическим шлюзом) упёрлись бы в финальный Block — и сплит «не
/// работал» при включённом kill-switch. Здесь они получают отдельный `RemoteHost`-permit, fail-closed
/// для всего прочего сохранён (Block — самый низкий вес, catch-all).
pub fn wfp_killswitch_plan(exit_ips: &[String], bypass: &[String]) -> Vec<WfpFilter> {
    let mut f = vec![
        WfpFilter { action: WfpAction::Permit, match_: WfpMatch::Loopback, weight: WFP_WEIGHT_PERMIT_HI },
        WfpFilter { action: WfpAction::Permit, match_: WfpMatch::TunnelInterface, weight: WFP_WEIGHT_PERMIT_HI },
    ];
    for eip in exit_ips {
        f.push(WfpFilter { action: WfpAction::Permit, match_: WfpMatch::RemoteHost(eip.clone()), weight: WFP_WEIGHT_PERMIT });
    }
    // C8.1/Q5: split-обход — permit ТОЛЬКО к выбранным назначениям (иначе fail-closed их режет).
    for b in bypass {
        f.push(WfpFilter { action: WfpAction::Permit, match_: WfpMatch::RemoteHost(b.clone()), weight: WFP_WEIGHT_PERMIT });
    }
    f.push(WfpFilter { action: WfpAction::Permit, match_: WfpMatch::Dhcp, weight: WFP_WEIGHT_PERMIT });
    // fail-closed catch-all — самый низкий вес: любой permit выше него.
    f.push(WfpFilter { action: WfpAction::Block, match_: WfpMatch::Any, weight: WFP_WEIGHT_BLOCK });
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_setup() -> TunSetup {
        TunSetup {
            addr: [10, 7, 0, 5],
            prefix: 16,
            mtu: 1100,
            routes: vec!["0.0.0.0/0".into()],
            dns: Some("1.1.1.1".into()),
            exit_ips: vec!["203.0.113.9".into()],
            bypass: vec!["192.168.1.0/24".into()],
            killswitch: true,
        }
    }

    /// Конфиг переживает CBOR round-trip (app кодирует → служба декодирует).
    #[test]
    fn config_frame_roundtrip() {
        let s = sample_setup();
        let frame = encode_config(&s);
        assert_eq!(frame[0], TAG_CONFIG);
        let len = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
        assert_eq!(len, frame.len() - 5);
        let back = decode_config(&frame[5..]).unwrap();
        assert_eq!(back, s);
    }

    /// Кадрирование пакетов: несколько полных кадров разбираются, частичный хвост остаётся.
    #[test]
    fn packet_framing_splits_and_keeps_partial() {
        let p1 = vec![0x45u8, 0, 0, 20, 1, 2, 3, 4];
        let p2 = vec![0x45u8, 9, 9];
        let mut buf = encode_packet(&p1);
        buf.extend_from_slice(&encode_packet(&p2));
        // добавим НЕДОкадр (заявлено 5 байт, дано 2) — не должен потребиться
        buf.extend_from_slice(&[0, 5, 0xAA, 0xBB]);

        let framed = parse_stream(&buf).unwrap();
        assert_eq!(framed.packets, vec![p1.clone(), p2.clone()]);
        assert!(!framed.clean_disconnect);
        // потреблены только два полных кадра; недокадр (4 байта) остался
        assert_eq!(framed.consumed, encode_packet(&p1).len() + encode_packet(&p2).len());
        assert_eq!(&buf[framed.consumed..], &[0, 5, 0xAA, 0xBB]);
    }

    /// Маркер чистого disconnect (len==0) распознаётся и останавливает разбор.
    #[test]
    fn clean_disconnect_marker_detected() {
        let mut buf = encode_packet(&[1, 2, 3]);
        buf.extend_from_slice(&clean_disconnect_marker());
        buf.extend_from_slice(&encode_packet(&[9, 9])); // после маркера — игнор
        let framed = parse_stream(&buf).unwrap();
        assert_eq!(framed.packets, vec![vec![1, 2, 3]]);
        assert!(framed.clean_disconnect);
    }

    /// Мусорный кадр > MAX_PACKET отвергается (анти-DoS), а не аллоцирует гигабайт.
    #[test]
    fn oversized_frame_rejected() {
        let buf = [0xFFu8, 0xFF, 0, 0]; // заявлено 65535 > MAX_PACKET
        assert!(parse_stream(&buf).is_err());
    }

    /// full-tunnel раскрывается в две /1-половины (физический default выживает); прочее — как есть.
    #[test]
    fn full_tunnel_route_halves() {
        assert_eq!(
            tunnel_route_entries(&["0.0.0.0/0".into()]),
            vec!["0.0.0.0/1".to_string(), "128.0.0.0/1".to_string()]
        );
        assert!(is_full_tunnel(&["0.0.0.0/0".into()]));
        assert_eq!(
            tunnel_route_entries(&["10.0.0.0/8".into(), "172.16.0.0/12".into()]),
            vec!["10.0.0.0/8".to_string(), "172.16.0.0/12".to_string()]
        );
        assert!(!is_full_tunnel(&["10.0.0.0/8".into()]));
    }

    /// READY-«ОК» round-trip (служба кодирует → провайдер декодирует TunReady); ошибка — текст.
    #[test]
    fn ready_frame_ok_and_err() {
        let ready = TunReady { adapter_luid: 0xDEAD_BEEF };
        let frame = encode_ready_ok(&ready);
        assert_eq!(frame[0], TAG_READY);
        assert_eq!(frame[1], 0); // status ок
        let len = u32::from_be_bytes([frame[2], frame[3], frame[4], frame[5]]) as usize;
        assert_eq!(decode_ready(&frame[6..6 + len]).unwrap(), ready);

        let err = encode_ready_err("нет прав на WinTUN");
        assert_eq!((err[0], err[1]), (TAG_READY, 1));
        let elen = u32::from_be_bytes([err[2], err[3], err[4], err[5]]) as usize;
        assert_eq!(&err[6..6 + elen], "нет прав на WinTUN".as_bytes());
    }

    /// split_routes — единый источник split-семантики Linux+Windows (та же логика, что была в gui_tun).
    #[test]
    fn split_routes_modes() {
        let dests = vec!["192.168.0.0/16".to_string(), "10.0.0.5/32".to_string()];
        // Off → маршруты ссылки, без обхода
        assert_eq!(split_routes(SplitMode::Off, "0.0.0.0/0", &dests), (vec!["0.0.0.0/0".to_string()], vec![]));
        // Include → в туннель только выбранные, обхода нет
        assert_eq!(split_routes(SplitMode::Include, "0.0.0.0/0", &dests), (dests.clone(), vec![]));
        // Exclude → маршруты ссылки + выбранные в обход
        assert_eq!(split_routes(SplitMode::Exclude, "0.0.0.0/0", &dests), (vec!["0.0.0.0/0".to_string()], dests.clone()));
    }

    /// WFP-kill-switch: fail-closed форма + Q5. exit-ip и split-обход — permit; ровно один Block-Any;
    /// Block имеет минимальный вес (любой permit его перебивает — «DROP после всех RETURN»).
    #[test]
    fn wfp_killswitch_failclosed_and_q5_bypass() {
        let exit = vec!["203.0.113.9".to_string()];
        let bypass = vec!["192.168.1.0/24".to_string(), "203.0.113.7".to_string()];
        let plan = wfp_killswitch_plan(&exit, &bypass);

        // ровно один финальный Block, условие Any
        let blocks: Vec<_> = plan.iter().filter(|f| f.action == WfpAction::Block).collect();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].match_, WfpMatch::Any);

        // loopback и туннель разрешены
        assert!(plan.iter().any(|f| f.action == WfpAction::Permit && f.match_ == WfpMatch::Loopback));
        assert!(plan.iter().any(|f| f.action == WfpAction::Permit && f.match_ == WfpMatch::TunnelInterface));

        // Q5: КАЖДОЕ split-обход-назначение — permit по RemoteHost (иначе сплит не работает при KS)
        for b in &bypass {
            assert!(
                plan.iter().any(|f| f.action == WfpAction::Permit
                    && f.match_ == WfpMatch::RemoteHost(b.clone())),
                "split-обход {b} должен быть Permit"
            );
        }
        // exit-ip тоже permit
        assert!(plan.iter().any(|f| f.match_ == WfpMatch::RemoteHost("203.0.113.9".into())));

        // fail-closed: Block — строго ниже любого permit по весу
        let min_permit = plan.iter().filter(|f| f.action == WfpAction::Permit).map(|f| f.weight).min().unwrap();
        assert!(blocks[0].weight < min_permit, "Block-вес должен быть ниже всех permit (fail-closed)");
    }
}
