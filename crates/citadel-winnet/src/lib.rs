//! `citadel-winnet` — платформо-нейтральное ядро Windows-модели W2 (сервис-плумбер + пакет-пайп).
//!
//! **Лёгкий общий крейт** (serde/ciborium/anyhow, БЕЗ движка): им пользуются и `WindowsTunProvider`
//! (в `citadel-client`, app-сторона), и привилегированная служба `citadel-svc` — чтобы обе стороны
//! кадрировали пайп и строили WFP-план ОДНИМ кодом, а служба НЕ линковала QUIC-движок (меньше
//! attack surface у elevated-процесса). `split_routes` (нужен `SplitMode`) живёт в `citadel-client`.
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

use serde::{Deserialize, Serialize};

/// Байт-тег управляющего кадра фазы конфигурации (app → служба): `TAG_CONFIG ‖ u32(len,BE) ‖ cbor`.
pub const TAG_CONFIG: u8 = 0x01;
/// Байт-тег ответа готовности (служба → app): `TAG_READY ‖ status(u8) ‖ u32(len,BE) ‖ cbor(TunReady)`.
/// `status`: 0 = ок (адаптер поднят, дальше фаза данных); ≠0 = ошибка (тело — UTF-8 текст).
pub const TAG_READY: u8 = 0x02;
/// Байт-тег «остановить службу» (app → служба, без тела): приложение шлёт его при ВЫХОДЕ, чтобы
/// привилегированная служба не висела в процессах, когда клиента нет (меньше attack surface у
/// elevated-процесса). Принимается только в фазе конфигурации от аутентифицированного клиента
/// (W3: образ из install-dir), а serve-цикл обслуживает клиентов ПО ОДНОМУ ⇒ пока идёт сессия,
/// кадр вообще некому прочитать: чужой туннель этим не оборвать.
pub const TAG_QUIT: u8 = 0x03;

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

/// Разобрать управляющий кадр конфига (без ведущего тега — тег читает транспорт-цикл). W2 (аудит-3):
/// CBOR приходит от НЕпривилегированного app по пайпу (ACL даёт IU), а поля уходят в `netsh`/`route`/
/// WFP привилегированной службы (LocalSystem) — валидируем ЗДЕСЬ, на границе привилегий, паритет с
/// Linux-helper (S1.2). Хоть std::process и не расщепляет argv (нет shell), битое значение сорвало бы
/// bring_up, а `0.0.0.0/0` в `bypass` дал бы WFP-permit «весь трафик» (дыра в KS) — отсекаем заранее.
pub fn decode_config(body: &[u8]) -> anyhow::Result<TunSetup> {
    let setup: TunSetup = ciborium::from_reader(body)?;
    setup.validate()?;
    Ok(setup)
}

/// `s` — валидный IPv4-адрес. Отсекает перевод строки/мусор (как `citadel-helper::is_ip`).
fn is_ipv4(s: &str) -> bool {
    s.parse::<std::net::Ipv4Addr>().is_ok()
}

/// `s` — валидный IPv4 `a.b.c.d/p` (0..=32) или голый IPv4 (=host /32). Как `citadel-helper::is_cidr`.
///
/// Одна дверь с [`parse_v4_cidr`] намеренно: «что считается валидным CIDR» должно быть ОДНИМ
/// определением. Иначе валидация на границе привилегий и разбор при армировании WFP разъезжаются,
/// и строка, прошедшая проверку, разбирается уже по-другому.
fn is_cidr_v4(s: &str) -> bool {
    parse_v4_cidr(s).is_ok()
}

/// `a.b.c.d` или `a.b.c.d/p` → `(адрес, маска)` в **host-порядке** (в этом виде их ждут
/// IP-условия WFP).
///
/// N-9: именно `Result`, а не «при неудаче 0.0.0.0». Прежний разбор молча превращал неразобранную
/// строку в `0.0.0.0/32`, и последствие было не «дыра» (permit просто не срабатывал — направление
/// fail-closed), а нечто хуже для оператора: интернет пропадал без единой причины в журнале.
/// Диагноз обязан появляться там, где ошибка, а не в виде необъяснимого поведения сети.
pub fn parse_v4_cidr(cidr: &str) -> anyhow::Result<(u32, u32)> {
    let (ip, prefix) = match cidr.split_once('/') {
        Some((a, p)) => {
            let n: u8 = p
                .parse()
                .map_err(|_| anyhow::anyhow!("CIDR {cidr:?}: префикс {p:?} — не число"))?;
            if n > 32 {
                anyhow::bail!("CIDR {cidr:?}: префикс /{n} вне 0..=32");
            }
            (a, n)
        }
        None => (cidr, 32),
    };
    let addr: std::net::Ipv4Addr = ip
        .parse()
        .map_err(|_| anyhow::anyhow!("CIDR {cidr:?}: {ip:?} — не IPv4-адрес"))?;
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) };
    Ok((u32::from(addr), mask))
}

/// N-9: проверить, что план WFP разбирается ЦЕЛИКОМ, прежде чем армировать хоть один фильтр.
///
/// Раньше неразобранная строка доезжала до `FwpmFilterAdd0` и превращалась в permit для
/// `0.0.0.0/32` — фильтр вставал, вёл себя не как задумано, и понять это по журналу было нельзя.
/// Проверка живёт здесь (а не в Windows-модуле), потому что так она проверяется тестом на любой
/// платформе, а не только на живой машине.
pub fn check_wfp_plan(filters: &[WfpFilter]) -> anyhow::Result<()> {
    for f in filters {
        if let WfpMatch::RemoteHost(cidr) = &f.match_ {
            parse_v4_cidr(cidr)
                .map_err(|e| anyhow::anyhow!("WFP-план не армирован: {e}"))?;
        }
    }
    // L-12: на каждом слое (семейство × ступень) catch-all Block обязан сопровождаться permit'ами
    // ЭТОГО ЖЕ слоя. Слой с одним лишь block-catch-all — это не kill-switch, а «интернета нет»:
    // рубится и туннель, и loopback. Проверка нужна именно с появлением второй ступени: раньше
    // потерять permit'ы можно было только переписав сам план целиком, теперь — забыв продублировать.
    for family in [WfpFamily::V4, WfpFamily::V6] {
        for stage in [WfpStage::Connect, WfpStage::Packet] {
            let layer = filters.iter().filter(|f| f.family == family && f.stage == stage);
            let (mut catch_all, mut permits) = (false, 0usize);
            for f in layer {
                match f.action {
                    WfpAction::Block if f.match_ == WfpMatch::Any => catch_all = true,
                    WfpAction::Permit => permits += 1,
                    WfpAction::Block => {}
                }
            }
            if catch_all && permits == 0 {
                anyhow::bail!(
                    "WFP-план не армирован: слой {family:?}/{stage:?} состоит из одного \
                     block-catch-all без единого permit — это отключение сети, а не kill-switch"
                );
            }
        }
    }
    Ok(())
}

impl TunSetup {
    /// W2: валидация всех строковых полей ДО построения netsh/route/WFP-плана (граница привилегий).
    /// Туннель IPv4-only ⇒ адреса/маршруты/DNS — только IPv4. Числовые (`mtu`/`addr`/`prefix`) уже
    /// типизированы (u32/[u8;4]/u8) — инъекция невозможна by-construction; `prefix` клампится в `mask`.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.prefix > 32 {
            anyhow::bail!("TunSetup: prefix {} вне 0..=32", self.prefix);
        }
        for r in &self.routes {
            if !is_cidr_v4(r) {
                anyhow::bail!("TunSetup: невалидный маршрут {r:?} (ожидался IPv4-CIDR)");
            }
        }
        if let Some(dns) = &self.dns {
            if !is_ipv4(dns) {
                anyhow::bail!("TunSetup: dns {dns:?} не IPv4-адрес (анти-инъекция)");
            }
        }
        for e in &self.exit_ips {
            if !is_ipv4(e) {
                anyhow::bail!("TunSetup: exit_ip {e:?} не IPv4-адрес");
            }
        }
        for b in &self.bypass {
            if !is_cidr_v4(b) {
                anyhow::bail!("TunSetup: bypass {b:?} не IPv4-CIDR");
            }
            // W2: bypass с префиксом /0 (0.0.0.0/0) стал бы WFP-permit «весь трафик» = дыра в
            // kill-switch (permit RemoteHost 0.0.0.0/0 перебил бы fail-closed Block). Запрещаем.
            if b.split_once('/').is_some_and(|(_, p)| p == "0") {
                anyhow::bail!("TunSetup: bypass {b:?} с префиксом /0 запрещён (обнулил бы kill-switch)");
            }
        }
        Ok(())
    }
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

/// Семейство адресов фильтра → слой WFP, на который его ставит служба. Туннель IPv4-only, поэтому
/// `V6`-фильтры служат ТОЛЬКО для fail-closed блока утечки нативного IPv6 (аналог `CITADEL_KS6` на
/// Linux, S2.2/A2): permit loopback, block-any на `FWPM_LAYER_ALE_AUTH_CONNECT_V6`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpFamily {
    V4,
    V6,
}

/// L-12 (аудит-4): **ступень** фильтрации — на каком слое WFP стоит фильтр.
///
/// `ALE_AUTH_CONNECT` гейтит только УСТАНОВЛЕНИЕ соединения: он спрашивается один раз, при
/// `connect()` (и на первом исходящем UDP-датаграмме). Уже установленный поток через него больше
/// не проходит — поэтому kill-switch, стоящий только на ALE, не рвёт скачивание, начатое ДО
/// подъёма туннеля: оно продолжает идти физическим интерфейсом мимо туннеля, ровно то, чего
/// kill-switch обязан не допускать (на Linux этого класса дыры нет — `iptables OUTPUT` смотрит
/// КАЖДЫЙ пакет).
///
/// Лечится вторым набором тех же правил на **пакетном** слое `OUTBOUND_TRANSPORT`, который
/// спрашивается на каждый исходящий пакет, включая пакеты давно живущих потоков. Выбран именно он,
/// а не `ALE_FLOW_ESTABLISHED`: последний тоже срабатывает один раз (в момент установления потока)
/// и для потоков, живших ДО армирования, не сработает вовсе — то есть не решает исходную задачу.
///
/// Обе ступени армируются вместе и содержат ОДИН И ТОТ ЖЕ набор permit/block: пакетный слой без
/// permit'ов зарубил бы и сам туннель.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpStage {
    /// `FWPM_LAYER_ALE_AUTH_CONNECT_{V4,V6}` — гейт установления исходящих соединений.
    Connect,
    /// `FWPM_LAYER_OUTBOUND_TRANSPORT_{V4,V6}` — пакетный слой: каждый исходящий пакет, включая
    /// пакеты потоков, установленных до армирования (L-12).
    Packet,
}

/// Один WFP-фильтр плана. `weight` — приоритет: чем выше, тем раньше матчится (permit'ы обязаны
/// стоять ВЫШЕ финального Block, иначе трафик был бы заблокирован — как «DROP после всех RETURN»).
/// `family` + `stage` выбирают слой (V4/V6 × connect/packet) — веса сравниваются В ПРЕДЕЛАХ слоя.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpFilter {
    pub action: WfpAction,
    pub match_: WfpMatch,
    pub weight: u8,
    pub family: WfpFamily,
    pub stage: WfpStage,
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
    let v4 = |action, match_, weight| WfpFilter {
        action,
        match_,
        weight,
        family: WfpFamily::V4,
        stage: WfpStage::Connect,
    };
    let mut f = vec![
        v4(WfpAction::Permit, WfpMatch::Loopback, WFP_WEIGHT_PERMIT_HI),
        v4(WfpAction::Permit, WfpMatch::TunnelInterface, WFP_WEIGHT_PERMIT_HI),
    ];
    for eip in exit_ips {
        f.push(v4(WfpAction::Permit, WfpMatch::RemoteHost(eip.clone()), WFP_WEIGHT_PERMIT));
    }
    // C8.1/Q5: split-обход — permit ТОЛЬКО к выбранным назначениям (иначе fail-closed их режет).
    for b in bypass {
        f.push(v4(WfpAction::Permit, WfpMatch::RemoteHost(b.clone()), WFP_WEIGHT_PERMIT));
    }
    f.push(v4(WfpAction::Permit, WfpMatch::Dhcp, WFP_WEIGHT_PERMIT));
    // fail-closed catch-all — самый низкий вес: любой permit выше него.
    f.push(v4(WfpAction::Block, WfpMatch::Any, WFP_WEIGHT_BLOCK));
    mirror_to_packet_stage(f)
}

/// L-12: продублировать план на пакетную ступень (`OUTBOUND_TRANSPORT`).
///
/// Ровно ТЕ ЖЕ правила и веса — меняется только слой. Дублируется весь набор, а не один финальный
/// Block: пакетный слой, на котором стоит только block-catch-all, зарубил бы и сам туннель (его
/// UDP к exit'у), и loopback, то есть превратил бы kill-switch в «интернета нет вообще».
fn mirror_to_packet_stage(connect: Vec<WfpFilter>) -> Vec<WfpFilter> {
    let packet: Vec<WfpFilter> = connect
        .iter()
        .map(|f| WfpFilter { stage: WfpStage::Packet, ..f.clone() })
        .collect();
    let mut all = connect;
    all.extend(packet);
    all
}

/// W1 (аудит-3) / A2-паритет для Windows: fail-closed блок исходящего IPv6. Туннель IPv4-only ⇒
/// нативный IPv6 (данные + IPv6-DNS) уходит физическим адаптером МИМО туннеля И мимо IPv4-kill-switch
/// → деанонимизация на dual-stack (ровно A2, закрытый на Linux `ip6tables`/Android blackhole, но не
/// на Windows). Ставится службой на `FWPM_LAYER_ALE_AUTH_CONNECT_V6`, который гейтит УСТАНОВЛЕНИЕ
/// исходящих IPv6-соединений (TCP-connect / первый UDP, включая IPv6-DNS). ICMPv6 ND (RS/RA/NS/NA)
/// идёт МИМО ALE_AUTH_CONNECT ⇒ локальный IPv6-стек не ломается без спец-permit (в отличие от Linux
/// OUTPUT, где ND пришлось разрешать явно). Permit только loopback (::1). Триггерится при
/// `killswitch || full-tunnel` (см. [`plan_session`]), как `block_ipv6` на Linux.
pub fn wfp_ipv6_block_plan() -> Vec<WfpFilter> {
    let v6 = |action, match_, weight| WfpFilter {
        action,
        match_,
        weight,
        family: WfpFamily::V6,
        stage: WfpStage::Connect,
    };
    mirror_to_packet_stage(vec![
        v6(WfpAction::Permit, WfpMatch::Loopback, WFP_WEIGHT_PERMIT_HI),
        // fail-closed: весь прочий исходящий IPv6 — Block (самый низкий вес, catch-all).
        v6(WfpAction::Block, WfpMatch::Any, WFP_WEIGHT_BLOCK),
    ])
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

    /// W2: decode_config валидирует недоверенный CBOR (граница привилегий app→служба). Валидный
    /// конфиг проходит; инъекция/мусор в полях, уходящих в netsh/route/WFP, — отклонены.
    #[test]
    fn decode_config_validates_untrusted_fields() {
        let enc = |s: &TunSetup| {
            let mut b = Vec::new();
            ciborium::into_writer(s, &mut b).unwrap();
            b
        };
        let base = sample_setup();
        assert!(decode_config(&enc(&base)).is_ok(), "валидный конфиг проходит");

        let bad = |mut mut_fn: Box<dyn FnMut(&mut TunSetup)>| {
            let mut s = base.clone();
            mut_fn(&mut s);
            decode_config(&enc(&s))
        };
        // инъекция перевода строки в dns (иначе ушла бы в netsh set dnsservers)
        assert!(bad(Box::new(|s| s.dns = Some("1.1.1.1\nnameserver 6.6.6.6".into()))).is_err());
        assert!(bad(Box::new(|s| s.routes = vec!["not-a-cidr".into()])).is_err()); // мусорный маршрут
        assert!(bad(Box::new(|s| s.bypass = vec!["junk/33".into()])).is_err()); // битый CIDR
        assert!(bad(Box::new(|s| s.bypass = vec!["0.0.0.0/0".into()])).is_err()); // /0 = дыра в KS
        assert!(bad(Box::new(|s| s.exit_ips = vec!["evil".into()])).is_err()); // exit_ip не IP
        assert!(bad(Box::new(|s| s.prefix = 33)).is_err()); // prefix вне диапазона
        // 0.0.0.0/0 в routes (full-tunnel) — ЛЕГИТИМНО, проходит
        assert!(bad(Box::new(|s| s.routes = vec!["0.0.0.0/0".into()])).is_ok());
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

    /// WFP-kill-switch: fail-closed форма + Q5. exit-ip и split-обход — permit; на КАЖДОЙ ступени
    /// ровно один Block-Any; Block имеет минимальный вес (любой permit его перебивает — «DROP после
    /// всех RETURN»).
    #[test]
    fn wfp_killswitch_failclosed_and_q5_bypass() {
        let exit = vec!["203.0.113.9".to_string()];
        let bypass = vec!["192.168.1.0/24".to_string(), "203.0.113.7".to_string()];
        let full = wfp_killswitch_plan(&exit, &bypass);

        for stage in [WfpStage::Connect, WfpStage::Packet] {
            let plan: Vec<&WfpFilter> = full.iter().filter(|f| f.stage == stage).collect();

            // ровно один финальный Block на ступень, условие Any
            let blocks: Vec<_> = plan.iter().filter(|f| f.action == WfpAction::Block).collect();
            assert_eq!(blocks.len(), 1, "{stage:?}: один Block-catch-all");
            assert_eq!(blocks[0].match_, WfpMatch::Any);

            // loopback и туннель разрешены
            assert!(plan.iter().any(|f| f.action == WfpAction::Permit && f.match_ == WfpMatch::Loopback));
            assert!(plan.iter().any(|f| f.action == WfpAction::Permit && f.match_ == WfpMatch::TunnelInterface));

            // Q5: КАЖДОЕ split-обход-назначение — permit по RemoteHost (иначе сплит не работает при KS)
            for b in &bypass {
                assert!(
                    plan.iter().any(|f| f.action == WfpAction::Permit
                        && f.match_ == WfpMatch::RemoteHost(b.clone())),
                    "{stage:?}: split-обход {b} должен быть Permit"
                );
            }
            // exit-ip тоже permit
            assert!(plan.iter().any(|f| f.match_ == WfpMatch::RemoteHost("203.0.113.9".into())));

            // fail-closed: Block — строго ниже любого permit по весу
            let min_permit =
                plan.iter().filter(|f| f.action == WfpAction::Permit).map(|f| f.weight).min().unwrap();
            assert!(blocks[0].weight < min_permit, "{stage:?}: Block ниже всех permit (fail-closed)");
        }

        // W1: kill-switch — целиком IPv4-слой (V6-утечку закрывает отдельный wfp_ipv6_block_plan).
        assert!(full.iter().all(|f| f.family == WfpFamily::V4), "KS-фильтры — семейство V4");
    }

    /// L-12 (аудит-4): kill-switch обязан рвать УЖЕ УСТАНОВЛЕННЫЕ потоки. `ALE_AUTH_CONNECT`
    /// спрашивается один раз при установлении соединения, поэтому скачивание, начатое до подъёма
    /// туннеля, продолжало идти мимо. План обязан существовать на ОБЕИХ ступенях и быть на них
    /// идентичным (пакетная ступень без permit'ов зарубила бы сам туннель).
    #[test]
    fn killswitch_covers_flows_established_before_arming() {
        let plans = [
            wfp_killswitch_plan(&["203.0.113.9".into()], &["192.168.1.0/24".into()]),
            wfp_ipv6_block_plan(),
        ];
        for plan in plans {
            let of = |stage: WfpStage| -> Vec<(WfpAction, WfpMatch, u8, WfpFamily)> {
                plan.iter()
                    .filter(|f| f.stage == stage)
                    .map(|f| (f.action, f.match_.clone(), f.weight, f.family))
                    .collect()
            };
            let connect = of(WfpStage::Connect);
            assert!(!connect.is_empty(), "ступень connect обязана быть");
            assert_eq!(connect, of(WfpStage::Packet), "ступени обязаны совпадать правило-в-правило");
        }
    }

    /// Страховка от «слой из одного Block»: продублировать catch-all, забыв permit'ы, — это не
    /// kill-switch, а отключение сети (рубится и туннель, и loopback). Такой план не армируется.
    #[test]
    fn plan_with_block_only_layer_is_refused() {
        let mut plan = wfp_killswitch_plan(&["203.0.113.9".into()], &[]);
        plan.retain(|f| f.stage == WfpStage::Connect || f.action == WfpAction::Block);
        let err = check_wfp_plan(&plan).expect_err("слой из одного Block обязан быть отвергнут");
        assert!(format!("{err}").contains("Packet"), "в отказе назван слой: {err}");
        // …а полный план проходит.
        check_wfp_plan(&wfp_killswitch_plan(&["203.0.113.9".into()], &[])).unwrap();
    }

    /// N-9: разбор CIDR для WFP — с ошибкой, а не с молчаливым `0.0.0.0`. Мусорная строка обязана
    /// останавливать армирование ПЛАНА ЦЕЛИКОМ и называть причину: прежнее поведение превращало
    /// опечатку в «интернета нет без объяснений» (permit просто не срабатывал).
    #[test]
    fn wfp_plan_is_not_armed_with_unparsed_cidr() {
        // Разбор: host-порядок, маска по префиксу, /0 — нулевая маска.
        assert_eq!(parse_v4_cidr("203.0.113.9").unwrap(), (0xCB00_7109, u32::MAX));
        assert_eq!(parse_v4_cidr("192.168.1.0/24").unwrap(), (0xC0A8_0100, 0xFFFF_FF00));
        assert_eq!(parse_v4_cidr("0.0.0.0/0").unwrap(), (0, 0));

        for bad in ["", "не-адрес", "192.168.1.0/33", "192.168.1.0/x", "1.2.3", "1.2.3.4/24 ", "1.2.3.4\n"] {
            assert!(parse_v4_cidr(bad).is_err(), "{bad:?} не должен разбираться");
        }

        // План с мусором не армируется, и в тексте отказа видно САМУ строку.
        let plan = wfp_killswitch_plan(&["203.0.113.9".into()], &["192.168.1.0/33".into()]);
        let err = check_wfp_plan(&plan).expect_err("план с мусорным CIDR обязан быть отвергнут");
        let msg = format!("{err}");
        assert!(msg.contains("192.168.1.0/33"), "в отказе должна быть сама строка: {msg}");

        // …а чистый план проходит.
        let ok = wfp_killswitch_plan(&["203.0.113.9".into()], &["192.168.1.0/24".into()]);
        check_wfp_plan(&ok).expect("корректный план обязан армироваться");
    }

    /// Валидация на границе привилегий и разбор при армировании обязаны сходиться: всё, что
    /// `TunSetup::validate` пропустил, должно разбираться, и наоборот. Разъезд этих двух мест —
    /// классический источник «проверили одно, применили другое».
    #[test]
    fn boundary_validation_agrees_with_wfp_parsing() {
        for s in ["10.0.0.1", "10.0.0.0/8", "0.0.0.0/0", "255.255.255.255/32"] {
            assert_eq!(is_cidr_v4(s), parse_v4_cidr(s).is_ok(), "{s}");
        }
        for s in ["", "10.0.0.1/33", "10.0.0.1/-1", "ten.zero", "::1", "10.0.0.1/8/8"] {
            assert!(!is_cidr_v4(s), "{s:?} не должен считаться валидным");
            assert!(parse_v4_cidr(s).is_err(), "{s:?} не должен разбираться");
        }
    }

    /// W1 (A2-паритет Windows): IPv6-блок — fail-closed на V6-слое. permit только loopback, ровно
    /// один Block-Any, Block ниже permit по весу, ВСЕ фильтры — семейство V6 (иначе встали бы на
    /// V4-слой и не закрыли бы утечку нативного IPv6 мимо IPv4-only туннеля).
    #[test]
    fn wfp_ipv6_block_failclosed_v6_family() {
        let full = wfp_ipv6_block_plan();
        assert!(full.iter().all(|f| f.family == WfpFamily::V6), "IPv6-блок — семейство V6");

        for stage in [WfpStage::Connect, WfpStage::Packet] {
            let plan: Vec<&WfpFilter> = full.iter().filter(|f| f.stage == stage).collect();
            let blocks: Vec<_> = plan.iter().filter(|f| f.action == WfpAction::Block).collect();
            assert_eq!(blocks.len(), 1, "{stage:?}: ровно один финальный Block");
            assert_eq!(blocks[0].match_, WfpMatch::Any, "Block — catch-all (весь IPv6)");

            // loopback (::1) разрешён — не рвём локальные IPv6-сокеты
            assert!(plan.iter().any(|f| f.action == WfpAction::Permit && f.match_ == WfpMatch::Loopback));

            // fail-closed: Block строго ниже любого permit по весу (иначе IPv6 утёк бы)
            let min_permit =
                plan.iter().filter(|f| f.action == WfpAction::Permit).map(|f| f.weight).min().unwrap();
            assert!(blocks[0].weight < min_permit, "{stage:?}: Block ниже всех permit");
        }
    }
}
