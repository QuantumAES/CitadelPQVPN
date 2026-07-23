//! WFP kill-switch — FWPM-фильтры fail-closed из плана [`citadel_winnet::wfp_killswitch_plan`].
//!
//! **Динамическая** WFP-сессия (`FWPM_SESSION0` c `FWPM_SESSION_FLAG_DYNAMIC`): все добавленные
//! фильтры и sublayer авто-удаляются при закрытии engine-хендла. Fail-closed: engine держится в
//! process-global [`ENGINE`], пока сессия жива. Чистый disconnect → [`disarm`] (закрыть engine →
//! снять фильтры). Аварийный разрыв (краш app/реконнект) → engine НЕ закрываем: фильтры остаются,
//! не-туннельный трафик заблокирован (как helper держит iptables при EOF-без-'Q'). [`arm`]
//! идемпотентен: сперва закрывает прошлый engine (чистит и осиротевший от аварии), затем ставит
//! свежий набор — как `setup_killswitch` вызывает `teardown_killswitch`.

use std::sync::Mutex;

use citadel_winnet::{WfpAction, WfpFilter, WfpMatch};
use windows::core::{GUID, PWSTR};
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

/// Фиксированный sublayer-ключ (свои объекты находим/чистим по нему).
const CITADEL_SUBLAYER: GUID = GUID::from_u128(0x0c17ade1_7c0a_4de1_9c17_ade17c0ade17);

struct Engine(HANDLE);
// SAFETY: engine-хендл используется под Mutex; WFP допускает вызовы из разных потоков.
unsafe impl Send for Engine {}

static ENGINE: Mutex<Option<Engine>> = Mutex::new(None);

/// Армировать WFP kill-switch по плану. `tun_luid` — LUID WinTUN-адаптера (permit трафика в туннель).
pub fn arm(filters: &[WfpFilter], tun_luid: u64) -> anyhow::Result<()> {
    let mut guard = ENGINE.lock().unwrap();
    // идемпотентность: снять прошлый набор (в т.ч. осиротевший после аварийного разрыва)
    if let Some(old) = guard.take() {
        unsafe { FwpmEngineClose0(old.0) };
    }
    let engine = open_dynamic_engine()?;
    // На ЛЮБОЙ ошибке ниже — закрыть engine. Иначе динамическая сессия (с уже добавленным sublayer'ом)
    // утекает: повторный arm откроет новый engine и упрётся в FWP_E_ALREADY_EXISTS на том же
    // sublayer-GUID (наблюдалось как каскад «os error 233» на второй попытке connect).
    let build = (|| -> anyhow::Result<()> {
        add_sublayer(engine)?;
        for f in filters {
            add_filter(engine, f, tun_luid)?;
        }
        Ok(())
    })();
    if let Err(e) = build {
        unsafe { FwpmEngineClose0(engine) };
        return Err(e);
    }
    *guard = Some(Engine(engine));
    Ok(())
}

/// Снять WFP (чистый disconnect): закрыть engine → динамические фильтры/sublayer удаляются.
pub fn disarm() {
    if let Some(e) = ENGINE.lock().unwrap().take() {
        unsafe { FwpmEngineClose0(e.0) };
    }
}

fn open_dynamic_engine() -> anyhow::Result<HANDLE> {
    // SAFETY: session — валидная zeroed-структура; enginehandle пишется API при успехе.
    let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    let mut handle = HANDLE::default();
    let rc = unsafe {
        FwpmEngineOpen0(
            windows::core::PCWSTR::null(),
            RPC_C_AUTHN_WINNT,
            None,
            Some(&session as *const _),
            &mut handle,
        )
    };
    if rc != ERROR_SUCCESS.0 {
        anyhow::bail!("FwpmEngineOpen0 → {rc}");
    }
    Ok(handle)
}

fn add_sublayer(engine: HANDLE) -> anyhow::Result<()> {
    let mut name: Vec<u16> = "CitadelPQVPN killswitch\0".encode_utf16().collect();
    // SAFETY: zeroed FWPM_SUBLAYER0; name живёт до конца вызова.
    let mut sub: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
    sub.subLayerKey = CITADEL_SUBLAYER;
    sub.displayData.name = PWSTR(name.as_mut_ptr());
    sub.weight = 0x8000; // высокий приоритет sublayer'а
    let rc = unsafe { FwpmSubLayerAdd0(engine, &sub, None) };
    if rc != ERROR_SUCCESS.0 {
        anyhow::bail!("FwpmSubLayerAdd0 → {rc}");
    }
    Ok(())
}

/// Добавить один фильтр (permit/block с условием по match). Backing-данные условия держим на стеке
/// до конца `FwpmFilterAdd0` (API копирует их внутрь).
fn add_filter(engine: HANDLE, f: &WfpFilter, tun_luid: u64) -> anyhow::Result<()> {
    let mut luid_store: u64 = tun_luid;
    let flag_store: u32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
    let mut addrmask_store = FWP_V4_ADDR_AND_MASK { addr: 0, mask: 0 };
    let mut addr_store: u32 = 0;
    let port_store: u16 = 67;

    let mut conds: Vec<FWPM_FILTER_CONDITION0> = Vec::new();
    // SAFETY (ниже): все условия — zeroed FWPM_FILTER_CONDITION0 с валидными полями; union-поля
    // conditionValue заполняем по типу; backing-переменные живут до FwpmFilterAdd0.
    match &f.match_ {
        WfpMatch::Any => {} // без условий — catch-all
        WfpMatch::Loopback => unsafe {
            let mut c: FWPM_FILTER_CONDITION0 = std::mem::zeroed();
            c.fieldKey = FWPM_CONDITION_FLAGS;
            c.matchType = FWP_MATCH_FLAGS_ANY_SET;
            c.conditionValue.r#type = FWP_UINT32;
            c.conditionValue.Anonymous.uint32 = flag_store;
            conds.push(c);
        },
        WfpMatch::TunnelInterface => unsafe {
            let mut c: FWPM_FILTER_CONDITION0 = std::mem::zeroed();
            c.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
            c.matchType = FWP_MATCH_EQUAL;
            c.conditionValue.r#type = FWP_UINT64;
            c.conditionValue.Anonymous.uint64 = &mut luid_store;
            conds.push(c);
        },
        WfpMatch::RemoteHost(cidr) => unsafe {
            let (addr, mask) = parse_v4(cidr);
            let mut c: FWPM_FILTER_CONDITION0 = std::mem::zeroed();
            c.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
            c.matchType = FWP_MATCH_EQUAL;
            if mask == u32::MAX {
                addr_store = addr;
                c.conditionValue.r#type = FWP_UINT32;
                c.conditionValue.Anonymous.uint32 = addr_store;
            } else {
                addrmask_store = FWP_V4_ADDR_AND_MASK { addr, mask };
                c.conditionValue.r#type = FWP_V4_ADDR_MASK;
                c.conditionValue.Anonymous.v4AddrMask = &mut addrmask_store;
            }
            conds.push(c);
        },
        WfpMatch::Dhcp => unsafe {
            let mut c: FWPM_FILTER_CONDITION0 = std::mem::zeroed();
            c.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
            c.matchType = FWP_MATCH_EQUAL;
            c.conditionValue.r#type = FWP_UINT16;
            c.conditionValue.Anonymous.uint16 = port_store;
            conds.push(c);
        },
    }

    // SAFETY: zeroed FWPM_FILTER0; поля выставлены; filterCondition указывает на conds (живёт до вызова).
    let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
    // FWPM требует НЕПУСТОЙ displayData.name у фильтра, иначе FwpmFilterAdd0 → FWP_E_NULL_DISPLAY_NAME
    // (0x80320023). Строка живёт до конца вызова (API копирует её внутрь объекта фильтра).
    let mut fname: Vec<u16> = "CitadelPQVPN killswitch\0".encode_utf16().collect();
    filter.displayData.name = PWSTR(fname.as_mut_ptr());
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey = CITADEL_SUBLAYER;
    filter.weight.r#type = FWP_UINT8;
    filter.weight.Anonymous.uint8 = f.weight;
    filter.numFilterConditions = conds.len() as u32;
    if !conds.is_empty() {
        filter.filterCondition = conds.as_mut_ptr();
    }
    filter.action.r#type = match f.action {
        WfpAction::Permit => FWP_ACTION_PERMIT,
        WfpAction::Block => FWP_ACTION_BLOCK,
    };

    let mut id: u64 = 0;
    let rc = unsafe { FwpmFilterAdd0(engine, &filter, None, Some(&mut id)) };
    if rc != ERROR_SUCCESS.0 {
        anyhow::bail!("FwpmFilterAdd0 → {rc}");
    }
    // держим backing-переменные до сюда (API уже скопировал)
    let _ = (&luid_store, &flag_store, &addrmask_store, &addr_store, &port_store, &fname);
    Ok(())
}

/// `a.b.c.d` или `a.b.c.d/p` → (адрес, маска) в HOST-порядке (WFP ждёт host-byte-order для IP-условий).
fn parse_v4(cidr: &str) -> (u32, u32) {
    let (ip, prefix) = match cidr.split_once('/') {
        Some((a, p)) => (a, p.parse::<u8>().unwrap_or(32)),
        None => (cidr, 32),
    };
    let addr = ip.parse::<std::net::Ipv4Addr>().map(u32::from).unwrap_or(0);
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) };
    (addr, mask)
}
