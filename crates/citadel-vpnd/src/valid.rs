//! Граница привилегий (L2): разбор недоверенного ввода перед привилегированными операциями.
//!
//! Принцип — **parse, don't validate**: строки, пришедшие от непривилегированных процессов
//! (`citadel-cli` → демон → движок → обратно), превращаются в типизированные значения
//! ([`std::net::Ipv4Addr`], `u8`, …), и аргументы `ip`/`iptables` собираются **заново** из них.
//! Сырая строка до `Command` не доходит вообще — этим класс инъекций (перевод строки в
//! `resolv.conf`, лишние флаги `iptables`, `--`-разделители) закрывается конструктивно, а не
//! чёрным списком. Это усиление относительно `citadel-helper`, где строки проверялись предикатом
//! и передавались дальше как есть.
//!
//! Кроме формы проверяются **границы количества и охвата** — они защищают не от синтаксиса, а от
//! злоупотребления семантикой:
//!   * [`MAX_ROUTES`]/[`MAX_BYPASS`]/[`MAX_EXIT_IPS`] — чтобы клиент не заставил root крутить
//!     тысячи `ip route` (локальный DoS);
//!   * [`MIN_BYPASS_PREFIX`] — «в обход» нельзя запросить `/0` (или половинки `/1`): иначе
//!     скомпрометированный движок пробил бы дыру во ВЕСЬ kill-switch, а пользователь продолжал
//!     бы видеть «kill-switch армирован». Тихая деактивация защиты — худший вид отказа.

use std::net::Ipv4Addr;

use anyhow::{bail, Result};

use crate::proto::TunSetupReq;

/// Максимум маршрутов в туннель за один запрос.
pub const MAX_ROUTES: usize = 64;
/// Максимум назначений «в обход» (split-tunnel Exclude).
pub const MAX_BYPASS: usize = 64;
/// Максимум IP exit'ов (bypass-маршрут, анти-петля).
pub const MAX_EXIT_IPS: usize = 32;
/// Минимальная длина префикса для «в обход»: `/8` и уже. `/0`–`/7` покрывают слишком большую
/// часть адресного пространства, чтобы называться исключением, и де-факто гасят kill-switch.
pub const MIN_BYPASS_PREFIX: u8 = 8;
/// Допустимый диапазон MTU туннеля.
pub const MTU_MIN: u32 = 576;
pub const MTU_MAX: u32 = 9000;

/// IPv4-подсеть — типизированный маршрут. Рендерится обратно строкой только через [`Self::to_string`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V4Net {
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

impl V4Net {
    /// Разобрать `A.B.C.D/N` либо голый `A.B.C.D` (= `/32`). Никаких пробелов/мусора.
    pub fn parse(s: &str) -> Result<V4Net> {
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, p),
            None => (s, "32"),
        };
        let addr: Ipv4Addr = a.parse().map_err(|_| anyhow::anyhow!("не IPv4-адрес: {a:?}"))?;
        let prefix: u8 = p.parse().map_err(|_| anyhow::anyhow!("не префикс: {p:?}"))?;
        if prefix > 32 {
            bail!("префикс вне 0..=32: {prefix}");
        }
        Ok(V4Net { addr, prefix })
    }

    /// Полный туннель (`0.0.0.0/0`) — обрабатывается двумя половинками `/1`, чтобы не затирать
    /// физический default (нужен как nexthop для bypass и для восстановления связи).
    pub fn is_default(&self) -> bool {
        self.prefix == 0
    }
}

impl std::fmt::Display for V4Net {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// Провалидированный запрос конфигурации туннеля: только типизированные значения.
#[derive(Debug, Clone)]
pub struct TunSetup {
    pub addr: Ipv4Addr,
    pub prefix: u8,
    pub mtu: u32,
    pub routes: Vec<V4Net>,
    pub dns: Option<Ipv4Addr>,
    pub exit_ips: Vec<Ipv4Addr>,
    pub killswitch: bool,
    pub bypass: Vec<V4Net>,
}

impl TunSetup {
    /// Разобрать запрос движка. Любая аномалия — отказ целиком (fail-closed): частично
    /// применённая сетевая конфигурация опаснее, чем непринятая.
    pub fn parse(r: &TunSetupReq) -> Result<TunSetup> {
        let addr = Ipv4Addr::from(r.addr);
        if addr.is_unspecified() || addr.is_broadcast() || addr.is_multicast() || addr.is_loopback()
        {
            bail!("адрес туннеля недопустим: {addr}");
        }
        if r.prefix == 0 || r.prefix > 32 {
            bail!("префикс адреса туннеля вне 1..=32: {}", r.prefix);
        }
        let mtu: u32 = r.mtu.trim().parse().map_err(|_| anyhow::anyhow!("MTU не число: {:?}", r.mtu))?;
        if !(MTU_MIN..=MTU_MAX).contains(&mtu) {
            bail!("MTU вне {MTU_MIN}..={MTU_MAX}: {mtu}");
        }

        if r.routes.len() > MAX_ROUTES {
            bail!("слишком много маршрутов: {} > {MAX_ROUTES}", r.routes.len());
        }
        let routes = r.routes.iter().map(|s| V4Net::parse(s)).collect::<Result<Vec<_>>>()?;

        if r.bypass.len() > MAX_BYPASS {
            bail!("слишком много назначений «в обход»: {} > {MAX_BYPASS}", r.bypass.len());
        }
        let bypass = r.bypass.iter().map(|s| V4Net::parse(s)).collect::<Result<Vec<_>>>()?;
        // Ключевая проверка охвата: «в обход» не может быть шире /8 — иначе это не исключение,
        // а тихое отключение kill-switch при включённом индикаторе защиты.
        if let Some(bad) = bypass.iter().find(|n| n.prefix < MIN_BYPASS_PREFIX) {
            bail!(
                "«в обход» слишком широкий ({bad}): минимум /{MIN_BYPASS_PREFIX} — иначе это \
                 отключает kill-switch целиком"
            );
        }

        if r.exit_ips.len() > MAX_EXIT_IPS {
            bail!("слишком много exit-адресов: {} > {MAX_EXIT_IPS}", r.exit_ips.len());
        }
        // IPv6-адреса exit'ов молча пропускаем (туннель IPv4-only, bypass для них не строится) —
        // это не ошибка конфигурации, а ожидаемый dual-stack DNS-ответ.
        let mut exit_ips = Vec::new();
        for e in &r.exit_ips {
            match e.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(v4)) => exit_ips.push(v4),
                Ok(std::net::IpAddr::V6(_)) => {}
                Err(_) => bail!("exit-адрес не IP: {e:?}"),
            }
        }

        let dns = match &r.dns {
            Some(d) => Some(
                d.trim().parse::<Ipv4Addr>().map_err(|_| anyhow::anyhow!("DNS не IPv4: {d:?}"))?,
            ),
            None => None,
        };

        Ok(TunSetup {
            addr,
            prefix: r.prefix,
            mtu,
            routes,
            dns,
            exit_ips,
            killswitch: r.killswitch,
            bypass,
        })
    }

    /// Full-tunnel (`0.0.0.0/0` в маршрутах) — признак, по которому включается блок IPv6 (A2/S2.2).
    pub fn is_full_tunnel(&self) -> bool {
        self.routes.iter().any(|r| r.is_default())
    }

    /// Адрес туннеля как CIDR (`ip addr add`).
    pub fn cidr(&self) -> String {
        format!("{}/{}", self.addr, self.prefix)
    }
}

/// Разобрать список адресов из [`crate::proto::EngineMsg::AllowExits`]: IPv4 берём, IPv6
/// пропускаем (туннель v4-only), мусор — отказ целиком, длина ограничена [`MAX_EXIT_IPS`].
pub fn parse_allow_exits(list: &[String]) -> Result<Vec<Ipv4Addr>> {
    if list.len() > MAX_EXIT_IPS {
        bail!("слишком много адресов доступа: {} > {MAX_EXIT_IPS}", list.len());
    }
    let mut out = Vec::new();
    for s in list {
        match s.trim().parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(v4)) => {
                // Исключение «ко всему» через 0.0.0.0 или широковещалку не пропускаем: это
                // была бы дыра во весь kill-switch под видом «адреса exit'а».
                if v4.is_unspecified() || v4.is_broadcast() {
                    bail!("недопустимый адрес доступа: {v4}");
                }
                if !out.contains(&v4) {
                    out.push(v4);
                }
            }
            Ok(std::net::IpAddr::V6(_)) => {}
            Err(_) => bail!("адрес доступа не IP: {s:?}"),
        }
    }
    Ok(out)
}

/// L16: срезать управляющие последовательности из строки, которая пойдёт в терминал или в лог.
/// Недоверенные строки (метка профиля из чужой ссылки, текст ошибки от сервера) не должны уметь
/// перерисовывать экран, менять заголовок окна или прятать текст (ANSI/OSC-инъекция).
pub fn sanitize_text(s: &str, max: usize) -> String {
    s.chars()
        .filter(|c| {
            // печатаемые + пробел; C0/C1/DEL/ESC — вон
            !c.is_control() && !('\u{80}'..='\u{9f}').contains(c)
        })
        .take(max)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::TunSetupReq;

    fn base() -> TunSetupReq {
        TunSetupReq {
            addr: [10, 8, 0, 2],
            prefix: 24,
            mtu: "1280".into(),
            routes: vec!["0.0.0.0/0".into()],
            dns: Some("10.8.0.1".into()),
            exit_ips: vec!["203.0.113.9".into()],
            killswitch: true,
            bypass: vec![],
        }
    }

    #[test]
    fn valid_request_parses() {
        let t = TunSetup::parse(&base()).unwrap();
        assert_eq!(t.cidr(), "10.8.0.2/24");
        assert!(t.is_full_tunnel());
        assert_eq!(t.dns.unwrap(), Ipv4Addr::new(10, 8, 0, 1));
        assert_eq!(t.exit_ips, vec![Ipv4Addr::new(203, 0, 113, 9)]);
    }

    /// L2: инъекция через перевод строки/пробелы (классика `resolv.conf` и `iptables`) не проходит
    /// ни в одном поле — типизированный разбор её просто не принимает.
    #[test]
    fn injection_attempts_rejected() {
        let mut r = base();
        r.dns = Some("10.8.0.1\nnameserver 6.6.6.6".into());
        assert!(TunSetup::parse(&r).is_err());

        let mut r = base();
        r.routes = vec!["0.0.0.0/0 -j ACCEPT".into()];
        assert!(TunSetup::parse(&r).is_err());

        let mut r = base();
        r.exit_ips = vec!["203.0.113.9; rm -rf /".into()];
        assert!(TunSetup::parse(&r).is_err());

        let mut r = base();
        r.mtu = "1280; reboot".into();
        assert!(TunSetup::parse(&r).is_err());
    }

    /// Главная семантическая проверка: «в обход» шире /8 отвергается — иначе kill-switch
    /// выключается целиком, а UI продолжает показывать «защита включена».
    #[test]
    fn overbroad_bypass_rejected() {
        for wide in ["0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1", "10.0.0.0/7"] {
            let mut r = base();
            r.bypass = vec![wide.into()];
            assert!(
                TunSetup::parse(&r).is_err(),
                "«в обход» {wide} должен быть отвергнут (дыра во весь kill-switch)"
            );
        }
        let mut ok = base();
        ok.bypass = vec!["192.168.1.0/24".into(), "10.0.0.0/8".into()];
        assert!(TunSetup::parse(&ok).is_ok());
    }

    /// Границы количества: клиент не может заставить root выполнить произвольно много команд.
    #[test]
    fn count_limits_enforced() {
        let mut r = base();
        r.routes = (0..MAX_ROUTES + 1).map(|i| format!("10.{i}.0.0/16")).collect();
        assert!(TunSetup::parse(&r).is_err());

        let mut r = base();
        r.exit_ips = (0..MAX_EXIT_IPS + 1).map(|i| format!("203.0.113.{i}")).collect();
        assert!(TunSetup::parse(&r).is_err());
    }

    /// Дегенеративные адреса/MTU отсекаются (0.0.0.0, loopback, multicast, /0-префикс адреса).
    #[test]
    fn degenerate_values_rejected() {
        let mut r = base();
        r.addr = [0, 0, 0, 0];
        assert!(TunSetup::parse(&r).is_err());

        let mut r = base();
        r.addr = [127, 0, 0, 1];
        assert!(TunSetup::parse(&r).is_err());

        let mut r = base();
        r.prefix = 0;
        assert!(TunSetup::parse(&r).is_err());

        let mut r = base();
        r.mtu = "100".into();
        assert!(TunSetup::parse(&r).is_err());
        r.mtu = "65535".into();
        assert!(TunSetup::parse(&r).is_err());
    }

    /// IPv6-адрес exit'а — не ошибка (dual-stack DNS), просто не участвует в bypass.
    #[test]
    fn ipv6_exit_ip_skipped_not_error() {
        let mut r = base();
        r.exit_ips = vec!["2001:db8::1".into(), "203.0.113.9".into()];
        let t = TunSetup::parse(&r).unwrap();
        assert_eq!(t.exit_ips, vec![Ipv4Addr::new(203, 0, 113, 9)]);
    }

    /// Список доступа к exit'ам: IPv4 берутся, IPv6 игнорируются, дубликаты схлопываются,
    /// «адрес ко всему» и мусор отвергаются.
    #[test]
    fn allow_exits_parsing() {
        let ok = parse_allow_exits(&[
            "203.0.113.9".into(),
            "203.0.113.9".into(),
            "2001:db8::1".into(),
            "198.51.100.4".into(),
        ])
        .unwrap();
        assert_eq!(ok, vec![Ipv4Addr::new(203, 0, 113, 9), Ipv4Addr::new(198, 51, 100, 4)]);

        assert!(parse_allow_exits(&["0.0.0.0".into()]).is_err(), "дыра во весь kill-switch");
        assert!(parse_allow_exits(&["255.255.255.255".into()]).is_err());
        assert!(parse_allow_exits(&["exit.example".into()]).is_err(), "имя вместо адреса");
        let many: Vec<String> = (0..MAX_EXIT_IPS + 1).map(|i| format!("203.0.113.{i}")).collect();
        assert!(parse_allow_exits(&many).is_err());
    }

    /// L16: ANSI/OSC-инъекция из недоверенной строки вычищается до показа в терминале.
    #[test]
    fn sanitize_strips_escapes() {
        let evil = "профиль\u{1b}]0;взлом\u{7}\u{1b}[2J\u{1b}[Hхвост";
        let s = sanitize_text(evil, 64);
        assert!(!s.contains('\u{1b}'), "ESC должен быть срезан: {s:?}");
        assert!(!s.contains('\u{7}'), "BEL должен быть срезан");
        assert!(s.starts_with("профиль") && s.ends_with("хвост"));
        // длина ограничивается (в символах, не байтах — не рвём UTF-8)
        assert_eq!(sanitize_text("ааааа", 3), "ааа");
    }
}
