//! Привилегированное исполнение сетевой конфигурации (только root-демон).
//!
//! Разделение «посчитать» / «сделать»: планы правил приходят из [`citadel_vpnd::plan`] (чистые,
//! покрыты юнит-тестами), здесь — их исполнение и учёт применённого, чтобы корректно свернуть.
//!
//! Безопасность исполнения (L2):
//!   * внешние утилиты запускаются **по абсолютному пути**, найденному один раз на старте, с
//!     проверкой, что бинарь принадлежит root и не писабелен группой/миром — иначе подмена `ip`
//!     означала бы выполнение чужого кода под root'ом;
//!   * окружение процесса вычищается (`env_clear`) — ни `PATH`, ни `LD_*` не наследуются;
//!   * все аргументы собираются из типизированных значений ([`citadel_vpnd::valid`]).
//!
//! `/etc/resolv.conf` (L4): файл может быть симлинком на stub `systemd-resolved`. Перезапись «по
//! ссылке» испортила бы сам stub и после disconnect оставила бы систему без резолвера, поэтому
//! симлинк снимается и восстанавливается как симлинк, а обычный файл — сохраняется побайтно.

use std::io::Write;
use std::net::Ipv4Addr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use citadel_tun::Tun;

use citadel_vpnd::plan::{self, PathKind};
use citadel_vpnd::valid::{TunSetup, V4Net};
use citadel_vpnd::TUN_NAME;

const RESOLV: &str = "/etc/resolv.conf";
const RESOLV_BAK: &str = "/run/citadel-vpn/resolv.bak";

/// Абсолютные пути к сетевым утилитам, проверенные на старте демона.
pub struct Tools {
    pub ip: PathBuf,
    pub iptables: PathBuf,
    pub ip6tables: PathBuf,
}

impl Tools {
    /// Найти утилиты в фиксированном списке системных каталогов (НЕ через `PATH`).
    pub fn discover() -> Result<Tools> {
        Ok(Tools {
            ip: find_tool("ip")?,
            iptables: find_tool("iptables")?,
            ip6tables: find_tool("ip6tables")?,
        })
    }
}

/// Поиск утилиты по фиксированным каталогам + проверка владельца и прав.
fn find_tool(name: &str) -> Result<PathBuf> {
    const DIRS: [&str; 4] = ["/usr/sbin", "/sbin", "/usr/bin", "/bin"];
    for d in DIRS {
        let p = Path::new(d).join(name);
        let Ok(md) = std::fs::metadata(&p) else { continue };
        if !md.is_file() {
            continue;
        }
        // Бинарь, который root запускает по чужой просьбе, обязан быть неизменяемым для не-root.
        if md.uid() != 0 {
            bail!("{} принадлежит uid {} (не root) — отказываюсь исполнять", p.display(), md.uid());
        }
        if md.mode() & 0o022 != 0 {
            bail!("{} писабелен группой/миром (mode {:o}) — отказываюсь исполнять", p.display(), md.mode() & 0o7777);
        }
        return Ok(p);
    }
    bail!("не найдена утилита {name} (нужны пакеты iproute2 и iptables)")
}

/// Запустить утилиту без окружения. stderr глушится: почти все вызовы идемпотентны
/// (удаление несуществующего маршрута/цепочки — норма), диагностика — по коду возврата.
fn run(tool: &Path, args: &[String]) -> bool {
    Command::new(tool)
        .args(args)
        .env_clear()
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    }

fn run_str(tool: &Path, args: &[&str]) -> bool {
    let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    run(tool, &owned)
}

/// Запустить утилиту и вернуть stdout (для `ip route get`).
fn output(tool: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new(tool).args(args).env_clear().stderr(Stdio::null()).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Что именно применено к системе — чтобы свернуть ровно это и ничего лишнего.
#[derive(Default)]
pub struct NetState {
    /// Добавленные bypass-маршруты (только те, что мы реально создавали).
    bypass_routes: Vec<String>,
    /// F6-правила DNS активны для интерфейса.
    dns_ifn: Option<String>,
    /// Резервная копия резолвера.
    resolv_backup: Option<ResolvBackup>,
    /// Применённый набор правил kill-switch (сравнивается на реконнекте, чтобы НЕ пересоздавать
    /// цепочку без нужды — иначе на каждом реконнекте открывается микро-окно без защиты).
    ks_applied: Option<Vec<Vec<String>>>,
    /// Блок IPv6 активен.
    ipv6_blocked: bool,
    /// Адреса, к которым движку разрешён доступ помимо exit'а из `TunSetup` (issuer, резервные
    /// exit'ы). Живут всю сессию: иначе на реконнекте пересобранная цепочка снова отрезала бы
    /// issuer'а и добыча Layer-1 токена вставала бы.
    allowed_extra: Vec<Ipv4Addr>,
}

/// Исходное состояние `/etc/resolv.conf`.
enum ResolvBackup {
    /// Был симлинком (типично для systemd-resolved) — вернём симлинк на ту же цель.
    Symlink(PathBuf),
    /// Был обычным файлом — содержимое сохранено в [`RESOLV_BAK`].
    File,
    /// Файла не было вовсе.
    Missing,
}

impl NetState {
    /// Применить конфигурацию туннеля: создать TUN, поднять адрес/маршруты/DNS и (при запросе)
    /// армировать kill-switch. Возвращает созданный TUN — его fd уходит движку по SCM_RIGHTS.
    ///
    /// Порядок важен: bypass-маршруты к exit'ам ставятся **до** подмены таблицы туннелем (иначе
    /// `ip route get` вернёт уже citadel0 и мы «зациклим» собственный трафик к exit'у).
    pub fn apply(&mut self, t: &Tools, s: &TunSetup, engine_uid: Option<u32>) -> Result<Tun> {
        // Осиротевший интерфейс прошлой сессии занял бы имя (TUNSETIFF → EBUSY).
        run_str(&t.ip, &["link", "delete", TUN_NAME]);
        let tun = Tun::create(TUN_NAME).context("создать TUN (нужен root/CAP_NET_ADMIN)")?;
        let ifn = tun.name().to_string();

        run_str(&t.ip, &["link", "set", &ifn, "mtu", &s.mtu.to_string(), "up"]);
        run_str(&t.ip, &["addr", "add", &s.cidr(), "dev", &ifn]);

        // 1. bypass: exit'ы (анти-петля) + назначения «в обход» (C8.3) — ДО маршрутов туннеля.
        if !s.exit_ips.is_empty() || !s.bypass.is_empty() {
            match self.default_gateway(t) {
                Some((gw, dev)) => {
                    for eip in &s.exit_ips {
                        self.add_bypass(t, &V4Net { addr: *eip, prefix: 32 }, &gw, &dev);
                    }
                    for b in &s.bypass {
                        self.add_bypass(t, b, &gw, &dev);
                    }
                }
                None => eprintln!(
                    "[vpnd] WARN: нет default-route — bypass не добавлен (риск петли к exit'у)"
                ),
            }
        }

        // 2. маршруты туннеля (+ host-route на DNS)
        for cmd in plan::tunnel_route_cmds(s, &ifn) {
            run(&t.ip, &cmd);
        }

        // 3. DNS fail-closed (F6)
        if let Some(dns) = s.dns {
            self.setup_dns(t, &ifn, dns)?;
        }

        // 4. kill-switch (идемпотентно: одинаковый набор правил не переустанавливаем)
        if s.killswitch {
            self.ensure_killswitch(t, &ifn, &s.exit_ips, &s.bypass, engine_uid);
        }

        // 5. S2.2/A2: IPv6 fail-closed при full-tunnel или kill-switch (туннель IPv4-only)
        if s.killswitch || s.is_full_tunnel() {
            self.ensure_ipv6_block(t);
        }

        Ok(tun)
    }

    /// Открыть доступ к адресам exit'а/issuer'а ДО подъёма туннеля.
    ///
    /// Без этого армированный kill-switch (оставшийся после аварийного разрыва — намеренно)
    /// блокировал бы сам движок: `establish` не проходит, `TunSetup` не приходит, защиту снять
    /// некому — сессия не поднимается никогда. Правило вставляется в начало цепочки (все RETURN
    /// равноправны, важно лишь, что финальный DROP последний).
    pub fn allow_exits(&mut self, t: &Tools, ips: &[Ipv4Addr], engine_uid: Option<u32>) {
        let mut added = false;
        for ip in ips {
            if !self.allowed_extra.contains(ip) {
                self.allowed_extra.push(*ip);
                added = true;
            }
        }
        if !added || !self.killswitch_armed(t) {
            return;
        }
        for ip in ips {
            let dst = format!("{ip}/32");
            let ok = match engine_uid {
                Some(uid) => run_str(
                    &t.iptables,
                    &["-I", plan::KS_CHAIN, "1", "-d", &dst, "-m", "owner", "--uid-owner",
                      &uid.to_string(), "-j", "RETURN"],
                ),
                None => run_str(&t.iptables, &["-I", plan::KS_CHAIN, "1", "-d", &dst, "-j", "RETURN"]),
            };
            if !ok {
                run_str(&t.iptables, &["-I", plan::KS_CHAIN, "1", "-d", &dst, "-j", "RETURN"]);
            }
        }
        // Цепочка изменена мимо `ensure_killswitch` — сбрасываем «применённое», чтобы следующий
        // TunSetup честно пересобрал её целиком (уже с учётом allowed_extra).
        self.ks_applied = None;
        eprintln!("[vpnd] kill-switch: открыт доступ к {} адрес(ам) exit/issuer", ips.len());
    }

    /// Текущий физический default-маршрут (нужен как fallback-nexthop для bypass).
    fn default_gateway(&self, t: &Tools) -> Option<(String, String)> {
        let out = output(&t.ip, &["route", "show", "default"])?;
        plan::parse_default_route(out.lines().next()?)
    }

    /// Bypass-маршрут для назначения мимо туннеля, с сохранением фактического nexthop.
    /// On-link назначения (локальная подсеть) НЕ трогаем: connected-route уже держит их мимо
    /// туннеля, а `replace via gw` сломал бы доставку по L2 (ловили вживую на Linux/Android).
    fn add_bypass(&mut self, t: &Tools, dst: &V4Net, fallback_gw: &str, fallback_dev: &str) {
        let probe = dst.addr.to_string();
        let path = output(&t.ip, &["route", "get", &probe])
            .and_then(|o| o.lines().next().map(|l| l.to_string()))
            .and_then(|l| plan::parse_route_get(&l));
        let dst_s = dst.to_string();
        match path {
            Some(PathKind::Onlink { dev }) => {
                eprintln!("[vpnd] bypass {dst_s}: on-link (dev {dev}) — маршрут не нужен");
            }
            Some(PathKind::Via { nh, dev }) => {
                run_str(&t.ip, &["route", "replace", &dst_s, "via", &nh, "dev", &dev]);
                self.bypass_routes.push(dst_s);
            }
            None => {
                run_str(&t.ip, &["route", "replace", &dst_s, "via", fallback_gw, "dev", fallback_dev]);
                self.bypass_routes.push(dst_s);
            }
        }
    }

    /// F6: резолвер только через туннель + DROP на прочий `:53`.
    fn setup_dns(&mut self, t: &Tools, ifn: &str, dns: Ipv4Addr) -> Result<()> {
        if self.resolv_backup.is_none() {
            self.resolv_backup = Some(backup_resolv()?);
        }
        write_resolv(dns)?;
        for cmd in plan::dns_rules(ifn) {
            run(&t.iptables, &cmd);
        }
        self.dns_ifn = Some(ifn.to_string());
        Ok(())
    }

    /// Армировать kill-switch, если требуемый набор правил отличается от применённого.
    /// Совпадает — не трогаем: пересоздание цепочки на каждом реконнекте открывало бы окно,
    /// в котором fail-closed защиты нет.
    fn ensure_killswitch(
        &mut self,
        t: &Tools,
        ifn: &str,
        exit_ips: &[Ipv4Addr],
        bypass: &[V4Net],
        engine_uid: Option<u32>,
    ) {
        // Объединяем адреса из TunSetup с ранее разрешёнными (issuer/резервные exit'ы): иначе
        // пересборка цепочки на реконнекте снова отрезала бы issuer'а от движка.
        let mut all: Vec<Ipv4Addr> = exit_ips.to_vec();
        for ip in &self.allowed_extra {
            if !all.contains(ip) {
                all.push(*ip);
            }
        }
        let desired = plan::killswitch_rules(ifn, &all, bypass, engine_uid);
        if self.ks_applied.as_ref() == Some(&desired) && chain_exists(t, &t.iptables, plan::KS_CHAIN)
        {
            return;
        }
        for cmd in plan::killswitch_teardown() {
            run(&t.iptables, &cmd);
        }
        let mut applied = Vec::new();
        for cmd in &desired {
            if !run(&t.iptables, cmd) && cmd.contains(&"owner".to_string()) {
                // В ядре нет xt_owner — правило с привязкой к uid не встало. Фолбэк на правило
                // без owner-match: иначе к exit'у не пробьётся сам движок и туннель не поднимется.
                let fallback: Vec<String> =
                    cmd.iter().filter(|a| !["-m", "owner", "--uid-owner"].contains(&a.as_str())).cloned().collect();
                // убрать оставшийся аргумент uid (шёл следом за --uid-owner)
                let fallback: Vec<String> =
                    fallback.into_iter().filter(|a| a.parse::<u32>().is_err()).collect();
                eprintln!("[vpnd] WARN: нет модуля xt_owner — правило exit'а без привязки к uid");
                run(&t.iptables, &fallback);
                applied.push(fallback);
                continue;
            }
            applied.push(cmd.clone());
        }
        self.ks_applied = Some(applied);
        eprintln!("[vpnd] kill-switch армирован (fail-closed)");
    }

    /// Блок исходящего IPv6 (S2.2/A2).
    fn ensure_ipv6_block(&mut self, t: &Tools) {
        if self.ipv6_blocked && chain_exists(t, &t.ip6tables, plan::KS6_CHAIN) {
            return;
        }
        for cmd in plan::ipv6_block_teardown() {
            run(&t.ip6tables, &cmd);
        }
        for cmd in plan::ipv6_block_rules() {
            run(&t.ip6tables, &cmd);
        }
        self.ipv6_blocked = true;
        eprintln!("[vpnd] IPv6 заблокирован (fail-closed): туннель IPv4-only");
    }

    /// Свернуть сетевую конфигурацию сессии.
    ///
    /// `clean` — пользователь сам попросил отключиться: снимаем всё, включая fail-closed правила.
    /// `!clean` (движок упал/канал оборвался) — маршруты и DNS сворачиваем, но **kill-switch и
    /// блок IPv6 оставляем**: трафик обязан оставаться заблокированным, пока человек не решит
    /// иначе. Ровно та же семантика, что у `citadel-helper` (байт `'Q'` = чистый разрыв).
    pub fn teardown(&mut self, t: &Tools, clean: bool) {
        if let Some(ifn) = self.dns_ifn.take() {
            for cmd in plan::dns_rules_teardown(&ifn) {
                run(&t.iptables, &cmd);
            }
        }
        if let Some(b) = self.resolv_backup.take() {
            if let Err(e) = restore_resolv(b) {
                eprintln!("[vpnd] WARN: не удалось восстановить {RESOLV}: {e:#}");
            }
        }
        for dst in std::mem::take(&mut self.bypass_routes) {
            run_str(&t.ip, &["route", "del", &dst]);
        }
        // TUN исчезает сам, когда движок закрывает свой (последний) fd; страхуемся от осиротевшего.
        run_str(&t.ip, &["link", "delete", TUN_NAME]);

        if clean {
            self.disarm(t);
        } else if self.ks_applied.is_some() || self.ipv6_blocked {
            eprintln!(
                "[vpnd] АВАРИЙНЫЙ разрыв — kill-switch/IPv6-блок ОСТАВЛЕНЫ (fail-closed). \
                 Снять: citadel-cli killswitch --disarm"
            );
        }
    }

    /// Режим «блокировки до туннеля» (L10, opt-in `citadel-lockdown.service`): армировать
    /// fail-closed ДО поднятия сети, без единого исключения для exit'ов — их точечно откроет
    /// движок сообщением `AllowExits`, когда пользователь начнёт подключение.
    ///
    /// Плата за это — резолвер тоже закрыт: ссылка с ИМЕНЕМ exit'а в таком режиме не поднимется
    /// (резолвить негде), нужен адрес. Компромисс осознанный: смысл режима именно в том, что до
    /// туннеля наружу не уходит ни одного пакета, включая DNS-запрос с именем вашего VPN-сервера.
    pub fn arm_lockdown(&mut self, t: &Tools) {
        self.ensure_killswitch(t, TUN_NAME, &[], &[], None);
        self.ensure_ipv6_block(t);
    }

    /// Снять fail-closed правила (чистый disconnect, команда `--disarm`, остановка юнита).
    pub fn disarm(&mut self, t: &Tools) {
        for cmd in plan::killswitch_teardown() {
            run(&t.iptables, &cmd);
        }
        for cmd in plan::ipv6_block_teardown() {
            run(&t.ip6tables, &cmd);
        }
        self.ks_applied = None;
        self.ipv6_blocked = false;
        self.allowed_extra.clear();
    }

    /// Армирован ли kill-switch прямо сейчас (в т.ч. осиротевший от прошлого запуска, L11).
    pub fn killswitch_armed(&self, t: &Tools) -> bool {
        chain_exists(t, &t.iptables, plan::KS_CHAIN)
    }
}

/// Существует ли цепочка (проверка «по факту», а не по нашей памяти: цепочка могла остаться от
/// прошлого запуска демона или от GUI-клиента, который использует те же имена).
fn chain_exists(_t: &Tools, tool: &Path, chain: &str) -> bool {
    Command::new(tool)
        .args(["-n", "-L", chain])
        .env_clear()
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Сохранить исходный резолвер (симлинк/файл/отсутствие) — см. L4.
fn backup_resolv() -> Result<ResolvBackup> {
    match std::fs::symlink_metadata(RESOLV) {
        Err(_) => Ok(ResolvBackup::Missing),
        Ok(md) if md.file_type().is_symlink() => {
            let target = std::fs::read_link(RESOLV).context("прочитать симлинк resolv.conf")?;
            Ok(ResolvBackup::Symlink(target))
        }
        Ok(_) => {
            let content = std::fs::read(RESOLV).context("прочитать resolv.conf")?;
            write_private(Path::new(RESOLV_BAK), &content)?;
            Ok(ResolvBackup::File)
        }
    }
}

/// Записать наш резолвер (обычным файлом, сняв симлинк, чтобы не портить цель).
fn write_resolv(dns: Ipv4Addr) -> Result<()> {
    let _ = std::fs::remove_file(RESOLV);
    let body = format!("# CitadelPQVPN: резолвер туннеля (оригинал восстановится при disconnect)\nnameserver {dns}\noptions edns0\n");
    std::fs::write(RESOLV, body).with_context(|| format!("записать {RESOLV}"))?;
    Ok(())
}

/// Вернуть резолвер в исходное состояние.
fn restore_resolv(b: ResolvBackup) -> Result<()> {
    let _ = std::fs::remove_file(RESOLV);
    match b {
        ResolvBackup::Symlink(target) => {
            std::os::unix::fs::symlink(&target, RESOLV)
                .with_context(|| format!("восстановить симлинк {RESOLV} → {}", target.display()))?;
        }
        ResolvBackup::File => {
            let content = std::fs::read(RESOLV_BAK).context("прочитать резервную копию resolv.conf")?;
            std::fs::write(RESOLV, content).context("восстановить resolv.conf")?;
            let _ = std::fs::remove_file(RESOLV_BAK);
        }
        ResolvBackup::Missing => {}
    }
    Ok(())
}

/// Запись файла с правами 0600 (резервные копии в /run не должны быть читаемы всем).
fn write_private(path: &Path, content: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).ok();
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("создать {}", path.display()))?;
    f.write_all(content)?;
    Ok(())
}
