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
//! новый резолвер кладётся рядом и **переименовывается поверх** (rename заменяет саму ссылку,
//! атомарно и без окна «резолвера нет»), а исходное состояние — симлинк/файл/отсутствие —
//! запоминается и возвращается при disconnect.
//!
//! Записать `/etc/resolv.conf` можно НЕ всегда: read-only `/etc` (контейнер, immutable-дистрибутив,
//! сам юнит с `ProtectSystem=full` без `ReadWritePaths=/etc`), файл под bind-mount'ом или с
//! иммутабельным атрибутом. Раньше это валило всю сессию («записать /etc/resolv.conf: Read-only
//! file system»), хотя туннель уже стоял. Теперь способ настройки резолвера выбирается лестницей
//! [`choose_dns`]: файл → systemd-resolved → resolvconf → принудительный заворот `:53` в туннель.
//! Fail-closed при этом не ослабляется: F6-правила висят при любом способе, а если не сработал ни
//! один — сессия по-прежнему отвергается, потому что иначе DNS ушёл бы мимо туннеля.

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
/// Временный файл рядом с `resolv.conf`: пишем в него и переименовываем поверх (см. модульный
/// комментарий). Тот же каталог обязателен — `rename` не работает между файловыми системами.
const RESOLV_TMP: &str = "/etc/.citadel-resolv.tmp";

/// Абсолютные пути к сетевым утилитам, проверенные на старте демона.
pub struct Tools {
    pub ip: PathBuf,
    pub iptables: PathBuf,
    pub ip6tables: PathBuf,
    /// `resolvectl` (systemd-resolved) — есть не везде, поэтому опционально.
    pub resolvectl: Option<PathBuf>,
    /// `resolvconf` (openresolv/resolvconf) — тоже опционально.
    pub resolvconf: Option<PathBuf>,
}

impl Tools {
    /// Найти утилиты в фиксированном списке системных каталогов (НЕ через `PATH`).
    pub fn discover() -> Result<Tools> {
        Ok(Tools {
            ip: find_tool("ip")?,
            iptables: find_tool("iptables")?,
            ip6tables: find_tool("ip6tables")?,
            resolvectl: find_tool_opt("resolvectl"),
            resolvconf: find_tool_opt("resolvconf"),
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

/// Как [`find_tool`], но для необязательной утилиты: её отсутствие — не ошибка, просто этот
/// способ настройки резолвера недоступен. Подозрительные права — тоже `None`: под root'ом мы
/// такую утилиту не запустим, но и падать из-за неё не станем.
fn find_tool_opt(name: &str) -> Option<PathBuf> {
    match find_tool(name) {
        Ok(p) => Some(p),
        Err(e) => {
            // «не найдена» — обычное дело, а вот кривые права стоит показать.
            if !e.to_string().starts_with("не найдена") {
                eprintln!("[vpnd] {name} не будет использован: {e}");
            }
            None
        }
    }
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

/// Запустить утилиту, подав текст на stdin (`resolvconf -a` читает запись именно оттуда).
fn run_stdin(tool: &Path, args: &[&str], input: &str) -> bool {
    use std::io::Write as _;
    let Ok(mut child) = Command::new(tool)
        .args(args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    if let Some(mut sin) = child.stdin.take() {
        let _ = sin.write_all(input.as_bytes());
    } // drop → EOF, иначе утилита ждёт ввод вечно
    child.wait().map(|s| s.success()).unwrap_or(false)
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
    /// Каким способом настроен резолвер этой сессии (и что для этого сохранено). Выбирается
    /// один раз: свернуть надо ровно то, что применяли.
    dns: Option<DnsMethod>,
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

/// Чем именно настроен резолвер туннеля. Порядок вариантов = порядок попыток в [`choose_dns`].
enum DnsMethod {
    /// Переписан `/etc/resolv.conf`; исходное состояние — внутри.
    ResolvFile(ResolvBackup),
    /// systemd-resolved: сервер назначен на сам интерфейс (`resolvectl`), файл не тронут.
    Resolved,
    /// openresolv/resolvconf: запись зарегистрирована под именем интерфейса.
    Resolvconf,
    /// Резолвер системы не трогали вовсе — весь `:53` заворачивается NAT'ом в туннель.
    Redirect,
}

impl DnsMethod {
    /// Полагается ли способ на локальный stub-резолвер (⇒ `:53` на `lo` нельзя дропать).
    fn needs_loopback(&self) -> bool {
        matches!(self, DnsMethod::Resolved | DnsMethod::Redirect)
    }

    fn label(&self) -> &'static str {
        match self {
            DnsMethod::ResolvFile(_) => "/etc/resolv.conf",
            DnsMethod::Resolved => "systemd-resolved (resolvectl)",
            DnsMethod::Resolvconf => "resolvconf",
            DnsMethod::Redirect => "заворот :53 в туннель (NAT)",
        }
    }
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
    ///
    /// Зовётся на КАЖДЫЙ `TunSetup`, то есть и на реконнекте. Способ настройки выбирается один
    /// раз (иначе повторный бэкап затёр бы оригинал нашим же файлом), но переприменяется: TUN
    /// после реконнекта — новый интерфейс, настройки резолвера на старом умерли вместе с ним.
    fn setup_dns(&mut self, t: &Tools, ifn: &str, dns: Ipv4Addr) -> Result<()> {
        let method = match self.dns.take() {
            Some(m) => {
                reapply_dns(t, &m, ifn, dns);
                m
            }
            None => {
                let m = choose_dns(t, ifn, dns)?;
                eprintln!("[vpnd] DNS туннеля {dns}: {}", m.label());
                m
            }
        };
        // Сначала снять прошлые F6-правила, потом поставить: `-A` без этого копил бы по копии
        // DROP на каждый реконнект, а свернуть удалось бы только одну — и после disconnect
        // резолвер остался бы заблокирован намертво.
        for cmd in plan::dns_rules_teardown(ifn) {
            run(&t.iptables, &cmd);
        }
        for cmd in plan::dns_rules(ifn, method.needs_loopback()) {
            run(&t.iptables, &cmd);
        }
        self.dns_ifn = Some(ifn.to_string());
        self.dns = Some(method);
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
        let ifn = self.dns_ifn.take();
        if let Some(ifn) = &ifn {
            for cmd in plan::dns_rules_teardown(ifn) {
                run(&t.iptables, &cmd);
            }
        }
        if let Some(m) = self.dns.take() {
            teardown_dns(t, m, ifn.as_deref());
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
    ///
    /// Снимается и всё, что относится к DNS: если демона убили в обход штатной свёртки (SIGKILL,
    /// падение машины), в системе остаются `DROP` на `:53` мимо мёртвого интерфейса и — при
    /// запасном способе — цепочка заворота `:53` в исчезнувший туннель. Утечки в этом нет, но
    /// DNS не работает, и человек с «интернет есть, имена не резолвятся» должен уметь починить
    /// это ОДНОЙ понятной командой (`citadel-cli killswitch --disarm`), а не гадать. Тот же
    /// урок, что с залипшим kill-switch (L11).
    pub fn disarm(&mut self, t: &Tools) {
        for cmd in plan::killswitch_teardown() {
            run(&t.iptables, &cmd);
        }
        for cmd in plan::ipv6_block_teardown() {
            run(&t.ip6tables, &cmd);
        }
        // Интерфейс демона всегда один и тот же (TUN_NAME) — осиротевшие правила адресуемы даже
        // без памяти о прошлой сессии.
        for cmd in plan::dns_rules_teardown(TUN_NAME) {
            run(&t.iptables, &cmd);
        }
        for cmd in plan::dns_redirect_teardown() {
            run(&t.iptables, &cmd);
        }
        self.ks_applied = None;
        self.ipv6_blocked = false;
        self.allowed_extra.clear();
    }

    /// Остались ли от прошлого запуска правила DNS (без активной сессии это значит «имена не
    /// резолвятся»). Проверяется по факту, а не по нашей памяти — демон мог быть убит.
    pub fn dns_rules_orphaned(&self, t: &Tools) -> bool {
        chain_exists(t, &t.iptables, plan::DNS_NAT_CHAIN)
            || output(&t.iptables, &["-S", "OUTPUT"])
                .map(|s| s.lines().any(|l| l.contains("dport 53") && l.contains(TUN_NAME)))
                .unwrap_or(false)
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

// ───────────────────────────── резолвер (F6) ─────────────────────────────

/// Выбрать и применить способ настройки резолвера. Порядок — от «как было принято» к самому
/// жёсткому; следующий включается, только если предыдущий физически невозможен на этой машине.
///
/// Обещание одинаково для всех способов: имена резолвятся сервером туннеля, а весь прочий `:53`
/// заблокирован (F6, ставится вызывающим). Разница только в том, ЧЕМ мы этого добиваемся.
fn choose_dns(t: &Tools, ifn: &str, dns: Ipv4Addr) -> Result<DnsMethod> {
    // 1. /etc/resolv.conf — обычный путь; ничего лишнего в системе не остаётся.
    match backup_and_write_resolv(dns) {
        Ok(b) => return Ok(DnsMethod::ResolvFile(b)),
        Err(e) => eprintln!("[vpnd] {RESOLV} записать не удалось ({e:#}) — ищу другой способ"),
    }
    // 2. systemd-resolved: сервер вешается на интерфейс, файл не нужен вовсе.
    if resolved_is_system_resolver(t) && apply_resolved(t, ifn, dns) {
        return Ok(DnsMethod::Resolved);
    }
    // 3. resolvconf: он сам решит, куда писать (часто это /run, а не /etc).
    if apply_resolvconf(t, ifn, dns) {
        return Ok(DnsMethod::Resolvconf);
    }
    // 4. Резолвер системы не трогаем — заворачиваем весь :53 в туннель принудительно.
    if apply_redirect(t, dns) {
        eprintln!(
            "[vpnd] резолвер системы настроить нечем — весь :53 принудительно заворачивается \
             в туннель ({dns}); файл {RESOLV} остался как был"
        );
        return Ok(DnsMethod::Redirect);
    }
    bail!(
        "не удалось настроить DNS туннеля ни одним способом: {RESOLV} недоступен для записи, \
         systemd-resolved и resolvconf недоступны, заворот :53 через iptables nat не встал. \
         Сессия отклонена, иначе DNS-запросы ушли бы мимо туннеля"
    )
}

/// Переприменить уже выбранный способ (реконнект: интерфейс пересоздан, правила могли протухнуть).
fn reapply_dns(t: &Tools, m: &DnsMethod, ifn: &str, dns: Ipv4Addr) {
    let ok = match m {
        // бэкап уже снят — здесь только перезапись (файл мог переписать NetworkManager/DHCP)
        DnsMethod::ResolvFile(_) => write_resolv(dns).is_ok(),
        DnsMethod::Resolved => apply_resolved(t, ifn, dns),
        DnsMethod::Resolvconf => apply_resolvconf(t, ifn, dns),
        DnsMethod::Redirect => apply_redirect(t, dns),
    };
    if !ok {
        eprintln!("[vpnd] WARN: резолвер ({}) не переприменился на реконнекте", m.label());
    }
}

/// Свернуть настройку резолвера: вернуть систему ровно в то состояние, из которого взяли.
fn teardown_dns(t: &Tools, m: DnsMethod, ifn: Option<&str>) {
    match m {
        DnsMethod::ResolvFile(b) => {
            if let Err(e) = restore_resolv(b) {
                eprintln!("[vpnd] WARN: не удалось восстановить {RESOLV}: {e:#}");
            }
        }
        DnsMethod::Resolved => {
            if let (Some(rc), Some(ifn)) = (&t.resolvectl, ifn) {
                run_str(rc, &["revert", ifn]);
            }
        }
        DnsMethod::Resolvconf => {
            if let (Some(rcf), Some(ifn)) = (&t.resolvconf, ifn) {
                run_str(rcf, &["-d", &resolvconf_iface(ifn)]);
            }
        }
        DnsMethod::Redirect => {
            for cmd in plan::dns_redirect_teardown() {
                run(&t.iptables, &cmd);
            }
        }
    }
}

/// Является ли systemd-resolved резолвером системы. Проверка обязательна: `resolvectl dns`
/// отработает «успешно» и на машине, где resolved стоит, но `resolv.conf` смотрит мимо него —
/// и мы бы решили, что DNS настроен, оставив пользователя без резолвинга.
fn resolved_is_system_resolver(t: &Tools) -> bool {
    let Some(rc) = &t.resolvectl else { return false };
    if !run_str(rc, &["status"]) {
        return false; // сервис не отвечает по D-Bus — он не резолвер
    }
    if let Ok(target) = std::fs::read_link(RESOLV) {
        if target.to_string_lossy().contains("systemd/resolve") {
            return true;
        }
    }
    // stub-адреса systemd-resolved; читаем «по ссылке» — нас интересует итоговое содержимое
    std::fs::read_to_string(RESOLV)
        .map(|s| s.contains("127.0.0.53") || s.contains("127.0.0.54"))
        .unwrap_or(false)
}

/// systemd-resolved: назначить сервер туннеля на интерфейс и сделать его маршрутом для ВСЕХ имён
/// (`~.` — routing-домен «всё»). Параллельные апстримы физических линков этим не отменяются, но
/// им закрыт выход F6-правилами, так что ответить может только туннель.
fn apply_resolved(t: &Tools, ifn: &str, dns: Ipv4Addr) -> bool {
    let Some(rc) = &t.resolvectl else { return false };
    let ip = dns.to_string();
    if !run_str(rc, &["dns", ifn, &ip]) || !run_str(rc, &["domain", ifn, "~."]) {
        return false;
    }
    // Дальше — best effort: не поддерживается на старых версиях, но и не критично.
    run_str(rc, &["default-route", ifn, "yes"]);
    run_str(rc, &["llmnr", ifn, "no"]);
    run_str(rc, &["mdns", ifn, "no"]);
    true
}

/// Имя записи для resolvconf: `<интерфейс>.<программа>` — так удаление снимает ровно нашу.
fn resolvconf_iface(ifn: &str) -> String {
    format!("{ifn}.citadel")
}

fn apply_resolvconf(t: &Tools, ifn: &str, dns: Ipv4Addr) -> bool {
    let Some(rcf) = &t.resolvconf else { return false };
    let body = format!("# CitadelPQVPN\nnameserver {dns}\noptions edns0\n");
    run_stdin(rcf, &["-a", &resolvconf_iface(ifn)], &body)
}

/// Заворот всего `:53` в резолвер туннеля (таблица nat). Перед установкой снимаем прошлое —
/// иначе `-N` упадёт на существующей цепочке, а хуки в OUTPUT задвоятся.
fn apply_redirect(t: &Tools, dns: Ipv4Addr) -> bool {
    for cmd in plan::dns_redirect_teardown() {
        run(&t.iptables, &cmd);
    }
    let mut ok = true;
    for cmd in plan::dns_redirect_rules(dns) {
        ok &= run(&t.iptables, &cmd);
    }
    if !ok {
        // Полумера хуже отсутствия: часть правил без DNAT — это просто дыра в F6.
        for cmd in plan::dns_redirect_teardown() {
            run(&t.iptables, &cmd);
        }
    }
    ok
}

/// Снять бэкап и записать наш резолвер. При неудаче записи бэкап удаляется: `resolv.conf` не
/// тронут, восстанавливать нечего, а лишний файл в `/run` только запутал бы следующий disconnect.
fn backup_and_write_resolv(dns: Ipv4Addr) -> Result<ResolvBackup> {
    let b = backup_resolv()?;
    match write_resolv(dns) {
        Ok(()) => Ok(b),
        Err(e) => {
            let _ = std::fs::remove_file(RESOLV_BAK);
            Err(e)
        }
    }
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
            // Резервная копия в /run — только для root (в ней виден резолвер пользователя).
            write_mode(Path::new(RESOLV_BAK), &content, 0o600)?;
            Ok(ResolvBackup::File)
        }
    }
}

/// Записать наш резолвер обычным файлом поверх текущего (в т.ч. поверх симлинка — заменяется
/// сама ссылка, её цель не портится).
fn write_resolv(dns: Ipv4Addr) -> Result<()> {
    let body = format!("# CitadelPQVPN: резолвер туннеля (оригинал восстановится при disconnect)\nnameserver {dns}\noptions edns0\n");
    install_resolv(body.as_bytes())
}

/// Положить содержимое в `/etc/resolv.conf`.
///
/// Основной способ — временный файл рядом + `rename`: атомарно (никто не увидит машину без
/// резолвера), заменяет и симлинк целиком, не портя его цель. Почему не `remove` + `write`, как
/// было: между ними резолвера нет вовсе, а если запись не удастся — система останется без файла.
///
/// Запасной способ — запись «на месте», нужна там, где `rename` невозможен: в контейнерах
/// `/etc/resolv.conf` подмонтирован bind-mount'ом, и переименование поверх точки монтирования
/// даёт `EBUSY`, тогда как запись в сам файл проходит. Применяется ТОЛЬКО к обычному файлу:
/// писать «по ссылке» нельзя — испортили бы stub systemd-resolved (L4).
fn install_resolv(content: &[u8]) -> Result<()> {
    let tmp = Path::new(RESOLV_TMP);
    let _ = std::fs::remove_file(tmp);
    // 0644 задаём явно: umask демона 0077, иначе резолвер стал бы нечитаемым для всех, кроме root.
    let prepared = write_mode(tmp, content, 0o644);
    let rename_err = match &prepared {
        Ok(()) => match std::fs::rename(tmp, RESOLV) {
            Ok(()) => return Ok(()),
            Err(e) => {
                let _ = std::fs::remove_file(tmp);
                Some(e.to_string())
            }
        },
        Err(e) => Some(format!("{e:#}")),
    };
    let is_symlink =
        std::fs::symlink_metadata(RESOLV).map(|m| m.file_type().is_symlink()).unwrap_or(false);
    if !is_symlink {
        if let Err(e) = std::fs::write(RESOLV, content) {
            bail!("записать {RESOLV}: {e} (подмена файлом: {})", rename_err.unwrap_or_default());
        }
        // Права на существующем файле не меняем: он мог быть создан не нами.
        return Ok(());
    }
    bail!("записать {RESOLV}: {}", rename_err.unwrap_or_default())
}

/// Вернуть резолвер в исходное состояние.
fn restore_resolv(b: ResolvBackup) -> Result<()> {
    match b {
        ResolvBackup::Symlink(target) => {
            // Симлинк тоже ставим через rename: он атомарно заменяет наш файл ссылкой.
            let tmp = Path::new(RESOLV_TMP);
            let _ = std::fs::remove_file(tmp);
            std::os::unix::fs::symlink(&target, tmp)
                .with_context(|| format!("подготовить симлинк {RESOLV} → {}", target.display()))?;
            std::fs::rename(tmp, RESOLV)
                .inspect_err(|_| {
                    let _ = std::fs::remove_file(tmp);
                })
                .with_context(|| format!("восстановить симлинк {RESOLV}"))?;
        }
        ResolvBackup::File => {
            let content = std::fs::read(RESOLV_BAK).context("прочитать резервную копию resolv.conf")?;
            install_resolv(&content).context("восстановить resolv.conf")?;
            let _ = std::fs::remove_file(RESOLV_BAK);
        }
        // Файла не было — убираем свой и оставляем как было.
        ResolvBackup::Missing => {
            let _ = std::fs::remove_file(RESOLV);
        }
    }
    Ok(())
}

/// Запись файла с явными правами. Права выставляются отдельным `chmod`, а не только флагом
/// `mode()`: у демона umask 0077, и `resolv.conf` иначе получился бы root-only, то есть
/// нечитаемым для всех приложений, которым он и предназначен.
fn write_mode(path: &Path, content: &[u8], mode: u32) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).ok();
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("создать {}", path.display()))?;
    f.write_all(content)?;
    f.flush()?;
    std::fs::set_permissions(path, perms(mode))
        .with_context(|| format!("права {mode:o} на {}", path.display()))?;
    Ok(())
}

fn perms(mode: u32) -> std::fs::Permissions {
    use std::os::unix::fs::PermissionsExt;
    std::fs::Permissions::from_mode(mode)
}
