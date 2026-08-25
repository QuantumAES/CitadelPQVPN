//! `citadel-cli` — консольный клиент CitadelPQVPN для Linux.
//!
//! Работает от обычного пользователя и НЕ имеет привилегий: хранит профили в зашифрованном
//! мастер-паролем хранилище (`vault`, Argon2id — то же, что у GUI-клиента) и управляет туннелем
//! через демон `citadel-vpnd` по unix-сокету. Без аргументов запускается полноэкранный TUI,
//! с подкомандами — скриптуемый режим.
//!
//! Секреты (мастер-пароль, `citadel://`-ссылка) принимаются только с терминала или stdin —
//! никогда из аргументов: `/proc/<pid>/cmdline` виден всем локальным пользователям (L5).
//! Любая строка, пришедшая извне (метка, ошибка сервера, имя exit'а), перед выводом в терминал
//! очищается от управляющих последовательностей (L16).

mod askpass;
mod ipc;
mod settings;
mod tui;

use anyhow::{bail, Context, Result};

use citadel_client::Vault;
use citadel_vpnd::proto::ConnectReq;
use citadel_vpnd::valid::sanitize_text;

use ipc::Client;
use settings::Settings;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Ссылка в аргументах — самая частая и самая дорогая ошибка: она осядет в истории шелла и
    // будет видна в `ps` всем на машине. Ловим её раньше любой обработки.
    if let Some(a) = args.iter().find(|a| a.starts_with("citadel://")) {
        let _ = a;
        bail!(
            "не передавайте citadel://-ссылку аргументом: она видна всем в `ps` и остаётся \
             в истории шелла.\nИспользуйте: citadel-cli add   (ссылка запрашивается интерактивно) \
             или: cat link.txt | citadel-cli add --stdin"
        );
    }

    match args.first().map(String::as_str) {
        None => tui::run(),
        Some("status") => cmd_status(),
        Some("connect") => cmd_connect(args.get(1).cloned()),
        Some("disconnect") | Some("down") => cmd_disconnect(),
        Some("profiles") | Some("list") => cmd_profiles(),
        Some("add") => cmd_add(&args[1..]),
        Some("remove") | Some("rm") => cmd_remove(args.get(1).cloned()),
        Some("killswitch") => cmd_killswitch(&args[1..]),
        Some("split") => cmd_split(&args[1..]),
        Some("passwd") => cmd_passwd(),
        Some("version") | Some("--version") => cmd_version(),
        Some("help") | Some("-h") | Some("--help") => {
            print_help();
            Ok(())
        }
        Some(other) => {
            print_help();
            bail!("неизвестная команда: {}", sanitize_text(other, 32))
        }
    }
}

fn print_help() {
    println!(
        "citadel-cli — консольный клиент CitadelPQVPN\n\
         \n\
         Без аргументов — полноэкранный интерфейс настройки (TUI).\n\
         \n\
         Команды:\n\
         \x20 status                 состояние сессии\n\
         \x20 connect [профиль]      подключиться (без имени — единственный профиль)\n\
         \x20 disconnect             отключиться\n\
         \x20 profiles               список профилей в хранилище\n\
         \x20 add [--name ИМЯ]       добавить профиль (ссылка вводится интерактивно)\n\
         \x20 add --stdin            то же, ссылка со stdin (для скриптов)\n\
         \x20 add --code XXXXXX      код сверки одноразовой ссылки (иначе спросим интерактивно)\n\
         \x20 remove ИМЯ|ID          удалить профиль\n\
         \x20 killswitch on|off      настройка kill-switch (со следующего подключения)\n\
         \x20 killswitch --disarm    аварийно снять залипшие правила (сеть и DNS)\n\
         \x20 split off|include|exclude [CIDR…]   split-tunnel по назначениям\n\
         \x20 passwd                 сменить мастер-пароль хранилища\n\
         \x20 version                версии клиента и демона\n\
         \n\
         Журнал демона: journalctl -u citadel-vpnd -f"
    );
}

// ───────────────────────────── состояние и сессия ─────────────────────────────

/// Сказать вслух, если демон работает из устаревшего бинаря (см. [`ipc::stale_daemon_hint`]).
/// Молча пропускаем всё, что не удалось выяснить: подсказка обязана быть либо точной, либо
/// отсутствовать — ложная тревога тут хуже молчания.
fn warn_if_stale_daemon(c: &Client) {
    if let Ok(s) = c.status() {
        if let Some(h) = ipc::stale_daemon_hint(&s) {
            eprintln!("ВНИМАНИЕ: {h}");
        }
    }
}

fn cmd_status() -> Result<()> {
    let c = Client::default();
    let s = c.status()?;
    println!("Состояние:    {}", state_ru(&s.state));
    if !s.label.is_empty() {
        println!("Профиль:      {}", sanitize_text(&s.label, 64));
    }
    if !s.exit.is_empty() {
        println!("Exit:         {}", sanitize_text(&s.exit, 128));
        println!("Транспорт:    {}", sanitize_text(&s.transport, 32));
        println!("Адрес:        {}", sanitize_text(&s.cidr, 64));
    }
    println!("Kill-switch:  {}", if s.killswitch_armed { "армирован" } else { "снят" });
    if s.killswitch_armed && s.state == "idle" {
        println!(
            "  ВНИМАНИЕ: защита армирована без активной сессии — трафик заблокирован.\n\
             \x20 Снять: citadel-cli killswitch --disarm"
        );
    }
    // Человеку — итог, а не текст ошибки движка: подробности всё равно есть в журнале демона.
    if !s.last_error.is_empty() {
        if s.label.is_empty() {
            println!("Результат:    сервер недоступен");
        } else {
            println!("Результат:    сервер недоступен (профиль «{}»)", sanitize_text(&s.label, 64));
        }
        println!("              подробности: journalctl -u citadel-vpnd -n 50");
    }
    if let Some(h) = ipc::stale_daemon_hint(&s) {
        println!("\nВНИМАНИЕ: {h}");
    }
    Ok(())
}

fn cmd_connect(name: Option<String>) -> Result<()> {
    // Хранилище открывается РОВНО ОДИН раз за команду: каждый вызов `with_vault` спрашивает
    // мастер-пароль, и три вопроса подряд на одно «citadel-cli connect» — это не безопасность, а
    // раздражение. Поэтому выбор профиля, активация (M-9) и подстановка ключа устройства идут
    // внутри одного захода.
    let (uri, label) = with_vault(|v| {
        let profiles = v.list();
        if profiles.is_empty() {
            bail!("в хранилище нет профилей — добавьте: citadel-cli add");
        }
        let p = match &name {
            Some(n) => find_profile(&profiles, n)?,
            None if profiles.len() == 1 => profiles[0].clone(),
            None => {
                let names: Vec<String> = profiles.iter().map(|p| p.name.clone()).collect();
                bail!("укажите профиль: {}", names.join(", "));
            }
        };
        // M-9: первичная ссылка активируется на ЭТОМ устройстве до первого подключения. Делает это
        // консоль, а не демон: ключ надо положить в хранилище, а хранилище есть только у
        // пользователя (демон и движок живут за границей привилегий и его не видят).
        let (id, sid, mid) = (p.id.clone(), p.id.clone(), p.id.clone());
        // Обоим callback'ам нужен `&mut Vault`, но выполняются они строго по очереди — делим
        // владение RefCell'ом, а не второй копией хранилища в памяти.
        let cell = std::cell::RefCell::new(&mut *v);
        let outcome = citadel_client::activate_profile_blocking(
            &p,
            |seed| cell.borrow_mut().set_device_seed(&sid, seed),
            || cell.borrow_mut().mark_enrolled(&mid),
        )
        .context("активация ссылки")?;
        if outcome == citadel_client::Activation::Activated {
            println!("Ссылка активирована на этом устройстве (повторно использовать её нельзя).");
        }
        // Демону уходит ссылка с ТЕМ ключом, которым положено представляться издателю: после
        // активации — устройственным. Подменить поле в ссылке проще и безопаснее, чем расширять
        // IPC ещё одним секретом, а движок про активацию так и не знает.
        let fresh = cell
            .borrow()
            .list()
            .into_iter()
            .find(|x| x.id == id)
            .unwrap_or_else(|| p.clone());
        let link = citadel_client::CredentialLink::from_uri(&fresh.uri)?;
        let uri = match citadel_client::effective_seed(&fresh, &link) {
            Some(seed) if Some(seed) != link.client_seed => {
                let mut l = citadel_client::CredentialLink::from_uri(&fresh.uri)?;
                l.client_seed = Some(seed);
                l.to_uri()?
            }
            _ => fresh.uri.clone(),
        };
        Ok((uri, fresh.name.clone()))
    })?;

    let st = Settings::load();
    let c = Client::default();
    // До подключения: если сессия не поднимется из-за давно исправленного бага в старом
    // демоне, человек должен узнать причину сразу, а не из журнала.
    warn_if_stale_daemon(&c);
    println!("Подключение к профилю «{}»…", sanitize_text(&label, 64));
    c.connect_session(ConnectReq {
        link: uri,
        killswitch: st.killswitch,
        split_mode: st.dest_mode.clone(),
        split_dests: st.dests.clone(),
        label,
    })?;
    follow_until_settled(&c)
}

/// Показывать события, пока сессия не поднимется или не станет ясно, что не поднимется.
fn follow_until_settled(c: &Client) -> Result<()> {
    let mut s = c.subscribe()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    while std::time::Instant::now() < deadline {
        match ipc::read_event(&mut s)? {
            Some(ev) => match ev.kind.as_str() {
                "connected" => {
                    println!(
                        "Подключено: exit {} ({}), адрес {}",
                        sanitize_text(&ev.exit, 128),
                        sanitize_text(&ev.transport, 32),
                        sanitize_text(&ev.cidr, 64)
                    );
                    return Ok(());
                }
                "error" => println!("  … {}", sanitize_text(&ev.error, 512)),
                "state" => {
                    println!("  … {}", state_ru(&ev.state));
                    if ev.state == "down" {
                        bail!("сессия завершилась, не поднявшись (см. journalctl -u citadel-vpnd)");
                    }
                }
                _ => {}
            },
            None => bail!("демон закрыл поток событий"),
        }
    }
    println!("Сессия ещё поднимается — следите: citadel-cli status");
    Ok(())
}

fn cmd_disconnect() -> Result<()> {
    Client::default().disconnect()?;
    println!("Отключено, kill-switch снят.");
    Ok(())
}

fn cmd_version() -> Result<()> {
    println!("citadel-cli   {}", env!("CARGO_PKG_VERSION"));
    println!("ядро          {}", citadel_client::version());
    let c = Client::default();
    match c.version() {
        Ok(v) => println!("citadel-vpnd  {v} ({})", c.socket_path()),
        Err(e) => println!("citadel-vpnd  недоступен ({e})"),
    }
    warn_if_stale_daemon(&c);
    Ok(())
}

// ───────────────────────────── профили ─────────────────────────────

fn cmd_profiles() -> Result<()> {
    with_vault(|v| {
        let list = v.list();
        if list.is_empty() {
            println!("Хранилище пусто. Добавить профиль: citadel-cli add");
            return Ok(());
        }
        for p in list {
            // Имя профиля приходит из чужой ссылки — чистим перед выводом (L16).
            println!("{}  {}", &p.id[..8.min(p.id.len())], sanitize_text(&p.name, 64));
        }
        Ok(())
    })
}

fn cmd_add(args: &[String]) -> Result<()> {
    let name = args
        .iter()
        .position(|a| a == "--name")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_default();
    let from_stdin = args.iter().any(|a| a == "--stdin");

    let uri = if from_stdin {
        askpass::read_secret_line()?
    } else {
        askpass::read_password("Вставьте citadel://-ссылку или парольный блок (ввод скрыт): ")?
    };
    // B-2: мастер-ссылка может приехать в парольном конверте (`-----BEGIN CITADEL MASTER LINK-----`,
    // см. `citadel_client::masterlink`). Спрашиваем пароль ровно тогда, когда конверт распознан:
    // всем подряд поле пароля показывать незачем.
    let uri = if citadel_client::masterlink::looks_wrapped(&uri) {
        let pass = askpass::read_password("Пароль конверта мастер-ссылки (ввод скрыт): ")?;
        // Развёрнутая ссылка — такой же секрет, как введённый блок: держим её в Zeroizing.
        askpass::Secret::new(
            citadel_client::masterlink::unwrap(&uri, &pass)
                .context("развернуть парольный блок мастер-ссылки")?,
        )
    } else {
        uri
    };
    if !uri.starts_with("citadel://") {
        bail!("это не citadel://-ссылка");
    }
    verify_link_code(&uri, args)?;

    with_vault(|v| {
        let p = v.add(&name, &uri)?;
        println!("Профиль добавлен: {} ({})", sanitize_text(&p.name, 64), &p.id[..8.min(p.id.len())]);
        Ok(())
    })
}

/// M-9: сверка кода ПЕРВИЧНОЙ (одноразовой) ссылки при импорте.
///
/// Подмену ссылки по дороге не ловит ничто внутри неё самой: подменивший перевыпустит её целиком,
/// вместе с любой внутренней подписью. Единственная работающая проверка — сравнить короткий
/// отпечаток по ДРУГОМУ каналу (админ называет его голосом). Поэтому здесь код спрашивается, а не
/// печатается «к сведению». Многоразовые ссылки (розданные до M-9) кода не несут — их пропускаем,
/// иначе уже работающие абоненты не смогли бы перенести профиль.
///
/// `--code XXXXXX` — для скриптов и неинтерактивного запуска; без него код спрашивается с клавиатуры.
fn verify_link_code(uri: &str, args: &[String]) -> Result<()> {
    let link = citadel_client::CredentialLink::from_uri(uri).context("разбор ссылки")?;
    let Some(expect) = link.verify_code().filter(|_| link.enroll) else {
        return Ok(());
    };
    let given = args
        .iter()
        .position(|a| a == "--code")
        .and_then(|i| args.get(i + 1))
        .cloned();
    let given = match given {
        Some(c) => c,
        None => {
            use std::io::IsTerminal;
            if !std::io::stdin().is_terminal() {
                // Неинтерактивный запуск: спросить некого, а пропускать проверку нельзя —
                // ровно её отсутствие и делает подмену ссылки при доставке незаметной.
                bail!(
                    "ссылка одноразовая, нужен код сверки от администратора: \
                     передайте его флагом --code XXXXXX"
                );
            }
            println!("Ссылка одноразовая: активируется на ОДНОМ устройстве.");
            println!("Введите код сверки, который назвал администратор (отдельно от ссылки).");
            askpass::read_line("Код сверки: ")?
        }
    };
    // Сравнение — как в GUI: регистр/разделители не значат ничего, а O/I/L человек слышит как 0/1/1.
    let norm = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .map(|c| match c.to_ascii_uppercase() {
                'O' => '0',
                'I' | 'L' => '1',
                x => x,
            })
            .collect()
    };
    if norm(&given) != norm(&expect) {
        bail!(
            "код сверки не совпал — это НЕ та ссылка, которую выдал администратор. \
             Не подключайтесь по ней, запросите ссылку заново."
        );
    }
    println!("Код сверки совпал.");
    Ok(())
}

fn cmd_remove(name: Option<String>) -> Result<()> {
    let name = name.context("укажите имя или id профиля")?;
    with_vault(|v| {
        let p = find_profile(&v.list(), &name)?;
        v.remove(&p.id)?;
        println!("Удалён профиль {}", sanitize_text(&p.name, 64));
        Ok(())
    })
}

fn cmd_passwd() -> Result<()> {
    let path = settings::vault_path();
    if !Vault::exists(&path) {
        bail!("хранилище не создано");
    }
    let old = askpass::read_password("Текущий мастер-пароль: ")?;
    let mut v = Vault::open(&path, &old)?;
    let new = askpass::read_new_password("Новый мастер-пароль: ")?;
    v.change_password(&new)?;
    println!("Мастер-пароль изменён (хранилище перешифровано).");
    Ok(())
}

// ───────────────────────────── настройки ─────────────────────────────

fn cmd_killswitch(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("on") => {
            Settings::save_killswitch(true)?;
            println!("Kill-switch включён (применится со следующего подключения).");
        }
        Some("off") => {
            Settings::save_killswitch(false)?;
            println!("Kill-switch выключен (применится со следующего подключения).");
        }
        Some("--disarm") => {
            Client::default().disarm_killswitch()?;
            println!("Fail-closed правила и правила DNS сняты, доступ в сеть восстановлен.");
        }
        None | Some("status") => {
            let st = Settings::load();
            println!("Настройка: {}", if st.killswitch { "включён" } else { "выключен" });
            if let Ok(s) = Client::default().status() {
                println!("Сейчас:    {}", if s.killswitch_armed { "армирован" } else { "снят" });
            }
        }
        Some(other) => bail!("killswitch: on|off|status|--disarm (получено {})", sanitize_text(other, 32)),
    }
    Ok(())
}

fn cmd_split(args: &[String]) -> Result<()> {
    let mut st = Settings::load();
    match args.first().map(String::as_str) {
        None | Some("status") => {
            println!("Режим:      {}", st.dest_mode);
            if st.dests.is_empty() {
                println!("Назначения: (пусто)");
            } else {
                println!("Назначения: {}", st.dests.join(", "));
            }
        }
        Some(mode @ ("off" | "include" | "exclude")) => {
            st.dest_mode = mode.to_string();
            let rest: Vec<String> = args[1..].to_vec();
            if !rest.is_empty() {
                st.dests = rest;
            }
            st.save_split()?;
            println!("Split: {} {}", st.dest_mode, st.dests.join(" "));
            println!("Применится со следующего подключения.");
        }
        Some(other) => bail!("split: off|include|exclude [CIDR…] (получено {})", sanitize_text(other, 32)),
    }
    Ok(())
}

// ───────────────────────────── хранилище ─────────────────────────────

/// Открыть (или создать) хранилище, спросив мастер-пароль, и выполнить над ним операцию.
fn with_vault<T>(f: impl FnOnce(&mut Vault) -> Result<T>) -> Result<T> {
    let path = settings::vault_path();
    let mut v = if Vault::exists(&path) {
        let pass = askpass::read_password("Мастер-пароль хранилища: ")?;
        Vault::open(&path, &pass).context("открыть хранилище")?
    } else {
        println!("Хранилище не найдено — создаём {}", path.display());
        let pass = askpass::read_new_password("Задайте мастер-пароль (минимум 8 символов): ")?;
        Vault::create(&path, &pass).context("создать хранилище")?
    };
    f(&mut v)
}

/// Найти профиль по имени (точное совпадение) или по префиксу id.
fn find_profile(
    profiles: &[citadel_client::Profile],
    key: &str,
) -> Result<citadel_client::Profile> {
    if let Some(p) = profiles.iter().find(|p| p.name == key) {
        return Ok(p.clone());
    }
    let by_id: Vec<_> = profiles.iter().filter(|p| p.id.starts_with(key)).collect();
    match by_id.len() {
        1 => Ok(by_id[0].clone()),
        0 => bail!("профиль не найден: {}", sanitize_text(key, 64)),
        _ => bail!("неоднозначный префикс id: {}", sanitize_text(key, 64)),
    }
}

/// Человеческое имя состояния (одинаково в CLI и TUI).
pub fn state_ru(state: &str) -> &'static str {
    match state {
        "idle" => "не подключено",
        "connecting" => "подключение…",
        "up" => "подключено",
        "migrating" => "восстановление связи…",
        "down" => "отключено",
        _ => "неизвестно",
    }
}
