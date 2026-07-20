//! citadel-token — роли анонимного issuance (M5, issuer↔exit split).
//!
//! Режим (env `Citadel_TOKEN_ROLE` или arg[1]):
//!   `issuer` — сгенерировать ключ, опубликовать issuer.pub, слушать TCP и подписывать ВСЛЕПУЮ
//!              (издатель видит только blind_msg, не токен). sk остаётся в процессе.
//!   `client` — подключиться к издателю, интерактивно получить N токенов (blind→sign→finalize),
//!              записать в файл. Издатель не может связать выданное с предъявленным на exit.
//!   `batch`  — (legacy) выпустить N токенов в одном процессе → файл (для локального демо/тестов).
//!
//! CLI-подкоманды (arg[1], вне env-роли): `registry` — оффлайн-правка Layer-1 реестра на сервере
//! (C5.5); `admin` — те же операции ПО СЕТЕВОМУ admin-каналу (PQ-TLS+pin, домен+EKM; C7.5) — путь
//! GUI, обычно через туннель к ADMIN_VIP.
//!
//! Сетевой формат: кадр `u32(len, BE) ‖ payload`; запрос — blind_msg, ответ — blind_sig.

use std::collections::HashMap;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use citadel_token::{read_frame, write_frame}; // C5.3: фрейминг вынесен в lib (переиспользует fetch_tokens)

fn token_dir() -> String {
    std::env::var("Citadel_TOKEN_DIR").unwrap_or_else(|_| "/shared".into())
}

/// S2.1/A1-остаток: obfs-PSK канала к издателю из `Citadel_OBFS_PSK` (hex32). `Some` → issuer/CLI
/// оборачивают TLS в obfs (probe-resistance, неотличимость от туннеля); `None`/мусор → голый TLS.
/// Тот же PSK, что у туннеля (в ссылке) — обе стороны обязаны совпадать, иначе `open` рвёт канал.
fn obfs_psk_from_env() -> Option<[u8; 32]> {
    std::env::var("Citadel_OBFS_PSK")
        .ok()
        .and_then(|s| hex::decode(s.trim()).ok())
        .and_then(|v| v.try_into().ok())
}
fn token_count() -> usize {
    std::env::var("Citadel_TOKEN_COUNT").ok().and_then(|s| s.parse().ok()).unwrap_or(8)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ===================== C5.2 Layer-1: реестр «абонентов» у issuer =====================
fn registry_path(dir: &str) -> String {
    format!("{dir}/registry")
}

/// Реестр — строки `<pub_hex> <valid_until_unix> <status>`. Возвращает true, если pub найден,
/// `active` и не истёк. Читается на КАЖДЫЙ auth → отзыв/добавление действуют сразу (≤ след. коннект).
/// C7.1: разбор строк — общий `admin::parse_registry` (первое совпадение решает, как раньше).
fn registry_allows(dir: &str, pub_key: &[u8], now: u64) -> bool {
    let Ok(content) = std::fs::read_to_string(registry_path(dir)) else {
        return false; // нет реестра → никто не авторизован (secure default)
    };
    citadel_token::admin::parse_registry(&content)
        .iter()
        .find(|e| e.client_id[..] == *pub_key)
        .is_some_and(|e| e.status == "active" && now < e.valid_until)
}

/// Bootstrap реестра Layer-1 из env (демо + installer, C5.4b):
///   - `Citadel_REGISTER_PUBS`  — client_id-pub'ы (hex32, через пробел): **issuer НЕ видит seed**
///     абонента (installer/прод-путь — админ регистрирует только публичный id).
///   - `Citadel_REGISTER_SEEDS` — seed'ы (hex32) → pub деривится здесь (демо/legacy: issuer знает seed).
///
/// **Идемпотентно и не затирает** существующие строки: pub, уже присутствующий в реестре, не трогается.
/// Это критично — иначе admin-revoke (`status=revoked`) терялся бы при рестарте контейнера и отозванный
/// абонент «воскресал» бы `active`. Добавляются только новые pub'ы как `active` на +10 лет. В проде
/// правкой файла (revoke/add) управляет админ (C5.5); bootstrap лишь досевает недостающих.
fn bootstrap_registry(dir: &str) -> Result<()> {
    let mut pubs: Vec<[u8; 32]> = Vec::new();
    if let Ok(list) = std::env::var("Citadel_REGISTER_PUBS") {
        for p in list.split_whitespace() {
            let pk: [u8; 32] = hex::decode(p)
                .ok()
                .and_then(|v| v.try_into().ok())
                .context("Citadel_REGISTER_PUBS: client_id должен быть 32 байта hex")?;
            pubs.push(pk);
        }
    }
    if let Ok(list) = std::env::var("Citadel_REGISTER_SEEDS") {
        for s in list.split_whitespace() {
            let seed: [u8; 32] = hex::decode(s)
                .ok()
                .and_then(|v| v.try_into().ok())
                .context("Citadel_REGISTER_SEEDS: seed должен быть 32 байта hex")?;
            pubs.push(citadel_token::ed25519_pub_from_seed(&seed)?);
        }
    }
    if pubs.is_empty() {
        return Ok(()); // нет bootstrap-env → реестр как есть (admin-managed или пуст)
    }
    let existing = std::fs::read_to_string(registry_path(dir)).unwrap_or_default();
    let far = now_unix() + 10 * 365 * 24 * 3600;
    let merged = merge_registry(&existing, &pubs, far);
    std::fs::write(registry_path(dir), &merged).context("запись реестра")?;
    eprintln!(
        "[issuer] реестр Layer-1: {} абонент(ов) (bootstrap-merge; revoke переживает рестарт)",
        merged.lines().filter(|l| !l.trim().is_empty()).count()
    );
    Ok(())
}

/// Чистая логика слияния реестра: сохраняет ВСЕ существующие строки (в т.ч. `revoked`/`expired`),
/// добавляет только те `pubs`, которых ещё нет (по pub_hex), как `active` до `valid_until`.
/// Идемпотентно: повторный вызов с теми же pub'ами не меняет вывод.
fn merge_registry(existing: &str, pubs: &[[u8; 32]], valid_until: u64) -> String {
    let present: std::collections::HashSet<&str> =
        existing.lines().filter_map(|l| l.split_whitespace().next()).collect();
    let mut out = existing.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    for pk in pubs {
        let hexpk = hex::encode(pk);
        if !present.contains(hexpk.as_str()) {
            out.push_str(&format!("{hexpk} {valid_until} active\n"));
        }
    }
    out
}

// ===================== C5.5: admin-CLI управления реестром =====================

/// `citadel-token registry <add|add-seed|revoke|list> …` — оффлайн-правка Layer-1 реестра админом
/// (замена ручного `sed` из installer'а). Каталог реестра — `Citadel_TOKEN_DIR` (том issuer'а).
/// Issuer перечитывает реестр на КАЖДЫЙ auth ⇒ add/revoke действуют со следующего коннекта
/// (отзыв — ≤ длины эпохи). Запись атомарна (temp+rename) — конкурентный читатель-issuer видит
/// старый ИЛИ новый файл, не частичный. C7.1: логика реестра — общая `citadel_token::admin`
/// (те же функции обслуживают admin-канал по туннелю).
fn run_registry(args: &[String]) -> Result<()> {
    use citadel_token::admin::{atomic_write, registry_apply_add, registry_apply_revoke};
    let path = registry_path(&token_dir());
    match args.get(2).map(String::as_str) {
        Some("add") => {
            let pk = parse_hex32(args.get(3), "pub (client_id, 64 hex)")?;
            let vu = parse_valid_until(args.get(4).map(String::as_str))?;
            let cur = std::fs::read_to_string(&path).unwrap_or_default();
            atomic_write(&path, &registry_apply_add(&cur, &pk, vu))?;
            eprintln!("[registry] add {} active до {vu}", hex::encode(pk));
        }
        Some("add-seed") => {
            // Провижининг нового абонента: из его seed выводим pub (client_id) и регистрируем ЕГО.
            // Seed НЕ сохраняется (уходит абоненту в ссылке) — в реестре только публичный id.
            let seed = parse_hex32(args.get(3), "seed (64 hex)")?;
            let pk = citadel_token::ed25519_pub_from_seed(&seed)?;
            let vu = parse_valid_until(args.get(4).map(String::as_str))?;
            let cur = std::fs::read_to_string(&path).unwrap_or_default();
            atomic_write(&path, &registry_apply_add(&cur, &pk, vu))?;
            eprintln!("[registry] add-seed → client_id {} active до {vu}", hex::encode(pk));
        }
        Some("revoke") => {
            let pk = parse_hex32(args.get(3), "pub (client_id, 64 hex)")?;
            let cur = std::fs::read_to_string(&path).unwrap_or_default();
            atomic_write(&path, &registry_apply_revoke(&cur, &pk)?)?;
            eprintln!("[registry] revoke {} (действует ≤ длины эпохи)", hex::encode(pk));
        }
        Some("list") => print!("{}", std::fs::read_to_string(&path).unwrap_or_default()),
        _ => anyhow::bail!(
            "citadel-token registry <add <pub>|add-seed <seed>|revoke <pub>|list> [valid_until]\n  \
             valid_until: unix-секунды | +<N>d | +<N>h | +<секунды> (дефолт +365d).  \
             Каталог реестра — $Citadel_TOKEN_DIR (том issuer'а)."
        ),
    }
    Ok(())
}

// ===================== C7.5: admin-CLI ПО КАНАЛУ (туннелю) =====================

/// `citadel-token admin <list|add <pub> [valid_until]|revoke <pub>>` — управление реестром через
/// СЕТЕВОЙ admin-канал issuer'а (PQ-TLS+pin, Ed25519 домен+EKM) — тот же путь, что GUI (C7.3/C7.4),
/// в отличие от `registry` (оффлайн-правка файла на сервере). Для харнеса C7.5 и ops/break-glass
/// с любой машины, у которой есть мастер-креды и туннель.
///
/// Env: `Citadel_ADMIN_ADDR` (host:port; из туннеля — `10.7.0.1:<admin_port>`),
///      `Citadel_ISSUER_PIN` (hex32 — тот же TLS-pin issuer'а, что для token-fetch),
///      `Citadel_ADMIN_SEED` (hex32 — admin-seed из мастер-ссылки).
fn run_admin_channel(args: &[String]) -> Result<()> {
    let addr = std::env::var("Citadel_ADMIN_ADDR")
        .context("нужен Citadel_ADMIN_ADDR (host:port admin-канала; из туннеля — ADMIN_VIP:порт)")?;
    let pin = parse_hex32(
        std::env::var("Citadel_ISSUER_PIN").ok().as_ref(),
        "Citadel_ISSUER_PIN (TLS-pin issuer, 64 hex)",
    )?;
    let seed = parse_hex32(
        std::env::var("Citadel_ADMIN_SEED").ok().as_ref(),
        "Citadel_ADMIN_SEED (admin-seed, 64 hex)",
    )?;
    // S2.1/A1-остаток: obfs-обёртка admin-канала (probe-resistance) — PSK из env, как token-fetch.
    let obfs_psk = obfs_psk_from_env();
    let mut c = citadel_token::admin::AdminClient::connect(&addr, &pin, &seed, obfs_psk)
        .context("admin-канал: connect/auth")?;
    match args.get(2).map(String::as_str) {
        Some("list") => {
            for e in c.list()? {
                println!("{} {} {}", hex::encode(e.client_id), e.valid_until, e.status);
            }
        }
        Some("add") => {
            let pk = parse_hex32(args.get(3), "pub (client_id, 64 hex)")?;
            // Без аргумента шлём 0 → срок назначает СЕРВЕР (+365d), как GUI-путь admin_issue.
            let vu = match args.get(4) {
                None => 0,
                Some(s) => parse_valid_until(Some(s))?,
            };
            c.add(pk, vu)?;
            eprintln!("[admin] add {} по каналу (срок: {})", hex::encode(pk),
                if vu == 0 { "серверный дефолт".into() } else { vu.to_string() });
        }
        Some("revoke") => {
            let pk = parse_hex32(args.get(3), "pub (client_id, 64 hex)")?;
            c.revoke(pk)?;
            eprintln!("[admin] revoke {} по каналу (действует ≤ длины эпохи)", hex::encode(pk));
        }
        _ => anyhow::bail!(
            "citadel-token admin <list|add <pub> [valid_until]|revoke <pub>>\n  \
             env: Citadel_ADMIN_ADDR, Citadel_ISSUER_PIN, Citadel_ADMIN_SEED.  \
             Операции идут по PQ-TLS admin-каналу (обычно — через туннель к ADMIN_VIP)."
        ),
    }
    Ok(())
}

/// Разобрать 32-байтный hex-аргумент (pub/seed) или дать понятную ошибку.
fn parse_hex32(arg: Option<&String>, what: &str) -> Result<[u8; 32]> {
    let s = arg.with_context(|| format!("нужен <{what}>"))?;
    hex::decode(s.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .with_context(|| format!("<{what}> должен быть ровно 32 байта hex"))
}

/// `valid_until`: абсолютные unix-секунды, либо относительно now — `+<N>d`/`+<N>h`/`+<секунды>`.
/// Пусто → now + 365 дней.
fn parse_valid_until(arg: Option<&str>) -> Result<u64> {
    let now = now_unix();
    let Some(s) = arg else {
        return Ok(now + 365 * 24 * 3600);
    };
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('+') {
        let (num, mult) = match rest.chars().last() {
            Some('d') => (&rest[..rest.len() - 1], 24 * 3600),
            Some('h') => (&rest[..rest.len() - 1], 3600),
            _ => (rest, 1),
        };
        let n: u64 = num.parse().context("valid_until: ожидалось +<N>d | +<N>h | +<секунды>")?;
        Ok(now + n * mult)
    } else {
        s.parse().context("valid_until: unix-секунды или относительное +<N>d")
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    // C5.5 admin-CLI управления реестром — оффлайн-операция админа (add/revoke/list), не сетевая
    // роль, поэтому маршрутизируем по arg[1] ДО env-роли (Citadel_TOKEN_ROLE её не задаёт).
    if args.get(1).map(String::as_str) == Some("registry") {
        return run_registry(&args);
    }
    // C7.5: сетевой admin-канал (list/add/revoke по туннелю) — тот же путь, что GUI.
    if args.get(1).map(String::as_str) == Some("admin") {
        return run_admin_channel(&args);
    }
    let role = std::env::var("Citadel_TOKEN_ROLE")
        .ok()
        .or_else(|| args.get(1).cloned())
        .unwrap_or_else(|| "batch".into());
    match role.as_str() {
        "issuer" | "serve" => run_issuer(),
        "client" | "fetch" => run_client_fetch(),
        "pubkey" => run_pubkey(),
        "batch" => run_batch(),
        other => Err(anyhow::anyhow!(
            "Citadel_TOKEN_ROLE должен быть issuer|client|pubkey|batch (или arg[1]=registry), а не {other:?}"
        )),
    }
}

/// C5.1: ключ издателя на ТЕКУЩУЮ эпоху (`(epoch, pk_der, sk_der)`) под Mutex — фоновая ротация
/// меняет его при смене эпохи. Токены становятся epoch-scoped: exit примет их только ключом
/// текущей±прошлой эпохи → «гаснут» к концу эпохи (отзыв по времени, M6).
type EpochKey = (u64, Vec<u8>, Vec<u8>);

/// S2.4/A6: счётчик выданных токенов `client_id → (эпоха, число)` (анти-фарминг, per-epoch).
type QuotaMap = HashMap<[u8; 32], (u64, u32)>;

/// Задача 4 (вариант B — мягкий single-session): время, до которого client_id УЖЕ обслужен и не
/// получит новую выдачу (`client_id → expiry_unix`). Ограничивает открытие ПАРАЛЛЕЛЬНЫХ сессий с
/// одной ссылки, не ломая unlinkability (exit по-прежнему не знает client_id — контроль на issuer,
/// который видит его при Layer-1).
type LeaseMap = HashMap<[u8; 32], u64>;

/// Опубликовать pub эпохи (`issuer-<epoch>.pub`) + `issuer.pub` (= current, back-compat не-epoch exit).
fn publish_epoch_pub(dir: &str, epoch: u64, pk: &[u8]) -> Result<()> {
    std::fs::write(format!("{dir}/{}", citadel_token::epoch_pub_name(epoch)), pk)
        .with_context(|| format!("публикация pub эпохи {epoch}"))?;
    std::fs::write(format!("{dir}/issuer.pub"), pk).context("issuer.pub (back-compat = current)")?;
    Ok(())
}

/// Издатель (биллинг): держит sk текущей эпохи, слепо подписывает по TCP; ротирует ключ по эпохам.
fn run_issuer() -> Result<()> {
    let bits = 2048;
    let epoch_secs: u64 =
        std::env::var("Citadel_EPOCH_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(3600);
    let dir = token_dir();
    bootstrap_registry(&dir)?; // C5.2: демо-регистрация абонентов из Citadel_REGISTER_SEEDS

    // S2.1/A1: постоянная TLS-идентичность издателя (pin кладётся в ссылку → клиент пиннит канал).
    let identity = citadel_token::pqtls::IssuerIdentity::load_or_generate(&dir)?;
    eprintln!(
        "[issuer] PQ-TLS канал: pin {} → {dir}/issuer-tls.pin (клиент пиннит, анти-MITM A1)",
        hex::encode(identity.pin)
    );
    let scfg = identity.server_config()?;
    // S2.1/A1-остаток: obfs-обёртка issuer-канала (probe-resistance). При заданном PSK и token-, и
    // admin-канал молчат на не-obfs пробу и на проводе неотличимы от туннеля (тот же PSK из ссылки).
    let obfs_psk = obfs_psk_from_env();
    eprintln!(
        "[issuer] obfs-обёртка канала: {} (probe-resistance issuer-порта, A1-остаток)",
        if obfs_psk.is_some() { "включена" } else { "выкл (голый TLS)" }
    );

    // C7.1: admin-канал (управление реестром по PQ-TLS: domain-sep Ed25519 + EKM channel binding).
    // Отдельный listener — в деплое наружу НЕ публикуется (доступ только из туннеля через DNAT
    // exit'а, C7.2). TLS-идентичность общая с token-fetch → pin из ссылки валиден для обоих каналов.
    if let Ok(admin_listen) = std::env::var("Citadel_ADMIN_LISTEN") {
        let scfg = scfg.clone();
        let dir = dir.clone();
        std::thread::spawn(move || {
            let listener = match TcpListener::bind(&admin_listen) {
                Ok(l) => l,
                Err(e) => return eprintln!("[issuer] admin-канал: bind {admin_listen}: {e}"),
            };
            eprintln!("[issuer] admin-канал на {admin_listen} (PQ-TLS+pin, Ed25519 домен+EKM)");
            for conn in listener.incoming() {
                match conn {
                    Ok(tcp) => {
                        let scfg = scfg.clone();
                        let dir = dir.clone();
                        std::thread::spawn(move || {
                            let srv = citadel_token::admin::AdminServer { dir };
                            let r = citadel_token::pqtls::accept_tls(tcp, scfg, obfs_psk)
                                .and_then(|tls| srv.serve_conn(tls));
                            if let Err(e) = r {
                                eprintln!("[issuer] admin-соединение завершено: {e}");
                            }
                        });
                    }
                    Err(e) => eprintln!("[issuer] admin accept: {e}"),
                }
            }
        });
    }

    let e = citadel_token::current_epoch(epoch_secs);
    eprintln!("[issuer] эпоха {e} (длина {epoch_secs}с); генерирую ключ (RSA-{bits}, ~10с)…");
    let (pk, sk) = citadel_token::issuer_keypair(bits)?;
    publish_epoch_pub(&dir, e, &pk)?;
    eprintln!("[issuer] эпоха {e}: pub опубликован → {dir} (sk остаётся в процессе)");
    let state: Arc<Mutex<EpochKey>> = Arc::new(Mutex::new((e, pk, sk)));

    // Фоновая ротация: при смене эпохи генерим новый ключ и публикуем (keygen ВНЕ лока, чтобы
    // не блокировать подписание; прошлый pub оставляем на диске для grace на exit).
    {
        let state = state.clone();
        let dir = dir.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs((epoch_secs / 4).clamp(5, 30)));
            let ce = citadel_token::current_epoch(epoch_secs);
            if ce == state.lock().unwrap().0 {
                continue;
            }
            eprintln!("[issuer] эпоха сменилась → {ce}; ротация ключа…");
            match citadel_token::issuer_keypair(bits) {
                Ok((npk, nsk)) => {
                    if publish_epoch_pub(&dir, ce, &npk).is_ok() {
                        *state.lock().unwrap() = (ce, npk, nsk);
                        eprintln!("[issuer] эпоха {ce}: ключ ротирован, pub опубликован");
                    }
                }
                Err(err) => eprintln!("[issuer] keygen при ротации не удался: {err}"),
            }
        });
    }

    // S2.4/A6: квота выданных токенов на client_id за эпоху (анти-фарминг). Env `Citadel_TOKEN_QUOTA`
    // (default 64 — с запасом на реконнекты нормального абонента, но режет массовую раздачу).
    let max_per_epoch: u32 =
        std::env::var("Citadel_TOKEN_QUOTA").ok().and_then(|s| s.parse().ok()).unwrap_or(64);
    let quota: Arc<Mutex<QuotaMap>> = Arc::new(Mutex::new(HashMap::new()));
    eprintln!("[issuer] квота выдачи: {max_per_epoch} токен(ов) на абонента в эпоху (A6)");

    // Задача 4 (вариант B): мягкий single-session — client_id получает новую выдачу не чаще раза в
    // `Citadel_TOKEN_LEASE_SECS` (0 = выкл). Ограничивает параллельные сессии с одной ссылки;
    // компромисс — реконнект в пределах окна ждёт истечения аренды (см. `lease_grant`).
    let lease_secs: u64 =
        std::env::var("Citadel_TOKEN_LEASE_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let lease: Arc<Mutex<LeaseMap>> = Arc::new(Mutex::new(HashMap::new()));
    eprintln!(
        "[issuer] single-session (задача 4/B): {}",
        if lease_secs == 0 { "выкл".into() } else { format!("аренда {lease_secs}с на абонента") }
    );

    let listen = std::env::var("Citadel_TOKEN_LISTEN").unwrap_or_else(|_| "0.0.0.0:7000".into());
    let listener = TcpListener::bind(&listen).with_context(|| format!("bind {listen}"))?;
    eprintln!("[issuer] слепое подписание на {listen} (blind RSA-{bits}, epoch-scoped, PQ-TLS+pin)");
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let state = state.clone();
                let dir = dir.clone();
                let scfg = scfg.clone();
                let quota = quota.clone();
                let lease = lease.clone();
                std::thread::spawn(move || {
                    if let Err(e) = serve_client(
                        stream, scfg, &state, &dir, &quota, max_per_epoch, &lease, lease_secs,
                        obfs_psk,
                    ) {
                        eprintln!("[issuer] соединение завершено: {e}");
                    }
                });
            }
            Err(e) => eprintln!("[issuer] accept: {e}"),
        }
    }
    Ok(())
}

/// S2.4/A6: под локом решить, можно ли выдать ещё один токен `client_id` в `epoch` (инкрементит
/// счётчик). Смена эпохи сбрасывает счётчик. `false` → квота исчерпана. Чистая логика (тестируемо).
fn quota_grant(
    map: &mut QuotaMap,
    client_id: [u8; 32],
    epoch: u64,
    max: u32,
) -> bool {
    let e = map.entry(client_id).or_insert((epoch, 0));
    if e.0 != epoch {
        *e = (epoch, 0); // новая эпоха → сброс
    }
    if e.1 >= max {
        return false;
    }
    e.1 += 1;
    true
}

/// Задача 4 (вариант B): под локом решить, можно ли НАЧАТЬ новую выдачу `client_id` (одна ссылка →
/// одна свежая сессия в окне `lease_secs`). `lease_secs == 0` → механизм выключен (всегда `true`).
/// Иначе: если предыдущая выдача ещё «активна» (`now < expiry`) → `false` (второе устройство / слишком
/// частый реконнект отклоняются); иначе ставим новую аренду `now + lease_secs` и разрешаем. Чистая
/// логика (тестируемо). NB: уже поднятая QUIC-сессия живёт независимо — это МЯГКИЙ контроль (лимит
/// на открытие новых параллельных сессий), не жёсткий kill уже активной (тот требует exit-tracking
/// → слом unlinkability, отвергнут в пользу B).
fn lease_grant(map: &mut LeaseMap, client_id: [u8; 32], now: u64, lease_secs: u64) -> bool {
    if lease_secs == 0 {
        return true;
    }
    match map.get(&client_id) {
        Some(&expiry) if now < expiry => false, // аренда ещё активна — новую сессию не открываем
        _ => {
            map.insert(client_id, now + lease_secs);
            true
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn serve_client(
    tcp: TcpStream,
    scfg: Arc<rustls::ServerConfig>,
    state: &Mutex<EpochKey>,
    dir: &str,
    quota: &Mutex<QuotaMap>,
    max_per_epoch: u32,
    lease: &Mutex<LeaseMap>,
    lease_secs: u64,
    obfs_psk: Option<[u8; 32]>,
) -> Result<()> {
    let peer = tcp.peer_addr().ok();
    // S2.1/A1: поднять PQ-TLS поверх TCP ДО любого обмена — Layer-1 и слепая выдача идут в шифре
    // с целостностью; клиент уже спиннил серт (MITM не подставит свои blind_msg, client_id скрыт).
    let mut conn = citadel_token::pqtls::accept_tls(tcp, scfg, obfs_psk)?;
    // C5.2 Layer-1: challenge-response ДО слепой подписи (аутентификация «абонента»).
    let challenge: [u8; 32] = rand::random();
    write_frame(&mut conn, &challenge)?;
    let auth = read_frame(&mut conn)?; // ожидаем pub(32) ‖ sig(64)
    if auth.len() != 96 {
        anyhow::bail!("Layer-1: плохой auth-кадр ({} б, ожидалось 96)", auth.len());
    }
    let (pk, sig) = (&auth[..32], &auth[32..]);
    if !citadel_token::ed25519_verify(pk, &challenge, sig) {
        anyhow::bail!("Layer-1: подпись челленджа неверна (client {peer:?})");
    }
    if !registry_allows(dir, pk, now_unix()) {
        anyhow::bail!("Layer-1: client_id не активен/истёк/отозван — отказ (client {peer:?})");
    }
    let client_id: [u8; 32] = pk.try_into().expect("pk = auth[..32], ровно 32 байта");
    eprintln!("[issuer] Layer-1 ✔ абонент {}… авторизован", &hex::encode(pk)[..12]);
    // Задача 4/B (мягкий single-session): аренда client_id ещё активна → отклоняем новую выдачу
    // (второе устройство с той же ссылки / слишком частый реконнект). Клиент получит 0 токенов →
    // establish без токена → exit откажет → клиент подождёт истечения аренды и переподключится.
    // Закрываем соединение ДО отправки epoch-pub (ничего лишнего не раскрываем).
    if !lease_grant(&mut lease.lock().unwrap(), client_id, now_unix(), lease_secs) {
        eprintln!(
            "[issuer] single-session (4/B): {}… держит активную аренду — новая сессия отклонена",
            &hex::encode(client_id)[..12]
        );
        return Ok(());
    }
    // C5.3: отдаём клиенту ТЕКУЩИЙ epoch-pub (клиент ослепляет под актуальным ключом).
    let cur_pub = state.lock().unwrap().1.clone();
    write_frame(&mut conn, &cur_pub)?;

    let mut n = 0u32;
    // клиент закрыл соединение → read_frame вернёт Err → выходим из цикла
    while let Ok(blind_msg) = read_frame(&mut conn) {
        // S2.4/A6: квота токенов на client_id за эпоху. Без неё один «абонемент» чеканил бы
        // неограниченно токенов → раздача безлимиту фрирайдеров за эпоху (epoch+double-spend
        // режут повтор ОДНОГО токена, но не число разных). Счётчик per-(client_id, эпоха),
        // сбрасывается со сменой эпохи. In-RAM (как spent-set exit'а): рестарт обнуляет, но
        // квота epoch-bounded. Достигнут потолок → прекращаем выдачу этому клиенту в эту эпоху.
        let cur_epoch = state.lock().unwrap().0;
        if !quota_grant(&mut quota.lock().unwrap(), client_id, cur_epoch, max_per_epoch) {
            eprintln!(
                "[issuer] квота исчерпана: {}… уже получил {max_per_epoch} токен(ов) в эпоху {cur_epoch} — стоп",
                &hex::encode(client_id)[..12]
            );
            break;
        }
        // sk текущей эпохи (клонируем, чтобы не держать лок во время RSA-подписи)
        let sk = state.lock().unwrap().2.clone();
        let blind_sig = citadel_token::issuer_blind_sign(&sk, &blind_msg)?;
        write_frame(&mut conn, &blind_sig)?;
        n += 1;
    }
    eprintln!("[issuer] клиент {peer:?}: подписано вслепую {n} токен(ов)");
    Ok(())
}

/// Клиент: интерактивно получает N токенов от издателя (blind→sign→finalize), пишет в файл.
fn run_client_fetch() -> Result<()> {
    let issuer = std::env::var("Citadel_TOKEN_ISSUER").context("Citadel_TOKEN_ISSUER не задан")?;
    // C5.2 Layer-1: seed «абонента» (= приватный Ed25519) — обязателен для авторизации у issuer.
    let seed: [u8; 32] = std::env::var("Citadel_CLIENT_SEED")
        .ok()
        .and_then(|s| hex::decode(s.trim()).ok())
        .and_then(|v| v.try_into().ok())
        .context("Citadel_CLIENT_SEED (32 байта hex) обязателен для Layer-1")?;
    // S2.1/A1: pin TLS-серта издателя — обязателен (fail-closed: без него канал был бы MITM-открыт).
    let issuer_pin: [u8; 32] = std::env::var("Citadel_ISSUER_PIN")
        .ok()
        .and_then(|s| hex::decode(s.trim()).ok())
        .and_then(|v| v.try_into().ok())
        .context("Citadel_ISSUER_PIN (32 байта hex) обязателен для PQ-TLS канала к издателю")?;
    let count = token_count();
    let dir = token_dir();
    // S2.1/A1-остаток: obfs-обёртка канала (probe-resistance) — PSK из env, обязан совпасть с issuer.
    let obfs_psk = obfs_psk_from_env();
    eprintln!("[client] Layer-1 issuance у издателя {issuer} ({count} токенов, PQ-TLS+pin{}, blind epoch-scoped)…",
        if obfs_psk.is_some() { "+obfs" } else { "" });
    // C5.3: весь протокол (Layer-1 auth + получение текущего epoch-pub + слепая выдача) — в citadel_token.
    let tokens = citadel_token::fetch_tokens(&issuer, &issuer_pin, &seed, count, 20, obfs_psk)?;

    let mut f = std::fs::File::create(format!("{dir}/tokens")).context("запись tokens")?;
    for t in &tokens {
        writeln!(f, "{}", hex::encode(t))?;
    }
    eprintln!("[client] получено {} токенов → {dir}/tokens (издатель их НЕ видел → unlinkable)", tokens.len());
    Ok(())
}

/// C5.4: печатает Ed25519 pub (hex) для `Citadel_CLIENT_SEED` — для добавления в реестр issuer'а
/// (admin, C5.5) или e2e-тестов отзыва. pub = client_id «абонента».
fn run_pubkey() -> Result<()> {
    let seed: [u8; 32] = std::env::var("Citadel_CLIENT_SEED")
        .ok()
        .and_then(|s| hex::decode(s.trim()).ok())
        .and_then(|v| v.try_into().ok())
        .context("Citadel_CLIENT_SEED (32 байта hex)")?;
    println!("{}", hex::encode(citadel_token::ed25519_pub_from_seed(&seed)?));
    Ok(())
}

/// Legacy: выпуск пачки токенов в одном процессе → файлы (локальное демо/тесты, без сети).
fn run_batch() -> Result<()> {
    let count = token_count();
    let dir = token_dir();
    eprintln!("[issuer:batch] выпускаю {count} токенов (blind RSA-2048) → {dir}");
    let issued = citadel_token::issue_batch(count, 2048)?;
    std::fs::write(format!("{dir}/issuer.pub"), &issued.pk_der).context("запись issuer.pub")?;
    let mut f = std::fs::File::create(format!("{dir}/tokens")).context("запись tokens")?;
    for t in &issued.tokens {
        writeln!(f, "{}", hex::encode(t))?;
    }
    eprintln!("[issuer:batch] готово: issuer.pub + {} токенов", issued.tokens.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::merge_registry;

    /// C5.4b: bootstrap НЕ воскрешает отозванного абонента при рестарте (сохраняет `revoked`),
    /// новый pub добавляется как `active`, дубликатов нет.
    #[test]
    fn merge_preserves_revoked_and_adds_new() {
        let pk_a = [0xAAu8; 32];
        let pk_b = [0xBBu8; 32];
        let hex_a = hex::encode(pk_a);
        let hex_b = hex::encode(pk_b);
        // Реестр после admin-revoke абонента A.
        let existing = format!("{hex_a} 9999999999 revoked\n");
        // Рестарт: bootstrap снова несёт A (уже отозванного) и нового B.
        let merged = merge_registry(&existing, &[pk_a, pk_b], 8888888888);
        assert!(merged.contains(&format!("{hex_a} 9999999999 revoked")), "A остаётся revoked");
        assert_eq!(merged.matches(&hex_a).count(), 1, "A не продублирован (не воскрешён active)");
        assert!(merged.contains(&format!("{hex_b} 8888888888 active")), "B добавлен active");
    }

    /// Повторный bootstrap тех же pub'ов идемпотентен (вывод не растёт/не меняется).
    #[test]
    fn merge_is_idempotent() {
        let pk = [0x11u8; 32];
        let first = merge_registry("", &[pk], 100);
        let second = merge_registry(&first, &[pk], 200);
        assert_eq!(first, second);
    }

    // ── C5.5 admin-CLI реестра: тесты registry_apply_* переехали в citadel_token::admin (C7.1) ──

    /// S2.4/A6: квота на client_id за эпоху — до потолка выдаём, дальше отказ; смена эпохи сбрасывает;
    /// разные client_id учитываются раздельно.
    #[test]
    fn quota_grant_caps_per_epoch() {
        use super::quota_grant;
        let mut m = std::collections::HashMap::new();
        let a = [0xAAu8; 32];
        let b = [0xBBu8; 32];
        // до потолка (3) — выдаём
        assert!(quota_grant(&mut m, a, 100, 3));
        assert!(quota_grant(&mut m, a, 100, 3));
        assert!(quota_grant(&mut m, a, 100, 3));
        // потолок достигнут — отказ
        assert!(!quota_grant(&mut m, a, 100, 3));
        // другой абонент — свой счётчик
        assert!(quota_grant(&mut m, b, 100, 3));
        // смена эпохи сбрасывает счётчик a
        assert!(quota_grant(&mut m, a, 101, 3));
        assert!(quota_grant(&mut m, a, 101, 3));
    }

    /// Задача 4/B: аренда client_id блокирует новую выдачу в окне; истекла → снова разрешена;
    /// `lease_secs == 0` — механизм выключен (всегда разрешает).
    #[test]
    fn lease_grant_single_session_window() {
        use super::lease_grant;
        let mut m = std::collections::HashMap::new();
        let a = [0xAAu8; 32];
        let b = [0xBBu8; 32];
        // первая выдача в now=1000, аренда 300с (до 1300)
        assert!(lease_grant(&mut m, a, 1000, 300));
        // повторная попытка в окне (now=1100 < 1300) — отказ (второе устройство/частый реконнект)
        assert!(!lease_grant(&mut m, a, 1100, 300));
        assert!(!lease_grant(&mut m, a, 1299, 300));
        // другой абонент — своя аренда, не задет
        assert!(lease_grant(&mut m, b, 1100, 300));
        // аренда истекла (now=1300 >= expiry) — снова разрешено (реконнект после окна)
        assert!(lease_grant(&mut m, a, 1300, 300));
        // выключено (lease_secs=0) — всегда true, карта не растёт
        let mut off = std::collections::HashMap::new();
        assert!(lease_grant(&mut off, a, 1, 0));
        assert!(lease_grant(&mut off, a, 1, 0));
        assert!(off.is_empty());
    }

    /// valid_until: относительные формы и абсолют.
    #[test]
    fn valid_until_forms() {
        let now = super::now_unix();
        assert_eq!(super::parse_valid_until(Some("1700000000")).unwrap(), 1_700_000_000);
        let d = super::parse_valid_until(Some("+2d")).unwrap();
        assert!((d as i64 - (now as i64 + 2 * 24 * 3600)).abs() <= 2);
        let h = super::parse_valid_until(Some("+3h")).unwrap();
        assert!((h as i64 - (now as i64 + 3 * 3600)).abs() <= 2);
        let def = super::parse_valid_until(None).unwrap();
        assert!((def as i64 - (now as i64 + 365 * 24 * 3600)).abs() <= 2);
        assert!(super::parse_valid_until(Some("+bad")).is_err());
    }
}
