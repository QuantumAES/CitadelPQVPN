//! citadel-token — роли анонимного issuance (M5, issuer↔exit split).
//!
//! Режим (env `Citadel_TOKEN_ROLE` или arg[1]):
//!   `issuer` — сгенерировать ключ, опубликовать issuer.pub, слушать TCP и подписывать ВСЛЕПУЮ
//!              (издатель видит только blind_msg, не токен). sk остаётся в процессе.
//!   `client` — подключиться к издателю, интерактивно получить N токенов (blind→sign→finalize),
//!              записать в файл. Издатель не может связать выданное с предъявленным на exit.
//!   `batch`  — (legacy) выпустить N токенов в одном процессе → файл (для локального демо/тестов).
//!
//! Сетевой формат: кадр `u32(len, BE) ‖ payload`; запрос — blind_msg, ответ — blind_sig.

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use citadel_token::{read_frame, write_frame}; // C5.3: фрейминг вынесен в lib (переиспользует fetch_tokens)

fn token_dir() -> String {
    std::env::var("Citadel_TOKEN_DIR").unwrap_or_else(|_| "/shared".into())
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
fn registry_allows(dir: &str, pub_key: &[u8], now: u64) -> bool {
    let want = hex::encode(pub_key);
    let Ok(content) = std::fs::read_to_string(registry_path(dir)) else {
        return false; // нет реестра → никто не авторизован (secure default)
    };
    for line in content.lines() {
        let mut it = line.split_whitespace();
        if let (Some(p), Some(vu), Some(st)) = (it.next(), it.next(), it.next()) {
            if p == want {
                return st == "active" && now < vu.parse::<u64>().unwrap_or(0);
            }
        }
    }
    false
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
/// старый ИЛИ новый файл, не частичный.
fn run_registry(args: &[String]) -> Result<()> {
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

/// Upsert строки реестра: если pub уже есть — заменяем (новый valid_until, статус `active`, в т.ч.
/// «разотзыв»); иначе добавляем. Прочие строки сохраняются, дубликаты pub схлопываются, пустые
/// строки убираются. Чистая логика (тестируемо, без I/O).
fn registry_apply_add(existing: &str, pk: &[u8; 32], valid_until: u64) -> String {
    let hexpk = hex::encode(pk);
    let mut out = String::new();
    let mut done = false;
    for line in existing.lines() {
        if line.split_whitespace().next() == Some(hexpk.as_str()) {
            if !done {
                out.push_str(&format!("{hexpk} {valid_until} active\n"));
                done = true;
            }
        } else if !line.trim().is_empty() {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !done {
        out.push_str(&format!("{hexpk} {valid_until} active\n"));
    }
    out
}

/// Отзыв: у строки pub статус → `revoked` (valid_until сохраняется). Если pub нет — ошибка
/// (нечего отзывать; защищает от опечатки в client_id). Чистая логика.
fn registry_apply_revoke(existing: &str, pk: &[u8; 32]) -> Result<String> {
    let hexpk = hex::encode(pk);
    let mut out = String::new();
    let mut found = false;
    for line in existing.lines() {
        let mut it = line.split_whitespace();
        if it.next() == Some(hexpk.as_str()) {
            if !found {
                let vu = it.next().unwrap_or("0");
                out.push_str(&format!("{hexpk} {vu} revoked\n"));
                found = true;
            }
        } else if !line.trim().is_empty() {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !found {
        anyhow::bail!("client_id {hexpk} не найден в реестре — нечего отзывать");
    }
    Ok(out)
}

/// Атомарная запись файла реестра: temp в том же каталоге + rename (POSIX-атомарно на одной ФС).
fn atomic_write(path: &str, content: &str) -> Result<()> {
    let tmp = format!("{path}.tmp.{}", std::process::id());
    std::fs::write(&tmp, content).with_context(|| format!("запись {tmp}"))?;
    std::fs::rename(&tmp, path).with_context(|| format!("rename {tmp} → {path}"))?;
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    // C5.5 admin-CLI управления реестром — оффлайн-операция админа (add/revoke/list), не сетевая
    // роль, поэтому маршрутизируем по arg[1] ДО env-роли (Citadel_TOKEN_ROLE её не задаёт).
    if args.get(1).map(String::as_str) == Some("registry") {
        return run_registry(&args);
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

    let listen = std::env::var("Citadel_TOKEN_LISTEN").unwrap_or_else(|_| "0.0.0.0:7000".into());
    let listener = TcpListener::bind(&listen).with_context(|| format!("bind {listen}"))?;
    eprintln!("[issuer] слепое подписание на {listen} (blind RSA-{bits}, epoch-scoped)");
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let state = state.clone();
                let dir = dir.clone();
                std::thread::spawn(move || {
                    if let Err(e) = serve_client(stream, &state, &dir) {
                        eprintln!("[issuer] соединение завершено: {e}");
                    }
                });
            }
            Err(e) => eprintln!("[issuer] accept: {e}"),
        }
    }
    Ok(())
}

fn serve_client(mut conn: TcpStream, state: &Mutex<EpochKey>, dir: &str) -> Result<()> {
    let peer = conn.peer_addr().ok();
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
    eprintln!("[issuer] Layer-1 ✔ абонент {}… авторизован", &hex::encode(pk)[..12]);
    // C5.3: отдаём клиенту ТЕКУЩИЙ epoch-pub (клиент ослепляет под актуальным ключом).
    let cur_pub = state.lock().unwrap().1.clone();
    write_frame(&mut conn, &cur_pub)?;

    let mut n = 0u32;
    // клиент закрыл соединение → read_frame вернёт Err → выходим из цикла
    while let Ok(blind_msg) = read_frame(&mut conn) {
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
    let count = token_count();
    let dir = token_dir();
    eprintln!("[client] Layer-1 issuance у издателя {issuer} ({count} токенов, blind epoch-scoped)…");
    // C5.3: весь протокол (Layer-1 auth + получение текущего epoch-pub + слепая выдача) — в citadel_token.
    let tokens = citadel_token::fetch_tokens(&issuer, &seed, count, 20)?;

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

    // ── C5.5 admin-CLI реестра ──

    /// add в пустой реестр, затем add того же pub «разотзывает» и обновляет срок; чужие строки целы.
    #[test]
    fn registry_add_upsert_and_unrevoke() {
        let a = [0xAAu8; 32];
        let b = [0xBBu8; 32];
        let ha = hex::encode(a);
        let hb = hex::encode(b);
        // старт: A revoked, B active (B — «чужая» строка, не должна пострадать)
        let start = format!("{ha} 100 revoked\n{hb} 200 active\n");
        let out = super::registry_apply_add(&start, &a, 500);
        assert!(out.contains(&format!("{ha} 500 active")), "A обновлён и разотозван");
        assert!(out.contains(&format!("{hb} 200 active")), "B не тронут");
        assert_eq!(out.matches(&ha).count(), 1, "A без дубликатов");
    }

    /// add схлопывает дубликаты одного pub в одну строку.
    #[test]
    fn registry_add_dedups() {
        let a = [0x77u8; 32];
        let ha = hex::encode(a);
        let start = format!("{ha} 1 active\n{ha} 2 revoked\n");
        let out = super::registry_apply_add(&start, &a, 9);
        assert_eq!(out, format!("{ha} 9 active\n"));
    }

    /// revoke переводит статус в revoked, сохраняя valid_until; отсутствующий pub → ошибка.
    #[test]
    fn registry_revoke_and_missing() {
        let a = [0xCCu8; 32];
        let ha = hex::encode(a);
        let ok = super::registry_apply_revoke(&format!("{ha} 42 active\n"), &a).unwrap();
        assert_eq!(ok, format!("{ha} 42 revoked\n"), "срок сохранён, статус revoked");
        assert!(super::registry_apply_revoke("", &a).is_err(), "нет pub → ошибка");
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
