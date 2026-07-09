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

/// Bootstrap (демо): зарегистрировать pub'ы seed'ов из `Citadel_REGISTER_SEEDS` (hex, через пробел)
/// как active на +10 лет. В проде реестром управляет админ (C5.5) — правит файл напрямую.
fn bootstrap_registry(dir: &str) -> Result<()> {
    let Ok(seeds) = std::env::var("Citadel_REGISTER_SEEDS") else {
        return Ok(());
    };
    let far = now_unix() + 10 * 365 * 24 * 3600;
    let mut reg = String::new();
    for s in seeds.split_whitespace() {
        let seed: [u8; 32] = hex::decode(s)
            .ok()
            .and_then(|v| v.try_into().ok())
            .context("Citadel_REGISTER_SEEDS: seed должен быть 32 байта hex")?;
        let pk = citadel_token::ed25519_pub_from_seed(&seed)?;
        reg.push_str(&format!("{} {far} active\n", hex::encode(pk)));
    }
    std::fs::write(registry_path(dir), &reg).context("запись реестра")?;
    eprintln!("[issuer] реестр Layer-1: {} абонент(ов) активны (Citadel_REGISTER_SEEDS)", reg.lines().count());
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let role = std::env::var("Citadel_TOKEN_ROLE")
        .ok()
        .or_else(|| args.get(1).cloned())
        .unwrap_or_else(|| "batch".into());
    match role.as_str() {
        "issuer" | "serve" => run_issuer(),
        "client" | "fetch" => run_client_fetch(),
        "pubkey" => run_pubkey(),
        "batch" => run_batch(),
        other => Err(anyhow::anyhow!("Citadel_TOKEN_ROLE должен быть issuer|client|pubkey|batch, а не {other:?}")),
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
