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

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};

const MAX_FRAME: usize = 65536;

fn token_dir() -> String {
    std::env::var("Citadel_TOKEN_DIR").unwrap_or_else(|_| "/shared".into())
}
fn token_count() -> usize {
    std::env::var("Citadel_TOKEN_COUNT").ok().and_then(|s| s.parse().ok()).unwrap_or(8)
}

fn write_frame(w: &mut impl Write, data: &[u8]) -> io::Result<()> {
    w.write_all(&(data.len() as u32).to_be_bytes())?;
    w.write_all(data)?;
    w.flush()
}
fn read_frame(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut lb = [0u8; 4];
    r.read_exact(&mut lb)?;
    let len = u32::from_be_bytes(lb) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "плохая длина кадра"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
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
        "batch" => run_batch(),
        other => Err(anyhow::anyhow!("Citadel_TOKEN_ROLE должен быть issuer|client|batch, а не {other:?}")),
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
                std::thread::spawn(move || {
                    if let Err(e) = serve_client(stream, &state) {
                        eprintln!("[issuer] соединение завершено: {e}");
                    }
                });
            }
            Err(e) => eprintln!("[issuer] accept: {e}"),
        }
    }
    Ok(())
}

fn serve_client(mut conn: TcpStream, state: &Mutex<EpochKey>) -> Result<()> {
    let peer = conn.peer_addr().ok();
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
    let count = token_count();
    let dir = token_dir();
    let pk_der = std::fs::read(format!("{dir}/issuer.pub")).context("читаю issuer.pub")?;

    // издатель генерит RSA-ключ ~несколько секунд при старте → ретраим коннект
    let mut conn = None;
    for attempt in 1..=20 {
        match TcpStream::connect(&issuer) {
            Ok(c) => {
                conn = Some(c);
                break;
            }
            Err(e) => {
                eprintln!("[client] издатель {issuer} ещё не готов (попытка {attempt}): {e}");
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }
    let mut conn = conn.with_context(|| format!("издатель {issuer} недоступен"))?;
    eprintln!("[client] получаю {count} токенов от издателя {issuer} (blind issuance)");
    let mut tokens = Vec::with_capacity(count);
    for _ in 0..count {
        let (blind_msg, st) = citadel_token::client_blind(&pk_der)?;
        write_frame(&mut conn, &blind_msg)?;
        let blind_sig = read_frame(&mut conn)?;
        tokens.push(citadel_token::client_finalize(&pk_der, &blind_sig, &st)?);
    }

    let mut f = std::fs::File::create(format!("{dir}/tokens")).context("запись tokens")?;
    for t in &tokens {
        writeln!(f, "{}", hex::encode(t))?;
    }
    eprintln!("[client] получено {} токенов → {dir}/tokens (издатель их НЕ видел → unlinkable)", tokens.len());
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
