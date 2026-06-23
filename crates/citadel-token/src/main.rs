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
use std::sync::Arc;

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

/// Издатель (биллинг): держит sk, подписывает ослеплённые сообщения вслепую по TCP.
fn run_issuer() -> Result<()> {
    let bits = 2048;
    let (pk_der, sk_der) = citadel_token::issuer_keypair(bits)?;
    let dir = token_dir();
    std::fs::write(format!("{dir}/issuer.pub"), &pk_der).context("запись issuer.pub")?;
    eprintln!("[issuer] ключ сгенерирован; issuer.pub ({} б) → {dir} (sk остаётся в процессе)", pk_der.len());

    let listen = std::env::var("Citadel_TOKEN_LISTEN").unwrap_or_else(|_| "0.0.0.0:7000".into());
    let listener = TcpListener::bind(&listen).with_context(|| format!("bind {listen}"))?;
    eprintln!("[issuer] слепое подписание на {listen} (blind RSA-{bits})");

    let sk = Arc::new(sk_der);
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let sk = sk.clone();
                std::thread::spawn(move || {
                    if let Err(e) = serve_client(stream, &sk) {
                        eprintln!("[issuer] соединение завершено: {e}");
                    }
                });
            }
            Err(e) => eprintln!("[issuer] accept: {e}"),
        }
    }
    Ok(())
}

fn serve_client(mut conn: TcpStream, sk_der: &[u8]) -> Result<()> {
    let peer = conn.peer_addr().ok();
    let mut n = 0u32;
    loop {
        let blind_msg = match read_frame(&mut conn) {
            Ok(b) => b,
            Err(_) => break, // клиент закрыл соединение
        };
        let blind_sig = citadel_token::issuer_blind_sign(sk_der, &blind_msg)?;
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
