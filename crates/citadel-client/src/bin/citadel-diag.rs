//! `citadel-diag` — CLI-прогон диагностики подключения по `citadel://`-ссылке (та же логика,
//! что кнопка «Диагностика» в приложении, [`citadel_client::run_diagnostics`]). Для быстрой
//! проверки exit'а с десктопа/сервера без GUI.
//!
//! ```text
//! citadel-diag "citadel://…"        # или Citadel_LINK=citadel://… citadel-diag
//! ```
//! Печатает по шагу: DNS → QUIC/UDP → TCP(obfs) → establish → egress-через-туннель.

use anyhow::{anyhow, Result};

use citadel_client::{run_diagnostics, CredentialLink};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let link = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("Citadel_LINK").ok())
        .ok_or_else(|| anyhow!("использование: citadel-diag \"citadel://…\"  (или Citadel_LINK=…)"))?;

    let cfg = CredentialLink::from_uri(&link)?.to_client_config();
    eprintln!("[citadel-diag] старт диагностики ({} exit'ов)…\n", cfg.servers.len());

    let mut fails = 0u32;
    run_diagnostics(&cfg, |s| {
        if !s.ok {
            fails += 1;
        }
        println!("[{}] {} — {}", if s.ok { "OK  " } else { "FAIL" }, s.name, s.detail);
    })
    .await;

    println!();
    if fails == 0 {
        println!("[citadel-diag] все проверки пройдены ✔");
        Ok(())
    } else {
        Err(anyhow!("{fails} шаг(ов) не пройдено — см. выше"))
    }
}
