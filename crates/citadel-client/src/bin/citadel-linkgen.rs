//! `citadel-linkgen` — генератор `citadel://`-ссылки под exit: печатает компактную ссылку в stdout,
//! опционально QR-SVG. Token-less / без PQ-auth (mldsa). Шипается в релизе рядом с `citadel-m1` и
//! вызывается серверным installer-скриптом (C4) для выдачи админской ссылки после развёртывания.
//!
//! ```text
//! citadel-linkgen --servers "1.2.3.4:4433" --psk <hex64|passphrase> --pin <hex64> \
//!   [--kx all] [--tcp-port 443] [--routes "1.1.1.1/32 1.0.0.1/32"] \
//!   [--dns 1.1.1.1] [--server-name citadel.exit] [--qr link.svg]
//! ```
//! `--psk` — passphrase (BLAKE3-derive, как на exit) или 64-hex; `--pin` — hex из exit.pin.

use std::collections::HashMap;

use citadel_client::{parse_obfs_psk, parse_pin, CredentialBundle, CredentialLink, BUNDLE_VERSION};

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let mut m = HashMap::new();
    let mut i = 1;
    while i + 1 < argv.len() {
        m.insert(argv[i].clone(), argv[i + 1].clone());
        i += 2;
    }
    let get = |k: &str| m.get(k).cloned();

    let servers: Vec<String> = get("--servers")
        .unwrap_or_default()
        .split_whitespace()
        .map(String::from)
        .collect();
    if servers.is_empty() {
        eprintln!("нужен --servers \"host:port ...\" (например 1.2.3.4:4433)");
        std::process::exit(1);
    }

    let bundle = CredentialBundle {
        version: BUNDLE_VERSION,
        servers,
        server_name: get("--server-name").unwrap_or_else(|| "citadel.exit".into()),
        kx_suite: get("--kx").unwrap_or_else(|| "pq".into()),
        cert_pin: get("--pin").as_deref().and_then(parse_pin),
        mldsa_pub: None, // token-less: PQ-auth не требуется (mldsa=None)
        obfs_psk: get("--psk").as_deref().and_then(parse_obfs_psk),
        tcp_port: Some(get("--tcp-port").unwrap_or_else(|| "443".into())),
        issuer: None, // token-less exit
        issuer_pub: None,
        client_seed: None,
        routes: get("--routes").unwrap_or_default(),
        dns: get("--dns"),
    };

    let link = CredentialLink::from_bundle(&bundle);
    let uri = link.to_uri().expect("to_uri");
    println!("{uri}");
    eprintln!(
        "[linkgen] servers={:?} pin={} psk={} routes={:?}",
        bundle.servers,
        if bundle.cert_pin.is_some() { "да" } else { "НЕТ (no-pin, PoC)" },
        if bundle.obfs_psk.is_some() { "да" } else { "НЕТ" },
        bundle.routes,
    );
    if let Some(qr) = get("--qr") {
        std::fs::write(&qr, link.to_qr_svg().expect("qr")).expect("write qr");
        eprintln!("[linkgen] QR-SVG → {qr}");
    }
}
