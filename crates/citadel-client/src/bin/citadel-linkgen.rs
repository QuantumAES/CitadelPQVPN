//! `citadel-linkgen` — генератор `citadel://`-ссылки под exit: печатает компактную ссылку в stdout,
//! опционально QR-SVG. Шипается в релизе рядом с `citadel-m1` и вызывается серверным
//! installer-скриптом (C4/C5.4b) для выдачи админской ссылки после развёртывания.
//!
//! ```text
//! citadel-linkgen --servers "1.2.3.4:4433" --psk <hex64> --pin <hex64> \
//!   [--activate-secs 86400] \
//!   [--kx all] [--tcp-port 443] [--routes "1.1.1.1/32 1.0.0.1/32"] \
//!   [--dns 1.1.1.1] [--server-name citadel.exit] [--qr link.svg] \
//!   [--issuer host:7000] [--issuer-pin <hex64>] [--issuer-mldsa <hex64>] [--client-seed <hex64>] \
//!   [--mldsa-pub exit.mldsa] [--admin-seed <hex64>] [--admin-port 7001]
//! ```
//! C7.2 admin-плоскость: `--admin-seed` (hex64, отдельный Ed25519 админа — НЕ равен client-seed) +
//! опц. `--admin-port` (дефолт 7001) делают ссылку МАСТЕР-ссылкой (управление реестром абонентов по
//! туннелю, см. citadel-token::admin). Клиентские ссылки эти флаги НЕ несут — иначе абонент получил
//! бы admin-права. v3-формат: ссылки без admin-полей читаются старым клиентом как v2 (serde default).
//! `--psk` — 64-hex (ровно 32 байта, как на exit; M-7 — фразы не принимаются); `--pin` — hex из exit.pin.
//! C5.4b двухслойная идентичность: `--issuer` (host:port издателя) + `--issuer-pin` (hex из
//! issuer-tls.pin, S2.1/A1 — клиент пиннит PQ-TLS канал) + `--client-seed` (hex64,
//! приватный Ed25519 «абонента») → GUI авто-фетчит epoch-токен перед коннектом. Пара к выдаче —
//! регистрация абонента у issuer: `citadel-token registry add-seed <тот же seed>` (C5.5). `--mldsa-pub` —
//! файл ML-DSA-65 pub exit'а (M7): в ссылку кладётся обязательство `H(pub)` (client-enforcement
//! ждёт commitment-fetch, см. SECURITY-ROADMAP §S3/creds).

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

    // C5.4b: ML-DSA-65 pub exit'а (M7) — из файла (1952 B). В ссылку пойдёт обязательство H(pub).
    let mldsa_pub = get("--mldsa-pub").map(|f| {
        std::fs::read(&f).unwrap_or_else(|e| {
            eprintln!("не прочитать --mldsa-pub {f}: {e}");
            std::process::exit(1);
        })
    });

    let bundle = CredentialBundle {
        version: BUNDLE_VERSION,
        servers,
        server_name: get("--server-name").unwrap_or_else(|| "citadel.exit".into()),
        kx_suite: get("--kx").unwrap_or_else(|| "pq".into()),
        cert_pin: get("--pin").as_deref().and_then(parse_pin),
        mldsa_pub, // M7 PQ-auth: Some → ссылка несёт H(pub); None → token-less по ML-DSA
        // M-7: PSK принимается только как 64 hex. Раньше сюда годилась любая строка (BLAKE3 в
        // один проход), и ссылка молча уносила слабый ключ; теперь негодное значение — отказ.
        obfs_psk: get("--psk").map(|v| {
            parse_obfs_psk(&v).unwrap_or_else(|| {
                eprintln!(
                    "--psk: ожидаются ровно 64 hex-символа (32 байта). Парольные фразы больше не \
                     принимаются: они выводились в ключ одним проходом BLAKE3 (M-7)"
                );
                std::process::exit(1);
            })
        }),
        tcp_port: Some(get("--tcp-port").unwrap_or_else(|| "443".into())),
        // C5.4b Layer-1: issuer host:port + client_seed (hex64 → [u8;32], та же кодировка, что pin).
        issuer: get("--issuer"),
        issuer_pub: None, // клиент дотягивает issuer_pub по каналу при фетче (не нужен в ссылке)
        // S2.1/A1: pin TLS-серта издателя (из issuer-tls.pin) — клиент пиннит PQ-TLS канал фетча.
        issuer_pin: get("--issuer-pin").as_deref().and_then(parse_pin),
        // PQ: обязательство к ML-DSA-идентичности издателя (из issuer-mldsa.pin).
        issuer_mldsa: get("--issuer-mldsa").as_deref().and_then(parse_pin),
        client_seed: get("--client-seed").as_deref().and_then(parse_pin),
        // C7.2: admin-плоскость — только для МАСТЕР-ссылки. `--admin-seed` (hex64, отдельный Ed25519,
        // не равен client-seed) + опц. `--admin-port` (дефолт 7001). Клиентские ссылки эти флаги НЕ несут.
        admin_seed: get("--admin-seed").as_deref().and_then(parse_pin),
        admin_port: get("--admin-port"),
        routes: get("--routes").unwrap_or_default(),
        dns: get("--dns"),
        // M-9: окно активации первичной ссылки. `--activate-secs N` делает ссылку ОДНОРАЗОВОЙ:
        // она годна N секунд и активируется на одном устройстве. Без флага ссылка прежняя
        // (многоразовая) — так печатаются ссылки самой установки, которыми оператор заводит своё
        // устройство и админ-доступ; абонентские ссылки выдаёт admin-плоскость, и там окно есть
        // всегда (см. `citadel_client::admin::admin_issue`).
        exp: get("--activate-secs")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|s| *s > 0)
            .map(|s| now_unix() + s),
        enroll: false, // выставится ниже, если задан --activate-secs
    };
    let mut bundle = bundle;
    bundle.enroll = bundle.exp.is_some();

    let link = CredentialLink::from_bundle(&bundle);
    let uri = link.to_uri().expect("to_uri");
    println!("{uri}");
    if bundle.issuer.is_some() && bundle.issuer_pin.is_none() {
        eprintln!("[linkgen] ⚠ --issuer задан БЕЗ --issuer-pin — клиент не сможет безопасно фетчить токен (A1)");
    }
    if bundle.issuer.is_some() && bundle.issuer_mldsa.is_none() {
        eprintln!(
            "[linkgen] ⚠ --issuer задан БЕЗ --issuer-mldsa — клиент ОТКАЖЕТСЯ фетчить токены и \
             открывать admin-канал (PQ-аутентификация издателя обязательна). Возьми hex из \
             issuer-mldsa.pin на томе издателя."
        );
    }
    if bundle.admin_seed.is_some() {
        eprintln!(
            "[linkgen] ⚠ МАСТЕР-ссылка (несёт admin-seed): даёт управление реестром абонентов — \
             НЕ раздавать, только админу. Клиентам генерируй ссылку БЕЗ --admin-seed."
        );
    }
    eprintln!(
        "[linkgen] servers={:?} pin={} psk={} mldsa={} issuer={} issuer-pin={} issuer-mldsa={} layer1-seed={} admin={} routes={:?}",
        bundle.servers,
        if bundle.cert_pin.is_some() { "да" } else { "НЕТ (no-pin, PoC)" },
        if bundle.obfs_psk.is_some() { "да" } else { "НЕТ" },
        if bundle.mldsa_pub.is_some() { "H(pub) в ссылке" } else { "НЕТ" },
        bundle.issuer.as_deref().unwrap_or("НЕТ (token-less)"),
        if bundle.issuer_pin.is_some() { "да" } else { "НЕТ" },
        if bundle.issuer_mldsa.is_some() { "да" } else { "НЕТ" },
        if bundle.client_seed.is_some() { "да" } else { "НЕТ" },
        if bundle.admin_seed.is_some() { format!("МАСТЕР (порт {})", bundle.admin_port.as_deref().unwrap_or("7001")) } else { "нет".into() },
        bundle.routes,
    );
    // M-9: код сверки — короткий отпечаток ссылки, который называют абоненту по другому каналу
    // (голосом), а он сверяет его при импорте. Ловит подмену ссылки при доставке — единственное,
    // чего не может поймать никакая проверка ВНУТРИ самой ссылки.
    if let (Some(code), Some(h)) = (link.verify_code(), link.link_hash()) {
        eprintln!("[linkgen] код сверки: {code}   (продиктуй абоненту отдельно от самой ссылки)");
        eprintln!("[linkgen] отпечаток ссылки: {}", hex::encode(h));
    }
    if let Some(until) = bundle.exp {
        eprintln!(
            "[linkgen] ⚠ ОДНОРАЗОВАЯ ссылка: активировать до {until} (unix), на ОДНОМ устройстве;              после активации копия ссылки бесполезна"
        );
    }
    if let Some(qr) = get("--qr") {
        std::fs::write(&qr, link.to_qr_svg().expect("qr")).expect("write qr");
        eprintln!("[linkgen] QR-SVG → {qr}");
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
