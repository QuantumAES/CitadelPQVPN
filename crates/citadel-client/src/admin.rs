//! C7.3 — клиентское ядро admin-плоскости: управление реестром абонентов ПО ТУННЕЛЮ и локальная
//! выдача клиентских ссылок. Async-обёртка (spawn_blocking) над sync-протоколом
//! `citadel_token::admin` — работает на ВСЕХ платформах (в отличие от SSH-пути C5.5: russh не
//! собирался в мобильный APK).
//!
//! Модель (см. SECURITY-ROADMAP §C7):
//!   - параметры admin-канала (адрес/pin/seed) выводятся из МАСТЕР-ссылки: `admin_seed` +
//!     `issuer_pin` (тот же pin PQ-TLS, что для token-fetch) + `admin_port`; хост фиксирован —
//!     [`ADMIN_VIP`] (шлюз туннеля), поэтому канал достижим только из-под поднятого туннеля;
//!   - выдача нового абонента идёт ЦЕЛИКОМ на устройстве админа: свежий `client_seed` (CSPRNG) →
//!     регистрация ТОЛЬКО pub (client_id) по admin-каналу → клиентская ссылка собирается локально
//!     (мастер-бандл минус admin-поля, с новым seed). Issuer seed не видит (модель C5.4b).
//!
//! Каждая операция самодостаточна: `connect → op → close` (как `fetch_tokens`/бывший SSH-путь) —
//! состояние TLS-сессии между вызовами не удерживается (admin-операции редкие, человеко-инициируемые).

use anyhow::{anyhow, Context, Result};
use zeroize::Zeroize;

use citadel_token::admin::{AdminClient, RegistryEntry, ADMIN_VIP};
use citadel_token::ed25519_pub_from_seed;

use crate::creds::CredentialLink;

/// Запись реестra абонентов для UI (client_id в hex; `active` — удобный флаг).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscriberEntry {
    pub client_id_hex: String,
    pub valid_until_unix: i64,
    pub status: String,
    pub active: bool,
}

impl From<RegistryEntry> for SubscriberEntry {
    fn from(e: RegistryEntry) -> Self {
        Self {
            active: e.status == "active",
            client_id_hex: hex::encode(e.client_id),
            valid_until_unix: e.valid_until as i64,
            status: e.status,
        }
    }
}

/// Результат выдачи нового абонента: его client_id (hex) и готовая клиентская `citadel://`-ссылка.
#[derive(Clone, Debug)]
pub struct IssuedLink {
    pub client_id_hex: String,
    /// Клиентская ссылка (БЕЗ admin-полей) — раздать абоненту (QR/копирование).
    pub uri: String,
}

/// Свежий client-seed из CSPRNG (aws-lc-rs, тот же бэкенд, что vault/движок).
fn random_seed() -> Result<[u8; 32]> {
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};
    let mut s = [0u8; 32];
    SystemRandom::new().fill(&mut s).map_err(|_| anyhow!("CSPRNG"))?;
    Ok(s)
}

/// Параметры аутентификации admin-канала: `(issuer_pin, admin_seed, obfs_psk)`.
type AdminAuth = ([u8; 32], [u8; 32], Option<[u8; 32]>);

/// `(pin, admin_seed, obfs_psk)` из мастер-ссылки. Ошибка, если ссылка не мастер (нет admin-seed) или
/// в ней нет issuer_pin (без него PQ-TLS канал к admin-плоскости был бы MITM-открыт — fail-closed).
/// `obfs_psk` (S2.1/A1-остаток) — тот же, что у туннеля/token-fetch: `Some` → admin-канал обёрнут в
/// obfs (probe-resistance), совпадает с серверной обёрткой; `None` (ссылка без obfs) → голый TLS.
fn admin_auth(master_uri: &str) -> Result<AdminAuth> {
    let link = CredentialLink::from_uri(master_uri).context("разбор мастер-ссылки")?;
    let seed = link
        .admin_seed
        .ok_or_else(|| anyhow!("ссылка не мастер (нет admin-seed) — admin-операции недоступны"))?;
    let pin = link.issuer_pin.ok_or_else(|| {
        anyhow!("в ссылке нет issuer_pin — небезопасный канал к admin-плоскости (A1)")
    })?;
    Ok((pin, seed, link.obfs_psk))
}

/// Адрес admin-канала (host:port) для мастер-ссылки: хост фиксирован [`ADMIN_VIP`] (доступ только
/// из туннеля), порт — из ссылки.
fn admin_addr(master_uri: &str) -> Result<String> {
    let port = CredentialLink::from_uri(master_uri).context("разбор мастер-ссылки")?.admin_port();
    Ok(format!("{ADMIN_VIP}:{port}"))
}

/// Цель диагностической admin-пробы: `(ADMIN_VIP, admin_port)` для МАСТЕР-ссылки. `None` —
/// ссылка клиентская (admin-полей нет) или не парсится, тогда шаг диагностики просто пропускается.
/// Проба (см. `citadel_quic::diag`) шлёт TCP-SYN на этот адрес прямо в туннель, мимо ОС-роутинга.
pub fn admin_probe_dst(master_uri: &str) -> Option<([u8; 4], u16)> {
    let link = CredentialLink::from_uri(master_uri).ok()?;
    link.admin_seed?; // не мастер (нет admin-seed) — admin-канала нет
    let vip: std::net::Ipv4Addr = ADMIN_VIP.parse().ok()?;
    Some((vip.octets(), link.admin_port().parse().ok()?))
}

/// Разобрать client_id (64 hex) в 32 байта.
pub fn parse_client_id(hexstr: &str) -> Result<[u8; 32]> {
    hex::decode(hexstr.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| anyhow!("client_id должен быть 64 hex (32 байта)"))
}

/// `valid_until` для UI → абсолютные unix-секунды. Пусто → `0` (серверный дефолт +365д);
/// `+<N>d`/`+<N>h`/`+<секунды>` — относительно `now`; иначе абсолютные unix-секунды.
pub fn parse_valid_until(s: &str, now: u64) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(0); // сигнал «серверный дефолт»
    }
    if let Some(rest) = s.strip_prefix('+') {
        let (num, mult) = match rest.chars().last() {
            Some('d') => (&rest[..rest.len() - 1], 24 * 3600),
            Some('h') => (&rest[..rest.len() - 1], 3600),
            _ => (rest, 1),
        };
        let n: u64 = num.parse().context("срок: ожидалось +<N>d | +<N>h | +<секунды> | unix")?;
        Ok(now + n * mult)
    } else {
        s.parse().context("срок: unix-секунды или относительное +<N>d")
    }
}

/// Собрать КЛИЕНТСКУЮ ссылку из мастер-ссылки: тот же exit/pin/obfs/issuer, но со СВЕЖИМ
/// `client_seed` и БЕЗ admin-полей (абонент не получает admin-прав). Чистая функция (без сети).
pub fn build_subscriber_link(master_uri: &str, client_seed: &[u8; 32]) -> Result<String> {
    let mut link = CredentialLink::from_uri(master_uri).context("разбор мастер-ссылки")?;
    // затираем admin-seed мастера в этой копии ДО сброса поля (не оставляем секрет в памяти)
    if let Some(mut s) = link.admin_seed.take() {
        s.zeroize();
    }
    link.admin_port = None;
    link.client_seed = Some(*client_seed);
    link.to_uri()
}

// ─────────────────────────── async-операции (spawn_blocking) ───────────────────────────
// Внутренние `*_at` берут явный `addr` (тестируемы против in-process issuer); публичные выводят
// адрес из мастер-ссылки ([`ADMIN_VIP`]).

async fn list_at(
    addr: String,
    pin: [u8; 32],
    seed: [u8; 32],
    obfs_psk: Option<[u8; 32]>,
) -> Result<Vec<SubscriberEntry>> {
    tokio::task::spawn_blocking(move || -> Result<Vec<SubscriberEntry>> {
        let mut c = AdminClient::connect(&addr, &pin, &seed, obfs_psk)?;
        Ok(c.list()?.into_iter().map(SubscriberEntry::from).collect())
    })
    .await
    .context("admin-list задача паникнула")?
}

async fn add_at(
    addr: String,
    pin: [u8; 32],
    seed: [u8; 32],
    obfs_psk: Option<[u8; 32]>,
    client_id: [u8; 32],
    valid_until: u64,
) -> Result<()> {
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut c = AdminClient::connect(&addr, &pin, &seed, obfs_psk)?;
        c.add(client_id, valid_until)
    })
    .await
    .context("admin-add задача паникнула")?
}

async fn revoke_at(
    addr: String,
    pin: [u8; 32],
    seed: [u8; 32],
    obfs_psk: Option<[u8; 32]>,
    client_id: [u8; 32],
) -> Result<()> {
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut c = AdminClient::connect(&addr, &pin, &seed, obfs_psk)?;
        c.revoke(client_id)
    })
    .await
    .context("admin-revoke задача паникнула")?
}

/// Список абонентов реестра (по admin-каналу через туннель).
pub async fn admin_list(master_uri: String) -> Result<Vec<SubscriberEntry>> {
    let (pin, seed, obfs_psk) = admin_auth(&master_uri)?;
    list_at(admin_addr(&master_uri)?, pin, seed, obfs_psk).await
}

/// Отозвать абонента по client_id (hex). Отзыв админом собственного client_id сервер отклонит (R6).
pub async fn admin_revoke(master_uri: String, client_id_hex: String) -> Result<()> {
    let (pin, seed, obfs_psk) = admin_auth(&master_uri)?;
    let cid = parse_client_id(&client_id_hex)?;
    revoke_at(admin_addr(&master_uri)?, pin, seed, obfs_psk, cid).await
}

/// Выдать доступ новому абоненту: свежий seed → регистрация pub по admin-каналу → клиентская ссылка
/// (локально). `valid_until == 0` → серверный дефолт. Возвращает client_id + ссылку для раздачи.
/// Ссылка строится ДО регистрации (валидация мастер-ссылки) — при ошибке сборки в реестр ничего
/// не пишем.
pub async fn admin_issue(master_uri: String, valid_until: u64) -> Result<IssuedLink> {
    let (pin, seed, obfs_psk) = admin_auth(&master_uri)?;
    let addr = admin_addr(&master_uri)?;
    let mut client_seed = random_seed()?;
    let client_id = ed25519_pub_from_seed(&client_seed)?;
    let uri = build_subscriber_link(&master_uri, &client_seed);
    client_seed.zeroize(); // seed уже в ссылке; локальную копию затираем
    let uri = uri?;
    add_at(addr, pin, seed, obfs_psk, client_id, valid_until).await?;
    Ok(IssuedLink { client_id_hex: hex::encode(client_id), uri })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::creds::{CredentialBundle, BUNDLE_VERSION};
    use citadel_token::admin::AdminServer;
    use citadel_token::pqtls;
    use std::net::TcpListener;

    /// Мастер-бандл: exit/pin/issuer/obfs + admin (seed фиксирован для детерминизма теста).
    fn master_bundle(admin_seed: [u8; 32]) -> CredentialBundle {
        CredentialBundle {
            version: BUNDLE_VERSION,
            servers: vec!["exit.example:4433".into()],
            server_name: "citadel.exit".into(),
            kx_suite: "pq".into(),
            cert_pin: Some([1u8; 32]),
            mldsa_pub: Some(vec![2u8; 1952]),
            obfs_psk: Some([3u8; 32]),
            tcp_port: Some("443".into()),
            issuer: Some("exit.example:7000".into()),
            issuer_pub: Some(vec![4u8; 270]),
            issuer_pin: Some([5u8; 32]),
            client_seed: Some([6u8; 32]),
            admin_seed: Some(admin_seed),
            admin_port: Some("7001".into()),
            routes: "0.0.0.0/0".into(),
            dns: Some("1.1.1.1".into()),
        }
    }

    fn master_uri(admin_seed: [u8; 32]) -> String {
        CredentialLink::from_bundle(&master_bundle(admin_seed)).to_uri().unwrap()
    }

    /// build_subscriber_link: клиентская ссылка теряет admin-поля, получает НОВЫЙ seed, сохраняет
    /// exit/pin/obfs/issuer; parse видит её как не-мастер.
    #[test]
    fn subscriber_link_strips_admin_and_swaps_seed() {
        let uri = master_uri([0x77; 32]);
        let new_seed = [0xAB; 32];
        let client_uri = build_subscriber_link(&uri, &new_seed).unwrap();
        let client = CredentialLink::from_uri(&client_uri).unwrap();
        assert!(!client.is_admin(), "клиентская ссылка без admin-прав");
        assert_eq!(client.admin_seed, None);
        assert_eq!(client.admin_port, None);
        assert_eq!(client.client_seed, Some(new_seed), "свежий client-seed");
        // унаследованное от мастера — на месте
        assert_eq!(client.cert_pin, Some([1u8; 32]));
        assert_eq!(client.obfs_psk, Some([3u8; 32]));
        assert_eq!(client.issuer_pin, Some([5u8; 32]));
        assert_eq!(client.servers, vec!["exit.example:4433".to_string()]);
    }

    /// admin_addr / admin_auth выводятся из мастер-ссылки; на не-мастер (клиентской) — ошибка.
    #[test]
    fn conn_params_derived_and_reject_non_master() {
        let uri = master_uri([0x51; 32]);
        assert_eq!(admin_addr(&uri).unwrap(), format!("{ADMIN_VIP}:7001"));
        let (pin, seed, obfs) = admin_auth(&uri).unwrap();
        assert_eq!(pin, [5u8; 32]);
        assert_eq!(seed, [0x51; 32]);
        assert_eq!(obfs, Some([3u8; 32]), "obfs_psk наследуется из мастер-ссылки (A1-остаток)");
        // клиентская ссылка (без admin) → admin_auth отказывает
        let client_uri = build_subscriber_link(&uri, &[9u8; 32]).unwrap();
        assert!(admin_auth(&client_uri).is_err());
    }

    #[test]
    fn valid_until_parsing() {
        let now = 1_000_000u64;
        assert_eq!(parse_valid_until("", now).unwrap(), 0); // дефолт
        assert_eq!(parse_valid_until("1700000000", now).unwrap(), 1_700_000_000);
        assert_eq!(parse_valid_until("+2d", now).unwrap(), now + 2 * 24 * 3600);
        assert_eq!(parse_valid_until("+3h", now).unwrap(), now + 3 * 3600);
        assert!(parse_valid_until("+bad", now).is_err());
    }

    // ── e2e против in-process issuer admin-сервера (тот же путь, что реальный, минус туннель) ──

    fn spawn_admin(dir: &str, conns: usize) -> (String, [u8; 32], std::thread::JoinHandle<()>) {
        let id = pqtls::IssuerIdentity::load_or_generate(dir).unwrap();
        let pin = id.pin;
        let scfg = id.server_config().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let dir = dir.to_string();
        let h = std::thread::spawn(move || {
            for _ in 0..conns {
                let (tcp, _) = listener.accept().unwrap();
                let srv = AdminServer { dir: dir.clone() };
                if let Ok(tls) = pqtls::accept_tls(tcp, scfg.clone(), None) {
                    let _ = srv.serve_conn(tls);
                }
            }
        });
        (addr, pin, h)
    }

    fn tmp_dir(tag: &str) -> String {
        let d = std::env::temp_dir().join(format!("citadel-cliadmin-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d.to_str().unwrap().to_string()
    }

    /// Полный клиентский цикл: issue (свежий seed → регистрация → ссылка) → list видит абонента
    /// active → revoke → list видит revoked. Идёт через реальный async-путь (`*_at`), но с явным
    /// 127.0.0.1-адресом вместо ADMIN_VIP (туннель в юните недоступен).
    #[tokio::test]
    async fn e2e_issue_list_revoke_via_admin_channel() {
        let dir = tmp_dir("e2e");
        let admin_seed = [0x33u8; 32];
        let admin_id = ed25519_pub_from_seed(&admin_seed).unwrap();
        std::fs::write(format!("{dir}/admin_id"), hex::encode(admin_id)).unwrap();
        std::fs::write(format!("{dir}/registry"), "").unwrap();
        let (addr, pin, h) = spawn_admin(&dir, 4); // add + list + revoke + list = 4 коннекта

        let uri = master_uri(admin_seed);
        // issue: сгенерить seed, собрать ссылку, зарегистрировать client_id
        let mut client_seed = random_seed().unwrap();
        let client_id = ed25519_pub_from_seed(&client_seed).unwrap();
        let client_uri = build_subscriber_link(&uri, &client_seed).unwrap();
        client_seed.zeroize();
        add_at(addr.clone(), pin, admin_seed, None, client_id, 0).await.unwrap();
        assert!(CredentialLink::from_uri(&client_uri).unwrap().client_seed.is_some());

        // list: абонент active с дефолтным сроком (+365д)
        let list = list_at(addr.clone(), pin, admin_seed, None).await.unwrap();
        let e = list.iter().find(|e| e.client_id_hex == hex::encode(client_id)).expect("в реестре");
        assert!(e.active && e.status == "active");
        assert!(e.valid_until_unix > 0);

        // revoke → status revoked
        revoke_at(addr.clone(), pin, admin_seed, None, client_id).await.unwrap();
        let after = list_at(addr, pin, admin_seed, None).await.unwrap();
        assert_eq!(
            after.iter().find(|e| e.client_id_hex == hex::encode(client_id)).unwrap().status,
            "revoked"
        );
        h.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Чужой admin-seed (не тот, что записан в admin_id на сервере) → connect отклонён.
    #[tokio::test]
    async fn admin_channel_rejects_wrong_seed() {
        let dir = tmp_dir("wrong");
        let real_admin = ed25519_pub_from_seed(&[0x40u8; 32]).unwrap();
        std::fs::write(format!("{dir}/admin_id"), hex::encode(real_admin)).unwrap();
        std::fs::write(format!("{dir}/registry"), "").unwrap();
        let (addr, pin, h) = spawn_admin(&dir, 1);
        // клиент подписывает ДРУГИМ seed → сервер не пускает
        assert!(list_at(addr, pin, [0x41u8; 32], None).await.is_err());
        h.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
