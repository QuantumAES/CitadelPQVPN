//! C7.1 — admin-плоскость issuer'а: управление Layer-1 реестром по PQ-TLS каналу.
//!
//! Заменяет SSH-путь GUI (см. SECURITY-ROADMAP §C7): admin аутентифицируется отдельным
//! Ed25519-ключом (`admin_seed` из мастер-ссылки; на сервере — только pub `admin_id`),
//! подпись **domain-separated** (`AUTH_DOMAIN`) и **привязана к TLS-сессии** через EKM
//! (TLS-exporter) — кросс-протокольный replay Layer-1-подписи и релей между сессиями
//! невозможны. Команды после auth — CBOR-кадры [`AdminRequest`]/[`AdminResponse`] поверх
//! того же фрейминга `u32(len BE) ‖ payload`.
//!
//! Транспортная приватность (недостижимость admin-порта извне туннеля) обеспечивается
//! деплоем (C7.2: DNAT с `-i Citadel0`, порт наружу не публикуется) — этот модуль даёт
//! криптографический слой, который держит и без неё (defense in depth).

use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::pqtls::{ClientTlsStream, IssuerTlsStream};
use crate::{ed25519_pub_from_seed, ed25519_sign, ed25519_verify, read_frame, write_frame};

/// C7.2: admin-VIP — адрес, на который клиент-админ адресует admin-канал ИЗ ТУННЕЛЯ (шлюз туннеля).
/// Совпадает с гейтвеем `Citadel_TUN_ADDR` exit'а (installer: `10.7.0.1/16`). Exit пропускает TCP
/// к `ADMIN_VIP:admin_port` мимо egress-фильтра и DNAT'ит его на issuer (порт наружу не публикуется).
/// Инвариант деплоя: при смене `Citadel_TUN_ADDR` синхронизировать это значение (и наоборот).
pub const ADMIN_VIP: &str = "10.7.0.1";

/// Домен admin-подписи. Layer-1 подписывает СЫРОЙ challenge — admin-подпись живёт в другом
/// домене, поэтому issuer никогда не примет одну вместо другой (даже при совпадении ключей).
pub const AUTH_DOMAIN: &[u8] = b"citadel-admin/v1";
/// Метка TLS-exporter'а (EKM) для channel binding admin-подписи.
pub const EKM_LABEL: &[u8] = b"EXPORTER-citadel-admin/v1";
/// Длина EKM (байт).
pub const EKM_LEN: usize = 32;
/// Префикс-байт auth-кадра админа: кадр = `0x01 ‖ pub(32) ‖ sig(64)` (97 Б; Layer-1 кадр — 96 Б).
pub const AUTH_PREFIX: u8 = 0x01;
/// Длина auth-кадра админа.
pub const AUTH_FRAME_LEN: usize = 97;

/// Запись Layer-1 реестра (`<pub_hex> <valid_until_unix> <status>`) — общая для issuer'а,
/// admin-клиента и CLI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryEntry {
    pub client_id: [u8; 32],
    pub valid_until: u64,
    pub status: String,
}

/// Команда админа (CBOR-кадр после успешного auth).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdminRequest {
    /// Список записей реестра.
    List,
    /// Зарегистрировать/обновить абонента (upsert + «разотзыв», как CLI `registry add`).
    /// `valid_until == 0` → серверный дефолт (+365 дней).
    Add { client_id: [u8; 32], valid_until: u64 },
    /// Отозвать абонента (`status=revoked`; действует ≤ длины эпохи).
    Revoke { client_id: [u8; 32] },
}

/// Ответ issuer'а на команду.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdminResponse {
    Ok,
    Entries(Vec<RegistryEntry>),
    Err(String),
}

// ─────────────────────────── реестр: чистая логика (перенесено из main.rs, C5.5) ───────────────────────────

/// Разобрать текст реестра в записи; кривые строки молча пропускаются (как `registry_allows`).
pub fn parse_registry(content: &str) -> Vec<RegistryEntry> {
    content
        .lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let (p, vu, st) = (it.next()?, it.next()?, it.next()?);
            let client_id: [u8; 32] = hex::decode(p).ok()?.try_into().ok()?;
            Some(RegistryEntry {
                client_id,
                valid_until: vu.parse().ok()?,
                status: st.to_string(),
            })
        })
        .collect()
}

/// Upsert строки реестра: если pub уже есть — заменяем (новый valid_until, статус `active`, в т.ч.
/// «разотзыв»); иначе добавляем. Прочие строки сохраняются, дубликаты pub схлопываются, пустые
/// строки убираются. Чистая логика (тестируемо, без I/O).
pub fn registry_apply_add(existing: &str, pk: &[u8; 32], valid_until: u64) -> String {
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
pub fn registry_apply_revoke(existing: &str, pk: &[u8; 32]) -> Result<String> {
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
        bail!("client_id {hexpk} не найден в реестре — нечего отзывать");
    }
    Ok(out)
}

/// Атомарная запись файла реестра: temp в том же каталоге + rename (POSIX-атомарно на одной ФС).
pub fn atomic_write(path: &str, content: &str) -> Result<()> {
    let tmp = format!("{path}.tmp.{}", std::process::id());
    std::fs::write(&tmp, content).with_context(|| format!("запись {tmp}"))?;
    std::fs::rename(&tmp, path).with_context(|| format!("rename {tmp} → {path}"))?;
    Ok(())
}

// ─────────────────────────── auth: подпись домен‖challenge‖EKM ───────────────────────────

/// Сообщение admin-подписи: `AUTH_DOMAIN ‖ challenge ‖ EKM`.
fn auth_msg(challenge: &[u8], ekm: &[u8; EKM_LEN]) -> Vec<u8> {
    let mut m = Vec::with_capacity(AUTH_DOMAIN.len() + challenge.len() + EKM_LEN);
    m.extend_from_slice(AUTH_DOMAIN);
    m.extend_from_slice(challenge);
    m.extend_from_slice(ekm);
    m
}

/// Собрать auth-кадр админа: `0x01 ‖ pub(32) ‖ sig(64)`.
pub fn build_auth_frame(
    admin_seed: &[u8; 32],
    challenge: &[u8],
    ekm: &[u8; EKM_LEN],
) -> Result<Vec<u8>> {
    let pk = ed25519_pub_from_seed(admin_seed)?;
    let sig = ed25519_sign(admin_seed, &auth_msg(challenge, ekm))?;
    let mut f = Vec::with_capacity(AUTH_FRAME_LEN);
    f.push(AUTH_PREFIX);
    f.extend_from_slice(&pk);
    f.extend_from_slice(&sig);
    Ok(f)
}

/// Проверить auth-кадр админа: формат, совпадение pub с `admin_id` и подпись (домен+EKM).
/// Возвращает pub при успехе.
pub fn verify_auth_frame(
    frame: &[u8],
    challenge: &[u8],
    ekm: &[u8; EKM_LEN],
    admin_id: &[u8; 32],
) -> Result<[u8; 32]> {
    if frame.len() != AUTH_FRAME_LEN || frame[0] != AUTH_PREFIX {
        bail!("admin-auth: плохой кадр ({} Б; ожидалось {AUTH_FRAME_LEN})", frame.len());
    }
    let pk: [u8; 32] = frame[1..33].try_into().expect("frame[1..33] = 32 байта");
    if &pk != admin_id {
        bail!("admin-auth: ключ не является admin_id — отказ");
    }
    if !ed25519_verify(&pk, &auth_msg(challenge, ekm), &frame[33..]) {
        bail!("admin-auth: подпись неверна (нет домена/EKM или подделка)");
    }
    Ok(pk)
}

/// EKM (TLS-exporter) сессии — channel binding admin-подписи. Требует ЗАВЕРШЁННОГО хендшейка:
/// вызывать после первого прочитанного кадра (клиент) / после чтения auth-кадра (сервер) —
/// к этому моменту Finished обеих сторон обработаны и экспортёр совпадает у сторон.
fn ekm_from<D>(conn: &rustls::ConnectionCommon<D>) -> Result<[u8; EKM_LEN]> {
    conn.export_keying_material([0u8; EKM_LEN], EKM_LABEL, None)
        .map_err(|e| anyhow!("EKM (хендшейк не завершён?): {e}"))
}

/// EKM клиентской стороны admin-канала.
pub fn ekm_client(tls: &ClientTlsStream) -> Result<[u8; EKM_LEN]> {
    ekm_from(&tls.conn)
}

/// EKM серверной стороны admin-канала.
pub fn ekm_server(tls: &IssuerTlsStream) -> Result<[u8; EKM_LEN]> {
    ekm_from(&tls.conn)
}

// ─────────────────────────── сервер ───────────────────────────

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Серверная сторона admin-канала. Контекст — каталог issuer'а (`Citadel_TOKEN_DIR`):
/// `registry` (реестр), `admin_id` (hex64 pub админа), `admin.client_id` (hex64 Layer-1
/// client_id админа — защита от self-lockout). Файлы читаются на КАЖДУЮ операцию —
/// ротация ключа/реестра действует без рестарта (как `registry_allows`).
pub struct AdminServer {
    pub dir: String,
}

impl AdminServer {
    fn read_hex32(&self, name: &str) -> Option<[u8; 32]> {
        let s = std::fs::read_to_string(format!("{}/{name}", self.dir)).ok()?;
        hex::decode(s.trim()).ok()?.try_into().ok()
    }

    /// pub админа. Нет файла → admin-канал никого не пускает (secure default).
    pub fn admin_id(&self) -> Option<[u8; 32]> {
        self.read_hex32("admin_id")
    }

    /// Layer-1 client_id самого админа: его `Revoke` отклоняется (анти-self-lockout, R6);
    /// разотзыв/ротация — break-glass на сервере.
    pub fn admin_client_id(&self) -> Option<[u8; 32]> {
        self.read_hex32("admin.client_id")
    }

    fn registry_path(&self) -> String {
        format!("{}/registry", self.dir)
    }

    /// Обслужить admin-соединение: challenge → auth-кадр (домен+EKM, сверка `admin_id`) →
    /// цикл CBOR-команд до закрытия клиентом. Провал auth → пауза 1с (анти-brute, R5) + разрыв
    /// БЕЗ ack (клиент не отличает «нет admin_id» от «чужой ключ» — не оракул).
    pub fn serve_conn(&self, mut tls: IssuerTlsStream) -> Result<()> {
        let challenge: [u8; 32] = rand::random();
        write_frame(&mut tls, &challenge)?;
        let frame = read_frame(&mut tls)?;
        // EKM после первого прочитанного кадра — хендшейк точно завершён (см. ekm_from).
        let ekm = ekm_server(&tls)?;
        let verified = self
            .admin_id()
            .ok_or_else(|| anyhow!("admin-канал: admin_id не задан — отказ (secure default)"))
            .and_then(|id| verify_auth_frame(&frame, &challenge, &ekm, &id));
        if let Err(e) = verified {
            std::thread::sleep(std::time::Duration::from_secs(1)); // throttle brute-force
            return Err(e);
        }
        write_frame(&mut tls, b"OK")?; // ack: клиент отличает «auth прошёл» от разрыва
        loop {
            let Ok(raw) = read_frame(&mut tls) else {
                return Ok(()); // клиент закрыл соединение — нормальное завершение
            };
            let resp = self.handle(&raw);
            let mut buf = Vec::new();
            ciborium::into_writer(&resp, &mut buf).context("CBOR-сериализация ответа")?;
            write_frame(&mut tls, &buf)?;
        }
    }

    /// Разобрать и применить одну команду. Ошибки уходят клиенту как `AdminResponse::Err`
    /// (соединение живёт — админ видит причину и может продолжать).
    fn handle(&self, raw: &[u8]) -> AdminResponse {
        let req: AdminRequest = match ciborium::from_reader(raw) {
            Ok(r) => r,
            Err(e) => return AdminResponse::Err(format!("плохой запрос: {e}")),
        };
        match self.apply(req) {
            Ok(resp) => resp,
            Err(e) => AdminResponse::Err(format!("{e:#}")),
        }
    }

    fn apply(&self, req: AdminRequest) -> Result<AdminResponse> {
        let path = self.registry_path();
        let cur = std::fs::read_to_string(&path).unwrap_or_default();
        match req {
            AdminRequest::List => Ok(AdminResponse::Entries(parse_registry(&cur))),
            AdminRequest::Add { client_id, valid_until } => {
                let vu = if valid_until == 0 { now_unix() + 365 * 24 * 3600 } else { valid_until };
                if vu <= now_unix() {
                    bail!("valid_until в прошлом — запись была бы мёртвой");
                }
                atomic_write(&path, &registry_apply_add(&cur, &client_id, vu))?;
                // stderr = audit-trail admin-мутаций (docker logs issuer)
                eprintln!("[admin] add {}… active до {vu}", &hex::encode(client_id)[..12]);
                Ok(AdminResponse::Ok)
            }
            AdminRequest::Revoke { client_id } => {
                if self.admin_client_id() == Some(client_id) {
                    bail!("отзыв client_id админа запрещён (self-lockout, R6) — break-glass на сервере");
                }
                atomic_write(&path, &registry_apply_revoke(&cur, &client_id)?)?;
                eprintln!("[admin] revoke {}… (действует ≤ длины эпохи)", &hex::encode(client_id)[..12]);
                Ok(AdminResponse::Ok)
            }
        }
    }
}

// ─────────────────────────── клиент ───────────────────────────

/// Клиентская сторона admin-канала: PQ-TLS(pin) → challenge → domain+EKM подпись → команды.
/// Sync (std::net), как `fetch_tokens` — GUI-обвязка гоняет в `spawn_blocking` (C7.3).
pub struct AdminClient {
    tls: ClientTlsStream,
}

impl AdminClient {
    /// Таймаут TCP-connect к admin-каналу. VIP маршрутизируем только из-под туннеля: без него
    /// SYN может молча тонуть (blackhole) до OS-таймаута ~2 мин — GUI обязан получить отказ быстро.
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
    /// Таймаут каждой read/write операции канала (handshake и CBOR-команды; операции короткие).
    const IO_TIMEOUT: Duration = Duration::from_secs(15);

    /// Подключиться и аутентифицироваться. `addr` — host:port admin-канала (за туннелем, C7.2);
    /// `issuer_pin` — тот же pin PQ-TLS, что для token-fetch (одна TLS-идентичность issuer'а);
    /// `obfs_psk` — S2.1/A1-остаток: `Some` → obfs-обёртка канала (probe-resistance; PSK из ссылки,
    /// как у token-fetch и туннеля), `None` → голый TLS. Обязан совпадать с серверным.
    pub fn connect(
        addr: &str,
        issuer_pin: &[u8; 32],
        admin_seed: &[u8; 32],
        obfs_psk: Option<[u8; 32]>,
    ) -> Result<Self> {
        let sa = addr
            .to_socket_addrs()
            .with_context(|| format!("разбор адреса admin-канала {addr}"))?
            .next()
            .ok_or_else(|| anyhow!("admin-канал {addr}: адрес не резолвится"))?;
        let tcp = TcpStream::connect_timeout(&sa, Self::CONNECT_TIMEOUT)
            .with_context(|| format!("admin-канал {addr} недоступен (туннель поднят?)"))?;
        tcp.set_read_timeout(Some(Self::IO_TIMEOUT)).context("set_read_timeout")?;
        tcp.set_write_timeout(Some(Self::IO_TIMEOUT)).context("set_write_timeout")?;
        let mut tls = crate::pqtls::connect_tls(tcp, *issuer_pin, obfs_psk)?;
        let challenge = read_frame(&mut tls).context("admin-канал: нет challenge (pin mismatch?)")?;
        let ekm = ekm_client(&tls)?;
        let frame = build_auth_frame(admin_seed, &challenge, &ekm)?;
        write_frame(&mut tls, &frame)?;
        let ack = read_frame(&mut tls).context("admin-auth отклонён сервером (не admin_id?)")?;
        if ack != b"OK" {
            bail!("admin-auth: неожиданный ответ сервера");
        }
        Ok(Self { tls })
    }

    fn call(&mut self, req: &AdminRequest) -> Result<AdminResponse> {
        let mut buf = Vec::new();
        ciborium::into_writer(req, &mut buf).context("CBOR-сериализация запроса")?;
        write_frame(&mut self.tls, &buf)?;
        let raw = read_frame(&mut self.tls).context("admin-канал: сервер оборвал соединение")?;
        ciborium::from_reader(&raw[..]).context("CBOR-разбор ответа")
    }

    fn expect_ok(&mut self, req: &AdminRequest) -> Result<()> {
        match self.call(req)? {
            AdminResponse::Ok => Ok(()),
            AdminResponse::Err(e) => bail!(e),
            AdminResponse::Entries(_) => bail!("неожиданный ответ Entries"),
        }
    }

    /// Список записей реестра.
    pub fn list(&mut self) -> Result<Vec<RegistryEntry>> {
        match self.call(&AdminRequest::List)? {
            AdminResponse::Entries(v) => Ok(v),
            AdminResponse::Err(e) => bail!(e),
            AdminResponse::Ok => bail!("неожиданный ответ Ok"),
        }
    }

    /// Зарегистрировать/обновить абонента. `valid_until == 0` → серверный дефолт (+365d).
    pub fn add(&mut self, client_id: [u8; 32], valid_until: u64) -> Result<()> {
        self.expect_ok(&AdminRequest::Add { client_id, valid_until })
    }

    /// Отозвать абонента.
    pub fn revoke(&mut self, client_id: [u8; 32]) -> Result<()> {
        self.expect_ok(&AdminRequest::Revoke { client_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqtls;
    use std::net::TcpListener;

    // ── чистая логика реестра (перенесено из main.rs вместе с кодом, C5.5) ──

    /// add в пустой реестр, затем add того же pub «разотзывает» и обновляет срок; чужие строки целы.
    #[test]
    fn registry_add_upsert_and_unrevoke() {
        let a = [0xAAu8; 32];
        let b = [0xBBu8; 32];
        let ha = hex::encode(a);
        let hb = hex::encode(b);
        let start = format!("{ha} 100 revoked\n{hb} 200 active\n");
        let out = registry_apply_add(&start, &a, 500);
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
        assert_eq!(registry_apply_add(&start, &a, 9), format!("{ha} 9 active\n"));
    }

    /// revoke переводит статус в revoked, сохраняя valid_until; отсутствующий pub → ошибка.
    #[test]
    fn registry_revoke_and_missing() {
        let a = [0xCCu8; 32];
        let ha = hex::encode(a);
        let ok = registry_apply_revoke(&format!("{ha} 42 active\n"), &a).unwrap();
        assert_eq!(ok, format!("{ha} 42 revoked\n"), "срок сохранён, статус revoked");
        assert!(registry_apply_revoke("", &a).is_err(), "нет pub → ошибка");
    }

    /// parse_registry: валидные строки разбираются, мусор пропускается.
    #[test]
    fn parse_registry_skips_garbage() {
        let a = [0x0Du8; 32];
        let ha = hex::encode(a);
        let txt = format!("{ha} 123 active\nмусор\nshort 1 active\n\n{ha} notnum active\n");
        let got = parse_registry(&txt);
        assert_eq!(got, vec![RegistryEntry { client_id: a, valid_until: 123, status: "active".into() }]);
    }

    // ── auth: чистые негативы без TLS ──

    /// verify_auth_frame: happy + все негативы формата/ключа/подписи/домена/EKM.
    #[test]
    fn auth_frame_verify_matrix() {
        let seed = [0x42u8; 32];
        let admin_id = ed25519_pub_from_seed(&seed).unwrap();
        let challenge = [0x11u8; 32];
        let ekm = [0x22u8; EKM_LEN];
        let frame = build_auth_frame(&seed, &challenge, &ekm).unwrap();
        assert_eq!(frame.len(), AUTH_FRAME_LEN);
        // happy
        assert_eq!(verify_auth_frame(&frame, &challenge, &ekm, &admin_id).unwrap(), admin_id);
        // чужой admin_id → отказ (ключ не админский)
        let foreign = ed25519_pub_from_seed(&[0x43u8; 32]).unwrap();
        assert!(verify_auth_frame(&frame, &challenge, &ekm, &foreign).is_err());
        // Layer-1-стиль (96 Б, без префикса) → отказ по формату
        assert!(verify_auth_frame(&frame[1..], &challenge, &ekm, &admin_id).is_err());
        // неверный префикс → отказ
        let mut bad = frame.clone();
        bad[0] = 0x02;
        assert!(verify_auth_frame(&bad, &challenge, &ekm, &admin_id).is_err());
        // подпись без домена/EKM (сырой challenge, как Layer-1) → отказ (domain separation)
        let sig_raw = ed25519_sign(&seed, &challenge).unwrap();
        let mut f96 = vec![AUTH_PREFIX];
        f96.extend_from_slice(&admin_id);
        f96.extend_from_slice(&sig_raw);
        assert!(verify_auth_frame(&f96, &challenge, &ekm, &admin_id).is_err());
        // подпись домен‖challenge, но БЕЗ EKM → отказ (channel binding обязателен)
        let mut no_ekm = AUTH_DOMAIN.to_vec();
        no_ekm.extend_from_slice(&challenge);
        let sig_no_ekm = ed25519_sign(&seed, &no_ekm).unwrap();
        let mut f_no_ekm = vec![AUTH_PREFIX];
        f_no_ekm.extend_from_slice(&admin_id);
        f_no_ekm.extend_from_slice(&sig_no_ekm);
        assert!(verify_auth_frame(&f_no_ekm, &challenge, &ekm, &admin_id).is_err());
        // чужая сессия (другой EKM) → отказ (анти-релей между TLS-сессиями)
        assert!(verify_auth_frame(&frame, &challenge, &[0x99u8; EKM_LEN], &admin_id).is_err());
        // повреждённая подпись → отказ
        let mut tampered = frame;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(verify_auth_frame(&tampered, &challenge, &ekm, &admin_id).is_err());
    }

    /// CBOR wire-формат команд/ответов: roundtrip без потерь.
    #[test]
    fn wire_cbor_roundtrip() {
        let reqs = [
            AdminRequest::List,
            AdminRequest::Add { client_id: [7u8; 32], valid_until: 0 },
            AdminRequest::Revoke { client_id: [8u8; 32] },
        ];
        for r in &reqs {
            let mut buf = Vec::new();
            ciborium::into_writer(r, &mut buf).unwrap();
            let back: AdminRequest = ciborium::from_reader(&buf[..]).unwrap();
            assert_eq!(&back, r);
        }
        let resps = [
            AdminResponse::Ok,
            AdminResponse::Err("x".into()),
            AdminResponse::Entries(vec![RegistryEntry {
                client_id: [9u8; 32],
                valid_until: 1,
                status: "active".into(),
            }]),
        ];
        for r in &resps {
            let mut buf = Vec::new();
            ciborium::into_writer(r, &mut buf).unwrap();
            let back: AdminResponse = ciborium::from_reader(&buf[..]).unwrap();
            assert_eq!(&back, r);
        }
    }

    // ── e2e поверх PQ-TLS: in-process issuer admin-канал ──

    /// Поднять admin-сервер на `conns` последовательных соединений. Возвращает (addr, pin, handle).
    fn spawn_admin_server(
        dir: &str,
        conns: usize,
    ) -> (String, [u8; 32], std::thread::JoinHandle<()>) {
        let identity = pqtls::IssuerIdentity::load_or_generate(dir).unwrap();
        let pin = identity.pin;
        let scfg = identity.server_config().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let dir = dir.to_string();
        let h = std::thread::spawn(move || {
            for _ in 0..conns {
                let (tcp, _) = listener.accept().unwrap();
                let srv = AdminServer { dir: dir.clone() };
                // провал auth — ожидаемый исход негативных тестов, не паника сервера
                if let Ok(tls) = pqtls::accept_tls(tcp, scfg.clone(), None) {
                    let _ = srv.serve_conn(tls);
                }
            }
        });
        (addr, pin, h)
    }

    fn tmp_dir(tag: &str) -> String {
        let d = std::env::temp_dir().join(format!("citadel-admin-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d.to_str().unwrap().to_string()
    }

    /// Happy-path: list пуст → add(дефолтный срок) → active в списке → revoke → revoked;
    /// self-lockout: revoke собственного client_id админа → Err, реестр не изменён.
    #[test]
    fn admin_e2e_list_add_revoke_and_lockout_guard() {
        let dir = tmp_dir("e2e");
        let admin_seed = [0x51u8; 32];
        let admin_id = ed25519_pub_from_seed(&admin_seed).unwrap();
        std::fs::write(format!("{dir}/admin_id"), hex::encode(admin_id)).unwrap();
        // Layer-1 client_id самого админа (guard R6)
        let admin_cid = ed25519_pub_from_seed(&[0x52u8; 32]).unwrap();
        std::fs::write(format!("{dir}/admin.client_id"), hex::encode(admin_cid)).unwrap();
        std::fs::write(format!("{dir}/registry"), format!("{} 9999999999 active\n", hex::encode(admin_cid))).unwrap();

        let (addr, pin, h) = spawn_admin_server(&dir, 1);
        let mut c = AdminClient::connect(&addr, &pin, &admin_seed, None).unwrap();

        // list: только запись админа
        let start = c.list().unwrap();
        assert_eq!(start.len(), 1);
        // add с дефолтным сроком (0 → +365d)
        let subscriber = ed25519_pub_from_seed(&[0x53u8; 32]).unwrap();
        c.add(subscriber, 0).unwrap();
        let after_add = c.list().unwrap();
        let e = after_add.iter().find(|e| e.client_id == subscriber).expect("абонент в реестре");
        assert_eq!(e.status, "active");
        assert!(e.valid_until > now_unix() + 300 * 24 * 3600, "дефолт ≈ +365d");
        // revoke абонента
        c.revoke(subscriber).unwrap();
        let after_revoke = c.list().unwrap();
        assert_eq!(
            after_revoke.iter().find(|e| e.client_id == subscriber).unwrap().status,
            "revoked"
        );
        // self-lockout guard: отзыв client_id админа → Err, запись осталась active
        let err = c.revoke(admin_cid).unwrap_err();
        assert!(err.to_string().contains("self-lockout"), "err: {err}");
        let fin = c.list().unwrap();
        assert_eq!(fin.iter().find(|e| e.client_id == admin_cid).unwrap().status, "active");
        // add с valid_until в прошлом → Err
        assert!(c.add([0x54u8; 32], 1).is_err(), "прошлое → отказ");

        drop(c);
        h.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Чужой ключ (не admin_id) — auth отклонён; сервер не выдал ack (без оракула).
    #[test]
    fn admin_auth_rejects_foreign_key() {
        let dir = tmp_dir("foreign");
        let admin_id = ed25519_pub_from_seed(&[0x61u8; 32]).unwrap();
        std::fs::write(format!("{dir}/admin_id"), hex::encode(admin_id)).unwrap();
        let (addr, pin, h) = spawn_admin_server(&dir, 1);
        // валидная по формату подпись, но чужим seed'ом
        assert!(AdminClient::connect(&addr, &pin, &[0x62u8; 32], None).is_err());
        h.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Нет файла admin_id → канал не пускает даже «правильную» подпись (secure default).
    #[test]
    fn admin_auth_rejects_without_admin_id_file() {
        let dir = tmp_dir("noid");
        let (addr, pin, h) = spawn_admin_server(&dir, 1);
        assert!(AdminClient::connect(&addr, &pin, &[0x63u8; 32], None).is_err());
        h.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Layer-1-стилевой кадр (96 Б `pub‖sig(challenge)`, как у fetch_tokens) на admin-канале —
    /// отказ: кросс-протокольный доступ абонентским ключом невозможен, даже если этот ключ
    /// записан как admin_id (домен+EKM обязательны).
    #[test]
    fn admin_auth_rejects_layer1_frame() {
        let dir = tmp_dir("layer1");
        let seed = [0x71u8; 32];
        let pk = ed25519_pub_from_seed(&seed).unwrap();
        // намеренно worst case: этот же ключ объявлен admin_id
        std::fs::write(format!("{dir}/admin_id"), hex::encode(pk)).unwrap();
        let (addr, pin, h) = spawn_admin_server(&dir, 1);

        let tcp = TcpStream::connect(&addr).unwrap();
        let mut tls = pqtls::connect_tls(tcp, pin, None).unwrap();
        let challenge = read_frame(&mut tls).unwrap();
        // ровно то, что шлёт Layer-1 клиент: pub(32) ‖ Ed25519(seed, сырой challenge)
        let sig = ed25519_sign(&seed, &challenge).unwrap();
        let mut auth = Vec::with_capacity(96);
        auth.extend_from_slice(&pk);
        auth.extend_from_slice(&sig);
        write_frame(&mut tls, &auth).unwrap();
        assert!(read_frame(&mut tls).is_err(), "ack не должен прийти — соединение разорвано");
        h.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
