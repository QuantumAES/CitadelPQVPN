//! C7.1 — admin-плоскость issuer'а: управление Layer-1 реестром по PQ-TLS каналу.
//!
//! Заменяет SSH-путь GUI (см. SECURITY-ROADMAP §C7): admin аутентифицируется отдельным ключом
//! (`admin_seed` из мастер-ссылки; на сервере — только его идентификатор `admin_id`), подпись
//! **domain-separated** ([`pqid::DOMAIN_ADMIN`]) и **привязана к TLS-сессии** через EKM
//! (TLS-exporter) — кросс-протокольный replay Layer-1-подписи и релей между сессиями
//! невозможны. Команды после auth — CBOR-кадры [`AdminRequest`]/[`AdminResponse`] поверх
//! того же фрейминга `u32(len BE) ‖ payload`.
//!
//! PQ-трек: подпись админа **гибридная** (Ed25519 + ML-DSA-65 из того же seed), а издатель ПЕРВЫМ
//! кадром доказывает свою подлинность ML-DSA-подписью привязки (см. [`crate::pqid`]). До этого
//! обе стороны опирались на классическую подпись и pin серта, то есть квантовый противник,
//! располагая лишь публичными данными (`admin_id` на сервере, серт издателя на проводе), мог и
//! выдать себя за админа, и подставить себя вместо издателя.
//!
//! Транспортная приватность (недостижимость admin-порта извне туннеля) обеспечивается
//! деплоем (C7.2: DNAT с `-i Citadel0`, порт наружу не публикуется) — этот модуль даёт
//! криптографический слой, который держит и без неё (defense in depth).

use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::pqtls::{self, ClientTlsStream, IssuerTlsStream};
use crate::pqid::{self, IssuerPqIdentity};
use crate::{read_frame, write_frame};

/// C7.2: admin-VIP — адрес, на который клиент-админ адресует admin-канал ИЗ ТУННЕЛЯ (шлюз туннеля).
/// Совпадает с гейтвеем `Citadel_TUN_ADDR` exit'а (installer: `10.7.0.1/16`). Exit пропускает TCP
/// к `ADMIN_VIP:admin_port` мимо egress-фильтра и DNAT'ит его на issuer (порт наружу не публикуется).
/// Инвариант деплоя: при смене `Citadel_TUN_ADDR` синхронизировать это значение (и наоборот).
pub const ADMIN_VIP: &str = "10.7.0.1";

/// Домен admin-подписи — [`pqid::DOMAIN_ADMIN`]. Абонент подписывает челлендж в СВОЁМ домене,
/// поэтому issuer никогда не примет одну подпись вместо другой (даже при совпадении ключей).
pub use crate::pqid::DOMAIN_ADMIN as AUTH_DOMAIN;

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
///
/// P1 (сужение поверхности): права `0600` ставятся на temp ДО rename — реестр читает только сам
/// издатель, а лежит он на общем томе рядом с публичными артефактами, которые exit читает из-под
/// `nobody`. Список `client_id` со сроками — приватные данные абонентской базы, и раздавать их
/// всем, кто может войти в каталог, незачем.
pub fn atomic_write(path: &str, content: &str) -> Result<()> {
    let tmp = format!("{path}.tmp.{}", std::process::id());
    std::fs::write(&tmp, content).with_context(|| format!("запись {tmp}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("права 600 на {tmp}"))?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("rename {tmp} → {path}"))?;
    Ok(())
}

// ─────────────────────────── auth: гибридная подпись домен‖challenge‖EKM ───────────────────────────

/// Собрать auth-кадр админа (гибрид Ed25519 + ML-DSA-65, привязка к сессии через EKM).
pub fn build_auth_frame(
    admin_seed: &[u8; 32],
    challenge: &[u8],
    ekm: &[u8; pqtls::EKM_LEN],
) -> Result<Vec<u8>> {
    pqid::build_auth(admin_seed, AUTH_DOMAIN, challenge, ekm)
}

/// Проверить auth-кадр админа: обе подписи (домен+EKM) и совпадение идентичности с `admin_id`.
/// Возвращает `admin_id` при успехе.
pub fn verify_auth_frame(
    frame: &[u8],
    challenge: &[u8],
    ekm: &[u8; pqtls::EKM_LEN],
    admin_id: &[u8; 32],
) -> Result<[u8; 32]> {
    let id = pqid::verify_auth(frame, AUTH_DOMAIN, challenge, ekm)?;
    if &id != admin_id {
        bail!("admin-auth: ключ не является admin_id — отказ");
    }
    Ok(id)
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

    /// Обслужить admin-соединение: hello издателя (челлендж + PQ-доказательство подлинности) →
    /// гибридный auth-кадр админа (домен+EKM, сверка `admin_id`) → цикл CBOR-команд до закрытия
    /// клиентом. Провал auth → пауза 1с (анти-brute, R5) + разрыв БЕЗ ack (клиент не отличает
    /// «нет admin_id» от «чужой ключ» — не оракул).
    pub fn serve_conn(
        &self,
        mut tls: IssuerTlsStream,
        pq: &IssuerPqIdentity,
        cert_pin: &[u8; 32],
    ) -> Result<()> {
        let ekm = pqtls::handshake_server(&mut tls)?;
        let challenge: [u8; 32] = rand::random();
        write_frame(&mut tls, &pq.hello(&challenge, cert_pin, &ekm)?)?;
        let frame = read_frame(&mut tls)?;
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
                // Мутация уже записана в сам реестр (он и есть audit-trail). В stderr дублируем
                // только под Citadel_DEBUG_LOG: иначе docker-лог накапливал бы «кто и когда выдан».
                crate::dlog!("[admin] add {}… active до {vu}", &hex::encode(client_id)[..12]);
                Ok(AdminResponse::Ok)
            }
            AdminRequest::Revoke { client_id } => {
                if self.admin_client_id() == Some(client_id) {
                    bail!("отзыв client_id админа запрещён (self-lockout, R6) — break-glass на сервере");
                }
                atomic_write(&path, &registry_apply_revoke(&cur, &client_id)?)?;
                crate::dlog!("[admin] revoke {}… (действует ≤ длины эпохи)", &hex::encode(client_id)[..12]);
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
        issuer_mldsa: &[u8; 32],
        admin_seed: &[u8; 32],
        obfs_psk: Option<[u8; 32]>,
    ) -> Result<Self> {
        let sa = addr
            .to_socket_addrs()
            .with_context(|| format!("разбор адреса admin-канала {addr}"))?
            .next()
            .ok_or_else(|| anyhow!("admin-канал {addr}: адрес не резолвится"))?;
        // ВНИМАНИЕ: сокет admin-канала защищать протектором НЕЛЬЗЯ (в отличие от канала к издателю
        // и транспорта к exit). Он идёт к ADMIN_VIP — адресу ВНУТРИ туннеля, ядро exit'а DNAT'ит
        // его на издателя (C7.2). Пометка «мимо туннеля» увела бы соединение в обычную сеть, где
        // такого адреса нет, и «Абоненты» перестали бы открываться.
        let tcp = TcpStream::connect_timeout(&sa, Self::CONNECT_TIMEOUT)
            .with_context(|| format!("admin-канал {addr} недоступен (туннель поднят?)"))?;
        tcp.set_read_timeout(Some(Self::IO_TIMEOUT)).context("set_read_timeout")?;
        tcp.set_write_timeout(Some(Self::IO_TIMEOUT)).context("set_write_timeout")?;
        let mut tls = pqtls::connect_tls(tcp, *issuer_pin, obfs_psk)?;
        let ekm = pqtls::handshake_client(&mut tls)?;
        // Издатель обязан представиться ПЕРВЫМ: admin-канал управляет реестром абонентов, и отдавать
        // admin-идентичность (пусть даже подписью) стороне, подлинность которой держится на одном
        // классическом серте, нельзя. Не сошлось — рвём до отправки чего-либо своего.
        let hello = read_frame(&mut tls).context("admin-канал: нет hello (pin/obfs/порт?)")?;
        let challenge = pqid::verify_hello(&hello, issuer_mldsa, issuer_pin, &ekm)
            .context("admin-канал: PQ-аутентификация издателя не прошла")?;
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

    /// verify_auth_frame: happy + негативы ключа/подписи/домена/EKM. Формат кадра и обе подписи
    /// проверяются в [`crate::pqid`]; здесь — то, что добавляет admin-слой: сверка с `admin_id`.
    #[test]
    fn auth_frame_verify_matrix() {
        let seed = [0x42u8; 32];
        let admin_id = pqid::id_from_seed(&seed).unwrap();
        let challenge = [0x11u8; 32];
        let ekm = [0x22u8; pqtls::EKM_LEN];
        let frame = build_auth_frame(&seed, &challenge, &ekm).unwrap();
        // happy
        assert_eq!(verify_auth_frame(&frame, &challenge, &ekm, &admin_id).unwrap(), admin_id);
        // чужой admin_id → отказ (ключ не админский)
        let foreign = pqid::id_from_seed(&[0x43u8; 32]).unwrap();
        assert!(verify_auth_frame(&frame, &challenge, &ekm, &foreign).is_err());
        // подпись абонента (домен Layer-1) в admin-канале → отказ (domain separation)
        let l1 = pqid::build_auth(&seed, pqid::DOMAIN_CLIENT, &challenge, &ekm).unwrap();
        assert!(verify_auth_frame(&l1, &challenge, &ekm, &admin_id).is_err());
        // чужая сессия (другой EKM) → отказ (анти-релей между TLS-сессиями)
        assert!(verify_auth_frame(&frame, &challenge, &[0x99u8; pqtls::EKM_LEN], &admin_id).is_err());
        // чужой челлендж → отказ (анти-replay)
        assert!(verify_auth_frame(&frame, &[0x12u8; 32], &ekm, &admin_id).is_err());
        // мусор вместо кадра → отказ, без паники
        assert!(verify_auth_frame(b"not-cbor", &challenge, &ekm, &admin_id).is_err());
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
    /// Возвращает (addr, cert_pin, обязательство PQ-идентичности издателя, handle).
    fn spawn_admin_server(
        dir: &str,
        conns: usize,
    ) -> (String, [u8; 32], [u8; 32], std::thread::JoinHandle<()>) {
        let identity = pqtls::IssuerIdentity::load_or_generate(dir).unwrap();
        let pin = identity.pin;
        let scfg = identity.server_config().unwrap();
        let pq = std::sync::Arc::new(IssuerPqIdentity::load_or_generate(dir).unwrap());
        let commitment = pq.commitment();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let dir = dir.to_string();
        let h = std::thread::spawn(move || {
            for _ in 0..conns {
                let (tcp, _) = listener.accept().unwrap();
                let srv = AdminServer { dir: dir.clone() };
                // провал auth — ожидаемый исход негативных тестов, не паника сервера
                if let Ok(tls) = pqtls::accept_tls(tcp, scfg.clone(), None) {
                    let _ = srv.serve_conn(tls, &pq, &pin);
                }
            }
        });
        (addr, pin, commitment, h)
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
        let admin_id = pqid::id_from_seed(&admin_seed).unwrap();
        std::fs::write(format!("{dir}/admin_id"), hex::encode(admin_id)).unwrap();
        // Layer-1 client_id самого админа (guard R6)
        let admin_cid = pqid::id_from_seed(&[0x52u8; 32]).unwrap();
        std::fs::write(format!("{dir}/admin.client_id"), hex::encode(admin_cid)).unwrap();
        std::fs::write(format!("{dir}/registry"), format!("{} 9999999999 active\n", hex::encode(admin_cid))).unwrap();

        let (addr, pin, mldsa, h) = spawn_admin_server(&dir, 1);
        let mut c = AdminClient::connect(&addr, &pin, &mldsa, &admin_seed, None).unwrap();

        // list: только запись админа
        let start = c.list().unwrap();
        assert_eq!(start.len(), 1);
        // add с дефолтным сроком (0 → +365d)
        let subscriber = pqid::id_from_seed(&[0x53u8; 32]).unwrap();
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
        let admin_id = pqid::id_from_seed(&[0x61u8; 32]).unwrap();
        std::fs::write(format!("{dir}/admin_id"), hex::encode(admin_id)).unwrap();
        let (addr, pin, mldsa, h) = spawn_admin_server(&dir, 1);
        // валидные по формату подписи, но чужим seed'ом
        assert!(AdminClient::connect(&addr, &pin, &mldsa, &[0x62u8; 32], None).is_err());
        h.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Нет файла admin_id → канал не пускает даже «правильную» подпись (secure default).
    #[test]
    fn admin_auth_rejects_without_admin_id_file() {
        let dir = tmp_dir("noid");
        let (addr, pin, mldsa, h) = spawn_admin_server(&dir, 1);
        assert!(AdminClient::connect(&addr, &pin, &mldsa, &[0x63u8; 32], None).is_err());
        h.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Кадр абонента (домен Layer-1, как у `fetch_tokens`) на admin-канале — отказ:
    /// кросс-протокольный доступ абонентским ключом невозможен, даже если этот ключ записан как
    /// `admin_id` (домен+EKM обязательны).
    #[test]
    fn admin_auth_rejects_layer1_frame() {
        let dir = tmp_dir("layer1");
        let seed = [0x71u8; 32];
        let id = pqid::id_from_seed(&seed).unwrap();
        // намеренно worst case: этот же ключ объявлен admin_id
        std::fs::write(format!("{dir}/admin_id"), hex::encode(id)).unwrap();
        let (addr, pin, mldsa, h) = spawn_admin_server(&dir, 1);

        let tcp = TcpStream::connect(&addr).unwrap();
        let mut tls = pqtls::connect_tls(tcp, pin, None).unwrap();
        let ekm = pqtls::handshake_client(&mut tls).unwrap();
        let hello = read_frame(&mut tls).unwrap();
        let challenge = pqid::verify_hello(&hello, &mldsa, &pin, &ekm).unwrap();
        // ровно то, что шлёт абонент на :7000 — тот же ключ, тот же EKM, но ДРУГОЙ домен
        let auth = pqid::build_auth(&seed, pqid::DOMAIN_CLIENT, &challenge, &ekm).unwrap();
        write_frame(&mut tls, &auth).unwrap();
        assert!(read_frame(&mut tls).is_err(), "ack не должен прийти — соединение разорвано");
        h.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Издатель-самозванец (свой TLS-серт и своя PQ-идентичность) не проходит: клиент сверяет
    /// обязательство из ссылки и рвёт соединение ДО отправки admin-подписи.
    #[test]
    fn admin_client_rejects_foreign_issuer() {
        let dir = tmp_dir("fakeissuer");
        let admin_seed = [0x81u8; 32];
        std::fs::write(
            format!("{dir}/admin_id"),
            hex::encode(pqid::id_from_seed(&admin_seed).unwrap()),
        )
        .unwrap();
        let (addr, pin, _mldsa, h) = spawn_admin_server(&dir, 1);
        // обязательство «другого» издателя — ровно то, что увидит клиент при подмене сервера
        let foreign = pqid::issuer_commitment(&pqid::mldsa_pub_from_seed(&[0x82u8; 32]).unwrap());
        let err = match AdminClient::connect(&addr, &pin, &foreign, &admin_seed, None) {
            Ok(_) => panic!("самозванец не должен пройти"),
            Err(e) => e,
        };
        assert!(format!("{err:#}").contains("PQ-аутентификация издателя"), "err: {err:#}");
        h.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
