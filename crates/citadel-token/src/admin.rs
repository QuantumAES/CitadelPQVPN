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

/// Запись Layer-1 реестра — общая для issuer'а, admin-клиента и CLI.
///
/// Формат строки: `<pub_hex> <valid_until_unix> <status> [k=v,k=v]`. Четвёртое поле появилось в
/// M-9 (одноразовые ссылки) и **необязательно**: строки, написанные до него (и руками оператора),
/// читаются как раньше. Ключи:
///   * `enroll=<unix>` — запись ждёт **активации** до этого момента (`0` — без срока);
///   * `dev=<hex64>`   — активирована в это устройство (после активации, вместе со `status=consumed`);
///   * `linkh=<hex64>` — отпечаток ссылки, заверенный при выдаче (M-9: сверяется при активации).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryEntry {
    pub client_id: [u8; 32],
    pub valid_until: u64,
    pub status: String,
    /// M-9: до какого момента запись можно активировать (`Some(0)` — без срока). `None` — запись
    /// обычная (многоразовая ссылка, поведение до M-9).
    #[serde(default)]
    pub enroll_until: Option<u64>,
    /// M-9: устройство, в которое активирована первичная ссылка.
    #[serde(default)]
    pub device: Option<[u8; 32]>,
    /// M-9: отпечаток ссылки (хэш канонической формы), заверенный издателем при выдаче.
    #[serde(default)]
    pub link_hash: Option<[u8; 32]>,
}

/// Статус записи, при котором Layer-1 пускает абонента (остальные — отказ).
pub const STATUS_ACTIVE: &str = "active";
/// M-9: первичная ссылка отработала — активирована на устройстве и больше никого не пускает.
pub const STATUS_CONSUMED: &str = "consumed";

impl RegistryEntry {
    /// Строка реестра. Флаги пишутся только когда есть что писать — файл, который админ читает
    /// глазами и правит руками, не должен обрастать `enroll=0,dev=,linkh=` на каждой строке.
    pub fn to_line(&self) -> String {
        let mut flags: Vec<String> = Vec::new();
        if let Some(u) = self.enroll_until {
            flags.push(format!("enroll={u}"));
        }
        if let Some(d) = self.device {
            flags.push(format!("dev={}", hex::encode(d)));
        }
        if let Some(h) = self.link_hash {
            flags.push(format!("linkh={}", hex::encode(h)));
        }
        let mut line = format!("{} {} {}", hex::encode(self.client_id), self.valid_until, self.status);
        if !flags.is_empty() {
            line.push(' ');
            line.push_str(&flags.join(","));
        }
        line.push('\n');
        line
    }
}

/// Разбор поля флагов (`k=v,k=v`). Незнакомые ключи игнорируются: реестр правят руками, и
/// неизвестный флаг не повод потерять всю запись.
fn parse_flags(raw: Option<&str>) -> (Option<u64>, Option<[u8; 32]>, Option<[u8; 32]>) {
    let (mut enroll, mut dev, mut linkh) = (None, None, None);
    for kv in raw.unwrap_or("").split(',') {
        let Some((k, v)) = kv.split_once('=') else { continue };
        match k.trim() {
            "enroll" => enroll = v.trim().parse::<u64>().ok(),
            "dev" => dev = hex::decode(v.trim()).ok().and_then(|b| b.try_into().ok()),
            "linkh" => linkh = hex::decode(v.trim()).ok().and_then(|b| b.try_into().ok()),
            _ => {}
        }
    }
    (enroll, dev, linkh)
}

/// Команда админа (CBOR-кадр после успешного auth).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdminRequest {
    /// Список записей реестра.
    List,
    /// Зарегистрировать/обновить абонента (upsert + «разотзыв», как CLI `registry add`).
    /// `valid_until == 0` → серверный дефолт (+365 дней).
    ///
    /// M-9: `enroll_until` делает выдаваемую ссылку ОДНОРАЗОВОЙ (окно активации, unix; `0` — без
    /// срока), `link_hash` — заверяемый отпечаток ссылки, который издатель сверит при активации.
    /// Оба поля `#[serde(default)]`: старый админ-клиент шлёт кадр без них и получает прежнее
    /// поведение (многоразовая запись).
    Add {
        client_id: [u8; 32],
        valid_until: u64,
        #[serde(default)]
        enroll_until: Option<u64>,
        #[serde(default)]
        link_hash: Option<[u8; 32]>,
    },
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
            let (enroll_until, device, link_hash) = parse_flags(it.next());
            Some(RegistryEntry {
                client_id,
                valid_until: vu.parse().ok()?,
                status: st.to_string(),
                enroll_until,
                device,
                link_hash,
            })
        })
        .collect()
}

/// Upsert строки реестра: если pub уже есть — заменяем (новый valid_until, статус `active`, в т.ч.
/// «разотзыв»); иначе добавляем. Прочие строки сохраняются, дубликаты pub схлопываются, пустые
/// строки убираются. Чистая логика (тестируемо, без I/O).
pub fn registry_apply_add(existing: &str, pk: &[u8; 32], valid_until: u64) -> String {
    registry_apply_add_full(existing, pk, valid_until, None, None)
}

/// M-9: тот же upsert, но с параметрами первичной ссылки — сроком активации и заверенным
/// отпечатком. `enroll_until = Some(t)` делает запись ОДНОРАЗОВОЙ: до `t` её можно активировать на
/// одном устройстве, после чего она становится `consumed` и никого не пускает.
///
/// Повторный `add` того же id **перезаписывает** запись целиком, в том числе снимает `consumed`.
/// Это осознанно: `add` — явная команда админа («выдай/продли/разотзови»), и другого способа
/// перевыпустить доступ на то же имя у него нет. Случайно так не сделаешь: id придётся указать.
pub fn registry_apply_add_full(
    existing: &str,
    pk: &[u8; 32],
    valid_until: u64,
    enroll_until: Option<u64>,
    link_hash: Option<[u8; 32]>,
) -> String {
    let hexpk = hex::encode(pk);
    let fresh = RegistryEntry {
        client_id: *pk,
        valid_until,
        status: STATUS_ACTIVE.into(),
        enroll_until,
        device: None,
        link_hash,
    }
    .to_line();
    let mut out = String::new();
    let mut done = false;
    for line in existing.lines() {
        if line.split_whitespace().next() == Some(hexpk.as_str()) {
            if !done {
                out.push_str(&fresh);
                done = true;
            }
        } else if !line.trim().is_empty() {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !done {
        out.push_str(&fresh);
    }
    out
}

/// M-9: **активация первичной ссылки**. Запись `bootstrap` становится `consumed` и получает
/// `dev=<device>`, а рядом заводится запись самого устройства с тем же сроком подписки.
///
/// Идемпотентность обязательна: клиент мог сохранить свой seed, отправить запрос и потерять ответ
/// (обрыв связи, убитый процесс). Повтор с ТЕМ ЖЕ устройством — успех и ничего не меняет; повтор с
/// ДРУГИМ — отказ, ради которого всё и затевалось (украденная ссылка после активации мертва).
///
/// `link_hash` — отпечаток ссылки, который предъявил клиент. Если издатель запомнил свой при
/// выдаче, они обязаны совпасть: расхождение означает, что ссылку по дороге подменили (адрес
/// exit'а, pin, PSK — что угодно), и активировать её нельзя.
pub fn registry_apply_enroll(
    existing: &str,
    bootstrap: &[u8; 32],
    device: &[u8; 32],
    link_hash: Option<[u8; 32]>,
    now: u64,
) -> Result<String> {
    let entries = parse_registry(existing);
    let e = entries
        .iter()
        .find(|e| &e.client_id == bootstrap)
        .ok_or_else(|| anyhow!("активация: запись не найдена"))?;
    let Some(deadline) = e.enroll_until else {
        bail!("активация: ссылка не первичная (запись не помечена как одноразовая)");
    };
    if bootstrap == device {
        bail!("активация: устройство обязано иметь СВОЮ идентичность, а не идентичность ссылки");
    }
    // Уже активирована: тем же устройством — идемпотентный успех, другим — отказ.
    if e.status == STATUS_CONSUMED || e.device.is_some() {
        return match e.device {
            Some(d) if &d == device => Ok(existing.to_string()),
            _ => bail!("активация: ссылка уже активирована на другом устройстве"),
        };
    }
    if e.status != STATUS_ACTIVE {
        bail!("активация: запись не активна (status={})", e.status);
    }
    if deadline > 0 && now >= deadline {
        bail!("активация: окно активации истекло");
    }
    // Заверение M-9: то, что абонент держит в руках, обязано быть тем, что выдал админ.
    match (e.link_hash, link_hash) {
        (Some(want), Some(got)) if want != got => {
            bail!("активация: отпечаток ссылки не совпал — ссылку подменили при доставке")
        }
        (Some(_), None) => bail!("активация: клиент не предъявил отпечаток заверенной ссылки"),
        _ => {}
    }
    let consumed = RegistryEntry {
        status: STATUS_CONSUMED.into(),
        device: Some(*device),
        ..e.clone()
    };
    let mut out = String::new();
    let hexpk = hex::encode(bootstrap);
    for line in existing.lines() {
        if line.split_whitespace().next() == Some(hexpk.as_str()) {
            out.push_str(&consumed.to_line());
        } else if !line.trim().is_empty() {
            out.push_str(line);
            out.push('\n');
        }
    }
    // Устройство наследует срок подписки исходной записи; одноразовым оно уже не помечается.
    Ok(registry_apply_add_full(&out, device, e.valid_until, None, None))
}

/// Все записи, которые гасит отзыв `pk`: он сам, устройство, в которое активирована его ссылка, и
/// ссылка, из которой выросло это устройство. Больше одного шага в каждую сторону быть не может
/// (устройственная запись сама одноразовой не помечается), но считаем по файлу — его мог править
/// оператор руками.
///
/// Отдельная функция, потому что цепочку обязаны знать ДВОЕ: сам отзыв и защита от self-lockout
/// (R6). Иначе админ, отозвав УСТРОЙСТВО, к которому привязана его же мастер-ссылка, запер бы
/// себя снаружи — проверка «id не равен admin.client_id» этого бы не заметила.
pub fn revoke_chain(existing: &str, pk: &[u8; 32]) -> Vec<[u8; 32]> {
    let entries = parse_registry(existing);
    let mut targets: Vec<[u8; 32]> = vec![*pk];
    for e in &entries {
        if &e.client_id == pk {
            if let Some(d) = e.device {
                targets.push(d); // ссылка → её устройство
            }
        }
        if e.device.as_ref() == Some(pk) {
            targets.push(e.client_id); // устройство → породившая ссылка
        }
    }
    targets
}

/// Отзыв: у строки pub статус → `revoked` (valid_until сохраняется). Если pub нет — ошибка
/// (нечего отзывать; защищает от опечатки в client_id). Чистая логика.
///
/// **M-9, живой дефект: отзыв обязан идти по всей цепочке «ссылка ⇄ устройство».** После активации
/// подписка переезжает на УСТРОЙСТВЕННЫЙ id, а запись ссылки становится `consumed` — то есть в
/// реестре появляются ДВЕ строки на одного абонента. Админ видит с меткой ту, которую сам выдал
/// (ссылочную), отзывал её — и ничего не происходило: пускала-то абонента вторая строка. Поэтому
/// отзыв ссылки гасит и её устройство, а отзыв устройства — породившую его ссылку (иначе
/// оставшаяся `consumed`-строка выглядела бы как «ещё можно активировать»).
pub fn registry_apply_revoke(existing: &str, pk: &[u8; 32]) -> Result<String> {
    let targets = revoke_chain(existing, pk);
    let hexpk = hex::encode(pk);
    let hex_targets: Vec<String> = targets.iter().map(hex::encode).collect();
    let mut out = String::new();
    let mut found = false;
    let mut seen: Vec<String> = Vec::new();
    for line in existing.lines() {
        let head = line.split_whitespace().next().unwrap_or_default().to_string();
        if hex_targets.contains(&head) {
            if seen.contains(&head) {
                continue; // дубликат строки того же id — схлопываем, как делает upsert
            }
            // Флаги M-9 (`enroll`/`dev`/`linkh`) при отзыве СОХРАНЯЮТСЯ: иначе отозванная
            // первичная ссылка теряла бы отметку «уже активирована», и повторный `add`
            // воскрешал бы её как свежую одноразовую — то есть отзыв ослаблял бы контроль.
            let mut e = parse_registry(line).pop().unwrap_or(RegistryEntry {
                client_id: *pk,
                ..Default::default()
            });
            e.status = "revoked".into();
            out.push_str(&e.to_line());
            seen.push(head.clone());
            if head == hexpk {
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
    ///
    /// H-1 (аудит-4): `on_auth` зовётся РОВНО в момент, когда админ доказал право — вызывающий
    /// освобождает по нему слот pre-auth и снимает жёсткий дедлайн хендшейка. Колбэк, а не
    /// действие вызывающего «после `serve_conn`»: иначе живая admin-сессия занимала бы слот
    /// потолка одновременных хендшейков всё время, пока открыта.
    pub fn serve_conn(
        &self,
        mut tls: IssuerTlsStream,
        pq: &IssuerPqIdentity,
        cert_pin: &[u8; 32],
        on_auth: impl FnOnce(),
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
        on_auth();
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
            AdminRequest::Add { client_id, valid_until, enroll_until, link_hash } => {
                let vu = if valid_until == 0 { now_unix() + 365 * 24 * 3600 } else { valid_until };
                if vu <= now_unix() {
                    bail!("valid_until в прошлом — запись была бы мёртвой");
                }
                // M-9: окно активации в прошлом = ссылка, мёртвая с рождения. Ловим здесь, а не
                // «потом на устройстве абонента», где причина уже не видна.
                if matches!(enroll_until, Some(t) if t > 0 && t <= now_unix()) {
                    bail!("окно активации в прошлом — такая ссылка не активируется никогда");
                }
                atomic_write(
                    &path,
                    &registry_apply_add_full(&cur, &client_id, vu, enroll_until, link_hash),
                )?;
                // Мутация уже записана в сам реестр (он и есть audit-trail). В stderr дублируем
                // только под Citadel_DEBUG_LOG: иначе docker-лог накапливал бы «кто и когда выдан».
                crate::dlog!("[admin] add {}… active до {vu}", &hex::encode(client_id)[..12]);
                Ok(AdminResponse::Ok)
            }
            AdminRequest::Revoke { client_id } => {
                // R6 (анти-self-lockout) считается по ВСЕЙ цепочке отзыва: мастер-ссылка админа
                // теперь тоже одноразовая, то есть его собственный доступ живёт на устройственной
                // записи, а `admin.client_id` — на ссылочной. Проверка одного лишь равенства
                // позволила бы админу отозвать своё устройство и вместе с ним (каскадом) себя.
                if let Some(mine) = self.admin_client_id() {
                    if revoke_chain(&cur, &client_id).contains(&mine) {
                        bail!(
                            "отзыв client_id админа запрещён (self-lockout, R6) — break-glass на сервере"
                        );
                    }
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
        // Диагностика пути «Абоненты». Единственный инструмент разбора жалобы «список не
        // грузится» — журнал ядра на самом устройстве: экран показывает лишь итог, а этапов у
        // операции четыре (TCP по туннелю → obfs → PQ-TLS с пином → PQ-аутентификация издателя),
        // и молчали они все. Адрес — VIP внутри туннеля, ничего приватного в строке нет.
        let t0 = std::time::Instant::now();
        eprintln!("[admin] подключаюсь к {addr} по туннелю…");
        let tcp = TcpStream::connect_timeout(&sa, Self::CONNECT_TIMEOUT)
            .with_context(|| format!("admin-канал {addr} недоступен (туннель поднят?)"))?;
        tcp.set_read_timeout(Some(Self::IO_TIMEOUT)).context("set_read_timeout")?;
        tcp.set_write_timeout(Some(Self::IO_TIMEOUT)).context("set_write_timeout")?;
        eprintln!("[admin] TCP до {addr} за {} мс — поднимаю PQ-TLS", t0.elapsed().as_millis());
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
        eprintln!("[admin] канал открыт за {} мс (PQ-TLS+pin, подпись админа принята)", t0.elapsed().as_millis());
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
        self.expect_ok(&AdminRequest::Add {
            client_id,
            valid_until,
            enroll_until: None,
            link_hash: None,
        })
    }

    /// M-9: выдать ОДНОРАЗОВУЮ ссылку — запись помечается окном активации и заверенным
    /// отпечатком. `enroll_until` — до какого момента (unix) ссылку можно активировать.
    pub fn add_enrollable(
        &mut self,
        client_id: [u8; 32],
        valid_until: u64,
        enroll_until: u64,
        link_hash: [u8; 32],
    ) -> Result<()> {
        self.expect_ok(&AdminRequest::Add {
            client_id,
            valid_until,
            enroll_until: Some(enroll_until),
            link_hash: Some(link_hash),
        })
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
        assert_eq!(
            got,
            vec![RegistryEntry {
                client_id: a,
                valid_until: 123,
                status: "active".into(),
                ..Default::default()
            }]
        );
    }

    /// M-9: активация — главный инвариант одноразовости. Первая активация переносит подписку на
    /// устройство и гасит запись ссылки; повтор ТЕМ ЖЕ устройством идемпотентен, ДРУГИМ — отказ.
    #[test]
    fn enroll_binds_link_to_first_device_only() {
        let boot = [0xB0u8; 32];
        let dev1 = [0xD1u8; 32];
        let dev2 = [0xD2u8; 32];
        let hash = [0x9Au8; 32];
        let start = registry_apply_add_full("", &boot, 2_000, Some(1_500), Some(hash));
        assert!(start.contains("enroll=1500"), "запись помечена одноразовой: {start}");

        let after = registry_apply_enroll(&start, &boot, &dev1, Some(hash), 1_000).unwrap();
        let e: Vec<_> = parse_registry(&after);
        let b = e.iter().find(|x| x.client_id == boot).unwrap();
        assert_eq!(b.status, STATUS_CONSUMED, "ссылка отработала");
        assert_eq!(b.device, Some(dev1), "видно, в какое устройство активирована");
        let d = e.iter().find(|x| x.client_id == dev1).unwrap();
        assert_eq!((d.status.as_str(), d.valid_until), (STATUS_ACTIVE, 2_000), "подписка переехала");
        assert!(d.enroll_until.is_none(), "устройственная запись уже не одноразовая");

        // Идемпотентность: тот же device — успех, реестр не меняется.
        let again = registry_apply_enroll(&after, &boot, &dev1, Some(hash), 1_100).unwrap();
        assert_eq!(again, after, "повтор той же активации ничего не меняет");
        // Второе устройство — отказ (ровно то, ради чего одноразовость и вводилась).
        let err = registry_apply_enroll(&after, &boot, &dev2, Some(hash), 1_100).unwrap_err();
        assert!(format!("{err:#}").contains("другом устройстве"), "err: {err:#}");
    }

    /// M-9: срок, заверение и «не первичная запись» — три причины отказа, которые обязаны
    /// различаться: за ними стоят разные действия человека.
    #[test]
    fn enroll_refuses_expired_tampered_and_plain_entries() {
        let boot = [0xB0u8; 32];
        let dev = [0xD1u8; 32];
        let hash = [0x9Au8; 32];
        let one_time = registry_apply_add_full("", &boot, 9_000, Some(1_500), Some(hash));

        // окно активации истекло
        let err = registry_apply_enroll(&one_time, &boot, &dev, Some(hash), 1_600).unwrap_err();
        assert!(format!("{err:#}").contains("окно активации"), "err: {err:#}");
        // отпечаток не совпал → ссылку подменили по дороге
        let err = registry_apply_enroll(&one_time, &boot, &dev, Some([0xEEu8; 32]), 1_000).unwrap_err();
        assert!(format!("{err:#}").contains("отпечаток"), "err: {err:#}");
        // клиент вовсе не предъявил отпечаток, хотя издатель его заверял
        let err = registry_apply_enroll(&one_time, &boot, &dev, None, 1_000).unwrap_err();
        assert!(format!("{err:#}").contains("не предъявил"), "err: {err:#}");
        // обычная (многоразовая) запись активации не подлежит
        let plain = registry_apply_add("", &boot, 9_000);
        let err = registry_apply_enroll(&plain, &boot, &dev, Some(hash), 1_000).unwrap_err();
        assert!(format!("{err:#}").contains("не первичная"), "err: {err:#}");
        // устройство обязано иметь СВОЮ идентичность
        let err = registry_apply_enroll(&one_time, &boot, &boot, Some(hash), 1_000).unwrap_err();
        assert!(format!("{err:#}").contains("СВОЮ идентичность"), "err: {err:#}");
    }

    /// Флаги M-9 переживают отзыв и чтение-запись реестра: иначе `revoke` стирал бы отметку
    /// «уже активирована», и повторный `add` воскрешал бы ссылку как свежую одноразовую.
    #[test]
    fn flags_survive_revoke_roundtrip() {
        let boot = [0xB0u8; 32];
        let dev = [0xD1u8; 32];
        let hash = [0x9Au8; 32];
        let reg = registry_apply_add_full("", &boot, 2_000, Some(1_500), Some(hash));
        let reg = registry_apply_enroll(&reg, &boot, &dev, Some(hash), 1_000).unwrap();
        let reg = registry_apply_revoke(&reg, &boot).unwrap();
        let e = parse_registry(&reg);
        let b = e.iter().find(|x| x.client_id == boot).unwrap();
        assert_eq!(b.status, "revoked");
        assert_eq!(b.device, Some(dev), "отметка активации сохранена");
        assert_eq!(b.link_hash, Some(hash), "заверенный отпечаток сохранён");
        assert_eq!(b.enroll_until, Some(1_500));
    }

    /// **Живой дефект M-9: отзыв обязан гасить и ссылку, и её устройство.** После активации
    /// доступ даёт УСТРОЙСТВЕННАЯ запись, а метку («телефон Али») админ помнит по ссылочной —
    /// и отзывал именно её. Устройственная оставалась `active`, абонент продолжал подключаться,
    /// а в списке абонентов напротив него честно стояло «отозван».
    #[test]
    fn revoke_follows_the_link_device_chain() {
        let boot = [0xB0u8; 32];
        let dev = [0xD1u8; 32];
        let other = [0x77u8; 32];
        let hash = [0x9Au8; 32];
        let base = registry_apply_add_full("", &boot, 2_000, Some(1_500), Some(hash));
        let base = registry_apply_add(&base, &other, 3_000); // посторонний абонент — не трогать
        let enrolled = registry_apply_enroll(&base, &boot, &dev, Some(hash), 1_000).unwrap();

        // отзыв ПО ССЫЛКЕ гасит устройство
        let by_link = parse_registry(&registry_apply_revoke(&enrolled, &boot).unwrap());
        assert_eq!(by_link.iter().find(|x| x.client_id == dev).unwrap().status, "revoked");
        assert_eq!(by_link.iter().find(|x| x.client_id == boot).unwrap().status, "revoked");
        assert_eq!(
            by_link.iter().find(|x| x.client_id == other).unwrap().status,
            STATUS_ACTIVE,
            "чужая запись не должна пострадать"
        );

        // и наоборот: отзыв ПО УСТРОЙСТВУ гасит породившую ссылку (иначе она выглядела бы как
        // «ещё можно активировать»)
        let by_dev = parse_registry(&registry_apply_revoke(&enrolled, &dev).unwrap());
        assert_eq!(by_dev.iter().find(|x| x.client_id == boot).unwrap().status, "revoked");
        assert_eq!(by_dev.iter().find(|x| x.client_id == dev).unwrap().status, "revoked");
        // строк не прибавилось и не убавилось
        assert_eq!(by_dev.len(), 3);
    }

    /// Строки без флагов (написанные до M-9 или руками оператора) читаются как раньше.
    #[test]
    fn legacy_lines_parse_without_flags() {
        let a = [0x11u8; 32];
        let e = parse_registry(&format!("{} 42 active\n", hex::encode(a)));
        assert_eq!(e.len(), 1);
        assert!(e[0].enroll_until.is_none() && e[0].device.is_none() && e[0].link_hash.is_none());
        // и обратно: запись без флагов не обрастает мусором
        assert_eq!(e[0].to_line(), format!("{} 42 active\n", hex::encode(a)));
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
            AdminRequest::Add {
                client_id: [7u8; 32],
                valid_until: 0,
                enroll_until: None,
                link_hash: None,
            },
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
                ..Default::default()
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
                    let _ = srv.serve_conn(tls, &pq, &pin, || {});
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
