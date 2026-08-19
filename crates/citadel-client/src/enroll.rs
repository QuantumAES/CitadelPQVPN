//! M-9: активация первичной ссылки — превращение bearer-контейнера в устройственный доступ.
//!
//! **Что чинится.** `citadel://` несёт секреты инлайн: PSK обфускации и Layer-1 seed «абонемента».
//! Пока ссылка многоразовая и бессрочная, кто её скопировал — тот и абонент: скриншот QR,
//! пересылка в мессенджере, бэкап приложения, история терминала. Аудит-4 назвал это M-9 и
//! предложил ровно то, что здесь сделано: **срок годности** и **одноразовость** — «ссылка
//! активируется один раз и превращается в устройство-специфичный материал».
//!
//! **Как это работает.** При выдаче админ помечает запись реестра окном активации и **заверяет
//! отпечаток ссылки** у издателя. Устройство при первом использовании создаёт СВОЙ Layer-1 ключ,
//! предъявляет его издателю (подписав ключом из ссылки — [`citadel_token::enroll_device`]) и
//! получает подписку на него. Запись исходной ссылки после этого `consumed`: та же ссылка на
//! другом устройстве не работает, а её копия у постороннего не стоит ничего.
//!
//! **Порядок операций выбран под отказы, а не под красоту:**
//!   1. ключ устройства создаётся и **сохраняется в хранилище** (`device_seed`, `enrolled=false`);
//!   2. только потом уходит запрос издателю;
//!   3. подтверждение помечает профиль `enrolled=true`.
//!
//! Если процесс умрёт между 2 и 3 — повторная активация с тем же ключом идемпотентна и завершит
//! начатое. Обратный порядок (сначала сеть) при той же аварии оставил бы человека с ключом,
//! которого нет ни у него, ни у сервера.
//!
//! **Чего активация не даёт.** Она не спасает ссылку, украденную ДО первого использования: вор,
//! успевший активировать её раньше владельца, и станет владельцем. Против этого работают срок
//! (окно узкое) и то, что законный абонент сразу увидит отказ «уже активирована на другом
//! устройстве» — то есть кража перестаёт быть незаметной, а это и есть главное отличие от
//! bearer-секрета, который делится молча.

use anyhow::{anyhow, Context, Result};

use crate::creds::CredentialLink;
use crate::vault::Profile;

/// Стабильная примета «активация не состоялась из-за СЕТИ, а не из-за ссылки».
///
/// Это два разных ответа человеку, и путать их дорого: отказ издателя значит «просите новую
/// ссылку у администратора», недоступность издателя — «включите сеть и повторите». К интерфейсу
/// через FFI едет только текст ошибки, поэтому различие обязано жить в нём и быть стабильным:
/// клиент ищет ровно эту подстроку ([`crate::enroll::OFFLINE_MARK`]). Пока её не было, попытка
/// активироваться без сети показывалась как «ссылку не удалось активировать: запросите новую» —
/// то есть целая ссылка выглядела сожжённой, а человек шёл к администратору вместо Wi-Fi.
pub const OFFLINE_MARK: &str = "нет связи с издателем";

/// Отказ активации → ошибка, в которой различима недоступность издателя (см. [`OFFLINE_MARK`]).
/// Ссылку при этом НИЧТО не тронуло: до издателя мы не дошли, а ключ устройства уже сохранён и
/// повтор доведёт активацию тем же ключом.
fn classify(e: anyhow::Error) -> anyhow::Error {
    if e.downcast_ref::<citadel_token::IssuerUnreachable>().is_some() {
        return e.context(format!("{OFFLINE_MARK}: активация не начиналась, ссылка цела"));
    }
    e
}

/// Что сделала [`activate_profile`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Activation {
    /// Активация не требуется: ссылка многоразовая (или профиль уже активирован).
    NotRequired,
    /// Ссылка активирована на этом устройстве (или подтверждена повторно — идемпотентно).
    Activated,
}

/// Свежий ключ устройства из системного CSPRNG (тот же источник, что у vault и движка).
fn random_seed() -> Result<[u8; 32]> {
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};
    let mut s = [0u8; 32];
    SystemRandom::new().fill(&mut s).map_err(|_| anyhow!("CSPRNG"))?;
    Ok(s)
}

/// Layer-1 ключ, которым профиль обязан представляться издателю: устройственный (после активации)
/// либо из ссылки (до неё / многоразовая ссылка).
///
/// Единая точка на всех клиентов: разойтись здесь — значит либо ходить мёртвым ключом ссылки после
/// активации, либо предъявлять непринятый сервером ключ устройства до неё.
pub fn effective_seed(profile: &Profile, link: &CredentialLink) -> Option<[u8; 32]> {
    match (profile.enrolled, profile.device_seed) {
        (true, Some(s)) => Some(s),
        _ => link.client_seed,
    }
}

/// Всё, что нужно для активации, вынуто из профиля и ссылки ОДИН раз: дальше шаги (сохранить
/// ключ → сходить к издателю → подтвердить) не зависят от разбора и проверок.
#[derive(Clone)]
struct Plan {
    issuer: String,
    pin: [u8; 32],
    mldsa: [u8; 32],
    bootstrap: [u8; 32],
    link_hash: [u8; 32],
    obfs_psk: Option<[u8; 32]>,
    /// Ключ устройства, уже сохранённый прошлой (оборванной) попыткой.
    existing: Option<[u8; 32]>,
}

impl Plan {
    /// Сетевой шаг (блокирующий протокол издателя).
    fn enroll(&self, device_seed: &[u8; 32]) -> Result<bool> {
        citadel_token::enroll_device(
            &self.issuer,
            &self.pin,
            &self.mldsa,
            &self.bootstrap,
            device_seed,
            &self.link_hash,
            3,
            self.obfs_psk,
        )
    }
}

/// Разбор профиля и все проверки «до сети». `None` — активировать нечего (нет Layer-1, профиль уже
/// активирован). Просроченная ссылка — ошибка ЗДЕСЬ: человеку нужен ответ «запросите новую», а не
/// десять секунд таймаутов и «издатель недоступен».
fn plan(profile: &Profile) -> Result<Option<Plan>> {
    if profile.enrolled {
        return Ok(None); // уже наше устройство
    }
    let link = CredentialLink::from_uri(&profile.uri).context("разбор ссылки профиля")?;
    // Ходить к издателю «на всякий случай» перед каждым подключением нельзя: это ровно тот
    // паттерн, который §7.1 только что убрал (обращение к издателю в момент старта сессии).
    // Поэтому активацию затевает либо признак в ссылке, либо незавершённая прошлая попытка.
    // Подменённая ссылка со снятым признаком ничего не выигрывает: издатель всё равно потребует
    // активацию на первом же фетче токенов, и человек увидит внятную причину, а не тихий доступ.
    if !link.enroll && profile.device_seed.is_none() {
        return Ok(None);
    }
    let (Some(issuer), Some(pin), Some(mldsa), Some(bootstrap)) =
        (link.issuer.clone(), link.issuer_pin, link.issuer_mldsa, link.client_seed)
    else {
        return Ok(None); // без Layer-1 активировать нечего
    };
    if link.activation_expired(now_unix()) {
        anyhow::bail!(
            "срок действия ссылки истёк — запросите новую у администратора (ссылка \
             действительна ограниченное время, чтобы утёкшая копия ничего не стоила)"
        );
    }
    let link_hash = link.link_hash().ok_or_else(|| anyhow!("в ссылке нет Layer-1 идентичности"))?;
    Ok(Some(Plan {
        issuer,
        pin,
        mldsa,
        bootstrap,
        link_hash,
        obfs_psk: link.obfs_psk,
        existing: profile.device_seed,
    }))
}

/// Активировать профиль, если издатель этого требует. Идемпотентна и безопасна для повторного
/// вызова: `NotRequired` — обычная ссылка либо активация уже подтверждена.
///
/// Хранилище трогается **двумя короткими callback'ами**, а не удерживается на всё время сетевого
/// обмена: `save_seed` (шаг 1, до сети) и `mark_enrolled` (шаг 3, после подтверждения). Так
/// вызывающий берёт свой замок на миллисекунды, а не на секунды таймаутов издателя — и не рискует
/// заблокировать интерфейс (а на стороне GUI ещё и держать `std::sync::Mutex` через `.await`).
pub async fn activate_profile<S, M>(
    profile: &Profile,
    save_seed: S,
    mark_enrolled: M,
) -> Result<Activation>
where
    S: FnOnce(&[u8; 32]) -> Result<()>,
    M: FnOnce() -> Result<()>,
{
    let Some(plan) = plan(profile)? else { return Ok(Activation::NotRequired) };
    let seed = ensure_seed(&plan, save_seed)?;
    let p = plan.clone();
    // Протокол издателя блокирующий — как и весь этот канал, гоняем его в blocking-пуле.
    let done = tokio::task::spawn_blocking(move || p.enroll(&seed))
        .await
        .context("задача активации паникнула")?
        .map_err(classify)?;
    confirm(done, mark_enrolled)
}

/// Синхронная активация — для консольного клиента: там нет tokio-runtime, а весь протокол издателя
/// и так блокирующий. Логика та же (и тот же порядок шагов), чтобы поведение платформ не разъехалось.
pub fn activate_profile_blocking<S, M>(
    profile: &Profile,
    save_seed: S,
    mark_enrolled: M,
) -> Result<Activation>
where
    S: FnOnce(&[u8; 32]) -> Result<()>,
    M: FnOnce() -> Result<()>,
{
    let Some(plan) = plan(profile)? else { return Ok(Activation::NotRequired) };
    let seed = ensure_seed(&plan, save_seed)?;
    confirm(plan.enroll(&seed).map_err(classify)?, mark_enrolled)
}

/// Шаг 1: ключ устройства. Берём уже сохранённый (оборванная попытка обязана продолжиться ТЕМ ЖЕ
/// ключом — иначе издатель справедливо откажет «уже активирована на другом устройстве») либо
/// создаём новый и сохраняем ДО обращения к издателю.
fn ensure_seed<S>(plan: &Plan, save_seed: S) -> Result<[u8; 32]>
where
    S: FnOnce(&[u8; 32]) -> Result<()>,
{
    match plan.existing {
        Some(s) => Ok(s),
        None => {
            let s = random_seed()?;
            save_seed(&s).context("сохранить ключ устройства")?;
            Ok(s)
        }
    }
}

/// Шаг 3: подтверждение. `false` от издателя означает «активация не требуется» — ключ устройства
/// остаётся в хранилище неподтверждённым и не используется (Layer-1 идёт ключом из ссылки).
fn confirm<M>(done: bool, mark_enrolled: M) -> Result<Activation>
where
    M: FnOnce() -> Result<()>,
{
    if !done {
        return Ok(Activation::NotRequired);
    }
    mark_enrolled().context("отметить профиль активированным")?;
    Ok(Activation::Activated)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::creds::{CredentialBundle, BUNDLE_VERSION};

    fn link_with(seed: Option<[u8; 32]>, exp: Option<u64>) -> CredentialLink {
        let mut l = CredentialLink::from_bundle(&CredentialBundle {
            version: BUNDLE_VERSION,
            servers: vec!["exit:4433".into()],
            server_name: "citadel.exit".into(),
            kx_suite: "pq".into(),
            cert_pin: Some([1u8; 32]),
            mldsa_pub: None,
            obfs_psk: None,
            tcp_port: None,
            issuer: Some("issuer:7000".into()),
            issuer_pub: None,
            issuer_pin: Some([2u8; 32]),
            issuer_mldsa: Some([3u8; 32]),
            client_seed: seed,
            admin_seed: None,
            admin_port: None,
            routes: String::new(),
            dns: None,
            exp,
            enroll: true,
        });
        l.exp = exp;
        l
    }

    fn profile(device_seed: Option<[u8; 32]>, enrolled: bool) -> Profile {
        Profile {
            id: "p1".into(),
            name: "n".into(),
            uri: String::new(),
            created: 0,
            last_exit: None,
            device_seed,
            enrolled,
        }
    }

    /// Ключ выбирается по состоянию активации: до подтверждения — из ссылки, после — устройственный.
    /// Ошибка здесь означает либо мёртвый ключ на проводе, либо ключ, которого сервер не знает.
    #[test]
    fn effective_seed_follows_enrollment_state() {
        let link = link_with(Some([9u8; 32]), None);
        assert_eq!(effective_seed(&profile(None, false), &link), Some([9u8; 32]));
        // ключ создан, но издатель ещё не подтвердил → идём ключом из ссылки
        assert_eq!(effective_seed(&profile(Some([7u8; 32]), false), &link), Some([9u8; 32]));
        // подтверждено → только устройственный
        assert_eq!(effective_seed(&profile(Some([7u8; 32]), true), &link), Some([7u8; 32]));
    }

    /// Многоразовая ссылка (без признака первичной) не порождает НИ ОДНОГО обращения к издателю:
    /// иначе активация вернула бы в клиент ровно тот паттерн «поход к издателю в момент старта
    /// сессии», который убран в §7.1.
    #[test]
    fn plain_link_costs_no_issuer_round_trip() {
        let mut b = crate::creds::CredentialBundle {
            version: BUNDLE_VERSION,
            servers: vec!["exit:4433".into()],
            server_name: "citadel.exit".into(),
            kx_suite: "pq".into(),
            cert_pin: Some([1u8; 32]),
            mldsa_pub: None,
            obfs_psk: None,
            tcp_port: None,
            issuer: Some("issuer:7000".into()),
            issuer_pub: None,
            issuer_pin: Some([2u8; 32]),
            issuer_mldsa: Some([3u8; 32]),
            client_seed: Some([9u8; 32]),
            admin_seed: None,
            admin_port: None,
            routes: String::new(),
            dns: None,
            exp: None,
            enroll: false,
        };
        let uri = CredentialLink::from_bundle(&b).to_uri().unwrap();
        let mut p = profile(None, false);
        p.uri = uri;
        assert!(plan(&p).unwrap().is_none(), "многоразовая ссылка — активации нет");
        // ...а первичная — есть.
        b.enroll = true;
        b.exp = Some(now_unix() + 600);
        p.uri = CredentialLink::from_bundle(&b).to_uri().unwrap();
        assert!(plan(&p).unwrap().is_some(), "первичная ссылка требует активации");
        // Незавершённая прошлая попытка доводится до конца даже без признака в ссылке.
        b.enroll = false;
        p.uri = CredentialLink::from_bundle(&b).to_uri().unwrap();
        p.device_seed = Some([7u8; 32]);
        assert!(plan(&p).unwrap().is_some(), "начатая активация обязана завершиться");
    }

    /// Просроченная ссылка отвергается ДО обращения к издателю (внятная причина без сети).
    #[test]
    fn expiry_is_checked_locally() {
        let now = now_unix();
        assert!(link_with(Some([9u8; 32]), Some(now - 1)).activation_expired(now));
        assert!(!link_with(Some([9u8; 32]), Some(now + 60)).activation_expired(now));
        assert!(!link_with(Some([9u8; 32]), None).activation_expired(now), "без срока — не истекает");
        assert!(!link_with(Some([9u8; 32]), Some(0)).activation_expired(now), "0 = срока нет");
    }
}
