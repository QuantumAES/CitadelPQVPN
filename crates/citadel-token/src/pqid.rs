//! PQ-удостоверение сторон канала издателя: **гибрид Ed25519 + ML-DSA-65** (FIPS 204).
//!
//! Зачем. Канал издателя (`:7000` — выдача токенов) и admin-канал уже идут по TLS 1.3 с
//! единственной гибридной группой `X25519MLKEM768` — то есть КОНФИДЕНЦИАЛЬНОСТЬ пост-квантовая
//! (анти-HNDL, см. [`crate::pqtls`]). А вот АУТЕНТИФИКАЦИЯ до этого модуля была классической:
//!
//!   - издатель предъявлял Ed25519-серт, а клиент верил ему по pin = BLAKE3(DER). Pin привязывает
//!     к конкретному сертификату, но не к владению ключом: CRQC восстанавливает приватный Ed25519
//!     из публичного (он лежит в самом серте) и проходит хендшейк под ТЕМ ЖЕ pin → полный MITM;
//!   - абонент (Layer-1) и админ доказывали владение «абонементом» Ed25519-подписью челленджа —
//!     CRQC подделывает её, зная лишь pub (а pub админа лежит на сервере в `admin_id`, реестр
//!     абонентов — тем более).
//!
//! Что делает этот модуль. Из ТОГО ЖЕ 32-байтного seed (`client_seed`/`admin_seed` в ссылке)
//! детерминированно выводятся ДВА ключа — Ed25519 и ML-DSA-65 — и обе подписи ставятся на одно и
//! то же сообщение. Проверяющая сторона требует ОБЕ: подделка требует сломать и классику, и PQ.
//! Идентификатор владельца (`client_id`, `admin_id`) = `BLAKE3(ed_pub ‖ mldsa_pub)` — 32 байта,
//! поэтому формат реестра, файлов и UI не меняется, но идентичность теперь связывает оба ключа
//! (подменить один, сохранив id, нельзя).
//!
//! Сервер доказывает свою подлинность симметрично: подписывает `DOMAIN ‖ challenge ‖ cert_pin ‖
//! EKM` (channel binding через TLS-exporter, RFC 5705 — как A3 у exit'а, см.
//! `citadel_quic::pqauth`), клиент сверяет ML-DSA pub с 32-байтным обязательством из ссылки.
//! Релей между двумя TLS-сессиями не проходит: EKM у плеч MITM разный.
//!
//! Wire-break: кадры аутентификации сменили формат (CBOR вместо `pub‖sig` фиксированной длины),
//! `client_id` сменил способ вычисления → сервер и клиенты обновляются одновременно, ссылки
//! перевыпускаются (бандл v4, см. `citadel_client::creds`).

use anyhow::{anyhow, bail, Context, Result};
use aws_lc_rs::signature::{KeyPair as _, UnparsedPublicKey};
use aws_lc_rs::unstable::signature::{PqdsaKeyPair, ML_DSA_65, ML_DSA_65_SIGNING};
use serde::{Deserialize, Serialize};

use crate::{ed25519_pub_from_seed, ed25519_sign, ed25519_verify};

/// Длина seed'а (общая для Ed25519 и ML-DSA-65: FIPS 204 выводит ключ из 32-байтного ξ).
pub const SEED_LEN: usize = 32;
/// Длина публичного ключа ML-DSA-65 (FIPS 204).
pub const MLDSA_PUB_LEN: usize = 1952;

/// Домен подписи абонента (Layer-1) — выдача токенов на `:7000`.
pub const DOMAIN_CLIENT: &[u8] = b"CitadelPQVPN/pqid/client/v1";
/// Домен подписи админа — admin-канал (управление реестром).
pub const DOMAIN_ADMIN: &[u8] = b"CitadelPQVPN/pqid/admin/v1";
/// Домен подписи ИЗДАТЕЛЯ (доказательство подлинности сервера обоих каналов).
pub const DOMAIN_ISSUER: &[u8] = b"CitadelPQVPN/pqid/issuer/v1";
/// Домен подписи exit-узла, забирающего ключ эпохи (M-6: `citadel-token keysync`). Отдельный домен
/// нужен, чтобы seed абонента нельзя было предъявить как keysync-идентичность (и наоборот): подпись
/// одного домена в другом не проверится, даже если seed утечёт.
pub const DOMAIN_KEYSYNC: &[u8] = b"CitadelPQVPN/pqid/keysync/v1";
/// M-9: домен подписи УСТРОЙСТВА при активации первичной ссылки. Подписывает НОВАЯ идентичность
/// (та, что рождается на устройстве) — этим она доказывает владение собой; кто именно активируется,
/// издатель знает из уже аутентифицированной сессии первичной ссылки. Отдельный домен нужен, чтобы
/// подпись активации нельзя было предъявить как Layer-1 (и наоборот).
pub const DOMAIN_ENROLL: &[u8] = b"CitadelPQVPN/pqid/enroll/v1";

/// Гибридная пара ключей, выведенная из seed. Секрет (`seed`) не хранится: ключи выводятся заново
/// на каждую подпись — так seed не залёживается копиями в памяти дольше вызова.
pub struct Identity {
    /// Ed25519 pub (32 Б).
    pub ed_pub: [u8; 32],
    /// ML-DSA-65 pub (1952 Б).
    pub mldsa_pub: Vec<u8>,
}

impl Identity {
    /// Вывести гибридную идентичность из seed (детерминированно).
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Result<Self> {
        Ok(Self { ed_pub: ed25519_pub_from_seed(seed)?, mldsa_pub: mldsa_pub_from_seed(seed)? })
    }

    /// Идентификатор владельца: `BLAKE3(ed_pub ‖ mldsa_pub)` — то, что лежит в реестре/`admin_id`.
    pub fn id(&self) -> [u8; 32] {
        identity_id(&self.ed_pub, &self.mldsa_pub)
    }
}

/// ML-DSA-65 pub из seed (FIPS 204 seed→keypair, детерминированно).
pub fn mldsa_pub_from_seed(seed: &[u8; SEED_LEN]) -> Result<Vec<u8>> {
    Ok(keypair(seed)?.public_key().as_ref().to_vec())
}

/// Подписать сообщение ML-DSA-65 ключом из seed.
pub fn mldsa_sign(seed: &[u8; SEED_LEN], msg: &[u8]) -> Result<Vec<u8>> {
    let kp = keypair(seed)?;
    let mut sig = vec![0u8; kp.algorithm().signature_len()];
    let n = kp.sign(msg, &mut sig).map_err(|_| anyhow!("ML-DSA-65 sign"))?;
    sig.truncate(n);
    Ok(sig)
}

/// Проверить ML-DSA-65 подпись под известным pub.
pub fn mldsa_verify(pub_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    UnparsedPublicKey::new(&ML_DSA_65, pub_key).verify(msg, sig).is_ok()
}

fn keypair(seed: &[u8; SEED_LEN]) -> Result<PqdsaKeyPair> {
    PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, seed).map_err(|_| anyhow!("ML-DSA-65 из seed"))
}

/// Идентификатор гибридной идентичности = `BLAKE3(ed_pub ‖ mldsa_pub)`.
///
/// Хеш, а не «просто Ed25519 pub» (как было до PQ-трека): id обязан покрывать ОБА ключа, иначе
/// владелец одного лишь классического ключа (или CRQC, подделавший его) выдавал бы себя за
/// зарегистрированного абонента, подставив собственный ML-DSA pub.
pub fn identity_id(ed_pub: &[u8; 32], mldsa_pub: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(ed_pub);
    h.update(mldsa_pub);
    h.finalize().into()
}

/// `client_id`/`admin_id` прямо из seed (то, что регистрируется у издателя).
pub fn id_from_seed(seed: &[u8; SEED_LEN]) -> Result<[u8; 32]> {
    Ok(Identity::from_seed(seed)?.id())
}

/// Обязательство к ML-DSA-идентичности издателя для ссылки: `BLAKE3(mldsa_pub)` (32 Б).
///
/// В ссылку кладётся именно обязательство, а не сам pub (1952 Б): ссылка и без того несёт ML-DSA
/// pub exit'а, и второй такой же раздул бы QR. Сам pub издатель присылает в hello-кадре, клиент
/// сверяет хеш — стойкость та же (подмена pub ломает хеш).
pub fn issuer_commitment(mldsa_pub: &[u8]) -> [u8; 32] {
    blake3::hash(mldsa_pub).into()
}

// ─────────────────────────── постоянная PQ-идентичность издателя ───────────────────────────

/// Имя файла с seed'ом ML-DSA-идентичности издателя (секрет, 600).
pub const ISSUER_SEED_FILE: &str = "issuer-mldsa.seed";
/// Имя файла с обязательством (hex32) — его читает установщик и кладёт в ссылку.
pub const ISSUER_COMMITMENT_FILE: &str = "issuer-mldsa.pin";

/// PQ-идентичность издателя: 32-байтный seed на диске тома `Citadel_TOKEN_DIR`.
///
/// Постоянная (как TLS-серт, A7): переживает рестарт контейнера, иначе обязательство в уже
/// розданных ссылках инвалидировалось бы при каждом перезапуске и клиенты вставали бы намертво
/// (fail-closed по определению — они обязаны отказаться подключаться к «другому» издателю).
pub struct IssuerPqIdentity {
    seed: [u8; SEED_LEN],
    /// ML-DSA-65 pub (кэш: вывод из seed не бесплатный, а hello строится на каждое соединение).
    pub mldsa_pub: Vec<u8>,
}

impl IssuerPqIdentity {
    /// Загрузить seed из `dir` или сгенерировать (CSPRNG) и сохранить с правами 600.
    /// Публикует обязательство `issuer-mldsa.pin` (hex) — его читает установщик для ссылки.
    pub fn load_or_generate(dir: &str) -> Result<Self> {
        let path = format!("{dir}/{ISSUER_SEED_FILE}");
        let seed: [u8; SEED_LEN] = match std::fs::read(&path) {
            Ok(v) if v.len() == SEED_LEN => v.try_into().expect("len проверен"),
            _ => {
                let mut s = [0u8; SEED_LEN];
                aws_lc_rs::rand::fill(&mut s).map_err(|_| anyhow!("CSPRNG для seed издателя"))?;
                std::fs::write(&path, s).with_context(|| format!("запись {path}"))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
                }
                s
            }
        };
        let mldsa_pub = mldsa_pub_from_seed(&seed)?;
        std::fs::write(format!("{dir}/{ISSUER_COMMITMENT_FILE}"), hex::encode(issuer_commitment(&mldsa_pub)))
            .with_context(|| format!("публикация {dir}/{ISSUER_COMMITMENT_FILE}"))?;
        Ok(Self { seed, mldsa_pub })
    }

    /// Обязательство `BLAKE3(mldsa_pub)` — то, что уходит в `citadel://`-ссылку.
    pub fn commitment(&self) -> [u8; 32] {
        issuer_commitment(&self.mldsa_pub)
    }

    /// Собрать hello-кадр для конкретной TLS-сессии (челлендж + доказательство подлинности).
    pub fn hello(&self, challenge: &[u8], cert_pin: &[u8; 32], ekm: &[u8]) -> Result<Vec<u8>> {
        build_hello(&self.seed, challenge, cert_pin, ekm)
    }
}

impl Drop for IssuerPqIdentity {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.seed.zeroize();
    }
}

// ─────────────────────────── кадры аутентификации ───────────────────────────

/// Приветствие издателя (первый кадр обоих каналов): челлендж + PQ-доказательство подлинности.
///
/// Клиент проверяет его ДО того, как отправит что-либо своё (в т.ч. `client_id` — иначе PQ-MITM
/// собирал бы идентификаторы абонентов, то есть деанонимизировал подписку).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerHello {
    /// Случайный челлендж сессии (его подписывает клиент в своём auth-кадре).
    #[serde(with = "serde_bytes")]
    pub challenge: Vec<u8>,
    /// ML-DSA-65 pub издателя (клиент сверяет `BLAKE3` с обязательством из ссылки).
    #[serde(with = "serde_bytes")]
    pub mldsa_pub: Vec<u8>,
    /// ML-DSA-подпись `DOMAIN_ISSUER ‖ challenge ‖ cert_pin ‖ EKM`.
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

/// Гибридный auth-кадр стороны, доказывающей владение seed (абонент или админ).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridAuth {
    #[serde(with = "serde_bytes")]
    pub ed_pub: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub mldsa_pub: Vec<u8>,
    /// Ed25519-подпись `domain ‖ challenge ‖ EKM`.
    #[serde(with = "serde_bytes")]
    pub ed_sig: Vec<u8>,
    /// ML-DSA-65 подпись ТОГО ЖЕ сообщения.
    #[serde(with = "serde_bytes")]
    pub mldsa_sig: Vec<u8>,
}

/// Первый кадр, который шлёт подключившаяся сторона после `IssuerHello`.
///
/// Типизирован, потому что к издателю ходят ДВА разных потребителя: абонент/админ (доказывают
/// владение seed) и **exit-узел, которому нужен ключ текущей эпохи** — чтобы проверять токены,
/// когда exit и издатель стоят на РАЗНЫХ машинах и общего тома `/shared` нет.
///
/// **M-6:** раньше вторым кадром был `EpochPub` — запрос БЕЗ аутентификации, потому что ключ эпохи
/// был публичным (RSA-pub). В схеме v2 (VOPRF) ключ эпохи — секрет: тот, кто его получил, чеканит
/// токены. Поэтому запрос требует собственной идентичности `keysync` (тот же гибрид Ed25519 +
/// ML-DSA-65, но со СВОИМ доменом — абонентским seed'ом ключ не вытянуть, и наоборот).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientFrame {
    /// Аутентификация владельца seed (абонент на `:7000` или админ на admin-канале).
    Auth(HybridAuth),
    /// «Дай ключ текущей эпохи» — запрос exit-узла (см. `citadel-token keysync`), с доказательством
    /// владения keysync-идентичностью.
    ///
    /// **B-1:** запрос называет ещё и `exit_pin` — узел просит СВОЙ ключ (`k_exit`), а не мастер
    /// эпохи. Pin входит в подписываемое сообщение (см. [`keysync_bound_challenge`]), поэтому
    /// подменить его на pin соседа нельзя даже владельцу keysync-seed'а: подпись перестанет
    /// сходиться. Без этого узел, доказавший свою идентичность, мог бы попросить ключ чужого.
    KeySync {
        auth: HybridAuth,
        #[serde(with = "serde_bytes")]
        exit_pin: Vec<u8>,
        /// P1: «пришли ключ ВМЕСТЕ С НОМЕРОМ ЭПОХИ, для которой он выведен».
        ///
        /// Эпоха входит в вывод ключа (`derive_for_exit`), но по проводу ехал голый скаляр, и
        /// сайдкар подписывал файл `exit-<эпоха>.key` номером СВОИХ часов. Достаточно, чтобы
        /// издатель был на секунду позади (его фоновая ротация просыпается раз в `epoch_secs/4`,
        /// либо часы машин чуть разошлись) — и ключ прошлой эпохи ложился под именем текущей. У
        /// сайдкара это выглядит как «ключ эпохи N обновлён», у exit'а — как исправный каталог с
        /// ключами, а у всех абонентов подряд — «exit отверг анонимный токен» до конца эпохи.
        ///
        /// Флаг, а не безусловный формат ответа, потому что издатель и exit при раздельном деплое
        /// стоят на РАЗНЫХ машинах и обновляются порознь: старый издатель это поле не разберёт и
        /// молча пришлёт голый ключ (как раньше), новый — ответит с меткой только тому, кто её
        /// попросил. Поле не под подписью: оно не влияет ни на выбор ключа, ни на права — только
        /// на формат ответа, а канал и так PQ-TLS с пиннингом.
        #[serde(default)]
        want_epoch: bool,
    },
}

/// B-1: челлендж keysync, привязанный к pin запрашивающего узла: `H(challenge ‖ exit_pin)`.
///
/// Обе стороны считают его одинаково и подписывают/проверяют именно его. Так `exit_pin`, который
/// едет отдельным полем кадра, оказывается под подписью, не меняя формат [`HybridAuth`].
pub fn keysync_bound_challenge(challenge: &[u8], exit_pin: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("CitadelPQVPN/keysync/v2/exit-bind");
    h.update(challenge);
    h.update(exit_pin);
    *h.finalize().as_bytes()
}

/// Собрать кадр-запрос ключа эпохи (exit-узел доказывает свою keysync-идентичность и называет
/// свой pin — B-1: издатель выведет ключ ровно для этого узла).
pub fn build_keysync_request(
    seed: &[u8; SEED_LEN],
    challenge: &[u8],
    ekm: &[u8],
    exit_pin: &[u8; 32],
) -> Result<Vec<u8>> {
    let bound = keysync_bound_challenge(challenge, exit_pin);
    let raw = build_auth(seed, DOMAIN_KEYSYNC, &bound, ekm)?;
    match parse_client_frame(&raw)? {
        ClientFrame::Auth(a) => to_cbor(&ClientFrame::KeySync {
            auth: a,
            exit_pin: exit_pin.to_vec(),
            want_epoch: true,
        }),
        ClientFrame::KeySync { .. } => unreachable!("build_auth возвращает Auth"),
    }
}

/// Разобрать первый кадр клиента (сервер решает, что делать дальше).
pub fn parse_client_frame(raw: &[u8]) -> Result<ClientFrame> {
    from_cbor(raw).context("первый кадр клиента: CBOR")
}

/// Подписываемое сообщение стороны-клиента: `domain ‖ challenge ‖ EKM`.
fn auth_msg(domain: &[u8], challenge: &[u8], ekm: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(domain.len() + challenge.len() + ekm.len());
    m.extend_from_slice(domain);
    m.extend_from_slice(challenge);
    m.extend_from_slice(ekm);
    m
}

/// Подписываемое сообщение издателя: `DOMAIN_ISSUER ‖ challenge ‖ cert_pin ‖ EKM`.
fn hello_msg(challenge: &[u8], cert_pin: &[u8; 32], ekm: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(DOMAIN_ISSUER.len() + challenge.len() + 32 + ekm.len());
    m.extend_from_slice(DOMAIN_ISSUER);
    m.extend_from_slice(challenge);
    m.extend_from_slice(cert_pin);
    m.extend_from_slice(ekm);
    m
}

/// Издатель: собрать hello-кадр (CBOR).
pub fn build_hello(
    issuer_seed: &[u8; SEED_LEN],
    challenge: &[u8],
    cert_pin: &[u8; 32],
    ekm: &[u8],
) -> Result<Vec<u8>> {
    let hello = IssuerHello {
        challenge: challenge.to_vec(),
        mldsa_pub: mldsa_pub_from_seed(issuer_seed)?,
        sig: mldsa_sign(issuer_seed, &hello_msg(challenge, cert_pin, ekm))?,
    };
    to_cbor(&hello)
}

/// Клиент: проверить hello-кадр издателя. Возвращает челлендж сессии.
///
/// Fail-closed по всем трём осям: обязательство из ссылки ≠ присланный pub, подпись не сходится,
/// либо кадр не разбирается — соединение обязано умереть ДО отправки собственной идентичности.
pub fn verify_hello(
    raw: &[u8],
    commitment: &[u8; 32],
    cert_pin: &[u8; 32],
    ekm: &[u8],
) -> Result<Vec<u8>> {
    let hello: IssuerHello = from_cbor(raw).context("hello издателя: CBOR")?;
    if hello.challenge.len() != 32 {
        bail!("hello издателя: челлендж {} Б (ожидалось 32)", hello.challenge.len());
    }
    if hello.mldsa_pub.len() != MLDSA_PUB_LEN {
        bail!("hello издателя: ML-DSA pub {} Б (ожидалось {MLDSA_PUB_LEN})", hello.mldsa_pub.len());
    }
    if &issuer_commitment(&hello.mldsa_pub) != commitment {
        bail!("hello издателя: ML-DSA-идентичность не совпала с обязательством из ссылки (MITM/чужой сервер?)");
    }
    if !mldsa_verify(&hello.mldsa_pub, &hello_msg(&hello.challenge, cert_pin, ekm), &hello.sig) {
        bail!("hello издателя: ML-DSA-подпись привязки неверна (релей чужой сессии?)");
    }
    Ok(hello.challenge)
}

/// Сторона-клиент (абонент/админ): собрать гибридный auth-кадр (CBOR).
pub fn build_auth(
    seed: &[u8; SEED_LEN],
    domain: &[u8],
    challenge: &[u8],
    ekm: &[u8],
) -> Result<Vec<u8>> {
    let id = Identity::from_seed(seed)?;
    let msg = auth_msg(domain, challenge, ekm);
    let auth = HybridAuth {
        ed_pub: id.ed_pub.to_vec(),
        mldsa_pub: id.mldsa_pub,
        ed_sig: ed25519_sign(seed, &msg)?.to_vec(),
        mldsa_sig: mldsa_sign(seed, &msg)?,
    };
    to_cbor(&ClientFrame::Auth(auth))
}

/// Издатель: проверить гибридный auth-кадр. Возвращает `id` предъявителя
/// (`BLAKE3(ed_pub ‖ mldsa_pub)`) — по нему сверяется реестр/`admin_id`.
///
/// Требуются ОБЕ подписи: одной классической мало (её подделает CRQC), одной PQ — тоже
/// (гибрид держит, даже если в ML-DSA найдут слабость).
pub fn verify_auth(raw: &[u8], domain: &[u8], challenge: &[u8], ekm: &[u8]) -> Result<[u8; 32]> {
    match parse_client_frame(raw)? {
        ClientFrame::Auth(auth) => verify_hybrid(auth, domain, challenge, ekm),
        ClientFrame::KeySync { .. } => bail!("на этом канале доступна только аутентификация"),
    }
}

/// Проверка уже разобранного auth-кадра (общая для обоих каналов).
pub fn verify_hybrid(
    auth: HybridAuth,
    domain: &[u8],
    challenge: &[u8],
    ekm: &[u8],
) -> Result<[u8; 32]> {
    let ed_pub: [u8; 32] = auth
        .ed_pub
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("auth-кадр: Ed25519 pub {} Б (ожидалось 32)", auth.ed_pub.len()))?;
    if auth.mldsa_pub.len() != MLDSA_PUB_LEN {
        bail!("auth-кадр: ML-DSA pub {} Б (ожидалось {MLDSA_PUB_LEN})", auth.mldsa_pub.len());
    }
    let msg = auth_msg(domain, challenge, ekm);
    if !ed25519_verify(&ed_pub, &msg, &auth.ed_sig) {
        bail!("auth-кадр: Ed25519-подпись неверна (нет домена/EKM или подделка)");
    }
    if !mldsa_verify(&auth.mldsa_pub, &msg, &auth.mldsa_sig) {
        bail!("auth-кадр: ML-DSA-подпись неверна");
    }
    Ok(identity_id(&ed_pub, &auth.mldsa_pub))
}

fn to_cbor<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(v, &mut buf).context("CBOR-сериализация кадра")?;
    Ok(buf)
}

fn from_cbor<T: for<'de> Deserialize<'de>>(raw: &[u8]) -> Result<T> {
    ciborium::from_reader(raw).map_err(|e| anyhow!("разбор кадра: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EKM: &[u8] = &[0x5au8; 32];
    const PIN: [u8; 32] = [0x77u8; 32];

    #[test]
    fn identity_is_deterministic_and_binds_both_keys() {
        let seed = [0x11u8; SEED_LEN];
        let a = Identity::from_seed(&seed).unwrap();
        let b = Identity::from_seed(&seed).unwrap();
        assert_eq!(a.ed_pub, b.ed_pub, "Ed25519 из seed детерминирован");
        assert_eq!(a.mldsa_pub, b.mldsa_pub, "ML-DSA из seed детерминирован");
        assert_eq!(a.mldsa_pub.len(), MLDSA_PUB_LEN);
        assert_eq!(a.id(), id_from_seed(&seed).unwrap());

        // id покрывает ОБА ключа: подмена любого меняет идентификатор.
        let other = Identity::from_seed(&[0x22u8; SEED_LEN]).unwrap();
        assert_ne!(a.id(), identity_id(&a.ed_pub, &other.mldsa_pub));
        assert_ne!(a.id(), identity_id(&other.ed_pub, &a.mldsa_pub));
        assert_ne!(a.id(), other.id());
    }

    #[test]
    fn hybrid_auth_roundtrip() {
        let seed = [0x33u8; SEED_LEN];
        let challenge = [0x44u8; 32];
        let frame = build_auth(&seed, DOMAIN_CLIENT, &challenge, EKM).unwrap();
        let id = verify_auth(&frame, DOMAIN_CLIENT, &challenge, EKM).unwrap();
        assert_eq!(id, id_from_seed(&seed).unwrap());
    }

    /// Домены разделены: подпись абонента не проходит как admin-подпись (и наоборот) — даже если
    /// ключ один и тот же. Иначе Layer-1 auth к `:7000` открывал бы admin-канал.
    #[test]
    fn domain_separation_enforced() {
        let seed = [0x55u8; SEED_LEN];
        let challenge = [0x66u8; 32];
        let frame = build_auth(&seed, DOMAIN_CLIENT, &challenge, EKM).unwrap();
        assert!(verify_auth(&frame, DOMAIN_ADMIN, &challenge, EKM).is_err());
    }

    /// Channel binding: кадр, снятый в одной TLS-сессии, не проходит в другой (у плеч MITM
    /// разный EKM). И чужой челлендж тоже не принимается (анти-replay).
    #[test]
    fn auth_is_bound_to_session() {
        let seed = [0x77u8; SEED_LEN];
        let challenge = [0x88u8; 32];
        let frame = build_auth(&seed, DOMAIN_CLIENT, &challenge, EKM).unwrap();
        assert!(verify_auth(&frame, DOMAIN_CLIENT, &challenge, &[0xEEu8; 32]).is_err());
        assert!(verify_auth(&frame, DOMAIN_CLIENT, &[0x99u8; 32], EKM).is_err());
    }

    /// Гибрид требует ОБЕ подписи: кадр с валидной классической и битой PQ-подписью (ровно то, что
    /// сможет предъявить квантовый противник, подделавший Ed25519) отвергается.
    #[test]
    fn classical_signature_alone_is_not_enough() {
        let seed = [0xAAu8; SEED_LEN];
        let challenge = [0xBBu8; 32];
        let raw = build_auth(&seed, DOMAIN_CLIENT, &challenge, EKM).unwrap();
        let ClientFrame::Auth(mut auth) = parse_client_frame(&raw).unwrap() else {
            panic!("build_auth собирает кадр аутентификации")
        };
        let pristine = auth.clone();
        auth.mldsa_sig[0] ^= 1;
        let forged = to_cbor(&ClientFrame::Auth(auth)).unwrap();
        assert!(verify_auth(&forged, DOMAIN_CLIENT, &challenge, EKM).is_err());

        // ...и наоборот: одной PQ-подписи без классической тоже мало.
        let mut auth2 = pristine;
        auth2.ed_sig[0] ^= 1;
        let forged2 = to_cbor(&ClientFrame::Auth(auth2)).unwrap();
        assert!(verify_auth(&forged2, DOMAIN_CLIENT, &challenge, EKM).is_err());
    }

    /// Подмена ML-DSA pub на собственный (при валидной классической подписи) не даёт выдать себя
    /// за зарегистрированного абонента: id считается по ОБОИМ ключам и в реестре не найдётся.
    #[test]
    fn swapped_pq_key_yields_different_id() {
        let victim = [0xCCu8; SEED_LEN];
        let attacker = [0xDDu8; SEED_LEN];
        let challenge = [0xEEu8; 32];
        let msg = auth_msg(DOMAIN_CLIENT, &challenge, EKM);
        let forged = HybridAuth {
            ed_pub: ed25519_pub_from_seed(&victim).unwrap().to_vec(),
            mldsa_pub: mldsa_pub_from_seed(&attacker).unwrap(),
            // «CRQC подделал классическую подпись жертвы» — моделируем прямой подписью её seed'ом.
            ed_sig: ed25519_sign(&victim, &msg).unwrap().to_vec(),
            mldsa_sig: mldsa_sign(&attacker, &msg).unwrap(),
        };
        let id = verify_auth(&to_cbor(&ClientFrame::Auth(forged)).unwrap(), DOMAIN_CLIENT, &challenge, EKM)
            .unwrap();
        assert_ne!(id, id_from_seed(&victim).unwrap(), "подделка не выдаёт себя за жертву");
    }

    #[test]
    fn issuer_hello_roundtrip_and_pin_binding() {
        let iseed = [0x0Fu8; SEED_LEN];
        let commitment = issuer_commitment(&mldsa_pub_from_seed(&iseed).unwrap());
        let challenge = [0x10u8; 32];
        let raw = build_hello(&iseed, &challenge, &PIN, EKM).unwrap();

        let got = verify_hello(&raw, &commitment, &PIN, EKM).unwrap();
        assert_eq!(got, challenge.to_vec());

        // чужой издатель (обязательство из ссылки не сходится)
        let other = issuer_commitment(&mldsa_pub_from_seed(&[0x20u8; SEED_LEN]).unwrap());
        assert!(verify_hello(&raw, &other, &PIN, EKM).is_err());
        // релей в другую TLS-сессию (другой EKM) и подмена серта (другой pin)
        assert!(verify_hello(&raw, &commitment, &PIN, &[0x21u8; 32]).is_err());
        assert!(verify_hello(&raw, &commitment, &[0x22u8; 32], EKM).is_err());
    }

    /// Запрос ключа эпохи (кадр exit-узла) не проходит там, где требуется аутентификация абонента
    /// или админа: иначе keysync-идентичность открывала бы admin-канал и Layer-1.
    ///
    /// M-6: и обратно — **абонентский seed не годится в keysync**. Домены разные, подпись одного в
    /// другом не проверяется, поэтому утечка ссылки абонента не даёт секрет эпохи (а он теперь
    /// позволяет чеканить токены).
    #[test]
    fn keysync_request_is_domain_separated() {
        let seed = [0x5eu8; SEED_LEN];
        let challenge = [0u8; 32];
        let pin = [0x77u8; 32];
        let bound = keysync_bound_challenge(&challenge, &pin);
        let raw = build_keysync_request(&seed, &challenge, EKM, &pin).unwrap();
        assert!(verify_auth(&raw, DOMAIN_CLIENT, &bound, EKM).is_err());
        assert!(verify_auth(&raw, DOMAIN_ADMIN, &bound, EKM).is_err());
        let ClientFrame::KeySync { auth, exit_pin, want_epoch } = parse_client_frame(&raw).unwrap()
        else {
            panic!("ожидался keysync-кадр");
        };
        assert_eq!(exit_pin, pin.to_vec(), "узел называет свой pin (B-1)");
        assert!(want_epoch, "P1: сайдкар просит ключ вместе с номером эпохи, под который он выведен");
        // Совместимость с издателем прежней версии: поле необязательное, кадр без него разбирается
        // (и означает «метку не присылай») — иначе обновление одной машины из двух ломало бы связь.
        let legacy = to_cbor(&ClientFrame::KeySync {
            auth: auth.clone(),
            exit_pin: pin.to_vec(),
            want_epoch: false,
        })
        .unwrap();
        assert!(matches!(
            parse_client_frame(&legacy).unwrap(),
            ClientFrame::KeySync { want_epoch: false, .. }
        ));
        assert_eq!(
            verify_hybrid(auth.clone(), DOMAIN_KEYSYNC, &bound, EKM).unwrap(),
            id_from_seed(&seed).unwrap(),
            "издатель опознаёт exit по keysync-id"
        );
        // тот же кадр под чужим доменом не проходит
        assert!(verify_hybrid(auth.clone(), DOMAIN_CLIENT, &bound, EKM).is_err());
        // B-1: подпись накрывает pin — подставить чужой (чтобы получить ключ соседа) нельзя
        let other = keysync_bound_challenge(&challenge, &[0x88u8; 32]);
        assert!(
            verify_hybrid(auth, DOMAIN_KEYSYNC, &other, EKM).is_err(),
            "подмена pin обязана ломать подпись"
        );
        // и наоборот: абонентский auth-кадр не сойдёт за keysync
        let as_client = build_auth(&seed, DOMAIN_CLIENT, &bound, EKM).unwrap();
        let ClientFrame::Auth(a) = parse_client_frame(&as_client).unwrap() else { unreachable!() };
        assert!(verify_hybrid(a, DOMAIN_KEYSYNC, &bound, EKM).is_err());
    }

    /// Мусор на входе не роняет верификаторы (кадры приходят из сети до всякой аутентификации).
    #[test]
    fn malformed_frames_do_not_panic() {
        let mut s = 0x1234_5678_9abc_def0u64;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..500 {
            let len = (next() % 300) as usize;
            let buf: Vec<u8> = (0..len).map(|_| (next() >> 33) as u8).collect();
            let _ = verify_auth(&buf, DOMAIN_CLIENT, &[0u8; 32], EKM);
            let _ = verify_hello(&buf, &[0u8; 32], &PIN, EKM);
        }
    }
}
