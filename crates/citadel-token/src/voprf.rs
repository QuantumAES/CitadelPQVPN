//! Layer-2 **v2**: анонимные токены на VOPRF (2HashDH) над ristretto255 — замена blind RSA (M-6).
//!
//! ## Зачем меняли схему
//!
//! Аудит-4 (M-6, M-10) зафиксировал две вещи про прежний Layer-2 (`blind RSA-2048`, RFC 9474):
//!
//!  * **RSA-2048 в постквантовом продукте.** CRQC восстанавливает `d` из опубликованного `n` —
//!    и чеканит токены неограниченно: контроль доступа, квоты и отзыв обнуляются. Публичный ключ
//!    эпохи при этом лежал файлом и отдавался по запросу без аутентификации, то есть материал
//!    для будущей атаки собирался тривиально и заранее.
//!  * **`rsa 0.8.2` — RUSTSEC-2023-0071 «Marvin»**, тайминговый сайд-канал в приватной операции;
//!    исправленной версии не существует ни в одной ветке крейта.
//!
//! Плюс третье, вскрывшееся при закрытии H-2: в blind RSA **невозможна привязка токена к сессии**.
//! Токен там — bearer-строка: предъявитель доказывает ЗНАНИЕ подписи над nonce, а не ВЛАДЕНИЕ
//! ключом, поэтому украденный токен работает у кого угодно. Отсюда и выбор схемы: нужна такая, где
//! у клиента после выдачи остаётся **секрет**, которым можно подписать контекст соединения.
//!
//! ## Конструкция
//!
//! 2HashDH (та же, что в Privacy Pass / RFC 9497 `OPRF(ristretto255)`), режим **verifiable**:
//!
//! ```text
//! ключ эпохи:  k ← Z_q,  K = k·G                      (32 Б секрет, 32 Б публичный)
//! выдача:      клиент:  nonce ← rand(32),  P = H2G(nonce),  r ← Z_q*,  B = r·P   → B
//!              издатель: E = k·B,  π = DLEQ(G,K; B,E)                            → E‖π
//!              клиент:  проверяет π,  N = r⁻¹·E,  y = Finalize(nonce, N)
//! токен:       (nonce, y)   — y НИКОГДА не покидает устройство
//! предъявление: клиент шлёт  nonce ‖ MAC_y(контекст сессии)
//!              exit: N' = k·H2G(nonce),  y' = Finalize(nonce, N'),  сверяет MAC
//! ```
//!
//! Что это даёт против прежней схемы:
//!
//! | | blind RSA-2048 | VOPRF ristretto255 |
//! |---|---|---|
//! | Привязка к сессии | невозможна (bearer) | **есть** (MAC над exporter'ом, см. [`Token::redeem`]) |
//! | Токен на проводе | 320 Б | **64 Б** |
//! | Генерация ключа эпохи | ~10 с (RSA keygen) | **микросекунды** |
//! | Тайминговые каналы | Marvin (M-10) | постоянное время (dalek) |
//! | Публичный материал | `n` файлом, отдаётся без auth | секрет `k`, только аутентифицированным |
//!
//! ## Чего это НЕ даёт — и почему так
//!
//! **VOPRF не постквантовый.** Практичной PQ-схемы анонимных токенов на 2026 год не существует:
//! слепая подпись требует гомоморфной структуры, единственные PQ-кандидаты — решёточные слепые
//! подписи (Rai-Choo и родственные, ~10 КБ на подпись) — не стандартизованы, не имеют
//! проверенных реализаций и меняются от статьи к статье. Поэтому здесь честная граница:
//!
//!  * **Анонимность (unlinkability) — информационно-теоретическая и от квантового противника НЕ
//!    страдает.** Ослеплённый элемент `B = r·P` при равномерном `r` равномерен в группе и
//!    статистически независим от `nonce`: для ЛЮБОЙ пары «выдача ↔ предъявление» существует
//!    подходящее `r`. Никакой вычислительной мощности не хватит связать их задним числом —
//!    HNDL к анонимности неприменим (это же верно и для прежнего blind RSA).
//!  * **Неподделываемость — классическая (DDH).** CRQC, узнав `K`, вычисляет `k` и чеканит токены.
//!    Но: (а) ключ живёт одну эпоху (по умолчанию час) ⇒ атака должна быть ОНЛАЙН, «накопить и
//!    посчитать потом» не работает — просроченный ключ бесполезен; (б) `K` больше не публикуется
//!    никому, кроме аутентифицированных абонентов и exit-узла (см. [`crate::fetch_tokens`]);
//!    (в) Layer-1 («абонемент», доступ к выдаче) — уже гибридный Ed25519+ML-DSA-65, то есть
//!    квантовый противник обязан быть ДЕЙСТВУЮЩИМ абонентом, чтобы вообще увидеть `K`.
//!
//! Итог: PQ-стойкость Layer-2 ограничена длиной эпохи и требует активного действующего абонента с
//! CRQC. Это записано в модель угроз (SPEC §8, `docs/SECURITY-AUDIT-4-2026-08.md` M-6) как
//! осознанное ограничение с планом замены на решёточную слепую подпись, когда такая появится.
//!
//! ## Замечание о DLEQ-доказательстве
//!
//! Доказательство Шаума–Педерсена (`π`) убеждает клиента, что издатель применил ИМЕННО тот `k`,
//! которому соответствует объявленный `K`. Оно закрывает два сценария: (1) издатель возвращает
//! мусор, и клиент узнаёт об этом только при подключении (сожжённая квота, необъяснимый отказ);
//! (2) издатель ослепляет разными ключами, помечая абонентов. Полностью tagging оно не исключает
//! (издатель, он же оператор exit'а, мог бы выдать exit'у несколько ключей) — но exit принимает
//! ровно два ключа, current и prev, ровно как и раньше при epoch-scoped RSA.

use anyhow::{anyhow, bail, Result};
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{Identity, VartimeMultiscalarMul},
};
use zeroize::Zeroize;

/// Длина элемента группы на проводе (сжатый ristretto255).
pub const ELEMENT_LEN: usize = 32;
/// Длина DLEQ-доказательства (`c ‖ s`).
pub const PROOF_LEN: usize = 64;
/// Длина nonce токена (он же ключ множества `spent` на exit'е).
pub const NONCE_LEN: usize = 32;
/// Длина секрета токена `y` (не покидает устройство).
pub const SECRET_LEN: usize = 32;
/// Длина MAC предъявления.
pub const MAC_LEN: usize = 32;
/// Токен на проводе: `nonce ‖ MAC`.
pub const REDEEM_LEN: usize = NONCE_LEN + MAC_LEN;
/// Токен в хранилище клиента: `nonce ‖ y`.
pub const TOKEN_LEN: usize = NONCE_LEN + SECRET_LEN;

// Домены. Меняются вместе со сменой формата — разные домены исключают перенос значения из одного
// контекста в другой (например, MAC предъявления не может сойти за секрет токена).
const DST_H2G: &str = "CitadelPQVPN/token/v2/hash-to-group";
const DST_FINALIZE: &str = "CitadelPQVPN/token/v2/finalize";
const DST_DLEQ: &str = "CitadelPQVPN/token/v2/dleq";

/// 64 байта псевдослучайного вывода BLAKE3 в режиме derive_key — вход для отображения в группу и
/// для вывода скаляра (оба требуют равномерных 64 Б, чтобы смещение было пренебрежимо мало).
fn xof64(dst: &str, parts: &[&[u8]]) -> [u8; 64] {
    let mut h = blake3::Hasher::new_derive_key(dst);
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; 64];
    h.finalize_xof().fill(&mut out);
    out
}

/// Отображение `nonce → точка группы` (one-way map ristretto255 из равномерных 64 Б).
fn hash_to_group(nonce: &[u8; NONCE_LEN]) -> RistrettoPoint {
    RistrettoPoint::from_uniform_bytes(&xof64(DST_H2G, &[nonce]))
}

/// Скаляр из равномерных 64 Б (`mod l`, смещение ~2⁻¹²⁵ — пренебрежимо).
fn hash_to_scalar(dst: &str, parts: &[&[u8]]) -> Scalar {
    Scalar::from_bytes_mod_order_wide(&xof64(dst, parts))
}

/// Случайный скаляр из системного CSPRNG (тот же `aws-lc-rs`, что и вся крипта проекта).
fn random_scalar() -> Result<Scalar> {
    let mut b = [0u8; 64];
    aws_lc_rs::rand::fill(&mut b).map_err(|_| anyhow!("CSPRNG"))?;
    let s = Scalar::from_bytes_mod_order_wide(&b);
    b.zeroize();
    Ok(s)
}

/// Разобрать элемент группы с проверкой каноничности и отказом на нейтральном элементе.
/// Нейтральный элемент запрещён с обеих сторон: `B = 0` даёт `E = 0` независимо от `k`, то есть
/// вырожденную «выдачу», а `K = 0` означал бы `k = 0` и токен, который подделывает кто угодно.
fn parse_element(raw: &[u8], what: &str) -> Result<RistrettoPoint> {
    let arr: [u8; ELEMENT_LEN] =
        raw.try_into().map_err(|_| anyhow!("{what}: ожидалось {ELEMENT_LEN} Б, получено {}", raw.len()))?;
    let p = CompressedRistretto(arr).decompress().ok_or_else(|| anyhow!("{what}: не точка ristretto255"))?;
    if p == RistrettoPoint::identity() {
        bail!("{what}: нейтральный элемент запрещён");
    }
    Ok(p)
}

/// Проверить, что 32 байта — годный публичный элемент эпохи (для ранней диагностики на клиенте,
/// до того как он потратит квоту выдачи на заведомо провальный обмен).
pub fn parse_public_element(raw: &[u8]) -> Result<()> {
    parse_element(raw, "публичный элемент эпохи").map(|_| ())
}

/// Финализация OPRF: секрет токена `y = H(nonce ‖ N)`. Nonce входит явно, поэтому секрет нельзя
/// «пересадить» на другой токен, даже если противник как-то добудет `N`.
fn finalize(nonce: &[u8; NONCE_LEN], unblinded: &CompressedRistretto) -> [u8; SECRET_LEN] {
    let mut h = blake3::Hasher::new_derive_key(DST_FINALIZE);
    h.update(nonce);
    h.update(unblinded.as_bytes());
    *h.finalize().as_bytes()
}

// ============================= ключ эпохи (издатель + exit) =============================

/// Ключ эпохи Layer-2: скаляр `k` и его публичный элемент `K = k·G`.
///
/// **Секретен целиком.** В отличие от прежней схемы (RSA-pub на диске, выдача по запросу без
/// аутентификации) `k` нужен и издателю — чтобы вслепую вычислять, и exit'у — чтобы проверять
/// предъявление. Отсюда следствие для деплоя: **exit держит секрет эпохи**, то есть скомпрометиро-
/// ванный exit может чеканить токены СВОЕЙ эпохи. Это не ухудшает его собственную позицию (exit и
/// так терминирует весь трафик и раздаёт доступ), но для мультиэкзитных установок означает, что
/// ключ каждого exit'а должен быть свой — см. бэклог «per-exit derivation» в отчёте аудита.
pub struct EpochKey {
    k: Scalar,
    public: CompressedRistretto,
}

impl Drop for EpochKey {
    fn drop(&mut self) {
        self.k.zeroize();
    }
}

impl EpochKey {
    /// Сгенерировать ключ эпохи (микросекунды — ротация больше не стоит 10 секунд RSA-keygen).
    pub fn generate() -> Result<Self> {
        Self::from_scalar(random_scalar()?)
    }

    /// Восстановить ключ из 32 Б секрета (файл эпохи / keysync).
    pub fn from_secret(raw: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = raw
            .try_into()
            .map_err(|_| anyhow!("ключ эпохи: ожидалось 32 Б, получено {}", raw.len()))?;
        // Каноничность обязательна: неканоничная кодировка дала бы два представления одного ключа
        // и рассинхрон «издатель ↔ exit» на ровном месте.
        let k = Option::<Scalar>::from(Scalar::from_canonical_bytes(arr))
            .ok_or_else(|| anyhow!("ключ эпохи: неканоничный скаляр"))?;
        Self::from_scalar(k)
    }

    fn from_scalar(k: Scalar) -> Result<Self> {
        if k == Scalar::ZERO {
            bail!("ключ эпохи: нулевой скаляр");
        }
        let public = RistrettoPoint::mul_base(&k).compress();
        Ok(Self { k, public })
    }

    /// 32 Б секрета — то, что кладётся на диск (0600) и синхронизируется на exit.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.k.to_bytes()
    }

    /// 32 Б публичного элемента `K` — уходит абоненту для проверки DLEQ.
    pub fn public_bytes(&self) -> [u8; ELEMENT_LEN] {
        self.public.to_bytes()
    }

    /// Роль издателя: вычислить `E = k·B` вслепую и доказать, что применён именно `k` от `K`.
    /// Издатель не видит ни nonce, ни итогового токена.
    pub fn evaluate(&self, blinded: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let b = parse_element(blinded, "ослеплённый элемент")?;
        let e = self.k * b;
        let proof = self.prove(&b, &e)?;
        Ok((e.compress().to_bytes().to_vec(), proof))
    }

    /// DLEQ (Шаум–Педерсен): `log_G(K) == log_B(E)`, без раскрытия `k`.
    fn prove(&self, b: &RistrettoPoint, e: &RistrettoPoint) -> Result<Vec<u8>> {
        let mut r = random_scalar()?;
        let a1 = RistrettoPoint::mul_base(&r).compress();
        let a2 = (r * b).compress();
        let c = dleq_challenge(&self.public, &b.compress(), &e.compress(), &a1, &a2);
        let s = r - c * self.k;
        r.zeroize();
        let mut out = Vec::with_capacity(PROOF_LEN);
        out.extend_from_slice(c.as_bytes());
        out.extend_from_slice(s.as_bytes());
        Ok(out)
    }

    /// Роль exit'а: проверить предъявление `nonce ‖ MAC` в контексте `ctx` (см.
    /// [`crate::redeem_context`]). Возвращает nonce для учёта double-spend.
    ///
    /// Сравнение MAC — постоянного времени (`blake3::Hash: PartialEq` сравнивает CT), скалярное
    /// умножение в dalek тоже: `nonce` приходит от недоверенной стороны и не должен просвечивать
    /// ключ эпохи по таймингу.
    pub fn verify_redemption(&self, redeem: &[u8], ctx: &[u8]) -> Option<[u8; NONCE_LEN]> {
        if redeem.len() != REDEEM_LEN {
            return None;
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&redeem[..NONCE_LEN]);
        let n = (self.k * hash_to_group(&nonce)).compress();
        let mut secret = finalize(&nonce, &n);
        let expect = blake3::keyed_hash(&secret, ctx);
        secret.zeroize();
        let mut got = [0u8; MAC_LEN];
        got.copy_from_slice(&redeem[NONCE_LEN..]);
        (expect == blake3::Hash::from(got)).then_some(nonce)
    }
}

/// Транскрипт Фиата–Шамира для DLEQ. Все пять точек входят целиком: выбросить любую — значит
/// позволить переиспользовать доказательство в другом контексте.
fn dleq_challenge(
    k_pub: &CompressedRistretto,
    b: &CompressedRistretto,
    e: &CompressedRistretto,
    a1: &CompressedRistretto,
    a2: &CompressedRistretto,
) -> Scalar {
    hash_to_scalar(
        DST_DLEQ,
        &[
            curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED.as_bytes(),
            k_pub.as_bytes(),
            b.as_bytes(),
            e.as_bytes(),
            a1.as_bytes(),
            a2.as_bytes(),
        ],
    )
}

/// Проверка DLEQ на стороне клиента (значения публичные → vartime-арифметика допустима).
fn dleq_verify(
    k_pub: &RistrettoPoint,
    b: &RistrettoPoint,
    e: &RistrettoPoint,
    proof: &[u8],
) -> Result<()> {
    if proof.len() != PROOF_LEN {
        bail!("DLEQ: ожидалось {PROOF_LEN} Б доказательства, получено {}", proof.len());
    }
    let c_bytes: [u8; 32] = proof[..32].try_into().expect("32 Б");
    let s_bytes: [u8; 32] = proof[32..].try_into().expect("32 Б");
    let c = Option::<Scalar>::from(Scalar::from_canonical_bytes(c_bytes))
        .ok_or_else(|| anyhow!("DLEQ: неканоничный c"))?;
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes))
        .ok_or_else(|| anyhow!("DLEQ: неканоничный s"))?;
    // A1 = s·G + c·K, A2 = s·B + c·E
    let a1 = RistrettoPoint::vartime_double_scalar_mul_basepoint(&c, k_pub, &s).compress();
    let a2 = RistrettoPoint::vartime_multiscalar_mul([s, c], [*b, *e]).compress();
    if dleq_challenge(&k_pub.compress(), &b.compress(), &e.compress(), &a1, &a2) != c {
        bail!("DLEQ: издатель применил не тот ключ эпохи (доказательство не сошлось)");
    }
    Ok(())
}

// ============================= роль клиента =============================

/// Состояние между ослеплением и финализацией. Не покидает устройство.
pub struct BlindState {
    nonce: [u8; NONCE_LEN],
    blind: Scalar,
    blinded: CompressedRistretto,
}

impl Drop for BlindState {
    fn drop(&mut self) {
        self.nonce.zeroize();
        self.blind.zeroize();
    }
}

impl BlindState {
    /// Шаг 1: свежий nonce + ослеплённый элемент для издателя.
    pub fn new() -> Result<Self> {
        let mut nonce = [0u8; NONCE_LEN];
        aws_lc_rs::rand::fill(&mut nonce).map_err(|_| anyhow!("CSPRNG для nonce токена"))?;
        // Ослепление обязано быть обратимым: r ← Z_q \ {0}. Вероятность нуля ~2⁻²⁵², но
        // fail-closed дешевле рассуждений о вероятностях.
        let blind = random_scalar()?;
        if blind == Scalar::ZERO {
            bail!("вырожденный множитель ослепления");
        }
        let blinded = (blind * hash_to_group(&nonce)).compress();
        Ok(Self { nonce, blind, blinded })
    }

    /// То, что уходит издателю (и только это).
    pub fn blinded_element(&self) -> [u8; ELEMENT_LEN] {
        self.blinded.to_bytes()
    }

    /// Шаг 2: проверить DLEQ, снять ослепление, получить токен. Ошибка здесь означает
    /// недобросовестного издателя — токен НЕ создаётся (иначе отказ всплыл бы уже на exit'е).
    pub fn finalize(self, issuer_public: &[u8], evaluated: &[u8], proof: &[u8]) -> Result<Token> {
        let k_pub = parse_element(issuer_public, "публичный элемент эпохи")?;
        let b = parse_element(&self.blinded_element(), "ослеплённый элемент")?;
        let e = parse_element(evaluated, "ответ издателя")?;
        dleq_verify(&k_pub, &b, &e, proof)?;
        let unblinded = (self.blind.invert() * e).compress();
        Ok(Token { nonce: self.nonce, secret: finalize(&self.nonce, &unblinded) })
    }
}

/// Готовый токен: `nonce` (уйдёт exit'у открыто) + секрет `y` (не уходит НИКОГДА).
pub struct Token {
    nonce: [u8; NONCE_LEN],
    secret: [u8; SECRET_LEN],
}

impl Drop for Token {
    fn drop(&mut self) {
        self.nonce.zeroize();
        self.secret.zeroize();
    }
}

impl Token {
    /// Сериализация для хранения/передачи внутри клиента: `nonce ‖ y`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(TOKEN_LEN);
        v.extend_from_slice(&self.nonce);
        v.extend_from_slice(&self.secret);
        v
    }

    /// Разбор сохранённого токена.
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        if raw.len() != TOKEN_LEN {
            bail!("токен: ожидалось {TOKEN_LEN} Б, получено {}", raw.len());
        }
        let mut nonce = [0u8; NONCE_LEN];
        let mut secret = [0u8; SECRET_LEN];
        nonce.copy_from_slice(&raw[..NONCE_LEN]);
        secret.copy_from_slice(&raw[NONCE_LEN..]);
        Ok(Self { nonce, secret })
    }

    /// **Предъявление, привязанное к сессии** — то, ради чего менялась схема (остаток H-2).
    ///
    /// На провод уходит `nonce ‖ MAC_y(ctx)`, где `ctx` описывает КОНКРЕТНОЕ соединение
    /// (TLS-exporter + pin сервера, см. [`crate::redeem_context`]). Перехваченное предъявление
    /// бесполезно в другой сессии: у неё другой exporter, а пересчитать MAC без `y` нельзя.
    /// В прежней схеме это было недостижимо — там на проводе была сама подпись над nonce.
    pub fn redeem(&self, ctx: &[u8]) -> Vec<u8> {
        let mac = blake3::keyed_hash(&self.secret, ctx);
        let mut out = Vec::with_capacity(REDEEM_LEN);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(mac.as_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue(key: &EpochKey) -> Token {
        let st = BlindState::new().unwrap();
        let (e, proof) = key.evaluate(&st.blinded_element()).unwrap();
        st.finalize(&key.public_bytes(), &e, &proof).unwrap()
    }

    #[test]
    fn issuance_and_redemption_roundtrip() {
        let key = EpochKey::generate().unwrap();
        let token = issue(&key);
        let ctx = b"ctx-A".as_slice();
        let redeem = token.redeem(ctx);
        assert_eq!(redeem.len(), REDEEM_LEN);
        let nonce = key.verify_redemption(&redeem, ctx).expect("валидное предъявление");
        assert_eq!(&nonce[..], &redeem[..NONCE_LEN], "nonce для spent-множества");
    }

    /// Главное новое свойство (остаток H-2): предъявление действительно только в СВОЕЙ сессии.
    /// Перехватив его, релей не подключится своей — у неё другой exporter.
    #[test]
    fn redemption_is_bound_to_session_context() {
        let key = EpochKey::generate().unwrap();
        let token = issue(&key);
        let redeem = token.redeem(b"exporter-of-session-1");
        assert!(key.verify_redemption(&redeem, b"exporter-of-session-1").is_some());
        assert!(
            key.verify_redemption(&redeem, b"exporter-of-session-2").is_none(),
            "токен, снятый MITM'ом, не должен работать в его собственной сессии"
        );
    }

    /// Ключ чужой эпохи не принимает токен (epoch-scoping = отзыв по времени).
    #[test]
    fn foreign_epoch_key_rejects() {
        let (a, b) = (EpochKey::generate().unwrap(), EpochKey::generate().unwrap());
        let redeem = issue(&a).redeem(b"ctx");
        assert!(a.verify_redemption(&redeem, b"ctx").is_some());
        assert!(b.verify_redemption(&redeem, b"ctx").is_none());
    }

    /// Издатель, применивший другой ключ (tagging/ошибка ротации), ловится DLEQ'ом — токен не
    /// создаётся вовсе, а не отказывает потом на exit'е.
    #[test]
    fn dleq_catches_wrong_key() {
        let honest = EpochKey::generate().unwrap();
        let other = EpochKey::generate().unwrap();
        let st = BlindState::new().unwrap();
        let (e, proof) = other.evaluate(&st.blinded_element()).unwrap();
        // `Token` намеренно без Debug (в нём секрет) — поэтому разбираем Result вручную.
        let Err(err) = st.finalize(&honest.public_bytes(), &e, &proof) else {
            panic!("DLEQ обязан был отвергнуть чужой ключ");
        };
        assert!(format!("{err:#}").contains("DLEQ"), "err: {err:#}");
    }

    #[test]
    fn dleq_rejects_tampered_proof_and_element() {
        let key = EpochKey::generate().unwrap();
        let st = BlindState::new().unwrap();
        let (e, proof) = key.evaluate(&st.blinded_element()).unwrap();
        for i in [0usize, 31, 32, 63] {
            let mut bad = proof.clone();
            bad[i] ^= 1;
            let st2 = BlindState::new().unwrap();
            let (e2, _) = key.evaluate(&st2.blinded_element()).unwrap();
            assert!(st2.finalize(&key.public_bytes(), &e2, &bad).is_err(), "порча байта {i}");
        }
        let mut bad_e = e.clone();
        bad_e[0] ^= 1;
        let st3 = BlindState::new().unwrap();
        let (_, p3) = key.evaluate(&st3.blinded_element()).unwrap();
        assert!(st3.finalize(&key.public_bytes(), &bad_e, &p3).is_err());
    }

    /// Вырожденные входы: нейтральный элемент, мусор, неверная длина — отказ без паники.
    #[test]
    fn degenerate_inputs_rejected() {
        let key = EpochKey::generate().unwrap();
        assert!(key.evaluate(&[0u8; 32]).is_err(), "нейтральный элемент");
        assert!(key.evaluate(&[0xffu8; 32]).is_err(), "не точка ristretto");
        assert!(key.evaluate(&[1u8; 31]).is_err(), "короткий элемент");
        assert!(EpochKey::from_secret(&[0u8; 32]).is_err(), "нулевой скаляр");
        assert!(EpochKey::from_secret(&[0xffu8; 32]).is_err(), "неканоничный скаляр");
        assert!(EpochKey::from_secret(&[1u8; 31]).is_err(), "короткий ключ");
        assert!(Token::from_bytes(&[0u8; 10]).is_err());
    }

    /// Ключ эпохи переживает сериализацию (файл эпохи / keysync) без потери совместимости.
    #[test]
    fn epoch_key_survives_serialization() {
        let key = EpochKey::generate().unwrap();
        let restored = EpochKey::from_secret(&key.secret_bytes()).unwrap();
        assert_eq!(key.public_bytes(), restored.public_bytes());
        let redeem = issue(&key).redeem(b"ctx");
        assert!(restored.verify_redemption(&redeem, b"ctx").is_some(), "exit проверяет своим файлом");
    }

    /// Каждая выдача даёт свой nonce — иначе double-spend ловил бы честные токены.
    #[test]
    fn nonces_are_unique() {
        let key = EpochKey::generate().unwrap();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            assert!(seen.insert(issue(&key).redeem(b"ctx")[..NONCE_LEN].to_vec()));
        }
    }

    /// Верификатор не паникует ни на каком мусоре (анти-DoS на malformed вводе от клиента).
    #[test]
    fn fuzz_verify_no_panic() {
        let key = EpochKey::generate().unwrap();
        let valid = issue(&key).redeem(b"ctx");
        let mut s = 0x1234_5678_9abc_def0u64;
        let mut next = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..2_000 {
            let len = (next() % 200) as usize;
            let b: Vec<u8> = (0..len).map(|_| (next() >> 33) as u8).collect();
            assert!(key.verify_redemption(&b, b"ctx").is_none());
        }
        for _ in 0..2_000 {
            let mut m = valid.clone();
            let i = (next() as usize) % m.len();
            m[i] ^= (next() as u8) | 1;
            assert!(key.verify_redemption(&m, b"ctx").is_none(), "мутация всегда невалидна");
        }
    }
}
