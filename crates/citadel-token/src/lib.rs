//! CitadelPQVPN — анонимные токены Layer-2, стиль Privacy Pass. Схема **v2: VOPRF (2HashDH) над
//! ristretto255** (M-6/аудит-4; прежняя — blind RSA-2048, RFC 9474 — снята вместе с крейтом `rsa`
//! и его незакрываемым RUSTSEC-2023-0071, см. M-10). Сама криптография — в [`voprf`], здесь —
//! протокол выдачи по сети и то, что от него нужно exit'у.
//!
//! Свойство **unlinkability** сохранено и остаётся информационно-теоретическим: издатель видит
//! только равномерно случайный ослеплённый элемент, поэтому даже он сам (он же провайдер exit'а,
//! он же противник с квантовым компьютером задним числом) не может связать выдачу с предъявлением.
//! Закрывает приватностный риск A4 (SPEC §8, F-M4).
//!
//! Что изменилось по существу:
//!
//!  * токен перестал быть bearer-строкой. У клиента остаётся секрет `y`, который **не уходит на
//!    провод**; при подключении предъявляется `nonce ‖ MAC_y(контекст сессии)` — украденное
//!    предъявление бесполезно в чужой сессии (остаток H-2, в blind RSA недостижимый);
//!  * материал эпохи стал **секретом** (`issuer-<epoch>.key`, 0600): проверка теперь приватная,
//!    и exit получает ключ либо с общего тома, либо аутентифицированным keysync'ом (P1);
//!  * ротация ключа эпохи перестала стоить ~10 секунд RSA-keygen.
//!
//! Роли по-прежнему разделены (M5, issuer↔exit split): клиент ослепляет и финализирует, издатель
//! вычисляет вслепую. По сети ходят только ослеплённый элемент и ответ с DLEQ-доказательством.

use anyhow::{anyhow, bail, Context, Result};
use std::io::{self, Read, Write};

pub use voprf::{BlindState, EpochKey, Token};

/// **No-logs (приватность серверных ролей).** Издатель и admin-канал по умолчанию НЕ пишут в лог
/// ничего, что связывает абонента, его адрес и время: ни `client_id`, ни IP пира, ни факт выдачи.
/// Иначе docker-лог/journald превращается в форензик-журнал «кто и когда подключался» — ровно то,
/// от чего защищает вся анонимная схема (blind RSA, unlinkability, C5.x). Диагностика включается
/// оператором явно и осознанно: `Citadel_DEBUG_LOG=1`.
pub fn debug_logs() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        let on =
            matches!(std::env::var("Citadel_DEBUG_LOG").as_deref(), Ok(v) if v != "0" && !v.is_empty());
        // L-10: включённый режим обязан быть ВИДЕН в логе с первой же строки. Иначе разница между
        // «no-logs» и «пишем IP, client_id и назначения» существует только в чужом env-файле —
        // а именно так демо-entrypoint и переезжает в прод копипастой.
        if on && !matches!(std::env::var("Citadel_DEMO_STAND").as_deref(), Ok("1")) {
            eprintln!(
                "[!] Citadel_DEBUG_LOG=1: диагностический лог ВКЛЮЧЁН — в него попадают адреса \
                 клиентов, client_id и назначения. Для прода это не режим по умолчанию (no-logs)"
            );
        }
        on
    })
}

/// `eprintln!`, который молчит без [`debug_logs`] — для строк с идентифицирующими данными.
#[macro_export]
macro_rules! dlog {
    ($($t:tt)*) => {
        if $crate::debug_logs() {
            eprintln!($($t)*);
        }
    };
}

pub mod admin; // C7.1: admin-плоскость (реестр по PQ-TLS: гибридная подпись + EKM channel binding)
pub mod voprf; // M-6: Layer-2 v2 — анонимные токены на VOPRF (2HashDH, ristretto255) вместо blind RSA
pub mod pqid; // PQ-удостоверение сторон: гибрид Ed25519 + ML-DSA-65 из одного seed (анти-CRQC auth)
pub mod pqtls; // S2.1/A1: PQ-TLS + pin канал к издателю (анти-MITM, анти-деанон client_id)
pub mod obfs_stream; // S2.1/A1 (остаток): синхронная obfs-обёртка issuer-канала (probe-resistance, анти-DPI)

pub const NONCE_LEN: usize = voprf::NONCE_LEN;

/// C5.1: номер текущей эпохи = unix-время / длина эпохи (сек). Токены Layer-2 скоупятся на эпоху —
/// exit проверяет их ТОЛЬКО ключом текущей (± прошлой, grace) эпохи, поэтому токен «гаснет» к концу
/// эпохи автоматически (отзыв по времени). Отзыв при компрометации — issuer перестаёт подписывать
/// такому клиенту, эффект ≤ длины эпохи. Требует слабой синхронизации часов issuer↔exit.
pub fn current_epoch(epoch_secs: u64) -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now / epoch_secs.max(1) // max(1): защита от деления на ноль при кривом конфиге
}

/// C5.1: имя файла ключа эпохи. Issuer публикует `issuer-<epoch>.key`; exit читает current(±prev).
/// Прежние ключи остаются на диске для grace, но exit их уже не запрашивает.
///
/// **Расширение сменилось с `.pub` на `.key` не косметически:** в схеме v2 это СЕКРЕТ (32 Б
/// скаляра), а не публичный ключ. Имя обязано это кричать — файл `issuer-*.pub` в мире, где его
/// содержимое стало приватным, рано или поздно кто-нибудь скопирует «как публичный».
pub fn epoch_key_name(epoch: u64) -> String {
    format!("issuer-{epoch}.key")
}

/// Домен контекста предъявления (входит в MAC — см. [`voprf::Token::redeem`]).
const REDEEM_DOMAIN: &[u8] = b"CitadelPQVPN/token/v2/redeem";

/// Контекст, к которому привязано предъявление токена: `домен ‖ TLS-exporter`.
///
/// Обе стороны считают его независимо и **никогда не передают по сети**. `exporter` (RFC 5705)
/// выводится из секретов ЭТОГО хендшейка с ЭТИМ сертификатом, поэтому он уникален для конкретной
/// сессии: у двух плеч релея он разный, и снятое предъявление в чужое соединение не переносится.
/// Это ровно та привязка, которую аудит-4 назвал недостижимой в blind RSA (§H-2, «❌ НЕ исправлено»).
///
/// **Почему в контексте нет `cert_pin`**, хотя ML-DSA-привязка рядом его включает. У сервера pin
/// есть всегда, а у клиента он появляется только при активном пиннинге: в беспиновом dev-режиме
/// (`Citadel_INSECURE_NO_PIN`, L-5) клиент подставляет нули — и контексты сторон разошлись бы,
/// давая «невалидный токен» на ровном месте. Пользы это не добавляет: привязка к узлу и так
/// обеспечена — pin проверяется на TLS-слое (fail-closed), а сам exporter зависит от сертификата
/// сервера. Лучше одна величина, которую обе стороны заведомо считают одинаково.
pub fn redeem_context(exporter: &[u8]) -> Vec<u8> {
    let mut ctx = Vec::with_capacity(REDEEM_DOMAIN.len() + exporter.len());
    ctx.extend_from_slice(REDEEM_DOMAIN);
    ctx.extend_from_slice(exporter);
    ctx
}

/// C5.1: проверить предъявление против нескольких ключей эпохи (current±prev — grace на границе
/// эпохи и при скью часов issuer↔exit). Возвращает nonce при успехе под ЛЮБЫМ ключом; иначе None.
pub fn verify_redemption_multi(
    keys: &[EpochKey],
    redeem: &[u8],
    ctx: &[u8],
) -> Option<[u8; NONCE_LEN]> {
    keys.iter().find_map(|k| k.verify_redemption(redeem, ctx))
}

// ===================== Layer-1 «абонемент» (C5.2): Ed25519 client-id =====================
// Клиент держит 32-байтный seed (= приватный Ed25519); его pub — client_id в реестре issuer'а.
// Issuer шлёт челлендж, клиент подписывает, issuer проверяет подпись + запись реестра
// (valid_until/status) ДО слепой подписи токенов. Отзыв: status=revoked (≤ длины эпохи) + expiry.

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _, UnparsedPublicKey, ED25519};

/// Ed25519 pub из 32-байтного client-seed (детерминированно; seed = приватный ключ «абонента»).
pub fn ed25519_pub_from_seed(seed: &[u8; 32]) -> Result<[u8; 32]> {
    let kp = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| anyhow!("ed25519 seed"))?;
    kp.public_key().as_ref().try_into().map_err(|_| anyhow!("ed25519 pub len"))
}

/// Подписать сообщение (челлендж issuer'а) client-seed'ом.
pub fn ed25519_sign(seed: &[u8; 32], msg: &[u8]) -> Result<[u8; 64]> {
    let kp = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| anyhow!("ed25519 seed"))?;
    kp.sign(msg).as_ref().try_into().map_err(|_| anyhow!("ed25519 sig len"))
}

/// Проверить подпись челленджа под pub'ом (issuer-сторона Layer-1).
pub fn ed25519_verify(pub_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    UnparsedPublicKey::new(&ED25519, pub_key).verify(msg, sig).is_ok()
}

// ===================== Сетевой протокол issuance (кадр `u32(len BE) ‖ payload`) =====================
/// Потолок размера кадра (анти-OOM при чтении len).
pub const MAX_FRAME: usize = 65536;

pub fn write_frame(w: &mut impl Write, data: &[u8]) -> io::Result<()> {
    w.write_all(&(data.len() as u32).to_be_bytes())?;
    w.write_all(data)?;
    w.flush()
}
pub fn read_frame(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut lb = [0u8; 4];
    r.read_exact(&mut lb)?;
    let len = u32::from_be_bytes(lb) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "плохая длина кадра"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Потолок ожидания TCP-connect к издателю. Без него недоступный издатель держал попытку минуты
/// (ретраи SYN в стеке), подвешивая весь цикл реконнекта клиента.
const ISSUER_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

/// Поднять канал к издателю и проверить ЕГО подлинность: TCP (с ретраями) → obfs → PQ-TLS с
/// пиннингом → `IssuerHello` с ML-DSA-подписью привязки. Возвращает поток, EKM сессии и челлендж.
///
/// Общая часть для всех потребителей канала (выдача токенов, синхронизация epoch-ключа), чтобы
/// проверка издателя не разъехалась между ними: пропустить её где-то одном — значит открыть там
/// PQ-MITM.
fn connect_authenticated_issuer(
    issuer_addr: &str,
    issuer_pin: &[u8; 32],
    issuer_mldsa: &[u8; 32],
    retries: u32,
    obfs_psk: Option<[u8; 32]>,
) -> Result<(pqtls::ClientTlsStream, [u8; pqtls::EKM_LEN], Vec<u8>)> {
    let mut tcp = None;
    for _ in 0..retries.max(1) {
        // Анти-петля (Android) + таймаут: сокет помечается «мимо туннеля» ДО connect. Клиент
        // ходит к издателю за свежим Layer-1 токеном на КАЖДЫЙ establish, в том числе при
        // реконнекте — незащищённый сокет здесь либо заворачивается в собственный туннель, либо
        // (при системном always-on с блокировкой без VPN) вообще не выпускается ОС, и реконнект
        // не может добыть токен. На сервере/desktop протектор не установлен → обычный connect.
        match citadel_protect::connect_tcp_str(issuer_addr, ISSUER_CONNECT_TIMEOUT) {
            Ok(c) => {
                tcp = Some(c);
                break;
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_secs(1)),
        }
    }
    let tcp = tcp.ok_or_else(|| anyhow!("издатель {issuer_addr} недоступен"))?;
    // S2.1/A1: поднять PQ-TLS поверх TCP; серт издателя пиннится → канал аутентифицирован и скрыт.
    // S2.1/A1-остаток: при заданном obfs_psk — под TLS obfs-слой (probe-resistance: issuer-порт
    // молчит на не-obfs пробу, трафик неотличим от туннеля). psk обязан совпасть с серверным.
    let mut conn = pqtls::connect_tls(tcp, *issuer_pin, obfs_psk)?;
    let ekm = pqtls::handshake_client(&mut conn)?;
    // Издатель доказывает подлинность PQ-подписью, привязанной к ЭТОЙ сессии (fail-closed:
    // не сошлось обязательство/подпись — рвём соединение, НЕ показав ничего своего).
    let hello = read_frame(&mut conn).context("издатель не прислал hello (порт/obfs/pin?)")?;
    let challenge = pqid::verify_hello(&hello, issuer_mldsa, issuer_pin, &ekm)
        .context("PQ-аутентификация издателя не прошла")?;
    Ok((conn, ekm, challenge))
}

/// Ключ ТЕКУЩЕЙ эпохи у издателя — для exit-узла, стоящего на ОТДЕЛЬНОЙ машине (`citadel-token
/// keysync`). Когда exit и издатель живут на одном сервере, exit читает `issuer-<epoch>.key` прямо
/// с общего тома.
///
/// **M-6: канал стал двусторонне аутентифицированным.** В схеме v1 отдавался публичный RSA-ключ, и
/// спросить его мог любой, кто знает obfs-PSK и pin (то есть любой абонент — PSK лежит в каждой
/// ссылке, H-3). В схеме v2 это секрет эпохи: получивший его чеканит токены. Поэтому exit
/// доказывает владение keysync-seed'ом (гибрид Ed25519 + ML-DSA-65, домен [`pqid::DOMAIN_KEYSYNC`],
/// привязка к сессии через EKM), а издатель сверяет его id с настроенным `Citadel_KEYSYNC_ID`.
/// Подлинность ИЗДАТЕЛЯ проверяется как и раньше — иначе exit принял бы ключ подставного и стал бы
/// верить чужим токенам.
pub fn fetch_epoch_key(
    issuer_addr: &str,
    issuer_pin: &[u8; 32],
    issuer_mldsa: &[u8; 32],
    keysync_seed: &[u8; 32],
    retries: u32,
    obfs_psk: Option<[u8; 32]>,
) -> Result<Vec<u8>> {
    let (mut conn, ekm, challenge) =
        connect_authenticated_issuer(issuer_addr, issuer_pin, issuer_mldsa, retries, obfs_psk)?;
    write_frame(&mut conn, &pqid::build_keysync_request(keysync_seed, &challenge, &ekm)?)?;
    let key = read_frame(&mut conn)
        .context("издатель не отдал ключ эпохи (keysync-идентичность не принята?)")?;
    // Разбираем сразу: мусор/чужой формат должен упасть здесь, а не при первой проверке токена.
    EpochKey::from_secret(&key).context("ключ эпохи от издателя")?;
    Ok(key)
}

/// C5.3: клиентская сторона issuance по сети (sync). Проходит Layer-1 (`seed` доказывает владение
/// «абонементом»), получает публичный элемент `K` ТЕКУЩЕЙ эпохи, добывает `count` токенов
/// (blind→evaluate→finalize). Издатель токены НЕ видит (unlinkable). `retries` — попытки коннекта.
/// Протокол: challenge → hello‖sig → K(32) → {blinded(32) → evaluated(32)‖DLEQ(64)}×N.
///
/// S2.1/A1: весь обмен идёт по **PQ-TLS с пиннингом** серта издателя (`issuer_pin`). Это закрывает
/// (a) MITM-кражу токенов (подстановку чужих `blind_msg`), (b) деанон `client_id` в открытом виде,
/// (c) импёрсонацию издателя. Несовпадение pin → отказ на TLS-хендшейке (fail-closed).
///
/// PQ-аутентификация (см. [`pqid`]): pin один защиты не даёт против квантового противника (ключ
/// Ed25519-серта восстанавливается из pub, лежащего в самом серте). Поэтому издатель ПЕРВЫМ кадром
/// доказывает подлинность ML-DSA-подписью, привязанной к этой TLS-сессии, а клиент сверяет её с
/// 32-байтным обязательством `issuer_mldsa` из ссылки — и только потом предъявляет свою
/// идентичность. Абонент, в свою очередь, подписывает челлендж ГИБРИДНО (Ed25519 + ML-DSA-65).
pub fn fetch_tokens(
    issuer_addr: &str,
    issuer_pin: &[u8; 32],
    issuer_mldsa: &[u8; 32],
    seed: &[u8; 32],
    count: usize,
    retries: u32,
    obfs_psk: Option<[u8; 32]>,
) -> Result<Vec<Vec<u8>>> {
    let (mut conn, ekm, challenge) =
        connect_authenticated_issuer(issuer_addr, issuer_pin, issuer_mldsa, retries, obfs_psk)?;

    // Layer-1: гибридная подпись челленджа (Ed25519 + ML-DSA-65, привязка к сессии через EKM).
    let auth = pqid::build_auth(seed, pqid::DOMAIN_CLIENT, &challenge, &ekm)?;
    write_frame(&mut conn, &auth)?;

    // Публичный элемент K текущей эпохи — под ним проверяется DLEQ каждой выдачи. Если Layer-1 не
    // прошёл, издатель закрыл соединение → read_frame вернёт Err (не «авторизован»).
    let issuer_public =
        read_frame(&mut conn).context("Layer-1: издатель не выдал ключ эпохи (не авторизован?)")?;
    // Разбираем сразу: негодный элемент — это сломанный/подставной издатель, и узнать об этом лучше
    // здесь, чем после цикла выдачи (иначе квота абонента тратится впустую, а причина всплывает
    // только на finalize).
    voprf::parse_public_element(&issuer_public).context("публичный элемент эпохи от издателя")?;

    let mut tokens = Vec::with_capacity(count);
    for _ in 0..count {
        let st = BlindState::new()?;
        write_frame(&mut conn, &st.blinded_element())?;
        let resp = read_frame(&mut conn)?;
        // Ответ издателя: `evaluated(32) ‖ DLEQ(64)`. Длина фиксирована — разбираем по границе,
        // а не «сколько дали»: иначе издатель управлял бы раскладкой полей.
        if resp.len() != voprf::ELEMENT_LEN + voprf::PROOF_LEN {
            bail!(
                "издатель прислал {} Б вместо {} (несовместимая версия?)",
                resp.len(),
                voprf::ELEMENT_LEN + voprf::PROOF_LEN
            );
        }
        let (evaluated, proof) = resp.split_at(voprf::ELEMENT_LEN);
        tokens.push(st.finalize(&issuer_public, evaluated, proof)?.to_bytes());
    }
    Ok(tokens)
}

// ===================== интерактивный issuance по ролям (M5, issuer↔exit split) =====================
// Разделение: КЛИЕНТ держит nonce и множитель ослепления и делает finalize; ИЗДАТЕЛЬ держит только
// ключ эпохи и вычисляет ВСЛЕПУЮ (не видит ни nonce, ни токен) → unlinkability, даже если издатель
// (биллинг) и exit сговорятся. По сети ходят только ослеплённый элемент и ответ с DLEQ.
// Сами примитивы — в [`voprf`]; здесь остались лишь удобные обёртки для тестов и локального демо.

/// Выпуск `count` токенов «в одном процессе» (все три роли сразу) — для тестов, бенчмарков и
/// офлайн-демо. В проде роли разнесены (`fetch_tokens` ↔ издатель).
pub fn issue_batch(count: usize) -> Result<Issued> {
    let key = EpochKey::generate()?;
    let public = key.public_bytes();
    let mut tokens = Vec::with_capacity(count);
    for _ in 0..count {
        let st = BlindState::new()?; // роль клиента: ослепление
        let (evaluated, proof) = key.evaluate(&st.blinded_element())?; // роль издателя (вслепую)
        tokens.push(st.finalize(&public, &evaluated, &proof)?.to_bytes()); // роль клиента: finalize
    }
    Ok(Issued { epoch_key: key.secret_bytes().to_vec(), tokens })
}

/// Результат [`issue_batch`]: секрет эпохи (им проверяет exit) и выпущенные токены.
pub struct Issued {
    pub epoch_key: Vec<u8>,
    pub tokens: Vec<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_layer1_roundtrip() {
        let seed = [0x11u8; 32];
        let pk = ed25519_pub_from_seed(&seed).unwrap();
        let msg = b"issuer-challenge-nonce";
        let sig = ed25519_sign(&seed, msg).unwrap();
        assert!(ed25519_verify(&pk, msg, &sig)); // валидная подпись
        assert!(!ed25519_verify(&pk, b"other", &sig)); // чужое сообщение
        assert!(!ed25519_verify(&ed25519_pub_from_seed(&[0x22u8; 32]).unwrap(), msg, &sig)); // чужой pub
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(!ed25519_verify(&pk, msg, &bad)); // подделанная подпись
        assert_eq!(pk, ed25519_pub_from_seed(&seed).unwrap()); // детерминизм seed→pub
    }

    #[test]
    fn epoch_basics() {
        assert!(current_epoch(3600) > 0); // после 1970 эпоха положительна
        assert_eq!(current_epoch(u64::MAX), 0); // эпоха длиннее возраста unix → 0
        let _ = current_epoch(0); // div-by-zero защита (max(1)) — не паникует
    }

    /// C5.1/M6: токен эпохи A НЕ принимается ключом эпохи B (epoch-scoping = отзыв по времени);
    /// проходит под своим ключом и в grace-наборе [prev, cur].
    #[test]
    fn epoch_scoping_cross_key_rejected() {
        let ctx = redeem_context(b"exporter");
        let a = issue_batch(1).unwrap();
        let b = issue_batch(1).unwrap();
        let (ka, kb) = (
            EpochKey::from_secret(&a.epoch_key).unwrap(),
            EpochKey::from_secret(&b.epoch_key).unwrap(),
        );
        let redeem = Token::from_bytes(&a.tokens[0]).unwrap().redeem(&ctx);
        assert!(kb.verify_redemption(&redeem, &ctx).is_none(), "ключ чужой эпохи не должен принять");
        assert!(ka.verify_redemption(&redeem, &ctx).is_some());
        assert!(verify_redemption_multi(std::slice::from_ref(&kb), &redeem, &ctx).is_none());
        assert!(verify_redemption_multi(&[kb, ka], &redeem, &ctx).is_some()); // grace prev+cur
        assert!(verify_redemption_multi(&[], &redeem, &ctx).is_none());
    }

    /// Остаток H-2 на уровне всей схемы: токен, добытый честно, действителен ТОЛЬКО в той сессии,
    /// контекст которой он подписал. Перехвативший предъявление релей не подключится своей.
    #[test]
    fn redemption_bound_to_session_exporter() {
        let issued = issue_batch(1).unwrap();
        let key = EpochKey::from_secret(&issued.epoch_key).unwrap();
        let token = Token::from_bytes(&issued.tokens[0]).unwrap();
        let redeem = token.redeem(&redeem_context(b"exporter-session-1"));
        assert!(key.verify_redemption(&redeem, &redeem_context(b"exporter-session-1")).is_some());
        assert!(
            key.verify_redemption(&redeem, &redeem_context(b"exporter-session-2")).is_none(),
            "другая сессия — другой exporter, предъявление не переносится"
        );
        // домен контекста входит в MAC: голый exporter не сходится с контекстом
        assert!(key.verify_redemption(&redeem, b"exporter-session-1").is_none());
    }

    /// C5.3 + S2.1/A1 + PQ: полный клиентский протокол `fetch_tokens` против in-process issuer
    /// поверх PQ-TLS. Проверяет, что (а) издатель доказывает подлинность ML-DSA-подписью привязки,
    /// (б) абонент авторизуется ГИБРИДНОЙ подписью и опознаётся по `BLAKE3(ed_pub‖mldsa_pub)`,
    /// (в) добытые токены проходят проверку ключом эпохи.
    #[test]
    fn fetch_tokens_layer1_roundtrip() {
        use std::net::TcpListener;
        let seed = [0x33u8; 32];
        let client_id = pqid::id_from_seed(&seed).unwrap();
        let epoch_key = EpochKey::generate().unwrap();
        let epoch_public = epoch_key.public_bytes();

        // S2.1/A1: издатель поднимает постоянный TLS-серт; клиент пиннит его pin.
        let dir = std::env::temp_dir().join(format!("citadel-fetch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dir = dir.to_str().unwrap();
        let identity = pqtls::IssuerIdentity::load_or_generate(dir).unwrap();
        let issuer_pin = identity.pin;
        let scfg = identity.server_config().unwrap();
        // PQ-идентичность издателя: обязательство уходит «в ссылку» (здесь — прямо клиенту).
        let pq = pqid::IssuerPqIdentity::load_or_generate(dir).unwrap();
        let issuer_mldsa = pq.commitment();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let srv = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let mut conn = pqtls::accept_tls(tcp, scfg, None).unwrap();
            let ekm = pqtls::handshake_server(&mut conn).unwrap();
            let challenge = [0x77u8; 32];
            write_frame(&mut conn, &pq.hello(&challenge, &issuer_pin, &ekm).unwrap()).unwrap();
            let auth = read_frame(&mut conn).unwrap();
            let got = pqid::verify_auth(&auth, pqid::DOMAIN_CLIENT, &challenge, &ekm).unwrap();
            assert_eq!(got, client_id, "зарегистрированный абонент");
            write_frame(&mut conn, &epoch_public).unwrap(); // публичный элемент текущей эпохи
            while let Ok(blinded) = read_frame(&mut conn) {
                let (e, proof) = epoch_key.evaluate(&blinded).unwrap();
                write_frame(&mut conn, &[e, proof].concat()).unwrap();
            }
            epoch_key
        });
        let tokens = fetch_tokens(&addr, &issuer_pin, &issuer_mldsa, &seed, 3, 3, None).unwrap();
        assert_eq!(tokens.len(), 3);
        let key = srv.join().unwrap();
        let ctx = redeem_context(b"e");
        for t in &tokens {
            let redeem = Token::from_bytes(t).unwrap().redeem(&ctx);
            assert!(key.verify_redemption(&redeem, &ctx).is_some(), "токен валиден под ключом эпохи");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// P1 (раздельный деплой): exit-узел на ДРУГОЙ машине забирает ключ эпохи, доказав СВОЮ
    /// keysync-идентичность (M-6: ключ стал секретом, безымянный запрос больше не проходит).
    #[test]
    fn fetch_epoch_key_serves_authenticated_exit() {
        use std::net::TcpListener;
        let dir = std::env::temp_dir().join(format!("citadel-keysync-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dir = dir.to_str().unwrap();
        let identity = pqtls::IssuerIdentity::load_or_generate(dir).unwrap();
        let issuer_pin = identity.pin;
        let scfg = identity.server_config().unwrap();
        let pq = pqid::IssuerPqIdentity::load_or_generate(dir).unwrap();
        let issuer_mldsa = pq.commitment();
        let keysync_seed = [0x5eu8; 32];
        let keysync_id = pqid::id_from_seed(&keysync_seed).unwrap();
        let epoch_key = EpochKey::generate().unwrap();
        let secret = epoch_key.secret_bytes();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let srv = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let mut conn = pqtls::accept_tls(tcp, scfg, None).unwrap();
            let ekm = pqtls::handshake_server(&mut conn).unwrap();
            let challenge = [0x31u8; 32];
            write_frame(&mut conn, &pq.hello(&challenge, &issuer_pin, &ekm).unwrap()).unwrap();
            let frame = read_frame(&mut conn).unwrap();
            let pqid::ClientFrame::KeySync(auth) = pqid::parse_client_frame(&frame).unwrap() else {
                panic!("ожидался keysync-кадр");
            };
            let got =
                pqid::verify_hybrid(auth, pqid::DOMAIN_KEYSYNC, &challenge, &ekm).unwrap();
            assert_eq!(got, keysync_id, "издатель узнаёт СВОЙ exit-узел");
            write_frame(&mut conn, &secret).unwrap();
        });

        let got =
            fetch_epoch_key(&addr, &issuer_pin, &issuer_mldsa, &keysync_seed, 3, None).unwrap();
        srv.join().unwrap();
        // и этим ключом exit действительно проверяет токены эпохи
        let restored = EpochKey::from_secret(&got).unwrap();
        let st = BlindState::new().unwrap();
        let (e, proof) = restored.evaluate(&st.blinded_element()).unwrap();
        let token = st.finalize(&restored.public_bytes(), &e, &proof).unwrap();
        let ctx = redeem_context(b"exp");
        assert!(restored.verify_redemption(&token.redeem(&ctx), &ctx).is_some());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Подставной издатель не снабдит exit ключом: обязательство из конфига не сойдётся, и
    /// синхронизация упадёт ДО того, как ключ попадёт на диск (иначе exit верил бы чужим токенам).
    /// Дополнительно проверяем, что keysync-кадр самозванцу НЕ уходит (в нём — id exit-узла).
    #[test]
    fn fetch_epoch_key_rejects_foreign_issuer_identity() {
        use std::net::TcpListener;
        use std::sync::{atomic::{AtomicBool, Ordering}, Arc};
        let dir = std::env::temp_dir().join(format!("citadel-keysync-mitm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dir = dir.to_str().unwrap();
        let identity = pqtls::IssuerIdentity::load_or_generate(dir).unwrap();
        let issuer_pin = identity.pin;
        let scfg = identity.server_config().unwrap();
        let pq = pqid::IssuerPqIdentity::load_or_generate(dir).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let saw_frame = Arc::new(AtomicBool::new(false));
        let flag = saw_frame.clone();
        let srv = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let Ok(mut conn) = pqtls::accept_tls(tcp, scfg, None) else { return };
            let Ok(ekm) = pqtls::handshake_server(&mut conn) else { return };
            let _ = write_frame(&mut conn, &pq.hello(&[0x41u8; 32], &issuer_pin, &ekm).unwrap());
            if read_frame(&mut conn).is_ok() {
                flag.store(true, Ordering::SeqCst);
            }
        });
        let foreign = pqid::issuer_commitment(&pqid::mldsa_pub_from_seed(&[0x99u8; 32]).unwrap());
        let err = fetch_epoch_key(&addr, &issuer_pin, &foreign, &[0x5eu8; 32], 1, None).unwrap_err();
        assert!(format!("{err:#}").contains("PQ-аутентификация издателя"), "err: {err:#}");
        srv.join().unwrap();
        assert!(!saw_frame.load(Ordering::SeqCst), "keysync-идентичность не должна уйти самозванцу");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Издатель-самозванец: TLS-серт свой (клиент пиннит ЕГО — то есть pin сходится, ровно как
    /// при квантовой подделке классической подписи), но PQ-обязательство из ссылки не то. Клиент
    /// обязан оборвать сессию ДО отправки `client_id` — иначе PQ-MITM собирал бы идентификаторы
    /// абонентов (деанон подписки).
    #[test]
    fn fetch_tokens_rejects_foreign_issuer_identity() {
        use std::net::TcpListener;
        let dir = std::env::temp_dir().join(format!("citadel-fetch-mitm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dir = dir.to_str().unwrap();
        let identity = pqtls::IssuerIdentity::load_or_generate(dir).unwrap();
        let issuer_pin = identity.pin;
        let scfg = identity.server_config().unwrap();
        let pq = pqid::IssuerPqIdentity::load_or_generate(dir).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let got_client_frame = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = got_client_frame.clone();
        let srv = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let Ok(mut conn) = pqtls::accept_tls(tcp, scfg, None) else { return };
            let Ok(ekm) = pqtls::handshake_server(&mut conn) else { return };
            let challenge = [0x11u8; 32];
            let _ = write_frame(&mut conn, &pq.hello(&challenge, &issuer_pin, &ekm).unwrap());
            if read_frame(&mut conn).is_ok() {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        });

        // «Другой» издатель в ссылке (обязательство не совпадает с предъявленным ML-DSA pub)
        let foreign = pqid::issuer_commitment(&pqid::mldsa_pub_from_seed(&[0xABu8; 32]).unwrap());
        let err = fetch_tokens(&addr, &issuer_pin, &foreign, &[0x44u8; 32], 1, 1, None).unwrap_err();
        assert!(format!("{err:#}").contains("PQ-аутентификация издателя"), "err: {err:#}");
        srv.join().unwrap();
        assert!(
            !got_client_frame.load(std::sync::atomic::Ordering::SeqCst),
            "client_id не должен был уйти самозванцу"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn issue_and_verify() {
        let issued = issue_batch(3).unwrap();
        let key = EpochKey::from_secret(&issued.epoch_key).unwrap();
        assert_eq!(issued.tokens.len(), 3);
        let ctx = redeem_context(b"exp");
        // все валидны, nonce различны
        let mut seen = std::collections::HashSet::new();
        for t in &issued.tokens {
            let redeem = Token::from_bytes(t).unwrap().redeem(&ctx);
            let nonce = key.verify_redemption(&redeem, &ctx).expect("валидный токен");
            assert!(seen.insert(nonce), "nonce должны быть уникальны");
        }
    }

    #[test]
    fn tampered_and_forged_tokens_rejected() {
        let issued = issue_batch(1).unwrap();
        let key = EpochKey::from_secret(&issued.epoch_key).unwrap();
        let ctx = redeem_context(b"exp");
        let mut redeem = Token::from_bytes(&issued.tokens[0]).unwrap().redeem(&ctx);
        let last = redeem.len() - 1;
        redeem[last] ^= 0x01; // портим MAC
        assert!(key.verify_redemption(&redeem, &ctx).is_none());
        // выдуманный «токен» без выдачи
        let forged = vec![0x42u8; voprf::REDEEM_LEN];
        assert!(key.verify_redemption(&forged, &ctx).is_none());
    }

    /// M5 split: клиент (blind→finalize) ↔ издатель (только evaluate) → валидный токен.
    /// Издатель видит лишь ослеплённый элемент; по сети ходят только он и ответ с DLEQ.
    #[test]
    fn split_issuance_roundtrip() {
        let key = EpochKey::generate().unwrap();
        let st = BlindState::new().unwrap(); // клиент
        let (evaluated, proof) = key.evaluate(&st.blinded_element()).unwrap(); // издатель (вслепую)
        let token = st.finalize(&key.public_bytes(), &evaluated, &proof).unwrap(); // клиент
        let ctx = redeem_context(b"exp");
        let nonce = key.verify_redemption(&token.redeem(&ctx), &ctx).expect("split-токен валиден");

        // токен другой эпохи не проходит под этим ключом
        let key2 = EpochKey::generate().unwrap();
        let st2 = BlindState::new().unwrap();
        let (e2, p2) = key2.evaluate(&st2.blinded_element()).unwrap();
        let tok2 = st2.finalize(&key2.public_bytes(), &e2, &p2).unwrap();
        let redeem2 = tok2.redeem(&ctx);
        assert_ne!(nonce, key2.verify_redemption(&redeem2, &ctx).unwrap(), "nonce различны");
        assert!(key.verify_redemption(&redeem2, &ctx).is_none(), "токен чужого издателя отвергнут");
    }
}
