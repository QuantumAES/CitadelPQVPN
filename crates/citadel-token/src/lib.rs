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

/// B-1: имя файла ключа эпохи **этого exit-узла** (`exit-<epoch>.key`, 0600).
///
/// Отдельное имя, а не то же `issuer-<epoch>.key`, потому что содержимое разное по смыслу: в
/// `issuer-*` лежит МАСТЕР эпохи (из него выводятся ключи всех узлов), в `exit-*` — ключ ровно
/// одного узла. Один и тот же путь для двух разных секретов рано или поздно означал бы, что мастер
/// уехал на exit-машину при раздельном деплое — то есть ровно та компрометация, которую B-1 и
/// закрывает.
pub fn exit_key_name(epoch: u64) -> String {
    format!("exit-{epoch}.key")
}

/// B-1: «выдача не привязана к узлу» — pin из одних нулей.
///
/// Нужен там, где абонент не знает pin exit'а заранее (TOFU-режим CLI, dev без пиннинга). Ключ под
/// ним выводится как обычно, но exit принимает такие токены ТОЛЬКО при `Citadel_TOKEN_UNBOUND=1`:
/// иначе непривязанная выдача тихо вернула бы общий ключ на весь деплой и обнулила бы B-1.
pub const EXIT_PIN_UNBOUND: [u8; 32] = [0u8; 32];

/// Метка кадра привязки выдачи к exit'у (см. [`build_exit_binding`]).
const EXIT_BIND_TAG: &[u8] = b"EXIT1";

/// B-1: кадр «токены нужны вот для этого узла»: `"EXIT1" ‖ pin(32)`.
///
/// Метка обязательна: без неё кадр неотличим от первого ослеплённого элемента (тоже 32 Б), и
/// клиент старой версии молча получал бы ключ, выведенный из его же `B` как из pin'а — с отказом
/// уже на exit'е и без единой внятной строки. Кадр идёт ВНУТРИ PQ-TLS после Layer-1, поэтому
/// отдельной подписи не требует: подделать его может только сам аутентифицированный абонент, а
/// назвать чужой exit ему не выгодно — он получит токены, годные не у себя.
pub fn build_exit_binding(exit_pin: &[u8; 32]) -> Vec<u8> {
    let mut f = Vec::with_capacity(EXIT_BIND_TAG.len() + 32);
    f.extend_from_slice(EXIT_BIND_TAG);
    f.extend_from_slice(exit_pin);
    f
}

/// Разобрать кадр привязки. Ошибка называет причину прямо: чаще всего это старый клиент.
pub fn parse_exit_binding(raw: &[u8]) -> Result<[u8; 32]> {
    if raw.len() != EXIT_BIND_TAG.len() + 32 || !raw.starts_with(EXIT_BIND_TAG) {
        bail!(
            "кадр привязки к exit'у не разобран ({} Б): клиент старой версии (до per-exit ключей \
             эпохи, B-1) — обновите приложение",
            raw.len()
        );
    }
    let mut pin = [0u8; 32];
    pin.copy_from_slice(&raw[EXIT_BIND_TAG.len()..]);
    Ok(pin)
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
    route: citadel_protect::Route,
) -> Result<(pqtls::ClientTlsStream, [u8; pqtls::EKM_LEN], Vec<u8>)> {
    let mut tcp = None;
    for _ in 0..retries.max(1) {
        // Анти-петля (Android) + таймаут: при `Route::Bypass` сокет помечается «мимо туннеля» ДО
        // connect. Клиент ходит к издателю в том числе при опущенном туннеле (перед establish) —
        // незащищённый сокет там либо заворачивается в собственный туннель, либо (при системном
        // always-on с блокировкой без VPN) вообще не выпускается ОС, и реконнект не может добыть
        // токен. На сервере/desktop протектор не установлен → обычный connect.
        // §7.1(в): фоновая дозаправка при ПОДНЯТОМ туннеле идёт `Route::Tunnel` — сознательно
        // внутрь туннеля, чтобы издателю был виден адрес exit'а, а не абонента.
        match citadel_protect::connect_tcp_str_route(issuer_addr, ISSUER_CONNECT_TIMEOUT, route) {
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
    // B-1: pin ЭТОГО exit'а — издатель выведет ключ именно для него (`k_exit`), мастер не покидает
    // машину издателя. Pin входит в подписываемое сообщение (см. `pqid::build_keysync_request`),
    // поэтому подменить его на чужой по дороге нельзя.
    exit_pin: &[u8; 32],
    retries: u32,
    obfs_psk: Option<[u8; 32]>,
) -> Result<Vec<u8>> {
    // Exit ходит к издателю со своей машины — туннеля у него нет, маршрут всегда прямой.
    let (mut conn, ekm, challenge) = connect_authenticated_issuer(
        issuer_addr,
        issuer_pin,
        issuer_mldsa,
        retries,
        obfs_psk,
        citadel_protect::Route::Bypass,
    )?;
    write_frame(
        &mut conn,
        &pqid::build_keysync_request(keysync_seed, &challenge, &ekm, exit_pin)?,
    )?;
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
#[allow(clippy::too_many_arguments)]
pub fn fetch_tokens(
    issuer_addr: &str,
    issuer_pin: &[u8; 32],
    issuer_mldsa: &[u8; 32],
    seed: &[u8; 32],
    // B-1: pin exit'а, на котором пачка будет предъявлена (из ссылки). [`EXIT_PIN_UNBOUND`] —
    // «узел заранее неизвестен»: такие токены exit примет только по явной настройке.
    exit_pin: &[u8; 32],
    count: usize,
    retries: u32,
    obfs_psk: Option<[u8; 32]>,
    route: citadel_protect::Route,
) -> Result<Grant> {
    let (mut conn, ekm, challenge) =
        connect_authenticated_issuer(issuer_addr, issuer_pin, issuer_mldsa, retries, obfs_psk, route)?;

    // Layer-1: гибридная подпись челленджа (Ed25519 + ML-DSA-65, привязка к сессии через EKM).
    let auth = pqid::build_auth(seed, pqid::DOMAIN_CLIENT, &challenge, &ekm)?;
    write_frame(&mut conn, &auth)?;

    // M-9: гейт выдачи — что издатель думает о нашей записи реестра. Кадр приходит ДО ключа эпохи,
    // поэтому отказ виден с внятной причиной, а не как «издатель молча закрыл соединение».
    match parse_gate_frame(
        &read_frame(&mut conn).context("Layer-1: издатель не ответил (не авторизован?)")?,
    )? {
        Gate::Allow => {}
        Gate::Enroll { until } => return Err(EnrollmentRequired { until }.into()),
        Gate::Refuse(code) => bail!("{}", refusal_text(code)),
    }

    // B-1: назвать узел, на котором пачка будет предъявлена, — ДО того, как издатель отдаст `K`:
    // публичный элемент относится уже к ключу этого узла (`k_exit`), и проверка DLEQ идёт под ним.
    write_frame(&mut conn, &build_exit_binding(exit_pin))?;

    // Публичный элемент K текущей эпохи — под ним проверяется DLEQ каждой выдачи.
    let issuer_public =
        read_frame(&mut conn).context("Layer-1: издатель не выдал ключ эпохи (не авторизован?)")?;
    // Разбираем сразу: негодный элемент — это сломанный/подставной издатель, и узнать об этом лучше
    // здесь, чем после цикла выдачи (иначе квота абонента тратится впустую, а причина всплывает
    // только на finalize).
    voprf::parse_public_element(&issuer_public).context("публичный элемент эпохи от издателя")?;

    // H-3: ключ L1-обфускации текущей эпохи (или явное «ротации нет») + §7.1: границы эпохи, по
    // которым клиент понимает, до какого момента годна взятая пачка.
    let epoch = parse_epoch_frame(
        &read_frame(&mut conn).context("издатель не прислал L1-кадр эпохи (старая версия?)")?,
    )?;

    let mut tokens = Vec::with_capacity(count);
    for i in 0..count {
        let st = BlindState::new()?;
        write_frame(&mut conn, &st.blinded_element())?;
        // Частичная пачка — норма, а не сбой (§7.1: клиент берёт токены пачкой). Издатель молча
        // закрывает выдачу, когда упёрлась квота эпохи (A6), и тогда `read_frame` возвращает Err.
        // Отдать то, что уже получено, лучше, чем потерять всю пачку: с пустыми руками клиент не
        // подключится вовсе, а с двумя токенами из восьми — подключится и переживёт реконнект.
        let resp = match read_frame(&mut conn) {
            Ok(r) => r,
            Err(e) if i > 0 => {
                dlog!("[token] пачка оборвалась на {i}-м токене ({e}) — берём что есть");
                break;
            }
            // Ни одного токена. Издатель по построению не говорит, почему (см. комментарий у
            // `Gate` — различимые причины были бы оракулом по политике узла), поэтому список
            // гипотез строим здесь, у себя: он один и тот же для всех абонентов и ничего не
            // раскрывает. Без этого текста человек видел «failed to fill whole buffer» и уходил
            // чинить сеть, хотя чаще всего это выбранная квота эпохи.
            Err(e) => {
                return Err(e).context(
                    "издатель прекратил выдачу, не выдав ни одного токена. Причину он не \
                     сообщает намеренно; на стороне абонента это обычно одно из: (а) выбрана \
                     квота выдачи на текущую эпоху — подождать следующую; (б) доступ отозван \
                     или срок подписки истёк; (в) активна аренда прошлой сессии",
                )
            }
        };
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
    Ok(Grant { tokens, data_psk: epoch.data_psk, epoch: epoch.epoch, epoch_secs: epoch.epoch_secs })
}

/// M-9: **активация первичной ссылки** — превращение её в устройство-специфичный доступ.
///
/// Абонент аутентифицируется ключом ИЗ ССЫЛКИ (`bootstrap_seed`), а предъявляет НОВУЮ идентичность
/// (`device_seed`), которую он только что создал у себя и никому не отдаёт. Издатель переносит
/// подписку на неё, а запись ссылки гасит: с этого момента та же ссылка на другом устройстве не
/// работает — в этом весь смысл (украденная/пересланная ссылка после активации ничего не стоит).
///
/// Операция **идемпотентна**: повтор с тем же `device_seed` — успех. Так и должно быть: клиент мог
/// сохранить свой ключ, отправить запрос и не получить ответ (обрыв, убитый процесс), и второй
/// заход обязан довести дело до конца, а не запереть человека снаружи навсегда.
///
/// `link_hash` — отпечаток ссылки ([`CredentialLink::link_hash`] на стороне клиента). Издатель
/// сверяет его с заверенным при выдаче: не совпало — ссылку подменили по дороге, активации нет.
///
/// Возвращает `Ok(true)` — активировано (или уже было), `Ok(false)` — издатель активации не
/// требует (запись обычная, многоразовая ссылка).
#[allow(clippy::too_many_arguments)]
pub fn enroll_device(
    issuer_addr: &str,
    issuer_pin: &[u8; 32],
    issuer_mldsa: &[u8; 32],
    bootstrap_seed: &[u8; 32],
    device_seed: &[u8; 32],
    link_hash: &[u8; 32],
    retries: u32,
    obfs_psk: Option<[u8; 32]>,
) -> Result<bool> {
    let (mut conn, ekm, challenge) = connect_authenticated_issuer(
        issuer_addr,
        issuer_pin,
        issuer_mldsa,
        retries,
        obfs_psk,
        citadel_protect::Route::Bypass, // активация идёт до первого туннеля — он ещё не поднят
    )?;
    let auth = pqid::build_auth(bootstrap_seed, pqid::DOMAIN_CLIENT, &challenge, &ekm)?;
    write_frame(&mut conn, &auth)?;
    match parse_gate_frame(&read_frame(&mut conn).context("издатель не ответил на Layer-1")?)? {
        // Издатель активации не ждёт: ссылка обычная (или уже активирована ЭТИМ устройством —
        // тогда мы и аутентифицировались как устройство). Молча соглашаемся.
        Gate::Allow => return Ok(false),
        Gate::Refuse(code) => bail!("{}", refusal_text(code)),
        Gate::Enroll { .. } => {}
    }
    let bootstrap_id = pqid::id_from_seed(bootstrap_seed)?;
    write_frame(&mut conn, &build_enroll_frame(device_seed, &bootstrap_id, link_hash, &ekm)?)?;
    match parse_gate_frame(&read_frame(&mut conn).context("издатель не ответил на активацию")?)? {
        Gate::Allow => Ok(true),
        Gate::Refuse(code) => bail!("{}", refusal_text(code)),
        Gate::Enroll { .. } => bail!("издатель снова просит активацию — несовместимая версия?"),
    }
}

/// Что абонент получает у издателя за один заход: токены Layer-2, ключ L1 текущей эпохи (H-3) и
/// границы самой эпохи (§7.1) — чтобы пачку можно было хранить ровно столько, сколько она годна.
#[derive(Debug, Clone)]
pub struct Grant {
    pub tokens: Vec<Vec<u8>>,
    /// `Some` — этим ключом заворачивать транспорт к exit'у (ротация H-3 включена);
    /// `None` — ротации нет, канал данных живёт на бутстрапном PSK из ссылки.
    pub data_psk: Option<[u8; 32]>,
    /// Номер эпохи, под ключом которой выданы токены (по часам ИЗДАТЕЛЯ).
    pub epoch: u64,
    /// Длина эпохи в секундах — из неё клиент считает `current_epoch` теми же часами, что издатель.
    pub epoch_secs: u64,
}

/// H-3 + §7.1: разбор кадра эпохи. Формат (v2, заход 7):
///
/// ```text
/// 0x02 ‖ epoch(u64 BE) ‖ epoch_secs(u64 BE) ‖ has_psk(0x00|0x01) [‖ psk(32)]
/// ```
///
/// **Почему в кадре появились номер и длина эпохи.** Без них клиент не знает, до какого момента
/// годна взятая пачка токенов, и обязан идти к издателю перед КАЖДЫМ establish — а это ровно тот
/// паттерн, который §7.1 называет худшим из возможных для корреляции «выдача ⇒ сессия». Величины
/// не секретны: длина эпохи одинакова для всех абонентов, номер выводится из времени.
///
/// Формат фиксирован, поэтому любое отклонение — несовместимый или подставной издатель: лучше
/// отказаться сразу, чем молча уйти на «ротации нет» и получить необъяснимо не поднимающийся
/// туннель. Кадры v1 (`0x00` / `0x01 ‖ psk`) сознательно НЕ принимаются: заходы 4–7 выходят одним
/// согласованным релизом, а тихая совместимость означала бы клиента, который считает эпоху сам и
/// расходится с издателем.
fn parse_epoch_frame(f: &[u8]) -> Result<EpochInfo> {
    let bad = |why: &str| anyhow!("L1-кадр эпохи от издателя: {why} ({} Б)", f.len());
    match f {
        [0x02, rest @ ..] if rest.len() == 17 || rest.len() == 49 => {
            let epoch = u64::from_be_bytes(rest[0..8].try_into().expect("длина проверена"));
            let epoch_secs = u64::from_be_bytes(rest[8..16].try_into().expect("длина проверена"));
            // Границы вменяемости: длина эпохи задаёт и срок годности пачки, и срок действия
            // ключа L1. Кривое значение (0, сутки, u64::MAX) превратило бы «кэш на эпоху» в
            // «кэш навсегда», поэтому оно отвергается на границе разбора, а не «клампится» —
            // расхождение с издателем всё равно сломало бы проверку токена на exit'е.
            if !(MIN_EPOCH_SECS..=MAX_EPOCH_SECS).contains(&epoch_secs) {
                return Err(bad(&format!(
                    "длина эпохи {epoch_secs}с вне допустимого {MIN_EPOCH_SECS}..{MAX_EPOCH_SECS}"
                )));
            }
            let data_psk = match &rest[16..] {
                [0x00] => None,
                [0x01, psk @ ..] if psk.len() == 32 => {
                    Some(psk.try_into().expect("длина проверена"))
                }
                _ => return Err(bad("непонятный признак ключа L1")),
            };
            Ok(EpochInfo { data_psk, epoch, epoch_secs })
        }
        [0x00] | [0x01, ..] => Err(bad("издатель старой версии (кадр v1 без границ эпохи)")),
        _ => Err(bad("непонятный формат — несовместимая версия?")),
    }
}

/// Разобранный кадр эпохи (см. [`parse_epoch_frame`]).
#[derive(Debug)]
struct EpochInfo {
    data_psk: Option<[u8; 32]>,
    epoch: u64,
    epoch_secs: u64,
}

// ─────────────────────── M-9: гейт выдачи (одноразовые ссылки, активация) ───────────────────────
// Сразу после Layer-1 издатель говорит абоненту, что с его записью реестра не так — ДО того, как
// начнётся выдача. Раньше в этом месте соединение просто закрывалось, и любой отказ выглядел
// одинаково («издатель не выдал ключ эпохи»), хотя причины разные и действия человека тоже:
// перевыпустить ссылку, взять новую, подождать. Кадр отправляется ПОСЛЕ проверки подписи, поэтому
// новым оракулом он не является: чтобы его увидеть, нужно владеть seed'ом абонента.

/// Причины отказа в выдаче (передаётся кодом, а не текстом: текст от сетевого пира в интерфейсе —
/// отдельный класс проблем, см. L-15).
pub const REFUSE_INACTIVE: u8 = 1;
/// Первичная ссылка уже активирована на другом устройстве (M-9, одноразовость).
pub const REFUSE_CONSUMED: u8 = 2;
/// Окно активации первичной ссылки истекло.
pub const REFUSE_EXPIRED: u8 = 3;
/// Отпечаток предъявленной ссылки не совпал с заверенным при выдаче — подмена при доставке.
pub const REFUSE_LINK_MISMATCH: u8 = 4;
/// Прочий отказ активации (несогласованное состояние записи).
pub const REFUSE_ENROLL: u8 = 5;

/// Человеческое объяснение кода отказа. Живёт на стороне КЛИЕНТА (по сети едет только код),
/// поэтому текст под нашим контролем и локализуется в UI по этому же смыслу.
pub fn refusal_text(code: u8) -> &'static str {
    match code {
        REFUSE_INACTIVE => "доступ не активен: ссылка отозвана или срок подписки истёк",
        REFUSE_CONSUMED => "эта ссылка уже активирована на другом устройстве — запросите новую",
        REFUSE_EXPIRED => "срок действия ссылки истёк (её нужно было активировать раньше)",
        REFUSE_LINK_MISMATCH => "ссылка не совпала с выданной — возможно, её подменили при доставке",
        _ => "издатель отклонил активацию",
    }
}

// **Почему у ОСТАНОВКИ ВЫДАЧИ нет кода причины — в отличие от гейта ниже.**
//
// Гейт отвечает на вопрос «что человеку делать со ссылкой» (активировать, взять новую, идти к
// админу): без ответа абонент беспомощен, поэтому код там есть — и уходит он только после
// проверенной гибридной подписи, то есть владельцу подписки. У остановки выдачи такой нужды нет:
// действие всегда одно — подождать. Зато различимые причины дали бы предъявителю ссылки (в том
// числе купленной, украденной или фаззеру с валидным seed'ом) оракул по политике узла: размер
// квоты, границы эпохи, факт отзыва, наличие аренды. Zero trust: издатель прекращает выдачу
// молча и одинаково во всех случаях, а гипотезы о причине строит КЛИЕНТ у себя, из того, что и
// так знает (см. `fetch_tokens`).

/// Что издатель сообщает абоненту сразу после Layer-1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// Обычный абонент — можно выдавать.
    Allow,
    /// M-9: первичная ссылка, требуется активация (до `until`; `0` — без срока).
    Enroll { until: u64 },
    /// Отказ с причиной (см. `REFUSE_*`).
    Refuse(u8),
}

/// Ошибка «нужна активация» — отдельным типом, чтобы вызывающий (владелец хранилища) распознал её
/// `downcast`'ом и запустил активацию, а не показал человеку сетевую ошибку.
#[derive(Debug, Clone, Copy)]
pub struct EnrollmentRequired {
    pub until: u64,
}

impl std::fmt::Display for EnrollmentRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ссылка первичная: требуется активация на этом устройстве")
    }
}
impl std::error::Error for EnrollmentRequired {}

/// Сборка кадра гейта (сторона издателя).
pub fn build_gate_frame(g: Gate) -> Vec<u8> {
    match g {
        Gate::Allow => vec![0x00],
        Gate::Enroll { until } => {
            let mut v = vec![0x01];
            v.extend_from_slice(&until.to_be_bytes());
            v
        }
        Gate::Refuse(code) => vec![0x02, code],
    }
}

/// Разбор кадра гейта (сторона абонента). Формат фиксирован — иначе отказ.
pub fn parse_gate_frame(f: &[u8]) -> Result<Gate> {
    match f {
        [0x00] => Ok(Gate::Allow),
        [0x01, rest @ ..] if rest.len() == 8 => Ok(Gate::Enroll {
            until: u64::from_be_bytes(rest.try_into().expect("длина проверена")),
        }),
        [0x02, code] => Ok(Gate::Refuse(*code)),
        _ => bail!("непонятный кадр гейта выдачи ({} Б) — несовместимая версия?", f.len()),
    }
}

/// M-9: кадр активации (абонент → издатель): отпечаток ссылки ‖ гибридная подпись УСТРОЙСТВА.
///
/// Подписывает новая (устройственная) идентичность в домене [`pqid::DOMAIN_ENROLL`], а в
/// подписываемое сообщение входят id первичной ссылки и отпечаток — поэтому кадр нельзя ни
/// переставить в чужую активацию, ни предъявить как Layer-1. Кто активируется, издатель знает из
/// уже аутентифицированной сессии; здесь доказывается владение НОВЫМ ключом.
pub fn build_enroll_frame(
    device_seed: &[u8; 32],
    bootstrap_id: &[u8; 32],
    link_hash: &[u8; 32],
    ekm: &[u8],
) -> Result<Vec<u8>> {
    let mut challenge = Vec::with_capacity(64);
    challenge.extend_from_slice(bootstrap_id);
    challenge.extend_from_slice(link_hash);
    let auth = pqid::build_auth(device_seed, pqid::DOMAIN_ENROLL, &challenge, ekm)?;
    let mut out = Vec::with_capacity(32 + auth.len());
    out.extend_from_slice(link_hash);
    out.extend_from_slice(&auth);
    Ok(out)
}

/// Разбор кадра активации (сторона издателя) → `(device_id, link_hash)`.
pub fn verify_enroll_frame(
    frame: &[u8],
    bootstrap_id: &[u8; 32],
    ekm: &[u8],
) -> Result<([u8; 32], [u8; 32])> {
    if frame.len() <= 32 {
        bail!("кадр активации короче ожидаемого ({} Б)", frame.len());
    }
    let (h, auth) = frame.split_at(32);
    let link_hash: [u8; 32] = h.try_into().expect("длина проверена");
    let mut challenge = Vec::with_capacity(64);
    challenge.extend_from_slice(bootstrap_id);
    challenge.extend_from_slice(&link_hash);
    let device_id = pqid::verify_auth(auth, pqid::DOMAIN_ENROLL, &challenge, ekm)
        .context("активация: подпись устройства")?;
    Ok((device_id, link_hash))
}

/// Нижняя и верхняя границы длины эпохи, которые клиент готов принять от издателя. Минимум —
/// чтобы e2e-стенды могли гонять ротацию за секунды; максимум — чтобы «эпоха» осталась сроком
/// годности, а не вечностью (отзыв абонента действует не дольше эпохи, H-3).
pub const MIN_EPOCH_SECS: u64 = 5;
pub const MAX_EPOCH_SECS: u64 = 86_400;

/// H-3: вывод ключа L1 эпохи из мастер-секрета. Реэкспорт из `citadel-obfs` — чтобы обе стороны
/// кадра эпохи (издатель, что его строит, и клиент, что его проверяет) брали функцию из одного
/// места, а не сходились на ней случайно.
pub use citadel_obfs::psk_epoch;

/// Сборка кадра эпохи (сторона издателя). Держится рядом с разбором намеренно: формат, у которого
/// две реализации в разных крейтах, расходится на первой же правке.
///
/// Кадр отправляется ВСЕГДА, даже когда ротация L1 не настроена (`master = None`): иначе клиент не
/// смог бы отличить «сервер старый» от «сервер новый, но ротации нет» — а различать их приходится
/// ровно тогда, когда что-то пошло не так, и гадать на длине ответа не хочется.
pub fn build_epoch_frame(master: Option<[u8; 32]>, epoch_secs: u64) -> Vec<u8> {
    let epoch = current_epoch(epoch_secs);
    let mut v = Vec::with_capacity(50);
    v.push(0x02);
    v.extend_from_slice(&epoch.to_be_bytes());
    v.extend_from_slice(&epoch_secs.to_be_bytes());
    match master {
        None => v.push(0x00),
        Some(m) => {
            v.push(0x01);
            v.extend_from_slice(&citadel_obfs::psk_epoch(&m, epoch));
        }
    }
    v
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
    use citadel_protect::Route;
    use super::*;

    /// Текущее unix-время для тестов (в самом крейте его нет: время нужно ролям, а не протоколу).
    fn test_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

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

    /// §7.1: кадр эпохи — разбор строгий. Он приносит клиенту срок годности пачки токенов,
    /// поэтому «почти правильный» кадр опаснее сломанного: пачка жила бы не столько, сколько надо.
    #[test]
    fn epoch_frame_roundtrip_and_strict_parse() {
        // Ротация выключена: границы эпохи есть, ключа L1 нет.
        let f = build_epoch_frame(None, 3600);
        let got = parse_epoch_frame(&f).unwrap();
        assert_eq!((got.epoch, got.epoch_secs), (current_epoch(3600), 3600));
        assert!(got.data_psk.is_none());

        // Ротация включена: ключ выводится из мастера тем же KDF, что у exit'а.
        let master = [0xA5u8; 32];
        let got = parse_epoch_frame(&build_epoch_frame(Some(master), 60)).unwrap();
        assert_eq!(got.epoch_secs, 60);
        assert_eq!(got.data_psk, Some(psk_epoch(&master, current_epoch(60))));

        // Кадры v1 (заход 6) больше не принимаются: клиент, считающий эпоху сам, обязан получить
        // её границы, а не догадываться.
        assert!(parse_epoch_frame(&[0x00]).unwrap_err().to_string().contains("старой версии"));
        assert!(parse_epoch_frame(&[&[0x01u8][..], &[7u8; 32][..]].concat()).is_err());
        // Мусор, обрезки и «почти v2».
        assert!(parse_epoch_frame(&[]).is_err());
        assert!(parse_epoch_frame(&[0x02]).is_err());
        assert!(parse_epoch_frame(&[0x02, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        // Длина эпохи вне допустимого — отказ, а не «клампим»: расхождение с издателем всё равно
        // сломало бы проверку токена на exit'е, а «эпоха на год» превратила бы кэш в вечный.
        let mut bad = build_epoch_frame(None, 3600);
        bad[9..17].copy_from_slice(&0u64.to_be_bytes());
        assert!(parse_epoch_frame(&bad).unwrap_err().to_string().contains("вне допустимого"));
        let mut bad = build_epoch_frame(None, 3600);
        bad[9..17].copy_from_slice(&(MAX_EPOCH_SECS + 1).to_be_bytes());
        assert!(parse_epoch_frame(&bad).is_err());
        // Признак ключа L1 испорчен → отказ (а не «молча без ротации»).
        let mut bad = build_epoch_frame(Some(master), 3600);
        bad[17] = 0x05;
        assert!(parse_epoch_frame(&bad).is_err());
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
        // B-1: издатель держит мастер эпохи, а вслепую считает ключом ЗАЯВЛЕННОГО узла.
        let master = EpochKey::generate().unwrap().secret_bytes();
        let exit_pin = [0x5cu8; 32];

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
            // M-9: гейт выдачи — «обычный абонент, активация не нужна».
            write_frame(&mut conn, &build_gate_frame(Gate::Allow)).unwrap();
            // B-1: абонент называет узел, под который берёт пачку → ключ выводится для него.
            let asked = parse_exit_binding(&read_frame(&mut conn).unwrap()).unwrap();
            assert_eq!(asked, exit_pin, "клиент назвал свой exit");
            let epoch_key = EpochKey::derive_for_exit(&master, current_epoch(3600), &asked).unwrap();
            write_frame(&mut conn, &epoch_key.public_bytes()).unwrap(); // публичный элемент эпохи
            // H-3 + §7.1: следом кадр эпохи; здесь ротация L1 выключена, но границы эпохи есть.
            write_frame(&mut conn, &build_epoch_frame(None, 3600)).unwrap();
            while let Ok(blinded) = read_frame(&mut conn) {
                let (e, proof) = epoch_key.evaluate(&blinded).unwrap();
                write_frame(&mut conn, &[e, proof].concat()).unwrap();
            }
            epoch_key
        });
        let grant = fetch_tokens(
            &addr,
            &issuer_pin,
            &issuer_mldsa,
            &seed,
            &exit_pin,
            3,
            3,
            None,
            Route::Bypass,
        )
        .unwrap();
        assert_eq!(grant.tokens.len(), 3);
        assert!(grant.data_psk.is_none(), "издатель сказал «ротации нет» — клиент это и увидел");
        assert_eq!(grant.epoch_secs, 3600, "длина эпохи приехала клиенту (§7.1: срок годности пачки)");
        assert_eq!(grant.epoch, current_epoch(3600), "номер эпохи — тот же, что считает издатель");
        let key = srv.join().unwrap();
        let ctx = redeem_context(b"e");
        for t in &grant.tokens {
            let redeem = Token::from_bytes(t).unwrap().redeem(&ctx);
            assert!(key.verify_redemption(&redeem, &ctx).is_some(), "токен валиден под ключом эпохи");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// M-9 сквозной путь по проводу: издатель говорит «нужна активация», клиент создаёт свой ключ
    /// и предъявляет его, издатель переносит подписку и гасит запись ссылки. Проверяется вся
    /// цепочка целиком — кадры, домены подписи, привязка к сессии и запись реестра.
    #[test]
    fn enroll_over_the_wire_moves_subscription_to_device() {
        use std::net::TcpListener;
        let boot_seed = [0x21u8; 32];
        let boot_id = pqid::id_from_seed(&boot_seed).unwrap();
        let dev_seed = [0x22u8; 32];
        let dev_id = pqid::id_from_seed(&dev_seed).unwrap();
        let link_hash = [0x33u8; 32];

        let dir = std::env::temp_dir().join(format!("citadel-enroll-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dirs = dir.to_str().unwrap().to_string();
        let identity = pqtls::IssuerIdentity::load_or_generate(&dirs).unwrap();
        let issuer_pin = identity.pin;
        let scfg = identity.server_config().unwrap();
        let pq = pqid::IssuerPqIdentity::load_or_generate(&dirs).unwrap();
        let issuer_mldsa = pq.commitment();
        // Реестр: одноразовая запись с окном активации и заверенным отпечатком.
        let registry = admin::registry_apply_add_full(
            "",
            &boot_id,
            test_now() + 3600,
            Some(test_now() + 600),
            Some(link_hash),
        );

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let srv = std::thread::spawn(move || -> String {
            let (tcp, _) = listener.accept().unwrap();
            let mut conn = pqtls::accept_tls(tcp, scfg, None).unwrap();
            let ekm = pqtls::handshake_server(&mut conn).unwrap();
            let challenge = [0x44u8; 32];
            write_frame(&mut conn, &pq.hello(&challenge, &issuer_pin, &ekm).unwrap()).unwrap();
            let auth = read_frame(&mut conn).unwrap();
            let who = pqid::verify_auth(&auth, pqid::DOMAIN_CLIENT, &challenge, &ekm).unwrap();
            assert_eq!(who, boot_id, "пришёл владелец ссылки");
            write_frame(&mut conn, &build_gate_frame(Gate::Enroll { until: test_now() + 600 }))
                .unwrap();
            let frame = read_frame(&mut conn).unwrap();
            let (device, got_hash) = verify_enroll_frame(&frame, &boot_id, &ekm).unwrap();
            let next =
                admin::registry_apply_enroll(&registry, &boot_id, &device, Some(got_hash), test_now())
                    .unwrap();
            write_frame(&mut conn, &build_gate_frame(Gate::Allow)).unwrap();
            next
        });

        let done = enroll_device(
            &addr,
            &issuer_pin,
            &issuer_mldsa,
            &boot_seed,
            &dev_seed,
            &link_hash,
            2,
            None,
        )
        .unwrap();
        assert!(done, "активация состоялась");

        let reg = srv.join().unwrap();
        let entries = admin::parse_registry(&reg);
        let b = entries.iter().find(|e| e.client_id == boot_id).unwrap();
        assert_eq!(b.status, admin::STATUS_CONSUMED, "ссылка отработала и больше не пускает");
        assert_eq!(b.device, Some(dev_id));
        let d = entries.iter().find(|e| e.client_id == dev_id).unwrap();
        assert_eq!(d.status, admin::STATUS_ACTIVE, "подписка на устройстве");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Кадр активации нельзя переиграть: подпись домена активации не проходит как Layer-1 (и
    /// наоборот), а привязка к сессии (EKM) не даёт перенести его в другое соединение.
    #[test]
    fn enroll_frame_is_domain_and_session_bound() {
        let dev = [0x51u8; 32];
        let boot = pqid::id_from_seed(&[0x52u8; 32]).unwrap();
        let hash = [0x53u8; 32];
        let ekm = [0x54u8; pqtls::EKM_LEN];
        let frame = build_enroll_frame(&dev, &boot, &hash, &ekm).unwrap();
        let (id, got) = verify_enroll_frame(&frame, &boot, &ekm).unwrap();
        assert_eq!((id, got), (pqid::id_from_seed(&dev).unwrap(), hash));

        // чужая сессия (другой EKM) — отказ
        assert!(verify_enroll_frame(&frame, &boot, &[0x99u8; pqtls::EKM_LEN]).is_err());
        // подставленная другая ссылка (bootstrap-id не тот) — отказ
        assert!(verify_enroll_frame(&frame, &[0u8; 32], &ekm).is_err());
        // подменённый отпечаток внутри кадра — подпись перестаёт сходиться
        let mut tampered = frame.clone();
        tampered[0] ^= 1;
        assert!(verify_enroll_frame(&tampered, &boot, &ekm).is_err());
        // кадр активации, предъявленный как Layer-1 (домен другой) — отказ
        assert!(pqid::verify_auth(&frame[32..], pqid::DOMAIN_CLIENT, &[boot, hash].concat(), &ekm)
            .is_err());
    }

    /// Гейт выдачи: сборка/разбор всех трёх исходов и отказ на мусоре.
    #[test]
    fn gate_frame_roundtrip() {
        assert_eq!(parse_gate_frame(&build_gate_frame(Gate::Allow)).unwrap(), Gate::Allow);
        let e = Gate::Enroll { until: 1_700_000_000 };
        assert_eq!(parse_gate_frame(&build_gate_frame(e)).unwrap(), e);
        let r = Gate::Refuse(REFUSE_CONSUMED);
        assert_eq!(parse_gate_frame(&build_gate_frame(r)).unwrap(), r);
        assert!(parse_gate_frame(&[]).is_err());
        assert!(parse_gate_frame(&[0x01, 0, 0]).is_err(), "обрезанный срок — отказ");
        assert!(parse_gate_frame(&[0x07]).is_err());
        // у каждого кода отказа есть человеческий текст (и он не пустой)
        for c in [REFUSE_INACTIVE, REFUSE_CONSUMED, REFUSE_EXPIRED, REFUSE_LINK_MISMATCH, REFUSE_ENROLL] {
            assert!(!refusal_text(c).is_empty());
        }
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
        // B-1: издатель держит МАСТЕР эпохи и отдаёт узлу выведенный из него `k_exit`.
        let master = EpochKey::generate().unwrap().secret_bytes();
        let exit_pin = [0x9au8; 32];
        let secret = EpochKey::derive_for_exit(&master, 7, &exit_pin).unwrap().secret_bytes();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let srv = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let mut conn = pqtls::accept_tls(tcp, scfg, None).unwrap();
            let ekm = pqtls::handshake_server(&mut conn).unwrap();
            let challenge = [0x31u8; 32];
            write_frame(&mut conn, &pq.hello(&challenge, &issuer_pin, &ekm).unwrap()).unwrap();
            let frame = read_frame(&mut conn).unwrap();
            let pqid::ClientFrame::KeySync { auth, exit_pin: asked } =
                pqid::parse_client_frame(&frame).unwrap()
            else {
                panic!("ожидался keysync-кадр");
            };
            assert_eq!(asked, exit_pin.to_vec(), "узел просит ключ ДЛЯ СЕБЯ (B-1)");
            let bound = pqid::keysync_bound_challenge(&challenge, &exit_pin);
            let got = pqid::verify_hybrid(auth, pqid::DOMAIN_KEYSYNC, &bound, &ekm).unwrap();
            assert_eq!(got, keysync_id, "издатель узнаёт СВОЙ exit-узел");
            write_frame(&mut conn, &secret).unwrap();
        });

        let got = fetch_epoch_key(
            &addr,
            &issuer_pin,
            &issuer_mldsa,
            &keysync_seed,
            &exit_pin,
            3,
            None,
        )
        .unwrap();
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
        let err = fetch_epoch_key(
            &addr,
            &issuer_pin,
            &foreign,
            &[0x5eu8; 32],
            &EXIT_PIN_UNBOUND,
            1,
            None,
        )
        .unwrap_err();
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
        let err = fetch_tokens(
            &addr,
            &issuer_pin,
            &foreign,
            &[0x44u8; 32],
            &EXIT_PIN_UNBOUND,
            1,
            1,
            None,
            Route::Bypass,
        )
        .unwrap_err();
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
