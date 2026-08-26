//! CitadelPQVPN — общая конфигурация PQ-QUIC (используется бинарями M0 и M1).
//!
//! Гибридная KX-группа X25519MLKEM768 (aws-lc-rs), TLS 1.3 over QUIC,
//! self-signed Ed25519 (этап-1 аутентификация), включённые QUIC DATAGRAM.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{aws_lc_rs, CryptoProvider, SupportedKxGroup};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

mod obfs_socket;
mod obfs_tcp;
pub mod client;
pub mod clientfw;
pub mod config;
pub mod dataplane;
pub mod deadline;
pub mod diag;
pub mod pqauth;
pub mod protect;
pub mod ratelimit;
pub mod tcp_obfs;
pub mod vpn;
pub use obfs_socket::{
    client_endpoint_obfs, client_endpoint_plain, pacing_profile, server_endpoint_obfs,
    shaping_stats, Pacing, PskSource, ShapingStats,
};
pub use obfs_tcp::{client_endpoint_obfs_tcp, server_endpoint_obfs_tcp};
pub use protect::{clear_socket_protector, set_socket_protector, SocketProtector};

pub const ALPN: &[u8] = b"Citadel-pq";

/// Коды `CONNECTION_CLOSE`, которыми exit называет ПРИЧИНУ отказа в доступе.
///
/// **Зачем коды, если есть reason-фраза.** Её не видно: `quinn::ReadError::ConnectionLost`
/// печатается как «connection lost» и вложенную `ConnectionError` (а с ней и текст пира) в
/// `Display` не включает. То есть exit закрывал сессию с внятным `auth-failed`, а в лог клиента и
/// в UI попадало «сервер недоступен» — диагноз, отправляющий человека проверять порты и firewall
/// при исправной сети. Код читается структурно (`Connection::close_reason`), поэтому не теряется.
///
/// **Зачем клиенту различать.** От причины зависит судьба анонимного токена. Токен «не принят» и
/// токен «уже потрачен» — разные состояния: первый ОСТАЛСЯ неистраченным и обязан пойти в
/// следующую попытку, второй потрачен и повтор им дал бы double-spend. Клиент этого не знал и
/// считал потраченным ВСЁ, что дошло до предъявления, — поэтому систематический отказ exit'а
/// (типично: рассинхрон ключа эпохи при раздельном деплое) сжигал кошелёк по два токена на
/// попытку, упирался в квоту выдачи (A6) и запирал абонента до конца эпохи. Ровно этот сценарий
/// и наблюдался в поле.
///
/// Номера НОВЫЕ (старый exit на любой отказ слал `1`): клиент трактует всё незнакомое
/// консервативно — «токен потрачен», как и раньше. Совместимость в обе стороны сохраняется.
pub mod refusal {
    /// Токен не принят и **НЕ потрачен**: exit не смог его проверить (нет ключа текущей эпохи —
    /// упавший `citadel-keysync`, разъехавшиеся часы — либо токен чужой/битый). Клиент вправе
    /// сохранить токен для следующей попытки.
    pub const TOKEN_REJECTED: u32 = 0x10;
    /// Токен **уже потрачен** (double-spend): повтор им бессмыслен, нужен новый.
    pub const TOKEN_SPENT: u32 = 0x11;
    /// Токен принят и потрачен, но выдать адрес нечем: пул exit'а исчерпан.
    pub const NO_ADDRESS: u32 = 0x12;
    /// Токен потрачен, а запрос после него не разобран (несовместимый/битый клиент).
    pub const BAD_REQUEST: u32 = 0x13;

    /// Оставил ли отказ с кодом `code` токен неистраченным у клиента.
    ///
    /// Fail-closed: всё, кроме явного [`TOKEN_REJECTED`], считается потраченным — включая
    /// исторический `1` старого exit'а и обрыв без кода вовсе. Ошибиться в эту сторону стоит
    /// одного токена, в обратную — отказа «double-spend» на каждой следующей попытке.
    pub fn token_survived(code: u32) -> bool {
        code == TOKEN_REJECTED
    }
}

/// **No-logs (приватность exit'а).** Exit по умолчанию НЕ пишет в лог ничего о клиентах и их
/// трафике: ни IP пира, ни выданный туннельный адрес, ни назначения/размеры пакетов. Такой лог —
/// готовый форензик-журнал «кто, когда и куда ходил», т.е. ровно то, что вся схема (анонимные
/// токены, unlinkability) старается не создавать; docker-лог при этом ещё и переживает контейнер.
/// Оператор включает диагностику явно: `Citadel_DEBUG_LOG=1`. Клиентская сторона движка своими
/// логами распоряжается сама (это устройство пользователя, там лог нужен для поддержки).
pub fn debug_logs() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        let on =
            matches!(std::env::var("Citadel_DEBUG_LOG").as_deref(), Ok(v) if v != "0" && !v.is_empty());
        // L-10: см. `citadel_token::debug_logs` — режим, отменяющий no-logs, обязан объявлять себя
        // сам, а не жить незаметной строчкой в чужом env-файле, приехавшем из демо-стенда.
        if on && !matches!(std::env::var("Citadel_DEMO_STAND").as_deref(), Ok("1")) {
            eprintln!(
                "[!] Citadel_DEBUG_LOG=1: диагностический лог ВКЛЮЧЁН — в него попадают адреса \
                 клиентов и назначения их трафика. Для прода это не режим по умолчанию (no-logs)"
            );
        }
        on
    })
}

/// Максимальная длина строки, пришедшей от пира, в наших сообщениях.
const PEER_TEXT_MAX: usize = 200;

/// **Обеззараживание текста, пришедшего от сетевого пира** (аудит-5 / L-15).
///
/// Ошибки quinn печатают reason-фразу CONNECTION_CLOSE так, как её прислал пир
/// (`String::from_utf8_lossy`, см. `quinn_proto::frame::{ConnectionClose,ApplicationClose}`), а
/// reason-фразу можно прислать ЛЮБУЮ и **до аутентификации** — transport-уровень закрывает
/// соединение ещё во время хендшейка. Мы эти ошибки печатаем в лог и подставляем в текст отказа,
/// который видит пользователь (журнал TUI, `citadel-svc.log`, панель диагностики в приложении).
/// Без фильтра пир получает: ANSI/OSC-управление терминалом (подделка строк журнала, скрытие
/// текста, OSC-8 «ссылка», OSC-52 работа с буфером обмена в части терминалов), перевод строки для
/// вставки СВОИХ строк лога и «телефонного» текста вида «обновите приложение по ссылке …».
///
/// Политика: только печатаемые символы (C0/C1/DEL/ESC — вон), лимит длины, пустая строка
/// заменяется явным маркером, чтобы не получить «закрыто: » без причины.
pub fn peer_text(e: impl std::fmt::Display) -> String {
    let cleaned: String = e
        .to_string()
        .chars()
        .filter(|c| !c.is_control() && !('\u{80}'..='\u{9f}').contains(c))
        .collect();
    if cleaned.trim().is_empty() {
        return "<причина не указана>".into();
    }
    let mut out: String = cleaned.chars().take(PEER_TEXT_MAX).collect();
    // Многоточие ставим ТОЛЬКО при обрезке по длине: иначе «…» появлялось бы от одного лишь
    // отфильтрованного управляющего символа и врало бы про полноту сообщения.
    if cleaned.chars().count() > PEER_TEXT_MAX {
        out.push('…');
    }
    out
}

/// Приписка «соединение запретил ЛОКАЛЬНЫЙ фильтр» — когда ОС отдала «отказано в доступе» на
/// исходящий connect (Windows `WSAEACCES` 10013, Unix `EPERM`/`EACCES`, типичный источник —
/// антивирус, сторонний файрвол, корпоративная политика или чужое WFP-правило).
///
/// Диагностически это важно отделить от «сервер недоступен»: код 10013 на 443 при живом
/// соединении к тому же адресу по другому порту (издатель) выглядит как поломка сервера, и
/// человек уходит проверять firewall на VPS, где всё в порядке. Наш собственный kill-switch под
/// подозрение не попадает: он пропускает трафик к адресу exit'а целиком, любым портом.
pub fn local_block_hint(e: &std::io::Error) -> &'static str {
    let denied = matches!(e.kind(), std::io::ErrorKind::PermissionDenied)
        || matches!(e.raw_os_error(), Some(10013));
    if denied {
        " — исходящее соединение запретил ЛОКАЛЬНЫЙ фильтр на этом устройстве \
         (антивирус/файрвол/политика); сервер к этому отношения не имеет"
    } else {
        ""
    }
}

/// То же для ошибки в обёртке anyhow: ищем `io::Error` по всей цепочке причин.
pub fn local_block_hint_any(e: &anyhow::Error) -> &'static str {
    e.chain()
        .filter_map(|c| c.downcast_ref::<std::io::Error>())
        .map(local_block_hint)
        .find(|h| !h.is_empty())
        .unwrap_or("")
}

/// `eprintln!`, который на серверной стороне молчит без [`debug_logs`].
#[macro_export]
macro_rules! dlog {
    ($($t:tt)*) => {
        if $crate::debug_logs() {
            eprintln!($($t)*);
        }
    };
}

/// Максимальный inner-IP-пакет, который ГАРАНТИРОВАННО влезает в одну QUIC-датаграмму при
/// фиксированном MTU транспорта (`citadel_obfs::MAX_QUIC_PACKET`): пакет минус QUIC/AEAD-оверхед
/// минус 1 байт context-varint MASQUE. Клиент клампит свой TUN под фактический
/// `Session::quic_datagram_mtu()`, но exit конфигурирует общий TUN ДО появления соединений, поэтому
/// ему нужна константа. Держать TUN exit'а выше этого значения нельзя: пакеты из интернета размером
/// 1162..MTU молча дропались бы в `pump` («datagram too large») — TCP спасал бы MSS-clamp, а крупные
/// UDP (QUIC/HTTP3, игры, видео) просто пропадали бы. Синхронность с quinn проверяет тест
/// `inner_mtu_fits_real_datagram_budget` (живое соединение на loopback).
pub const INNER_MTU: u16 = 1161;

pub fn pq_groups() -> Vec<&'static dyn SupportedKxGroup> {
    vec![aws_lc_rs::kx_group::X25519MLKEM768]
}
pub fn classical_groups() -> Vec<&'static dyn SupportedKxGroup> {
    vec![aws_lc_rs::kx_group::X25519]
}

/// Crypto-agility (M6): именованный выбор KX-suite. TLS 1.3 negotiate'ит общую группу из списка,
/// поэтому смена suite на одной стороне совместима, если у другой есть пересечение (graceful
/// downgrade/upgrade без слома). Добавление нового suite — одна ветка здесь.
///   `pq` (default) — `X25519MLKEM768` (гибрид, анти-HNDL);
///   `classical`    — `X25519` (без PQ — для отладки/совместимости);
///   `all`          — оба по приоритету (negotiate; миграция парка без флэг-дня).
pub fn kx_groups_for(suite: &str) -> Vec<&'static dyn SupportedKxGroup> {
    match suite.trim() {
        "classical" | "x25519" => classical_groups(),
        "all" | "hybrid" => vec![aws_lc_rs::kx_group::X25519MLKEM768, aws_lc_rs::kx_group::X25519],
        _ => pq_groups(), // "pq" / пусто / неизвестное → безопасный default (PQ)
    }
}

/// Имя выбранного KX-suite (для логов).
pub fn kx_suite_name(suite: &str) -> &'static str {
    match suite.trim() {
        "classical" | "x25519" => "X25519 (classical)",
        "all" | "hybrid" => "X25519MLKEM768+X25519 (negotiate)",
        _ => "X25519MLKEM768 (PQ-гибрид)",
    }
}

/// S1.1/M4: гарантирует ли suite пост-квантовую сессию. Только `pq`/пусто: клиент предлагает
/// ТОЛЬКО гибридную группу → согласуется гибрид либо хендшейк падает (понизить нельзя).
/// `classical` — точно не PQ; `all` — PQ-предпочтительно, но при не-PQ сервере тихо
/// откатывается на X25519 → НЕ гарантия. Прод-клиент/сервер должны быть `pq` (анти-HNDL).
pub fn kx_is_pq(suite: &str) -> bool {
    matches!(suite.trim(), "" | "pq")
}

/// KX-suite из env `Citadel_KX` (`pq`|`classical`|`all`), по умолчанию `pq`.
pub fn kx_groups_from_env() -> Vec<&'static dyn SupportedKxGroup> {
    kx_groups_for(&std::env::var("Citadel_KX").unwrap_or_default())
}

pub fn provider(groups: Vec<&'static dyn SupportedKxGroup>) -> Arc<CryptoProvider> {
    let mut p = aws_lc_rs::default_provider();
    p.kx_groups = groups;
    Arc::new(p)
}

pub fn self_signed_ed25519() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let cert = rcgen::CertificateParams::new(vec!["Citadel.exit".to_string()])?.self_signed(&key)?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    Ok((cert_der, key_der))
}

/// **П5: `max_idle_timeout`, который объявляем мы сами.**
///
/// Было 15 с — «быстрее детектим мёртвое соединение при смене сети». Практика показала, что
/// мёртвый путь ловят не idle-таймер, а data-path watchdog (4 с затора, 16 с односторонней дыры)
/// и Android-watchdog смены сети (C6/S1) — и ловят раньше. Платой же за короткий idle был
/// маячок раз в 2–4 с: LTE-модем после каждой передачи держит RRC_CONNECTED ещё 5–10 с, поэтому
/// он не уходил в idle никогда, и это — главный расход батареи в простое (десятки процентов
/// заряда в сутки только за удержание канала).
///
/// 90 с позволяют маячку разредиться до 15–28 с. Ценой того, что мёртвая сессия в ПРОСТОЕ
/// замечается позже: на exit'е она до полутора минут держит адрес пула (пул раздаётся только под
/// токен эпохи, поэтому «набить» его без квоты нельзя), а на клиенте простой никто не наблюдает.
///
/// Значение обязано быть ≥ `RELAXED_MIN_IDLE` (60 с) на ОБЕИХ сторонах, иначе редкий маячок не
/// включится: эффективный idle-таймаут равен минимуму из объявленных (RFC 9000 §10.1). Оно же
/// уходит пиру подсказкой в капсуле адреса — держится тестом `idle_timeout_allows_relaxed_ka`.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(90);

// QUIC-транспорт с включёнными датаграммами + keepalive (для удержания туннеля).
fn transport() -> Arc<quinn::TransportConfig> {
    let mut tc = quinn::TransportConfig::default();
    tc.datagram_receive_buffer_size(Some(1 << 20));
    tc.datagram_send_buffer_size(1 << 20);
    // M-8/аудит-4: это СТРАХОВКА, а не основной keep-alive. Штатно туннель держит собственный
    // маячок со случайным интервалом (`dataplane::keepalive_delay`) — он всегда успевает раньше,
    // поэтому периодический PING quinn'а в поток не попадает и не даёт цензору строгую
    // периодичность для автокорреляции.
    //
    // П5: 60 с (было 5). Таймер quinn'а сбрасывается на КАЖДОМ принятом пакете, а наш маячок
    // всегда вызывает ответный ACK — значит, при живом маячке этот PING не срабатывает вообще,
    // и 5 секунд здесь означали бы ровно ту строгую периодичность, от которой мы уходили. При
    // этом 60 < 90 (idle): если задача маячка умрёт, соединение всё же попробуют оживить.
    tc.keep_alive_interval(Some(Duration::from_secs(60)));
    tc.max_idle_timeout(Some(IDLE_TIMEOUT.try_into().unwrap()));
    // Фиксируем MTU: запас под obfs-оверхед L1 (M3), без агрессивного discovery до 1500.
    // Значение синхронизировано с `citadel_obfs::MAX_QUIC_PACKET` (потолок провода L1) — см.
    // тест `obfs_wire_cap_matches_quic_mtu`: иначе паддинг L1 раздувает пакет выше того, что
    // QUIC считает своим MTU, и полноразмерные пакеты чёрнодырятся на «узких» путях (мобильные/NAT64).
    tc.initial_mtu(citadel_obfs::MAX_QUIC_PACKET as u16);
    tc.mtu_discovery_config(None);
    Arc::new(tc)
}

/// Pin сертификата = BLAKE3 от его DER (формат провижининга, см. THREAT-MODEL §3 F1).
pub fn cert_pin(cert: &CertificateDer<'_>) -> [u8; 32] {
    blake3::hash(cert.as_ref()).into()
}

pub fn server_config(groups: Vec<&'static dyn SupportedKxGroup>) -> Result<quinn::ServerConfig> {
    Ok(server_config_with_pin(groups)?.0)
}

/// Как [`server_config`], но дополнительно отдаёт pin серверного сертификата —
/// клиент пиннит его (канал провижининга), чтобы исключить MITM (S1/F1).
pub fn server_config_with_pin(
    groups: Vec<&'static dyn SupportedKxGroup>,
) -> Result<(quinn::ServerConfig, [u8; 32])> {
    let (cert, key) = self_signed_ed25519()?;
    server_config_with_cert(groups, cert, key)
}

/// A7: как [`server_config_with_pin`], но из ЗАДАННЫХ cert/key — для персистентной идентичности
/// exit (стабильный pin между рестартами; иначе розданные клиентам ссылки ломались бы на ребуте).
pub fn server_config_with_cert(
    groups: Vec<&'static dyn SupportedKxGroup>,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<(quinn::ServerConfig, [u8; 32])> {
    let pin = cert_pin(&cert);
    let mut crypto = rustls::ServerConfig::builder_with_provider(provider(groups))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let mut sc = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));
    sc.transport_config(transport());
    // M4: принимать миграцию соединения (смена пути client'а: WiFi↔LTE / NAT-rebind). QUIC опознаёт
    // соединение по Connection ID, валидирует новый путь (PATH_CHALLENGE) и продолжает без разрыва.
    sc.migration(true);
    Ok((sc, pin))
}

pub fn client_config(groups: Vec<&'static dyn SupportedKxGroup>) -> Result<quinn::ClientConfig> {
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider(groups))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert)) // PoC: фокус на KX, не PKI
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let mut cc = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
    cc.transport_config(transport());
    Ok(cc)
}

/// Прод-путь (F1): клиент пиннит серверный сертификат по `pin` И проверяет CertVerify-подпись.
pub fn client_config_pinned(
    groups: Vec<&'static dyn SupportedKxGroup>,
    pin: [u8; 32],
) -> Result<quinn::ClientConfig> {
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider(groups))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServerCert::new(pin)))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let mut cc = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
    cc.transport_config(transport());
    Ok(cc)
}

/// Верификатор с pinning: сверяет pin сертификата И проверяет подпись хендшейка
/// штатными алгоритмами провайдера (без этого pin публичного ключа не защищал бы от MITM).
pub struct PinnedServerCert {
    pin: [u8; 32],
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl PinnedServerCert {
    pub fn new(pin: [u8; 32]) -> Self {
        Self {
            pin,
            algs: aws_lc_rs::default_provider().signature_verification_algorithms,
        }
    }
}

impl std::fmt::Debug for PinnedServerCert {
    /// Без значения pin: `Debug` верификатора попадает в диагностику rustls/quinn, а pin — это
    /// идентификатор сертификата exit'а, которому не место в журнале на устройстве (см. лог
    /// «pinning …: серт-pin активен» в `client.rs`).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PinnedServerCert(pin скрыт)")
    }
}

impl ServerCertVerifier for PinnedServerCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if cert_pin(end_entity) == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("Citadel: server certificate pin mismatch".into()))
        }
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, dss, &self.algs)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, dss, &self.algs)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// PoC-only верификатор: принимает любой серверный сертификат (демо про KX, не про доверие цепочке).
#[derive(Debug)]
pub struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

#[cfg(test)]
mod tests {
    // P-1: тестовая петля 127.0.0.1 к собственному туннелю отношения не имеет — маршрутного
    // решения здесь нет, и фабрика `citadel_protect` не нужна (см. clippy.toml).
    #![allow(clippy::disallowed_methods)]
    use super::*;

    /// **Судьба токена решается кодом отказа, и трактовка fail-closed.**
    ///
    /// Токен возвращается в кошелёк ТОЛЬКО по явному `TOKEN_REJECTED` (exit сказал: не проверил,
    /// значит и не потратил). Всё остальное — включая исторический `1` старого exit'а, «пул
    /// адресов исчерпан» (там токен уже потрачен) и обрыв без кода — считается потраченным.
    /// Ошибка в эту сторону стоит одного токена; в обратную — «double-spend» на каждой попытке.
    #[test]
    fn refusal_codes_decide_token_fate_fail_closed() {
        assert!(refusal::token_survived(refusal::TOKEN_REJECTED));
        for spent in [refusal::TOKEN_SPENT, refusal::NO_ADDRESS, refusal::BAD_REQUEST, 1, 0] {
            assert!(!refusal::token_survived(spent), "код {spent} обязан считаться потраченным");
        }
        // Коды не должны совпадать между собой — иначе развилка «потрачен / нет» схлопнется.
        let all = [refusal::TOKEN_REJECTED, refusal::TOKEN_SPENT, refusal::NO_ADDRESS, refusal::BAD_REQUEST];
        let uniq: std::collections::HashSet<_> = all.iter().collect();
        assert_eq!(uniq.len(), all.len());
        // И ни один не должен занять исторический `1` (иначе старый exit «сказал бы» новое).
        assert!(!all.contains(&1), "код 1 занят прежним общим auth-failed");
    }

    /// Crypto-agility (M6): именованный выбор KX-suite и человекочитаемые имена.
    #[test]
    fn kx_suite_selection() {
        assert_eq!(kx_groups_for("pq").len(), 1);
        assert_eq!(kx_groups_for("classical").len(), 1);
        assert_eq!(kx_groups_for("all").len(), 2); // negotiate из двух групп
        assert_eq!(kx_groups_for("").len(), 1); // пусто → default pq
        assert_eq!(kx_groups_for("garbage").len(), 1); // неизвестное → default pq
        assert!(kx_suite_name("pq").contains("MLKEM"));
        assert!(kx_suite_name("classical").contains("X25519"));
        assert!(kx_suite_name("all").contains("negotiate"));
        // S1.1/M4: только pq/пусто гарантируют PQ; classical/all — нет.
        assert!(kx_is_pq("pq") && kx_is_pq(""));
        assert!(!kx_is_pq("classical") && !kx_is_pq("all"));
    }

    /// MTU-инвариант L0/L1: потолок obfs-провода = ровно тот пакет, который может отдать QUIC
    /// (`initial_mtu`), плюс фрейминг. Если разъедутся — паддинг L1 начнёт раздувать полноразмерные
    /// пакеты выше MTU пути, и на «узких» путях (мобильные сети/NAT64/CLAT) данные уйдут в чёрную
    /// дыру при живом хендшейке. Тест держит обе константы в синхроне.
    #[test]
    fn obfs_wire_cap_matches_quic_mtu() {
        assert_eq!(
            citadel_obfs::WIRE_CAP,
            citadel_obfs::MAX_QUIC_PACKET + citadel_obfs::FRAMING_OVERHEAD
        );
        // потолок провода + UDP(8) + IPv4(20) обязан влезать в 1300 б — запас под мобильные пути
        const { assert!(citadel_obfs::WIRE_CAP + 28 <= 1300, "obfs-пакет не влезает в узкий путь") };
        match citadel_obfs::DEFAULT_RANDOM_PAD {
            citadel_obfs::Padding::Random { cap, .. } => assert_eq!(cap, citadel_obfs::WIRE_CAP),
            _ => panic!("дефолтная политика паддинга должна быть Random"),
        }
    }

    /// `INNER_MTU` обязан помещаться в реальный бюджет QUIC-датаграммы (+1 байт context-varint).
    /// Живое соединение на loopback (поверх obfs-TCP — без биндинга UDP-портов в CI) даёт настоящий
    /// `max_datagram_size` от quinn: если апстрим сменит оверхед, тест поймает это здесь, а не
    /// «тихими дропами» полноразмерных пакетов на exit'е.
    #[tokio::test]
    async fn inner_mtu_fits_real_datagram_budget() {
        let psk = [0x33u8; 32];
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let scfg = server_config(kx_groups_for("pq")).unwrap();
            let ep = server_endpoint_obfs_tcp(stream, scfg, &[psk]).await.unwrap();
            let conn = ep.accept().await.unwrap().await.unwrap();
            let budget = conn.max_datagram_size().unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            budget
        });
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let ep = client_endpoint_obfs_tcp(stream, psk).unwrap();
        let ccfg = client_config(kx_groups_for("pq")).unwrap();
        let conn = ep.connect_with(ccfg, addr, "Citadel.exit").unwrap().await.unwrap();
        let client_budget = conn.max_datagram_size().unwrap();
        let server_budget = srv.await.unwrap();
        for b in [client_budget, server_budget] {
            assert!(
                b > INNER_MTU as usize,
                "бюджет датаграммы {b} < INNER_MTU {INNER_MTU} + 1 байт контекста"
            );
        }
    }

    /// L-15: текст, пришедший от пира (reason-фраза CONNECTION_CLOSE), не должен управлять
    /// терминалом и вставлять свои строки в наш журнал.
    #[test]
    fn peer_text_strips_control_and_bounds_length() {
        // ANSI/OSC-управление, перевод строки с поддельной строкой лога, DEL, C1
        let evil = "\u{1b}[2J\u{1b}]8;;http://evil\u{7}клик\u{1b}]8;;\u{7}\nЗащищено ✔\u{7f}\u{9b}";
        let got = peer_text(evil);
        assert!(!got.contains('\u{1b}'), "ESC остался: {got:?}");
        assert!(!got.contains('\n'), "перевод строки остался: {got:?}");
        assert!(!got.contains('\u{7}') && !got.contains('\u{7f}') && !got.contains('\u{9b}'));
        assert!(got.contains("Защищено"), "печатаемый текст сохраняется (диагностика нужна)");
        // длинную «простыню» режем и помечаем обрезку
        let long = peer_text("щ".repeat(10_000));
        assert!(long.chars().count() <= PEER_TEXT_MAX + 1, "лимит длины не сработал");
        assert!(long.ends_with('…'));
        // пустая причина (пир закрыл соединение без текста) — явный маркер, а не пустое место
        assert_eq!(peer_text(""), "<причина не указана>");
        // после снятия ESC остаётся печатаемый остаток — он и печатается (это уже не управление)
        assert_eq!(peer_text("\u{1b}[0m"), "[0m");
        // обычная ошибка проходит без изменений
        assert_eq!(peer_text("timed out"), "timed out");
    }

    /// A7: `server_config_with_cert` даёт pin = BLAKE3(cert DER) — стабильный для одной идентичности
    /// (персист серта между рестартами ⇒ pin в розданных ссылках не ломается).
    #[test]
    fn server_config_cert_pin_is_stable() {
        let (cert, key) = self_signed_ed25519().unwrap();
        let expected = cert_pin(&cert);
        let (_sc, pin) = server_config_with_cert(pq_groups(), cert, key).unwrap();
        assert_eq!(pin, expected, "pin детерминирован от серта (A7)");
    }
}
