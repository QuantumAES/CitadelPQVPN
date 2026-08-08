//! `ClientConfig` — конфигурация клиента движка, развязанная от окружения.
//!
//! Бинарь `citadel-m1` строит её `ClientConfig::from_env()` (контракт `Citadel_*`);
//! GUI-клиент (трек C0.4+) построит из распарсенного бандла/QR/ссылки. Движок
//! (connect/handshake/data-plane) читает ТОЛЬКО эту структуру и НЕ трогает env —
//! это предпосылка к встраиванию в мобильный/десктоп-клиент (docs/CLIENT-ARCH.md §4.2).

use anyhow::{Context, Result};

/// Режим pinning сертификата сервера (F1) для конкретного host.
pub enum PinMode {
    Pinned([u8; 32]),
    Waiting, // pinning настроен, но pin ещё не доступен (ждём, пока exit его запишет)
    NoPin,   // pinning не настроен (PoC-режим)
}

/// Откуда брать pin сервера, резолвится per-host в [`ClientConfig::pin_for`].
#[derive(Clone)]
pub enum PinSource {
    Bytes([u8; 32]), // прямые байты pin (из бандла кред / QR — мобильный путь, C1.4)
    Shared(String), // общий hex-pin на все exit (Citadel_PIN)
    Dir(String),    // <dir>/<host>.pin — per-exit, multi-server (Citadel_PIN_DIR)
    File(String),   // один файл (Citadel_PIN_FILE, legacy single-server)
    None,           // PoC: pinning не настроен
}

/// Откуда брать ML-DSA-65 pub сервера (M7), резолвится per-host в [`ClientConfig::mldsa_for`].
#[derive(Clone)]
pub enum MldsaSource {
    Bytes(Vec<u8>), // прямые байты ML-DSA pub (из бандла кред / QR, C1.4)
    File(String), // Citadel_MLDSA_PUB
    Dir(String),  // <dir>/<host>.mldsa (Citadel_PIN_DIR)
    Commit([u8; 32]), // только обязательство H(pub) (из `citadel://`-ссылки / Citadel_MLDSA_COMMIT):
    // полный pub дотягивается по control-каналу и сверяется с этим commit — commitment-fetch (§S3).
    None,
}

/// Что клиент ожидает по ML-DSA-65 pub сервера (M7), резолвится per-host в [`ClientConfig::mldsa_expect`].
#[derive(Clone)]
pub enum MldsaExpect {
    /// PQ-auth не запрашивается (pub/commit не провижированы).
    None,
    /// Полный pub провижирован (байты/файл/dir) — им и верифицируем подпись.
    Pub(Vec<u8>),
    /// Только обязательство `H(pub)` — полный pub берём из ответа сервера, сверяем `sha256(pub)==commit`
    /// и лишь затем верифицируем подпись (commitment-fetch, §S3).
    Commit([u8; 32]),
}

/// C8.3 split-tunneling: как применяется список (приложений или назначений).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SplitMode {
    /// Правило выключено — весь трафик по обычным маршрутам.
    #[default]
    Off,
    /// Только перечисленные — через туннель (остальное в обход).
    Include,
    /// Перечисленные — в обход туннеля (остальное через туннель).
    Exclude,
}

impl SplitMode {
    pub fn as_str(self) -> &'static str {
        match self {
            SplitMode::Off => "off",
            SplitMode::Include => "include",
            SplitMode::Exclude => "exclude",
        }
    }
    pub fn parse(s: &str) -> SplitMode {
        match s.trim() {
            "include" => SplitMode::Include,
            "exclude" => SplitMode::Exclude,
            _ => SplitMode::Off,
        }
    }
}

/// C8.3 split-tunneling (Android): две независимые оси — по приложениям (package-имена) и по
/// назначениям (домен/IP/CIDR, в т.ч. локальная подсеть). Клиентская настройка (не из ссылки).
#[derive(Clone, Debug, Default)]
pub struct SplitTunnel {
    /// Режим фильтра приложений.
    pub app_mode: SplitMode,
    /// Package-имена приложений (Android).
    pub apps: Vec<String>,
    /// Режим фильтра назначений.
    pub dest_mode: SplitMode,
    /// Записи назначений как их ввёл пользователь: `domain` | `IP` | `IP/prefix` (CIDR).
    /// Домены резолвятся в CIDR перед конфигурацией туннеля (см. `vpn::resolve_dests`).
    pub dests: Vec<String>,
}

impl SplitTunnel {
    /// Есть ли что применять (иначе TUN строится как обычно).
    pub fn is_active(&self) -> bool {
        (self.app_mode != SplitMode::Off && !self.apps.is_empty())
            || (self.dest_mode != SplitMode::Off && !self.dests.is_empty())
    }
}

/// Конфигурация клиента: всё, что нужно движку для подключения к exit'ам.
#[derive(Clone)]
pub struct ClientConfig {
    /// Список exit-серверов `host:port` (уже перемешан для балансировки, M5).
    pub servers: Vec<String>,
    /// SNI / server_name для TLS.
    pub server_name: String,
    /// L1-obfs PSK (`None` → без обфускации, PoC).
    pub obfs_psk: Option<[u8; 32]>,
    /// KX-suite (crypto-agility, M6): сырое значение `Citadel_KX` ("", "pq", "classical", "all").
    pub kx_suite: String,
    /// Порт obfs-over-TCP fallback (M4).
    pub tcp_port: String,
    /// Маршруты в туннель (через пробел); пусто → таблицу не трогаем.
    pub routes: String,
    /// DNS-резолвер для F6 (`None` → не настраиваем).
    pub dns: Option<String>,
    /// MTU туннеля.
    pub mtu: String,
    /// Анонимный токен для предъявления exit (M4/M5); пусто → exit может отказать.
    pub token: Vec<u8>,
    /// Источник pin'ов сервера (F1).
    pub pin: PinSource,
    /// Источник ML-DSA pub (M7).
    pub mldsa: MldsaSource,
    /// S0.1/H2: разрешить QUIC БЕЗ серт-pin (AcceptAnyServerCert = MITM-открыто). Только
    /// dev/PoC (env `Citadel_INSECURE_NO_PIN=1`); прод — `false` (fail-closed).
    pub allow_insecure_no_pin: bool,
    /// M-2/аудит-4: разрешить НЕ пост-квантовый KX-suite (`classical`/`all`). Дефолт `false` —
    /// такая сессия не защищена от Harvest-Now-Decrypt-Later, а `kx_suite` приходит из ССЫЛКИ,
    /// то есть подменённая ссылка иначе молча понижала бы криптографию до X25519. Включается
    /// только явным dev-флагом `Citadel_INSECURE_CLASSICAL_KX=1` (харнес crypto-agility);
    /// из ссылки/бандла — никогда.
    pub allow_classical_kx: bool,
    /// M-1/аудит-4: требовать PQ-аутентификацию сервера (ML-DSA pub либо commit). Дефолт `false`
    /// (провижининг решает сам); `Citadel_REQUIRE_PQ_AUTH=1` делает отсутствие материала отказом.
    pub require_pq_auth: bool,
    /// C6/M9 kill-switch: блокировать не-туннельный трафик, пока туннель активен (fail-closed при
    /// краше движка). Клиентская настройка (не из ссылки); env `Citadel_KILLSWITCH=1` / GUI-тумблер.
    pub killswitch: bool,
    /// C8.3 split-tunneling (Android): фильтр по приложениям и/или назначениям. Клиентская настройка
    /// (не из ссылки); дефолт `Off`. Desktop-провайдер поле игнорирует (Linux split — позже).
    pub split: SplitTunnel,
}

impl Drop for ClientConfig {
    /// S1.3/M7: затираем секреты конфига при дропе (obfs PSK, токен). Copy-поля pin/mldsa —
    /// публичные обязательства, не секрет. NB: PSK копируется и в obfs-слой (Sealer/Opener) —
    /// его затирание там — отдельный слой (частичное покрытие).
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(psk) = self.obfs_psk.as_mut() {
            psk.zeroize();
        }
        self.token.zeroize();
    }
}

/// Pin из hex (ровно 32 байта).
pub fn parse_pin(s: &str) -> Option<[u8; 32]> {
    hex::decode(s.trim()).ok().and_then(|v| v.try_into().ok())
}

/// obfs PSK из строки: **только** 64 hex = 32 байта. Иначе `None` (fail-closed).
///
/// M-7 (аудит-4). Раньше любая другая строка превращалась в PSK через
/// `blake3::derive_key(…, v)` — один проход, без соли и без work-factor. Оператор, задавший
/// `--obfs-psk` парольной фразой, получал секрет, который офлайн-перебор вскрывает на скорости
/// миллиардов кандидатов в секунду; а этот PSK — общий на весь деплой (H-3) и лежит в каждой
/// ссылке, то есть цена его компрометации максимальна: он же probe-resistance, он же гейт
/// pre-auth поверхности exit'а и издателя.
///
/// Штатный путь (установщик и docker-стенд генерируют 32 байта из `/dev/urandom`) не затронут:
/// там ровно 64 hex. Ручной ввод фразы теперь отвергается — вызывающая сторона обязана сказать
/// об этом внятно, а не молча работать на слабом секрете.
pub fn parse_obfs_psk(v: &str) -> Option<[u8; 32]> {
    let v = v.trim();
    if v.len() != 64 {
        return None;
    }
    hex::decode(v).ok()?.try_into().ok()
}

/// PSK из `Citadel_OBFS_PSK` с **fail-closed** разбором (M-7).
///
/// Отсутствует или пуст — obfs выключен, это штатная конфигурация. А вот заданное, но негодное
/// значение — ошибка запуска: после ужесточения [`parse_obfs_psk`] «тихий None» означал бы
/// молча выключенный L1-слой при внешне настроенном PSK (и рассинхрон с другой стороной, которая
/// свой PSK разобрала). Ровно тот класс дефекта, что M-1 и `Citadel_ISSUER_PUB`.
pub fn env_obfs_psk() -> Result<Option<[u8; 32]>> {
    let Ok(raw) = std::env::var("Citadel_OBFS_PSK") else { return Ok(None) };
    if raw.trim().is_empty() {
        return Ok(None);
    }
    parse_obfs_psk(&raw).map(Some).ok_or_else(|| {
        anyhow::anyhow!(
            "Citadel_OBFS_PSK: ожидаются ровно 64 hex-символа (32 байта). Парольные фразы больше \
             не принимаются: они выводились в ключ одним проходом BLAKE3, без соли и work-factor, \
             и вскрывались офлайн-перебором (M-7). Сгенерируйте: head -c 32 /dev/urandom | xxd -p -c 32"
        )
    })
}

/// S1.2/M1: `dns` обязан быть одним IP (иначе — инъекция в `/etc/resolv.conf` через root-helper).
pub fn is_ip(s: &str) -> bool {
    s.trim().parse::<std::net::IpAddr>().is_ok()
}

/// S1.2/M1: токен маршрута — валидный CIDR `IP/prefix` или голый IP (=host-route).
pub fn is_cidr(s: &str) -> bool {
    let s = s.trim();
    match s.split_once('/') {
        Some((a, p)) => {
            let Ok(ip) = a.parse::<std::net::IpAddr>() else { return false };
            p.parse::<u8>().map(|n| n <= if ip.is_ipv4() { 32 } else { 128 }).unwrap_or(false)
        }
        None => is_ip(s),
    }
}

/// S1.2/M1: проверить net-поля (dns/routes) перед тем, как они уйдут в привилегированный контекст
/// (resolv.conf, `ip route`). Вызывается при импорте бандла/ссылки/env — отсекает инъекции.
pub fn validate_net_fields(dns: Option<&str>, routes: &str) -> Result<()> {
    if let Some(d) = dns {
        if !d.trim().is_empty() && !is_ip(d) {
            anyhow::bail!("dns не является IP-адресом: {d:?} (защита от инъекции в resolv.conf)");
        }
    }
    for r in routes.split_whitespace() {
        if !is_cidr(r) {
            anyhow::bail!("маршрут не является валидным CIDR: {r:?}");
        }
    }
    Ok(())
}

impl ClientConfig {
    /// Построить из окружения `Citadel_*` (контракт бинаря/Docker).
    pub fn from_env() -> Result<Self> {
        let mut servers: Vec<String> = match std::env::var("Citadel_SERVERS") {
            Ok(s) => s
                .split([' ', ';', ','])
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(String::from)
                .collect(),
            Err(_) => vec![std::env::var("Citadel_CONNECT")
                .context("ни Citadel_SERVERS, ни Citadel_CONNECT не заданы")?],
        };
        use rand::seq::SliceRandom;
        servers.shuffle(&mut rand::thread_rng());

        // pin: Citadel_PIN (общий) > Citadel_PIN_DIR (per-host) > Citadel_PIN_FILE (legacy).
        let pin = if let Ok(h) = std::env::var("Citadel_PIN") {
            PinSource::Shared(h)
        } else if let Ok(d) = std::env::var("Citadel_PIN_DIR") {
            PinSource::Dir(d)
        } else if let Ok(f) = std::env::var("Citadel_PIN_FILE") {
            PinSource::File(f)
        } else {
            PinSource::None
        };

        // mldsa: Citadel_MLDSA_PUB (файл, полный pub) > Citadel_MLDSA_COMMIT (hex32, обязательство →
        // commitment-fetch) > Citadel_PIN_DIR/<host>.mldsa.
        let mldsa = if let Ok(f) = std::env::var("Citadel_MLDSA_PUB") {
            MldsaSource::File(f)
        } else if let Ok(h) = std::env::var("Citadel_MLDSA_COMMIT") {
            parse_pin(&h).map(MldsaSource::Commit).unwrap_or(MldsaSource::None)
        } else if let Ok(d) = std::env::var("Citadel_PIN_DIR") {
            MldsaSource::Dir(d)
        } else {
            MldsaSource::None
        };

        let token = std::env::var("Citadel_TOKENS")
            .ok()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| s.lines().next().map(|l| l.trim().to_string()))
            .and_then(|l| hex::decode(l).ok())
            .unwrap_or_default();

        // S1.2/M1: dns/routes попадают в root-контекст (resolv.conf, ip route) → валидируем.
        let routes = std::env::var("Citadel_ROUTES").unwrap_or_default();
        let dns = std::env::var("Citadel_DNS").ok();
        validate_net_fields(dns.as_deref(), &routes).context("Citadel_ROUTES/Citadel_DNS")?;

        Ok(Self {
            servers,
            server_name: std::env::var("Citadel_SERVER_NAME").unwrap_or_else(|_| "Citadel.exit".into()),
            obfs_psk: env_obfs_psk()?,
            kx_suite: std::env::var("Citadel_KX").unwrap_or_default(),
            tcp_port: std::env::var("Citadel_TCP_PORT").unwrap_or_else(|_| "443".into()),
            routes,
            dns,
            mtu: std::env::var("Citadel_MTU").unwrap_or_else(|_| "1280".into()),
            token,
            pin,
            mldsa,
            allow_insecure_no_pin: env_flag("Citadel_INSECURE_NO_PIN"),
            allow_classical_kx: env_flag("Citadel_INSECURE_CLASSICAL_KX"),
            require_pq_auth: env_flag("Citadel_REQUIRE_PQ_AUTH"),
            killswitch: env_flag("Citadel_KILLSWITCH"),
            split: Default::default(), // C8.3 split-tunnel — только клиентское GUI (Android), не env
        })
    }

    /// Pin сервера `host`: Shared > Dir/`<host>.pin` > File. Совпадает со старым `read_pin_for`.
    pub fn pin_for(&self, host: &str) -> PinMode {
        match &self.pin {
            PinSource::Bytes(p) => PinMode::Pinned(*p),
            PinSource::Shared(h) => parse_pin(h).map(PinMode::Pinned).unwrap_or(PinMode::Waiting),
            PinSource::Dir(dir) => pin_from_file(&format!("{dir}/{host}.pin")),
            PinSource::File(f) => pin_from_file(f),
            PinSource::None => PinMode::NoPin,
        }
    }

    /// ML-DSA-65 pub выбранного `host` (M7): File > Dir/`<host>.mldsa`. None → PQ-auth не запрашивается.
    /// Только для источников с полным pub; `Commit` полного pub не имеет (см. [`mldsa_expect`]).
    pub fn mldsa_for(&self, host: &str) -> Option<Vec<u8>> {
        match &self.mldsa {
            MldsaSource::Bytes(k) => Some(k.clone()),
            MldsaSource::File(f) => std::fs::read(f).ok(),
            MldsaSource::Dir(dir) => std::fs::read(format!("{dir}/{host}.mldsa")).ok(),
            MldsaSource::Commit(_) | MldsaSource::None => None,
        }
    }

    /// Ожидание клиента по ML-DSA pub выбранного `host`: полный pub (Bytes/File/Dir) → `Pub`;
    /// обязательство (ссылка/`Citadel_MLDSA_COMMIT`) → `Commit`; источник не настроен → `None`
    /// (PQ-auth не запрашивается).
    ///
    /// **M-1/аудит-4 — fail-closed.** Раньше нечитаемый File/Dir схлопывался в `None`, то есть
    /// PQ-аутентификация сервера МОЛЧА выключалась и клиент подключался на одном классическом pin,
    /// внешне неотличимо от штатной работы. Для контроля аутентификации это неверный дефолт: pin
    /// в той же ситуации fail-closed (см. `client::require_pin_or_insecure`). Теперь:
    ///   * `File` задан явно (`Citadel_MLDSA_PUB`) ⇒ файл ОБЯЗАН читаться, иначе ошибка;
    ///   * `Dir` выводится неявно из `Citadel_PIN_DIR` и обслуживает multi-exit, где PQ-auth
    ///     провижирована не для каждого exit'а ⇒ отсутствие файла — законное «не настроено»
    ///     (`None`), а вот существующий, но нечитаемый/пустой — ошибка (права, обрезанный файл);
    ///   * `Citadel_REQUIRE_PQ_AUTH=1` превращает любое `None` в отказ — рубильник для оператора,
    ///     которому нужна гарантия, а не «как получится».
    pub fn mldsa_expect(&self, host: &str) -> Result<MldsaExpect> {
        let expect = match &self.mldsa {
            MldsaSource::Bytes(k) => MldsaExpect::Pub(k.clone()),
            MldsaSource::File(f) => MldsaExpect::Pub(read_mldsa_pub(f)?),
            MldsaSource::Dir(dir) => {
                let path = format!("{dir}/{host}.mldsa");
                if std::path::Path::new(&path).exists() {
                    MldsaExpect::Pub(read_mldsa_pub(&path)?)
                } else {
                    MldsaExpect::None // PQ-auth для этого exit'а не провижирована
                }
            }
            MldsaSource::Commit(c) => MldsaExpect::Commit(*c),
            MldsaSource::None => MldsaExpect::None,
        };
        if self.require_pq_auth && matches!(expect, MldsaExpect::None) {
            anyhow::bail!(
                "PQ-auth обязательна (Citadel_REQUIRE_PQ_AUTH=1), но ML-DSA pub/commit для {host} \
                 не провижирован — отказ (fail-closed)"
            );
        }
        Ok(expect)
    }
}

/// Прочитать провижированный ML-DSA pub. Пустой файл — тоже отказ: он даёт `Pub(vec![])`, под
/// которым не сойдётся ни одна подпись, и клиент получил бы «подпись не прошла» вместо настоящей
/// причины «ключ не доехал».
fn read_mldsa_pub(path: &str) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path).with_context(|| {
        format!("PQ-auth: ML-DSA pub провижирован ({path}), но не читается — отказ (fail-closed)")
    })?;
    if bytes.is_empty() {
        anyhow::bail!("PQ-auth: ML-DSA pub {path} пуст — отказ (fail-closed)");
    }
    Ok(bytes)
}

/// Булев флаг окружения: `1`/`true` — включено, всё остальное (в т.ч. отсутствие) — выключено.
fn env_flag(name: &str) -> bool {
    std::env::var(name).map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false)
}

fn pin_from_file(path: &str) -> PinMode {
    match std::fs::read_to_string(path) {
        Ok(s) => parse_pin(&s).map(PinMode::Pinned).unwrap_or(PinMode::Waiting),
        Err(_) => PinMode::Waiting,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_mode_roundtrip_and_active() {
        for m in [SplitMode::Off, SplitMode::Include, SplitMode::Exclude] {
            assert_eq!(SplitMode::parse(m.as_str()), m);
        }
        assert_eq!(SplitMode::parse("garbage"), SplitMode::Off); // неизвестное → Off (fail-safe)
        // is_active: активна, только если режим не Off И список непуст
        let mut s = SplitTunnel::default();
        assert!(!s.is_active());
        s.app_mode = SplitMode::Include; // режим есть, список пуст → не активна
        assert!(!s.is_active());
        s.apps = vec!["com.example.app".into()];
        assert!(s.is_active());
        let d = SplitTunnel { dest_mode: SplitMode::Exclude, dests: vec!["192.168.0.0/16".into()], ..Default::default() };
        assert!(d.is_active());
    }

    #[test]
    fn parse_pin_cases() {
        let p = [0xABu8; 32];
        assert_eq!(parse_pin(&hex::encode(p)), Some(p));
        assert_eq!(parse_pin("  not-hex  "), None);
        assert_eq!(parse_pin(&hex::encode([0u8; 31])), None); // не 32 байта
    }

    /// M-7: PSK принимается ТОЛЬКО как 64 hex. Парольная фраза больше не выводится в ключ —
    /// раньше это был BLAKE3 в один проход, без соли и work-factor, то есть офлайн-перебор по
    /// словарю против секрета, общего на весь деплой и лежащего в каждой ссылке.
    #[test]
    fn obfs_psk_accepts_only_hex32() {
        assert_eq!(parse_obfs_psk(&hex::encode([7u8; 32])), Some([7u8; 32]));
        assert_eq!(parse_obfs_psk(&format!("  {}  ", hex::encode([7u8; 32]))), Some([7u8; 32]));
        for bad in ["", "   ", "hunter2", "correct horse battery staple"] {
            assert_eq!(parse_obfs_psk(bad), None, "фраза {bad:?} не должна становиться ключом");
        }
        assert_eq!(parse_obfs_psk(&hex::encode([7u8; 31])), None, "62 hex — не 32 байта");
        assert_eq!(parse_obfs_psk(&"z".repeat(64)), None, "64 символа, но не hex");
    }

    /// …и негодное значение переменной — это ОШИБКА запуска, а не «obfs выключен»: иначе опечатка
    /// в PSK молча снимала бы весь L1-слой при внешне настроенном конфиге.
    #[test]
    fn env_obfs_psk_is_fail_closed() {
        // SAFETY (тест): переменная трогается в одном месте и восстанавливается сразу же.
        let restore = std::env::var("Citadel_OBFS_PSK").ok();
        std::env::set_var("Citadel_OBFS_PSK", "hunter2");
        let err = env_obfs_psk().unwrap_err();
        assert!(format!("{err:#}").contains("64 hex"), "err: {err:#}");
        std::env::set_var("Citadel_OBFS_PSK", hex::encode([9u8; 32]));
        assert_eq!(env_obfs_psk().unwrap(), Some([9u8; 32]));
        std::env::set_var("Citadel_OBFS_PSK", "");
        assert_eq!(env_obfs_psk().unwrap(), None, "пусто = obfs не настроен, это штатно");
        std::env::remove_var("Citadel_OBFS_PSK");
        assert_eq!(env_obfs_psk().unwrap(), None);
        if let Some(v) = restore {
            std::env::set_var("Citadel_OBFS_PSK", v);
        }
    }

    #[test]
    fn pin_for_modes() {
        let mk = |pin| ClientConfig {
            servers: vec![],
            server_name: "x".into(),
            obfs_psk: None,
            kx_suite: String::new(),
            tcp_port: "443".into(),
            routes: String::new(),
            dns: None,
            mtu: "1280".into(),
            token: vec![],
            pin,
            mldsa: MldsaSource::None,
            allow_insecure_no_pin: false,
            allow_classical_kx: false,
            require_pq_auth: false,
            killswitch: false,
            split: Default::default(),
        };
        assert!(matches!(mk(PinSource::None).pin_for("h"), PinMode::NoPin));
        let p = [3u8; 32];
        assert!(matches!(mk(PinSource::Shared(hex::encode(p))).pin_for("h"), PinMode::Pinned(x) if x == p));
        assert!(matches!(mk(PinSource::Shared("nothex".into())).pin_for("h"), PinMode::Waiting));
        assert!(matches!(mk(PinSource::Bytes(p)).pin_for("h"), PinMode::Pinned(x) if x == p));
    }

    #[test]
    fn mldsa_for_bytes() {
        let cfg = ClientConfig {
            servers: vec![],
            server_name: "x".into(),
            obfs_psk: None,
            kx_suite: String::new(),
            tcp_port: "443".into(),
            routes: String::new(),
            dns: None,
            mtu: "1280".into(),
            token: vec![],
            pin: PinSource::None,
            mldsa: MldsaSource::Bytes(vec![1, 2, 3]),
            allow_insecure_no_pin: false,
            allow_classical_kx: false,
            require_pq_auth: false,
            killswitch: false,
            split: Default::default(),
        };
        assert_eq!(cfg.mldsa_for("any"), Some(vec![1, 2, 3]));
    }

    // ───────────── M-1/аудит-4: PQ-auth не должна выключаться молча ─────────────

    fn cfg_with_mldsa(mldsa: MldsaSource, require_pq_auth: bool) -> ClientConfig {
        ClientConfig {
            servers: vec![],
            server_name: "x".into(),
            obfs_psk: None,
            kx_suite: String::new(),
            tcp_port: "443".into(),
            routes: String::new(),
            dns: None,
            mtu: "1280".into(),
            token: vec![],
            pin: PinSource::None,
            mldsa,
            allow_insecure_no_pin: false,
            allow_classical_kx: false,
            require_pq_auth,
            killswitch: false,
            split: Default::default(),
        }
    }

    /// Явно заданный (`Citadel_MLDSA_PUB`), но нечитаемый ML-DSA pub — ОТКАЗ, а не тихое
    /// отключение PQ-аутентификации. Регрессия, которую это ловит: раньше удалённый/недоступный
    /// по правам файл схлопывался в `MldsaExpect::None`, клиент подключался на одном классическом
    /// pin и внешне это было неотличимо от штатной работы.
    #[test]
    fn missing_provisioned_mldsa_file_is_refused() {
        let cfg = cfg_with_mldsa(MldsaSource::File("/nonexistent/exit.mldsa".into()), false);
        // `expect_err` требовал бы `Debug` на `MldsaExpect`, а он несёт ML-DSA pub (1952 Б) —
        // выводить его в диагностику незачем. Разбираем результат вручную.
        let Err(err) = cfg.mldsa_expect("h") else { panic!("нечитаемый провижированный pub — отказ") };
        assert!(format!("{err:#}").contains("не читается"), "err: {err:#}");
    }

    /// Пустой файл — тоже отказ: иначе клиент получил бы «подпись не прошла» вместо настоящей
    /// причины «ключ не доехал».
    #[test]
    fn empty_provisioned_mldsa_file_is_refused() {
        let p = std::env::temp_dir().join(format!("citadel-mldsa-empty-{}", std::process::id()));
        std::fs::write(&p, b"").unwrap();
        let cfg = cfg_with_mldsa(MldsaSource::File(p.to_string_lossy().into_owned()), false);
        assert!(cfg.mldsa_expect("h").is_err(), "пустой pub — отказ");
        let _ = std::fs::remove_file(&p);
    }

    /// `Dir` выводится неявно из `Citadel_PIN_DIR` и обслуживает multi-exit, где PQ-auth
    /// провижирована не для каждого узла: ОТСУТСТВИЕ файла — законное «не настроено» (иначе
    /// сломались бы работающие деплои), а вот существующий пустой — ошибка.
    #[test]
    fn mldsa_dir_absent_is_not_configured_but_broken_is_error() {
        let dir = std::env::temp_dir().join(format!("citadel-mldsa-dir-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let d = dir.to_string_lossy().into_owned();

        // файла нет → PQ-auth для этого host'а просто не провижирована
        let cfg = cfg_with_mldsa(MldsaSource::Dir(d.clone()), false);
        assert!(matches!(cfg.mldsa_expect("exit1").unwrap(), MldsaExpect::None));

        // файл есть, но пустой → отказ (права/обрезанный файл — это поломка, а не «не настроено»)
        std::fs::write(dir.join("exit2.mldsa"), b"").unwrap();
        assert!(cfg.mldsa_expect("exit2").is_err());

        // нормальный файл → Pub
        std::fs::write(dir.join("exit3.mldsa"), vec![7u8; 1952]).unwrap();
        assert!(matches!(cfg.mldsa_expect("exit3").unwrap(), MldsaExpect::Pub(k) if k.len() == 1952));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `Citadel_REQUIRE_PQ_AUTH=1` — рубильник оператора: любое «не провижировано» становится
    /// отказом. Без флага поведение прежнее (провижининг решает сам).
    #[test]
    fn require_pq_auth_flag_turns_absent_into_refusal() {
        assert!(matches!(
            cfg_with_mldsa(MldsaSource::None, false).mldsa_expect("h").unwrap(),
            MldsaExpect::None
        ));
        let Err(err) = cfg_with_mldsa(MldsaSource::None, true).mldsa_expect("h") else {
            panic!("с рубильником отсутствие материала — отказ")
        };
        assert!(format!("{err:#}").contains("REQUIRE_PQ_AUTH"), "err: {err:#}");
        // commit из ссылки удовлетворяет требование
        assert!(cfg_with_mldsa(MldsaSource::Commit([1u8; 32]), true).mldsa_expect("h").is_ok());
    }

    #[test]
    fn net_field_validation() {
        assert!(validate_net_fields(Some("1.1.1.1"), "0.0.0.0/0 10.0.0.0/8").is_ok());
        assert!(validate_net_fields(None, "").is_ok());
        // инъекция перевода строки в dns → отказ (иначе — произвольный resolv.conf от root)
        assert!(validate_net_fields(Some("1.1.1.1\nnameserver 6.6.6.6"), "").is_err());
        assert!(validate_net_fields(Some("not-an-ip"), "").is_err());
        assert!(validate_net_fields(None, "1.1.1.1/33").is_err()); // префикс >32
        assert!(validate_net_fields(None, "garbage").is_err());
        assert!(is_cidr("10.0.0.0/8") && is_cidr("1.1.1.1")); // CIDR и голый IP
        assert!(!is_cidr("1.1.1.1/40"));
    }
}
