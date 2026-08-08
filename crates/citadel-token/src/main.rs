//! citadel-token — роли анонимного issuance (M5, issuer↔exit split).
//!
//! Режим (env `Citadel_TOKEN_ROLE` или arg[1]):
//!   `issuer`  — сгенерировать ключ эпохи, положить его в `issuer-<epoch>.key` (0600), слушать TCP
//!               и вычислять ВСЛЕПУЮ (издатель видит только ослеплённый элемент, не токен).
//!   `client`  — подключиться к издателю, интерактивно получить N токенов (blind→evaluate→
//!               finalize), записать в файл. Издатель не связывает выданное с предъявленным.
//!   `keysync` — exit-узел на ОТДЕЛЬНОЙ машине забирает ключ текущей эпохи (P1), доказав свою
//!               keysync-идентичность. Раньше назывался `pubsync` и ходил без аутентификации —
//!               в схеме v2 (M-6) ключ эпохи секретен, см. `citadel_token::fetch_epoch_key`.
//!   `batch`   — (legacy) выпустить N токенов в одном процессе → файл (для локального демо/тестов).
//!
//! CLI-подкоманды (arg[1], вне env-роли): `registry` — оффлайн-правка Layer-1 реестра на сервере
//! (C5.5); `admin` — те же операции ПО СЕТЕВОМУ admin-каналу (PQ-TLS+pin, домен+EKM; C7.5) — путь
//! GUI, обычно через туннель к ADMIN_VIP.
//!
//! Сетевой формат: кадр `u32(len, BE) ‖ payload`; запрос — ослеплённый элемент (32 Б), ответ —
//! `evaluated(32) ‖ DLEQ(64)`.

use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use citadel_token::{read_frame, write_frame}; // C5.3: фрейминг вынесен в lib (переиспользует fetch_tokens)

fn token_dir() -> String {
    std::env::var("Citadel_TOKEN_DIR").unwrap_or_else(|_| "/shared".into())
}

/// S2.1/A1-остаток: obfs-PSK канала к издателю из `Citadel_OBFS_PSK` (hex32). `Some` → issuer/CLI
/// оборачивают TLS в obfs (probe-resistance, неотличимость от туннеля); `None`/мусор → голый TLS.
/// Тот же PSK, что у туннеля (в ссылке) — обе стороны обязаны совпадать, иначе `open` рвёт канал.
fn obfs_psk_from_env() -> Option<[u8; 32]> {
    std::env::var("Citadel_OBFS_PSK")
        .ok()
        .and_then(|s| hex::decode(s.trim()).ok())
        .and_then(|v| v.try_into().ok())
}
fn token_count() -> usize {
    std::env::var("Citadel_TOKEN_COUNT").ok().and_then(|s| s.parse().ok()).unwrap_or(8)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// M-4 (аудит-4): сбросить привилегии издателя — **opt-in по `Citadel_DROP_UID`**.
///
/// Издателю root не нужен ни для чего: он слушает порты >1024, не трогает сеть ядра и работает
/// только со своим каталогом `Citadel_TOKEN_DIR`. А держит при этом всё самое ценное — RSA-sk
/// текущей эпохи, TLS-приватник, ML-DSA-seed, реестр абонентов и obfs-PSK — и разбирает весь
/// недоверенный сетевой ввод (obfs-record, TLS-record, CBOR-кадры, ослеплённые сообщения).
///
/// **Почему opt-in, а не как у exit'а (F4, всегда).** В docker-деплое издатель и exit делят ОДИН
/// том. Сменить uid издателя — значит переразметить владение этим томом, а писать в него как root
/// продолжают и entrypoint издателя, и exit (его `exit.pin`/серт/seed), и — при раздельной
/// установке — сайдкар pubsync. Согласованная схема владения нужна сразу в трёх ролях и двух
/// compose-файлах, из которых харнесом проверяется только один. Цена ошибки — «издатель не
/// стартовал» в проде; выигрыш поверх `cap_drop: ALL` + `read_only` + `no-new-privileges` мал
/// (у root без capabilities на неизменяемом rootfs остаётся ровно то, к чему процесс и так имеет
/// законный доступ). Поэтому в контейнере привилегии режутся capability-набором, а этот
/// сброс — для запуска издателя ВНЕ докера (systemd/bare metal), где каталог принадлежит
/// сервисному пользователю и всё однозначно.
///
/// Сбрасываем в САМОМ НАЧАЛЕ роли (до создания файлов), иначе `issuer.pub` и ключи эпохи остались
/// бы root-owned и фоновая ротация не смогла бы их перезаписать.
///
/// NB: если задаёте `Citadel_DROP_UID` при совмещённом с exit'ом томе — берите uid, ОТЛИЧНЫЙ от
/// `Citadel_DROP_UID` exit'а (по умолчанию 65534). Совпади они — exit прочитал бы `issuer-tls.key`,
/// `issuer-mldsa.seed` и реестр (они 0600), и разделение ролей исчезло бы.
fn drop_privileges() -> Result<()> {
    let Some(uid) = std::env::var("Citadel_DROP_UID").ok().and_then(|s| s.parse::<u32>().ok()) else {
        return Ok(()); // не задано — работаем как есть (в контейнере привилегии режет cap_drop)
    };
    // SAFETY: geteuid без побочных эффектов.
    if unsafe { libc::geteuid() } != 0 {
        return Ok(()); // не root (уже под юзером) — нечего ронять
    }
    if uid == 0 {
        anyhow::bail!("Citadel_DROP_UID=0 — сброс привилегий в root не имеет смысла");
    }
    let gid: u32 = std::env::var("Citadel_DROP_GID").ok().and_then(|s| s.parse().ok()).unwrap_or(uid);
    // Порядок принципиален: доп. группы → gid → uid (после setuid вернуть их уже нельзя).
    // SAFETY: значения — обычные uid/gid; setgroups(0, NULL) очищает список доп. групп.
    unsafe {
        if libc::setgroups(0, std::ptr::null::<libc::gid_t>()) != 0 {
            anyhow::bail!("setgroups: {}", std::io::Error::last_os_error());
        }
        if libc::setgid(gid) != 0 {
            anyhow::bail!("setgid({gid}): {}", std::io::Error::last_os_error());
        }
        if libc::setuid(uid) != 0 {
            anyhow::bail!("setuid({uid}): {}", std::io::Error::last_os_error());
        }
        // Контрольный выстрел: если привилегии на самом деле не упали, дальше идти нельзя.
        if libc::setuid(0) == 0 {
            anyhow::bail!("привилегии не сброшены: setuid(0) неожиданно удался");
        }
    }
    eprintln!("[issuer] привилегии сброшены: uid={uid} gid={gid} (M-4)");
    Ok(())
}

// ============ H-1 (аудит-4): гейт соединений издателя ДО аутентификации ============
//
// Раньше `accept` порождал поток на КАЖДОЕ соединение, а поток немедленно вставал в блокирующем
// чтении TLS/obfs-хендшейка — при этом на сокете НЕ стояло ни одного таймаута. Молчаливый коннект
// парковал поток навсегда, знание obfs-PSK для этого не требовалось (блокировка наступает до
// первого байта). Издатель — единая точка отказа всей системы: свежий Layer-1 токен нужен клиенту
// на КАЖДЫЙ establish, включая реконнект, а в том же процессе живёт admin-канал. Тем же приёмом
// абонент мог положить издателя изнутри туннеля через ADMIN_VIP.
//
// Закрываем тремя средствами (то же, что уже сделано на exit'е — см. семафоры и
// TCP_HANDSHAKE_TIMEOUT в citadel-m1):
//   * потолок ОДНОВРЕМЕННЫХ pre-auth соединений — общий и на адрес;
//   * таймауты сокета (SO_RCVTIMEO/SO_SNDTIMEO) на время хендшейка;
//   * жёсткий дедлайн всей фазы до аутентификации (таймаут сокета сбрасывается на каждый вызов
//     read, поэтому одного его мало против «капающего по байту» противника).
// Слот освобождается СРАЗУ после аутентификации: установленная сессия потолок не занимает.

/// Потолок одновременных pre-auth соединений канала выдачи токенов.
const MAX_PREAUTH: usize = 256;
/// ...и одного адреса: без него один источник забирает весь потолок, и легитимные клиенты
/// не проходят, хотя формально лимит «на всех» соблюдён.
const MAX_PREAUTH_PER_IP: usize = 8;
/// Потолки admin-канала — отдельные: флуд на выдачу токенов не должен отбирать у администратора
/// возможность подключиться (и наоборот).
const MAX_PREAUTH_ADMIN: usize = 32;
const MAX_PREAUTH_ADMIN_PER_IP: usize = 4;

/// Таймаут одной операции сокета ДО аутентификации. Хендшейк короткий (TLS 1.3 + hello ~3.4 КБ +
/// auth-кадр ~5.3 КБ) — даже на плохом мобильном канале это доли секунды.
const PREAUTH_TIMEOUT: Duration = Duration::from_secs(10);
/// Жёсткий потолок всей фазы до аутентификации (см. про «каплю по байту» выше).
const PREAUTH_DEADLINE: Duration = Duration::from_secs(20);
/// Таймаут операций ПОСЛЕ аутентификации: слепая выдача идёт пачкой сразу, а admin-сессия ждёт
/// команды человека — потолок щедрый, но конечный (мёртвый пир не висит вечно).
const SESSION_TIMEOUT: Duration = Duration::from_secs(300);
/// Шаг опроса сторожевого потока: чем мельче, тем быстрее он уходит после штатного завершения.
const WATCH_TICK: Duration = Duration::from_millis(250);

/// Учёт одновременных pre-auth соединений. Карта адресов ограничена сверху `max_total`
/// (у каждой записи счётчик ≥ 1), поэтому неограниченно расти не может.
#[derive(Default)]
struct GateState {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
}

#[derive(Clone)]
struct Gate {
    state: Arc<Mutex<GateState>>,
    max_total: usize,
    max_per_ip: usize,
}

/// Занятый слот: держится, пока жив. Освобождается дропом — в том числе на любом раннем возврате
/// по ошибке, поэтому «потерять» слот нельзя.
struct Pass {
    gate: Gate,
    ip: IpAddr,
}

impl Drop for Pass {
    fn drop(&mut self) {
        self.gate.release(self.ip);
    }
}

impl Gate {
    fn new(max_total: usize, max_per_ip: usize) -> Self {
        Self { state: Arc::new(Mutex::new(GateState::default())), max_total, max_per_ip }
    }

    /// Взять слот под pre-auth фазу. `None` — потолок исчерпан (соединение закрываем немедленно,
    /// не заводя ни потока, ни состояния).
    fn admit(&self, ip: IpAddr) -> Option<Pass> {
        let mut st = self.state.lock().unwrap();
        if st.total >= self.max_total {
            return None;
        }
        let cur = st.per_ip.get(&ip).copied().unwrap_or(0);
        if cur >= self.max_per_ip {
            return None;
        }
        st.per_ip.insert(ip, cur + 1);
        st.total += 1;
        Some(Pass { gate: self.clone(), ip })
    }

    fn release(&self, ip: IpAddr) {
        let mut st = self.state.lock().unwrap();
        st.total = st.total.saturating_sub(1);
        if let Some(n) = st.per_ip.get_mut(&ip) {
            *n -= 1;
            if *n == 0 {
                st.per_ip.remove(&ip); // пустые записи не копим
            }
        }
    }
}

/// Пульт сокета: жёсткий дедлайн фазы до аутентификации и смена таймаутов после неё.
///
/// Держит дублированный дескриптор — `SO_RCVTIMEO`/`SO_SNDTIMEO` и `shutdown` действуют на сам
/// сокет, поэтому работают, хотя поток уже уехал внутрь TLS/obfs-обёртки.
struct SockCtl {
    sock: Option<TcpStream>,
    /// «Сторож больше не нужен»: ставится и при успешной аутентификации, и при завершении
    /// обслуживания (Drop). Без второго условия сторожевые потоки копились бы при высокой
    /// текучке коротких соединений.
    done: Arc<AtomicBool>,
}

impl SockCtl {
    /// Завести пульт и сторожевой поток на `PREAUTH_DEADLINE`.
    fn arm(tcp: &TcpStream) -> Self {
        let done = Arc::new(AtomicBool::new(false));
        if let Ok(watch) = tcp.try_clone() {
            let flag = done.clone();
            std::thread::spawn(move || {
                let deadline = Instant::now() + PREAUTH_DEADLINE;
                while Instant::now() < deadline {
                    if flag.load(Ordering::Acquire) {
                        return; // аутентифицировались или соединение уже закрыто — сторож не нужен
                    }
                    std::thread::sleep(WATCH_TICK);
                }
                if !flag.load(Ordering::Acquire) {
                    // Аутентификации за отведённое время не случилось: закрываем сокет, чтобы
                    // блокирующее чтение в рабочем потоке вернуло ошибку и поток вышел.
                    let _ = watch.shutdown(std::net::Shutdown::Both);
                }
            });
        }
        Self { sock: tcp.try_clone().ok(), done }
    }

    /// Аутентификация пройдена: снять жёсткий дедлайн и ослабить таймауты до сессионных.
    fn authenticated(&self) {
        self.done.store(true, Ordering::Release);
        if let Some(s) = &self.sock {
            let _ = s.set_read_timeout(Some(SESSION_TIMEOUT));
            let _ = s.set_write_timeout(Some(SESSION_TIMEOUT));
        }
    }
}

impl Drop for SockCtl {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Release);
    }
}

/// Общая accept-петля обоих каналов издателя: гейт, таймауты, throttl'ированный лог отказов.
/// `serve` получает поток, слот (освобождает его после аутентификации) и пульт сокета.
/// L-14/аудит-4: allowlist адресов, с которых принимается admin-канал.
///
/// При раздельном деплое (`--role issuer`) admin-порт приходится публиковать наружу — его дёргает
/// exit-машина через DNAT из туннеля. До этого его «защищала» строчка в выводе установщика
/// («закрой firewall'ом»), то есть контроль существовал только в голове оператора. Теперь список
/// разрешённых источников знает сам процесс: чужой коннект закрывается ДО TLS, не тратя ни
/// хендшейка, ни слота гейта. Это не замена firewall'у, а второй рубеж, который нельзя забыть
/// применить и который переживает переустановку хоста.
///
/// Пусто или `any` — без ограничения (совмещённый деплой: порт вообще не публикуется).
#[derive(Clone, Default)]
struct PeerAllow(Option<Arc<Vec<std::net::IpAddr>>>);

impl PeerAllow {
    fn from_env(var: &str) -> Result<Self> {
        let raw = match std::env::var(var) {
            Ok(v) => v,
            Err(_) => return Ok(Self(None)),
        };
        let t = raw.trim();
        if t.is_empty() || t.eq_ignore_ascii_case("any") {
            return Ok(Self(None));
        }
        let mut ips = Vec::new();
        for p in t.split([',', ' ', ';']).map(str::trim).filter(|s| !s.is_empty()) {
            // Опечатка в адресе не должна превращаться в «пускаем всех»: это ровно тот
            // fail-open, за который аудит уже ловил mldsa_expect (M-1) и parse_obfs_psk (M-7).
            ips.push(p.parse::<std::net::IpAddr>().map_err(|_| {
                anyhow!("{var}: '{p}' — не IP-адрес (ожидается список адресов через запятую либо 'any')")
            })?);
        }
        Ok(Self(if ips.is_empty() { None } else { Some(Arc::new(ips)) }))
    }

    fn permits(&self, ip: std::net::IpAddr) -> bool {
        match &self.0 {
            None => true,
            Some(list) => list.contains(&ip),
        }
    }

    fn describe(&self) -> String {
        match &self.0 {
            None => "любой адрес (ограничение не задано)".into(),
            Some(l) => l.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", "),
        }
    }
}

fn accept_loop<F>(listener: TcpListener, what: &'static str, gate: Gate, allow: PeerAllow, serve: F)
where
    F: Fn(TcpStream, Pass, SockCtl) + Send + Sync + 'static,
{
    let serve = Arc::new(serve);
    // Лог отказов агрегируем раз в секунду: строка на каждый отбитый коннект — это лог-амплификация,
    // то есть вторичный DoS поверх уже закрытого (тот же приём, что в citadel-m1).
    let mut rejected: u64 = 0;
    let mut last_log = Instant::now();
    for conn in listener.incoming() {
        let tcp = match conn {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[issuer] {what}: accept: {e}");
                // EMFILE/ENFILE: без паузы петля крутилась бы вхолостую на полной скорости.
                std::thread::sleep(WATCH_TICK);
                continue;
            }
        };
        let Ok(ip) = tcp.peer_addr().map(|a| a.ip()) else { continue };
        // L-14: посторонний источник закрывается до всего остального (и до слота гейта).
        if !allow.permits(ip) {
            drop(tcp);
            rejected += 1;
            if last_log.elapsed() >= Duration::from_secs(1) {
                eprintln!(
                    "[issuer] {what}: отклонено {rejected} соединений с посторонних адресов за \
                     секунду — разрешены только {} (L-14)",
                    allow.describe()
                );
                rejected = 0;
                last_log = Instant::now();
            }
            continue;
        }
        let Some(pass) = gate.admit(ip) else {
            drop(tcp); // потолок исчерпан — закрываем сразу, состояния не заводим
            rejected += 1;
            if last_log.elapsed() >= Duration::from_secs(1) {
                eprintln!(
                    "[issuer] {what}: лимит одновременных pre-auth соединений \
                     ({} всего / {} на адрес) — отклонено {rejected} за секунду (H-1)",
                    gate.max_total, gate.max_per_ip
                );
                rejected = 0;
                last_log = Instant::now();
            }
            continue;
        };
        let _ = tcp.set_read_timeout(Some(PREAUTH_TIMEOUT));
        let _ = tcp.set_write_timeout(Some(PREAUTH_TIMEOUT));
        let ctl = SockCtl::arm(&tcp);
        let serve = serve.clone();
        std::thread::spawn(move || serve(tcp, pass, ctl));
    }
}

// ===================== C5.2 Layer-1: реестр «абонентов» у issuer =====================
fn registry_path(dir: &str) -> String {
    format!("{dir}/registry")
}

/// Реестр — строки `<client_id_hex> <valid_until_unix> <status>`. Возвращает true, если id найден,
/// `active` и не истёк. Читается на КАЖДЫЙ auth → отзыв/добавление действуют сразу (≤ след. коннект).
/// C7.1: разбор строк — общий `admin::parse_registry` (первое совпадение решает, как раньше).
///
/// PQ-трек: `client_id` — уже не «Ed25519 pub абонента», а `BLAKE3(ed_pub ‖ mldsa_pub)` его
/// гибридной идентичности ([`citadel_token::pqid`]); длина и формат файла те же.
fn registry_allows(dir: &str, client_id: &[u8], now: u64) -> bool {
    let Ok(content) = std::fs::read_to_string(registry_path(dir)) else {
        return false; // нет реестра → никто не авторизован (secure default)
    };
    citadel_token::admin::parse_registry(&content)
        .iter()
        .find(|e| e.client_id[..] == *client_id)
        .is_some_and(|e| e.status == "active" && now < e.valid_until)
}

/// Bootstrap реестра Layer-1 из env (демо + installer, C5.4b):
///   - `Citadel_REGISTER_PUBS`  — client_id-pub'ы (hex32, через пробел): **issuer НЕ видит seed**
///     абонента (installer/прод-путь — админ регистрирует только публичный id).
///   - `Citadel_REGISTER_SEEDS` — seed'ы (hex32) → pub деривится здесь (демо/legacy: issuer знает seed).
///
/// **Идемпотентно и не затирает** существующие строки: pub, уже присутствующий в реестре, не трогается.
/// Это критично — иначе admin-revoke (`status=revoked`) терялся бы при рестарте контейнера и отозванный
/// абонент «воскресал» бы `active`. Добавляются только новые pub'ы как `active` на +10 лет. В проде
/// правкой файла (revoke/add) управляет админ (C5.5); bootstrap лишь досевает недостающих.
/// L-10/аудит-4: стенд обязан быть помечен стендом. Демо-`entrypoint`'ы включают диагностический
/// лог и держат seed'ы вида `c5c5…`/`adad…` прямо в тексте — а аудит справедливо считает
/// реалистичным сценарий «взяли готовый entrypoint из репозитория и подняли им прод».
/// `Citadel_DEMO_STAND=1` — единственное место, где такие значения разрешены.
fn demo_stand() -> bool {
    matches!(std::env::var("Citadel_DEMO_STAND").as_deref(), Ok("1"))
}

/// L-10: отказать в старте на seed'е с очевидно нулевой энтропией (повтор одного и того же
/// 1/2/4-байтного шаблона — ровно так выглядят и демо-seed'ы, и «набрано руками»). Такой seed —
/// это приватный ключ абонента/админа/keysync, и подобрать его может кто угодно за один вечер.
fn guard_weak_seed(what: &str, seed: &[u8; 32]) -> Result<()> {
    let weak = [1usize, 2, 4].iter().any(|&p| seed.chunks(p).all(|c| c == &seed[..p]));
    if weak && !demo_stand() {
        bail!(
            "{what}: seed из повторяющегося шаблона ({}…) — это не секрет, а демо-значение. \
             Сгенерируй настоящий: `head -c 32 /dev/urandom | xxd -p -c 32`. \
             Если это заведомо стенд — Citadel_DEMO_STAND=1",
            hex::encode(&seed[..4])
        );
    }
    Ok(())
}

fn bootstrap_registry(dir: &str) -> Result<()> {
    let mut pubs: Vec<[u8; 32]> = Vec::new();
    if let Ok(list) = std::env::var("Citadel_REGISTER_PUBS") {
        for p in list.split_whitespace() {
            let pk: [u8; 32] = hex::decode(p)
                .ok()
                .and_then(|v| v.try_into().ok())
                .context("Citadel_REGISTER_PUBS: client_id должен быть 32 байта hex")?;
            pubs.push(pk);
        }
    }
    if let Ok(list) = std::env::var("Citadel_REGISTER_SEEDS") {
        for s in list.split_whitespace() {
            let seed: [u8; 32] = hex::decode(s)
                .ok()
                .and_then(|v| v.try_into().ok())
                .context("Citadel_REGISTER_SEEDS: seed должен быть 32 байта hex")?;
            guard_weak_seed("Citadel_REGISTER_SEEDS", &seed)?; // L-10
            pubs.push(citadel_token::pqid::id_from_seed(&seed)?);
        }
    }
    if pubs.is_empty() {
        return Ok(()); // нет bootstrap-env → реестр как есть (admin-managed или пуст)
    }
    let existing = std::fs::read_to_string(registry_path(dir)).unwrap_or_default();
    let far = now_unix() + 10 * 365 * 24 * 3600;
    let merged = merge_registry(&existing, &pubs, far);
    // P1: реестр — приватные данные абонентской базы; читает его только издатель (600).
    citadel_token::admin::atomic_write(&registry_path(dir), &merged).context("запись реестра")?;
    eprintln!(
        "[issuer] реестр Layer-1: {} абонент(ов) (bootstrap-merge; revoke переживает рестарт)",
        merged.lines().filter(|l| !l.trim().is_empty()).count()
    );
    Ok(())
}

/// Чистая логика слияния реестра: сохраняет ВСЕ существующие строки (в т.ч. `revoked`/`expired`),
/// добавляет только те `pubs`, которых ещё нет (по pub_hex), как `active` до `valid_until`.
/// Идемпотентно: повторный вызов с теми же pub'ами не меняет вывод.
fn merge_registry(existing: &str, pubs: &[[u8; 32]], valid_until: u64) -> String {
    let present: std::collections::HashSet<&str> =
        existing.lines().filter_map(|l| l.split_whitespace().next()).collect();
    let mut out = existing.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    for pk in pubs {
        let hexpk = hex::encode(pk);
        if !present.contains(hexpk.as_str()) {
            out.push_str(&format!("{hexpk} {valid_until} active\n"));
        }
    }
    out
}

// ===================== C5.5: admin-CLI управления реестром =====================

/// `citadel-token registry <add|add-seed|revoke|list> …` — оффлайн-правка Layer-1 реестра админом
/// (замена ручного `sed` из installer'а). Каталог реестра — `Citadel_TOKEN_DIR` (том issuer'а).
/// Issuer перечитывает реестр на КАЖДЫЙ auth ⇒ add/revoke действуют со следующего коннекта
/// (отзыв — ≤ длины эпохи). Запись атомарна (temp+rename) — конкурентный читатель-issuer видит
/// старый ИЛИ новый файл, не частичный. C7.1: логика реестра — общая `citadel_token::admin`
/// (те же функции обслуживают admin-канал по туннелю).
fn run_registry(args: &[String]) -> Result<()> {
    use citadel_token::admin::{atomic_write, registry_apply_add, registry_apply_revoke};
    let path = registry_path(&token_dir());
    match args.get(2).map(String::as_str) {
        Some("add") => {
            let pk = parse_hex32(args.get(3), "pub (client_id, 64 hex)")?;
            let vu = parse_valid_until(args.get(4).map(String::as_str))?;
            let cur = std::fs::read_to_string(&path).unwrap_or_default();
            atomic_write(&path, &registry_apply_add(&cur, &pk, vu))?;
            eprintln!("[registry] add {} active до {vu}", hex::encode(pk));
        }
        Some("add-seed") => {
            // Провижининг нового абонента: из его seed выводим pub (client_id) и регистрируем ЕГО.
            // Seed НЕ сохраняется (уходит абоненту в ссылке) — в реестре только публичный id.
            let seed = parse_hex32(args.get(3), "seed (64 hex)")?;
            let pk = citadel_token::pqid::id_from_seed(&seed)?;
            let vu = parse_valid_until(args.get(4).map(String::as_str))?;
            let cur = std::fs::read_to_string(&path).unwrap_or_default();
            atomic_write(&path, &registry_apply_add(&cur, &pk, vu))?;
            eprintln!("[registry] add-seed → client_id {} active до {vu}", hex::encode(pk));
        }
        Some("revoke") => {
            let pk = parse_hex32(args.get(3), "pub (client_id, 64 hex)")?;
            let cur = std::fs::read_to_string(&path).unwrap_or_default();
            atomic_write(&path, &registry_apply_revoke(&cur, &pk)?)?;
            eprintln!("[registry] revoke {} (действует ≤ длины эпохи)", hex::encode(pk));
        }
        Some("list") => print!("{}", std::fs::read_to_string(&path).unwrap_or_default()),
        _ => anyhow::bail!(
            "citadel-token registry <add <pub>|add-seed <seed>|revoke <pub>|list> [valid_until]\n  \
             valid_until: unix-секунды | +<N>d | +<N>h | +<секунды> (дефолт +365d).  \
             Каталог реестра — $Citadel_TOKEN_DIR (том issuer'а)."
        ),
    }
    Ok(())
}

// ===================== C7.5: admin-CLI ПО КАНАЛУ (туннелю) =====================

/// `citadel-token admin <list|add <pub> [valid_until]|revoke <pub>>` — управление реестром через
/// СЕТЕВОЙ admin-канал issuer'а (PQ-TLS+pin, Ed25519 домен+EKM) — тот же путь, что GUI (C7.3/C7.4),
/// в отличие от `registry` (оффлайн-правка файла на сервере). Для харнеса C7.5 и ops/break-glass
/// с любой машины, у которой есть мастер-креды и туннель.
///
/// Env: `Citadel_ADMIN_ADDR` (host:port; из туннеля — `10.7.0.1:<admin_port>`),
///      `Citadel_ISSUER_PIN` (hex32 — тот же TLS-pin issuer'а, что для token-fetch),
///      `Citadel_ISSUER_MLDSA` (hex32 — обязательство PQ-идентичности издателя из ссылки),
///      `Citadel_ADMIN_SEED` (hex32 — admin-seed из мастер-ссылки).
fn run_admin_channel(args: &[String]) -> Result<()> {
    let addr = std::env::var("Citadel_ADMIN_ADDR")
        .context("нужен Citadel_ADMIN_ADDR (host:port admin-канала; из туннеля — ADMIN_VIP:порт)")?;
    let pin = parse_hex32(
        std::env::var("Citadel_ISSUER_PIN").ok().as_ref(),
        "Citadel_ISSUER_PIN (TLS-pin issuer, 64 hex)",
    )?;
    let issuer_mldsa = parse_hex32(
        std::env::var("Citadel_ISSUER_MLDSA").ok().as_ref(),
        "Citadel_ISSUER_MLDSA (обязательство PQ-идентичности издателя, 64 hex)",
    )?;
    let seed = parse_hex32(
        std::env::var("Citadel_ADMIN_SEED").ok().as_ref(),
        "Citadel_ADMIN_SEED (admin-seed, 64 hex)",
    )?;
    // S2.1/A1-остаток: obfs-обёртка admin-канала (probe-resistance) — PSK из env, как token-fetch.
    let obfs_psk = obfs_psk_from_env();
    let mut c = citadel_token::admin::AdminClient::connect(&addr, &pin, &issuer_mldsa, &seed, obfs_psk)
        .context("admin-канал: connect/auth")?;
    match args.get(2).map(String::as_str) {
        Some("list") => {
            for e in c.list()? {
                println!("{} {} {}", hex::encode(e.client_id), e.valid_until, e.status);
            }
        }
        Some("add") => {
            let pk = parse_hex32(args.get(3), "pub (client_id, 64 hex)")?;
            // Без аргумента шлём 0 → срок назначает СЕРВЕР (+365d), как GUI-путь admin_issue.
            let vu = match args.get(4) {
                None => 0,
                Some(s) => parse_valid_until(Some(s))?,
            };
            c.add(pk, vu)?;
            eprintln!("[admin] add {} по каналу (срок: {})", hex::encode(pk),
                if vu == 0 { "серверный дефолт".into() } else { vu.to_string() });
        }
        Some("revoke") => {
            let pk = parse_hex32(args.get(3), "pub (client_id, 64 hex)")?;
            c.revoke(pk)?;
            eprintln!("[admin] revoke {} по каналу (действует ≤ длины эпохи)", hex::encode(pk));
        }
        _ => anyhow::bail!(
            "citadel-token admin <list|add <pub> [valid_until]|revoke <pub>>\n  \
             env: Citadel_ADMIN_ADDR, Citadel_ISSUER_PIN, Citadel_ADMIN_SEED.  \
             Операции идут по PQ-TLS admin-каналу (обычно — через туннель к ADMIN_VIP)."
        ),
    }
    Ok(())
}

/// Разобрать 32-байтный hex-аргумент (pub/seed) или дать понятную ошибку.
fn parse_hex32(arg: Option<&String>, what: &str) -> Result<[u8; 32]> {
    let s = arg.with_context(|| format!("нужен <{what}>"))?;
    hex::decode(s.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .with_context(|| format!("<{what}> должен быть ровно 32 байта hex"))
}

/// `valid_until`: абсолютные unix-секунды, либо относительно now — `+<N>d`/`+<N>h`/`+<секунды>`.
/// Пусто → now + 365 дней.
fn parse_valid_until(arg: Option<&str>) -> Result<u64> {
    let now = now_unix();
    let Some(s) = arg else {
        return Ok(now + 365 * 24 * 3600);
    };
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('+') {
        let (num, mult) = match rest.chars().last() {
            Some('d') => (&rest[..rest.len() - 1], 24 * 3600),
            Some('h') => (&rest[..rest.len() - 1], 3600),
            _ => (rest, 1),
        };
        let n: u64 = num.parse().context("valid_until: ожидалось +<N>d | +<N>h | +<секунды>")?;
        Ok(now + n * mult)
    } else {
        s.parse().context("valid_until: unix-секунды или относительное +<N>d")
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    // C5.5 admin-CLI управления реестром — оффлайн-операция админа (add/revoke/list), не сетевая
    // роль, поэтому маршрутизируем по arg[1] ДО env-роли (Citadel_TOKEN_ROLE её не задаёт).
    if args.get(1).map(String::as_str) == Some("registry") {
        return run_registry(&args);
    }
    // C7.5: сетевой admin-канал (list/add/revoke по туннелю) — тот же путь, что GUI.
    if args.get(1).map(String::as_str) == Some("admin") {
        return run_admin_channel(&args);
    }
    let role = std::env::var("Citadel_TOKEN_ROLE")
        .ok()
        .or_else(|| args.get(1).cloned())
        .unwrap_or_else(|| "batch".into());
    match role.as_str() {
        "issuer" | "serve" => run_issuer(),
        "client" | "fetch" => run_client_fetch(),
        "keysync" => run_keysync(),
        // M-6: `pubsync` тянул ПУБЛИЧНЫЙ ключ эпохи без аутентификации. Молча принять старое имя
        // значило бы оставить exit без ключа (или, хуже, с чужим) — отказ с объяснением честнее.
        "pubsync" => Err(anyhow::anyhow!(
            "роль `pubsync` заменена на `keysync`: ключ эпохи стал секретом (схема токенов v2, M-6). \
             Нужен Citadel_KEYSYNC_SEED, выданный установкой издателя (поле KEYSYNC_SEED в бандле)"
        )),
        "pubkey" => run_pubkey(),
        "batch" => run_batch(),
        other => Err(anyhow::anyhow!(
            "Citadel_TOKEN_ROLE должен быть issuer|client|keysync|pubkey|batch (или arg[1]=registry), а не {other:?}"
        )),
    }
}

/// C5.1: ключ издателя на ТЕКУЩУЮ эпоху (`(epoch, key)`) под Mutex — фоновая ротация меняет его
/// при смене эпохи. Токены epoch-scoped: exit примет их только ключом текущей±прошлой эпохи →
/// «гаснут» к концу эпохи (отзыв по времени, M6).
type EpochState = (u64, Arc<citadel_token::EpochKey>);

/// S2.4/A6: счётчик выданных токенов `client_id → (эпоха, число)` (анти-фарминг, per-epoch).
type QuotaMap = HashMap<[u8; 32], (u64, u32)>;

/// Задача 4 (вариант B — мягкий single-session): время, до которого client_id УЖЕ обслужен и не
/// получит новую выдачу (`client_id → expiry_unix`). Ограничивает открытие ПАРАЛЛЕЛЬНЫХ сессий с
/// одной ссылки, не ломая unlinkability (exit по-прежнему не знает client_id — контроль на issuer,
/// который видит его при Layer-1).
type LeaseMap = HashMap<[u8; 32], u64>;

/// Положить ключ эпохи (`issuer-<epoch>.key`) + `issuer.key` (= current) на общий том — оттуда его
/// читает exit, стоящий на ТОЙ ЖЕ машине.
///
/// **Права важнее, чем кажется (M-6).** В схеме v1 здесь лежал публичный RSA-ключ, и режим 0644 был
/// безобиден. В v2 это секрет эпохи: кто его прочитал — тот чеканит токены. Но и «просто 0600»
/// нельзя: exit сбрасывает привилегии до `nobody` (F4, `citadel-m1:drop_privileges`) и читает файл
/// уже под ними, поэтому файл, доступный только владельцу-издателю, оставил бы exit без ключа —
/// то есть без проверки токенов вообще.
///
/// Компромисс: `0640`, группа — `Citadel_KEY_GID` (по умолчанию 65534 = та, в которую садится
/// exit). Прочитать может издатель и exit, но не произвольный пользователь хоста. Если сменить
/// группу не удалось (издатель уже не root), остаётся `0600` и **громкое предупреждение** —
/// молчаливый откат к 0644 был бы худшим из вариантов.
///
/// Пишем во временный файл и переименовываем: между `write` и `set_permissions` иначе существует
/// окно, в котором секрет лежит с правами по umask, а exit читает каталог в цикле.
fn publish_epoch_key(dir: &str, epoch: u64, key: &[u8]) -> Result<()> {
    for name in [citadel_token::epoch_key_name(epoch), "issuer.key".into()] {
        let path = format!("{dir}/{name}");
        let tmp = format!("{path}.tmp");
        std::fs::write(&tmp, key).with_context(|| format!("публикация ключа эпохи {epoch}"))?;
        restrict_epoch_key(&tmp);
        std::fs::rename(&tmp, &path).with_context(|| format!("публикация ключа эпохи {epoch}"))?;
    }
    Ok(())
}

/// Права на файл ключа эпохи: `0640`, группа = `Citadel_KEY_GID` (см. [`publish_epoch_key`]).
///
/// Штатный путь — **издатель уже работает с нужной группой** (в compose это `user: "0:65534"`, та
/// же группа, в которую садится exit): тогда файл рождается с ней и менять владельца не нужно.
/// Это существенно: после M-4 у контейнера издателя `cap_drop: ALL`, то есть `CAP_CHOWN` у него
/// нет и `chown` заведомо не пройдёт. `chown` остаётся запасным путём для запуска вне докера.
fn restrict_epoch_key(path: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |m| std::fs::set_permissions(path, std::fs::Permissions::from_mode(m));
        let _ = mode(0o600);
        let gid: libc::gid_t =
            std::env::var("Citadel_KEY_GID").ok().and_then(|s| s.parse().ok()).unwrap_or(65534);
        // SAFETY: getegid без побочных эффектов.
        let own_gid = unsafe { libc::getegid() };
        let ok = own_gid == gid || {
            match std::ffi::CString::new(path) {
                // SAFETY: путь — валидная C-строка; uid -1 = «не менять владельца».
                Ok(c) => (unsafe { libc::chown(c.as_ptr(), u32::MAX, gid) }) == 0,
                Err(_) => false,
            }
        };
        if ok {
            let _ = mode(0o640);
        } else {
            static WARNED: AtomicBool = AtomicBool::new(false);
            if !WARNED.swap(true, Ordering::Relaxed) {
                eprintln!(
                    "[issuer] ВНИМАНИЕ: ключ эпохи остаётся 0600 — группа {gid} не выставлена \
                     (своя gid={own_gid}, chown: {}). exit на этой же машине его НЕ прочитает и \
                     будет отказывать всем токенам. Запустите издателя с этой группой \
                     (в compose: user: \"0:{gid}\") либо согласуйте Citadel_KEY_GID с \
                     Citadel_DROP_GID exit'а.",
                    std::io::Error::last_os_error()
                );
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Издатель (биллинг): держит ключ текущей эпохи, вычисляет вслепую по TCP; ротирует по эпохам.
fn run_issuer() -> Result<()> {
    // M-4: root издателю не нужен — роняем привилегии ДО создания файлов и открытия сокетов.
    // NB: при заданном `Citadel_DROP_UID` издатель теряет право сменить группу файла ключа эпохи —
    // см. предупреждение в `restrict_epoch_key`; в докере привилегии режет compose, а не setuid.
    drop_privileges()?;
    let epoch_secs: u64 =
        std::env::var("Citadel_EPOCH_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(3600);
    let dir = token_dir();
    bootstrap_registry(&dir)?; // C5.2: демо-регистрация абонентов из Citadel_REGISTER_SEEDS

    // S2.1/A1: постоянная TLS-идентичность издателя (pin кладётся в ссылку → клиент пиннит канал).
    let identity = citadel_token::pqtls::IssuerIdentity::load_or_generate(&dir)?;
    eprintln!(
        "[issuer] PQ-TLS канал: pin {} → {dir}/issuer-tls.pin (клиент пиннит, анти-MITM A1)",
        hex::encode(identity.pin)
    );
    let scfg = identity.server_config()?;
    let cert_pin = identity.pin;
    // PQ-аутентификация издателя: постоянная ML-DSA-65 идентичность (seed 600 на томе, обязательство
    // — в ссылку). Даёт то, чего pin дать не может: доказательство ВЛАДЕНИЯ ключом, устойчивое к
    // CRQC (приватный ключ Ed25519-серта тот восстановит из pub и пройдёт пиннинг «легально»).
    let pq = Arc::new(citadel_token::pqid::IssuerPqIdentity::load_or_generate(&dir)?);
    eprintln!(
        "[issuer] PQ-идентичность (ML-DSA-65): обязательство {} → {dir}/{} (кладётся в ссылку)",
        hex::encode(pq.commitment()),
        citadel_token::pqid::ISSUER_COMMITMENT_FILE
    );
    // S2.1/A1-остаток: obfs-обёртка issuer-канала (probe-resistance). При заданном PSK и token-, и
    // admin-канал молчат на не-obfs пробу и на проводе неотличимы от туннеля (тот же PSK из ссылки).
    let obfs_psk = obfs_psk_from_env();
    eprintln!(
        "[issuer] obfs-обёртка канала: {} (probe-resistance issuer-порта, A1-остаток)",
        if obfs_psk.is_some() { "включена" } else { "выкл (голый TLS)" }
    );

    // C7.1: admin-канал (управление реестром по PQ-TLS: domain-sep Ed25519 + EKM channel binding).
    // Отдельный listener — в деплое наружу НЕ публикуется (доступ только из туннеля через DNAT
    // exit'а, C7.2). TLS-идентичность общая с token-fetch → pin из ссылки валиден для обоих каналов.
    // L-14: список источников разбираем ДО потока — опечатка в адресе обязана уронить старт, а не
    // всплыть отказами admin-канала посреди работы.
    let admin_allow = PeerAllow::from_env("Citadel_ADMIN_PEER")?;
    if let Ok(admin_listen) = std::env::var("Citadel_ADMIN_LISTEN") {
        let scfg = scfg.clone();
        let dir = dir.clone();
        let pq = pq.clone();
        eprintln!("[issuer] admin-канал принимает: {}", admin_allow.describe());
        std::thread::spawn(move || {
            let listener = match TcpListener::bind(&admin_listen) {
                Ok(l) => l,
                Err(e) => return eprintln!("[issuer] admin-канал: bind {admin_listen}: {e}"),
            };
            eprintln!(
                "[issuer] admin-канал на {admin_listen} (PQ-TLS+pin, гибрид Ed25519+ML-DSA домен+EKM)"
            );
            // H-1: собственный гейт — флуд на :7000 не должен отбирать у админа возможность войти.
            let gate = Gate::new(MAX_PREAUTH_ADMIN, MAX_PREAUTH_ADMIN_PER_IP);
            accept_loop(listener, "admin-канал", gate, admin_allow, move |tcp, pass, ctl| {
                let srv = citadel_token::admin::AdminServer { dir: dir.clone() };
                let r = citadel_token::pqtls::accept_tls(tcp, scfg.clone(), obfs_psk).and_then(|tls| {
                    // Слот и жёсткий дедлайн снимаются РОВНО на границе аутентификации.
                    srv.serve_conn(tls, &pq, &cert_pin, move || {
                        ctl.authenticated();
                        drop(pass);
                    })
                });
                if let Err(e) = r {
                    citadel_token::dlog!("[issuer] admin-соединение завершено: {e}");
                }
            });
        });
    }

    let e = citadel_token::current_epoch(epoch_secs);
    let key = citadel_token::EpochKey::generate()?;
    publish_epoch_key(&dir, e, &key.secret_bytes())?;
    eprintln!(
        "[issuer] эпоха {e} (длина {epoch_secs}с): ключ сгенерирован и положен в {dir} (0640, секрет)"
    );
    let state: Arc<Mutex<EpochState>> = Arc::new(Mutex::new((e, Arc::new(key))));

    // Фоновая ротация: при смене эпохи генерим новый ключ и публикуем (прошлый ключ оставляем на
    // диске для grace на exit'е). В схеме v2 генерация — микросекунды (был RSA-keygen ~10 с), так
    // что отдельная забота «не держать лок во время keygen» больше не нужна.
    {
        let state = state.clone();
        let dir = dir.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs((epoch_secs / 4).clamp(5, 30)));
            let ce = citadel_token::current_epoch(epoch_secs);
            if ce == state.lock().unwrap().0 {
                continue;
            }
            eprintln!("[issuer] эпоха сменилась → {ce}; ротация ключа…");
            match citadel_token::EpochKey::generate() {
                Ok(nk) => {
                    if publish_epoch_key(&dir, ce, &nk.secret_bytes()).is_ok() {
                        *state.lock().unwrap() = (ce, Arc::new(nk));
                        eprintln!("[issuer] эпоха {ce}: ключ ротирован и опубликован");
                    }
                }
                Err(err) => eprintln!("[issuer] генерация ключа при ротации не удалась: {err}"),
            }
        });
    }

    // S2.4/A6: квота выданных токенов на client_id за эпоху (анти-фарминг). Env `Citadel_TOKEN_QUOTA`
    // (default 64 — с запасом на реконнекты нормального абонента, но режет массовую раздачу).
    let max_per_epoch: u32 =
        std::env::var("Citadel_TOKEN_QUOTA").ok().and_then(|s| s.parse().ok()).unwrap_or(64);
    let quota: Arc<Mutex<QuotaMap>> = Arc::new(Mutex::new(HashMap::new()));
    eprintln!("[issuer] квота выдачи: {max_per_epoch} токен(ов) на абонента в эпоху (A6)");

    // Задача 4 (вариант B): мягкий single-session — client_id получает новую выдачу не чаще раза в
    // `Citadel_TOKEN_LEASE_SECS` (0 = выкл). Ограничивает параллельные сессии с одной ссылки;
    // компромисс — реконнект в пределах окна ждёт истечения аренды (см. `lease_grant`).
    let lease_secs: u64 =
        std::env::var("Citadel_TOKEN_LEASE_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let lease: Arc<Mutex<LeaseMap>> = Arc::new(Mutex::new(HashMap::new()));
    eprintln!(
        "[issuer] single-session (задача 4/B): {}",
        if lease_secs == 0 { "выкл".into() } else { format!("аренда {lease_secs}с на абонента") }
    );

    let listen = std::env::var("Citadel_TOKEN_LISTEN").unwrap_or_else(|_| "0.0.0.0:7000".into());
    let listener = TcpListener::bind(&listen).with_context(|| format!("bind {listen}"))?;
    eprintln!(
        "[issuer] слепая выдача на {listen} (VOPRF ristretto255, epoch-scoped, PQ-TLS+pin, \
         гибридная PQ-аутентификация сторон)"
    );
    // M-6: keysync — раздача ключа эпохи exit-узлу на ДРУГОЙ машине. Ключ секретен, поэтому без
    // настроенного id канал закрыт (fail-closed): при раздельном деплое установщик кладёт сюда id,
    // при совмещённом — раздачи по сети просто нет, exit читает файл с тома.
    let keysync_id = parse_hex32(std::env::var("Citadel_KEYSYNC_ID").ok().as_ref(), "Citadel_KEYSYNC_ID").ok();
    eprintln!(
        "[issuer] keysync (ключ эпохи по сети для отдельного exit'а): {}",
        match &keysync_id {
            Some(id) => format!("для id {}…", &hex::encode(id)[..12]),
            None => "выкл (Citadel_KEYSYNC_ID не задан — совмещённый деплой)".into(),
        }
    );
    // H-1: гейт pre-auth соединений + таймауты/дедлайн хендшейка (см. модуль выше).
    let gate = Gate::new(MAX_PREAUTH, MAX_PREAUTH_PER_IP);
    eprintln!(
        "[issuer] гейт pre-auth: {MAX_PREAUTH} одновременных хендшейков ({MAX_PREAUTH_PER_IP} на адрес), \
         таймаут {}с, дедлайн {}с (H-1)",
        PREAUTH_TIMEOUT.as_secs(),
        PREAUTH_DEADLINE.as_secs()
    );
    accept_loop(listener, "выдача токенов", gate, PeerAllow::default(), move |stream, pass, ctl| {
        if let Err(e) = serve_client(
            stream, pass, ctl, scfg.clone(), &pq, &cert_pin, &state, &dir, &quota, max_per_epoch,
            &lease, lease_secs, obfs_psk, keysync_id.as_ref(),
        ) {
            citadel_token::dlog!("[issuer] соединение завершено: {e}");
        }
    });
    Ok(())
}

/// S2.4/A6: под локом решить, можно ли выдать ещё один токен `client_id` в `epoch` (инкрементит
/// счётчик). Смена эпохи сбрасывает счётчик. `false` → квота исчерпана. Чистая логика (тестируемо).
fn quota_grant(
    map: &mut QuotaMap,
    client_id: [u8; 32],
    epoch: u64,
    max: u32,
) -> bool {
    let e = map.entry(client_id).or_insert((epoch, 0));
    if e.0 != epoch {
        *e = (epoch, 0); // новая эпоха → сброс
    }
    if e.1 >= max {
        return false;
    }
    e.1 += 1;
    true
}

/// Задача 4 (вариант B): под локом решить, можно ли НАЧАТЬ новую выдачу `client_id` (одна ссылка →
/// одна свежая сессия в окне `lease_secs`). `lease_secs == 0` → механизм выключен (всегда `true`).
/// Иначе: если предыдущая выдача ещё «активна» (`now < expiry`) → `false` (второе устройство / слишком
/// частый реконнект отклоняются); иначе ставим новую аренду `now + lease_secs` и разрешаем. Чистая
/// логика (тестируемо). NB: уже поднятая QUIC-сессия живёт независимо — это МЯГКИЙ контроль (лимит
/// на открытие новых параллельных сессий), не жёсткий kill уже активной (тот требует exit-tracking
/// → слом unlinkability, отвергнут в пользу B).
fn lease_grant(map: &mut LeaseMap, client_id: [u8; 32], now: u64, lease_secs: u64) -> bool {
    if lease_secs == 0 {
        return true;
    }
    match map.get(&client_id) {
        Some(&expiry) if now < expiry => false, // аренда ещё активна — новую сессию не открываем
        _ => {
            map.insert(client_id, now + lease_secs);
            true
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn serve_client(
    tcp: TcpStream,
    // H-1: слот pre-auth и пульт сокета. Слот освобождается, а таймауты ослабляются РОВНО после
    // того, как абонент доказал право на выдачу (подпись + активная запись реестра) — до этого
    // соединение остаётся под жёстким дедлайном и занимает место в потолке.
    pass: Pass,
    ctl: SockCtl,
    scfg: Arc<rustls::ServerConfig>,
    pq: &citadel_token::pqid::IssuerPqIdentity,
    cert_pin: &[u8; 32],
    state: &Mutex<EpochState>,
    dir: &str,
    quota: &Mutex<QuotaMap>,
    max_per_epoch: u32,
    lease: &Mutex<LeaseMap>,
    lease_secs: u64,
    obfs_psk: Option<[u8; 32]>,
    keysync_id: Option<&[u8; 32]>,
) -> Result<()> {
    let peer = tcp.peer_addr().ok();
    // S2.1/A1: поднять PQ-TLS поверх TCP ДО любого обмена — Layer-1 и слепая выдача идут в шифре
    // с целостностью; клиент уже спиннил серт (MITM не подставит свои blind_msg, client_id скрыт).
    let mut conn = citadel_token::pqtls::accept_tls(tcp, scfg, obfs_psk)?;
    // PQ-аутентификация: экспортер этой сессии нужен ОБЕИМ сторонам как channel binding, поэтому
    // хендшейк доводится явно, до первого прикладного кадра.
    let ekm = citadel_token::pqtls::handshake_server(&mut conn)?;
    // Издатель представляется ПЕРВЫМ: ML-DSA-подпись `домен‖челлендж‖cert_pin‖EKM`. Иначе клиент
    // отдавал бы `client_id` стороне, подлинность которой держится на одном лишь Ed25519-серте
    // (его квантовый противник восстанавливает из pub и проходит pin) — то есть деанон подписки.
    let challenge: [u8; 32] = rand::random();
    write_frame(&mut conn, &pq.hello(&challenge, cert_pin, &ekm)?)?;
    // Первый кадр клиента типизирован: абонент аутентифицируется, exit-узел просит ключ эпохи.
    let frame = read_frame(&mut conn)?;
    let auth = match citadel_token::pqid::parse_client_frame(&frame)? {
        citadel_token::pqid::ClientFrame::KeySync(auth) => {
            // Раздельный деплой (P1): exit на другой машине подтягивает ключ эпохи — общего тома
            // /shared у него нет. M-6: ключ СЕКРЕТЕН, поэтому здесь полноценная аутентификация, а
            // не «раз дошёл — держи»: доказательство владения keysync-seed'ом в своём домене плюс
            // сверка id с настроенным. Не настроен id — канал закрыт (fail-closed).
            let Some(expect) = keysync_id else {
                anyhow::bail!("keysync запрошен, но Citadel_KEYSYNC_ID не настроен — отказ");
            };
            let id = citadel_token::pqid::verify_hybrid(
                auth,
                citadel_token::pqid::DOMAIN_KEYSYNC,
                &challenge,
                &ekm,
            )
            .context("keysync: аутентификация exit-узла")?;
            if &id != expect {
                anyhow::bail!("keysync: чужая идентичность — отказ");
            }
            ctl.authenticated();
            drop(pass);
            let cur = state.lock().unwrap().1.clone();
            write_frame(&mut conn, &cur.secret_bytes())?;
            citadel_token::dlog!("[issuer] отдан ключ эпохи (keysync exit-узла)");
            return Ok(());
        }
        citadel_token::pqid::ClientFrame::Auth(a) => a,
    };
    let client_id = citadel_token::pqid::verify_hybrid(
        auth,
        citadel_token::pqid::DOMAIN_CLIENT,
        &challenge,
        &ekm,
    )
    .context("Layer-1: аутентификация абонента")?;
    if !registry_allows(dir, &client_id, now_unix()) {
        anyhow::bail!("Layer-1: client_id не активен/истёк/отозван — отказ");
    }
    // H-1: право на выдачу доказано (подпись сошлась И запись реестра активна) — освобождаем слот
    // pre-auth и снимаем жёсткий дедлайн. Отозванный абонент с валидной подписью слот НЕ удерживает:
    // проверка реестра идёт раньше этой строки.
    ctl.authenticated();
    drop(pass);
    // no-logs: связка client_id↔время — только при явном Citadel_DEBUG_LOG (см. citadel_token::debug_logs)
    citadel_token::dlog!("[issuer] Layer-1 ✔ абонент {}… авторизован", &hex::encode(client_id)[..12]);
    // Задача 4/B (мягкий single-session): аренда client_id ещё активна → отклоняем новую выдачу
    // (второе устройство с той же ссылки / слишком частый реконнект). Клиент получит 0 токенов →
    // establish без токена → exit откажет → клиент подождёт истечения аренды и переподключится.
    // Закрываем соединение ДО отправки epoch-pub (ничего лишнего не раскрываем).
    if !lease_grant(&mut lease.lock().unwrap(), client_id, now_unix(), lease_secs) {
        citadel_token::dlog!(
            "[issuer] single-session (4/B): {}… держит активную аренду — новая сессия отклонена",
            &hex::encode(client_id)[..12]
        );
        return Ok(());
    }
    // C5.3: отдаём клиенту публичный элемент K ТЕКУЩЕЙ эпохи — под ним он проверит DLEQ каждой
    // выдачи (и заметит, если издатель применит не тот ключ).
    let cur = state.lock().unwrap().1.clone();
    write_frame(&mut conn, &cur.public_bytes())?;

    let mut n = 0u32;
    // клиент закрыл соединение → read_frame вернёт Err → выходим из цикла
    while let Ok(blinded) = read_frame(&mut conn) {
        // S2.4/A6: квота токенов на client_id за эпоху. Без неё один «абонемент» чеканил бы
        // неограниченно токенов → раздача безлимиту фрирайдеров за эпоху (epoch+double-spend
        // режут повтор ОДНОГО токена, но не число разных). Счётчик per-(client_id, эпоха),
        // сбрасывается со сменой эпохи. In-RAM (как spent-set exit'а): рестарт обнуляет, но
        // квота epoch-bounded. Достигнут потолок → прекращаем выдачу этому клиенту в эту эпоху.
        let (cur_epoch, key) = {
            let s = state.lock().unwrap();
            (s.0, s.1.clone())
        };
        if !quota_grant(&mut quota.lock().unwrap(), client_id, cur_epoch, max_per_epoch) {
            citadel_token::dlog!(
                "[issuer] квота исчерпана: {}… уже получил {max_per_epoch} токен(ов) в эпоху {cur_epoch} — стоп",
                &hex::encode(client_id)[..12]
            );
            break;
        }
        // Слепое вычисление под ключом ТЕКУЩЕЙ эпохи + DLEQ. Ключ мог смениться между выдачами
        // (ротация в фоне) — тогда клиент получит элемент под новым K и, не сойдясь с прежним,
        // явно откажется; это лучше, чем молча выданный токен, который exit не примет.
        let (evaluated, proof) = key.evaluate(&blinded)?;
        write_frame(&mut conn, &[evaluated, proof].concat())?;
        n += 1;
    }
    citadel_token::dlog!("[issuer] клиент {peer:?}: выдано вслепую {n} токен(ов)");
    Ok(())
}

/// Клиент: интерактивно получает N токенов от издателя (blind→sign→finalize), пишет в файл.
fn run_client_fetch() -> Result<()> {
    let issuer = std::env::var("Citadel_TOKEN_ISSUER").context("Citadel_TOKEN_ISSUER не задан")?;
    // C5.2 Layer-1: seed «абонента» (= приватный Ed25519) — обязателен для авторизации у issuer.
    let seed: [u8; 32] = std::env::var("Citadel_CLIENT_SEED")
        .ok()
        .and_then(|s| hex::decode(s.trim()).ok())
        .and_then(|v| v.try_into().ok())
        .context("Citadel_CLIENT_SEED (32 байта hex) обязателен для Layer-1")?;
    guard_weak_seed("Citadel_CLIENT_SEED", &seed)?; // L-10
    // S2.1/A1: pin TLS-серта издателя — обязателен (fail-closed: без него канал был бы MITM-открыт).
    let issuer_pin: [u8; 32] = std::env::var("Citadel_ISSUER_PIN")
        .ok()
        .and_then(|s| hex::decode(s.trim()).ok())
        .and_then(|v| v.try_into().ok())
        .context("Citadel_ISSUER_PIN (32 байта hex) обязателен для PQ-TLS канала к издателю")?;
    // PQ-аутентификация издателя: обязательство ML-DSA из ссылки — обязательно (fail-closed: без
    // него канал защищён лишь классической подписью серта, а её квантовый противник обходит).
    let issuer_mldsa: [u8; 32] = std::env::var("Citadel_ISSUER_MLDSA")
        .ok()
        .and_then(|s| hex::decode(s.trim()).ok())
        .and_then(|v| v.try_into().ok())
        .context("Citadel_ISSUER_MLDSA (32 байта hex) обязателен: PQ-обязательство издателя")?;
    let count = token_count();
    let dir = token_dir();
    // S2.1/A1-остаток: obfs-обёртка канала (probe-resistance) — PSK из env, обязан совпасть с issuer.
    let obfs_psk = obfs_psk_from_env();
    eprintln!("[client] Layer-1 issuance у издателя {issuer} ({count} токенов, PQ-TLS+pin{}, VOPRF epoch-scoped)…",
        if obfs_psk.is_some() { "+obfs" } else { "" });
    // C5.3: весь протокол (Layer-1 auth + получение K текущей эпохи + слепая выдача) — в citadel_token.
    let tokens =
        citadel_token::fetch_tokens(&issuer, &issuer_pin, &issuer_mldsa, &seed, count, 20, obfs_psk)?;

    let mut f = std::fs::File::create(format!("{dir}/tokens")).context("запись tokens")?;
    for t in &tokens {
        writeln!(f, "{}", hex::encode(t))?;
    }
    eprintln!("[client] получено {} токенов → {dir}/tokens (издатель их НЕ видел → unlinkable)", tokens.len());
    Ok(())
}

/// C5.4: печатает Ed25519 pub (hex) для `Citadel_CLIENT_SEED` — для добавления в реестр issuer'а
/// (admin, C5.5) или e2e-тестов отзыва. pub = client_id «абонента».
fn run_pubkey() -> Result<()> {
    let seed: [u8; 32] = std::env::var("Citadel_CLIENT_SEED")
        .ok()
        .and_then(|s| hex::decode(s.trim()).ok())
        .and_then(|v| v.try_into().ok())
        .context("Citadel_CLIENT_SEED (32 байта hex)")?;
    println!("{}", hex::encode(citadel_token::pqid::id_from_seed(&seed)?));
    Ok(())
}

/// **keysync** — синхронизация ключа эпохи для exit-узла на ОТДЕЛЬНОЙ машине (P1). Бывший
/// `pubsync`; переименован вместе со сменой схемы токенов (M-6), потому что синхронизируется теперь
/// **секрет**, а не публичный ключ.
///
/// Когда exit и издатель стоят на одном сервере, exit читает `issuer-<epoch>.key` с общего тома.
/// При раздельном деплое общего тома нет, а ключ ротируется каждую эпоху — этот режим и закрывает
/// разрыв: раз в интервал подтягивает текущий ключ у издателя (obfs + PQ-TLS с пиннингом +
/// проверка ML-DSA-идентичности издателя + **своя** keysync-идентичность) и кладёт его туда,
/// откуда exit читает.
///
/// Живёт рядом с exit'ом (отдельный контейнер того же compose), а не внутри exit-процесса: у того
/// сброшены привилегии и он намеренно ничего не тянет из сети сам.
///
/// Env: `Citadel_TOKEN_ISSUER` (host:port), `Citadel_ISSUER_PIN`, `Citadel_ISSUER_MLDSA`,
///      `Citadel_KEYSYNC_SEED` (32 Б hex — выдаёт установка издателя), `Citadel_TOKEN_DIR`,
///      `Citadel_EPOCH_SECS` (та же длина эпохи, что у издателя), `Citadel_OBFS_PSK`,
///      `Citadel_KEYSYNC_INTERVAL` (сек; по умолчанию — восьмая часть эпохи, но не реже минуты и
///      не чаще раза в 15 с).
fn run_keysync() -> Result<()> {
    let issuer = std::env::var("Citadel_TOKEN_ISSUER").context("Citadel_TOKEN_ISSUER не задан")?;
    let issuer_pin = parse_hex32(
        std::env::var("Citadel_ISSUER_PIN").ok().as_ref(),
        "Citadel_ISSUER_PIN (TLS-pin издателя, 64 hex)",
    )?;
    let issuer_mldsa = parse_hex32(
        std::env::var("Citadel_ISSUER_MLDSA").ok().as_ref(),
        "Citadel_ISSUER_MLDSA (обязательство PQ-идентичности издателя, 64 hex)",
    )?;
    let keysync_seed = parse_hex32(
        std::env::var("Citadel_KEYSYNC_SEED").ok().as_ref(),
        "Citadel_KEYSYNC_SEED (идентичность exit-узла для получения ключа эпохи, 64 hex)",
    )?;
    guard_weak_seed("Citadel_KEYSYNC_SEED", &keysync_seed)?; // L-10
    let dir = token_dir();
    let epoch_secs: u64 =
        std::env::var("Citadel_EPOCH_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(3600);
    let interval = std::env::var("Citadel_KEYSYNC_INTERVAL")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or_else(|| (epoch_secs / 8).clamp(15, 60));
    let obfs_psk = obfs_psk_from_env();
    eprintln!(
        "[keysync] издатель {issuer}, каталог {dir}, эпоха {epoch_secs}с, опрос раз в {interval}с{}",
        if obfs_psk.is_some() { " (obfs)" } else { "" }
    );

    let mut last: Option<u64> = None;
    loop {
        let epoch = citadel_token::current_epoch(epoch_secs);
        // Уже есть ключ ЭТОЙ эпохи — не дёргаем издателя лишний раз (сеть + его accept-петля).
        if last != Some(epoch) {
            match citadel_token::fetch_epoch_key(
                &issuer,
                &issuer_pin,
                &issuer_mldsa,
                &keysync_seed,
                3,
                obfs_psk,
            ) {
                Ok(key) => {
                    if let Err(e) = publish_epoch_key(&dir, epoch, &key) {
                        eprintln!("[keysync] ключ эпохи {epoch} получен, но не записан: {e:#}");
                    } else {
                        // no-logs и гигиена секрета: длину ключа не печатаем, сам ключ — тем более.
                        eprintln!("[keysync] ключ эпохи {epoch} обновлён");
                        last = Some(epoch);
                    }
                }
                // Издатель недоступен — не фатально: exit продолжает работать на ключе прошлой
                // эпохи (grace current±prev), а мы повторим через интервал. Валиться нельзя:
                // рестарт-петля контейнера ничего не чинит, а логи забивает.
                Err(e) => eprintln!("[keysync] не удалось получить ключ эпохи {epoch}: {e:#}"),
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(interval.max(5)));
    }
}

/// Legacy: выпуск пачки токенов в одном процессе → файлы (локальное демо/тесты, без сети).
///
/// **Токены здесь не привязаны к сессии** (контекст предъявления известен только в момент
/// подключения), поэтому файл содержит `nonce‖y` — материал, из которого клиент считает
/// предъявление сам. Режим офлайновый и остаётся демонстрационным.
fn run_batch() -> Result<()> {
    let count = token_count();
    let dir = token_dir();
    eprintln!("[issuer:batch] выпускаю {count} токенов (VOPRF ristretto255) → {dir}");
    let issued = citadel_token::issue_batch(count)?;
    let key_path = format!("{dir}/issuer.key");
    std::fs::write(&key_path, &issued.epoch_key).context("запись issuer.key")?;
    restrict_epoch_key(&key_path);
    let mut f = std::fs::File::create(format!("{dir}/tokens")).context("запись tokens")?;
    for t in &issued.tokens {
        writeln!(f, "{}", hex::encode(t))?;
    }
    eprintln!("[issuer:batch] готово: issuer.key + {} токенов", issued.tokens.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::merge_registry;

    /// C5.4b: bootstrap НЕ воскрешает отозванного абонента при рестарте (сохраняет `revoked`),
    /// новый pub добавляется как `active`, дубликатов нет.
    #[test]
    fn merge_preserves_revoked_and_adds_new() {
        let pk_a = [0xAAu8; 32];
        let pk_b = [0xBBu8; 32];
        let hex_a = hex::encode(pk_a);
        let hex_b = hex::encode(pk_b);
        // Реестр после admin-revoke абонента A.
        let existing = format!("{hex_a} 9999999999 revoked\n");
        // Рестарт: bootstrap снова несёт A (уже отозванного) и нового B.
        let merged = merge_registry(&existing, &[pk_a, pk_b], 8888888888);
        assert!(merged.contains(&format!("{hex_a} 9999999999 revoked")), "A остаётся revoked");
        assert_eq!(merged.matches(&hex_a).count(), 1, "A не продублирован (не воскрешён active)");
        assert!(merged.contains(&format!("{hex_b} 8888888888 active")), "B добавлен active");
    }

    /// Повторный bootstrap тех же pub'ов идемпотентен (вывод не растёт/не меняется).
    #[test]
    fn merge_is_idempotent() {
        let pk = [0x11u8; 32];
        let first = merge_registry("", &[pk], 100);
        let second = merge_registry(&first, &[pk], 200);
        assert_eq!(first, second);
    }

    // ── C5.5 admin-CLI реестра: тесты registry_apply_* переехали в citadel_token::admin (C7.1) ──

    /// S2.4/A6: квота на client_id за эпоху — до потолка выдаём, дальше отказ; смена эпохи сбрасывает;
    /// разные client_id учитываются раздельно.
    #[test]
    fn quota_grant_caps_per_epoch() {
        use super::quota_grant;
        let mut m = std::collections::HashMap::new();
        let a = [0xAAu8; 32];
        let b = [0xBBu8; 32];
        // до потолка (3) — выдаём
        assert!(quota_grant(&mut m, a, 100, 3));
        assert!(quota_grant(&mut m, a, 100, 3));
        assert!(quota_grant(&mut m, a, 100, 3));
        // потолок достигнут — отказ
        assert!(!quota_grant(&mut m, a, 100, 3));
        // другой абонент — свой счётчик
        assert!(quota_grant(&mut m, b, 100, 3));
        // смена эпохи сбрасывает счётчик a
        assert!(quota_grant(&mut m, a, 101, 3));
        assert!(quota_grant(&mut m, a, 101, 3));
    }

    /// L-10: seed из повторяющегося шаблона (ровно такие стоят в демо-entrypoint'ах) — отказ
    /// старта, если стенд не помечен стендом. Настоящий случайный seed проходит всегда.
    #[test]
    fn weak_seed_is_rejected_outside_demo_stand() {
        use super::guard_weak_seed;
        // SAFETY (тест): своя переменная, снимается сразу.
        std::env::remove_var("Citadel_DEMO_STAND");
        for pat in [[0xc5u8; 32], [0u8; 32], [0xffu8; 32]] {
            assert!(guard_weak_seed("тест", &pat).is_err(), "{}", hex::encode(&pat[..4]));
        }
        // повтор 2- и 4-байтного шаблона тоже не секрет
        let mut p2 = [0u8; 32];
        for (i, b) in p2.iter_mut().enumerate() {
            *b = if i % 2 == 0 { 0xab } else { 0xcd };
        }
        assert!(guard_weak_seed("тест", &p2).is_err());
        // настоящий seed (32 разных байта) проходит
        let real: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
        assert!(guard_weak_seed("тест", &real).is_ok());
        // на помеченном стенде демо-значения разрешены
        std::env::set_var("Citadel_DEMO_STAND", "1");
        assert!(guard_weak_seed("тест", &[0xc5u8; 32]).is_ok());
        std::env::remove_var("Citadel_DEMO_STAND");
    }

    /// L-14: allowlist admin-канала. Ключевое — «не задано» и «задано неверно» это РАЗНЫЕ исходы:
    /// первое штатно (совмещённый деплой, порт наружу не смотрит), второе обязано ронять старт,
    /// иначе опечатка в адресе тихо превращается в «пускаем всех».
    #[test]
    fn admin_peer_allowlist() {
        use super::PeerAllow;
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();

        // SAFETY (тест): своя переменная, снимается в конце.
        std::env::remove_var("Citadel_TEST_PEER");
        let any = PeerAllow::from_env("Citadel_TEST_PEER").unwrap();
        assert!(any.permits(ip("203.0.113.9")), "не задано — ограничения нет");

        std::env::set_var("Citadel_TEST_PEER", "any");
        assert!(PeerAllow::from_env("Citadel_TEST_PEER").unwrap().permits(ip("203.0.113.9")));

        std::env::set_var("Citadel_TEST_PEER", "203.0.113.7, 2001:db8::1");
        let a = PeerAllow::from_env("Citadel_TEST_PEER").unwrap();
        assert!(a.permits(ip("203.0.113.7")));
        assert!(a.permits(ip("2001:db8::1")));
        assert!(!a.permits(ip("203.0.113.8")), "посторонний адрес обязан отбиваться");
        assert!(!a.permits(ip("127.0.0.1")));

        std::env::set_var("Citadel_TEST_PEER", "203.0.113.7, не-адрес");
        assert!(PeerAllow::from_env("Citadel_TEST_PEER").is_err(), "мусор в списке = отказ старта");
        std::env::remove_var("Citadel_TEST_PEER");
    }

    /// Задача 4/B: аренда client_id блокирует новую выдачу в окне; истекла → снова разрешена;
    /// `lease_secs == 0` — механизм выключен (всегда разрешает).
    #[test]
    fn lease_grant_single_session_window() {
        use super::lease_grant;
        let mut m = std::collections::HashMap::new();
        let a = [0xAAu8; 32];
        let b = [0xBBu8; 32];
        // первая выдача в now=1000, аренда 300с (до 1300)
        assert!(lease_grant(&mut m, a, 1000, 300));
        // повторная попытка в окне (now=1100 < 1300) — отказ (второе устройство/частый реконнект)
        assert!(!lease_grant(&mut m, a, 1100, 300));
        assert!(!lease_grant(&mut m, a, 1299, 300));
        // другой абонент — своя аренда, не задет
        assert!(lease_grant(&mut m, b, 1100, 300));
        // аренда истекла (now=1300 >= expiry) — снова разрешено (реконнект после окна)
        assert!(lease_grant(&mut m, a, 1300, 300));
        // выключено (lease_secs=0) — всегда true, карта не растёт
        let mut off = std::collections::HashMap::new();
        assert!(lease_grant(&mut off, a, 1, 0));
        assert!(lease_grant(&mut off, a, 1, 0));
        assert!(off.is_empty());
    }

    // ───────────────── H-1 (аудит-4): гейт pre-auth соединений издателя ─────────────────

    fn ip(n: u8) -> std::net::IpAddr {
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, n))
    }

    /// Общий потолок: сверх него слот не выдаётся, а освобождение (дроп) возвращает место.
    /// Это и есть замена «поток на каждый accept без единого таймаута».
    #[test]
    fn gate_caps_total_and_releases_on_drop() {
        use super::Gate;
        let g = Gate::new(3, 3);
        let a = g.admit(ip(1)).expect("слот 1");
        let b = g.admit(ip(2)).expect("слот 2");
        let c = g.admit(ip(3)).expect("слот 3");
        assert!(g.admit(ip(4)).is_none(), "сверх потолка слот выдаваться не должен");
        drop(b);
        assert!(g.admit(ip(4)).is_some(), "освободившееся место переиспользуется");
        drop(a);
        drop(c);
    }

    /// Потолок НА АДРЕС: без него один источник забирает весь общий лимит, и легитимные клиенты
    /// не проходят — глобальный счётчик от этого не спасает.
    #[test]
    fn gate_caps_per_ip_so_one_source_cannot_starve_others() {
        use super::Gate;
        let g = Gate::new(100, 2);
        let _a = g.admit(ip(1)).expect("первый от адреса");
        let b = g.admit(ip(1)).expect("второй от адреса");
        assert!(g.admit(ip(1)).is_none(), "третий с того же адреса — отказ");
        // другой адрес при этом не задет (иначе флудер отключал бы всех)
        assert!(g.admit(ip(2)).is_some(), "чужой адрес не должен страдать от флуда соседа");
        drop(b);
        assert!(g.admit(ip(1)).is_some(), "освобождённый слот адреса снова доступен");
    }

    /// Карта адресов не растёт: запись убирается, когда её счётчик обнуляется (иначе долгий
    /// прогон с меняющихся адресов сам стал бы утечкой памяти).
    #[test]
    fn gate_forgets_addresses_with_no_slots() {
        use super::Gate;
        let g = Gate::new(8, 4);
        for n in 0..200u8 {
            let p = g.admit(ip(n)).expect("слот");
            drop(p);
        }
        let st = g.state.lock().unwrap();
        assert_eq!(st.total, 0, "все слоты освобождены");
        assert!(st.per_ip.is_empty(), "пустые записи адресов не копятся: {}", st.per_ip.len());
    }

    /// Дедлайн pre-auth строго больше таймаута одной операции: иначе сторож рвал бы соединение
    /// раньше, чем сокет успел бы честно отдать таймаут по чтению.
    #[test]
    fn preauth_deadline_exceeds_socket_timeout() {
        assert!(super::PREAUTH_DEADLINE > super::PREAUTH_TIMEOUT);
        assert!(super::SESSION_TIMEOUT > super::PREAUTH_DEADLINE, "сессия живёт дольше хендшейка");
    }

    /// valid_until: относительные формы и абсолют.
    #[test]
    fn valid_until_forms() {
        let now = super::now_unix();
        assert_eq!(super::parse_valid_until(Some("1700000000")).unwrap(), 1_700_000_000);
        let d = super::parse_valid_until(Some("+2d")).unwrap();
        assert!((d as i64 - (now as i64 + 2 * 24 * 3600)).abs() <= 2);
        let h = super::parse_valid_until(Some("+3h")).unwrap();
        assert!((h as i64 - (now as i64 + 3 * 3600)).abs() <= 2);
        let def = super::parse_valid_until(None).unwrap();
        assert!((def as i64 - (now as i64 + 365 * 24 * 3600)).abs() <= 2);
        assert!(super::parse_valid_until(Some("+bad")).is_err());
    }
}
