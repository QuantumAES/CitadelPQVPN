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
//! CLI-подкоманды (arg[1], вне env-роли): `registry` — провижининг Layer-1 реестра на сервере
//! (C5.5), ТОЛЬКО `add`/`add-seed`: отзыв и список с сервера убраны (см. [`run_registry`]);
//! `admin` — управление ПО СЕТЕВОМУ admin-каналу (PQ-TLS+pin, домен+EKM; C7.5) — путь GUI,
//! обычно через туннель к ADMIN_VIP, требует admin-seed из мастер-ссылки.
//!
//! Сетевой формат: кадр `u32(len, BE) ‖ payload`; запрос — ослеплённый элемент (32 Б), ответ —
//! `evaluated(32) ‖ DLEQ(64)`.

use std::collections::{HashMap, VecDeque};
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
    /// G3 (аудит-5): живые pre-auth соединения в порядке появления (front — самое старое).
    /// Нужен, чтобы при заполнении гейта вытеснять старое, а не отказывать новому (см. [`Gate`]).
    live: VecDeque<Live>,
    next_id: u64,
}

/// Занятый слот с точки зрения гейта: чем его закрыть и кому он принадлежит.
struct Live {
    id: u64,
    ip: IpAddr,
    /// Дублированный дескриптор соединения — `shutdown` по нему выводит рабочий поток из
    /// блокирующего чтения. `None` только в тестах учёта (такую запись гейт вытеснять не станет).
    sock: Option<TcpStream>,
}

impl GateState {
    /// Вытеснить самое старое соединение (при `only_ip` — самое старое С ЭТОГО адреса) и
    /// освободить его слот. Записи без дескриптора пропускаем: закрыть их нечем, а снять с учёта,
    /// не закрыв, значило бы пустить сверх потолка. `false` — вытеснять нечего.
    fn evict_oldest(&mut self, only_ip: Option<IpAddr>) -> bool {
        let Some(pos) = self.live.iter().position(|l| {
            l.sock.is_some() && only_ip.is_none_or(|ip| l.ip == ip)
        }) else {
            return false;
        };
        let victim = self.live.remove(pos).expect("позиция получена из этого же дека");
        self.forget(victim.ip);
        if let Some(s) = victim.sock {
            // Рабочий поток жертвы сидит в blocking-read внутри TLS/obfs — он выйдет по ошибке
            // и дропнет свой Pass; release по id уже ничего не найдёт (двойного учёта нет).
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
        true
    }

    /// Снять один слот с учёта (общий счётчик + per-ip, с уборкой пустых записей).
    fn forget(&mut self, ip: IpAddr) {
        self.total = self.total.saturating_sub(1);
        if let Some(n) = self.per_ip.get_mut(&ip) {
            *n -= 1;
            if *n == 0 {
                self.per_ip.remove(&ip); // пустые записи не копим
            }
        }
    }
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
    id: u64,
}

impl Drop for Pass {
    fn drop(&mut self) {
        self.gate.release(self.id, self.ip);
    }
}

impl Gate {
    fn new(max_total: usize, max_per_ip: usize) -> Self {
        Self { state: Arc::new(Mutex::new(GateState::default())), max_total, max_per_ip }
    }

    /// Взять слот под pre-auth фазу, при заполнении — **вытеснив самое старое** соединение.
    ///
    /// G3 (аудит-5). Отказывать новому нельзя: за exit'ом весь туннельный трафик приходит с ОДНОГО
    /// адреса (MASQUERADE), поэтому счётчик «на адрес» у admin-канала общий для всех абонентов И
    /// для самого админа. Четыре молчащих соединения абонента (переоткрываемых по истечении
    /// `PREAUTH_DEADLINE`) намертво запирали админа снаружи реестра — при исправном сервере и без
    /// единой ошибки аутентификации.
    ///
    /// Вытеснение переворачивает исход: честный хендшейк укладывается в миллисекунды и уходит из
    /// очереди сам (слот освобождается на границе auth), а паразитное соединение как раз ВИСИТ —
    /// то есть всегда оказывается ближе к голове очереди. Новоприбывший встаёт в хвост, и чтобы его
    /// вытеснить, атакующему нужно занять весь потолок ЗАНОВО, потратив на каждое соединение по
    /// RTT. Ценой становится редкий разрыв чужого недоделанного хендшейка под предельной нагрузкой
    /// — на порядок меньшее зло, чем гарантированная потеря управления.
    ///
    /// `sock` — дублированный дескриптор (по нему закрывается вытесняемое соединение). `None`
    /// допустим только в тестах учёта: такую запись гейт не вытесняет, она лишь занимает слот.
    /// `None` в ответе — вытеснять было нечего (все слоты заняты незакрываемыми записями).
    fn admit(&self, ip: IpAddr, sock: Option<TcpStream>) -> Option<Pass> {
        let mut st = self.state.lock().unwrap();
        // Сначала потолок адреса: жертву ищем среди соединений ЭТОГО адреса, чтобы флудер не
        // выбивал чужие соединения, уперевшись в свой персональный лимит.
        if st.per_ip.get(&ip).copied().unwrap_or(0) >= self.max_per_ip && !st.evict_oldest(Some(ip))
        {
            return None;
        }
        if st.total >= self.max_total && !st.evict_oldest(None) {
            return None;
        }
        st.next_id += 1;
        let id = st.next_id;
        *st.per_ip.entry(ip).or_insert(0) += 1;
        st.total += 1;
        st.live.push_back(Live { id, ip, sock });
        Some(Pass { gate: self.clone(), ip, id })
    }

    /// Освободить слот по завершении обслуживания. Если соединение уже вытеснено (`id` из очереди
    /// пропал), счётчики не трогаем — их уменьшил тот, кто вытеснял.
    fn release(&self, id: u64, ip: IpAddr) {
        let mut st = self.state.lock().unwrap();
        if let Some(pos) = st.live.iter().position(|l| l.id == id) {
            st.live.remove(pos);
            st.forget(ip);
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
        // G3: гейт вытесняет самое старое pre-auth соединение вместо отказа новому (см. `admit`).
        // Отказ остаётся лишь на вырожденный случай «вытеснять нечем» (нет дублей дескрипторов).
        let Some(pass) = gate.admit(ip, tcp.try_clone().ok()) else {
            drop(tcp);
            rejected += 1;
            if last_log.elapsed() >= Duration::from_secs(1) {
                eprintln!(
                    "[issuer] {what}: лимит одновременных pre-auth соединений \
                     ({} всего / {} на адрес) и вытеснять нечего — отклонено {rejected} за секунду (H-1/G3)",
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
/// M-9: что делать с записью реестра этого абонента. Отдельно от [`registry_allows`], потому что
/// решений стало три (пустить / потребовать активацию / отказать с причиной), а не два.
fn registry_gate(dir: &str, client_id: &[u8; 32], now: u64) -> citadel_token::Gate {
    use citadel_token::admin::{STATUS_ACTIVE, STATUS_CONSUMED};
    use citadel_token::{Gate, REFUSE_CONSUMED, REFUSE_EXPIRED, REFUSE_INACTIVE};
    let Ok(content) = std::fs::read_to_string(registry_path(dir)) else {
        return Gate::Refuse(REFUSE_INACTIVE); // нет реестра → никто не авторизован (secure default)
    };
    let entries = citadel_token::admin::parse_registry(&content);
    let Some(e) = entries.iter().find(|e| &e.client_id == client_id) else {
        return Gate::Refuse(REFUSE_INACTIVE);
    };
    if e.status == STATUS_CONSUMED || (e.device.is_some() && e.enroll_until.is_some()) {
        return Gate::Refuse(REFUSE_CONSUMED); // первичная ссылка уже сработала на другом устройстве
    }
    if e.status != STATUS_ACTIVE || now >= e.valid_until {
        return Gate::Refuse(REFUSE_INACTIVE);
    }
    match e.enroll_until {
        Some(t) if t > 0 && now >= t => Gate::Refuse(REFUSE_EXPIRED),
        Some(t) => Gate::Enroll { until: t },
        None => Gate::Allow,
    }
}

/// M-9: применить активацию к реестру. Возвращает id устройства либо `(код отказа, причина)` —
/// код уходит абоненту, причина остаётся в логе издателя (текст по сети не гоняем, L-15).
fn apply_enrollment(
    dir: &str,
    bootstrap: &[u8; 32],
    frame: &[u8],
    ekm: &[u8],
) -> std::result::Result<[u8; 32], (u8, String)> {
    let (device_id, link_hash) = citadel_token::verify_enroll_frame(frame, bootstrap, ekm)
        .map_err(|e| (citadel_token::REFUSE_ENROLL, format!("{e:#}")))?;
    let path = registry_path(dir);
    let cur = std::fs::read_to_string(&path).unwrap_or_default();
    let next = citadel_token::admin::registry_apply_enroll(
        &cur,
        bootstrap,
        &device_id,
        Some(link_hash),
        now_unix(),
    )
    .map_err(|e| {
        let why = format!("{e:#}");
        // Разные причины — разные действия человека, поэтому и коды разные.
        let code = if why.contains("отпечаток") {
            citadel_token::REFUSE_LINK_MISMATCH
        } else if why.contains("другом устройстве") {
            citadel_token::REFUSE_CONSUMED
        } else if why.contains("окно активации") {
            citadel_token::REFUSE_EXPIRED
        } else {
            citadel_token::REFUSE_ENROLL
        };
        (code, why)
    })?;
    citadel_token::admin::atomic_write(&path, &next)
        .map_err(|e| (citadel_token::REFUSE_ENROLL, format!("запись реестра: {e:#}")))?;
    Ok(device_id)
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
    let mut pubs: Vec<BootstrapPub> = Vec::new();
    if let Ok(list) = std::env::var("Citadel_REGISTER_PUBS") {
        for p in list.split_whitespace() {
            pubs.push(parse_bootstrap_pub(p)?);
        }
    }
    if let Ok(list) = std::env::var("Citadel_REGISTER_SEEDS") {
        for s in list.split_whitespace() {
            let seed: [u8; 32] = hex::decode(s)
                .ok()
                .and_then(|v| v.try_into().ok())
                .context("Citadel_REGISTER_SEEDS: seed должен быть 32 байта hex")?;
            guard_weak_seed("Citadel_REGISTER_SEEDS", &seed)?; // L-10
            pubs.push(BootstrapPub {
                client_id: citadel_token::pqid::id_from_seed(&seed)?,
                enroll_until: None,
                link_hash: None,
            });
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

/// Запись bootstrap-реестра из env: client_id и — с M-9 — параметры ПЕРВИЧНОЙ ссылки.
struct BootstrapPub {
    client_id: [u8; 32],
    /// До какого момента (unix) ссылку можно активировать. `None` — запись многоразовая.
    enroll_until: Option<u64>,
    /// Отпечаток заверенной ссылки (издатель сверит его при активации).
    link_hash: Option<[u8; 32]>,
}

/// Разбор элемента `Citadel_REGISTER_PUBS`: `<client_id>[:<enroll_until>[:<link_hash>]]`.
///
/// M-9: установщик заводит СВОЮ мастер-ссылку одноразовой — иначе напечатанная в терминал ссылка
/// оставалась бы бессрочным предъявительским доступом, который поднимает туннель с любого числа
/// устройств (ровно то, что нашлось живьём). Расширение обратно совместимо: элемент без `:` —
/// прежняя многоразовая запись.
fn parse_bootstrap_pub(s: &str) -> Result<BootstrapPub> {
    let mut it = s.split(':');
    let id = it.next().unwrap_or_default();
    let client_id: [u8; 32] = hex::decode(id)
        .ok()
        .and_then(|v| v.try_into().ok())
        .context("Citadel_REGISTER_PUBS: client_id должен быть 32 байта hex")?;
    let enroll_until = match it.next().filter(|v| !v.is_empty()) {
        None => None,
        Some(v) => Some(v.parse::<u64>().context("Citadel_REGISTER_PUBS: срок активации — unix-секунды")?),
    };
    let link_hash = match it.next().filter(|v| !v.is_empty()) {
        None => None,
        Some(v) => Some(
            hex::decode(v)
                .ok()
                .and_then(|b| b.try_into().ok())
                .context("Citadel_REGISTER_PUBS: отпечаток ссылки — 32 байта hex")?,
        ),
    };
    Ok(BootstrapPub { client_id, enroll_until, link_hash })
}

/// Чистая логика слияния реестра: сохраняет ВСЕ существующие строки (в т.ч. `revoked`/`expired`),
/// добавляет только те `pubs`, которых ещё нет (по pub_hex), как `active` до `valid_until`.
/// Идемпотентно: повторный вызов с теми же pub'ами не меняет вывод — в том числе НЕ воскрешает
/// уже сработавшую (`consumed`) первичную ссылку при рестарте контейнера.
fn merge_registry(existing: &str, pubs: &[BootstrapPub], valid_until: u64) -> String {
    let present: std::collections::HashSet<&str> =
        existing.lines().filter_map(|l| l.split_whitespace().next()).collect();
    let mut out = existing.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    for p in pubs {
        let hexpk = hex::encode(p.client_id);
        if !present.contains(hexpk.as_str()) {
            out.push_str(
                &citadel_token::admin::RegistryEntry {
                    client_id: p.client_id,
                    valid_until,
                    status: citadel_token::admin::STATUS_ACTIVE.into(),
                    enroll_until: p.enroll_until,
                    device: None,
                    link_hash: p.link_hash,
                }
                .to_line(),
            );
        }
    }
    out
}

// ===================== C5.5: admin-CLI управления реестром =====================

/// `citadel-token registry <add|add-seed> …` — провижининг Layer-1 реестра на самом сервере.
/// Каталог реестра — `Citadel_TOKEN_DIR` (том issuer'а). Issuer перечитывает реестр на КАЖДЫЙ auth
/// ⇒ запись действует со следующего коннекта. Запись атомарна (temp+rename) — конкурентный
/// читатель-issuer видит старый ИЛИ новый файл, не частичный. C7.1: логика реестра — общая
/// `citadel_token::admin` (те же функции обслуживают admin-канал по туннелю).
///
/// **`revoke` и `list` на сервере УБРАНЫ (Q4-класс, как убран `citadel-linkgen`).** Управление
/// абонентской базой — исключительно по мастер-ссылке через admin-канал (`citadel-token admin`,
/// GUI «Абоненты»), то есть требует ключа, которого на боксе нет. Смысл: скомпрометированный
/// сервер не получает вместе с root'ом готовый инструмент перечисления базы и массового отзыва.
/// Это снимает инструмент, а не физическую возможность (root читает файл реестра и так) — ровно
/// как отсутствие `linkgen` не мешает root'у собрать URI руками; ценность в том, что серверу не
/// приписано НИ ОДНОЙ управляющей операции: ни в коде, ни в инструкции оператора.
///
/// Цена, принятая осознанно: break-glass после self-lockout (R6) и после потери мастер-доступа —
/// **реинсталл**, а не команда на боксе. `add`/`add-seed` остаются: их зовёт сам установщик
/// (заверение мастер-ссылки, `--enroll`/`--linkh`), и они не читают и не гасят чужие записи.
fn run_registry(args: &[String]) -> Result<()> {
    use citadel_token::admin::{atomic_write, registry_apply_add};
    let path = registry_path(&token_dir());
    match args.get(2).map(String::as_str) {
        Some("add") => {
            let pk = parse_hex32(args.get(3), "pub (client_id, 64 hex)")?;
            let vu = parse_valid_until(args.get(4).map(String::as_str))?;
            // M-9: `--enroll <unix> [--linkh <hex32>]` — сделать запись ОДНОРАЗОВОЙ и заверенной.
            // Этим установщик помечает мастер-ссылку: отпечаток известен только после того, как
            // ссылка собрана (TLS-идентичность издателя рождается при первом старте контейнера).
            let flag = |name: &str| -> Option<&String> {
                args.iter().position(|a| a == name).and_then(|i| args.get(i + 1))
            };
            let enroll = match flag("--enroll") {
                None => None,
                Some(v) => Some(v.parse::<u64>().context("--enroll: unix-секунды")?),
            };
            let linkh = match flag("--linkh") {
                None => None,
                Some(v) => Some(parse_hex32(Some(v), "--linkh (отпечаток ссылки, 64 hex)")?),
            };
            let cur = std::fs::read_to_string(&path).unwrap_or_default();
            let next = match enroll {
                None => registry_apply_add(&cur, &pk, vu),
                Some(u) => citadel_token::admin::registry_apply_add_full(&cur, &pk, vu, Some(u), linkh),
            };
            atomic_write(&path, &next)?;
            match enroll {
                None => eprintln!("[registry] add {} active до {vu}", hex::encode(pk)),
                Some(u) => eprintln!(
                    "[registry] add {} active до {vu}; одноразовая, активировать до {u}{}",
                    hex::encode(pk),
                    if linkh.is_some() { ", отпечаток заверен" } else { "" }
                ),
            }
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
        // Явный отказ, а не «неизвестная подкоманда»: оператор (и тот, кто читает старую
        // инструкцию) обязан увидеть, что операции не потерялись, а переехали в admin-канал.
        Some(gone @ ("revoke" | "list")) => anyhow::bail!(
            "`registry {gone}` на сервере больше нет. Отзыв и просмотр абонентской базы — только \n  \
             по мастер-ссылке через admin-канал: `citadel-token admin <list|revoke>` (env \n  \
             Citadel_ADMIN_ADDR/Citadel_ISSUER_PIN/Citadel_ISSUER_MLDSA/Citadel_ADMIN_SEED) либо \n  \
             GUI «Абоненты». На боксе управляющего ключа нет — и это намеренно (Q4-класс: как и \n  \
             citadel-linkgen, инструмент управления сервером не поставляется).\n  \
             Мастер-доступ утрачен → реинсталл (новая идентичность, прежние ссылки мертвы)."
        ),
        _ => anyhow::bail!(
            "citadel-token registry <add <pub>|add-seed <seed>> [valid_until]\n  \
             valid_until: unix-секунды | +<N>d | +<N>h | +<секунды> (дефолт +365d).\n  \
             add … --enroll <unix> [--linkh <hex32>]: одноразовая заверенная запись (M-9).\n  \
             Каталог реестра — $Citadel_TOKEN_DIR (том issuer'а).\n  \
             Отзыв/список — НЕ на сервере: `citadel-token admin <list|revoke>` по мастер-ссылке."
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

/// 32-байтный ключ из переменной окружения, fail-closed: нет/пусто — не настроено, мусор — ошибка
/// старта (тот же принцип, что у `Citadel_OBFS_PSK`, M-7).
fn parse_hex32_env(var: &str) -> Result<Option<[u8; 32]>> {
    let Ok(raw) = std::env::var(var) else { return Ok(None) };
    if raw.trim().is_empty() {
        return Ok(None);
    }
    let v: [u8; 32] = hex::decode(raw.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .with_context(|| format!("{var}: ожидаются ровно 64 hex-символа (32 байта)"))?;
    Ok(Some(v))
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
        "enroll" => run_enroll(),
        "batch" => run_batch(),
        other => Err(anyhow::anyhow!(
            "Citadel_TOKEN_ROLE должен быть issuer|client|enroll|keysync|pubkey|batch (или arg[1]=registry), а не {other:?}"
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
    // H-3: мастер-секрет L1. Есть — издатель раздаёт абонентам ключ ТЕКУЩЕЙ эпохи (ротация L1,
    // отзыв начинает работать и на этом слое); нет — канал данных остаётся на бутстрапном PSK.
    // Разбор fail-closed: опечатка роняет старт, а не выключает ротацию молча.
    let obfs_master = parse_hex32_env("Citadel_OBFS_MASTER")?;
    eprintln!(
        "[issuer] L1-ключ для абонентов: {}",
        match obfs_master {
            Some(_) => format!("ротация по эпохам ({epoch_secs}с, H-3)"),
            None => "не ротируется (Citadel_OBFS_MASTER не задан — token-less/legacy)".into(),
        }
    );

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
            &lease, lease_secs, obfs_psk, keysync_id.as_ref(), obfs_master, epoch_secs,
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
    // H-3: мастер-секрет L1 (не покидает сервер) + длина эпохи — из них выводится ключ, который
    // издатель отдаёт абоненту после Layer-1.
    obfs_master: Option<[u8; 32]>,
    epoch_secs: u64,
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
    // M-9: решение по записи реестра — пускать, требовать активацию или отказать с причиной.
    let gate = registry_gate(dir, &client_id, now_unix());
    if let citadel_token::Gate::Refuse(code) = gate {
        // Причину сообщаем ПОСЛЕ проверки подписи: увидеть её может только владелец seed'а, то
        // есть тот, кому она и адресована. Слот pre-auth при этом НЕ освобождаем (H-1).
        let _ = write_frame(&mut conn, &citadel_token::build_gate_frame(gate));
        anyhow::bail!("Layer-1: отказ по реестру (код {code})");
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
    // M-9: гейт выдачи. `Enroll` — первичная ссылка: прежде чем что-то выдавать, абонент обязан
    // предъявить СВОЮ (устройственную) идентичность, и подписка переезжает на неё. После этого та
    // же ссылка на другом устройстве не работает — ради этого всё и затевалось.
    write_frame(&mut conn, &citadel_token::build_gate_frame(gate))?;
    if let citadel_token::Gate::Enroll { .. } = gate {
        let frame = read_frame(&mut conn).context("абонент не прислал кадр активации")?;
        match apply_enrollment(dir, &client_id, &frame, &ekm) {
            Ok(device_id) => {
                write_frame(&mut conn, &citadel_token::build_gate_frame(citadel_token::Gate::Allow))?;
                citadel_token::dlog!(
                    "[issuer] активация: {}… → устройство {}…",
                    &hex::encode(client_id)[..12],
                    &hex::encode(device_id)[..12]
                );
            }
            Err((code, why)) => {
                let _ = write_frame(&mut conn, &citadel_token::build_gate_frame(citadel_token::Gate::Refuse(code)));
                anyhow::bail!("активация отклонена: {why}");
            }
        }
    }
    // C5.3: отдаём клиенту публичный элемент K ТЕКУЩЕЙ эпохи — под ним он проверит DLEQ каждой
    // выдачи (и заметит, если издатель применит не тот ключ).
    let cur = state.lock().unwrap().1.clone();
    write_frame(&mut conn, &cur.public_bytes())?;
    // H-3: следом — ключ L1-обфускации текущей эпохи. Он выводится из мастер-секрета, которого нет
    // ни в одной ссылке, поэтому получить его может ТОЛЬКО прошедший Layer-1 абонент — и ровно на
    // одну эпоху. Отсюда два свойства, которых не было: отзыв абонента гасит и L1-доступ (≤ эпохи),
    // а утёкшая ссылка перестаёт быть бессрочным классификатором трафика деплоя.
    // Кадр всегда есть (протокол фиксирован); §7.1: в нём же — номер и длина эпохи, из которых
    // абонент понимает, до какого момента годна взятая пачка токенов и когда идти за новой (без
    // этого он обязан спрашивать издателя перед каждым establish — худший паттерн для корреляции).
    write_frame(&mut conn, &citadel_token::build_epoch_frame(obfs_master, epoch_secs))?;

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

/// M-9 (роль `enroll`): активировать первичную ссылку на этом «устройстве».
///
/// Стендовая и ops-роль: в GUI/консольном клиенте активация встроена в подключение (ключ надо
/// класть в хранилище, а оно есть только у них). Здесь ключ устройства задаётся явно
/// (`Citadel_DEVICE_SEED`) — так активацию можно прогнать в харнесе и повторить руками.
fn run_enroll() -> Result<()> {
    let issuer = std::env::var("Citadel_TOKEN_ISSUER").context("Citadel_TOKEN_ISSUER не задан")?;
    let hex32 = |name: &str| -> Result<[u8; 32]> {
        std::env::var(name)
            .ok()
            .and_then(|s| hex::decode(s.trim()).ok())
            .and_then(|v| v.try_into().ok())
            .with_context(|| format!("{name} (32 байта hex) обязателен"))
    };
    let bootstrap = hex32("Citadel_CLIENT_SEED")?;
    guard_weak_seed("Citadel_CLIENT_SEED", &bootstrap)?;
    let device = hex32("Citadel_DEVICE_SEED")?;
    guard_weak_seed("Citadel_DEVICE_SEED", &device)?;
    let issuer_pin = hex32("Citadel_ISSUER_PIN")?;
    let issuer_mldsa = hex32("Citadel_ISSUER_MLDSA")?;
    // Отпечаток заверенной ссылки: у стенда ссылки как объекта нет, поэтому он передаётся явно.
    // Издатель сверит его с тем, что запомнил при выдаче — расхождение и есть «подменили ссылку».
    let link_hash = hex32("Citadel_LINK_HASH").unwrap_or([0u8; 32]);
    let obfs_psk = obfs_psk_from_env();
    let done = citadel_token::enroll_device(
        &issuer,
        &issuer_pin,
        &issuer_mldsa,
        &bootstrap,
        &device,
        &link_hash,
        20,
        obfs_psk,
    )?;
    if done {
        eprintln!("[enroll] ссылка активирована: подписка переехала на ключ устройства");
    } else {
        eprintln!("[enroll] активация не требуется — ссылка многоразовая");
    }
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
    // Роль CLI-стенда: туннеля у процесса нет, маршрут к издателю всегда прямой.
    let grant = citadel_token::fetch_tokens(
        &issuer,
        &issuer_pin,
        &issuer_mldsa,
        &seed,
        count,
        20,
        obfs_psk,
        citadel_protect::Route::Bypass,
    )?;

    let mut f = std::fs::File::create(format!("{dir}/tokens")).context("запись tokens")?;
    for t in &grant.tokens {
        writeln!(f, "{}", hex::encode(t))?;
    }
    // H-3: ключ L1 текущей эпохи — рядом с токенами. Эта роль CLI работает как отдельный процесс
    // (демо/стенд: сначала добыть токен, потом поднять туннель `citadel-m1`), поэтому ключ надо
    // передать «вбок» файлом, ровно как токены. В GUI/консольном клиенте того же не требуется:
    // там движок и добытчик токенов живут в одном процессе и обмениваются структурой.
    match grant.data_psk {
        Some(psk) => {
            let path = format!("{dir}/obfs.epoch");
            std::fs::write(&path, hex::encode(psk)).context("запись L1-ключа эпохи")?;
            set_file_perms_600(&path);
            eprintln!("[client] L1-ключ текущей эпохи → {path} (ротация H-3)");
        }
        None => {
            let _ = std::fs::remove_file(format!("{dir}/obfs.epoch")); // не тащить ключ прошлого стенда
        }
    }
    eprintln!(
        "[client] получено {} токенов → {dir}/tokens (издатель их НЕ видел → unlinkable)",
        grant.tokens.len()
    );
    Ok(())
}

/// Ключевой материал на диске — только владельцу (как `vault.bin`/`issuer-*.key`).
fn set_file_perms_600(path: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
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
    use super::{merge_registry, parse_bootstrap_pub, BootstrapPub};

    /// Многоразовая bootstrap-запись (как было до M-9).
    fn plain(pk: [u8; 32]) -> BootstrapPub {
        BootstrapPub { client_id: pk, enroll_until: None, link_hash: None }
    }

    /// Управляющих операций на сервере нет: `registry revoke|list` убраны (Q4-класс, как linkgen).
    /// Тест держит решение: случайный «возврат для удобства ops» уронит сборку, а не тихо вернёт
    /// скомпрометированному серверу готовый инструмент перечисления базы и массового отзыва.
    /// Провижининг (`add`/`add-seed`, зовёт установщик) обязан остаться живым.
    #[test]
    fn server_cli_has_no_revoke_and_no_list() {
        let argv = |cmd: &str| -> Vec<String> {
            ["citadel-token", "registry", cmd, &hex::encode([0x11u8; 32])]
                .iter()
                .map(|s| s.to_string())
                .collect()
        };
        for cmd in ["revoke", "list"] {
            let e = super::run_registry(&argv(cmd)).expect_err("операция обязана быть недоступна");
            let msg = format!("{e:#}");
            assert!(msg.contains("admin"), "отказ обязан указывать на admin-канал: {msg}");
        }
        // Неизвестная подкоманда печатает usage — и он тоже не должен рекламировать удалённое.
        let usage = format!("{:#}", super::run_registry(&argv("wat")).unwrap_err());
        assert!(!usage.contains("|revoke <pub>|list>"), "usage рекламирует удалённые команды: {usage}");
        assert!(usage.contains("add-seed"), "провижининг обязан остаться: {usage}");
    }

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
        let merged = merge_registry(&existing, &[plain(pk_a), plain(pk_b)], 8888888888);
        assert!(merged.contains(&format!("{hex_a} 9999999999 revoked")), "A остаётся revoked");
        assert_eq!(merged.matches(&hex_a).count(), 1, "A не продублирован (не воскрешён active)");
        assert!(merged.contains(&format!("{hex_b} 8888888888 active")), "B добавлен active");
    }

    /// Повторный bootstrap тех же pub'ов идемпотентен (вывод не растёт/не меняется).
    #[test]
    fn merge_is_idempotent() {
        let pk = [0x11u8; 32];
        let first = merge_registry("", &[plain(pk)], 100);
        let second = merge_registry(&first, &[plain(pk)], 200);
        assert_eq!(first, second);
    }

    /// M-9: установщик сеет СВОЮ мастер-ссылку одноразовой. Разбор формата
    /// `<client_id>[:<enroll_until>[:<linkh>]]` и то, что флаги доезжают до строки реестра.
    #[test]
    fn bootstrap_pub_parses_enrollable_form() {
        let pk = [0x22u8; 32];
        let h = [0x33u8; 32];
        let plain_form = parse_bootstrap_pub(&hex::encode(pk)).unwrap();
        assert!(plain_form.enroll_until.is_none() && plain_form.link_hash.is_none());

        let full = parse_bootstrap_pub(&format!("{}:1700000000:{}", hex::encode(pk), hex::encode(h)))
            .unwrap();
        assert_eq!(full.enroll_until, Some(1_700_000_000));
        assert_eq!(full.link_hash, Some(h));

        let line = merge_registry("", &[full], 5_000);
        let e = citadel_token::admin::parse_registry(&line).pop().unwrap();
        assert_eq!(e.enroll_until, Some(1_700_000_000), "запись одноразовая");
        assert_eq!(e.link_hash, Some(h), "и заверенная");

        // Мусор — отказ, а не молчаливая многоразовая запись (иначе ошибка в env тихо снимала бы
        // одноразовость мастер-ссылки).
        assert!(parse_bootstrap_pub("нехекс").is_err());
        assert!(parse_bootstrap_pub(&format!("{}:позже", hex::encode(pk))).is_err());
        assert!(parse_bootstrap_pub(&format!("{}:1:кривой", hex::encode(pk))).is_err());
    }

    /// И главное свойство: уже сработавшую (`consumed`) одноразовую ссылку рестарт контейнера НЕ
    /// воскрешает — иначе одноразовость снималась бы простым `docker restart`.
    #[test]
    fn merge_does_not_resurrect_consumed_link() {
        let pk = [0x44u8; 32];
        let hexpk = hex::encode(pk);
        let existing = format!("{hexpk} 9000 consumed enroll=1,dev={}\n", hex::encode([0x55u8; 32]));
        let merged = merge_registry(
            &existing,
            &[BootstrapPub { client_id: pk, enroll_until: Some(1), link_hash: None }],
            9000,
        );
        assert_eq!(merged, existing, "строка не тронута");
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

    /// Пара соединённых по loopback сокетов: гейту нужен ЖИВОЙ дескриптор, чтобы вытеснение было
    /// настоящим (`shutdown`), а не только записью в счётчике. Возвращаем оба конца — если бросить
    /// клиентский, серверный станет читаемым (EOF), и тест перестанет отличать вытеснение от него.
    fn sock_pair() -> (std::net::TcpStream, std::net::TcpStream) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        let a = std::net::TcpStream::connect(l.local_addr().unwrap()).expect("connect");
        let (b, _) = l.accept().expect("accept");
        (a, b)
    }

    /// Общий потолок: сверх него новое соединение вытесняет самое старое, а освобождение (дроп)
    /// возвращает место. Это и есть замена «поток на каждый accept без единого таймаута».
    #[test]
    fn gate_caps_total_and_releases_on_drop() {
        use super::Gate;
        let g = Gate::new(3, 3);
        let (_k1, s1) = sock_pair();
        let (_k2, s2) = sock_pair();
        let (_k3, s3) = sock_pair();
        let (_k4, s4) = sock_pair();
        let a = g.admit(ip(1), Some(s1)).expect("слот 1");
        let b = g.admit(ip(2), Some(s2)).expect("слот 2");
        let c = g.admit(ip(3), Some(s3)).expect("слот 3");
        assert_eq!(g.state.lock().unwrap().total, 3, "потолок занят");
        // Сверх потолка: место освобождается вытеснением САМОГО СТАРОГО (слот 1), а не отказом.
        let d = g.admit(ip(4), Some(s4)).expect("новое соединение проходит за счёт вытеснения");
        assert_eq!(g.state.lock().unwrap().total, 3, "потолок не превышен");
        // Дроп уже вытесненного Pass'а счётчики не трогает (иначе они уехали бы в минус).
        drop(a);
        assert_eq!(g.state.lock().unwrap().total, 3, "вытесненный Pass повторно слот не отдаёт");
        drop(b);
        drop(c);
        drop(d);
        assert_eq!(g.state.lock().unwrap().total, 0, "все слоты освобождены");
    }

    /// Потолок НА АДРЕС: жертву ищем среди соединений ТОГО ЖЕ адреса — флудер, упёршийся в свой
    /// лимит, не должен выбивать чужие соединения.
    #[test]
    fn gate_caps_per_ip_so_one_source_cannot_starve_others() {
        use super::Gate;
        let g = Gate::new(100, 2);
        let (_k1, s1) = sock_pair();
        let (_k2, s2) = sock_pair();
        let (_k3, s3) = sock_pair();
        let (_k4, s4) = sock_pair();
        let a = g.admit(ip(1), Some(s1)).expect("первый от адреса");
        let _b = g.admit(ip(1), Some(s2)).expect("второй от адреса");
        let other = g.admit(ip(2), Some(s3)).expect("чужой адрес не должен страдать от соседа");
        // Третий с того же адреса вытесняет ПЕРВЫЙ с того же адреса, а не чужой.
        let _c = g.admit(ip(1), Some(s4)).expect("третий с адреса проходит за счёт вытеснения");
        {
            let st = g.state.lock().unwrap();
            assert_eq!(st.per_ip.get(&ip(1)).copied(), Some(2), "лимит адреса соблюдён");
            assert_eq!(st.per_ip.get(&ip(2)).copied(), Some(1), "чужой слот на месте");
            assert!(!st.live.iter().any(|l| l.id == a.id), "вытеснено самое старое с этого адреса");
        }
        drop(other);
    }

    /// G3 (аудит-5): за exit'ом все туннельные соединения приходят с ОДНОГО адреса, поэтому
    /// «потолок на адрес» — общий счётчик абонентов и админа. Флудер, заливший его молчащими
    /// коннектами, обязан НЕ запирать управление: новое соединение проходит, вытесняя старое
    /// паразитное, и вытесненное реально закрывается (рабочий поток жертвы выйдет из read).
    #[test]
    fn gate_evicts_stale_flood_instead_of_locking_admin_out() {
        use super::Gate;
        use std::io::Read;
        let g = Gate::new(32, 4);
        let shared = ip(7); // адрес exit'а: и флудер, и админ приходят с него
        let mut flood_peers = Vec::new();
        let mut passes = Vec::new();
        for _ in 0..4 {
            let (peer, s) = sock_pair();
            passes.push(g.admit(shared, Some(s)).expect("слот флудера"));
            flood_peers.push(peer);
        }
        // Админ приходит пятым — до G3 здесь был отказ, и управление реестром терялось.
        let (_admin_peer, admin_sock) = sock_pair();
        let admin = g.admit(shared, Some(admin_sock)).expect("админ обязан пройти");
        assert!(
            g.state.lock().unwrap().live.iter().any(|l| l.id == admin.id),
            "соединение админа стоит в очереди"
        );
        // Самое старое соединение флудера закрыто на уровне сокета: его сторона читает EOF.
        let mut buf = [0u8; 1];
        flood_peers[0].set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        assert_eq!(flood_peers[0].read(&mut buf).ok(), Some(0), "вытесненное соединение закрыто");
        // Соседние соединения флудера при этом живы — вытесняется ровно одно, самое старое.
        assert_eq!(g.state.lock().unwrap().per_ip.get(&shared).copied(), Some(4));
    }

    /// Карта адресов не растёт: запись убирается, когда её счётчик обнуляется (иначе долгий
    /// прогон с меняющихся адресов сам стал бы утечкой памяти).
    #[test]
    fn gate_forgets_addresses_with_no_slots() {
        use super::Gate;
        let g = Gate::new(8, 4);
        for n in 0..200u8 {
            let (_peer, s) = sock_pair();
            let p = g.admit(ip(n), Some(s)).expect("слот");
            drop(p);
        }
        let st = g.state.lock().unwrap();
        assert_eq!(st.total, 0, "все слоты освобождены");
        assert!(st.per_ip.is_empty(), "пустые записи адресов не копятся: {}", st.per_ip.len());
        assert!(st.live.is_empty(), "очередь живых соединений тоже пуста: {}", st.live.len());
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
