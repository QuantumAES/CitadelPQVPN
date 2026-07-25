//! `citadel-vpnd` — системный демон Linux-клиента CitadelPQVPN (юнит systemd).
//!
//! Роль — «плумбер и супервизор», ровно как служба `citadel-svc` на Windows (модель W2):
//!   * держит управляющий сокет для непривилегированного `citadel-cli` (кто в группе
//!     `citadel-vpn` — тот может управлять туннелем; L1/L3);
//!   * запускает движок `citadel-engine` **под отдельным пользователем без привилегий**, передав
//!     ему конфиг по приватному сокету (не через argv — L5);
//!   * по запросу движка создаёт TUN и настраивает сеть, предварительно **заново валидируя**
//!     запрос (L2), и отдаёт дескриптор туннеля по SCM_RIGHTS;
//!   * сворачивает конфигурацию при разрыве: чистый disconnect снимает kill-switch, крах движка —
//!     оставляет (fail-closed, утечки нет).
//!
//! Чего демон НЕ делает принципиально: не разбирает `citadel://`, не ходит в сеть, не читает
//! файлы по путям, присланным клиентом, не исполняет произвольных команд. Весь недоверенный ввод
//! (ссылка, пакеты, ответы сервера) живёт в движке под другим uid.

mod net;

use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use sendfd::SendWithFd;
use zeroize::Zeroize;

use citadel_vpnd::proto::{
    read_frame, write_frame, ConnectReq, CtlRequest, CtlResponse, DaemonMsg, EngineMsg, EventMsg,
    StatusInfo,
};
use citadel_vpnd::valid::{sanitize_text, TunSetup};
use citadel_vpnd::{CTL_GROUP, CTL_SOCKET, ENGINE_PATH, ENGINE_USER};

use net::{NetState, Tools};

/// Сколько ждать штатного завершения движка после `Stop`, прежде чем убивать.
const STOP_GRACE: Duration = Duration::from_secs(8);
/// Потолок одновременных управляющих соединений (анти-DoS локальным клиентом).
const MAX_CLIENTS: usize = 32;

struct Daemon {
    tools: Tools,
    engine_path: String,
    engine_uid: u32,
    engine_gid: u32,
    shared: Mutex<Shared>,
    clients: Mutex<usize>,
}

#[derive(Default)]
struct Shared {
    session: Option<Session>,
    status: StatusInfo,
    subs: Vec<Sender<EventMsg>>,
    net: NetState,
    /// Движок прислал `CleanShutdown` — разрыв штатный, kill-switch снимаем.
    clean: bool,
    /// Растёт на каждую сессию: поток-супервизор понимает, что его сессию уже сменили.
    generation: u64,
}

struct Session {
    chan: Arc<UnixStream>,
    child: Child,
    owner_uid: u32,
}

fn main() -> Result<()> {
    // Файлы, создаваемые демоном (сокет, резервные копии), не должны быть доступны миру.
    // SAFETY: umask не имеет побочных эффектов, кроме установки маски процесса.
    unsafe { libc::umask(0o077) };

    let args: Vec<String> = std::env::args().collect();
    let arg = |name: &str, default: &str| -> String {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
            .unwrap_or_else(|| default.to_string())
    };
    let has = |name: &str| args.iter().any(|a| a == name);

    if has("--version") {
        println!("citadel-vpnd {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if has("--help") {
        println!(
            "citadel-vpnd — демон Linux-клиента CitadelPQVPN\n\n\
             --socket <path>        управляющий сокет (по умолчанию {CTL_SOCKET})\n\
             --group <name>         группа управления (по умолчанию {CTL_GROUP})\n\
             --engine <path>        путь движка (по умолчанию {ENGINE_PATH})\n\
             --engine-user <name>   пользователь движка (по умолчанию {ENGINE_USER})\n\
             --disarm               снять kill-switch/IPv6-блок и выйти\n\
             --version --help"
        );
        return Ok(());
    }

    // SAFETY: geteuid без побочных эффектов.
    if unsafe { libc::geteuid() } != 0 {
        bail!("citadel-vpnd должен работать от root (его запускает systemd)");
    }
    let tools = Tools::discover()?;

    // Аварийный режим: снять залипшие fail-closed правила и выйти (L11). Используется и
    // юнитом (ExecStopPost), и человеком, у которого после краха нет интернета.
    if has("--disarm") {
        let mut st = NetState::default();
        st.disarm(&tools);
        eprintln!("[vpnd] kill-switch и IPv6-блок сняты");
        return Ok(());
    }
    // L10: заблокировать сеть ДО её поднятия (citadel-lockdown.service, opt-in).
    if has("--lockdown") {
        let mut st = NetState::default();
        st.arm_lockdown(&tools);
        eprintln!("[vpnd] режим блокировки: наружу не уходит ничего, пока не поднят туннель");
        return Ok(());
    }

    let sock_path = arg("--socket", CTL_SOCKET);
    let group = arg("--group", CTL_GROUP);
    let engine_path = arg("--engine", ENGINE_PATH);
    let engine_user = arg("--engine-user", ENGINE_USER);

    let (engine_uid, engine_gid) = lookup_user(&engine_user).with_context(|| {
        format!(
            "нет системного пользователя {engine_user:?} — его создаёт установщик \
             (useradd --system --no-create-home --shell /usr/sbin/nologin {engine_user})"
        )
    })?;
    if engine_uid == 0 {
        bail!("пользователь движка не может быть root — теряется смысл разделения привилегий");
    }
    check_engine_binary(&engine_path)?;

    let daemon = Arc::new(Daemon {
        tools,
        engine_path,
        engine_uid,
        engine_gid,
        shared: Mutex::new(Shared { status: idle_status(), ..Default::default() }),
        clients: Mutex::new(0),
    });

    // Осиротевший kill-switch от прошлого запуска НЕ снимаем автоматически: он мог остаться
    // после краха и прямо сейчас защищает от утечки. Но говорим об этом громко — иначе человек
    // видит «интернет пропал» без объяснений (L11).
    if daemon.shared.lock().unwrap().net.killswitch_armed(&daemon.tools) {
        eprintln!(
            "[vpnd] ВНИМАНИЕ: kill-switch армирован с прошлого запуска (сессии нет). \
             Снять: citadel-cli killswitch --disarm"
        );
    }

    let listener = bind_control_socket(&sock_path, &group)?;
    install_signal_handler(daemon.clone(), sock_path.clone());
    eprintln!(
        "[vpnd] запущен: сокет {sock_path} (группа {group}), движок {} (uid {engine_uid})",
        daemon.engine_path
    );

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[vpnd] accept: {e}");
                continue;
            }
        };
        {
            let mut n = daemon.clients.lock().unwrap();
            if *n >= MAX_CLIENTS {
                eprintln!("[vpnd] отказ: слишком много управляющих соединений");
                continue;
            }
            *n += 1;
        }
        let d = daemon.clone();
        std::thread::spawn(move || {
            if let Err(e) = handle_client(&d, stream) {
                eprintln!("[vpnd] клиент: {e:#}");
            }
            *d.clients.lock().unwrap() -= 1;
        });
    }
    Ok(())
}

// ───────────────────────────── управляющий сокет ─────────────────────────────

/// Создать сокет в `/run/…`: каталог `0750 root:<группа>`, сокет `0660 root:<группа>`.
/// Право подключиться проверяет ядро по правам файла — это и есть основной гейт (L1);
/// `SO_PEERCRED` ниже используется для владения сессией, а не вместо прав.
fn bind_control_socket(path: &str, group: &str) -> Result<UnixListener> {
    let dir = std::path::Path::new(path).parent().context("путь сокета без каталога")?;
    std::fs::create_dir_all(dir).with_context(|| format!("создать {}", dir.display()))?;

    let gid = match lookup_group(group) {
        Some(g) => g,
        None => {
            eprintln!(
                "[vpnd] ВНИМАНИЕ: нет группы {group:?} — сокет останется root-only \
                 (управлять сможет только root). Создать: groupadd --system {group}"
            );
            0
        }
    };
    set_owner(dir, 0, gid)?;
    std::fs::set_permissions(dir, perms(if gid == 0 { 0o700 } else { 0o750 }))?;

    // Устаревший сокет мог остаться от аварийно завершённого демона. Каталог root-only,
    // поэтому подмены файла злоумышленником здесь быть не может.
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path).with_context(|| format!("bind {path}"))?;
    set_owner(std::path::Path::new(path), 0, gid)?;
    std::fs::set_permissions(path, perms(if gid == 0 { 0o600 } else { 0o660 }))?;
    Ok(listener)
}

fn perms(mode: u32) -> std::fs::Permissions {
    use std::os::unix::fs::PermissionsExt;
    std::fs::Permissions::from_mode(mode)
}

fn set_owner(path: &std::path::Path, uid: u32, gid: u32) -> Result<()> {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    // SAFETY: путь — валидная C-строка, живёт до конца вызова.
    if unsafe { libc::chown(c.as_ptr(), uid, gid) } != 0 {
        bail!("chown {}: {}", path.display(), std::io::Error::last_os_error());
    }
    Ok(())
}

/// uid/gid подключившегося процесса — ядро сообщает их само, подделать нельзя.
/// Намеренно НЕ используем PID (он переиспользуется — авторизация по нему гоночная).
fn peer_uid(stream: &UnixStream) -> Result<u32> {
    let mut cred = libc::ucred { pid: 0, uid: u32::MAX, gid: u32::MAX };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: размеры и указатели соответствуют контракту getsockopt(SO_PEERCRED).
    let r = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if r != 0 {
        bail!("SO_PEERCRED: {}", std::io::Error::last_os_error());
    }
    Ok(cred.uid)
}

fn handle_client(d: &Arc<Daemon>, stream: UnixStream) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let uid = peer_uid(&stream)?;
    let mut rd = stream.try_clone()?;

    let req: CtlRequest = match read_frame(&mut rd)? {
        Some(r) => r,
        None => return Ok(()), // клиент отключился, не спросив
    };
    match req {
        CtlRequest::Version => {
            reply(&stream, &CtlResponse::Version(env!("CARGO_PKG_VERSION").to_string()))
        }
        CtlRequest::Status => {
            let st = d.status_snapshot();
            reply(&stream, &CtlResponse::Status(st))
        }
        CtlRequest::Connect(mut c) => {
            let r = d.connect(c.clone(), uid);
            c.link.zeroize(); // L6: ссылка (bearer-креды) не должна оставаться в памяти демона
            match r {
                Ok(()) => reply(&stream, &CtlResponse::Ok),
                Err(e) => reply(&stream, &CtlResponse::Err(format!("{e:#}"))),
            }
        }
        CtlRequest::Disconnect => match d.disconnect(uid) {
            Ok(()) => reply(&stream, &CtlResponse::Ok),
            Err(e) => reply(&stream, &CtlResponse::Err(format!("{e:#}"))),
        },
        CtlRequest::DisarmKillswitch => match d.disarm(uid) {
            Ok(()) => reply(&stream, &CtlResponse::Ok),
            Err(e) => reply(&stream, &CtlResponse::Err(format!("{e:#}"))),
        },
        CtlRequest::Events => stream_events(d, stream),
    }
}

fn reply(stream: &UnixStream, resp: &CtlResponse) -> Result<()> {
    write_frame(&mut &*stream, resp)
}

/// Подписка на события: сначала текущее состояние (чтобы UI сразу отрисовался), затем поток.
fn stream_events(d: &Arc<Daemon>, stream: UnixStream) -> Result<()> {
    let (tx, rx) = channel::<EventMsg>();
    {
        let mut sh = d.shared.lock().unwrap();
        let cur = EventMsg::state(&sh.status.state);
        sh.subs.push(tx);
        drop(sh);
        reply(&stream, &CtlResponse::Event(cur))?;
    }
    // Поток живёт, пока клиент читает. Ошибка записи = клиент ушёл; его Sender осиротеет и
    // будет вычищен на ближайшей рассылке.
    while let Ok(ev) = rx.recv() {
        if reply(&stream, &CtlResponse::Event(ev)).is_err() {
            break;
        }
    }
    Ok(())
}

// ───────────────────────────── операции ─────────────────────────────

impl Daemon {
    fn status_snapshot(&self) -> StatusInfo {
        let sh = self.shared.lock().unwrap();
        let mut st = sh.status.clone();
        st.killswitch_armed = sh.net.killswitch_armed(&self.tools);
        st.version = env!("CARGO_PKG_VERSION").to_string();
        st
    }

    /// Поднять сессию: запустить движок под непривилегированным пользователем и передать ему
    /// конфиг по приватному каналу.
    fn connect(self: &Arc<Self>, req: ConnectReq, uid: u32) -> Result<()> {
        let mut sh = self.shared.lock().unwrap();
        if let Some(s) = &sh.session {
            bail!(
                "сессия уже активна (запущена uid {}) — сначала отключитесь",
                s.owner_uid
            );
        }
        if req.link.trim().is_empty() {
            bail!("пустая ссылка подключения");
        }

        let (parent, child_end) = UnixStream::pair().context("socketpair для движка")?;
        let child = self.spawn_engine(&child_end)?;
        drop(child_end); // копия дочернего конца в родителе не нужна: иначе EOF не придёт

        let chan = Arc::new(parent);
        // Конфиг уходит первым кадром — секреты идут по сокету, не через argv/env (L5).
        write_frame(&mut &*chan, &DaemonMsg::Config(req.clone())).context("передать конфиг движку")?;

        sh.generation += 1;
        let generation = sh.generation;
        sh.clean = false;
        sh.status = StatusInfo {
            state: "connecting".into(),
            label: sanitize_text(&req.label, 64),
            since_unix: now_unix(),
            owner_uid: uid,
            ..Default::default()
        };
        sh.session = Some(Session { chan: chan.clone(), child, owner_uid: uid });
        drop(sh);

        self.broadcast(EventMsg::state("connecting"));
        let d = self.clone();
        std::thread::spawn(move || supervise(d, chan, generation));
        Ok(())
    }

    /// Запустить движок, сбросив привилегии до непривилегированного пользователя (L13).
    fn spawn_engine(&self, child_end: &UnixStream) -> Result<Child> {
        use citadel_vpnd::proto::ENGINE_CHANNEL_FD;
        let fd = child_end.as_raw_fd();
        let (uid, gid) = (self.engine_uid, self.engine_gid);
        let mut cmd = Command::new(&self.engine_path);
        cmd.env_clear() // движок не наследует ни PATH, ни LD_*, ни чего-либо из окружения демона
            .stdin(Stdio::null());
        // SAFETY: в pre_exec (между fork и exec) зовём только async-signal-safe функции libc.
        unsafe {
            cmd.pre_exec(move || {
                // 1. полный сброс привилегий: сначала доп. группы, затем gid, только потом uid
                //    (после setuid вернуть их уже нельзя — порядок принципиален).
                if libc::setgroups(0, std::ptr::null()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // 2. проверка, что сброс реально состоялся (иначе движок стартанул бы как root)
                if libc::getuid() != uid || libc::geteuid() != uid {
                    return Err(std::io::Error::other("не удалось сбросить привилегии движка"));
                }
                // 3. никаких setuid-бинарей и capabilities из exec (NO_NEW_PRIVS), никаких
                //    core-dump'ов с секретами сессии (L6)
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
                let lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
                libc::setrlimit(libc::RLIMIT_CORE, &lim);
                // 4. приватный канал → фиксированный fd 3 (dup2 снимает CLOEXEC сам)
                if fd != ENGINE_CHANNEL_FD {
                    if libc::dup2(fd, ENGINE_CHANNEL_FD) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                } else {
                    let flags = libc::fcntl(ENGINE_CHANNEL_FD, libc::F_GETFD);
                    libc::fcntl(ENGINE_CHANNEL_FD, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
                }
                Ok(())
            });
        }
        cmd.spawn().with_context(|| format!("запустить движок {}", self.engine_path))
    }

    /// Разорвать сессию (чистый disconnect → kill-switch снимается).
    fn disconnect(&self, uid: u32) -> Result<()> {
        let chan = {
            let sh = self.shared.lock().unwrap();
            let Some(s) = &sh.session else {
                bail!("активной сессии нет");
            };
            // Чужую сессию рвать нельзя: на многопользовательской машине это был бы DoS
            // (и способ снять kill-switch чужими руками). root — исключение.
            if uid != 0 && uid != s.owner_uid {
                bail!("сессия запущена другим пользователем (uid {})", s.owner_uid);
            }
            s.chan.clone()
        };
        let _ = write_frame(&mut &*chan, &DaemonMsg::Stop);

        // Ждём, пока супервизор увидит завершение движка и свернёт сеть.
        let deadline = Instant::now() + STOP_GRACE;
        loop {
            if self.shared.lock().unwrap().session.is_none() {
                return Ok(());
            }
            if Instant::now() > deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        // Движок завис — добиваем. Сеть свернёт супервизор по EOF; kill-switch при этом
        // останется (разрыв не был чистым) — это осознанный fail-closed.
        let mut sh = self.shared.lock().unwrap();
        if let Some(s) = &mut sh.session {
            eprintln!("[vpnd] движок не завершился за {STOP_GRACE:?} — SIGKILL");
            let _ = s.child.kill();
        }
        Ok(())
    }

    /// Снять fail-closed правила вручную (L11).
    fn disarm(&self, _uid: u32) -> Result<()> {
        let mut sh = self.shared.lock().unwrap();
        if sh.session.is_some() {
            bail!("сессия активна — сначала отключитесь (иначе снятие защиты откроет утечку)");
        }
        sh.net.disarm(&self.tools);
        eprintln!("[vpnd] kill-switch и IPv6-блок сняты по запросу");
        Ok(())
    }

    /// Разослать событие подписчикам, попутно вычистив отвалившихся.
    fn broadcast(&self, ev: EventMsg) {
        let mut sh = self.shared.lock().unwrap();
        sh.subs.retain(|s| s.send(ev.clone()).is_ok());
    }
}

/// Поток-супервизор одной сессии: обслуживает приватный канал движка.
fn supervise(d: Arc<Daemon>, chan: Arc<UnixStream>, generation: u64) {
    loop {
        let msg: Option<EngineMsg> = match read_frame(&mut &*chan) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[vpnd] канал движка: {e:#}");
                None
            }
        };
        let Some(msg) = msg else { break };
        match msg {
            EngineMsg::AllowExits(list) => match citadel_vpnd::valid::parse_allow_exits(&list) {
                Ok(ips) => {
                    let mut sh = d.shared.lock().unwrap();
                    let uid = Some(d.engine_uid);
                    sh.net.allow_exits(&d.tools, &ips, uid);
                }
                Err(e) => eprintln!("[vpnd] AllowExits отклонён: {e:#}"),
            },
            EngineMsg::TunSetup(req) => {
                let resp = configure_tunnel(&d, &chan, req);
                if let Err(e) = resp {
                    eprintln!("[vpnd] конфигурация туннеля отклонена: {e:#}");
                    let _ = write_frame(&mut &*chan, &DaemonMsg::TunError(format!("{e:#}")));
                }
            }
            EngineMsg::Event(ev) => {
                {
                    let mut sh = d.shared.lock().unwrap();
                    apply_event(&mut sh.status, &ev);
                }
                d.broadcast(ev);
            }
            EngineMsg::CleanShutdown => {
                d.shared.lock().unwrap().clean = true;
            }
        }
    }

    // Канал закрыт — движок завершился (штатно или упав). Сворачиваем сессию.
    let mut sh = d.shared.lock().unwrap();
    if sh.generation != generation {
        return; // нашу сессию уже сменила новая — ничего не трогаем
    }
    let clean = sh.clean;
    if let Some(mut s) = sh.session.take() {
        let _ = s.child.wait(); // не оставляем зомби
    }
    sh.net.teardown(&d.tools, clean);
    sh.status = idle_status();
    sh.status.killswitch_armed = sh.net.killswitch_armed(&d.tools);
    if !clean {
        sh.status.last_error = "сессия прервана (движок завершился неожиданно)".into();
    }
    drop(sh);
    d.broadcast(EventMsg::state("down"));
    eprintln!("[vpnd] сессия завершена ({})", if clean { "штатно" } else { "аварийно" });
}

/// Привилегированная часть: валидация запроса движка и настройка сети.
fn configure_tunnel(d: &Arc<Daemon>, chan: &Arc<UnixStream>, req: citadel_vpnd::proto::TunSetupReq) -> Result<()> {
    // Граница привилегий: движок недоверен ровно так же, как CLI (L2/L13).
    let setup = TunSetup::parse(&req).context("запрос движка не прошёл валидацию")?;
    let mut sh = d.shared.lock().unwrap();
    let uid = Some(d.engine_uid);
    let tun = sh.net.apply(&d.tools, &setup, uid)?;
    drop(sh);

    // Ответ + дескриптор: сперва кадр, следом однобайтовое сообщение с SCM_RIGHTS
    // (вложение нельзя вешать на сам кадр — движок читает его обычным read).
    write_frame(&mut &**chan, &DaemonMsg::TunReady)?;
    chan.send_with_fd(b"F", &[tun.as_raw_fd()]).context("передать TUN-fd движку")?;
    // Свой дескриптор закрываем: интерфейс должен исчезнуть, когда движок закроет свой.
    drop(tun);
    eprintln!("[vpnd] туннель поднят: {} mtu {}", setup.cidr(), setup.mtu);
    Ok(())
}

fn apply_event(st: &mut StatusInfo, ev: &EventMsg) {
    match ev.kind.as_str() {
        "state" => st.state = ev.state.clone(),
        "connected" => {
            st.state = "up".into();
            st.exit = sanitize_text(&ev.exit, 128);
            st.transport = sanitize_text(&ev.transport, 32);
            st.cidr = sanitize_text(&ev.cidr, 64);
            st.last_error.clear();
        }
        "error" => st.last_error = sanitize_text(&ev.error, 512),
        _ => {}
    }
}

fn idle_status() -> StatusInfo {
    StatusInfo {
        state: "idle".into(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        ..Default::default()
    }
}

// ───────────────────────────── системное окружение ─────────────────────────────

/// Обработчик SIGTERM/SIGINT через выделенный поток и `sigwait` (в самом обработчике сигнала
/// делать что-либо сложное нельзя — не async-signal-safe).
///
/// `systemctl stop` = осознанная остановка защиты: сессия рвётся ЧИСТО, kill-switch снимается,
/// иначе машина осталась бы без сети без явного действия человека. Цена — окно утечки при
/// `systemctl restart`; кто этого не хочет, включает `citadel-killswitch.service` (см. docs).
fn install_signal_handler(d: Arc<Daemon>, sock_path: String) {
    // SAFETY: маскируем сигналы до создания потоков — их унаследуют все дочерние потоки.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());

        std::thread::spawn(move || {
            let mut sig: libc::c_int = 0;
            libc::sigwait(&set, &mut sig);
            eprintln!("[vpnd] сигнал {sig} — штатная остановка");
            let _ = d.disconnect(0);
            {
                let mut sh = d.shared.lock().unwrap();
                sh.net.teardown(&d.tools, true);
            }
            let _ = std::fs::remove_file(&sock_path);
            std::process::exit(0);
        });
    }
}

/// uid/gid системного пользователя.
fn lookup_user(name: &str) -> Result<(u32, u32)> {
    let c = std::ffi::CString::new(name)?;
    // SAFETY: getpwnam возвращает указатель на статический буфер; читаем поля сразу.
    let pw = unsafe { libc::getpwnam(c.as_ptr()) };
    if pw.is_null() {
        bail!("пользователь не найден");
    }
    // SAFETY: указатель не null (проверен выше).
    let (uid, gid) = unsafe { ((*pw).pw_uid, (*pw).pw_gid) };
    Ok((uid, gid))
}

/// gid группы (None — группы нет).
fn lookup_group(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: как и getpwnam — читаем поле сразу после проверки на null.
    let gr = unsafe { libc::getgrnam(c.as_ptr()) };
    if gr.is_null() {
        return None;
    }
    Some(unsafe { (*gr).gr_gid })
}

/// Движок исполняется root-демоном, поэтому его бинарь обязан быть неизменяемым для не-root:
/// иначе любой, кто может его переписать, выполняет свой код — правда, уже без привилегий,
/// но с доступом к секретам сессии.
fn check_engine_binary(path: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(path)
        .with_context(|| format!("движок {path} не найден (проверь установку)"))?;
    if md.uid() != 0 {
        bail!("движок {path} принадлежит uid {} (не root)", md.uid());
    }
    if md.mode() & 0o022 != 0 {
        bail!("движок {path} писабелен группой/миром (mode {:o})", md.mode() & 0o7777);
    }
    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
