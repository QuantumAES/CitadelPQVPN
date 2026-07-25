//! `citadel-engine` — движок Linux-клиента, работающий **без привилегий**.
//!
//! Запускается только демоном `citadel-vpnd` (root), который перед `exec` сбрасывает
//! привилегии до системного пользователя `citadel-vpn`, ставит `NO_NEW_PRIVS`, запрещает
//! core-dump и оставляет один приватный сокет на fd 3.
//!
//! Здесь — и только здесь — разбирается **недоверенный ввод**: `citadel://`-ссылка, ответы
//! exit'а/issuer'а, сетевые пакеты (QUIC/obfs/MASQUE). Компрометация любого из этих парсеров
//! даёт атакующему обычного непривилегированного пользователя без capabilities, а не root (L13).
//! Всё привилегированное (TUN, маршруты, DNS, kill-switch) движок может только **попросить** у
//! демона кадром [`EngineMsg::TunSetup`], который тот валидирует заново.
//!
//! Конфиг с секретами приходит первым кадром по fd 3 — не через argv/env (L5).

use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use sendfd::RecvWithFd;

use citadel_client::{
    CredentialLink, SplitMode, SplitTunnel, TunIo, TunParams, TunProvider, VpnController, VpnEvent,
    VpnState,
};
use citadel_vpnd::proto::{
    read_frame, write_frame, ConnectReq, DaemonMsg, EngineMsg, EventMsg, TunSetupReq,
    ENGINE_CHANNEL_FD,
};

/// Сколько ждать ответа демона на запрос конфигурации туннеля (там могут идти `ip`/`iptables`).
const TUN_SETUP_TIMEOUT: Duration = Duration::from_secs(30);

fn main() -> Result<()> {
    // Единственный аргумент — маркер режима: движок не принимает НИКАКИХ параметров из argv
    // (секреты и настройки приходят кадром по приватному каналу).
    if std::env::args().len() > 1 {
        bail!("citadel-engine не принимает аргументов (запускается демоном citadel-vpnd)");
    }
    // Защита от запуска руками из-под root: движок обязан быть непривилегированным. Если его
    // всё же стартовали как root, дальше идти нельзя — иначе весь смысл privsep теряется.
    // SAFETY: getuid не имеет побочных эффектов.
    if unsafe { libc_getuid() } == 0 {
        bail!("citadel-engine не должен работать от root — его запускает citadel-vpnd с dropped privileges");
    }

    // SAFETY: fd 3 передан демоном при exec (socketpair), владения им больше ни у кого нет.
    let sock = unsafe { UnixStream::from_raw_fd(ENGINE_CHANNEL_FD) };
    let chan = Arc::new(Chan::new(sock));

    // Первый кадр — конфиг (со ссылкой). Ждать его блокирующе: без него делать нечего.
    let cfg_req: ConnectReq = match chan.read_daemon_msg()? {
        Some(DaemonMsg::Config(c)) => c,
        Some(other) => bail!("первым кадром ожидался Config, пришло {other:?}"),
        None => bail!("демон закрыл канал до передачи конфига"),
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("tokio runtime")?;
    let r = rt.block_on(run(chan.clone(), cfg_req));
    // Причину падения (битая ссылка, отказ провайдера) отправляем демону событием — иначе
    // пользователь видит лишь «сессия прервана», а объяснение остаётся в журнале службы.
    if let Err(e) = &r {
        let _ = chan.send(&EngineMsg::Event(EventMsg::error(&format!("{e:#}"))));
    }
    r
}

/// Разбор ссылки, запуск контроллера и трансляция событий демону.
async fn run(chan: Arc<Chan>, req: ConnectReq) -> Result<()> {
    let link = CredentialLink::from_uri(&req.link).context("разобрать citadel://-ссылку")?;
    let mut cfg = link.to_client_config();
    cfg.killswitch = req.killswitch;
    cfg.split = SplitTunnel {
        // Ось приложений на Linux пока не поддержана (нужны cgroup v2 + fwmark) — только назначения.
        app_mode: SplitMode::Off,
        apps: Vec::new(),
        dest_mode: SplitMode::parse(&req.split_mode),
        dests: req.split_dests.clone(),
    };

    let controller = Arc::new(VpnController::new());

    // C5.4b: свежий Layer-1 токен на КАЖДЫЙ establish (иначе exit ловит double-spend на реконнекте).
    if let (Some(iss), Some(pin), Some(seed)) = (link.issuer.clone(), link.issuer_pin, link.client_seed)
    {
        let obfs_psk = link.obfs_psk;
        controller.set_token_refresher(Arc::new(move || {
            let iss = iss.clone();
            Box::pin(async move {
                match citadel_client::token_agent::fetch_tokens(&iss, &pin, &seed, 1, 3, obfs_psk).await
                {
                    Ok(mut v) => v.pop(),
                    Err(e) => {
                        eprintln!("[engine] Layer-1 фетч у issuer {iss} не удался: {e:#}");
                        None
                    }
                }
            }) as std::pin::Pin<Box<dyn std::future::Future<Output = Option<Vec<u8>>> + Send>>
        }));
    }

    // Читатель приватного канала: Stop от демона + ответы на TunSetup (их маршрутизируем провайдеру).
    let (tun_tx, tun_rx) = std::sync::mpsc::channel::<TunReply>();
    {
        let chan = chan.clone();
        let ctl = controller.clone();
        std::thread::spawn(move || reader_loop(chan, ctl, tun_tx));
    }

    // События движка → демону (он их раздаёт подписчикам `citadel-cli`).
    let mut rx = controller.subscribe();
    {
        let chan = chan.clone();
        tokio::spawn(async move {
            while let Ok(ev) = rx.recv().await {
                if chan.send(&EngineMsg::Event(to_event(&ev))).is_err() {
                    break; // демон ушёл — сессии всё равно конец
                }
            }
        });
    }

    let provider: Arc<dyn TunProvider> = Arc::new(DaemonTunProvider {
        chan: chan.clone(),
        replies: Mutex::new(tun_rx),
    });

    // ДО первой попытки установки сессии просим демон открыть доступ к exit'ам и issuer'у.
    // Нужно ровно для одного, но важного случая: kill-switch остался армированным после
    // аварийного разрыва (fail-closed, как задумано) — без этого движок сам себе заблокирован,
    // establish не проходит, TunSetup не приходит, и сессия не поднимается никогда.
    // Резолв идёт через системный резолвер: если это имя и DNS тоже закрыт защитой, список
    // окажется пустым — тогда человеку остаётся `citadel-cli killswitch --disarm` (см. LINUX-CLI.md).
    let mut targets: Vec<String> = cfg.servers.clone();
    if let Some(iss) = &link.issuer {
        targets.push(iss.clone());
    }
    let ips = resolve_all(&targets).await;
    if !ips.is_empty() {
        let _ = chan.send(&EngineMsg::AllowExits(ips));
    }

    controller.begin();
    let r = controller.connect(cfg, provider).await;
    // Штатное завершение по Stop: сообщить демону, что disconnect ЧИСТЫЙ (снять kill-switch).
    // Падение движка сюда не доходит — демон увидит EOF без CleanShutdown и оставит fail-closed.
    if r.is_ok() {
        let _ = chan.send(&EngineMsg::CleanShutdown);
    }
    r
}

/// Резолвить `host:port` в список IP (дубликаты схлопываются). Литеральные адреса проходят
/// без обращения к DNS — поэтому ссылка с IP-адресом exit'а работает даже при закрытом резолвере.
async fn resolve_all(targets: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in targets {
        if let Ok(addrs) = tokio::net::lookup_host(t.as_str()).await {
            for a in addrs {
                let s = a.ip().to_string();
                if !out.contains(&s) {
                    out.push(s);
                }
            }
        }
    }
    out
}

/// Приватный канал к демону: сериализует записи (события и запросы идут из разных потоков).
struct Chan {
    sock: UnixStream,
    wlock: Mutex<()>,
}

impl Chan {
    fn new(sock: UnixStream) -> Chan {
        Chan { sock, wlock: Mutex::new(()) }
    }

    fn send(&self, msg: &EngineMsg) -> Result<()> {
        let _g = self.wlock.lock().unwrap();
        write_frame(&mut &self.sock, msg)
    }

    fn read_daemon_msg(&self) -> Result<Option<DaemonMsg>> {
        read_frame(&mut &self.sock)
    }

    /// Принять дескриптор туннеля, который демон досылает следом за `TunReady` отдельным
    /// однобайтовым сообщением с SCM_RIGHTS (кадр читается обычным `read`, поэтому вложение
    /// нельзя вешать на него самого — оно было бы отброшено).
    fn recv_tun_fd(&self) -> Result<i32> {
        let mut buf = [0u8; 1];
        let mut fds = [0i32; 1];
        let (_n, fdn) = self.sock.recv_with_fd(&mut buf, &mut fds).context("recv_with_fd")?;
        if fdn != 1 {
            bail!("демон не передал TUN-fd (получено дескрипторов: {fdn})");
        }
        Ok(fds[0])
    }
}

/// Ответ демона на запрос конфигурации туннеля.
enum TunReply {
    Ready(i32),
    Failed(String),
}

/// Единственный читатель канала: раздаёт ответы провайдеру и исполняет `Stop`.
fn reader_loop(chan: Arc<Chan>, ctl: Arc<VpnController>, tun_tx: Sender<TunReply>) {
    loop {
        match chan.read_daemon_msg() {
            Ok(Some(DaemonMsg::Stop)) => {
                eprintln!("[engine] демон запросил разрыв сессии");
                ctl.disconnect();
            }
            Ok(Some(DaemonMsg::TunReady)) => {
                let reply = match chan.recv_tun_fd() {
                    Ok(fd) => TunReply::Ready(fd),
                    Err(e) => TunReply::Failed(format!("{e:#}")),
                };
                let _ = tun_tx.send(reply);
            }
            Ok(Some(DaemonMsg::TunError(e))) => {
                let _ = tun_tx.send(TunReply::Failed(e));
            }
            Ok(Some(DaemonMsg::Config(_))) => {
                eprintln!("[engine] повторный Config проигнорирован (сессия уже настроена)");
            }
            Ok(None) => {
                // Демон закрыл канал (остановлен/упал) — тянуть туннель дальше нельзя.
                eprintln!("[engine] канал с демоном закрыт — завершаюсь");
                ctl.disconnect();
                return;
            }
            Err(e) => {
                eprintln!("[engine] ошибка чтения канала демона: {e:#}");
                ctl.disconnect();
                return;
            }
        }
    }
}

/// `TunProvider`, который просит привилегированную часть у демона. Аналог `GuiTunProvider`
/// (polkit-helper) и `WindowsTunProvider` (служба по named pipe) — та же роль, другой канал.
struct DaemonTunProvider {
    chan: Arc<Chan>,
    /// Ответы приходят из потока-читателя; `configure` вызывается контроллером строго
    /// последовательно, поэтому одного приёмника достаточно.
    replies: Mutex<Receiver<TunReply>>,
}

impl TunProvider for DaemonTunProvider {
    fn configure(&self, p: &TunParams) -> Result<Arc<dyn TunIo>> {
        // C8.3: разделить маршруты на «в туннель» и «в обход» тем же кодом, что Windows/GUI
        // (единый источник истины, включая инвариант «подсеть туннеля всегда в туннеле»).
        let (routes, bypass) = citadel_client::winnet::split_routes(
            p.dest_mode,
            &p.routes,
            &p.dest_routes,
            (p.addr, p.prefix),
        );
        let req = TunSetupReq {
            addr: p.addr,
            prefix: p.prefix,
            mtu: p.mtu.clone(),
            routes,
            dns: p.dns.clone(),
            exit_ips: p.exit_ips.clone(),
            killswitch: p.killswitch,
            bypass,
        };
        self.chan.send(&EngineMsg::TunSetup(req)).context("запросить конфигурацию туннеля")?;

        let rx = self.replies.lock().unwrap();
        match rx.recv_timeout(TUN_SETUP_TIMEOUT) {
            Ok(TunReply::Ready(fd)) => {
                // SAFETY: fd только что получен от демона по SCM_RIGHTS, владеем им единолично.
                Ok(unsafe { citadel_client::tun_from_fd(fd) })
            }
            Ok(TunReply::Failed(e)) => Err(anyhow!("демон отказал в конфигурации туннеля: {e}")),
            Err(e) => Err(anyhow!("нет ответа демона на конфигурацию туннеля: {e}")),
        }
    }
}

fn to_event(ev: &VpnEvent) -> EventMsg {
    match ev {
        VpnEvent::State(s) => EventMsg::state(state_str(*s)),
        VpnEvent::Connected { exit, transport, cidr } => EventMsg {
            kind: "connected".into(),
            state: "up".into(),
            exit: exit.clone(),
            transport: transport.clone(),
            cidr: cidr.clone(),
            error: String::new(),
        },
        VpnEvent::Error(e) => EventMsg::error(e),
    }
}

fn state_str(s: VpnState) -> &'static str {
    match s {
        VpnState::Idle => "idle",
        VpnState::Connecting => "connecting",
        VpnState::Up => "up",
        VpnState::Migrating => "migrating",
        VpnState::Down => "down",
    }
}

// `getuid(2)`: объявляем сами, чтобы не тянуть в движок отдельную зависимость ради одного вызова.
extern "C" {
    #[link_name = "getuid"]
    fn libc_getuid() -> u32;
}
