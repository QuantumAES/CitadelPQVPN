//! `VpnController` — высокоуровневый фасад движка для GUI/FFI.
//!
//! Оркеструет `establish_session` → конфигурацию туннеля через [`TunProvider`] →
//! `run_data_plane`, отдавая поток событий состояния. UI/FFI (Flutter, C0.6+) держит
//! `Arc<VpnController>`, зовёт [`VpnController::connect`]/[`VpnController::disconnect`]
//! и слушает [`VpnController::subscribe`]. Платформа туннеля скрыта за `TunProvider`
//! (Linux `/dev/net/tun`, Android `VpnService.Builder`) — см. docs/CLIENT-ARCH.md §4.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use tokio::sync::{broadcast, Notify};

use citadel_tun::TunIo;

use crate::client::{establish_session, run_data_plane};
use crate::config::{is_cidr, ClientConfig, SplitMode};

/// Стартовый интервал backoff между попытками восстановления соединения.
const RECONNECT_BACKOFF_START: Duration = Duration::from_secs(1);
/// Потолок backoff (после ряда неудач ретраим не реже, чем раз в 30с).
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Сколько держится вердикт «QUIC/UDP в этой сети не работает» (см. [`udp_unusable_recent`]).
/// Не навсегда: сеть могла и починиться (сменился APN/оператор перекрыл только на время), а
/// obfs-TCP дороже — TCP поверх TCP даёт head-of-line blocking у пользовательских соединений.
/// Раз в четверть часа лишняя четырёхсекундная проба QUIC — приемлемая цена за возврат к нему.
const UDP_VERDICT_TTL: Duration = Duration::from_secs(15 * 60);

/// Когда в последний раз QUIC/UDP оказался непригодным в текущей сети. Непригодность бывает двух
/// видов, и для выбора транспорта они равнозначны:
///   * хендшейк не проходит вовсе (порт фильтруется/DPI) — 5 попыток по 3с, то есть **15 секунд
///     ожидания** перед тем же самым obfs-TCP, и так на КАЖДОЕ подключение;
///   * сессия поднимается, но канал односторонний (см. `dataplane::PumpExit`).
///
/// Глобально на процесс, а не поле контроллера, СПЕЦИАЛЬНО: приложение создаёт НОВЫЙ
/// `VpnController` на каждое нажатие «Подключить» (см. `app/rust/src/api/citadel.rs`), и вердикт,
/// живущий в структуре, умирал бы вместе с ней — вместе с ним умирал бы и весь смысл.
static UDP_UNUSABLE: Mutex<Option<std::time::Instant>> = Mutex::new(None);

/// Отметить: QUIC/UDP в текущей сети не работает (не поднялся либо не несёт трафик).
fn note_udp_unusable() {
    *UDP_UNUSABLE.lock().unwrap() = Some(std::time::Instant::now());
}

/// Забыть вердикт (сменилась сеть / obfs-TCP оказался не лучше — судить QUIC не за что).
fn clear_udp_verdict() {
    *UDP_UNUSABLE.lock().unwrap() = None;
}

/// Свеж ли вердикт «QUIC/UDP здесь не работает» (в пределах [`UDP_VERDICT_TTL`]).
fn udp_unusable_recent() -> bool {
    matches!(*UDP_UNUSABLE.lock().unwrap(), Some(at) if at.elapsed() < UDP_VERDICT_TTL)
}

/// Состояние VPN-сессии.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VpnState {
    Idle,
    Connecting,
    Up,
    /// Миграция пути (WiFi↔LTE/NAT-rebind). Пока НЕ эмитится автоматически: миграция
    /// прозрачна на уровне `obfs_socket` (M4); проброс сигнала в события — follow-up.
    Migrating,
    Down,
}

/// Событие движка для UI/FFI.
#[derive(Clone, Debug)]
pub enum VpnEvent {
    /// Смена состояния.
    State(VpnState),
    /// Сессия установлена: выбранный exit, транспорт ("QUIC/UDP"|"obfs-TCP"), адрес (CIDR).
    Connected {
        exit: String,
        transport: String,
        cidr: String,
    },
    /// Ошибка установки/работы сессии.
    Error(String),
}

/// Параметры конфигурации туннеля: назначенный сервером адрес + сетевые настройки из конфига.
pub struct TunParams {
    pub addr: [u8; 4],
    pub prefix: u8,
    pub mtu: String,
    pub routes: String,
    pub dns: Option<String>,
    /// IP-адреса exit'ов для bypass-маршрута (Linux): собственные пакеты клиента к exit НЕ должны
    /// уходить в туннель при full-tunnel (`0.0.0.0/0`), иначе — петля маршрутизации и egress встаёт.
    /// На Android не используется (там `VpnService.protect()` исключает сокет из туннеля).
    pub exit_ips: Vec<String>,
    /// C6/M9 kill-switch: провайдер (Linux `citadel-helper`) ставит fail-closed firewall —
    /// не-туннельный трафик блокируется, пока туннель активен; переживает краш движка.
    pub killswitch: bool,
    /// C8.3 split-tunneling по приложениям (Android): режим + package-имена. Desktop игнорирует.
    pub app_mode: SplitMode,
    pub apps: Vec<String>,
    /// C8.3 split-tunneling по назначениям (Android): режим + УЖЕ РЕЗОЛВНУТЫЕ в CIDR назначения
    /// (домены раскрыты в `resolve_dests` до конфигурации TUN). Desktop игнорирует.
    pub dest_mode: SplitMode,
    pub dest_routes: Vec<String>,
}

/// C8.3: раскрыть записи назначений split-tunnel (`domain` | `IP` | `IP/prefix`) в список
/// **IPv4-CIDR** для маршрутов туннеля. CIDR/голый IP — напрямую (IP→`/32`); домен — резолв A-записей
/// → `/32` на каждый адрес. IPv6-назначения в MVP пропускаются (Android-маршруты v4; v6 — future).
/// Битые/нерезолвнутые записи молча отбрасываются. Зовётся на каждый establish (реконнект
/// перерезолвит — подхватит смену IP у CDN). Дубликаты схлопываются.
pub async fn resolve_dests(dests: &[String]) -> Vec<String> {
    use std::net::IpAddr;
    let mut out: Vec<String> = Vec::new();
    let push = |c: String, out: &mut Vec<String>| {
        if !out.contains(&c) {
            out.push(c);
        }
    };
    for raw in dests {
        let d = raw.trim();
        if d.is_empty() {
            continue;
        }
        if d.contains('/') {
            // CIDR (только IPv4)
            if is_cidr(d) {
                if let Some((ip, _)) = d.split_once('/') {
                    if ip.parse::<IpAddr>().map(|a| a.is_ipv4()).unwrap_or(false) {
                        push(d.to_string(), &mut out);
                    }
                }
            }
        } else if let Ok(a) = d.parse::<IpAddr>() {
            // голый IP
            if a.is_ipv4() {
                push(format!("{d}/32"), &mut out);
            }
        } else if let Ok(addrs) = tokio::net::lookup_host((d, 0u16)).await {
            // домен → A-записи
            for a in addrs {
                if let IpAddr::V4(v4) = a.ip() {
                    push(format!("{v4}/32"), &mut out);
                }
            }
        }
    }
    out
}

/// Платформенный провайдер туннеля: по назначенному адресу строит/конфигурирует TUN и
/// отдаёт пакетный I/O. Linux — `/dev/net/tun` + `ip`; Android — `VpnService.Builder.establish()`.
///
/// Вызывается **после** `establish_session` (адрес уже известен) — порядок, которого требуют
/// мобильные ОС (адрес скармливается билдеру ДО получения fd).
pub trait TunProvider: Send + Sync + 'static {
    fn configure(&self, p: &TunParams) -> Result<Arc<dyn TunIo>>;
}

/// Что абонент приносит от издателя перед establish: токен Layer-2 и — с H-3 — ключ L1 текущей
/// эпохи для канала данных. Оба живут ровно одну попытку подключения, поэтому и добываются вместе.
#[derive(Clone, Debug, Default)]
pub struct SessionGrant {
    pub token: Vec<u8>,
    /// `None` — ротация L1 не настроена (сервер отдаёт данные под бутстрапным PSK из ссылки).
    pub data_psk: Option<[u8; 32]>,
}

/// Асинхронный добытчик свежего Layer-1 токена: зовётся перед КАЖДЫМ establish (в т.ч. реконнект),
/// чтобы не переиспользовать потраченный токен (exit ловит double-spend, M4/M5). `None` из замыкания —
/// токен не обновляем (token-less exit / нет Layer-1). Ставится приложением ([`VpnController::set_token_refresher`]).
pub type TokenRefresher = Arc<
    dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<SessionGrant>> + Send>>
        + Send
        + Sync,
>;

/// Высокоуровневый контроллер VPN-сессии. Потокобезопасен; для фонового запуска
/// держится в `Arc` и `connect` крутится в `tokio::spawn`, а `disconnect` зовётся из UI-потока.
pub struct VpnController {
    state: Mutex<VpnState>,
    events: broadcast::Sender<VpnEvent>,
    shutdown: Notify,
    /// Сигнал «сменилась underlying-сеть» (Android NetworkCallback): будит connect-loop оборвать
    /// текущий pump и НЕМЕДЛЕННО переустановить сессию над новой сетью — не ждать pump-watchdog
    /// (~8с) / QUIC idle-timeout. В отличие от [`shutdown`] — НЕ персистентный флаг: пропущенный
    /// сигнал (пришёл вне `select!`, напр. в фазе establish) безвреден, т.к. следующий establish и
    /// так идёт над новой сетью (`setUnderlyingNetworks` уже применён нативно).
    network_changed: Notify,
    /// Пользователь запросил разрыв — глушит авто-реконнект. Persistent-флаг (не только `Notify`)
    /// закрывает гонку: disconnect между итерациями цикла не теряется.
    stopped: AtomicBool,
    /// Добытчик свежего токена на каждый establish (реконнект-безопасность).
    token_refresh: Mutex<Option<TokenRefresher>>,
}

impl Default for VpnController {
    fn default() -> Self {
        Self::new()
    }
}

impl VpnController {
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(64);
        Self {
            state: Mutex::new(VpnState::Idle),
            events,
            shutdown: Notify::new(),
            network_changed: Notify::new(),
            stopped: AtomicBool::new(false),
            token_refresh: Mutex::new(None),
        }
    }

    /// Задать добытчик свежего Layer-1 токена (зовётся перед каждым establish). Приложение
    /// передаёт замыкание с `token_agent`, чтобы реконнект брал НОВЫЙ токен, а не потраченный.
    pub fn set_token_refresher(&self, f: TokenRefresher) {
        *self.token_refresh.lock().unwrap() = Some(f);
    }

    /// Подписаться на поток событий (несколько подписчиков допустимы).
    pub fn subscribe(&self) -> broadcast::Receiver<VpnEvent> {
        self.events.subscribe()
    }

    /// Текущее состояние.
    pub fn state(&self) -> VpnState {
        *self.state.lock().unwrap()
    }

    fn set_state(&self, s: VpnState) {
        *self.state.lock().unwrap() = s;
        let _ = self.events.send(VpnEvent::State(s)); // Err только если нет подписчиков — игнор
    }

    fn emit(&self, e: VpnEvent) {
        let _ = self.events.send(e);
    }

    /// Отметить начало подключения ДО вызова [`connect`] — для pre-connect шагов в GUI-мосте
    /// (напр. добыча Layer-1 токена у issuer, C5.4b): UI сразу видит «подключаемся», а не висит
    /// в idle пока идёт фетч. Затем вызывающий зовёт [`connect`] (он повторно выставит Connecting —
    /// идемпотентно) либо при неудаче шага — [`fail`].
    pub fn begin(&self) {
        self.set_state(VpnState::Connecting);
    }

    /// Сообщить о фатальной ошибке pre-connect шага (эмитит `Error` + переводит в `Down`), чтобы
    /// UI вышел из спиннера, а не завис. Используется, когда до [`connect`] дело не дошло (напр.
    /// не удалось получить токен доступа).
    pub fn fail(&self, msg: String) {
        // Дублируем в журнал: интерфейс покажет человеку короткий итог, а причина должна
        // оставаться в логе отладки — иначе разбирать отказ будет нечем.
        eprintln!("[vpn] отказ до подключения: {msg}");
        self.emit(VpnEvent::Error(msg));
        self.set_state(VpnState::Down);
    }

    /// Поднять VPN и **держать соединение живым**, пока пользователь не позовёт `disconnect`.
    ///
    /// Первичный коннект: `establish` → `provider.configure` → `data_plane`. При неудаче
    /// первичного коннекта — сразу ошибка (пользователь должен увидеть причину: битый конфиг,
    /// недоступный exit и т.п.). После того как соединение **хотя бы раз поднялось**, при разрыве
    /// транспорта (или падении data-plane) — **авто-реконнект с прогрессивным backoff**
    /// (1→2→4→…→30с, сброс после успеха), пока `disconnect` не остановит. Мягкие смены пути
    /// (WiFi↔LTE/NAT-rebind) прозрачны на уровне QUIC-миграции и сюда не доходят.
    ///
    /// Для фонового запуска — `tokio::spawn` с `Arc<VpnController>`. События — через `subscribe`.
    pub async fn connect(&self, mut cfg: ClientConfig, provider: Arc<dyn TunProvider>) -> Result<()> {
        self.stopped.store(false, Ordering::SeqCst);
        self.set_state(VpnState::Connecting);
        let mut backoff = RECONNECT_BACKOFF_START;
        let mut ever_up = false;
        // Лежит ли в `cfg.token` НЕПРЕДЪЯВЛЕННЫЙ токен. Потраченный слать повторно нельзя (exit
        // ловит double-spend → «auth-failed»), а непотраченный — обязательно нужно: попытка,
        // которая не дошла до control-обмена (закрытый порт, нет сети, разошёлся ключ L1), токен
        // не тратит, и брать новый значило бы жечь квоту эпохи абонента (A6) на каждый ретрай.
        // Стартовое значение: непустой токен из конфига (CLI/`Citadel_TOKENS`) ещё не предъявлялся.
        let mut have_unspent_token = !cfg.token.is_empty();
        // Была ли уже хоть одна попытка establish. Нужно ровно для одного случая: на самой первой
        // итерации без токена мы идём к exit'у как есть — чтобы человек увидел настоящий отказ
        // token-required exit'а, а не молчаливое ожидание.
        let mut attempted = false;
        // Идти ли сразу obfs-TCP. Ставится, когда QUIC/UDP в этой сети уже показал себя негодным:
        // либо не поднялся вовсе (порт фильтруется), либо сессия оказалась ОДНОСТОРОННЕЙ (наши
        // датаграммы не доезжают — см. `dataplane::PumpExit`). Повтор тем же транспортом упирается
        // ровно в то же самое. Начальное значение — из вердикта ПРОШЛОГО подключения (см.
        // [`udp_unusable_recent`]): сеть за минуту не меняется, а платит за повторную пробу
        // человек — пятнадцатью секундами таймаутов QUIC либо мёртвым туннелем и лишним токеном.
        let mut prefer_tcp = udp_unusable_recent() && cfg.transport_psk().is_some();
        // Источник предпочтения: вердикт о СЕТИ (протухает) или разовое решение «сменить транспорт
        // после петли» (протухание к нему не относится — иначе следующая же итерация вернула бы нас
        // в тот самый транспорт, из-за которого рвались, и получилось бы мигание).
        let mut tcp_by_verdict = prefer_tcp;
        if prefer_tcp {
            eprintln!(
                "[vpn] в этой сети QUIC/UDP уже не работал — начинаю сразу с obfs-TCP, не тратя \
                 попытки на UDP (вердикт сбрасывается сменой сети и через {} мин)",
                UDP_VERDICT_TTL.as_secs() / 60
            );
        }

        loop {
            if self.stopped.load(Ordering::SeqCst) {
                return self.finish_stopped();
            }
            // Вердикт о QUIC/UDP протух — пробуем его снова. Иначе долгоживущая сессия (десктоп
            // сутками, телефон — до смены сети) залипала бы на obfs-TCP навсегда, хотя срок,
            // который мы сами себе назначили, давно вышел: TTL обязан значить одно и то же и между
            // подключениями, и внутри одного.
            if prefer_tcp && tcp_by_verdict && !udp_unusable_recent() {
                eprintln!("[vpn] вердикт о QUIC/UDP протух — следующая попытка снова начнётся с UDP");
                prefer_tcp = false;
                tcp_by_verdict = false;
            }

            // Свежий Layer-1 токен на КАЖДУЮ попытку establish: реконнект НЕ должен переиспользовать
            // потраченный токен — exit отвергнет его как double-spend (M4/M5) и порвёт control-стрим.
            // Недоступен issuer → None → establish покажет отказ token-required exit, цикл ретраит
            // (само-лечится по восстановлении сети). token-less/без Layer-1 → refresher не задан.
            let refresher = self.token_refresh.lock().unwrap().clone();
            // К издателю идём, ТОЛЬКО если предъявлять нечего. Раньше сюда заходили на каждой
            // итерации, и шторм ретраев к недоступному exit'у выгребал квоту эпохи (A6): после
            // ~64 неудачных попыток издатель прекращал выдачу, и абонент оставался без связи до
            // конца эпохи — с диагнозом «издатель не ответил на первый ослеплённый элемент».
            if let (Some(f), false) = (&refresher, have_unspent_token) {
                // Фаза может тянуться (издатель недоступен → таймауты+ретраи), а пользователь
                // вправе нажать «Отключить» прямо в ней: ждём токен, но не дольше, чем до отмены.
                let Some(fetched) = self.until_stop(f()).await else {
                    return self.finish_stopped();
                };
                match fetched {
                    Some(g) => {
                        // Свежий токен — этой попытке есть что предъявить. Судьбу флага решает
                        // исход самой попытки (`match established` ниже), поэтому здесь его не
                        // трогаем: любое значение всё равно было бы перезаписано.
                        cfg.token = g.token;
                        // H-3: ключ L1 текущей эпохи приезжает тем же заходом. Не затираем прежний,
                        // если издатель ротацию не настроил (`None`) — иначе рабочая сессия после
                        // обновления сервера «теряла» бы ключ на ровном месте.
                        if g.data_psk.is_some() {
                            cfg.data_psk = g.data_psk;
                        }
                    }
                    // Свежего токена нет (issuer недоступен ЛИБО держит single-session-аренду 4/B
                    // после предыдущей сессии). Идти к exit'у с потраченным токеном бессмысленно —
                    // он ответит «auth-failed», и в UI встанет ложная причина. Ждём и пробуем снова.
                    None if attempted => {
                        let why = "нет свежего Layer-1 токена (issuer недоступен или ещё держит \
                                   аренду прошлой сессии) — жду и пробую снова";
                        self.emit(VpnEvent::Error(why.into()));
                        eprintln!("[vpn] {why} (через {backoff:?})");
                        self.set_state(if ever_up { VpnState::Migrating } else { VpnState::Connecting });
                        match self.backoff_wait(backoff).await {
                            Some(next) => backoff = next,
                            None => return self.finish_stopped(),
                        }
                        continue;
                    }
                    None => {} // первый заход: пусть exit сам скажет, что требует токен
                }
            }
            attempted = true;

            // ── establish: сперва QUIC/UDP ──
            // Самая длинная фаза цикла (до 5 попыток QUIC по 3с + obfs-TCP): «Отключить» обязано
            // прерывать её здесь, а не после. Иначе цикл доводил попытку до конца УЖЕ ПОСЛЕ
            // остановки — и лез конфигурировать TUN поверх погашенного сервиса (на Android это и
            // был «CitadelVpnService не зарегистрирован» в логе), а на desktop мог поднять туннель
            // и kill-switch заново, когда пользователь их только что снял.
            if prefer_tcp {
                eprintln!(
                    "[vpn] поднимаю сессию сразу obfs-TCP: QUIC/UDP на этой сети оказался \
                     односторонним (сегментация переживает узкий MTU и потери)"
                );
            }
            let Some(mut established) = self.until_stop(establish_session(&cfg, prefer_tcp)).await
            else {
                return self.finish_stopped();
            };
            // Эскалация на obfs-TCP: QUIC мог подняться (хендшейк), но крупный control-обмен не прошёл —
            // мобильный/NAT64-путь не несёт большой ML-DSA-ответ через QUIC (MTU: хендшейк ок, ответ
            // чёрнодырится → establish виснет). TCP решает это сегментацией/MSS. Токен берём свежий
            // (прошлый спенчен сервером на QUIC-попытке → иначе double-spend). Только при наличии
            // obfs-канала И только если отказ вообще лечится сменой транспорта (см. should_escalate_to_tcp:
            // иначе жжём второй токен и подменяем настоящую причину бесполезным «auth-failed»).
            if let Err(e) = &established {
                let first = format!("{e:#}");
                let quic_spent = e.token_presented;
                // `!prefer_tcp`: эскалировать на obfs-TCP с попытки, которая УЖЕ шла obfs-TCP,
                // бессмысленно — это был бы второй заход тем же транспортом ценой второго токена.
                if !prefer_tcp && cfg.transport_psk().is_some() && should_escalate_to_tcp(&first) {
                    eprintln!("[vpn] establish/QUIC не удался ({first}) — эскалация на obfs-TCP (мобильный MTU/NAT64?)");
                    // Второй токен берём, ТОЛЬКО если первый действительно ушёл exit'у на
                    // QUIC-попытке. Иначе идём тем же — эскалация не должна стоить абоненту
                    // лишней единицы квоты (это ровно то, что жгло её на мобильной сети).
                    let mut replaced = false;
                    if let (Some(f), true) = (&refresher, quic_spent) {
                        let Some(fresh) = self.until_stop(f()).await else {
                            return self.finish_stopped();
                        };
                        if let Some(g) = fresh {
                            cfg.token = g.token;
                            replaced = true;
                            if g.data_psk.is_some() {
                                cfg.data_psk = g.data_psk; // H-3: ключ мог смениться на границе эпохи
                            }
                        }
                    }
                    // Причину QUIC-попытки тащим в итоговую ошибку: без неё в UI оставалась бы только
                    // вторая (часто менее информативная), и диагноз уходил в сторону.
                    let Some(second) = self.until_stop(establish_session(&cfg, true)).await else {
                        return self.finish_stopped();
                    };
                    established = second.map_err(|e2| crate::client::EstablishError {
                        // Про токен, который сейчас в cfg: он потрачен, если его предъявила
                        // TCP-попытка ЛИБО если это по-прежнему тот же токен, что сгорел на QUIC
                        // (свежий взять не удалось — издатель недоступен).
                        token_presented: e2.token_presented || (quic_spent && !replaced),
                        source: anyhow::anyhow!("{e2:#}; ранее по QUIC/UDP: {first}"),
                    });
                }
            }
            let session = match established {
                Ok(s) => {
                    have_unspent_token = false; // токен предъявлен и принят — реконнекту нужен новый
                    s
                }
                Err(e) => {
                    // Токен, не дошедший до control-обмена, остаётся у нас и пойдёт в следующую
                    // попытку. Это и есть починка «квота кончилась после шторма ретраев».
                    //
                    // Второе условие обязательно: флаг означает «непредъявленный токен ЛЕЖИТ У
                    // НАС», а не «токен не предъявлен». Попытка, не доехавшая до exit'а (сети
                    // нет), токен не предъявляет — и цикл записывал себе на руки токен, которого
                    // никогда не было. К издателю он после этого не возвращался НИКОГДА, оставаясь
                    // с пустым токеном и БУТСТРАПНЫМ ключом L1: при включённой ротации (H-3) exit
                    // молча дропает такие пакеты, и в журнале это выглядит как закрытый порт
                    // («QUIC/UDP и obfs-TCP недоступны») — бесконечно. Подключение, начатое ДО
                    // появления сети, из-за этого не поднималось и после её появления; лечило
                    // только ручное «Отключить/Подключить» (новый `connect` считает флаг заново).
                    have_unspent_token = !e.token_presented && !cfg.token.is_empty();
                    // Принудительный obfs-TCP не поднялся (порт 443 закрыт/фильтруется) — снимаем
                    // предпочтение, иначе застряли бы на заведомо мёртвом транспорте навсегда.
                    // Обычный порядок сам попробует QUIC, а при его недоступности — тот же TCP.
                    if prefer_tcp {
                        eprintln!("[vpn] obfs-TCP тоже не поднялся — возвращаюсь к обычному порядку транспортов");
                        prefer_tcp = false;
                        tcp_by_verdict = false;
                        // И вердикт о QUIC забываем: он вёл нас в транспорт, который здесь не
                        // поднимается вовсе. Пусть следующая попытка идёт обычным порядком.
                        clear_udp_verdict();
                    }
                    // Ретраим ВСЕГДА, в т.ч. ПЕРВЫЙ коннект: сеть/issuer могли быть недоступны на
                    // старте (подключились до появления сети) — по восстановлении следующая попытка
                    // возьмёт свежий токен и поднимется. Причину показываем (Error), но не сдаёмся до
                    // disconnect (стандартное поведение VPN «connecting…»). Пользователь остановит сам.
                    self.emit(VpnEvent::Error(format!("{e:#}")));
                    eprintln!("[vpn] establish не удался: {e:#} — ретрай через {:?}", backoff);
                    self.set_state(if ever_up { VpnState::Migrating } else { VpnState::Connecting });
                    match self.backoff_wait(backoff).await {
                        Some(next) => backoff = next,
                        None => return self.finish_stopped(),
                    }
                    continue;
                }
            };
            // Сессия могла подняться уже ПОСЛЕ «Отключить» (пользователь нажал, пока шёл establish):
            // показывать «Подключено» и тем более строить TUN здесь нельзя — гасим транспорт (drop
            // закрывает соединение) и выходим.
            if self.stopped.load(Ordering::SeqCst) {
                drop(session);
                return self.finish_stopped();
            }
            self.emit(VpnEvent::Connected {
                exit: session.chosen.clone(),
                transport: session.transport().to_string(),
                cidr: session.cidr(),
            });
            // Сессия поднялась поверх obfs-TCP, хотя мы его НЕ навязывали ⇒ QUIC/UDP в этой сети не
            // прошёл хендшейк (порт фильтруется/DPI). Это ровно тот же вердикт о сети, что и
            // односторонний канал, и запоминать его надо здесь: иначе каждое следующее подключение
            // снова платит 5 попытками QUIC по 3с — 15 секунд ожидания перед тем же самым
            // obfs-TCP. Если TCP мы навязали сами, судить UDP не по чему: его не пробовали.
            if session.over_tcp() && !prefer_tcp {
                eprintln!(
                    "[vpn] QUIC/UDP в этой сети не поднялся, работаем поверх obfs-TCP — запоминаю \
                     на {} мин, чтобы следующее подключение не ждало таймаутов UDP",
                    UDP_VERDICT_TTL.as_secs() / 60
                );
                note_udp_unusable();
                // И в ЭТОМ цикле тоже: иначе каждый реконнект (а на мобильной сети их много)
                // заново платил бы теми же пятнадцатью секундами за уже известный ответ.
                prefer_tcp = cfg.transport_psk().is_some();
                tcp_by_verdict = true;
            }

            // Собрать IP всех сконфигурированных exit'ов (+ фактический peer) для bypass-маршрута:
            // при full-tunnel исключаем их из туннеля, иначе собственный QUIC/obfs-трафик к exit
            // заворачивается обратно в citadel0 → петля, egress встаёт (см. TunParams::exit_ips).
            let mut exit_ips = std::collections::BTreeSet::new();
            exit_ips.insert(session.peer_addr().ip().to_string());
            for s in &cfg.servers {
                if let Ok(addrs) = tokio::net::lookup_host(s).await {
                    for a in addrs {
                        exit_ips.insert(a.ip().to_string());
                    }
                }
            }

            // C8.3: раскрыть домены назначений в CIDR (на каждый establish — реконнект перерезолвит).
            // Пустой результат Include/Exclude → трактуем как Off (не строим туннель, который ничего
            // не маршрутизирует / нечего исключать).
            let dest_routes = if cfg.split.dest_mode != SplitMode::Off {
                resolve_dests(&cfg.split.dests).await
            } else {
                Vec::new()
            };
            let dest_mode = if dest_routes.is_empty() { SplitMode::Off } else { cfg.split.dest_mode };

            // Конфигурируем туннель ПОД назначенный адрес (на Android — VpnService.Builder).
            // На реконнекте адрес может смениться — TUN пере-конфигурируется под новый; polkit с
            // auth_admin_keep не переспрашивает пароль в пределах сессии.
            let params = TunParams {
                addr: session.addr,
                prefix: session.prefix,
                mtu: clamp_tun_mtu(&cfg.mtu, session.quic_datagram_mtu()),
                routes: cfg.routes.clone(),
                dns: cfg.dns.clone(),
                exit_ips: exit_ips.into_iter().collect(),
                killswitch: cfg.killswitch,
                app_mode: cfg.split.app_mode,
                apps: cfg.split.apps.clone(),
                dest_mode,
                dest_routes,
            };
            // Последняя проверка перед привилегированной операцией: между establish и этим местом
            // были резолвы (exit_ips, назначения split'а), и «Отключить» могло прийти в них.
            // `configure` уже НЕ отменяем — он синхронный и идёт в платформенный сервис/helper.
            if self.stopped.load(Ordering::SeqCst) {
                return self.finish_stopped();
            }
            let tun = match provider.configure(&params) {
                Ok(t) => t,
                Err(e) => {
                    if !ever_up {
                        // В журнал — полная цепочка причин: интерфейс показывает человеку итог
                        // («сервер недоступен»), а разбираться приходится по логу.
                        eprintln!("[vpn] configure TUN не удался: {e:#}");
                        self.emit(VpnEvent::Error(format!("{e:#}")));
                        self.set_state(VpnState::Down);
                        return Err(e);
                    }
                    eprintln!("[vpn] реконнект: configure TUN не удался: {e:#} — ретрай через {:?}", backoff);
                    self.set_state(VpnState::Migrating);
                    match self.backoff_wait(backoff).await {
                        Some(next) => backoff = next,
                        None => return self.finish_stopped(),
                    }
                    continue;
                }
            };

            self.set_state(VpnState::Up);
            ever_up = true;
            backoff = RECONNECT_BACKOFF_START; // успех — сбрасываем backoff

            // data-plane крутится до разрыва транспорта ИЛИ до disconnect (тогда future data-plane
            // дропается → транспорт (QUIC/TCP) закрывается при drop, TUN сворачивается).
            // Клон для сигнала ЧИСТОГО disconnect: на shutdown-ветке зовём clean_shutdown() ДО дропа
            // (Linux GuiTun шлёт 'Q' → helper снимает kill-switch). На реконнекте не зовём → KS остаётся.
            let tun_ctrl = tun.clone();
            let mut net_changed = false;
            // Каким транспортом жила эта сессия — нужно ПОСЛЕ неё (session уезжает в data-plane).
            let via_tcp = session.over_tcp();
            let r = tokio::select! {
                r = run_data_plane(session, tun) => r,
                // `cancelled` (а не голый `shutdown.notified()`): disconnect, пришедший ДО входа в
                // select (например, пока шёл configure), иначе потерялся бы — туннель остался бы
                // жить до следующего разрыва транспорта.
                _ = self.cancelled() => {
                    eprintln!("[vpn] disconnect — закрываю сессию");
                    tun_ctrl.clean_shutdown();
                    self.set_state(VpnState::Down);
                    return Ok(());
                }
                _ = self.network_changed.notified() => {
                    // Смена сети (Android): путь над старой сетью, скорее всего, мёртв — рвём pump и
                    // реконнектимся над новой СРАЗУ, не дожидаясь pump-watchdog / QUIC idle-timeout.
                    // Не глушит авто-реконнект (в отличие от disconnect): loop идёт на следующую итерацию.
                    eprintln!("[vpn] смена сети — переустанавливаю сессию над новой сетью");
                    net_changed = true;
                    Ok(Default::default())
                }
            };
            drop(tun_ctrl); // реконнект: закрыть старый TUN/сокет сейчас (helper EOF без 'Q' → KS держится)
            if self.stopped.load(Ordering::SeqCst) {
                return self.finish_stopped();
            }

            // Сменилась сеть — прежний вердикт о QUIC/UDP относился к ПРОШЛОЙ сети и здесь ничего
            // не значит: над новой QUIC может быть и лучшим транспортом. Судим заново.
            if net_changed {
                clear_udp_verdict();
                prefer_tcp = false;
                tcp_by_verdict = false;
            }
            // Односторонний путь (наши датаграммы не доезжали до exit'а) лечится сменой
            // транспорта, а не повтором: следующую попытку делаем сразу obfs-TCP. Если
            // односторонним оказался УЖЕ obfs-TCP — дело не в транспорте, возвращаемся к обычному
            // порядку (QUIC/UDP сперва), иначе застряли бы на TCP навсегда.
            if matches!(&r, Ok(x) if x.uplink_dead) {
                prefer_tcp = !via_tcp && cfg.transport_psk().is_some();
                // Вердикт переживает и эту сессию, и весь контроллер: следующее нажатие
                // «Подключить» не должно снова упираться в те же 4с мёртвого QUIC. Но записываем
                // его, ТОЛЬКО если беда действительно про сеть: петля (`looped`) — наша поломка
                // (сокет не исключён из туннеля), и «запомнить» её значило бы навсегда молча
                // уходить на obfs-TCP вместо того, чтобы её увидеть. Транспорт на эту сессию всё
                // равно меняем: obfs-TCP свой сокет защищает и связь даст.
                if via_tcp || matches!(&r, Ok(x) if x.looped) {
                    clear_udp_verdict();
                    tcp_by_verdict = false; // разовое переключение, а не приговор сети
                } else {
                    note_udp_unusable();
                    tcp_by_verdict = true;
                }
            }
            // Транспорт упал сам (не пользователь) → авто-реконнект.
            if !net_changed {
                match r {
                    Ok(_) => eprintln!("[vpn] транспорт закрылся — восстанавливаю соединение"),
                    Err(e) => eprintln!("[vpn] data-plane упал: {e} — восстанавливаю соединение"),
                }
            }
            self.set_state(VpnState::Migrating);
            // Смена сети → реконнект немедленный (новая сеть уже поднята) — сбрасываем backoff и НЕ
            // спим. Иначе — прогрессивный backoff между попытками (сеть/exit могут быть ещё недоступны).
            if net_changed {
                backoff = RECONNECT_BACKOFF_START;
            } else {
                match self.backoff_wait(backoff).await {
                    Some(next) => backoff = next,
                    None => return self.finish_stopped(),
                }
            }
        }
    }

    /// Ждать запроса на разрыв ([`disconnect`]). Возвращается ТОЛЬКО когда сессию остановили.
    ///
    /// Гонку «сигнал пришёл между проверкой флага и подпиской» закрывает порядок: сначала
    /// регистрируем ожидание (`enable`), и лишь потом читаем `stopped`. Так `disconnect`, успевший
    /// пройти до подписки, виден по флагу, а успевший после — будит `notify_waiters`. Без этого
    /// пропущенный сигнал означал бы туннель, живущий после нажатия «Отключить».
    async fn cancelled(&self) {
        loop {
            let notified = self.shutdown.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.stopped.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
            if self.stopped.load(Ordering::SeqCst) {
                return;
            }
        }
    }

    /// Выполнить длинную фазу подключения, прерываясь на `disconnect`. `None` — сессию остановили
    /// (вызывающий обязан свернуться, ничего не поднимая).
    async fn until_stop<T>(&self, fut: impl std::future::Future<Output = T>) -> Option<T> {
        tokio::select! {
            biased; // отмена важнее результата фазы: оба готовы — выигрывает пользователь
            _ = self.cancelled() => None,
            v = fut => Some(v),
        }
    }

    /// Общий выход из `connect` по запросу пользователя: состояние `Down`, ошибки нет.
    fn finish_stopped(&self) -> Result<()> {
        self.set_state(VpnState::Down);
        Ok(())
    }

    /// Пауза перед следующей попыткой реконнекта. Возвращает backoff для СЛЕДУЮЩЕЙ паузы либо
    /// `None`, если пользователь остановил сессию (вызывающий выходит из цикла).
    ///
    /// Просыпается досрочно не только на `disconnect`, но и на смену сети: без этого возврат связи
    /// (сеть появилась после «нет сети вовсе») ждал бы истечения текущего backoff — до 30с при
    /// уже доступном интернете. Сигнал есть ровно тогда, когда ОС сообщила о новой underlying-сети,
    /// поэтому backoff при нём сбрасывается: это не «очередная неудачная попытка», а новые условия.
    async fn backoff_wait(&self, cur: Duration) -> Option<Duration> {
        if self.stopped.load(Ordering::SeqCst) {
            return None;
        }
        tokio::select! {
            biased;
            _ = self.cancelled() => None,
            _ = tokio::time::sleep(cur) => {
                if self.stopped.load(Ordering::SeqCst) { None } else { Some(next_backoff(cur)) }
            }
            _ = self.network_changed.notified() => {
                eprintln!("[vpn] смена сети во время паузы реконнекта — пробую сразу");
                Some(RECONNECT_BACKOFF_START)
            }
        }
    }

    /// Запросить разрыв активной сессии и остановить авто-реконнект (persistent-флаг + будим
    /// `connect`). Безопасно в любом состоянии (нет активной сессии → no-op).
    pub fn disconnect(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.shutdown.notify_waiters();
    }

    /// Запрошен ли разрыв ([`disconnect`]). Наблюдаемость для мостов/тестов: состояние (`state()`)
    /// на `disconnect` меняется не сразу (loop сворачивается асинхронно), поэтому «сессию погасили»
    /// по нему не отличить от «сессия жива». Нужно, чтобы фиксировать инвариант «операции с
    /// хранилищем не трогают туннель» (см. `vault_lock` в app/rust).
    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    /// Сигнал «сменилась underlying-сеть» (Android NetworkCallback: WiFi↔LTE/toggle): оборвать
    /// текущий pump и немедленно переустановить сессию над новой сетью. НЕ глушит авто-реконнект
    /// (в отличие от [`disconnect`]). Безопасно в любом состоянии: если активного pump нет,
    /// `notify_waiters` не запоминает сигнал — следующий establish и так пойдёт над новой сетью.
    pub fn notify_network_changed(&self) {
        self.network_changed.notify_waiters();
    }
}

/// Следующий backoff: удвоение с потолком [`RECONNECT_BACKOFF_MAX`].
fn next_backoff(cur: Duration) -> Duration {
    (cur * 2).min(RECONNECT_BACKOFF_MAX)
}

/// Стоит ли после неудачи QUIC-establish эскалировать на obfs-TCP. Эскалация лечит РОВНО один класс
/// отказов: транспорт поднялся, а крупный control-обмен (ML-DSA pub+sig, ~5 КБ) не прошёл — на
/// мобильном/NAT64-пути его чёрнодырит по MTU, и TCP решает это сегментацией.
///
/// Отказ «по существу» так не лечится, а цена ошибки высокая: вторая попытка ПРЕДЪЯВЛЯЕТ ЕЩЁ ОДИН
/// токен (issuer выдаёт их под single-session-аренду 4/B — запас не бесконечен), а в UI/лог уезжает
/// последняя, бесполезная причина («auth-failed») вместо настоящей. Поэтому не эскалируем, если exit
/// отказал осознанно (токен/double-spend/пул), не сошлась PQ-auth, не настроен pin или exit вовсе
/// недоступен (в этом случае `connect_server` уже пробовал obfs-TCP сам — второй заход бессмыслен).
fn should_escalate_to_tcp(err: &str) -> bool {
    let e = err.to_lowercase();
    const HARD_REFUSALS: &[&str] = &[
        "auth-failed",      // exit закрыл сессию: токен отвергнут / пул адресов исчерпан
        "double-spend",
        "токен",            // «невалидный токен», «токен уже использован», «токен не задан»
        "pq-auth",          // подпись ML-DSA / commitment не сошлись
        "pin",              // fail-closed по серт-pin (S0.1/H2)
        "недоступен",       // «ни один exit недоступен» — TCP-fallback уже пробовался внутри
    ];
    !HARD_REFUSALS.iter().any(|m| e.contains(m))
}

/// Ужать `cfg_mtu` под бюджет QUIC-датаграммы (`budget` от [`crate::client::Session::quic_datagram_mtu`]):
/// если сконфигурированный MTU больше бюджета — вернуть бюджет (иначе полноразмерные пакеты
/// дропаются в pump «datagram too large»). `None` (obfs-TCP) или MTU ≤ бюджета — оставить как есть.
pub fn clamp_tun_mtu(cfg_mtu: &str, budget: Option<usize>) -> String {
    let cur: usize = cfg_mtu.parse().unwrap_or(1280);
    match budget {
        Some(b) if cur > b => {
            eprintln!("[vpn] TUN MTU {cur} > бюджет QUIC-датаграммы {b} — ужимаю до {b}");
            b.to_string()
        }
        _ => cfg_mtu.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C8.3: резолв назначений — CIDR как есть, голый IP → /32, дубликаты схлопываются, IPv6 и
    /// мусор отбрасываются. Домены не тестируем (нужна сеть) — только детерминированные входы.
    #[tokio::test]
    async fn resolve_dests_cidr_ip_dedup_and_skips() {
        let got = resolve_dests(&[
            "192.168.0.0/16".into(), // CIDR — как есть
            "10.0.0.5".into(),       // голый IP → /32
            "10.0.0.5".into(),       // дубликат → схлопнуть
            "1.2.3.4/33".into(),     // битый префикс → скип
            "fd00::1/64".into(),     // IPv6 CIDR → скип (MVP IPv4)
            "::1".into(),            // IPv6 IP → скип
        ])
        .await;
        assert_eq!(got, vec!["192.168.0.0/16".to_string(), "10.0.0.5/32".to_string()]);
    }

    /// Подключение, начатое ДО появления сети, обязано подняться САМО, когда сеть появится.
    ///
    /// Регрессия, которую это ловит: после попытки, не доехавшей до exit'а, цикл записывал себе
    /// «непредъявленный токен» — хотя токена на руках не было вовсе (первый заход к издателю тоже
    /// не удался, сети нет). К издателю он больше не возвращался и навсегда оставался с пустым
    /// токеном и бутстрапным ключом L1; при ротации H-3 exit молча дропает такие пакеты, и в
    /// журнале это выглядит как закрытый порт. Помогало только ручное «Отключить/Подключить».
    #[tokio::test]
    async fn issuer_is_revisited_while_we_hold_no_token() {
        struct NoTun;
        impl TunProvider for NoTun {
            fn configure(&self, _p: &TunParams) -> Result<Arc<dyn TunIo>> {
                unreachable!("до туннеля дело не доходит: exit'ов в конфиге нет")
            }
        }

        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = Arc::new(VpnController::new());
        let n = calls.clone();
        // Издатель недоступен (сети нет) — как и в поле: кошелёк пуст, отдать нечего.
        c.set_token_refresher(Arc::new(move || {
            n.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { None })
        }));

        let c2 = c.clone();
        let h = tokio::spawn(async move {
            let _ = c2.connect(test_cfg(), Arc::new(NoTun)).await;
        });
        // `servers` пуст ⇒ establish отваливается мгновенно; backoff 1с → 2с. Трёх секунд хватает
        // на несколько итераций, и тест остаётся секундным.
        tokio::time::sleep(Duration::from_millis(3000)).await;
        c.disconnect();
        let _ = tokio::time::timeout(Duration::from_secs(5), h).await;

        assert!(
            calls.load(Ordering::SeqCst) >= 2,
            "к издателю сходили лишь {} раз: цикл считает, что держит непредъявленный токен, \
             которого у него нет — сессия не поднимется и после появления сети",
            calls.load(Ordering::SeqCst)
        );
    }

    /// Вердикт «QUIC/UDP здесь односторонний» живёт ДОЛЬШЕ контроллера (приложение создаёт новый
    /// на каждое подключение) — иначе каждое нажатие «Подключить» снова начиналось бы с четырёх
    /// секунд мёртвого туннеля и второго токена из кошелька. Но не вечно и не поперёк смены сети.
    #[test]
    fn udp_verdict_outlives_controller_but_expires_and_clears() {
        clear_udp_verdict();
        assert!(!udp_unusable_recent(), "чистый процесс — QUIC не осуждён");
        note_udp_unusable();
        assert!(udp_unusable_recent(), "вердикт вынесен — следующая сессия идёт obfs-TCP");
        // Смена сети / не поднявшийся obfs-TCP снимают вердикт: судить QUIC больше не за что.
        clear_udp_verdict();
        assert!(!udp_unusable_recent(), "вердикт снят — обычный порядок транспортов");
        // Протухание: вердикт старше TTL не считается (сеть могла и починиться).
        *UDP_UNUSABLE.lock().unwrap() =
            std::time::Instant::now().checked_sub(UDP_VERDICT_TTL + Duration::from_secs(1));
        assert!(!udp_unusable_recent(), "вердикт протух — пробуем QUIC заново");
        clear_udp_verdict();
    }

    /// Эскалация QUIC→obfs-TCP только там, где она лечит: «повисший»/оборванный крупный
    /// control-обмен (MTU/NAT64). На осознанном отказе exit'а (токен, PQ-auth, pin, недоступность)
    /// повтор лишь сожжёт второй токен и подменит причину в UI на «auth-failed» — не эскалируем.
    #[test]
    fn escalate_to_tcp_only_on_transport_style_failures() {
        // лечится TCP: соединение оборвалось/повисло на большом ответе
        assert!(should_escalate_to_tcp("read error: connection lost: timed out"));
        assert!(should_escalate_to_tcp("обрезанная PQ-подпись"));
        assert!(should_escalate_to_tcp("timed out"));
        // отказ по существу — эскалация только навредит
        assert!(!should_escalate_to_tcp(
            "read error: connection lost: closed by peer: auth-failed (code 1)"
        ));
        assert!(!should_escalate_to_tcp("токен уже использован (double-spend)"));
        assert!(!should_escalate_to_tcp("невалидный токен — отказ в доступе"));
        assert!(!should_escalate_to_tcp("PQ-auth: ML-DSA подпись сервера НЕ прошла — возможен MITM"));
        assert!(!should_escalate_to_tcp(
            "серт-pin не настроен — отказ (fail-closed, S0.1/H2)"
        ));
        assert!(!should_escalate_to_tcp(
            "ни один exit недоступен:\n1.2.3.4:4433: QUIC/UDP:4433 и obfs-TCP:443 недоступны"
        ));
    }

    #[tokio::test]
    async fn state_transitions_and_events() {
        let c = VpnController::new();
        assert_eq!(c.state(), VpnState::Idle);
        let mut rx = c.subscribe();

        c.set_state(VpnState::Connecting);
        c.set_state(VpnState::Up);
        assert_eq!(c.state(), VpnState::Up);

        // подписчик получает оба State-события по порядку
        assert!(matches!(rx.recv().await.unwrap(), VpnEvent::State(VpnState::Connecting)));
        assert!(matches!(rx.recv().await.unwrap(), VpnEvent::State(VpnState::Up)));
    }

    #[test]
    fn disconnect_when_idle_is_safe() {
        let c = VpnController::new();
        c.disconnect(); // не паникует, no-op без активной сессии
        assert_eq!(c.state(), VpnState::Idle);
    }

    #[test]
    fn notify_network_changed_when_idle_is_safe() {
        let c = VpnController::new();
        // Нет активного pump → notify_waiters без ждущих: сигнал не запоминается, не паникует,
        // состояние не трогает (реконнект инициирует только connect-loop, если он крутится).
        c.notify_network_changed();
        assert_eq!(c.state(), VpnState::Idle);
    }

    #[test]
    fn backoff_doubles_and_caps() {
        let mut b = RECONNECT_BACKOFF_START;
        assert_eq!(b, Duration::from_secs(1));
        b = next_backoff(b);
        assert_eq!(b, Duration::from_secs(2));
        b = next_backoff(b);
        assert_eq!(b, Duration::from_secs(4));
        for _ in 0..10 {
            b = next_backoff(b); // упирается в потолок, не растёт бесконечно
        }
        assert_eq!(b, RECONNECT_BACKOFF_MAX);
    }

    #[tokio::test]
    async fn backoff_wait_returns_immediately_when_stopped() {
        let c = VpnController::new();
        c.disconnect(); // ставит stopped
        // не ждёт 10с — сразу None (реконнект прерывается пользовательским disconnect)
        assert!(c.backoff_wait(Duration::from_secs(10)).await.is_none());
    }

    /// Пауза между попытками истекла штатно → backoff растёт (следующая пауза длиннее).
    #[tokio::test]
    async fn backoff_wait_grows_after_plain_timeout() {
        let c = VpnController::new();
        let next = c.backoff_wait(Duration::from_millis(1)).await;
        assert_eq!(next, Some(Duration::from_millis(2)));
    }

    /// Сеть вернулась во время паузы реконнекта (Android: onAvailable после «нет сети вовсе») →
    /// ждать до конца backoff нельзя, иначе интернет уже есть, а туннель поднимается через 30с.
    /// Просыпаемся досрочно и сбрасываем backoff.
    #[tokio::test]
    async fn backoff_wait_wakes_on_network_change_and_resets_backoff() {
        let c = Arc::new(VpnController::new());
        let c2 = c.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            c2.notify_network_changed();
        });
        let started = std::time::Instant::now();
        let next = c.backoff_wait(RECONNECT_BACKOFF_MAX).await;
        assert_eq!(next, Some(RECONNECT_BACKOFF_START), "backoff сброшен: условия новые");
        assert!(started.elapsed() < Duration::from_secs(5), "проснулись досрочно, а не через 30с");
    }

    /// Тестовый конфиг: движку сети не даём — все проверки ниже про фазы ДО establish.
    fn test_cfg() -> ClientConfig {
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
            data_psk: None,
            pin: crate::config::PinSource::None,
            mldsa: crate::config::MldsaSource::None,
            allow_insecure_no_pin: false,
            allow_classical_kx: false,
            require_pq_auth: false,
            killswitch: false,
            split: Default::default(),
            pacing: None,
        }
    }

    /// «Отключить» во время ФАЗЫ ПОДКЛЮЧЕНИЯ (здесь — добыча Layer-1 токена, которая может тянуться
    /// на недоступном издателе): цикл обязан свернуться сразу и НЕ трогать туннель.
    ///
    /// Регрессия, которую это ловит: раньше `disconnect` замечался только между итерациями, поэтому
    /// нажатие в фазе реконнекта доводило попытку до конца и лезло конфигурировать TUN — на Android
    /// уже поверх погашенного сервиса («CitadelVpnService не зарегистрирован» в логе), на desktop —
    /// поднимая туннель и kill-switch заново после того, как пользователь их снял.
    #[tokio::test]
    async fn disconnect_during_connect_phase_stops_without_touching_tun() {
        struct SpyProvider(Arc<AtomicBool>);
        impl TunProvider for SpyProvider {
            fn configure(&self, _p: &TunParams) -> Result<Arc<dyn TunIo>> {
                self.0.store(true, Ordering::SeqCst);
                Err(anyhow::anyhow!("configure не должен вызываться после disconnect"))
            }
        }

        let c = Arc::new(VpnController::new());
        let configured = Arc::new(AtomicBool::new(false));
        // Издатель «не отвечает никогда» — цикл стоит в фазе добычи токена, пока не придёт отмена.
        c.set_token_refresher(Arc::new(|| {
            Box::pin(async {
                std::future::pending::<()>().await;
                None
            })
        }));

        let c2 = c.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            c2.disconnect();
        });

        let provider: Arc<dyn TunProvider> = Arc::new(SpyProvider(configured.clone()));
        tokio::time::timeout(Duration::from_secs(5), c.connect(test_cfg(), provider))
            .await
            .expect("цикл обязан свернуться на disconnect, а не досиживать фазу")
            .expect("остановка пользователем — не ошибка");

        assert!(!configured.load(Ordering::SeqCst), "туннель после «Отключить» не конфигурируем");
        assert_eq!(c.state(), VpnState::Down);
    }

    /// Гонка «disconnect ровно перед подпиской на сигнал»: флаг выставлен до входа в ожидание —
    /// ждать нечего. Без этого порядка (подписка → проверка флага) сигнал терялся, и цикл
    /// продолжал подключаться после нажатия «Отключить».
    #[tokio::test]
    async fn cancelled_returns_when_stop_came_before_subscribing() {
        let c = VpnController::new();
        c.disconnect();
        tokio::time::timeout(Duration::from_millis(200), c.cancelled())
            .await
            .expect("уже остановлены — ожидание обязано вернуться сразу");
        // и та же проверка через until_stop: длинная фаза не должна даже начинаться
        let r = tokio::time::timeout(
            Duration::from_millis(200),
            c.until_stop(async { tokio::time::sleep(Duration::from_secs(30)).await }),
        )
        .await
        .expect("until_stop обязан вернуться сразу");
        assert!(r.is_none());
    }

    /// C5.4b: pre-connect провал (напр. фетч Layer-1 токена не удался) эмитит Error → Down,
    /// чтобы UI вышел из спиннера, а не завис. `begin` перед этим показывает Connecting.
    #[tokio::test]
    async fn fail_emits_error_then_down() {
        let c = VpnController::new();
        let mut rx = c.subscribe();
        c.begin();
        c.fail("токен недоступен".into());
        assert_eq!(c.state(), VpnState::Down);
        assert!(matches!(rx.recv().await.unwrap(), VpnEvent::State(VpnState::Connecting)));
        assert!(matches!(rx.recv().await.unwrap(), VpnEvent::Error(e) if e.contains("токен")));
        assert!(matches!(rx.recv().await.unwrap(), VpnEvent::State(VpnState::Down)));
    }
}
