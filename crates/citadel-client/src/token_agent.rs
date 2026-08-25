//! C5.3: `TokenAgent` — добыча анонимных epoch-токенов у issuer через Layer-1 «абонемент».
//!
//! GUI-клиент, имея бандл кред (`issuer` host:port + `client_seed`), получает unlinkable токены
//! ДО подключения к exit'у: `client_seed` (Ed25519) доказывает «абонемент» издателю (Layer-1),
//! издатель слепо подписывает epoch-токены (не видит их → unlinkability). Токены кладутся в
//! `ClientConfig.token` для предъявления exit'у (M4/M5).
//!
//! **§7.1 аудита-4 (заход 7): между issuance и сессией больше нет привязки «одно к одному».**
//! Раньше клиент шёл к издателю перед КАЖДЫМ establish — в том числе перед каждым реконнектом.
//! Слепая подпись прячет от издателя *какой* токен предъявлен, но не прячет, что абонент
//! `client_id` с адреса *IP* обратился в момент *t*; сессия на exit'е начиналась в *t + ε*, и
//! этой корреляции достаточно, чтобы связать сессию с абонентом (при `--role all` издатель и exit
//! — вообще один процесс). Теперь между ними стоит [`TokenPouch`]:
//!
//!  * токены берутся **пачкой на эпоху** и лежат в памяти процесса; реконнекты внутри эпохи
//!    издателя не видны вовсе;
//!  * дозаправка идёт **фоном, со случайной задержкой** и, если туннель поднят, — **сквозь сам
//!    туннель** ([`citadel_protect::Route::Tunnel`]), поэтому издатель видит адрес exit'а, а не
//!    абонента;
//!  * срок годности пачки — ровно эпоха издателя (её длину он присылает в кадре эпохи). Отзыв
//!    абонента поэтому по-прежнему действует, но с задержкой ≤ одной эпохи вместо «со следующего
//!    establish» — сознательный размен, зафиксированный в отчёте (§17.1).
//!
//! Протокол sync (std::net в `citadel_token::fetch_tokens`) — гоняем в `spawn_blocking`, чтобы не
//! блокировать движковый tokio-runtime (на мобилке блокирующий TCP → blocking-pool tokio).

use anyhow::{Context, Result};
use citadel_quic::protect::Route; // маршрут сокета к издателю: мимо туннеля / сквозь него
use citadel_quic::config::ClientConfig;
use citadel_quic::vpn::{SessionGrant, TokenRefresher, VpnController, VpnEvent, VpnState};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Сколько токенов брать за один заход к издателю. Верхняя граница осмысленности — квота издателя
/// на эпоху (`Citadel_TOKEN_QUOTA`, дефолт 64): пачка должна перекрывать разумное число
/// реконнектов, но не выгребать квоту за раз (иначе после нескольких дозаправок абонент упрётся в
/// потолок и останется без токенов до конца эпохи).
const DEFAULT_BATCH: usize = 8;

/// Порог дозаправки: пока в кошельке больше этого числа токенов, к издателю не ходим. Единица, а
/// не ноль, — чтобы фоновая дозаправка успевала пройти ДО того, как реконнект упрётся в пустой
/// кошелёк и пойдёт к издателю синхронно (то есть ровно в момент подключения — чего §7.1 и просит
/// избегать).
const LOW_WATER: usize = 1;

/// Добыть `count` epoch-токенов у `issuer` (host:port), авторизуясь `client_seed`'ом (Layer-1).
/// `retries` — попытки коннекта. Издатель токены НЕ видит.
/// S2.1/A1: канал к issuer'у — PQ-TLS с пиннингом (`issuer_pin`) → анти-MITM + скрытие client_id.
/// PQ: `issuer_mldsa` — обязательство к ML-DSA-идентичности издателя из ссылки; издатель обязан
/// доказать владение ею подписью привязки к сессии, иначе канал рвётся до отправки `client_id`.
/// `route` — идёт ли сокет мимо туннеля (перед establish) или сквозь него (фоновая дозаправка).
#[allow(clippy::too_many_arguments)]
pub async fn fetch_tokens(
    issuer: &str,
    issuer_pin: &[u8; 32],
    issuer_mldsa: &[u8; 32],
    client_seed: &[u8; 32],
    // B-1: pin exit'а, под который берётся пачка (из ссылки). Ключ эпохи выводится per-exit,
    // поэтому токен, взятый «вообще», ни на одном узле не пройдёт.
    exit_pin: &[u8; 32],
    count: usize,
    retries: u32,
    obfs_psk: Option<[u8; 32]>,
    route: Route,
) -> Result<citadel_token::Grant> {
    let issuer = issuer.to_string();
    let pin = *issuer_pin;
    let mldsa = *issuer_mldsa;
    let seed = *client_seed;
    let exit_pin = *exit_pin;
    tokio::task::spawn_blocking(move || {
        citadel_token::fetch_tokens(
            &issuer, &pin, &mldsa, &seed, &exit_pin, count, retries, obfs_psk, route,
        )
    })
    .await
    .context("token-fetch задача паникнула")?
}

/// Кошелёк токенов: пачка на эпоху + ключ L1 этой эпохи (H-3), общий на все попытки establish.
///
/// Живёт **только в памяти процесса**: на диск не ложится намеренно — иначе украденный бэкап
/// приложения давал бы готовые к предъявлению токены, а рестарт процесса перестал бы быть
/// естественной границей их жизни.
pub struct TokenPouch {
    issuer: String,
    pin: [u8; 32],
    mldsa: [u8; 32],
    seed: [u8; 32],
    /// B-1: pin exit'а из ссылки — пачка берётся под КОНКРЕТНЫЙ узел (нули = без привязки).
    exit_pin: [u8; 32],
    /// Бутстрапный obfs-PSK из ссылки — обёртка канала К ИЗДАТЕЛЮ (после H-3 только она).
    bootstrap_psk: Option<[u8; 32]>,
    batch: usize,
    st: Mutex<Purse>,
    /// Фоновая дозаправка уже запущена (её нельзя стартовать из sync-контекста без runtime).
    topup: AtomicBool,
    /// Подписка на события контроллера — из неё фоновая задача узнаёт, поднят ли туннель.
    /// `Mutex<Option<..>>`, потому что задача забирает её ровно один раз при старте.
    events: Mutex<Option<tokio::sync::broadcast::Receiver<VpnEvent>>>,
    /// Поколение привязки к контроллеру. Кошелёк переживает пересоздание контроллера
    /// ([`rebind`]), а вместе с ним — и фоновую задачу: старая обязана уйти, когда пришла новая.
    /// Она и так уходит по закрытому broadcast'у, но между `disconnect()` прошлой сессии и дропом
    /// прошлого контроллера есть окно, в котором живы обе; номер поколения его закрывает.
    generation: AtomicU64,
}

/// Содержимое кошелька. Пусто ⇒ следующий establish идёт к издателю синхронно.
#[derive(Default)]
struct Purse {
    tokens: Vec<Vec<u8>>,
    data_psk: Option<[u8; 32]>,
    /// Монотонный дедлайн годности пачки. `None` — кошелёк пуст.
    deadline: Option<Instant>,
    /// Длина эпохи издателя (сек) — из неё считается и дедлайн, и разброс фоновой дозаправки.
    epoch_secs: u64,
    /// До какого момента ходить к издателю бессмысленно: квота эпохи (A6) уже выбрана, и он не
    /// отдаст ни одного токена до её конца ([`citadel_token::QuotaExhausted`]). Без этой отметки
    /// цикл реконнекта поднимал PQ-TLS-сессию к издателю каждые несколько секунд до конца эпохи —
    /// сотня бесполезных хендшейков вместо одного честного «ждём столько-то».
    quota_block: Option<Instant>,
}

impl Purse {
    /// Не просрочена ли пачка. Дедлайн монотонный: перевод системных часов (в т.ч. злонамеренный)
    /// не продлевает жизнь токенов.
    fn fresh(&self) -> bool {
        matches!(self.deadline, Some(d) if Instant::now() < d)
    }

    fn clear(&mut self) {
        self.tokens.clear();
        self.data_psk = None;
        self.deadline = None;
    }

    /// Сколько ещё ждать до снятия блокировки по квоте (`None` — идти можно).
    fn quota_wait(&self) -> Option<Duration> {
        let until = self.quota_block?;
        until.checked_duration_since(Instant::now())
    }
}

impl TokenPouch {
    pub fn new(
        issuer: &str,
        pin: &[u8; 32],
        mldsa: &[u8; 32],
        seed: &[u8; 32],
        exit_pin: &[u8; 32],
        bootstrap_psk: Option<[u8; 32]>,
    ) -> Self {
        Self {
            issuer: issuer.to_string(),
            pin: *pin,
            mldsa: *mldsa,
            seed: *seed,
            exit_pin: *exit_pin,
            bootstrap_psk,
            batch: batch_size(),
            st: Mutex::new(Purse::default()),
            topup: AtomicBool::new(false),
            events: Mutex::new(None),
            generation: AtomicU64::new(0),
        }
    }

    /// Привязать переживший прошлую сессию кошелёк к НОВОМУ контроллеру.
    ///
    /// Кошелёк живёт дольше контроллера (см. [`install_with_seed`]), а фоновая дозаправка — нет:
    /// она слушает события конкретного контроллера. Поэтому при каждой новой сессии подписка
    /// меняется, номер поколения растёт (старая задача видит это и уходит), и право на старт
    /// задачи освобождается заново.
    fn rebind(self: &Arc<Self>, controller: &Arc<VpnController>) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        *self.events.lock().unwrap() = Some(controller.subscribe());
        self.topup.store(false, Ordering::SeqCst);
        self.ensure_topup();
    }

    /// Взять токен из кошелька, не обращаясь к издателю. `None` — пусто или пачка просрочена
    /// (просроченную выбрасываем здесь же: держать её незачем, exit её всё равно не примет после
    /// смены эпохи, а отзыв абонента обязан срабатывать).
    fn take_cached(&self) -> Option<SessionGrant> {
        let mut p = self.st.lock().unwrap();
        if !p.fresh() {
            p.clear();
            return None;
        }
        let token = p.tokens.pop()?;
        Some(SessionGrant { token, data_psk: p.data_psk })
    }

    /// Сколько токенов осталось (для фоновой дозаправки и тестов).
    fn left(&self) -> usize {
        let p = self.st.lock().unwrap();
        if p.fresh() {
            p.tokens.len()
        } else {
            0
        }
    }

    /// Сходить к издателю за пачкой. Возвращает число добытых токенов.
    async fn refill(&self, route: Route) -> Result<usize> {
        match self.refill_inner(route).await {
            Ok(n) => {
                self.st.lock().unwrap().quota_block = None; // выдача пошла — блокировка не нужна
                Ok(n)
            }
            Err(e) => {
                // A6: квота эпохи выбрана. Издатель не отдаст ничего до её конца, и повторные
                // заходы отличаются от первого только потраченным временем — отмечаем срок и
                // молчим до него (см. `Purse::quota_block`).
                if let Some(q) = e.downcast_ref::<citadel_token::QuotaExhausted>() {
                    let wait = q.retry_after();
                    self.st.lock().unwrap().quota_block = Some(Instant::now() + wait);
                    eprintln!(
                        "[token] {q} — к издателю не хожу ещё {} мин",
                        wait.as_secs().div_ceil(60)
                    );
                }
                Err(e)
            }
        }
    }

    async fn refill_inner(&self, route: Route) -> Result<usize> {
        let grant = fetch_tokens(
            &self.issuer,
            &self.pin,
            &self.mldsa,
            &self.seed,
            &self.exit_pin,
            self.batch,
            // Ретраи коннекта: фоновой дозаправке спешить некуда и повторить она может позже
            // сама, а вот путь перед establish обязан отработать сеть, которая только что
            // поднялась (реконнект на мобильной сети — самый частый случай).
            if route == Route::Tunnel { 2 } else { 3 },
            self.bootstrap_psk,
            route,
        )
        .await?;
        let n = grant.tokens.len();
        if n == 0 {
            anyhow::bail!("издатель не выдал ни одного токена (квота эпохи? отзыв?)");
        }
        let mut p = self.st.lock().unwrap();
        // Две дозаправки могли пойти внахлёст (фоновая началась, туннель упал, реконнект пошёл за
        // токеном сам). Пачки СКЛАДЫВАЕМ, а не затираем: непросроченный кошелёк держит токены той
        // же эпохи, и выбросить их значило бы сжечь квоту абонента (A6) на ровном месте.
        if p.fresh() {
            p.tokens.extend(grant.tokens);
        } else {
            p.tokens = grant.tokens;
        }
        p.data_psk = grant.data_psk;
        p.epoch_secs = grant.epoch_secs;
        p.deadline = Some(Instant::now() + pouch_lifetime(grant.epoch, grant.epoch_secs));
        Ok(n)
    }

    /// Путь перед establish: сперва кошелёк, и только если он пуст/просрочен — синхронный заход к
    /// издателю МИМО туннеля (его в этот момент нет). Это единственное место, где обращение к
    /// издателю остаётся привязанным ко времени подключения; фоновая дозаправка существует ровно
    /// затем, чтобы сюда попадали как можно реже (холодный старт, конец эпохи в офлайне).
    async fn take_or_fetch(self: &Arc<Self>) -> Option<SessionGrant> {
        self.ensure_topup();
        if let Some(g) = self.take_cached() {
            return Some(g);
        }
        // A6: квота эпохи выбрана — идти к издателю незачем до её конца. Говорим об этом один раз
        // за попытку и коротко: цикл реконнекта всё равно повторит, но уже не притащит за собой
        // TLS-хендшейк к издателю.
        if let Some(left) = self.st.lock().unwrap().quota_wait() {
            eprintln!(
                "[token] квота выдачи на текущую эпоху выбрана — новые токены будут через ~{} мин \
                 (доступ не отозван; чаще всего это слишком частые переподключения)",
                left.as_secs().div_ceil(60)
            );
            return None;
        }
        match self.refill(Route::Bypass).await {
            Ok(n) => {
                eprintln!("[token] кошелёк пополнен: {n} токен(ов) на эпоху");
                self.take_cached()
            }
            Err(e) => {
                // Причину НЕ проглатываем: «issuer недоступен / pin / obfs / kill-switch» —
                // основной диагноз при «не подключается», и он должен быть в логе ядра.
                eprintln!("[token] Layer-1 фетч у issuer {} не удался: {e:#}", self.issuer);
                None
            }
        }
    }

    /// Замыкание для [`VpnController::set_token_refresher`].
    pub fn refresher(self: &Arc<Self>) -> TokenRefresher {
        let me = self.clone();
        Arc::new(move || {
            let me = me.clone();
            Box::pin(async move { me.take_or_fetch().await })
                as std::pin::Pin<Box<dyn std::future::Future<Output = Option<SessionGrant>> + Send>>
        })
    }

    /// Запустить фоновую дозаправку, если ещё не запущена и если есть tokio-runtime. Зовётся и из
    /// [`install`] (там runtime может отсутствовать — GUI ставит refresher из sync-контекста), и
    /// из первого обращения к кошельку (оно всегда внутри runtime).
    fn ensure_topup(self: &Arc<Self>) {
        if self.topup.load(Ordering::SeqCst) {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else { return };
        if self.topup.swap(true, Ordering::SeqCst) {
            return; // право на старт застолбил кто-то другой
        }
        // Подписки нет — кошелёк живёт без контроллера (юнит-тесты, разовые сценарии): следить
        // за состоянием туннеля не по чему, фоновая дозаправка в таком режиме и не нужна.
        let Some(rx) = self.events.lock().unwrap().take() else { return };
        let me = self.clone();
        handle.spawn(async move { me.topup_loop(rx).await });
    }

    /// Фоновая дозаправка: ждём поднятого туннеля, ждём случайную задержку — и идём к издателю
    /// СКВОЗЬ туннель (§7.1(в)). Задача умирает вместе с контроллером (его broadcast закрывается).
    async fn topup_loop(self: Arc<Self>, mut rx: tokio::sync::broadcast::Receiver<VpnEvent>) {
        let mut up = false;
        let mine = self.generation.load(Ordering::SeqCst);
        loop {
            // Кошелёк переехал на новый контроллер ([`rebind`]) — эта задача слушает уже мёртвую
            // подписку, и вторая такая же в это время делает ту же работу.
            if self.generation.load(Ordering::SeqCst) != mine {
                return;
            }
            // Лок берём ОДИН раз и до ветвления: `Mutex` здесь не реентрантный, а ветки ниже
            // тоже смотрят в кошелёк (`left()`), и временная блокировка из условия дожила бы до
            // конца всей цепочки `if/else`.
            let quota_left = self.st.lock().unwrap().quota_wait();
            // Пока туннель не поднят — просто ждём событий: дозаправка мимо туннеля тут не нужна
            // (она раскрыла бы адрес абонента ровно так же, как старый путь), а пустой кошелёк
            // доберёт `take_or_fetch` перед следующим establish.
            let wait = if !up {
                None // до ближайшего события
            } else if let Some(left) = quota_left {
                Some(left) // квота эпохи выбрана — просыпаться раньше её конца незачем
            } else if self.left() > LOW_WATER {
                Some(Duration::from_secs(30)) // кошелёк полон — просто периодически перепроверяем
            } else {
                // Разброс: издатель не должен видеть заходы, выстроенные в узнаваемый ритм (ни
                // «через ровно час», ни «сразу после подъёма туннеля»). Верхняя граница — доля
                // эпохи: ждать дольше её остатка бессмысленно, пачка всё равно протухнет.
                Some(topup_delay(self.st.lock().unwrap().epoch_secs))
            };
            // Квота эпохи выбрана — дозаправлять нечем; ждём событий и срока, а не издателя.
            let need_topup = up && self.left() <= LOW_WATER && quota_left.is_none();
            match self.wait_events(&mut rx, wait, &mut up).await {
                Wake::Gone => return, // контроллер ушёл — уходим и мы
                Wake::Event => continue, // состояние поменялось: пересчитаем, что делать
                Wake::Elapsed => {}
            }
            // Проверяем поколение ещё раз ПЕРЕД походом к издателю, а не только в начале круга:
            // задача прошлой сессии могла проснуться с устаревшим `up == true` и потратить пачку
            // из квоты эпохи (A6) на туннель, которого уже нет.
            if !need_topup || !up || self.generation.load(Ordering::SeqCst) != mine {
                continue;
            }
            match self.refill(Route::Tunnel).await {
                Ok(n) => eprintln!("[token] кошелёк пополнен фоном через туннель: {n} токен(ов)"),
                // Не откатываемся на прямой канал: смысл фоновой дозаправки в том, что издатель
                // видит адрес exit'а, а не абонента. Не вышло (издатель за туннелем недоступен —
                // так бывает, например, когда издатель и exit на одном адресе и хайрпин закрыт) —
                // выжидаем штрафную паузу и пробуем снова; пустой кошелёк тем временем доберёт
                // `take_or_fetch` перед следующим establish, там туннеля всё равно нет.
                Err(e) => {
                    eprintln!("[token] фоновая дозаправка через туннель не удалась: {e:#}");
                    if matches!(
                        self.wait_events(&mut rx, Some(TOPUP_PENALTY), &mut up).await,
                        Wake::Gone
                    ) {
                        return;
                    }
                }
            }
        }
    }

    /// Подождать `dur` (или ближайшего события при `None`), попутно отслеживая, поднят ли туннель.
    /// Отдельная функция, потому что «ждать, не переставая слушать события» нужно в четырёх местах
    /// цикла, а расхождение между ними даёт зависшую дозаправку, которую никто не заметит.
    async fn wait_events(
        &self,
        rx: &mut tokio::sync::broadcast::Receiver<VpnEvent>,
        dur: Option<Duration>,
        up: &mut bool,
    ) -> Wake {
        let listen = async {
            loop {
                match rx.recv().await {
                    Ok(VpnEvent::State(s)) => {
                        let now_up = s == VpnState::Up;
                        if now_up != *up {
                            *up = now_up;
                            return Wake::Event;
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(_) => return Wake::Gone,
                }
            }
        };
        match dur {
            None => listen.await,
            Some(d) => tokio::time::timeout(d, listen).await.unwrap_or(Wake::Elapsed),
        }
    }
}

/// Чем закончилось ожидание в фоновой дозаправке.
#[derive(Debug, PartialEq, Eq)]
enum Wake {
    /// Сменилось состояние туннеля.
    Event,
    /// Вышло отведённое время.
    Elapsed,
    /// Контроллер уничтожен — задаче больше нечего делать.
    Gone,
}

/// Пауза после неудачной фоновой дозаправки. Не короткая: неудача обычно означает, что через
/// туннель издатель недоступен в принципе (конфигурация деплоя), и долбиться в него чаще
/// бессмысленно — а редкие попытки нужны, потому что маршрут может починиться.
const TOPUP_PENALTY: Duration = Duration::from_secs(300);

/// Размер пачки: [`DEFAULT_BATCH`], либо `Citadel_TOKEN_BATCH` (стенды и e2e). `1` возвращает
/// прежнее поведение «токен на каждый establish» — им же выключается кэширование в тестах отзыва.
fn batch_size() -> usize {
    std::env::var("Citadel_TOKEN_BATCH")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_BATCH)
        .clamp(1, 32)
}

/// Сколько пачка годна с момента получения.
///
/// Токены скоупятся на эпоху: exit проверяет их ключом current±prev, а ключ L1 из того же кадра
/// живёт ровно эпоху. Держим пачку **до конца эпохи издателя** — не дольше, даже с учётом
/// exit'ового grace: иначе отзыв абонента (admin-канал) откладывался бы на две эпохи.
///
/// Часы клиента могут расходиться с издателем — номер эпохи он прислал. Считаем остаток эпохи по
/// СВОИМ часам и, если номера разошлись, берём консервативную половину эпохи: рассинхрон в нашу
/// пользу не должен превращать «кэш на эпоху» в «кэш навсегда».
fn pouch_lifetime(issuer_epoch: u64, epoch_secs: u64) -> Duration {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if citadel_token::current_epoch(epoch_secs) != issuer_epoch {
        eprintln!(
            "[token] часы разошлись с издателем (его эпоха {issuer_epoch}, наша {}): пачку держим \
             половину эпохи",
            citadel_token::current_epoch(epoch_secs)
        );
        return Duration::from_secs(epoch_secs / 2);
    }
    Duration::from_secs(epoch_secs - now % epoch_secs.max(1))
}

/// Случайная задержка фоновой дозаправки: от 5 с до трети эпохи, но не дольше 10 минут.
/// Источник случайности — системный CSPRNG (тот же, что у крипты): предсказуемый разброс —
/// это отсутствие разброса.
fn topup_delay(epoch_secs: u64) -> Duration {
    let hi = (epoch_secs / 3).clamp(5, 600);
    let mut b = [0u8; 8];
    if aws_lc_rs::rand::fill(&mut b).is_err() {
        return Duration::from_secs(hi); // без случайности — максимум, а не ноль
    }
    let span = hi.saturating_sub(5).max(1);
    Duration::from_secs(5 + u64::from_be_bytes(b) % span)
}

/// Поставить контроллеру кошелёк токенов (Layer-1). Возвращает `false`, если в ссылке нет всего
/// набора (`issuer` + `issuer_pin` + `issuer_mldsa` + `client_seed`) — тогда refresher не ставится
/// вовсе: токен-less exit поднимется и так, а token-required честно откажет с внятной причиной.
///
/// Общая точка для всех трёх клиентов (GUI, консольный движок, тесты): раньше каждый собирал своё
/// замыкание с фетчем — и любое изменение политики выдачи приходилось повторять трижды.
pub fn install(controller: &Arc<VpnController>, link: &crate::creds::CredentialLink) -> bool {
    install_with_seed(controller, link, link.client_seed)
}

/// То же, но с явным Layer-1 ключом. M-9: после активации профиля абонент представляется
/// **устройственным** ключом, а не тем, что лежит в ссылке (его издатель уже не примет — запись
/// `consumed`). Выбор ключа делает владелец хранилища ([`crate::enroll::effective_seed`]), потому
/// что только он знает состояние активации; движок получает готовое значение.
pub fn install_with_seed(
    controller: &Arc<VpnController>,
    link: &crate::creds::CredentialLink,
    layer1_seed: Option<[u8; 32]>,
) -> bool {
    let (Some(issuer), Some(pin), Some(mldsa), Some(seed)) =
        (link.issuer.as_deref(), link.issuer_pin, link.issuer_mldsa, layer1_seed)
    else {
        return false;
    };
    // S2.1/A1-остаток: канал к издателю оборачиваем бутстрапным PSK из ссылки (probe-resistance).
    // B-1: узел, под который берём токены, — тот, чей pin лежит в ссылке. Ссылка без pin'а
    // (совсем старая) даёт непривязанную выдачу: exit примет её только в стендовом режиме, и это
    // лучше, чем молча вернуться к общему на весь деплой ключу эпохи.
    let exit_pin = link.cert_pin.unwrap_or(citadel_token::EXIT_PIN_UNBOUND);
    let key = PouchKey {
        issuer: issuer.to_string(),
        pin,
        mldsa,
        seed,
        exit_pin,
        obfs_psk: link.obfs_psk,
    };
    let pouch = pouch_for(key);
    pouch.rebind(controller);
    controller.set_token_refresher(pouch.refresher());
    true
}

/// Что делает кошелёк ТЕМ ЖЕ кошельком: тот же издатель, та же Layer-1 идентичность, тот же узел
/// и тот же канал к издателю. Расхождение по любому полю — другая пачка токенов (под другой ключ
/// эпохи или другую подписку), и переиспользовать её нельзя.
#[derive(PartialEq, Eq)]
struct PouchKey {
    issuer: String,
    pin: [u8; 32],
    mldsa: [u8; 32],
    seed: [u8; 32],
    exit_pin: [u8; 32],
    obfs_psk: Option<[u8; 32]>,
}

/// Кошелёк ПЕРЕЖИВАЕТ пересоздание контроллера — один слот на процесс.
///
/// **Зачем.** Контроллер создаётся заново на КАЖДОЕ подключение (GUI: `spawn_controller`), а
/// кошелёк жил внутри него. Значит «Отключить → Подключить» выбрасывало непотраченную пачку
/// (7 токенов из 8) и шло к издателю за новой. При квоте A6 в 64 токена на эпоху это ровно
/// **восемь** переподключений в час, после чего издатель переставал чеканить, и клиент до конца
/// эпохи видел «издатель прекратил выдачу, не выдав ни одного токена» — то есть выглядел как
/// сломанный сервер. Теперь тот же кошелёк подхватывается новой сессией: заходов к издателю
/// становится один на эпоху, как и задумано §7.1 (и, кстати, лучше для unlinkability — реже
/// «выдача ⇒ сессия»).
///
/// **Границы жизни не изменились:** только память процесса, на диск ничего не ложится, рестарт
/// приложения по-прежнему обнуляет кошелёк. Слот ОДИН: сессия в клиенте тоже одна, а держать
/// токены профиля, к которому не подключены, незачем — смена профиля вытесняет прошлый кошелёк.
static POUCH: Mutex<Option<(PouchKey, Arc<TokenPouch>)>> = Mutex::new(None);

fn pouch_for(key: PouchKey) -> Arc<TokenPouch> {
    let mut slot = POUCH.lock().unwrap();
    if let Some((k, p)) = slot.as_ref() {
        if *k == key {
            return p.clone();
        }
    }
    let p = Arc::new(TokenPouch::new(
        &key.issuer,
        &key.pin,
        &key.mldsa,
        &key.seed,
        &key.exit_pin,
        key.obfs_psk,
    ));
    *slot = Some((key, p.clone()));
    p
}

/// Забыть кошелёк процесса — точка сброса для тестов (в клиенте её звать неоткуда и не нужно:
/// слот вытесняется сменой профиля, а рестарт процесса и так границей жизни токенов).
pub fn forget_pouch() {
    *POUCH.lock().unwrap() = None;
}

/// B-1: pin exit'а, под который клиент берёт токены, по уже собранному конфигу.
///
/// Берётся из того же источника, что и проверка сертификата (`ClientConfig::pin_for`), — иначе
/// абонент назвал бы издателю один узел, а подключился к другому и получил бы отказ, который на
/// его стороне выглядит как «сервер не принимает токен».
///
/// Пиннинг не настроен (`NoPin`) или pin ещё не известен (`Waiting`, TOFU) → нули: выдача без
/// привязки. Такой токен exit принимает только в стендовом режиме — см. `Citadel_TOKEN_UNBOUND`.
fn exit_pin_of(config: &ClientConfig) -> [u8; 32] {
    let host = config
        .servers
        .first()
        .map(|s| citadel_quic::client::host_of(s))
        .unwrap_or(config.server_name.as_str());
    match config.pin_for(host) {
        citadel_quic::config::PinMode::Pinned(p) => p,
        _ => citadel_token::EXIT_PIN_UNBOUND,
    }
}

/// C5.4: разовая добыча токена для диагностики/одиночного establish (кошелька нет — он привязан к
/// контроллеру). Если бандл/ссылка несут `issuer`+`issuer_pin`+`client_seed` (Layer-1) — добываем
/// токен по PQ-TLS каналу и вписываем в `config.token`. Без issuer/seed → config как есть.
/// **issuer без pin — ошибка** (S2.1/A1 fail-closed: голый канал к издателю недопустим).
pub async fn with_token(
    mut config: ClientConfig,
    issuer: Option<&str>,
    issuer_pin: Option<&[u8; 32]>,
    issuer_mldsa: Option<&[u8; 32]>,
    client_seed: Option<&[u8; 32]>,
) -> Result<ClientConfig> {
    // нет issuer/seed → без токена (passthrough); есть issuer — pin и PQ-обязательство обязательны
    // (fail-closed).
    if let (Some(issuer), Some(seed)) = (issuer, client_seed) {
        let pin = issuer_pin.ok_or_else(|| {
            anyhow::anyhow!("issuer задан без issuer_pin — небезопасный канал (A1); ссылка устарела?")
        })?;
        let mldsa = issuer_mldsa.ok_or_else(|| {
            anyhow::anyhow!(
                "в ссылке нет PQ-обязательства издателя — канал держался бы на классической \
                 подписи серта; перевыпустите ссылку у администратора"
            )
        })?;
        // S2.1/A1-остаток: obfs-обёртка issuer-канала берётся из того же ClientConfig.obfs_psk,
        // что и туннель (probe-resistance; None → голый TLS для ссылок без obfs).
        let obfs_psk = config.obfs_psk;
        // Диагностика идёт при опущенном туннеле → маршрут прямой.
        // B-1: под какой узел берём токен. Диагностический путь работает с уже собранным
        // `ClientConfig`, поэтому pin берём оттуда же, откуда его возьмёт TLS-проверка.
        let exit_pin = exit_pin_of(&config);
        let mut grant =
            fetch_tokens(issuer, pin, mldsa, seed, &exit_pin, 1, 20, obfs_psk, Route::Bypass)
                .await?;
        if let Some(t) = grant.tokens.pop() {
            config.token = t;
        }
        // H-3: тем же заходом приезжает ключ L1 текущей эпохи для канала данных.
        if grant.data_psk.is_some() {
            config.data_psk = grant.data_psk;
        }
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pouch() -> Arc<TokenPouch> {
        Arc::new(TokenPouch::new(
            "127.0.0.1:9",
            &[0u8; 32],
            &[1u8; 32],
            &[7u8; 32],
            &[0x5cu8; 32],
            None,
        ))
    }

    /// Недоступный issuer → Err (обёртка не паникует и не виснет); 1 попытка → быстро.
    #[tokio::test]
    async fn unreachable_issuer_errs() {
        assert!(super::fetch_tokens(
            "127.0.0.1:9",
            &[0u8; 32],
            &[1u8; 32],
            &[7u8; 32],
            &[0x5cu8; 32],
            1,
            1,
            None,
            Route::Bypass
        )
        .await
        .is_err());
    }

    fn key(seed: [u8; 32], exit_pin: [u8; 32]) -> PouchKey {
        PouchKey {
            issuer: "127.0.0.1:9".into(),
            pin: [0u8; 32],
            mldsa: [1u8; 32],
            seed,
            exit_pin,
            obfs_psk: None,
        }
    }

    /// **Регрессия на «после нескольких переподключений клиент перестаёт подключаться».**
    ///
    /// Контроллер в GUI создаётся заново на каждое «Подключить», а кошелёк жил внутри него — и
    /// «Отключить → Подключить» выбрасывало непотраченную пачку (7 токенов из 8) и шло к издателю
    /// за новой. Квота A6 (64 токена на эпоху) выбиралась за восемь таких кругов, после чего
    /// издатель до конца эпохи не выдавал ничего. Инвариант: тот же профиль — тот же кошелёк, и
    /// уже добытые токены переживают пересоздание контроллера.
    #[test]
    fn wallet_survives_reconnect_and_is_per_profile() {
        forget_pouch();
        let first = pouch_for(key([7u8; 32], [0x5cu8; 32]));
        first.st.lock().unwrap().tokens = vec![vec![1], vec![2]];

        let again = pouch_for(key([7u8; 32], [0x5cu8; 32]));
        assert!(Arc::ptr_eq(&first, &again), "тот же профиль обязан получить ТОТ ЖЕ кошелёк");
        assert_eq!(again.st.lock().unwrap().tokens.len(), 2, "пачка пережила новый контроллер");

        // Другая Layer-1 идентичность — другая подписка и другая пачка: делить их нельзя.
        let other = pouch_for(key([8u8; 32], [0x5cu8; 32]));
        assert!(!Arc::ptr_eq(&first, &other), "чужой профиль обязан получить свой кошелёк");
        assert!(other.st.lock().unwrap().tokens.is_empty());
        // ...и тот же профиль, но другой exit: ключ эпохи выводится per-exit (B-1), пачка чужая.
        let other_exit = pouch_for(key([7u8; 32], [0x5du8; 32]));
        assert!(!Arc::ptr_eq(&first, &other_exit), "другой узел — другая пачка");
        forget_pouch();
    }

    /// Выбранная квота эпохи (A6) — не повод долбить издателя до её конца: пока отметка жива,
    /// `take_or_fetch` обязан отвечать сразу и БЕЗ сети. Проверяем по времени: заход к мёртвому
    /// издателю стоил бы секунд, отметка — микросекунды.
    #[tokio::test]
    async fn quota_block_stops_pointless_issuer_visits() {
        let p = pouch();
        p.st.lock().unwrap().quota_block = Some(Instant::now() + Duration::from_secs(600));
        let t0 = Instant::now();
        assert!(p.take_or_fetch().await.is_none(), "токенов нет и взять негде");
        assert!(t0.elapsed() < Duration::from_millis(200), "к издателю ходить не должны");
    }

    /// §7.1: пока пачка не просрочена, токены отдаются ИЗ ПАМЯТИ — к издателю (заведомо мёртвому)
    /// никто не идёт. Это и есть разрыв привязки «одно обращение к издателю = одна сессия».
    #[tokio::test]
    async fn cached_batch_serves_reconnects_without_touching_issuer() {
        let p = pouch();
        {
            let mut st = p.st.lock().unwrap();
            st.tokens = vec![vec![1], vec![2], vec![3]];
            st.data_psk = Some([9u8; 32]);
            st.epoch_secs = 3600;
            st.deadline = Some(Instant::now() + Duration::from_secs(60));
        }
        for _ in 0..3 {
            let g = p.take_or_fetch().await.expect("токен из кошелька");
            assert_eq!(g.data_psk, Some([9u8; 32]), "ключ L1 эпохи едет вместе с токеном");
        }
        assert_eq!(p.left(), 0);
        // Кошелёк пуст → идём к издателю (127.0.0.1:9 закрыт) → None, а не паника/зависание.
        assert!(p.take_or_fetch().await.is_none());
    }

    /// Главный тест §7.1: **одна пачка = одно обращение к издателю на много establish'ей.**
    /// Поднимаем настоящего (по протоколу) издателя и считаем принятые соединения: восемь подряд
    /// взятых грантов обязаны стоить ровно один TCP-заход. Раньше их было бы восемь — и издатель
    /// видел бы восемь моментов «абонент X подключается».
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_issuer_visit_serves_whole_batch() {
        use citadel_token::{pqid, pqtls, read_frame, write_frame, EpochKey};
        use std::net::TcpListener;
        use std::sync::atomic::AtomicUsize;

        let dir = std::env::temp_dir().join(format!("citadel-pouch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dirs = dir.to_str().unwrap().to_string();
        let identity = pqtls::IssuerIdentity::load_or_generate(&dirs).unwrap();
        let issuer_pin = identity.pin;
        let scfg = identity.server_config().unwrap();
        let pq = pqid::IssuerPqIdentity::load_or_generate(&dirs).unwrap();
        let issuer_mldsa = pq.commitment();
        // B-1: издатель считает вслепую ключом ЗАЯВЛЕННОГО узла, выведенным из мастера эпохи.
        let master = EpochKey::generate().unwrap().secret_bytes();
        let exit_pin = [0x5cu8; 32];

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let visits = Arc::new(AtomicUsize::new(0));
        let seen = visits.clone();
        let srv = std::thread::spawn(move || {
            for _ in 0..2 {
                let Ok((tcp, _)) = listener.accept() else { return };
                seen.fetch_add(1, Ordering::SeqCst);
                let Ok(mut conn) = pqtls::accept_tls(tcp, scfg.clone(), None) else { return };
                let Ok(ekm) = pqtls::handshake_server(&mut conn) else { return };
                let challenge = [0x5au8; 32];
                let _ = write_frame(&mut conn, &pq.hello(&challenge, &issuer_pin, &ekm).unwrap());
                let Ok(auth) = read_frame(&mut conn) else { return };
                pqid::verify_auth(&auth, pqid::DOMAIN_CLIENT, &challenge, &ekm).unwrap();
                // M-9: гейт выдачи — обычный абонент (активация не требуется).
                let _ = write_frame(&mut conn, &citadel_token::build_gate_frame(citadel_token::Gate::Allow));
                // B-1: клиент называет узел → ключ эпохи выводится под него.
                let Ok(bind) = read_frame(&mut conn) else { return };
                let asked = citadel_token::parse_exit_binding(&bind).unwrap();
                assert_eq!(asked, exit_pin, "клиент назвал exit из ссылки");
                let epoch_key = EpochKey::derive_for_exit(
                    &master,
                    citadel_token::current_epoch(3600),
                    &asked,
                )
                .unwrap();
                let _ = write_frame(&mut conn, &epoch_key.public_bytes());
                // Ротация L1 включена (0x01) + границы эпохи: ровно то, что клиент кладёт в кошелёк.
                let _ = write_frame(&mut conn, &citadel_token::build_epoch_frame(Some([7u8; 32]), 3600));
                while let Ok(blinded) = read_frame(&mut conn) {
                    let (e, proof) = epoch_key.evaluate(&blinded).unwrap();
                    if write_frame(&mut conn, &[e, proof].concat()).is_err() {
                        break;
                    }
                }
            }
        });

        let p = Arc::new(TokenPouch::new(
            &addr,
            &issuer_pin,
            &issuer_mldsa,
            &[0x33u8; 32],
            &exit_pin,
            None,
        ));
        assert_eq!(p.batch, DEFAULT_BATCH, "по умолчанию берём пачку, а не один токен");
        let mut tokens = Vec::new();
        for i in 0..DEFAULT_BATCH {
            let g = p.take_or_fetch().await.unwrap_or_else(|| panic!("грант {i}"));
            assert_eq!(g.data_psk, Some(citadel_obfs_psk_epoch([7u8; 32])), "ключ L1 эпохи (H-3)");
            tokens.push(g.token);
        }
        assert_eq!(visits.load(Ordering::SeqCst), 1, "вся пачка — за ОДИН заход к издателю");
        tokens.sort();
        tokens.dedup();
        assert_eq!(tokens.len(), DEFAULT_BATCH, "токены в пачке разные (не копия одного)");
        // Пачка кончилась → следующий грант стоит второго захода (и он тоже один на пачку).
        assert!(p.take_or_fetch().await.is_some());
        assert_eq!(visits.load(Ordering::SeqCst), 2);
        drop(p);
        let _ = srv.join();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Ключ эпохи, который издатель выводит из мастера, — тот же, что ждёт клиент (H-3).
    fn citadel_obfs_psk_epoch(master: [u8; 32]) -> [u8; 32] {
        citadel_token::psk_epoch(&master, citadel_token::current_epoch(3600))
    }

    /// Просроченная пачка не предъявляется: exit её после смены эпохи не примет, а отзыв абонента
    /// обязан срабатывать не позже конца эпохи. Просрочка чистит и ключ L1.
    #[tokio::test]
    async fn expired_batch_is_dropped_not_used() {
        let p = pouch();
        {
            let mut st = p.st.lock().unwrap();
            st.tokens = vec![vec![1], vec![2]];
            st.data_psk = Some([9u8; 32]);
            st.epoch_secs = 3600;
            st.deadline = Some(Instant::now() - Duration::from_secs(1)); // уже протухла
        }
        assert_eq!(p.left(), 0, "просроченная пачка не считается за токены");
        assert!(p.take_cached().is_none());
        let st = p.st.lock().unwrap();
        assert!(st.tokens.is_empty() && st.data_psk.is_none(), "просрочка вычищена целиком");
    }

    /// Фоновая задача обязана умирать вместе с контроллером: иначе каждая новая сессия оставляла
    /// бы за собой вечно живущую задачу с копией кошелька (и с ключом L1 в памяти).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn topup_task_dies_with_controller() {
        let c = Arc::new(VpnController::new());
        let p = pouch();
        *p.events.lock().unwrap() = Some(c.subscribe());
        p.ensure_topup();
        assert!(p.topup.load(Ordering::SeqCst), "задача запущена (есть runtime)");
        assert!(Arc::strong_count(&p) > 1, "задача держит кошелёк");
        drop(c);
        for _ in 0..50 {
            if Arc::strong_count(&p) == 1 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("фоновая задача пережила контроллер");
    }

    /// Ожидание не путает «пришло событие, но состояние то же» с «состояние сменилось»: иначе
    /// каждый `Error`/`Connecting` сбрасывал бы отсчёт разброса и дозаправка не наступала никогда.
    #[tokio::test]
    async fn waiting_ignores_events_that_do_not_change_tunnel_state() {
        let c = Arc::new(VpnController::new());
        let mut rx = c.subscribe();
        let p = pouch();
        c.begin(); // State(Connecting) — туннель как не был поднят, так и не поднят
        let mut up = false;
        assert_eq!(
            p.wait_events(&mut rx, Some(Duration::from_millis(120)), &mut up).await,
            Wake::Elapsed
        );
        assert!(!up);
        drop(c);
        assert_eq!(p.wait_events(&mut rx, None, &mut up).await, Wake::Gone);
    }

    /// Срок годности пачки — остаток эпохи по своим часам; при расхождении с издателем — половина
    /// эпохи (консервативно). Ни в одном случае пачка не живёт дольше эпохи.
    #[test]
    fn lifetime_never_exceeds_epoch() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let good = pouch_lifetime(citadel_token::current_epoch(3600), 3600);
        assert!(good <= Duration::from_secs(3600) && good > Duration::from_secs(0));
        assert_eq!(good, Duration::from_secs(3600 - now % 3600));
        let skewed = pouch_lifetime(citadel_token::current_epoch(3600) + 5, 3600);
        assert_eq!(skewed, Duration::from_secs(1800));
    }

    /// Разброс дозаправки: всегда в границах и не вырожден в константу (иначе издатель видел бы
    /// ровный ритм заходов — тот же фингерпринт, только реже).
    #[test]
    fn topup_delay_is_bounded_and_random() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let d = topup_delay(3600).as_secs();
            assert!((5..=600).contains(&d), "разброс вне границ: {d}");
            seen.insert(d);
        }
        assert!(seen.len() > 1, "задержка обязана быть случайной");
        // Короткая эпоха (стенды): верхняя граница не ниже нижней, значения валидны.
        for _ in 0..8 {
            let d = topup_delay(6).as_secs();
            assert!((5..=600).contains(&d), "короткая эпоха: {d}");
        }
    }

    /// C5.4: без issuer/seed `with_token` возвращает config без токена (passthrough, не виснет).
    #[tokio::test]
    async fn with_token_passthrough_without_layer1() {
        let cfg = crate::creds::CredentialBundle {
            version: crate::creds::BUNDLE_VERSION,
            servers: vec!["exit:4433".into()],
            server_name: "citadel.exit".into(),
            kx_suite: "pq".into(),
            cert_pin: None,
            mldsa_pub: None,
            obfs_psk: None,
            tcp_port: None,
            issuer: None,
            issuer_pub: None,
            issuer_pin: None,
            issuer_mldsa: Some([9u8; 32]),
            client_seed: None,
            admin_seed: None,
            admin_port: None,
            routes: String::new(),
            dns: None,
            exp: None,
            enroll: false,
        }
        .to_client_config();
        let out = super::with_token(cfg, None, None, None, None).await.unwrap();
        assert!(out.token.is_empty());
    }

    /// Fail-closed на границе доверия к издателю: issuer задан, но нет pin (S2.1/A1) ЛИБО нет
    /// PQ-обязательства (`issuer_mldsa`) → `with_token` возвращает ошибку, а не молча идёт в
    /// небезопасный фетч.
    #[tokio::test]
    async fn with_token_requires_pin_and_pq_commitment_when_issuer_set() {
        let cfg = crate::creds::CredentialBundle {
            version: crate::creds::BUNDLE_VERSION,
            servers: vec!["exit:4433".into()],
            server_name: "citadel.exit".into(),
            kx_suite: "pq".into(),
            cert_pin: None,
            mldsa_pub: None,
            obfs_psk: None,
            tcp_port: None,
            issuer: Some("issuer:7000".into()),
            issuer_pub: None,
            issuer_pin: None,
            issuer_mldsa: Some([9u8; 32]),
            client_seed: None,
            admin_seed: None,
            admin_port: None,
            routes: String::new(),
            dns: None,
            exp: None,
            enroll: false,
        }
        .to_client_config();
        let seed = [9u8; 32];
        // issuer без pin — отказ (A1)
        assert!(super::with_token(cfg.clone(), Some("issuer:7000"), None, Some(&[1u8; 32]), Some(&seed))
            .await
            .is_err());
        // issuer с pin, но БЕЗ PQ-обязательства издателя — тоже отказ (fail-closed, PQ-трек)
        assert!(super::with_token(cfg, Some("issuer:7000"), Some(&[2u8; 32]), None, Some(&seed))
            .await
            .is_err());
    }

    /// `install` — единственная точка постановки кошелька: без полного набора Layer-1 refresher не
    /// ставится (иначе движок ходил бы к издателю с неполными кредами и падал на каждом establish).
    #[test]
    fn install_requires_full_layer1_set() {
        let mut link = crate::creds::CredentialLink {
            version: crate::creds::BUNDLE_VERSION,
            servers: vec!["exit:4433".into()],
            server_name: "citadel.exit".into(),
            kx_suite: "pq".into(),
            cert_pin: None,
            mldsa_commit: None,
            obfs_psk: None,
            tcp_port: None,
            issuer: None,
            issuer_commit: None,
            issuer_pin: None,
            issuer_mldsa: None,
            client_seed: None,
            admin_seed: None,
            admin_port: None,
            routes: String::new(),
            dns: None,
            exp: None,
            enroll: false,
        };
        let c = Arc::new(VpnController::new());
        assert!(!install(&c, &link), "без Layer-1 — не ставим");
        link.issuer = Some("127.0.0.1:7000".into());
        link.issuer_pin = Some([1u8; 32]);
        link.client_seed = Some([2u8; 32]);
        assert!(!install(&c, &link), "без PQ-обязательства издателя — не ставим (fail-closed)");
        link.issuer_mldsa = Some([3u8; 32]);
        assert!(install(&c, &link), "полный набор — кошелёк поставлен");
    }
}
