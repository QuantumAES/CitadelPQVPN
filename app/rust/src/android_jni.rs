//! JNI-мост (C3.3): Kotlin `CitadelVpnService` регистрирует себя как socket-протектор Rust-движка.
//!
//! Движок зовёт `protect_socket(fd)` (deep в `obfs_socket`, при создании/rebind исходящего
//! сокета) → здесь это уходит в `VpnService.protect(fd)` через JNI, исключая сокет из туннеля
//! (иначе исходящий UDP/TCP к exit зациклится в собственном TUN). На desktop протектор не
//! ставится (там путь через polkit-helper).

use std::sync::{Arc, Mutex, OnceLock};

use jni::objects::{GlobalRef, JObject, JString, JValue};
use jni::{JNIEnv, JavaVM};

use citadel_client::{clear_socket_protector, set_socket_protector, SocketProtector, TunParams};

/// JavaVM захватывается при регистрации сервиса — нужна, чтобы attach'иться к JVM из
/// tokio-потоков движка (protect зовётся не из Java-потока).
static VM: OnceLock<JavaVM> = OnceLock::new();

/// GlobalRef на `CitadelVpnService` (захват в [`Java_com_quantumaes_citadelpqvpn_CitadelVpnService_nativeRegister`]) —
/// общий для `protectFd` (через [`JniProtector`]) и [`establish_tun`]. `Mutex<Option>`, а не `OnceLock`:
/// сервис может пересоздаваться (onDestroy→onCreate) — ref тогда обновляется, а не залипает мёртвым.
static SERVICE: Mutex<Option<GlobalRef>> = Mutex::new(None);

/// Протектор, делегирующий в `CitadelVpnService.protectFd(fd)` через JNI.
struct JniProtector {
    service: jni::objects::GlobalRef,
}

impl SocketProtector for JniProtector {
    fn protect(&self, fd: i32) -> bool {
        let Some(vm) = VM.get() else {
            eprintln!("[jni] нет JavaVM — сокет НЕ защищён (возможна петля)");
            return false;
        };
        let mut env = match vm.attach_current_thread() {
            Ok(e) => e,
            Err(e) => {
                eprintln!("[jni] attach_current_thread: {e}");
                return false;
            }
        };
        let res = env.call_method(self.service.as_obj(), "protectFd", "(I)Z", &[JValue::Int(fd)]);
        // ВАЖНО: очистить любое ожидающее Java-исключение ДО дропа guard'а (detach потока с
        // висящим исключением → ART вызывает abort() «JNI DETECTED ERROR», процесс падает).
        // Заодно ИЗВЛЕКАЕМ текст исключения в панель (не только logcat через describe) — нужно
        // понять, ПОЧЕМУ protect() бросает (иначе сокет не защищён → петля → нет интернета).
        if env.exception_check().unwrap_or(false) {
            let thrown = env.exception_occurred();
            let _ = env.exception_clear(); // очистить ДО любых других JNI-вызовов
            if let Ok(ex) = thrown {
                match env.call_method(&ex, "toString", "()Ljava/lang/String;", &[]) {
                    Ok(v) => match v.l() {
                        Ok(obj) => match env.get_string(&JString::from(obj)) {
                            Ok(s) => eprintln!("[jni] protectFd бросил: {}", s.to_string_lossy()),
                            Err(e) => eprintln!("[jni] protectFd бросил (не прочитать текст): {e}"),
                        },
                        Err(e) => eprintln!("[jni] protectFd бросил (нет объекта): {e}"),
                    },
                    Err(e) => eprintln!("[jni] protectFd бросил (toString не вызвать): {e}"),
                }
            }
        }
        match res {
            Ok(v) => v.z().unwrap_or(false),
            Err(e) => {
                eprintln!("[jni] VpnService.protectFd: {e}");
                false
            }
        }
    }
}

/// Kotlin `CitadelVpnService.onCreate` → зарегистрировать сервис протектором (instance-метод:
/// второй аргумент — сам `this`-сервис).
#[no_mangle]
pub extern "system" fn Java_com_quantumaes_citadelpqvpn_CitadelVpnService_nativeRegister<'local>(
    env: JNIEnv<'local>,
    service: JObject<'local>,
) {
    if let Ok(vm) = env.get_java_vm() {
        let _ = VM.set(vm);
    }
    match env.new_global_ref(&service) {
        Ok(global) => {
            // Общий ref для establish_tun; отдельный клон уходит в протектор (оба держат один
            // Java-объект — GlobalRef рефкаунтит в JVM).
            *SERVICE.lock().unwrap() = Some(global.clone());
            set_socket_protector(Arc::new(JniProtector { service: global }));
        }
        Err(e) => eprintln!("[jni] new_global_ref: {e}"),
    }
}

/// Kotlin `onDestroy` → снять протектор.
///
/// Снимаем, ТОЛЬКО если умирает тот самый сервис, который сейчас зарегистрирован. Быстрый цикл
/// «Отключить → Подключить» даёт перекрытие: новый экземпляр успевает пройти `onCreate` и
/// зарегистрироваться раньше, чем система добирается до `onDestroy` старого. Безусловный сброс в
/// этот момент снимал ЖИВОЙ протектор — и первый транспортный сокет новой сессии уходил
/// незащищённым, то есть в собственный туннель. Внешне это неотличимо от «сеть не пускает UDP».
#[no_mangle]
pub extern "system" fn Java_com_quantumaes_citadelpqvpn_CitadelVpnService_nativeUnregister<'local>(
    env: JNIEnv<'local>,
    service: JObject<'local>,
) {
    let mut slot = SERVICE.lock().unwrap();
    let mine = match slot.as_ref() {
        // `is_same_object` сравнивает Java-ссылки (GlobalRef и локальную) — это и есть «тот же
        // экземпляр сервиса». Ошибку JNI трактуем как «тот же»: лучше снять протектор лишний раз,
        // чем оставить висеть ссылку на уничтоженный сервис.
        Some(cur) => env.is_same_object(cur.as_obj(), &service).unwrap_or(true),
        None => false,
    };
    if !mine {
        eprintln!("[jni] onDestroy старого экземпляра сервиса — протектор нового не трогаю");
        return;
    }
    clear_socket_protector();
    *slot = None;
}

/// Kotlin `CitadelVpnService` NetworkCallback → сменилась underlying-сеть (WiFi↔LTE/toggle) →
/// разбудить нативный connect-loop переустановить сессию над новой сетью (S2). Зовётся из
/// Java-потока колбэка ConnectivityManager — env валиден, attach не нужен; аргументы не используются.
/// NetworkCallback теперь в СЕРВИСЕ (переживает Activity), поэтому сигнал доходит и при закрытом окне.
#[no_mangle]
pub extern "system" fn Java_com_quantumaes_citadelpqvpn_CitadelVpnService_nativeNetworkChanged<'local>(
    _env: JNIEnv<'local>,
    _service: JObject<'local>,
) {
    crate::api::citadel::notify_active_network_changed();
}

/// Kotlin `CitadelVpnService.onStartCommand` → жива ли нативная сессия в этом процессе.
///
/// Спрашивается ровно в одном случае: сервис воскрешён системой по `START_STICKY` (`intent == null`).
/// Если процесс перед этим убили, здесь новые пустые статики — сессии нет, и сервису незачем висеть
/// с нотификацией «Подключение…» над отсутствующим туннелем. Штатный старт (`startService` из
/// приложения) сюда не заходит: там сессия появляется мгновением позже.
#[no_mangle]
pub extern "system" fn Java_com_quantumaes_citadelpqvpn_CitadelVpnService_nativeHasSession<'local>(
    _env: JNIEnv<'local>,
    _service: JObject<'local>,
) -> jni::sys::jboolean {
    u8::from(crate::api::citadel::has_active_session())
}

/// Показать состояние сессии в постоянной нотификации (`CitadelVpnService.setStatus`). Зовётся из
/// форвард-задачи событий движка на каждую смену состояния — включая случай, когда окна приложения
/// нет: нотификация тогда единственный индикатор, и «туннель активен» в ней при пропавшей сети —
/// прямая ложь. Best-effort: сервис не зарегистрирован / JNI не дался → молча пропускаем (текст
/// нотификации не стоит того, чтобы ронять сессию).
pub fn set_status(state: &str) {
    let Some(vm) = VM.get() else { return };
    let Some(service) = SERVICE.lock().unwrap().clone() else { return };
    let mut env = match vm.attach_current_thread() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[jni] setStatus: attach_current_thread: {e}");
            return;
        }
    };
    let Ok(state_j) = env.new_string(state) else { return };
    let res = env.call_method(
        service.as_obj(),
        "setStatus",
        "(Ljava/lang/String;)V",
        &[JValue::Object(&state_j)],
    );
    // Как и в остальных мостах: висящее Java-исключение обязано быть очищено ДО дропа env,
    // иначе detach потока валит процесс («JNI DETECTED ERROR»).
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
    }
    if let Err(e) = res {
        eprintln!("[jni] CitadelVpnService.setStatus: {e}");
    }
}

// Итог захвата IPv6 в туннель — те же значения, что константы `IPV6_*` в `CitadelVpnService`.
/// blackhole поставлен: весь IPv6 уходит в туннель (и там дропается exit'ом).
pub const IPV6_CAPTURED: i32 = 0;
/// blackhole не встал И у приложений под VPN есть путь наружу по IPv6 — это УТЕЧКА (N-1).
pub const IPV6_FALLBACK: i32 = 1;
/// Захват неприменим: не full-tunnel (split-include) — IPv6 идёт напрямую по выбору человека.
pub const IPV6_SPLIT: i32 = 2;
/// blackhole не встал, но пути наружу по IPv6 нет вовсе (Android кладёт `unreachable ::/0` в
/// таблицу VPN-сети, когда в конфиге VpnService нет ни v6-адреса, ни v6-маршрута). Цель S2.2/A2
/// достигнута — предупреждать не о чем. Штатный исход на Android: TUN ужат под бюджет
/// QUIC-датаграммы (1161 б), а IPv6 на интерфейсе с MTU < 1280 ядро не поднимает вовсе.
pub const IPV6_BLOCKED: i32 = 3;

/// Итог последней попытки захватить IPv6 (`CitadelVpnService.ipv6State()`, S2.2/A2). Спрашивается
/// сразу после [`establish_tun`]: молчаливый фолбэк без blackhole означает нативный IPv6 мимо
/// туннеля на dual-stack, и человек обязан это увидеть (находка N-1).
///
/// Мост не дался → отвечаем [`IPV6_SPLIT`] («предупреждать не о чем»): выдумывать утечку там, где
/// мы просто не смогли спросить, значит приучать человека игнорировать предупреждение.
pub fn ipv6_state() -> i32 {
    let Some(vm) = VM.get() else { return IPV6_SPLIT };
    let Some(service) = SERVICE.lock().unwrap().clone() else {
        return IPV6_SPLIT;
    };
    let Ok(mut env) = vm.attach_current_thread() else {
        return IPV6_SPLIT;
    };
    let res = env.call_method(service.as_obj(), "ipv6State", "()I", &[]);
    // Висящее Java-исключение обязано быть очищено ДО дропа env (иначе detach валит процесс).
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
    }
    match res.and_then(|v| v.i()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[jni] CitadelVpnService.ipv6State: {e}");
            IPV6_SPLIT
        }
    }
}

/// Построить TUN через `CitadelVpnService.establishTun(...)` (JNI, Rust→Kotlin) → detached fd.
/// Зовётся из `AndroidTunProvider::configure` в нативном `VpnController::connect`-loop
/// (tokio-поток, НЕ Java-поток → `attach_current_thread`, как `protectFd`). routes/dns передаём
/// строкой через пробел (Kotlin делит) — так не строим jobjectArray. Возврат: fd (≥0) либо `Err`
/// (сервис не зарегистрирован / establish бросил / вернул невалидный fd).
pub fn establish_tun(p: &TunParams, require_v6: bool) -> anyhow::Result<i32> {
    let vm = VM
        .get()
        .ok_or_else(|| anyhow::anyhow!("нет JavaVM — CitadelVpnService не зарегистрирован"))?;
    let service = SERVICE
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| anyhow::anyhow!("CitadelVpnService не зарегистрирован"))?;
    let mut env = vm.attach_current_thread()?;

    let addr = format!("{}.{}.{}.{}", p.addr[0], p.addr[1], p.addr[2], p.addr[3]);
    let mtu: i32 = p.mtu.parse().unwrap_or(1280);
    let addr_j = env.new_string(&addr)?;
    let routes_j = env.new_string(&p.routes)?;
    let dns_j = env.new_string(p.dns.as_deref().unwrap_or(""))?;
    // C8.3 split-tunnel: режимы строкой, списки — через пробел (package-имена и CIDR пробелов не
    // содержат → безопасно join'ить). Kotlin применяет фильтр приложений и/или маршрутов назначений.
    let app_mode_j = env.new_string(p.app_mode.as_str())?;
    let apps_j = env.new_string(p.apps.join(" "))?;
    let dest_mode_j = env.new_string(p.dest_mode.as_str())?;
    let dest_routes_j = env.new_string(p.dest_routes.join(" "))?;

    let res = env.call_method(
        service.as_obj(),
        "establishTun",
        "(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)I",
        &[
            JValue::Object(&addr_j),
            JValue::Int(p.prefix as i32),
            JValue::Object(&routes_j),
            JValue::Object(&dns_j),
            JValue::Int(mtu),
            JValue::Object(&app_mode_j),
            JValue::Object(&apps_j),
            JValue::Object(&dest_mode_j),
            JValue::Object(&dest_routes_j),
            JValue::Bool(u8::from(require_v6)),
        ],
    );
    // Очистить любое ожидающее Java-исключение ДО дропа env (detach потока с висящим исключением →
    // ART abort «JNI DETECTED ERROR»), извлекая текст в лог: иначе establishTun молча вернёт ошибку
    // и не понять, почему нет TUN (нет VPN-разрешения / кривые маршруты / …). Тот же порядок, что в
    // `JniProtector::protect`: exception_clear ДО любых других JNI-вызовов.
    let mut thrown_text = String::new();
    if env.exception_check().unwrap_or(false) {
        let thrown = env.exception_occurred();
        let _ = env.exception_clear();
        if let Ok(ex) = thrown {
            if let Ok(v) = env.call_method(&ex, "toString", "()Ljava/lang/String;", &[]) {
                if let Ok(obj) = v.l() {
                    if let Ok(s) = env.get_string(&JString::from(obj)) {
                        thrown_text = s.to_string_lossy().into_owned();
                        eprintln!("[jni] establishTun бросил: {thrown_text}");
                    }
                }
            }
        }
    }
    match res {
        Ok(v) => Ok(v.i()?),
        // Текст Java-исключения кладём В САМУ ошибку, а не только в лог: причина отказа доходит до
        // экрана (UI разбирает её в `AppState._classify` — например, отказ строгого IPv6, N-1), а
        // при выключенном режиме отладки журнала попросту нет. `{e}` в jni-rs — это «Java exception
        // was thrown» без единого слова о том, какое именно.
        Err(e) if thrown_text.is_empty() => Err(anyhow::anyhow!("VpnService.establishTun: {e}")),
        Err(_) => Err(anyhow::anyhow!("VpnService.establishTun: {thrown_text}")),
    }
}
