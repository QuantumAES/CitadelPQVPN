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
#[no_mangle]
pub extern "system" fn Java_com_quantumaes_citadelpqvpn_CitadelVpnService_nativeUnregister<'local>(
    _env: JNIEnv<'local>,
    _service: JObject<'local>,
) {
    clear_socket_protector();
    *SERVICE.lock().unwrap() = None;
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

/// Построить TUN через `CitadelVpnService.establishTun(...)` (JNI, Rust→Kotlin) → detached fd.
/// Зовётся из `AndroidTunProvider::configure` в нативном `VpnController::connect`-loop
/// (tokio-поток, НЕ Java-поток → `attach_current_thread`, как `protectFd`). routes/dns передаём
/// строкой через пробел (Kotlin делит) — так не строим jobjectArray. Возврат: fd (≥0) либо `Err`
/// (сервис не зарегистрирован / establish бросил / вернул невалидный fd).
pub fn establish_tun(p: &TunParams) -> anyhow::Result<i32> {
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
        "(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I",
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
        ],
    );
    // Очистить любое ожидающее Java-исключение ДО дропа env (detach потока с висящим исключением →
    // ART abort «JNI DETECTED ERROR»), извлекая текст в лог: иначе establishTun молча вернёт ошибку
    // и не понять, почему нет TUN (нет VPN-разрешения / кривые маршруты / …). Тот же порядок, что в
    // `JniProtector::protect`: exception_clear ДО любых других JNI-вызовов.
    if env.exception_check().unwrap_or(false) {
        let thrown = env.exception_occurred();
        let _ = env.exception_clear();
        if let Ok(ex) = thrown {
            if let Ok(v) = env.call_method(&ex, "toString", "()Ljava/lang/String;", &[]) {
                if let Ok(obj) = v.l() {
                    if let Ok(s) = env.get_string(&JString::from(obj)) {
                        eprintln!("[jni] establishTun бросил: {}", s.to_string_lossy());
                    }
                }
            }
        }
    }
    match res {
        Ok(v) => Ok(v.i()?),
        Err(e) => Err(anyhow::anyhow!("VpnService.establishTun: {e}")),
    }
}
