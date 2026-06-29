//! JNI-мост (C3.3): Kotlin `CitadelVpnService` регистрирует себя как socket-протектор Rust-движка.
//!
//! Движок зовёт `protect_socket(fd)` (deep в `obfs_socket`, при создании/rebind исходящего
//! сокета) → здесь это уходит в `VpnService.protect(fd)` через JNI, исключая сокет из туннеля
//! (иначе исходящий UDP/TCP к exit зациклится в собственном TUN). На desktop протектор не
//! ставится (там путь через polkit-helper).

use std::sync::{Arc, OnceLock};

use jni::objects::{JObject, JValue};
use jni::{JNIEnv, JavaVM};

use citadel_client::{clear_socket_protector, set_socket_protector, SocketProtector};

/// JavaVM захватывается при регистрации сервиса — нужна, чтобы attach'иться к JVM из
/// tokio-потоков движка (protect зовётся не из Java-потока).
static VM: OnceLock<JavaVM> = OnceLock::new();

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
        match env.call_method(self.service.as_obj(), "protectFd", "(I)Z", &[JValue::Int(fd)]) {
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
pub extern "system" fn Java_com_example_app_CitadelVpnService_nativeRegister<'local>(
    env: JNIEnv<'local>,
    service: JObject<'local>,
) {
    if let Ok(vm) = env.get_java_vm() {
        let _ = VM.set(vm);
    }
    match env.new_global_ref(&service) {
        Ok(global) => set_socket_protector(Arc::new(JniProtector { service: global })),
        Err(e) => eprintln!("[jni] new_global_ref: {e}"),
    }
}

/// Kotlin `onDestroy` → снять протектор.
#[no_mangle]
pub extern "system" fn Java_com_example_app_CitadelVpnService_nativeUnregister<'local>(
    _env: JNIEnv<'local>,
    _service: JObject<'local>,
) {
    clear_socket_protector();
}
