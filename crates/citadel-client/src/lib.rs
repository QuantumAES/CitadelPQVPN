//! CitadelPQVPN — встраиваемое клиентское ядро (FFI-вуаль).
//!
//! Тонкий крейт поверх `citadel_quic::{vpn,config}`: собирается как `cdylib`/`staticlib`
//! и линкуется в GUI (Flutter через flutter_rust_bridge; Android/iOS через UniFFI).
//! Серверный бинарь `citadel-m1` сюда НЕ входит (он живёт в citadel-quic) — GUI тянет
//! только клиентскую поверхность. Биндинги (Dart/Kotlin/Swift) генерируются на треке C2.
//!
//! C0.6: каркас + cdylib + кросс-сборка под Android. Де-риск R1 (aws-lc-rs под NDK) пройден —
//! `cargo ndk -t arm64-v8a build` собирает ядро с PQ-криптой под aarch64-linux-android.

pub mod api;
pub mod creds;
pub mod vault;
pub mod token_agent; // C5.3: добыча Layer-1 epoch-токенов у issuer (async-обёртка над citadel_token)
pub mod enroll; // M-9: активация первичной ссылки (одноразовость + срок годности + заверение)
pub mod admin; // C7.3: admin-плоскость по туннелю (управление реестром + минт клиентских ссылок), все платформы
// gui_tun компилируется и на Android (unix SCM_RIGHTS/UnixSocket), но там НЕ используется —
// мобильный путь идёт через VpnService (android_establish/run_data_plane). Нужно, чтобы
// frb_generated.rs (ссылается на vpn_connect → GuiTunProvider) собирался под android.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod gui_tun;
// L-7/L-8 (аудит-4): модуль `deploy` (SSH-деплой сервера через russh, C4/C5.5) УДАЛЁН.
// Путь был мёртв с перехода на in-band admin-плоскость (C7.3, см. api/admin.rs), но продолжал
// собираться в desktop-бинарь и тянуть за собой `russh 0.61` вместе с pre-release зависимостями
// (`ssh-key 0.7.0-rc.10`, `argon2 0.6.0-rc.8`), а внутри содержал `MemoryTofu`, молча принимавший
// ЛЮБОЙ SSH host-key, и неэкранированную сборку `registry_cmd`. Единственный админский путь —
// `citadel_client::admin` по туннелю (PQ-TLS + pin + ML-DSA-подпись домена admin).
// C3-Windows (W2): платформо-нейтральное ядро сервис-модели (IPC-кадры app↔служба, WFP-план,
// маршруты). Компилируется на ВСЕХ ОС (юнит-тесты гоняются на Linux); WinAPI живёт в cfg(windows)
// провайдере/службе, что потребляют эти планы. Аналог чистых функций killswitch_rules в helper.
pub mod winnet;
// C3-Windows (W2): WindowsTunProvider — TunProvider поверх named pipe к службе citadel-svc.
// Только Windows (WinAPI/пайп-путь); движок в приложении, как GuiTunProvider на Linux.
#[cfg(windows)]
pub mod win_tun;

// Поверхность движка для FFI/UI: один крейт, чтобы биндинг-генератор видел всё в одном месте.
pub use citadel_quic::config::{
    parse_obfs_psk, parse_pin, ClientConfig, MldsaSource, PinMode, PinSource, SplitMode, SplitTunnel,
};
pub use citadel_quic::client::{establish_session, run_data_plane, Session};
// Индикация скорости в UI: монотонные счётчики inner-байтов туннеля (клиентская сторона).
pub use citadel_quic::dataplane::traffic_bytes;
pub use citadel_quic::diag::{run_diagnostics, DiagStep};
pub use citadel_quic::protect::{clear_socket_protector, set_socket_protector, SocketProtector};
pub use citadel_quic::vpn::{
    clamp_tun_mtu, SessionGrant, TunParams, TunProvider, VpnController, VpnEvent, VpnState,
};
pub use citadel_tun::TunIo;
pub use creds::{CredentialBundle, CredentialLink, BUNDLE_VERSION, DEFAULT_ADMIN_PORT};
pub use admin::{
    admin_issue, admin_list, admin_probe_dst, admin_revoke, build_subscriber_link, IssuedLink,
    SubscriberEntry,
};
pub use vault::{
    IssuedRecord, Profile, Vault, VaultOpenError, MAX_PROFILE_NAME_LEN, MIN_PASSPHRASE_LEN,
};
pub use enroll::{activate_profile, activate_profile_blocking, effective_seed, Activation};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use gui_tun::GuiTunProvider;
#[cfg(windows)]
pub use win_tun::WindowsTunProvider;

/// Версия ядра (about-экран UI / диагностика).
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Обернуть TUN-fd в [`TunIo`] для `run_data_plane`. Источник fd:
/// Android — `VpnService.establish()` (`ParcelFileDescriptor.detachFd()`), Linux — citadel-helper.
///
/// # Safety
/// `fd` должен быть валидным открытым TUN-дескриптором, которым не владеет никто другой
/// (берётся владение, закроется при дропе).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub unsafe fn tun_from_fd(fd: i32) -> std::sync::Arc<dyn TunIo> {
    // SAFETY: контракт делегирован вызывающему (см. # Safety).
    std::sync::Arc::new(citadel_tun::Tun::from_raw_fd(fd))
}

/// C-ABI якорь: подтверждает, что `cdylib` экспортирует символы (smoke для FFI-линковки).
/// Полноценный typed API (Dart/Kotlin/Swift) генерируется на C2; пока — версия ABI-контракта.
#[no_mangle]
pub extern "C" fn citadel_client_abi_version() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_nonempty() {
        assert!(!super::version().is_empty());
    }

    #[test]
    fn abi_anchor() {
        assert_eq!(super::citadel_client_abi_version(), 1);
    }
}
