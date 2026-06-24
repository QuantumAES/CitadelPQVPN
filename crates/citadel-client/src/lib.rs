//! CitadelPQVPN — встраиваемое клиентское ядро (FFI-вуаль).
//!
//! Тонкий крейт поверх `citadel_quic::{vpn,config}`: собирается как `cdylib`/`staticlib`
//! и линкуется в GUI (Flutter через flutter_rust_bridge; Android/iOS через UniFFI).
//! Серверный бинарь `citadel-m1` сюда НЕ входит (он живёт в citadel-quic) — GUI тянет
//! только клиентскую поверхность. Биндинги (Dart/Kotlin/Swift) генерируются на треке C2.
//!
//! C0.6: каркас + cdylib + кросс-сборка под Android. Де-риск R1 (aws-lc-rs под NDK) пройден —
//! `cargo ndk -t arm64-v8a build` собирает ядро с PQ-криптой под aarch64-linux-android.

pub mod creds;

// Поверхность движка для FFI/UI: один крейт, чтобы биндинг-генератор видел всё в одном месте.
pub use citadel_quic::config::{ClientConfig, MldsaSource, PinMode, PinSource};
pub use citadel_quic::vpn::{TunParams, TunProvider, VpnController, VpnEvent, VpnState};
pub use creds::{CredentialBundle, CredentialLink, BUNDLE_VERSION};

/// Версия ядра (about-экран UI / диагностика).
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
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
