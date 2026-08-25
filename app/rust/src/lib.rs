pub mod api;
mod frb_generated;

// Android: JNI-экспорты для регистрации VpnService как socket-протектора (C3.3).
// Вне api/ — это не frb-поверхность, а нативные Java_* символы для Kotlin.
#[cfg(target_os = "android")]
mod android_jni;
