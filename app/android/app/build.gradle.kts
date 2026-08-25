import java.util.Properties

plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

// ── Релизный keystore ───────────────────────────────────────────────────────────────────────
// Источник подписи ищем в двух местах и НИКОГДА не в репозитории:
//   1) android/key.properties (локальная сборка релиза; в .gitignore);
//   2) переменные окружения CITADEL_KEYSTORE / _PASSWORD / _KEY_ALIAS / _KEY_PASSWORD (CI:
//      GitHub Secrets → файл на раннере, см. .github/workflows/release.yml).
// Не нашли — release подписывается debug-ключом, как в шаблоне Flutter, чтобы
// `flutter build apk --release` работал у любого разработчика. Такой APK годится ТОЛЬКО для
// локальной проверки: подпись debug-ключом означает «источник не проверен», и обновление
// поверх релизной сборки на устройстве не встанет (разные подписи).
val keystoreProps = Properties().apply {
    val f = rootProject.file("key.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}

fun signingValue(prop: String, env: String): String? =
    (keystoreProps.getProperty(prop) ?: System.getenv(env))?.takeIf { it.isNotBlank() }

val releaseStoreFile = signingValue("storeFile", "CITADEL_KEYSTORE")?.let { file(it) }
val hasReleaseKey = releaseStoreFile?.exists() == true

android {
    namespace = "com.quantumaes.citadelpqvpn"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        // Идентификатор приложения в экосистеме Android. Менять его после публикации нельзя:
        // для системы это другое приложение (обновление поверх не встанет, данные не переедут).
        applicationId = "com.quantumaes.citadelpqvpn"
        // You can update the following values to match your application needs.
        // For more information, see: https://flutter.dev/to/review-gradle-config.
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    signingConfigs {
        if (hasReleaseKey) {
            create("release") {
                storeFile = releaseStoreFile
                storePassword = signingValue("storePassword", "CITADEL_KEYSTORE_PASSWORD")
                keyAlias = signingValue("keyAlias", "CITADEL_KEY_ALIAS")
                keyPassword = signingValue("keyPassword", "CITADEL_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            signingConfig = if (hasReleaseKey) {
                signingConfigs.getByName("release")
            } else {
                // Молчаливый откат на debug-ключ — это релиз, который никто не сможет обновить
                // и чей источник не подтверждён, поэтому о нём говорим вслух. NB: `flutter build`
                // фильтрует вывод gradle, и увидеть эту строку можно при `-v` или при прямом
                // вызове gradle — так что единственная НАДЁЖНАЯ преграда не здесь, а в
                // tools/mk-client-release.sh: он проверяет подпись готового APK через apksigner
                // и отказывается класть debug-сборку в релиз.
                logger.lifecycle(
                    "CitadelPQVPN: релизного keystore нет (key.properties / CITADEL_KEYSTORE) — " +
                        "APK будет подписан DEBUG-ключом, для распространения он НЕ годится",
                )
                signingConfigs.getByName("debug")
            }

            // R8/minify ВЫКЛ для release. Причина: движок зовёт CitadelVpnService.protectFd(int)
            // по имени через JNI (socket-protector, анти-петля C3.3). R8 не видит этот вызов как
            // reachable и ВЫРЕЗАЕТ метод → NoSuchMethodError → сокет не защищён → маршрутная петля
            // → туннель up, но нет интернета. Для pre-release корректность важнее размера APK.
            // proguard-rules.pro держит keep-правила, если minify когда-нибудь включат обратно.
            // Flutter 3.44 по умолчанию включает и minify, и shrinkResources для release —
            // отключаем ОБА (shrinkResources требует minify, иначе gradle падает).
            isMinifyEnabled = false
            isShrinkResources = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }
}

dependencies {
    // C9: системный диалог отпечатка поверх CryptoObject (androidx.biometric умеет это с API 23,
    // платформенный android.hardware.biometrics.BiometricPrompt — только с 28). Тянет за собой
    // androidx.fragment — отсюда и FlutterFragmentActivity в MainActivity.
    implementation("androidx.biometric:biometric:1.1.0")
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

flutter {
    source = "../.."
}
