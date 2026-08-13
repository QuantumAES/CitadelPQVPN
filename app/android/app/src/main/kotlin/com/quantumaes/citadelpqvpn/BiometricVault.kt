package com.quantumaes.citadelpqvpn

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * C9: разблокировка хранилища отпечатком — платформенная половина.
 *
 * Ядро (`citadel_client::vault`) отдаёт сюда мастер-ключ хранилища, здесь он заворачивается ключом
 * **Android Keystore**, который: (1) неэкспортируем — живёт в TEE/StrongBox и наружу не выходит
 * даже с root; (2) требует биометрической аутентификации на КАЖДУЮ операцию; (3) уничтожается
 * системой, если в устройство добавили новый отпечаток. Наружу отдаётся непрозрачный блоб
 * `IV(12) ‖ AES-256-GCM(мастер-ключ)`, который ядро кладёт в файл хранилища отдельным слотом.
 *
 * **Почему не «спросить, приложен ли палец»:** `BiometricPrompt` без `CryptoObject` возвращает
 * обычное булево «да» в память приложения — на рутованном устройстве оно подделывается хуком за
 * минуту, и «биометрическая защита» превращается в декорацию. Здесь расшифровку выполняет сам
 * Keystore и только после успешной аутентификации: подделывать «да» бесполезно.
 *
 * **Почему только BIOMETRIC_STRONG и без DEVICE_CREDENTIAL:** системный PIN/графический ключ знают
 * все, кто когда-либо видел, как человек разблокирует телефон, а слабая биометрия (класс 2, напр.
 * распознавание лица по фронтальной камере) не допускается к ключам Keystore в принципе. Резервный
 * путь у нас один и он честный — мастер-пароль хранилища.
 */
object BiometricVault {
    const val CHANNEL = "citadel/biometric"

    private const val ALIAS = "citadel-vault-master-key"
    private const val STORE = "AndroidKeyStore"
    private const val TRANSFORM = "AES/GCM/NoPadding"
    private const val IV_LEN = 12
    private const val TAG_BITS = 128

    /** Что вернуть Dart'у, чтобы он решил, показывать ли настройку вообще. */
    private const val OK = "ok"
    private const val NO_HARDWARE = "no_hardware"
    private const val NONE_ENROLLED = "none_enrolled"
    private const val UNAVAILABLE = "unavailable"

    /** Ключ Keystore уничтожен системой (сменилась биометрия устройства) — слот в файле мёртв. */
    private const val ERR_INVALIDATED = "invalidated"
    private const val ERR_CANCELLED = "cancelled"
    private const val ERR_NO_KEY = "no_key"

    fun register(activity: FragmentActivity, ch: MethodChannel) {
        ch.setMethodCallHandler { call, result ->
            when (call.method) {
                "status" -> result.success(status(activity))
                "wrap" -> wrap(activity, call, result)
                "unwrap" -> unwrap(activity, call, result)
                "remove" -> {
                    deleteKey()
                    result.success(true)
                }
                else -> result.notImplemented()
            }
        }
    }

    /**
     * Готова ли биометрия к работе С КЛЮЧАМИ. Спрашиваем именно про `BIOMETRIC_STRONG`: слабый
     * класс к Keystore не допускается, и «датчик есть» ещё не значит «ключ получится сделать».
     */
    private fun status(activity: FragmentActivity): String {
        if (Build.VERSION.SDK_INT < 23) return NO_HARDWARE // Keystore с user-auth появился в M
        return when (
            BiometricManager.from(activity)
                .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        ) {
            BiometricManager.BIOMETRIC_SUCCESS -> OK
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> NONE_ENROLLED
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> NO_HARDWARE
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> UNAVAILABLE
            else -> UNAVAILABLE
        }
    }

    /**
     * Включение: перевыпустить ключ и завернуть им мастер-ключ хранилища.
     *
     * Ключ именно ПЕРЕвыпускается: включение биометрии заново должно обнулять всё, что было
     * завёрнуто прежним ключом (иначе старый блоб из резервной копии файла оставался бы рабочим).
     */
    private fun wrap(activity: FragmentActivity, call: MethodCall, result: MethodChannel.Result) {
        val secret = call.argument<ByteArray>("secret")
        if (secret == null || secret.isEmpty()) {
            result.error("args", "нет ключа для обёртки", null)
            return
        }
        val cipher = try {
            deleteKey()
            createKey()
            Cipher.getInstance(TRANSFORM).apply { init(Cipher.ENCRYPT_MODE, requireKey()) }
        } catch (e: Exception) {
            result.error("keystore", e.message ?: e.toString(), null)
            return
        }
        prompt(activity, call, cipher) { c, err ->
            if (c == null) {
                deleteKey() // не подтвердил — не оставляем висеть бесхозный ключ
                result.error(err ?: ERR_CANCELLED, err, null)
                return@prompt
            }
            try {
                val ct = c.doFinal(secret)
                val iv = c.iv
                // IV у GCM из Keystore всегда 12 байт; проверяем, а не полагаемся — от длины
                // зависит разбор блоба при разворачивании.
                if (iv.size != IV_LEN) {
                    deleteKey()
                    result.error("keystore", "неожиданная длина IV: ${iv.size}", null)
                } else {
                    result.success(iv + ct)
                }
            } catch (e: Exception) {
                deleteKey()
                result.error("keystore", e.message ?: e.toString(), null)
            } finally {
                secret.fill(0) // копия ключа в Kotlin живёт ровно до этой строки
            }
        }
    }

    /** Разблокировка: развернуть мастер-ключ из блоба после успешного отпечатка. */
    private fun unwrap(activity: FragmentActivity, call: MethodCall, result: MethodChannel.Result) {
        val blob = call.argument<ByteArray>("blob")
        if (blob == null || blob.size <= IV_LEN) {
            result.error("args", "повреждённый блоб", null)
            return
        }
        val key = existingKey()
        if (key == null) {
            // Ключа нет: приложение переустановили, данные очистили, ключ удалён. Слот в файле
            // остался, но развернуть его нечем — честно говорим об этом, вход по паролю работает.
            result.error(ERR_NO_KEY, "ключ биометрии отсутствует", null)
            return
        }
        val cipher = try {
            Cipher.getInstance(TRANSFORM).apply {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, blob, 0, IV_LEN))
            }
        } catch (e: KeyPermanentlyInvalidatedException) {
            // Ровно то, ради чего стоит setInvalidatedByBiometricEnrollment: в устройство добавили
            // новый отпечаток — прежний ключ система уничтожила, и хранилище им больше не открыть.
            result.error(ERR_INVALIDATED, e.message, null)
            return
        } catch (e: Exception) {
            result.error("keystore", e.message ?: e.toString(), null)
            return
        }
        prompt(activity, call, cipher) { c, err ->
            if (c == null) {
                result.error(err ?: ERR_CANCELLED, err, null)
                return@prompt
            }
            try {
                result.success(c.doFinal(blob, IV_LEN, blob.size - IV_LEN))
            } catch (e: Exception) {
                result.error("keystore", e.message ?: e.toString(), null)
            }
        }
    }

    /**
     * Системный диалог отпечатка поверх `CryptoObject`. Тексты присылает Dart — язык интерфейса
     * выбирает пользователь в приложении, и системная локаль тут не указ (та же логика, что у
     * строк постоянной нотификации в [MainActivity]).
     */
    private fun prompt(
        activity: FragmentActivity,
        call: MethodCall,
        cipher: Cipher,
        done: (Cipher?, String?) -> Unit,
    ) {
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(call.argument<String>("title") ?: "CitadelPQVPN")
            .setSubtitle(call.argument<String>("subtitle") ?: "")
            .setNegativeButtonText(call.argument<String>("cancel") ?: "Отмена")
            // Только сильная биометрия и БЕЗ системного PIN: пароль хранилища — единственный
            // резервный путь, и подменять его тем, что знает окружение человека, нельзя.
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setConfirmationRequired(false)
            .build()

        val prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(r: BiometricPrompt.AuthenticationResult) {
                    done(r.cryptoObject?.cipher, null)
                }

                override fun onAuthenticationError(code: Int, msg: CharSequence) {
                    val why = when (code) {
                        BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                        BiometricPrompt.ERROR_USER_CANCELED,
                        BiometricPrompt.ERROR_CANCELED,
                        -> ERR_CANCELLED
                        else -> "$code: $msg"
                    }
                    done(null, why)
                }
                // onAuthenticationFailed (палец не распознан) намеренно не переопределяем:
                // системный диалог сам предлагает повторить, а завершать по нему сценарий —
                // значит закрывать окно на первом же смазанном касании.
            },
        )
        prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }

    // ── Keystore ──

    private fun keyStore(): KeyStore = KeyStore.getInstance(STORE).apply { load(null) }

    private fun existingKey(): SecretKey? =
        try {
            keyStore().getKey(ALIAS, null) as? SecretKey
        } catch (e: Exception) {
            null
        }

    private fun requireKey(): SecretKey =
        existingKey() ?: throw IllegalStateException("ключ биометрии не создан")

    private fun deleteKey() {
        try {
            keyStore().deleteEntry(ALIAS)
        } catch (e: Exception) {
            // нечего удалять — не ошибка
        }
    }

    /**
     * Создать ключ обёртки. Существенны все четыре ограничения:
     *   * `setUserAuthenticationRequired` — без аутентификации ключ не работает вообще;
     *   * `setInvalidatedByBiometricEnrollment` (24+) — добавили в устройство чужой палец → ключ
     *     уничтожен. Без этого тот, кто знает PIN, добавляет свой отпечаток и открывает хранилище;
     *   * `setUnlockedDeviceRequired` (28+) — ключом нельзя пользоваться на запертом экране;
     *   * `setUserAuthenticationParameters(0, BIOMETRIC_STRONG)` (30+) / `…Seconds(-1)` (23–29) —
     *     аутентификация на КАЖДУЮ операцию, а не «действует N секунд после разблокировки».
     */
    private fun createKey() {
        val spec = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
        if (Build.VERSION.SDK_INT >= 24) spec.setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= 28) spec.setUnlockedDeviceRequired(true)
        if (Build.VERSION.SDK_INT >= 30) {
            spec.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        } else {
            @Suppress("DEPRECATION")
            spec.setUserAuthenticationValidityDurationSeconds(-1)
        }

        // StrongBox (выделенный чип) — где есть; где нет, генерация падает
        // StrongBoxUnavailableException, и мы повторяем на обычном TEE. Разница для нас не
        // принципиальна (оба неэкспортируемы), поэтому отсутствие StrongBox не повод отказывать.
        if (Build.VERSION.SDK_INT >= 28) {
            try {
                generate(spec.setIsStrongBoxBacked(true).build())
                return
            } catch (e: Exception) {
                spec.setIsStrongBoxBacked(false)
            }
        }
        generate(spec.build())
    }

    private fun generate(spec: KeyGenParameterSpec) {
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, STORE).apply {
            init(spec)
            generateKey()
        }
    }
}
