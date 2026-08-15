package com.quantumaes.citadelpqvpn

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.view.WindowManager
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * Мост Dart ↔ Android VpnService (трек C3.2). Канал `dev.citadelpqvpn/vpn`:
 *   prepare      → системный консент VpnService (один раз) → Bool granted
 *   startService → запустить foreground CitadelVpnService → Bool ready
 *   stopService  → остановить сервис
 * TUN строит Rust напрямую (JNI → CitadelVpnService.establishTun) в нативном connect-loop, не Dart.
 * Мониторинг underlying-сети (WiFi↔LTE) и сигнал реконнекта при её смене живут в CitadelVpnService
 * (S2 — переживают Activity, работают при закрытом окне), а не здесь: Activity в смене сети больше
 * не участвует.
 *
 * Второй канал — `citadel/biometric` (C9, разблокировка хранилища отпечатком, см. [BiometricVault]).
 *
 * NB: базовый класс — `FlutterFragmentActivity`, а не `FlutterActivity`. Это требование
 * `androidx.biometric`: системный диалог отпечатка живёт во фрагменте и без `FragmentActivity`
 * падает в рантайме. Для остального кода замена прозрачна (тот же жизненный цикл, тот же движок).
 */
class MainActivity : FlutterFragmentActivity() {
    private val channelName = "dev.citadelpqvpn/vpn"
    private val reqVpn = 0x1011
    private var prepareResult: MethodChannel.Result? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // C8.5: по умолчанию ЗАПРЕЩАЕМ скриншоты/запись экрана (FLAG_SECURE) — ставим в onCreate,
        // чтобы защитить и самый ранний кадр, и превью в «Недавних». Dart снимет флаг, если юзер
        // выключил (setSecureFlag(false)); дефолт (файла нет) — запрет включён.
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        // C9: разблокировка хранилища отпечатком — свой канал, своя ответственность (Keystore +
        // BiometricPrompt). К VPN отношения не имеет и с ним не пересекается.
        BiometricVault.register(
            this,
            MethodChannel(flutterEngine.dartExecutor.binaryMessenger, BiometricVault.CHANNEL),
        )

        val ch = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, channelName)
        ch.setMethodCallHandler { call, result ->
            when (call.method) {
                "prepare" -> {
                    val intent = VpnService.prepare(this)
                    if (intent != null) {
                        prepareResult = result
                        startActivityForResult(intent, reqVpn)
                    } else {
                        result.success(true)
                    }
                }
                "startService" -> {
                    // `ready()`, а не `instance != null`: экземпляр, получивший stopSelf, ещё жив,
                    // но его onDestroy снимет протектор уже из-под новой сессии. Такой считаем
                    // отсутствующим и поднимаем сервис заново — ждать готовности нового экземпляра.
                    if (CitadelVpnService.ready()) {
                        result.success(true) // уже запущен (реконнект)
                    } else {
                        // ждём onCreate+nativeRegister: протектор сокетов должен встать ДО
                        // establish, иначе первый сокет движка уйдёт незащищённым (петля).
                        // Незакрытый прошлый запрос (сервис умер, не дойдя до onCreate) закрываем
                        // сами: иначе тот await в Dart висел бы вечно, и «Подключить» не работало бы.
                        CitadelVpnService.onServiceReady?.invoke()
                        CitadelVpnService.onServiceReady = {
                            runOnUiThread { result.success(true) }
                        }
                        val i = Intent(this, CitadelVpnService::class.java)
                        if (Build.VERSION.SDK_INT >= 26) startForegroundService(i) else startService(i)
                    }
                }
                "stopService" -> {
                    CitadelVpnService.instance?.stopTun()
                    result.success(true)
                }
                // Язык интерфейса выбирает пользователь в приложении, а постоянная нотификация —
                // часть того же интерфейса (и единственное, что видно о VPN при закрытом окне).
                // Поэтому её тексты присылает Dart, а не берутся из системной локали.
                "setNotifStrings" -> {
                    CitadelVpnService.setNotifStrings(
                        call.argument<String>("up") ?: CitadelVpnService.STATUS_UP,
                        call.argument<String>("connecting") ?: CitadelVpnService.STATUS_CONNECTING,
                        call.argument<String>("reconnecting") ?: CitadelVpnService.STATUS_RECONNECTING,
                        call.argument<String>("down") ?: CitadelVpnService.STATUS_DOWN,
                    )
                    result.success(true)
                }
                "setSecureFlag" -> {
                    // C8.5: включить/снять FLAG_SECURE (запрет скриншотов). Dart зовёт на старте
                    // (из сохранённой настройки) и по тумблеру. Флаги окна — только с UI-потока.
                    val on = call.argument<Boolean>("on") ?: true
                    runOnUiThread {
                        if (on) {
                            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                        } else {
                            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                        }
                    }
                    result.success(true)
                }
                // П8 (маскировка/батарея): система сама говорит, что экономит заряд. Строгий
                // профиль маскировки на это время понижается до экономного — решение принимает
                // ядро, здесь только факт от `PowerManager`.
                "powerSaveMode" -> {
                    val pm = getSystemService(Context.POWER_SERVICE) as? PowerManager
                    result.success(pm?.isPowerSaveMode ?: false)
                }
                "listInstalledApps" -> {
                    // C8.3: список запускаемых приложений (для split-tunnel picker). Только те, что
                    // имеют LAUNCHER-активность (пользовательские, не системные службы). Видимость
                    // даёт <queries> в манифесте (без чувствительного QUERY_ALL_PACKAGES).
                    try {
                        val pm = packageManager
                        val intent = Intent(Intent.ACTION_MAIN, null).addCategory(Intent.CATEGORY_LAUNCHER)
                        val seen = HashSet<String>()
                        val out = ArrayList<Map<String, String>>()
                        for (ri in pm.queryIntentActivities(intent, 0)) {
                            val pkg = ri.activityInfo.packageName
                            if (pkg == packageName || !seen.add(pkg)) continue // сам клиент/дубликаты — мимо
                            out.add(mapOf("package" to pkg, "label" to ri.loadLabel(pm).toString()))
                        }
                        out.sortBy { it["label"]?.lowercase() }
                        result.success(out)
                    } catch (e: Exception) {
                        result.error("apps", e.message, null)
                    }
                }
                "openVpnSettings" -> {
                    // C6 Android kill-switch = СИСТЕМНЫЙ always-on + «блокировать без VPN» (lockdown).
                    // Приложение не может форсить его (iptables-аналога у VpnService нет), но ведёт сюда.
                    try {
                        startActivity(
                            Intent("android.settings.VPN_SETTINGS")
                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        )
                        result.success(true)
                    } catch (e: Exception) {
                        result.success(false)
                    }
                }
                // N-3: копирование ЧУВСТВИТЕЛЬНОГО в буфер обмена (ссылка абонента, client_id).
                // Две вещи, которых не делает `Clipboard.setData` из Dart:
                //   * пометка `EXTRA_IS_SENSITIVE` (Android 13+) — системное превью буфера
                //     показывает «•••» вместо самой ссылки (её иначе видно на весь экран);
                //   * автоочистка через `ttl` секунд, чтобы ссылка не жила в буфере до перезагрузки.
                // Очистка идёт с Handler'а процесса, а не из Dart-таймера: изолят UI может умереть
                // вместе с окном, а процесс живёт дальше (foreground-сервис).
                "copySensitive" -> {
                    val text = call.argument<String>("text") ?: ""
                    val ttl = (call.argument<Int>("ttlSeconds") ?: 90).coerceIn(5, 600)
                    result.success(SensitiveClipboard.copy(this, text, ttl))
                }
                else -> result.notImplemented()
            }
        }
    }

    /** N-3: доочистить буфер обмена, если срок вышел, пока приложение было в фоне (с Android 10
     *  менять буфер без фокуса система не даёт — из фона очистка молча не срабатывает). */
    override fun onResume() {
        super.onResume()
        SensitiveClipboard.onResume(this)
    }

    @Deprecated("compat: onActivityResult для VpnService.prepare consent")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == reqVpn) {
            prepareResult?.success(resultCode == Activity.RESULT_OK)
            prepareResult = null
        }
    }
}
