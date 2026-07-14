package com.example.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import io.flutter.embedding.android.FlutterActivity
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
 */
class MainActivity : FlutterActivity() {
    private val channelName = "dev.citadelpqvpn/vpn"
    private val reqVpn = 0x1011
    private var prepareResult: MethodChannel.Result? = null

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
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
                    if (CitadelVpnService.instance != null) {
                        result.success(true) // уже запущен (реконнект)
                    } else {
                        // ждём onCreate+nativeRegister: протектор сокетов должен встать ДО
                        // establish, иначе первый сокет движка уйдёт незащищённым (петля)
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
                else -> result.notImplemented()
            }
        }
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
