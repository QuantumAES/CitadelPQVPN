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
 *   startService → запустить foreground CitadelVpnService
 *   establishTun → построить TUN по параметрам движка → Int fd (detached, владелец — Rust)
 *   stopService  → остановить сервис
 */
class MainActivity : FlutterActivity() {
    private val channelName = "dev.citadelpqvpn/vpn"
    private val reqVpn = 0x1011
    private var prepareResult: MethodChannel.Result? = null

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, channelName)
            .setMethodCallHandler { call, result ->
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
                    "establishTun" -> {
                        val svc = CitadelVpnService.instance
                        if (svc == null) {
                            result.error("no_service", "VpnService не запущен", null)
                        } else {
                            try {
                                val fd = svc.establishTun(
                                    call.argument<String>("addr")!!,
                                    call.argument<Int>("prefix")!!,
                                    call.argument<List<String>>("routes") ?: emptyList(),
                                    call.argument<List<String>>("dns") ?: emptyList(),
                                    call.argument<Int>("mtu") ?: 1280,
                                )
                                result.success(fd)
                            } catch (e: Exception) {
                                result.error("establish_failed", e.message, null)
                            }
                        }
                    }
                    "stopService" -> {
                        CitadelVpnService.instance?.stopTun()
                        result.success(true)
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
