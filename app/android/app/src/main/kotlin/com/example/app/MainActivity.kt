package com.example.app

import android.app.Activity
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * Мост Dart ↔ Android VpnService (трек C3.2). Канал `dev.citadelpqvpn/vpn`:
 *   prepare      → системный консент VpnService (один раз) → Bool granted
 *   startService → запустить foreground CitadelVpnService (+ мониторинг сети)
 *   establishTun → построить TUN по параметрам движка → Int fd (detached, владелец — Rust)
 *   stopService  → остановить сервис (+ снять мониторинг сети)
 * Обратно (native → Dart): `onNetworkChanged` — сменилась underlying-сеть (WiFi↔LTE/toggle) →
 * Dart форсирует реконнект над новой сетью. Плюс сервису обновляется setUnderlyingNetworks, чтобы
 * protected-сокет движка корректно маршрутизировался на новую сеть (иначе туннель «висит» мёртвым).
 */
class MainActivity : FlutterActivity() {
    private val channelName = "dev.citadelpqvpn/vpn"
    private val reqVpn = 0x1011
    private var prepareResult: MethodChannel.Result? = null
    private var channel: MethodChannel? = null

    private var netCallback: ConnectivityManager.NetworkCallback? = null
    private var currentNetworkId: Long = -1L

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        val ch = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, channelName)
        channel = ch
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
                    registerNetCallback() // мониторим underlying-сеть на всю сессию
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
                    unregisterNetCallback()
                    CitadelVpnService.instance?.stopTun()
                    result.success(true)
                }
                else -> result.notImplemented()
            }
        }
    }

    /** Следить за underlying-сетями (WiFi/LTE, не VPN). При смене — обновить setUnderlyingNetworks
     *  сервиса и дёрнуть Dart на реконнект. Идемпотентно. */
    private fun registerNetCallback() {
        if (netCallback != null) return
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        val req = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
            .build()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val id = network.networkHandle
                val changed = currentNetworkId != -1L && currentNetworkId != id
                currentNetworkId = id
                // сказать VPN'у, поверх какой реальной сети он идёт (правильная маршрутизация
                // protected-сокета движка на новую сеть)
                CitadelVpnService.instance?.setUnderlyingNetworks(arrayOf(network))
                // первое событие = текущая сеть (коннект уже над ней) → реконнект не нужен
                if (changed) {
                    runOnUiThread { channel?.invokeMethod("onNetworkChanged", null) }
                }
            }

            override fun onLost(network: Network) {
                if (network.networkHandle == currentNetworkId) currentNetworkId = -1L
            }
        }
        netCallback = cb
        try {
            cm.registerNetworkCallback(req, cb)
        } catch (e: Exception) {
            netCallback = null
        }
    }

    private fun unregisterNetCallback() {
        val cb = netCallback ?: return
        try {
            getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(cb)
        } catch (_: Exception) {
        }
        netCallback = null
        currentNetworkId = -1L
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
