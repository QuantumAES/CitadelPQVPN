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
    // Была ли уже underlying-сеть: отличает ПЕРВЫЙ onAvailable (туннель поднимается — реконнект не
    // нужен) от возврата сети после onLost (toggle WiFi — реконнект НУЖЕН).
    private var hadNetwork: Boolean = false

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
                // Реконнект нужен, если сеть сменилась на другую ЛИБО вернулась после потери текущей
                // (onLost обнулил currentNetworkId в -1). Пропускаем только САМЫЙ первый onAvailable
                // (hadNetwork=false — туннель и так поднимается над этой сетью). Раньше без hadNetwork
                // toggle WiFi (onLost→onAvailable) не триггерил реконнект: onLost ставил -1, а
                // onAvailable трактовал -1 как «первое событие» → туннель висел на мёртвом сокете.
                val changed = hadNetwork && currentNetworkId != id
                currentNetworkId = id
                hadNetwork = true
                // сказать VPN'у, поверх какой реальной сети он идёт (правильная маршрутизация
                // protected-сокета движка на новую сеть)
                CitadelVpnService.instance?.setUnderlyingNetworks(arrayOf(network))
                if (changed) {
                    runOnUiThread { channel?.invokeMethod("onNetworkChanged", null) }
                }
            }

            override fun onLost(network: Network) {
                // Потеряли текущую сеть → -1; следующий onAvailable (даже той же сети с новым handle)
                // станет "changed" (hadNetwork=true) → форс реконнект. hadNetwork НЕ сбрасываем.
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
        hadNetwork = false // следующий старт VPN — снова «первый onAvailable», без лишнего реконнекта
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
