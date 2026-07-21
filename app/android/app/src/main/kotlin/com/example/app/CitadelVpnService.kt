package com.example.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor

/**
 * Тонкий VpnService для CitadelPQVPN (трек C3.2). Привилегированную сеть/крипту делает
 * Rust-движок в изоляте Flutter; этот сервис лишь: (1) строит TUN по назначенным движком
 * параметрам и отдаёт fd в Rust; (2) держит foreground-нотификацию; (3) (C3.3) protect()
 * исходящих сокетов движка от заворачивания в туннель.
 *
 * fd передаётся через detachFd(): владельцем становится Rust (Tun::from_raw_fd), он же закрывает
 * его при остановке/реконнекте нативного connect-loop (vpn_disconnect → loop завершается → tun
 * дропается → fd закрывается; на реконнекте старый fd дропается перед новым establishTun). Поэтому
 * сервис fd НЕ закрывает (иначе double-close).
 */
class CitadelVpnService : VpnService() {

    companion object {
        @Volatile
        var instance: CitadelVpnService? = null

        /** Колбэк готовности (после nativeRegister) — startService ждёт его, чтобы протектор
         *  встал ДО establish (иначе первый сокет движка не защищён → петля). */
        @Volatile
        var onServiceReady: (() -> Unit)? = null

        const val CHANNEL_ID = "citadel_vpn"
        const val NOTIF_ID = 1

        init {
            // та же .so, что грузит Flutter/frb; нужна, чтобы резолвились JNI-методы native*
            System.loadLibrary("rust_lib_app")
        }
    }

    // JNI (C3.3): регистрируем сервис протектором сокетов движка (Rust → VpnService.protect)
    private external fun nativeRegister()
    private external fun nativeUnregister()

    // JNI (S2): смена underlying-сети → разбудить нативный connect-loop (Rust notify_network_changed)
    private external fun nativeNetworkChanged()

    // Мониторинг underlying-сети (WiFi/LTE) живёт в СЕРВИСЕ (переживает Activity → сигнал доходит и
    // при закрытом окне; в S1 он был в MainActivity и умирал с окном).
    private var netCallback: ConnectivityManager.NetworkCallback? = null
    private var currentNetworkId: Long = -1L
    // Была ли уже underlying-сеть: отличает ПЕРВЫЙ onAvailable (туннель поднимается — реконнект не
    // нужен) от возврата сети после onLost (toggle WiFi — реконнект НУЖЕН).
    private var hadNetwork: Boolean = false

    override fun onCreate() {
        super.onCreate()
        instance = this
        nativeRegister() // движок теперь может protect() свои исходящие сокеты
        registerNetCallback() // мониторим underlying-сеть на всю жизнь сервиса
        onServiceReady?.invoke()
        onServiceReady = null
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForegroundNotif()
        return START_STICKY
    }

    /** Построить TUN по параметрам, назначенным движком, вернуть detached fd для Rust. Зовётся из
     *  Rust через JNI (`AndroidTunProvider::configure` в нативном connect-loop) на КАЖДЫЙ (ре)коннект,
     *  НЕ из Dart. routes/dns приходят строкой через пробел (Rust шлёт TunParams как есть, без массивов). */
    fun establishTun(
        addr: String, prefix: Int, routes: String, dns: String, mtu: Int,
        appMode: String, apps: String, destMode: String, destRoutes: String,
    ): Int {
        val linkRoutes = routes.split(" ").filter { it.isNotEmpty() }
        val appList = apps.split(" ").filter { it.isNotEmpty() }
        val destList = destRoutes.split(" ").filter { it.isNotEmpty() }
        // C8.3 назначения: include → только они в туннель (остальное, вкл. IPv6, напрямую);
        //                  exclude → full-tunnel минус они (excludeRoute, Android 13+/API33).
        val destInclude = destMode == "include" && destList.isNotEmpty()
        val destExclude = destMode == "exclude" && destList.isNotEmpty()
        val tunnelRoutes = if (destInclude) destList else linkRoutes
        // full-tunnel (→ IPv6-blackhole применим) только когда НЕ селективный include и маршруты полны
        val fullTunnel = !destInclude && (tunnelRoutes.isEmpty() || tunnelRoutes.any { it == "0.0.0.0/0" })

        // C8.3 приложения: include → только выбранные пакеты в туннель; exclude → все, кроме них.
        // addAllowed/DisallowedApplication взаимоисключающи; несуществующий пакет бросает — ловим
        // пер-пакет, чтобы один удалённый пакет не завалил establish целиком.
        fun applyAppFilter(b: Builder) {
            for (pkg in appList) {
                try {
                    when (appMode) {
                        "include" -> b.addAllowedApplication(pkg)
                        "exclude" -> b.addDisallowedApplication(pkg)
                    }
                } catch (e: Exception) {
                    android.util.Log.w("CitadelVpn", "C8.3 split-app: пакет пропущен ($pkg): ${e.message}")
                }
            }
        }

        // Собрать VpnService.Builder. `withV6Blackhole` — захватить весь IPv6 в туннель (S2.2/A2):
        // туннель IPv4-only, поэтому нативный IPv6 иначе утекает мимо него (деанон на dual-stack).
        // Dummy ULA + ::/0 (как WireGuard) → v6-пакеты уходят в tun, движок форвардит их exit'у, тот
        // дропает (S0.2 default-deny не-IPv4) — открытого IPv6 на проводе нет.
        fun build(withV6Blackhole: Boolean): android.os.ParcelFileDescriptor? {
            val b = Builder()
                .setSession("CitadelPQVPN")
                .setMtu(mtu)
                .addAddress(addr, prefix)
            applyAppFilter(b)
            for (r in tunnelRoutes) {
                val s = splitCidr(r)
                b.addRoute(s.first, s.second)
            }
            for (d in dns.split(" ").filter { it.isNotEmpty() }) b.addDnsServer(d)
            if (tunnelRoutes.isEmpty()) b.addRoute("0.0.0.0", 0) // нет split-маршрутов → full-tunnel
            // C8.3 exclude: вырезать выбранные назначения из full-tunnel (Android 13+/API33)
            if (destExclude) {
                if (Build.VERSION.SDK_INT >= 33) {
                    for (d in destList) {
                        val s = splitCidr(d)
                        b.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName(s.first), s.second))
                    }
                } else {
                    android.util.Log.w("CitadelVpn", "C8.3 split-dest exclude требует Android 13+ (API33); назначения НЕ исключены (остаются в туннеле)")
                }
            }
            if (withV6Blackhole) {
                b.addAddress("fd00:cade:1::1", 128)
                b.addRoute("::", 0)
            }
            return b.establish()
        }

        // Пробуем с IPv6-blackhole (только full-tunnel). НЕ все устройства/версии принимают v6-адрес
        // или ::/0 на VpnService — тогда establish() бросает («Cannot set address») ЛИБО возвращает
        // null; в этом случае пересобираем БЕЗ blackhole (fallback → системный always-on lockdown,
        // который тоже режет не-VPN трафик). Так establish не ломается там, где v6 не поддержан.
        if (fullTunnel) {
            try {
                val fd = build(true)
                if (fd != null) return fd.detachFd()
                android.util.Log.w("CitadelVpn", "S2.2/A2: establish с IPv6-blackhole вернул null — пробую без него")
            } catch (e: Exception) {
                android.util.Log.w("CitadelVpn", "S2.2/A2: IPv6-blackhole отвергнут устройством (${e.message}); fallback без него (OS lockdown)")
            }
        }
        val fd = build(false) ?: throw IllegalStateException("VpnService.establish() == null (нет разрешения VPN?)")
        return fd.detachFd() // владение переходит в Rust
    }

    /** C3.3: исключить сокет движка из туннеля (анти-петля). Зовётся из Rust через JNI. */
    fun protectFd(fd: Int): Boolean = protect(fd)

    fun stopTun() {
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        unregisterNetCallback()
        nativeUnregister()
        instance = null
        super.onDestroy()
    }

    /** Следить за underlying-сетями (WiFi/LTE, не VPN). При смене — обновить setUnderlyingNetworks
     *  (protected-сокет движка маршрутизируется на новую сеть) и разбудить нативный connect-loop
     *  (`nativeNetworkChanged`) переустановить сессию. Идемпотентно. */
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
                // Реконнект нужен, если сеть сменилась ЛИБО вернулась после потери текущей (onLost
                // обнулил currentNetworkId в -1). Пропускаем только САМЫЙ первый onAvailable
                // (hadNetwork=false — туннель и так поднимается над этой сетью).
                val changed = hadNetwork && currentNetworkId != id
                currentNetworkId = id
                hadNetwork = true
                // сказать VPN'у, поверх какой реальной сети он идёт (маршрутизация protected-сокета)
                setUnderlyingNetworks(arrayOf(network))
                android.util.Log.d("CitadelNet", "onAvailable id=$id changed=$changed")
                if (changed) nativeNetworkChanged() // разбудить нативный connect-loop
            }

            override fun onLost(network: Network) {
                android.util.Log.d("CitadelNet", "onLost id=${network.networkHandle} cur=$currentNetworkId")
                // Потеряли текущую сеть → -1; следующий onAvailable (даже той же сети с новым handle)
                // станет "changed" → форс реконнект. hadNetwork НЕ сбрасываем.
                if (network.networkHandle == currentNetworkId) currentNetworkId = -1L
            }
        }
        netCallback = cb
        try {
            cm.registerNetworkCallback(req, cb)
            android.util.Log.d("CitadelNet", "NetworkCallback зарегистрирован (сервис)")
        } catch (e: Exception) {
            netCallback = null
            android.util.Log.d("CitadelNet", "registerNetworkCallback FAILED: ${e.message}")
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
        hadNetwork = false
    }

    private fun splitCidr(cidr: String): Pair<String, Int> {
        val i = cidr.indexOf('/')
        return if (i < 0) Pair(cidr, 32) else Pair(cidr.substring(0, i), cidr.substring(i + 1).toInt())
    }

    private fun startForegroundNotif() {
        if (Build.VERSION.SDK_INT >= 26) {
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "CitadelPQVPN", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val n: Notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("CitadelPQVPN")
            .setContentText("Постквантовый туннель активен")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        } else {
            startForeground(NOTIF_ID, n)
        }
    }
}
