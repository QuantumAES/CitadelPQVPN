package com.example.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.ServiceInfo
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
 * его при остановке data-plane (android_disconnect → pump сворачивается). Поэтому сервис fd НЕ
 * закрывает (иначе double-close).
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

    override fun onCreate() {
        super.onCreate()
        instance = this
        nativeRegister() // движок теперь может protect() свои исходящие сокеты
        onServiceReady?.invoke()
        onServiceReady = null
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForegroundNotif()
        return START_STICKY
    }

    /** Построить TUN по параметрам, назначенным движком (фаза 1), вернуть detached fd для Rust. */
    fun establishTun(addr: String, prefix: Int, routes: List<String>, dns: List<String>, mtu: Int): Int {
        val b = Builder()
            .setSession("CitadelPQVPN")
            .setMtu(mtu)
            .addAddress(addr, prefix)
        for (r in routes) {
            val s = splitCidr(r)
            b.addRoute(s.first, s.second)
        }
        for (d in dns) b.addDnsServer(d)
        if (routes.isEmpty()) b.addRoute("0.0.0.0", 0) // нет split-маршрутов → full-tunnel
        val fd = b.establish() ?: throw IllegalStateException("VpnService.establish() == null (нет разрешения VPN?)")
        return fd.detachFd() // владение переходит в Rust
    }

    /** C3.3: исключить сокет движка из туннеля (анти-петля). Зовётся из Rust через JNI. */
    fun protectFd(fd: Int): Boolean = protect(fd)

    fun stopTun() {
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        nativeUnregister()
        instance = null
        super.onDestroy()
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
