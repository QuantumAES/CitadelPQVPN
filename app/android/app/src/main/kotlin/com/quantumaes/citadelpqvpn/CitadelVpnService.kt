package com.quantumaes.citadelpqvpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
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

        // Тексты постоянной нотификации по состоянию сессии. Она — единственное, что видно о VPN
        // при закрытом окне, поэтому «туннель активен» в ней должно означать ровно то, что сказано:
        // при пропаже сети движок уходит в переподключение, и нотификация обязана это показать.
        const val STATUS_UP = "Постквантовый туннель активен"
        const val STATUS_CONNECTING = "Подключение…"
        const val STATUS_RECONNECTING = "Нет соединения — восстанавливаю"
        const val STATUS_DOWN = "Туннель не активен"

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

    // JNI: жива ли нативная сессия движка в ЭТОМ процессе (Rust `has_active_session`). Нужен на
    // воскрешении сервиса системой: у свежего процесса сессии нет, и это надо отличать от штатного
    // старта, где сессию поднимет приложение сразу после `startService` (см. onStartCommand).
    private external fun nativeHasSession(): Boolean

    // Мониторинг underlying-сети (WiFi/LTE) живёт в СЕРВИСЕ (переживает Activity → сигнал доходит и
    // при закрытом окне; в S1 он был в MainActivity и умирал с окном).
    private var netCallback: ConnectivityManager.NetworkCallback? = null
    private var currentNetworkId: Long = -1L
    // Была ли уже underlying-сеть: отличает ПЕРВЫЙ onAvailable (туннель поднимается — реконнект не
    // нужен) от возврата сети после onLost (toggle WiFi — реконнект НУЖЕН).
    private var hadNetwork: Boolean = false
    // Живые underlying-сети (только те, что прошли фильтр NetworkRequest: WiFi/LTE с интернетом).
    // Нужны, чтобы при потере ТЕКУЩЕЙ сети сразу перейти на оставшуюся: onAvailable по ней уже
    // прошёл и второй раз не придёт, а спрашивать ConnectivityManager при поднятом VPN бесполезно —
    // activeNetwork вернёт саму VPN-сеть. Трогается только из потока NetworkCallback.
    private val liveNetworks = LinkedHashMap<Long, Network>()
    // Текст последней foreground-нотификации — чтобы не дёргать NotificationManager вхолостую.
    @Volatile
    private var statusText: String = STATUS_CONNECTING

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
        // `intent == null` — сервис ВОСКРЕШЁН системой по START_STICKY после того, как процесс был
        // убит (нехватка памяти, чистка «недавних» на OEM-прошивках — на устройствах эпохи
        // Android 9 это рядовое событие). Восстановить сессию мы при этом не можем по построению:
        // ссылка профиля лежит в зашифрованном хранилище и без мастер-пароля недоступна.
        //
        // Значит, туннеля нет — и постоянная нотификация вместе с системной иконкой ключа в
        // статус-баре сейчас утверждали бы обратное. Это худший из возможных исходов: человек
        // считает трафик защищённым, а он идёт открытым. Гасим сервис — отсутствие защиты должно
        // быть видно; сессию поднимет приложение при следующем подключении.
        if (intent == null && !nativeHasSession()) {
            android.util.Log.w(
                "CitadelVpn",
                "сервис воскрешён без нативной сессии (процесс был убит) — гашу, чтобы не показывать защиту, которой нет"
            )
            stopTun()
            return START_NOT_STICKY
        }
        return START_STICKY
    }

    /**
     * Пользователь закрыл приложение (смахнул из «недавних»). Туннель обязан остаться: окно — лишь
     * пульт, сессию держит нативный движок в этом же процессе, а сервис — его foreground-якорь.
     *
     * Базовая реализация `Service.onTaskRemoved` пуста, и метод переопределён ради двух вещей:
     * (а) зафиксировать намерение «сессию НЕ трогаем» рядом с `android:stopWithTask="false"` в
     * манифесте; (б) переподтвердить foreground-нотификацию — часть прошивок в этот момент снимает
     * её, и процесс из «perceptible» проваливается в кэш, откуда его убивают первым (после чего
     * сервис воскресает уже без сессии — см. onStartCommand).
     */
    override fun onTaskRemoved(rootIntent: Intent?) {
        android.util.Log.d("CitadelVpn", "onTaskRemoved: окно закрыто, сессию держим")
        startForegroundNotif()
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
        val dnsList = dns.split(" ").filter { it.isNotEmpty() }
        // Подсеть туннеля (назначенный addr/prefix). В ней живёт шлюз exit'а = ADMIN_VIP (C7.2),
        // т.е. admin-канал «Абоненты». На Linux/Windows маршрут в неё появляется САМ (адрес на
        // интерфейсе → on-link), а у VPN-сети Android маршрутов ровно столько, сколько добавлено
        // здесь. Поэтому подсеть туннеля добавляем ЯВНО и ВСЕГДА — иначе split (dest-include без
        // неё, dest-exclude поверх неё, app-фильтр без нас самих) уносит её мимо VPN, и connect()
        // к 10.7.0.1 падает в EHOSTUNREACH «No route to host» (для UID под VPN Android ставит
        // fallthrough-правило unreachable). prefix 0 не трогаем — это и есть 0.0.0.0/0.
        val tunNet = if (prefix in 1..32) networkOf(addr, prefix) else null
        // C8.3 назначения: include → только они в туннель (остальное, вкл. IPv6, напрямую);
        //                  exclude → full-tunnel минус они (excludeRoute, Android 13+/API33).
        // Из exclude-списка вырезаем всё, что накрывает подсеть туннеля (инвариант выше).
        val destInclude = destMode == "include" && destList.isNotEmpty()
        val excludeList = if (destMode == "exclude") destList.filter { d ->
            val s = splitCidr(d)
            val clash = tunNet != null && prefixesOverlap(s.first, s.second, tunNet, prefix)
            if (clash) {
                android.util.Log.w("CitadelVpn", "C8.3 split-dest: $d накрывает подсеть туннеля $tunNet/$prefix — НЕ исключаю (иначе теряется admin-канал)")
            }
            !clash
        } else emptyList()
        val destExclude = excludeList.isNotEmpty()
        val tunnelRoutes = if (destInclude) destList else linkRoutes
        // full-tunnel (→ IPv6-blackhole применим) только когда НЕ селективный include и маршруты полны
        val fullTunnel = !destInclude && (tunnelRoutes.isEmpty() || tunnelRoutes.any { it == "0.0.0.0/0" })

        // C8.3 приложения: include → только выбранные пакеты в туннель; exclude → все, кроме них.
        // Фильтр активен, только если список непуст (режим без списка = «не ограничивать», как
        // SplitTunnel::is_active в ядре) — иначе include с пустым списком запер бы в туннель всё.
        // addAllowed/DisallowedApplication взаимоисключающи; несуществующий пакет бросает — ловим
        // пер-пакет, чтобы один удалённый пакет не завалил establish целиком.
        fun applyAppFilter(b: Builder) {
            if (appList.isEmpty()) return
            // САМИ мы всегда в туннеле: admin-канал идёт к ADMIN_VIP (адрес внутри туннеля) из
            // этого же процесса, а сокеты движка к exit'у и так исключены protect() (C3.3).
            // include → добавляем себя в разрешённые; exclude → никогда не исключаем себя.
            if (appMode == "include") {
                try {
                    b.addAllowedApplication(packageName)
                } catch (e: Exception) {
                    android.util.Log.w("CitadelVpn", "C8.3 split-app: не добавил себя ($packageName): ${e.message}")
                }
            }
            for (pkg in appList) {
                if (pkg == packageName) continue // см. выше: себя не исключаем и не дублируем
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
            for (d in dnsList) b.addDnsServer(d)
            if (tunnelRoutes.isEmpty()) b.addRoute("0.0.0.0", 0) // нет split-маршрутов → full-tunnel
            // Инвариант «резолвер туннеля ходит ЧЕРЕЗ туннель» — то же, что host-route на DNS в
            // citadel-vpnd (plan::tunnel_route_cmds). Без него при dest-include (в туннель только
            // выбранные адреса) или при exclude, накрывающем резолвер, DNS-сервер оказывается вне
            // туннеля: приложения под VPN не резолвят ничего вовсе. /32 специфичнее любого
            // exclude-префикса, поэтому исключения его не отменяют.
            for (d in dnsList) {
                if (d.contains(':')) continue // туннель IPv4-only, v6-резолвер не маршрутизируем
                try {
                    b.addRoute(d, 32)
                } catch (e: Exception) {
                    android.util.Log.w("CitadelVpn", "маршрут к резолверу $d не добавлен: ${e.message}")
                }
            }
            // Инвариант: подсеть туннеля (шлюз = ADMIN_VIP, admin-канал) всегда через туннель —
            // при любом split-конфиге. Дубль с 0.0.0.0/0 безвреден (более специфичный префикс).
            if (tunNet != null) b.addRoute(tunNet, prefix)
            // C8.3 exclude: вырезать выбранные назначения из full-tunnel (Android 13+/API33)
            if (destExclude) {
                if (Build.VERSION.SDK_INT >= 33) {
                    for (d in excludeList) {
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
                liveNetworks[id] = network
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
                val id = network.networkHandle
                liveNetworks.remove(id)
                android.util.Log.d("CitadelNet", "onLost id=$id cur=$currentNetworkId live=${liveNetworks.size}")
                if (id != currentNetworkId) return // упала не та сеть, поверх которой идёт туннель
                // Потеряли сеть, которая несла туннель. Молчать нельзя: пакеты уходят в никуда, а
                // движок этого не видит (обратного трафика нет и при простое, watchdog срабатывает
                // только под нагрузкой, quinn ждёт idle-timeout) — и приложение продолжает
                // показывать «Защищено» при отсутствии интернета. Будим connect-loop: он оборвёт
                // мёртвый pump и уйдёт в переподключение.
                val alt = liveNetworks.values.lastOrNull()
                if (alt != null) {
                    // Осталась другая сеть (выключили WiFi при живом LTE) — переезжаем на неё сразу;
                    // её onAvailable уже был и повторно не придёт.
                    currentNetworkId = alt.networkHandle
                    setUnderlyingNetworks(arrayOf(alt))
                } else {
                    // Сети нет вовсе. Снимаем указание на мёртвую underlying-сеть (null = «как у
                    // системы»), иначе система считает VPN идущим поверх того, чего больше нет.
                    currentNetworkId = -1L
                    setUnderlyingNetworks(null)
                }
                nativeNetworkChanged()
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
        liveNetworks.clear()
    }

    private fun splitCidr(cidr: String): Pair<String, Int> {
        val i = cidr.indexOf('/')
        return if (i < 0) Pair(cidr, 32) else Pair(cidr.substring(0, i), cidr.substring(i + 1).toInt())
    }

    // ── IPv4-хелперы для маршрутной арифметики split'а (Kotlin-Int знаковый → считаем в Long) ──

    /** "a.b.c.d" → беззнаковый u32 в Long; `-1` — не IPv4-литерал. */
    private fun ipv4ToLong(ip: String): Long {
        val parts = ip.split(".")
        if (parts.size != 4) return -1L
        var v = 0L
        for (p in parts) {
            val n = p.toIntOrNull() ?: return -1L
            if (n !in 0..255) return -1L
            v = (v shl 8) or n.toLong()
        }
        return v
    }

    /** Маска префикса как u32-в-Long (`/0` → 0). */
    private fun maskOf(prefix: Int): Long =
        if (prefix <= 0) 0L else (0xFFFFFFFFL shl (32 - prefix.coerceAtMost(32))) and 0xFFFFFFFFL

    /** Сетевой адрес `ip/prefix` строкой (кривой ip → сам ip: маршрут добавится как есть). */
    private fun networkOf(ip: String, prefix: Int): String {
        val v = ipv4ToLong(ip)
        if (v < 0) return ip
        val n = v and maskOf(prefix)
        return "${(n shr 24) and 0xff}.${(n shr 16) and 0xff}.${(n shr 8) and 0xff}.${n and 0xff}"
    }

    /** Пересекаются ли префиксы (один содержит другой) — сравнение по более короткому. */
    private fun prefixesOverlap(a: String, ap: Int, b: String, bp: Int): Boolean {
        val av = ipv4ToLong(a)
        val bv = ipv4ToLong(b)
        if (av < 0 || bv < 0) return false
        val m = maskOf(minOf(ap, bp))
        return (av and m) == (bv and m)
    }

    private fun startForegroundNotif() {
        if (Build.VERSION.SDK_INT >= 26) {
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "CitadelPQVPN", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val n = buildNotif(statusText)
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        } else {
            startForeground(NOTIF_ID, n)
        }
    }

    private fun buildNotif(text: String): Notification =
        Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("CitadelPQVPN")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setContentIntent(openAppIntent()) // тап → окно приложения
            .build()

    /**
     * «Открыть приложение» по тапу на постоянной нотификации. При закрытом окне она — единственное,
     * что видно о сессии, и до сих пор была мёртвой: вернуться к управлению можно было только через
     * лаунчер. `ACTION_MAIN`+`CATEGORY_LAUNCHER` с явным компонентом поднимают СУЩЕСТВУЮЩУЮ задачу,
     * а не создают вторую поверх (иначе новый экземпляр Activity перерисовал бы состояние с нуля).
     *
     * `FLAG_IMMUTABLE` обязателен с API 31 и доступен с API 23 (у нас minSdk 24) — ставим всегда:
     * менять этот intent извне некому.
     */
    private fun openAppIntent(): PendingIntent {
        val i = Intent(this, MainActivity::class.java)
            .setAction(Intent.ACTION_MAIN)
            .addCategory(Intent.CATEGORY_LAUNCHER)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_RESET_TASK_IF_NEEDED)
        return PendingIntent.getActivity(
            this, 0, i, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }

    /**
     * Отразить состояние сессии в постоянной нотификации. Зовётся из Rust через JNI на каждую смену
     * состояния движка (`idle|connecting|up|migrating|down`) — в том числе когда окна приложения
     * нет вовсе: тогда нотификация — единственный индикатор, и она не должна утверждать, что
     * туннель активен, пока движок переподключается (например, при пропавшей сети).
     * NotificationManager потокобезопасен, поэтому вызов из tokio-потока движка допустим.
     */
    fun setStatus(state: String) {
        val text = when (state) {
            "up" -> STATUS_UP
            "connecting" -> STATUS_CONNECTING
            "migrating" -> STATUS_RECONNECTING
            else -> STATUS_DOWN // down|idle
        }
        if (text == statusText) return
        statusText = text
        try {
            getSystemService(NotificationManager::class.java)?.notify(NOTIF_ID, buildNotif(text))
        } catch (e: Exception) {
            android.util.Log.w("CitadelVpn", "не обновить нотификацию: ${e.message}")
        }
    }
}
