package snf.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.ComponentName
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.graphics.drawable.Icon
import android.net.VpnService
import android.service.quicksettings.TileService
import android.util.Log
import java.net.InetAddress
import java.net.InetSocketAddress
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class FilterVpnService : VpnService(), snf.core.Callback {
    companion object {
        const val STOP = "snf.STOP"
        // Compose state, so the UI observes these instead of polling.
        var starting by mutableStateOf(false)
            private set
        var running by mutableStateOf(false) // engine is up and filtering
            private set
        var lastError by mutableStateOf<String?>(null)
            private set
        var alwaysOn by mutableStateOf(false) // the system runs us as the Always-on VPN
            private set

        // Every engine start/reconfigure/stop runs here, in order, so a stale config can't win.
        private val engine = Executors.newSingleThreadExecutor()

        fun start(ctx: Context) = ctx.startForegroundService(Intent(ctx, FilterVpnService::class.java))
        fun stop(ctx: Context) = ctx.startService(Intent(ctx, FilterVpnService::class.java).setAction(STOP))

        private val reconfigurePending = AtomicBoolean(false)

        /** Pushes changed settings into a running (or starting) engine. A burst of writes becomes one reconfigure. */
        fun reconfigure(ctx: Context) {
            if (!running && !starting) return
            if (!reconfigurePending.compareAndSet(false, true)) return // the queued one will read the latest settings
            val app = ctx.applicationContext
            engine.execute {
                reconfigurePending.set(false) // cleared before reading, so a write from here on queues another
                if (!running) return@execute // a start still queued reads the latest settings itself
                try { snf.core.Core.reconfigure(Settings.of(app).configJson()); lastError = null }
                catch (e: Exception) { lastError = e.message; Log.e("snf", "reconfigure", e) }
            }
        }
    }

    private lateinit var cm: ConnectivityManager

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == STOP) {
            // shortcut: queues behind a running launch(), which may spend a while downloading lists; interrupt it if that bites.
            engine.execute { shutdown() }
            return START_NOT_STICKY
        }
        cm = getSystemService(ConnectivityManager::class.java)
        startForeground(1, notification(active = true), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        if (!running && !starting) {
            starting = true
            engine.execute { launch() }
        }
        return START_STICKY
    }

    private fun launch() {
        val settings = Settings.of(this)
        try {
            if (settings.adblock) settings.refreshLists()
            // shortcut: the local network is read once at start, like v6; restart the VPN after a network change.
            val skip = if (settings.skipLan) localNets() else ""
            val b = Builder()
                .setSession(getString(R.string.app_name))
                .setMtu(MTU)
                .addAddress("10.111.0.1", 32)
                .routes("0.0.0.0/0", skip)
                .addDnsServer("10.111.0.2") // any :53 is intercepted; this is just what apps are told
                .addDisallowedApplication(packageName) // our own upstream sockets bypass the tunnel
            // Without v6 config Android blocks v6 for VPN apps, so they fall back to v4 instead of
            // trying v6 we can't reach.
            if (hasGlobalV6()) b.addAddress("fd00:111::1", 128).routes("::/0", skip).addDnsServer("fd00:111::2")
            val pfd = b.establish() ?: error("VPN permission revoked")
            snf.core.Core.start(pfd.detachFd().toLong(), MTU.toLong(), settings.configJson(), this)
            lastError = null
            // Only true once our tunnel is established. shortcut: read at start, so toggling Always-on shows after a restart.
            alwaysOn = isAlwaysOn
            running = true
            refreshTile()
        } catch (e: Exception) {
            lastError = e.message
            Log.e("snf", "start", e)
            shutdown()
        } finally {
            starting = false
        }
    }

    /** Everything in [root] except [skip]; computed in Go because Builder.excludeRoute needs Android 13. */
    private fun Builder.routes(root: String, skip: String) = apply {
        snf.core.Core.routesExcluding(root, skip).lines().filter { it.isNotEmpty() }.forEach {
            addRoute(it.substringBefore('/'), it.substringAfter('/').toInt())
        }
    }

    /** Local subnets plus link-local, multicast and broadcast, so casting and device discovery skip the filter. */
    // shortcut: an app sending plain DNS straight to the router's LAN IP skips our DNS too; carve :53 hosts out if it matters.
    private fun localNets() = (cm.getLinkProperties(cm.activeNetwork)?.linkAddresses.orEmpty()
        .map { "${it.address.hostAddress!!.substringBefore('%')}/${it.prefixLength}" } +
        listOf("169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32", "fe80::/10", "ff00::/8")).joinToString(" ")

    private fun hasGlobalV6() = cm.getLinkProperties(cm.activeNetwork)?.linkAddresses.orEmpty().any {
        val a = it.address
        a is java.net.Inet6Address && !a.isLinkLocalAddress && !a.isSiteLocalAddress && (a.address[0].toInt() and 0xfe) != 0xfc
    }

    /** Only call on [engine]. */
    private fun shutdown() {
        snf.core.Core.stop()
        running = false
        alwaysOn = false
        refreshTile()
        stopForeground(STOP_FOREGROUND_REMOVE)
        // Same id, so starting again replaces it; swipe-away, unlike the running one.
        getSystemService(NotificationManager::class.java).notify(1, notification(active = false))
        stopSelf()
    }

    private fun refreshTile() = TileService.requestListeningState(this, ComponentName(this, FilterTile::class.java))

    override fun onRevoke() = engine.execute { shutdown() } // another VPN took over
    override fun onDestroy() { engine.execute { if (running) shutdown() }; super.onDestroy() }

    override fun uidFor(proto: Long, srcIP: String, srcPort: Long, dstIP: String, dstPort: Long): Long = try {
        cm.getConnectionOwnerUid(
            proto.toInt(),
            InetSocketAddress(InetAddress.getByName(srcIP), srcPort.toInt()),
            InetSocketAddress(InetAddress.getByName(dstIP), dstPort.toInt()),
        ).toLong()
    } catch (e: Exception) { -1 }

    override fun log(msg: String) { Log.i("snf-core", msg) }

    private fun notification(active: Boolean): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel("vpn", "VPN status", NotificationManager.IMPORTANCE_LOW))
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val self = Intent(this, FilterVpnService::class.java)
        val action = when {
            active -> PendingIntent.getService(this, 1, self.setAction(STOP), PendingIntent.FLAG_IMMUTABLE)
            VpnService.prepare(this) == null -> PendingIntent.getForegroundService(this, 2, self, PendingIntent.FLAG_IMMUTABLE)
            else -> open // VPN consent was revoked (another VPN took over); the app asks again
        }
        return Notification.Builder(this, "vpn")
            .setSmallIcon(R.drawable.ic_launcher_mono)
            .setContentTitle(if (active) "Switchyard active" else "Switchyard off")
            .setContentIntent(open)
            .setOngoing(active)
            .addAction(Notification.Action.Builder(Icon.createWithResource(this, R.drawable.ic_launcher_mono), if (active) "Stop" else "Start", action).build())
            .build()
    }
}

private const val MTU = 1500
