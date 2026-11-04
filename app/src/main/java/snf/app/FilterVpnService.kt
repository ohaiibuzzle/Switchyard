package snf.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.VpnService
import android.util.Log
import java.net.InetAddress
import java.net.InetSocketAddress
import kotlin.concurrent.thread

class FilterVpnService : VpnService(), snf.core.Callback {
    companion object {
        const val STOP = "snf.STOP"
        @Volatile var running = false
            private set
        @Volatile var lastError: String? = null

        fun start(ctx: Context) = ctx.startForegroundService(Intent(ctx, FilterVpnService::class.java))
        fun stop(ctx: Context) = ctx.startService(Intent(ctx, FilterVpnService::class.java).setAction(STOP))

        /** Pushes changed settings into a running engine. */
        fun reconfigure(ctx: Context) {
            if (!running) return
            thread {
                try { snf.core.Core.reconfigure(Settings(ctx).configJson()); lastError = null }
                catch (e: Exception) { lastError = e.message; Log.e("snf", "reconfigure", e) }
            }
        }
    }

    private lateinit var cm: ConnectivityManager

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == STOP) {
            shutdown()
            return START_NOT_STICKY
        }
        cm = getSystemService(ConnectivityManager::class.java)
        startForeground(1, notification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        if (!running) {
            running = true
            thread { launch() }
        }
        return START_STICKY
    }

    private fun launch() {
        val settings = Settings(this)
        try {
            if (settings.bool("adblock")) settings.refreshLists()
            val b = Builder()
                .setSession(getString(R.string.app_name))
                .setMtu(MTU)
                .addAddress("10.111.0.1", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("10.111.0.2") // any :53 is intercepted; this is just what apps are told
                .addDisallowedApplication(packageName) // our own upstream sockets bypass the tunnel
            // Without v6 config Android blocks v6 for VPN apps, so they fall back to v4 instead of
            // trying v6 we can't reach. shortcut: decided once at start, restart the VPN after a network change.
            if (hasGlobalV6()) b.addAddress("fd00:111::1", 128).addRoute("::", 0).addDnsServer("fd00:111::2")
            val pfd = b.establish() ?: error("VPN permission revoked")
            snf.core.Core.start(pfd.detachFd().toLong(), MTU.toLong(), settings.configJson(), this)
            lastError = null
        } catch (e: Exception) {
            lastError = e.message
            Log.e("snf", "start", e)
            shutdown()
        }
    }

    private fun hasGlobalV6() = cm.getLinkProperties(cm.activeNetwork)?.linkAddresses.orEmpty().any {
        val a = it.address
        a is java.net.Inet6Address && !a.isLinkLocalAddress && !a.isSiteLocalAddress && (a.address[0].toInt() and 0xfe) != 0xfc
    }

    private fun shutdown() {
        snf.core.Core.stop()
        running = false
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() = shutdown() // another VPN took over
    override fun onDestroy() { if (running) shutdown(); super.onDestroy() }

    override fun uidFor(proto: Long, srcIP: String, srcPort: Long, dstIP: String, dstPort: Long): Long = try {
        cm.getConnectionOwnerUid(
            proto.toInt(),
            InetSocketAddress(InetAddress.getByName(srcIP), srcPort.toInt()),
            InetSocketAddress(InetAddress.getByName(dstIP), dstPort.toInt()),
        ).toLong()
    } catch (e: Exception) { -1 }

    override fun log(msg: String) { Log.i("snf-core", msg) }

    private fun notification(): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel("vpn", "VPN status", NotificationManager.IMPORTANCE_LOW))
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, "vpn")
            .setSmallIcon(R.drawable.ic_launcher_mono)
            .setContentTitle("Network filter active")
            .setContentIntent(open)
            .setOngoing(true)
            .build()
    }
}

private const val MTU = 1500
