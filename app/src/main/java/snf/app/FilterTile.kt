package snf.app

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

/** Quick Settings toggle for the filter. */
class FilterTile : TileService() {
    private val on get() = FilterVpnService.running || FilterVpnService.starting

    override fun onStartListening() { show(on) }

    override fun onClick() {
        when {
            on -> FilterVpnService.stop(this)
            VpnService.prepare(this) == null -> FilterVpnService.start(this)
            else -> return openApp() // no VPN consent yet; it's asked for in the app
        }
        show(!on) // the service reports back via requestListeningState once it settles
    }

    private fun show(active: Boolean) = qsTile?.run {
        state = if (active) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        updateTile()
    }

    private fun openApp() {
        val i = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= 34) startActivityAndCollapse(PendingIntent.getActivity(this, 0, i, PendingIntent.FLAG_IMMUTABLE))
        else @Suppress("DEPRECATION") startActivityAndCollapse(i)
    }
}
