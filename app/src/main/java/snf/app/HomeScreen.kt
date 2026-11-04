package snf.app

import android.content.Intent
import android.net.Uri
import android.os.PowerManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp

@Composable
fun HomeScreen(s: Settings, open: (Page) -> Unit, goTo: (Tab) -> Unit) {
    val act = LocalContext.current as MainActivity
    val running = FilterVpnService.running
    val starting = FilterVpnService.starting
    val err = FilterVpnService.lastError
    val strictPrivateDns = android.provider.Settings.Global.getString(act.contentResolver, "private_dns_mode") == "hostname"
    val power = act.getSystemService(PowerManager::class.java)
    var batteryExempt by remember { mutableStateOf(power.isIgnoringBatteryOptimizations(act.packageName)) }
    val askExempt = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        batteryExempt = power.isIgnoringBatteryOptimizations(act.packageName)
    }
    val c = MaterialTheme.colorScheme
    val btnColor by animateColorAsState(if (running) c.primary else c.surfaceContainerHighest)
    val iconColor by animateColorAsState(if (running) c.onPrimary else c.onSurfaceVariant)

    ScreenColumn {
        Column(Modifier.fillMaxWidth().padding(vertical = 24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Surface(
                onClick = { if (running || starting) FilterVpnService.stop(act) else act.startVpn() },
                shape = CircleShape, color = btnColor, modifier = Modifier.size(168.dp),
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(Icons.Rounded.PowerSettingsNew, if (running) "Turn off" else "Turn on", Modifier.size(72.dp), tint = iconColor)
                }
            }
            Spacer(Modifier.height(20.dp))
            val status = when {
                running && FilterVpnService.alwaysOn -> "Always-on"
                running -> "Protected"
                starting -> "Starting…"
                else -> "Not protected"
            }
            Text(status, style = MaterialTheme.typography.headlineSmall)
        }
        if (err != null) Notice(Icons.Rounded.ErrorOutline, "Couldn't start the filter", err)
        if (!batteryExempt) Notice(
            Icons.Rounded.BatteryAlert, "Let it run in the background",
            "Battery optimization can stop the filter. Tap to allow.",
        ) {
            askExempt.launch(Intent(android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:${act.packageName}")))
        }
        if (strictPrivateDns) Notice(
            Icons.Rounded.Warning, "Turn off Android's Private DNS",
            "System Private DNS conflicts with this app and may cause loss of Internet access. Set it to Off or Automatic in system settings.",
        )
        val preset = DNS_PRESETS.firstOrNull { it.url == s.dnsUrl }
        val privacy = listOfNotNull(
            if (s.tricksOn() > 0) "Disguise on" else null,
            if (s.routeMode == "proxy" || s.routeMode == "wg") routeSummary(s) else null, // Tailscale has its own row
        ).joinToString(" · ").ifEmpty { "Off" }
        Group {
            val dns = (preset?.let { "${it.name} · ${dnsKind(it.url)}" } ?: "Custom server").let { if (s.routeMode == "ts" && s.tsDns) "Tailscale, then $it" else it }
            NavRow(Icons.Rounded.Dns, "Private DNS", dns) { goTo(Tab.Dns) }
            NavRow(Icons.Rounded.Apps, "App access", s.blockedUids.size.let { if (it == 0) "All apps allowed" else "$it ${if (it == 1) "app" else "apps"} blocked" }) { goTo(Tab.Apps) }
            NavRow(Icons.Rounded.Block, "Ad blocking", adBlockSummary(s)) { open(Page.AdBlock) }
            NavRow(Icons.Rounded.Hub, "Tailscale", if (s.routeMode == "ts") "On" else "Off") { goTo(Tab.Tailscale) }
            NavRow(Icons.Rounded.VisibilityOff, "Privacy", privacy) { goTo(Tab.Privacy) }
        }
        Group {
            NavRow(Icons.Rounded.History, "Activity", if (s.logOn) "Recording" else "Off") { open(Page.Activity) }
        }
    }
}
