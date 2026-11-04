package snf.app

import android.Manifest
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.ScrollState
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay

class MainActivity : ComponentActivity() {
    private val vpnConsent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == RESULT_OK) FilterVpnService.start(this)
    }

    fun startVpn() {
        val consent = VpnService.prepare(this)
        if (consent != null) vpnConsent.launch(consent) else FilterVpnService.start(this)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        registerForActivityResult(ActivityResultContracts.RequestPermission()) {}.launch(Manifest.permission.POST_NOTIFICATIONS)
        setContent { AppTheme { App(Settings(this)) } }
    }
}

/** Wallpaper-based Material You colors on Android 12+, stock M3 below. */
@Composable
fun AppTheme(content: @Composable () -> Unit) {
    val ctx = LocalContext.current
    val dark = isSystemInDarkTheme()
    val colors = when {
        Build.VERSION.SDK_INT >= 31 -> if (dark) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx)
        dark -> darkColorScheme()
        else -> lightColorScheme()
    }
    MaterialTheme(colorScheme = colors, content = content)
}

private data class Tab(val title: String, val label: String, val icon: ImageVector)

private val TABS = listOf(
    Tab("Network Filter", "Home", Icons.Rounded.Shield),
    Tab("Private DNS", "DNS", Icons.Rounded.Dns),
    Tab("App access", "Apps", Icons.Rounded.Apps),
    Tab("Ad blocking", "Ads", Icons.Rounded.Block),
    Tab("Privacy", "Privacy", Icons.Rounded.VisibilityOff),
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun App(s: Settings) {
    val ctx = LocalContext.current
    var tab by remember { mutableIntStateOf(0) }
    // Bumped on every settings write so screens re-read prefs.
    var rev by remember { mutableIntStateOf(0) }
    val change: (() -> Unit) -> Unit = { it(); rev++; FilterVpnService.reconfigure(ctx) }
    val scroll = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(rememberTopAppBarState())
    val tabScroll = remember { List(TABS.size) { ScrollState(0) } }
    Scaffold(
        Modifier.nestedScroll(scroll.nestedScrollConnection),
        topBar = { LargeTopAppBar(title = { Text(TABS[tab].title) }, scrollBehavior = scroll) },
        bottomBar = {
            NavigationBar {
                TABS.forEachIndexed { i, t ->
                    NavigationBarItem(
                        selected = tab == i, onClick = { tab = i },
                        icon = { Icon(t.icon, null) }, label = { Text(t.label) },
                    )
                }
            }
        },
    ) { pad ->
        Box(Modifier.padding(pad).fillMaxSize()) {
            // Apps stays outside key(rev) so toggling doesn't reload the app list or clear the search.
            if (tab == 2) AppsScreen(s, change, rev)
            else CompositionLocalProvider(LocalScroll provides tabScroll[tab]) {
                key(rev) {
                    when (tab) {
                        0 -> HomeScreen(s) { tab = it }
                        1 -> DnsScreen(s, change)
                        3 -> AdBlockScreen(s, change)
                        4 -> PrivacyScreen(s, change)
                    }
                }
            }
        }
    }
}

@Composable
fun HomeScreen(s: Settings, goTo: (Int) -> Unit) {
    val act = LocalContext.current as MainActivity
    var running by remember { mutableStateOf(FilterVpnService.running) }
    var err by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(Unit) { while (true) { running = FilterVpnService.running; err = FilterVpnService.lastError; delay(500) } }
    val strictPrivateDns = android.provider.Settings.Global.getString(act.contentResolver, "private_dns_mode") == "hostname"
    val c = MaterialTheme.colorScheme
    val btnColor by animateColorAsState(if (running) c.primary else c.surfaceContainerHighest)
    val iconColor by animateColorAsState(if (running) c.onPrimary else c.onSurfaceVariant)

    ScreenColumn {
        Column(Modifier.fillMaxWidth().padding(vertical = 24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Surface(
                onClick = { if (running) FilterVpnService.stop(act) else act.startVpn() },
                shape = CircleShape, color = btnColor, modifier = Modifier.size(168.dp),
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(Icons.Rounded.PowerSettingsNew, if (running) "Turn off" else "Turn on", Modifier.size(72.dp), tint = iconColor)
                }
            }
            Spacer(Modifier.height(20.dp))
            Text(if (running) "Protected" else "Not protected", style = MaterialTheme.typography.headlineSmall)
            Text(
                if (running) "All app traffic goes through the filter" else "Tap to start filtering",
                style = MaterialTheme.typography.bodyMedium, color = c.onSurfaceVariant, textAlign = TextAlign.Center,
            )
        }
        if (err != null) Notice(Icons.Rounded.ErrorOutline, "Couldn't start the filter", err!!)
        if (strictPrivateDns) Notice(
            Icons.Rounded.Warning, "Turn off Android's Private DNS",
            "It's set to a specific provider, which conflicts with this app. Set it to Off or Automatic in system settings.",
        )
        val preset = DNS_PRESETS.firstOrNull { it.url == s.dnsUrl() }
        val tricks = listOf("sniSplit", "tlsFrag", "hostTricks", "blockQuic").count { s.bool(it) }
        val privacy = listOfNotNull(
            if (tricks > 0) "Disguise on" else null,
            when (s.routeMode()) { "wg" -> "via ${s.activeWg()?.name ?: "WireGuard"}"; "proxy" -> "via proxy"; else -> null },
        ).joinToString(" · ").ifEmpty { "Off" }
        val lists = s.set("lists").size
        Group {
            NavRow(Icons.Rounded.Dns, "Private DNS", preset?.let { "${it.name} · ${dnsKind(it.url)}" } ?: "Custom server") { goTo(1) }
            NavRow(Icons.Rounded.Apps, "App access", s.set("blocked").size.let { if (it == 0) "All apps allowed" else "$it ${if (it == 1) "app" else "apps"} blocked" }) { goTo(2) }
            NavRow(Icons.Rounded.Block, "Ad blocking", if (s.bool("adblock")) "On · $lists ${if (lists == 1) "list" else "lists"}" else "Off") { goTo(3) }
            NavRow(Icons.Rounded.VisibilityOff, "Privacy", privacy) { goTo(4) }
        }
    }
}
