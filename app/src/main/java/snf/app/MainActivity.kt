package snf.app

import android.Manifest
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.AltRoute
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.*
import androidx.compose.material3.adaptive.currentWindowAdaptiveInfoV2
import androidx.compose.material3.adaptive.navigationsuite.NavigationSuiteItem
import androidx.compose.material3.adaptive.navigationsuite.NavigationSuiteScaffold
import androidx.compose.material3.adaptive.navigationsuite.NavigationSuiteScaffoldDefaults
import androidx.compose.material3.adaptive.navigationsuite.NavigationSuiteType
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.window.core.layout.WindowSizeClass

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
        val s = Settings.of(this)
        setContent { AppTheme { App(s) } }
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

enum class Tab(val title: String, val label: String, val icon: ImageVector) {
    Home("Switchyard", "Home", Icons.AutoMirrored.Rounded.AltRoute),
    Dns("DNS", "DNS", Icons.Rounded.Dns),
    Apps("App access", "Apps", Icons.Rounded.Apps),
    Tailscale("Tailscale", "Tailscale", Icons.Rounded.Hub),
    Privacy("Privacy", "Privacy", Icons.Rounded.VisibilityOff),
}

/** Landscape phone: too short for a bottom bar, a large title or a stacked Home. */
@Composable
fun isShort() = !currentWindowAdaptiveInfoV2().windowSizeClass.isHeightAtLeastBreakpoint(WindowSizeClass.HEIGHT_DP_MEDIUM_LOWER_BOUND)

/** Sub-pages, opened over a tab with a back arrow. */
enum class Page(val title: String) { Activity("Activity"), Rules("Custom rules"), AdBlock("Ad blocking"), Disguise("Disguise traffic"), Route("Route traffic") }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun App(s: Settings) {
    var tab by rememberSaveable { mutableStateOf(Tab.Home) }
    var page by rememberSaveable { mutableStateOf<Page?>(null) }
    val scroll = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(rememberTopAppBarState())
    val tabState = rememberSaveableStateHolder() // keeps each tab's scroll position across tab switches
    val open = { p: Page -> page = p }
    // Bar on portrait phones; rail on tablets and when short (the default would pick a bar there, eating scarce height).
    // Sub-pages hide the bar (they have a back arrow) but keep the rail, so wide layouts don't jump sideways.
    val short = isShort()
    val auto = if (short) NavigationSuiteType.NavigationRail
        else NavigationSuiteScaffoldDefaults.navigationSuiteType(currentWindowAdaptiveInfoV2())
    val isBar = auto == NavigationSuiteType.NavigationBar ||
        auto == NavigationSuiteType.ShortNavigationBarCompact || auto == NavigationSuiteType.ShortNavigationBarMedium
    val navType = if (page != null && isBar) NavigationSuiteType.None else auto
    NavigationSuiteScaffold(
        navigationItems = {
            Tab.entries.forEach { t ->
                NavigationSuiteItem(
                    selected = tab == t, onClick = { tab = t; page = null },
                    icon = { Icon(t.icon, null) }, label = { Text(t.label) },
                    navigationSuiteType = navType,
                )
            }
        },
        navigationSuiteType = navType,
    ) {
        // Capped and centred so rows stay readable on wide screens.
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
            Scaffold(
                Modifier.widthIn(max = 720.dp).nestedScroll(scroll.nestedScrollConnection),
                topBar = {
                    val p = page
                    if (p != null) TopAppBar(
                        title = { Text(p.title) },
                        navigationIcon = { IconButton({ page = null }) { Icon(Icons.AutoMirrored.Rounded.ArrowBack, "Back") } },
                    ) else if (short) TopAppBar(title = { Text(tab.title) })
                    else LargeTopAppBar(
                        title = { Text(tab.title) }, scrollBehavior = scroll,
                        // Flat when collapsed: a tinted bar only spans the capped column and leaves a seam by the rail.
                        colors = TopAppBarDefaults.topAppBarColors(scrolledContainerColor = MaterialTheme.colorScheme.surface),
                    )
                },
            ) { pad ->
                Box(Modifier.padding(pad).fillMaxSize()) {
                    BackHandler(page != null) { page = null }
                    when (page) {
                        Page.Activity -> ActivityScreen(s)
                        Page.Rules -> RulesScreen(s)
                        Page.AdBlock -> AdBlockScreen(s)
                        Page.Disguise -> DisguiseScreen(s)
                        Page.Route -> ScreenColumn { RouteGroup(s) }
                        null -> tabState.SaveableStateProvider(tab) {
                            when (tab) {
                                Tab.Home -> HomeScreen(s, open) { tab = it }
                                Tab.Dns -> DnsScreen(s)
                                Tab.Apps -> AppsScreen(s)
                                Tab.Tailscale -> TailscaleScreen(s)
                                Tab.Privacy -> PrivacyScreen(s, open)
                            }
                        }
                    }
                }
            }
        }
    }
}
