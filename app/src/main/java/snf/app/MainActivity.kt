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
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp

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
    Home("Network Filter", "Home", Icons.Rounded.Shield),
    Dns("Private DNS", "DNS", Icons.Rounded.Dns),
    Apps("App access", "Apps", Icons.Rounded.Apps),
    Ads("Ad blocking", "Ads", Icons.Rounded.Block),
    Privacy("Privacy", "Privacy", Icons.Rounded.VisibilityOff),
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun App(s: Settings) {
    var tab by remember { mutableStateOf(Tab.Home) }
    var activity by remember { mutableStateOf(false) } // Activity log screen, opened from Home
    val scroll = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(rememberTopAppBarState())
    val tabState = rememberSaveableStateHolder() // keeps each tab's scroll position across tab switches
    Scaffold(
        Modifier.nestedScroll(scroll.nestedScrollConnection),
        topBar = {
            if (activity) TopAppBar(
                title = { Text("Activity") },
                navigationIcon = { IconButton({ activity = false }) { Icon(Icons.AutoMirrored.Rounded.ArrowBack, "Back") } },
            ) else LargeTopAppBar(title = { Text(tab.title) }, scrollBehavior = scroll)
        },
        bottomBar = {
            if (!activity) NavigationBar {
                Tab.entries.forEach { t ->
                    NavigationBarItem(
                        selected = tab == t, onClick = { tab = t },
                        icon = { Icon(t.icon, null) }, label = { Text(t.label) },
                    )
                }
            }
        },
    ) { pad ->
        Box(Modifier.padding(pad).fillMaxSize()) {
            BackHandler(activity) { activity = false }
            if (activity) ActivityScreen(s)
            else tabState.SaveableStateProvider(tab) {
                when (tab) {
                    Tab.Home -> HomeScreen(s, onActivity = { activity = true }) { tab = it }
                    Tab.Dns -> DnsScreen(s)
                    Tab.Apps -> AppsScreen(s)
                    Tab.Ads -> AdBlockScreen(s)
                    Tab.Privacy -> PrivacyScreen(s)
                }
            }
        }
    }
}
