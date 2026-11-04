package snf.app

import android.content.pm.ApplicationInfo
import android.text.format.DateUtils
import android.util.LruCache
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowForwardIos
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// ---- Building blocks, styled after the system Settings app ----

@Composable
fun ScreenColumn(content: @Composable ColumnScope.() -> Unit) = Column(
    Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp).padding(bottom = 24.dp),
    verticalArrangement = Arrangement.spacedBy(16.dp),
    content = content,
)

/** A rounded container of rows, with an optional small heading above it. */
@Composable
fun Group(title: String? = null, content: @Composable ColumnScope.() -> Unit) = Column {
    if (title != null) Text(
        title, Modifier.padding(start = 16.dp, bottom = 8.dp),
        style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary,
    )
    Surface(shape = RoundedCornerShape(24.dp), color = MaterialTheme.colorScheme.surfaceContainer) {
        Column(content = content)
    }
}

val rowColors @Composable get() = ListItemDefaults.colors(containerColor = Color.Transparent)

@Composable
fun SwitchRow(icon: ImageVector?, title: String, sub: String? = null, checked: Boolean, onChange: (Boolean) -> Unit) = ListItem(
    headlineContent = { Text(title) },
    supportingContent = sub?.let { { Text(it) } },
    leadingContent = icon?.let { { Icon(it, null) } },
    trailingContent = { Switch(checked, null) },
    colors = rowColors,
    modifier = Modifier.toggleable(checked, role = Role.Switch, onValueChange = onChange),
)

@Composable
fun NavRow(icon: ImageVector, title: String, sub: String, onClick: () -> Unit) = ListItem(
    headlineContent = { Text(title) },
    supportingContent = { Text(sub) },
    leadingContent = { Icon(icon, null) },
    trailingContent = { Icon(Icons.AutoMirrored.Rounded.ArrowForwardIos, null, Modifier.size(16.dp)) },
    colors = rowColors,
    modifier = Modifier.clickable(onClick = onClick),
)

@Composable
fun Notice(icon: ImageVector, title: String, body: String) = Surface(
    shape = RoundedCornerShape(24.dp), color = MaterialTheme.colorScheme.errorContainer,
) {
    ListItem(
        headlineContent = { Text(title) }, supportingContent = { Text(body) }, leadingContent = { Icon(icon, null) },
        colors = ListItemDefaults.colors(
            containerColor = Color.Transparent,
            headlineColor = MaterialTheme.colorScheme.onErrorContainer,
            supportingColor = MaterialTheme.colorScheme.onErrorContainer,
            leadingIconColor = MaterialTheme.colorScheme.onErrorContainer,
        ),
    )
}

@Composable
fun Hint(text: String) = Text(
    text, Modifier.padding(horizontal = 16.dp),
    style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant,
)

// ---- Screens ----

@Composable
fun DnsScreen(s: Settings, change: (() -> Unit) -> Unit) {
    val saved = s.dnsUrl
    // Keyed on the saved server so picking a preset or saving refreshes the form.
    var custom by remember(saved) { mutableStateOf(DNS_PRESETS.none { it.url == saved }) }
    var url by remember(saved) { mutableStateOf(saved) }
    var boot by remember(saved) { mutableStateOf(s.dnsBootstrap) }
    ScreenColumn {
        Group("Provider") {
            DNS_PRESETS.forEach { p ->
                ListItem(
                    headlineContent = { Text(p.name) },
                    supportingContent = { Text(dnsKind(p.url)) },
                    trailingContent = { RadioButton(!custom && saved == p.url, null) },
                    colors = rowColors,
                    modifier = Modifier.selectable(!custom && saved == p.url, role = Role.RadioButton) {
                        custom = false
                        change { s.setDns(p.url, p.bootstrap) }
                    },
                )
            }
            ListItem(
                headlineContent = { Text("Custom") },
                trailingContent = { RadioButton(custom, null) },
                colors = rowColors,
                modifier = Modifier.selectable(custom, role = Role.RadioButton) { custom = true },
            )
            if (custom) Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(url, { url = it }, Modifier.fillMaxWidth(), label = { Text("Server address") },
                    placeholder = { Text("https://, tls:// or quic://") }, singleLine = true)
                OutlinedTextField(boot, { boot = it }, Modifier.fillMaxWidth(), label = { Text("Server IPs (optional)") },
                    placeholder = { Text("1.2.3.4, 5.6.7.8") }, singleLine = true)
                FilledTonalButton({ change { s.setDns(url.trim(), boot.trim()) } }) { Text("Save") }
            }
        }
        Group("Protection") {
            SwitchRow(Icons.Rounded.GppGood, "Block apps' own DNS", checked = s.blockBypass) { v ->
                change { s.blockBypass = v }
            }
        }
    }
}

data class AppEntry(val label: String, val pkg: String, val uid: Int, val system: Boolean)

private val iconCache = LruCache<String, ImageBitmap>(300)

@Composable
fun AppIcon(pkg: String) {
    val ctx = LocalContext.current
    val img by produceState(iconCache.get(pkg), pkg) {
        if (value == null) value = withContext(Dispatchers.IO) {
            runCatching { ctx.packageManager.getApplicationIcon(pkg).toBitmap(108, 108).asImageBitmap() }
                .getOrNull()?.also { iconCache.put(pkg, it) }
        }
    }
    val m = Modifier.size(40.dp).clip(RoundedCornerShape(12.dp))
    img?.let { Image(it, null, m) } ?: Box(m)
}

@Composable
fun AppsScreen(s: Settings, change: (() -> Unit) -> Unit) {
    val ctx = LocalContext.current
    var apps by remember { mutableStateOf<List<AppEntry>?>(null) }
    var query by remember { mutableStateOf("") }
    var showSystem by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        apps = withContext(Dispatchers.IO) {
            val pm = ctx.packageManager
            pm.getInstalledApplications(0)
                .filter { it.packageName != ctx.packageName }
                .map { AppEntry(pm.getApplicationLabel(it).toString(), it.packageName, it.uid, it.flags and ApplicationInfo.FLAG_SYSTEM != 0) }
                .sortedBy { it.label.lowercase() }
        }
    }
    val blocked = s.blockedUids
    val proxied = s.routedUids
    val mode = s.routeMode
    val proxyOn = mode != "off"
    Column(Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
        OutlinedTextField(
            query, { query = it }, Modifier.fillMaxWidth(),
            placeholder = { Text("Search apps") }, leadingIcon = { Icon(Icons.Rounded.Search, null) },
            singleLine = true, shape = RoundedCornerShape(28.dp),
        )
        Row(Modifier.padding(vertical = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(showSystem, { showSystem = !showSystem }, label = { Text("System apps") })
        }
        if (proxyOn) {
            Hint("Globe: route through ${if (mode == "wg") "WireGuard" else "proxy"}. None picked = all apps.")
            Spacer(Modifier.height(8.dp))
        }
        val list = apps
        if (list == null) Box(Modifier.fillMaxWidth().padding(32.dp), Alignment.Center) { CircularProgressIndicator() }
        else LazyColumn(Modifier.clip(RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp))) {
            items(list.filter { (showSystem || !it.system) && (it.label.contains(query, true) || it.pkg.contains(query, true)) }, key = { it.pkg }) { a ->
                val uid = a.uid
                val allowed = uid !in blocked
                ListItem(
                    headlineContent = { Text(a.label, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                    supportingContent = { Text(if (allowed) a.pkg else "No internet access", maxLines = 1, overflow = TextOverflow.Ellipsis) },
                    leadingContent = { AppIcon(a.pkg) },
                    trailingContent = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            if (proxyOn) IconToggleButton(uid in proxied, { change { s.routedUids = s.routedUids.toggle(uid) } }) {
                                Icon(Icons.Rounded.Public, "Route through tunnel")
                            }
                            Switch(allowed, null)
                        }
                    },
                    colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
                    modifier = Modifier.toggleable(allowed, role = Role.Switch) { change { s.blockedUids = s.blockedUids.toggle(uid) } },
                )
            }
        }
    }
}

@Composable
fun AdBlockScreen(s: Settings, change: (() -> Unit) -> Unit) {
    val scope = rememberCoroutineScope()
    var newUrl by remember { mutableStateOf("") }
    var refreshStatus by remember { mutableStateOf<String?>(null) }
    val lists = s.lists
    val presetUrls = LIST_PRESETS.map { it.url }.toSet()
    fun updated(url: String) = s.listFile(url).let {
        if (it.exists()) "Updated " + DateUtils.getRelativeTimeSpanString(it.lastModified()) else "Not downloaded yet"
    }
    ScreenColumn {
        Group {
            SwitchRow(Icons.Rounded.Block, "Block ads and trackers", checked = s.adblock) { v ->
                change { s.adblock = v }
            }
        }
        Group("Block lists") {
            LIST_PRESETS.forEach { p ->
                SwitchRow(null, p.name, if (p.url in lists) "${p.desc}\n${updated(p.url)}" else p.desc, p.url in lists) {
                    change { s.lists = s.lists.toggle(p.url) }
                }
            }
            (lists - presetUrls).forEach { url ->
                ListItem(
                    headlineContent = { Text(url.substringAfter("://").substringBefore('/')) },
                    supportingContent = { Text(updated(url)) },
                    trailingContent = { IconButton({ change { s.lists = s.lists - url } }) { Icon(Icons.Rounded.Delete, "Remove") } },
                    colors = rowColors,
                )
            }
            Row(Modifier.padding(start = 16.dp, end = 8.dp, bottom = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(newUrl, { newUrl = it }, Modifier.weight(1f), placeholder = { Text("Add list by URL") }, singleLine = true)
                IconButton({ newUrl.trim().takeIf { it.startsWith("http") }?.let { u -> change { s.lists = s.lists + u }; newUrl = "" } }) {
                    Icon(Icons.Rounded.Add, "Add list")
                }
            }
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            FilledTonalButton({
                refreshStatus = "Updating…"
                scope.launch {
                    val errs = withContext(Dispatchers.IO) { s.refreshLists(maxAgeMs = 0) }
                    refreshStatus = if (errs.isEmpty()) null else "Some lists failed to update:\n" + errs.entries.joinToString("\n") { "${it.key}: ${it.value}" }
                    change {}
                }
            }) {
                Icon(Icons.Rounded.Refresh, null, Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text("Update lists now")
            }
        }
        refreshStatus?.let { Hint(it) }
    }
}

@Composable
fun PrivacyScreen(s: Settings, change: (() -> Unit) -> Unit) {
    ScreenColumn {
        Group("Disguise traffic") {
            SwitchRow(Icons.Rounded.Lock, "Hide site names in secure connections", checked = s.sniSplit) { v ->
                change { s.sniSplit = v }
            }
            SwitchRow(Icons.Rounded.CallSplit, "Fragment secure handshakes", checked = s.tlsFrag) { v ->
                change { s.tlsFrag = v }
            }
            SwitchRow(Icons.Rounded.Http, "Disguise unencrypted requests", checked = s.hostTricks) { v ->
                change { s.hostTricks = v }
            }
            SwitchRow(Icons.Rounded.Speed, "Turn off QUIC", "Lets the options above cover more apps", s.blockQuic) { v ->
                change { s.blockQuic = v }
            }
        }
        RouteGroup(s, change)
    }
}

@Composable
fun RouteGroup(s: Settings, change: (() -> Unit) -> Unit) {
    val mode = s.routeMode
    val savedProxy = s.proxyUrl
    var proxy by remember(savedProxy) { mutableStateOf(savedProxy) }
    Group("Route traffic") {
        listOf(
            Triple("off", "Directly", null),
            Triple("proxy", "Through a proxy", "TCP only"),
            Triple("wg", "Through WireGuard", null),
        ).forEach { (key, title, sub) ->
            ListItem(
                headlineContent = { Text(title) }, supportingContent = sub?.let { { Text(it) } },
                trailingContent = { RadioButton(mode == key, null) },
                colors = rowColors,
                modifier = Modifier.selectable(mode == key, role = Role.RadioButton) { change { s.routeMode = key } },
            )
        }
        if (mode == "proxy") Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(proxy, { proxy = it }, Modifier.fillMaxWidth(), label = { Text("Proxy address") },
                placeholder = { Text("socks5://host:port or http://host:port") }, singleLine = true)
            FilledTonalButton({ change { s.proxyUrl = proxy.trim() } }) { Text("Save") }
        }
        if (mode == "wg") WgProfiles(s, change)
    }
    if (mode == "wg") Hint("DNS doesn't go through the tunnel.")
}
