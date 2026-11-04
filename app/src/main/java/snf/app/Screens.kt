package snf.app

import android.content.pm.ApplicationInfo
import android.provider.OpenableColumns
import android.text.format.DateUtils
import android.util.LruCache
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.ScrollState
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// ---- Building blocks, styled after the system Settings app ----

/** Per-tab scroll state, provided from above key(rev) so a settings change doesn't jump to the top. */
val LocalScroll = compositionLocalOf<ScrollState?> { null }

@Composable
fun ScreenColumn(content: @Composable ColumnScope.() -> Unit) = Column(
    Modifier.fillMaxSize().verticalScroll(LocalScroll.current ?: rememberScrollState()).padding(horizontal = 16.dp).padding(bottom = 24.dp),
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

private val rowColors @Composable get() = ListItemDefaults.colors(containerColor = Color.Transparent)

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
    val saved = s.dnsUrl()
    var custom by remember { mutableStateOf(DNS_PRESETS.none { it.url == saved }) }
    var url by remember { mutableStateOf(saved) }
    var boot by remember { mutableStateOf(s.dnsBootstrap()) }
    ScreenColumn {
        Hint("Every app's DNS lookups are encrypted and sent to the provider you pick here.")
        Group("Provider") {
            DNS_PRESETS.forEach { p ->
                ListItem(
                    headlineContent = { Text(p.name) },
                    supportingContent = { Text(dnsKind(p.url)) },
                    trailingContent = { RadioButton(!custom && saved == p.url, null) },
                    colors = rowColors,
                    modifier = Modifier.selectable(!custom && saved == p.url, role = Role.RadioButton) {
                        custom = false
                        change { s.put("dnsUrl", p.url); s.put("dnsBootstrap", p.bootstrap) }
                    },
                )
            }
            ListItem(
                headlineContent = { Text("Custom") },
                supportingContent = { Text("Your own DoH, DoT or DoQ server") },
                trailingContent = { RadioButton(custom, null) },
                colors = rowColors,
                modifier = Modifier.selectable(custom, role = Role.RadioButton) { custom = true },
            )
            if (custom) Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(url, { url = it }, Modifier.fillMaxWidth(), label = { Text("Server address") },
                    placeholder = { Text("https://, tls:// or quic://") }, singleLine = true)
                OutlinedTextField(boot, { boot = it }, Modifier.fillMaxWidth(), label = { Text("Server IPs (optional)") },
                    placeholder = { Text("1.2.3.4, 5.6.7.8") }, singleLine = true)
                FilledTonalButton({ change { s.put("dnsUrl", url.trim()); s.put("dnsBootstrap", boot.trim()) } }) { Text("Save") }
            }
        }
        Group("Protection") {
            SwitchRow(
                Icons.Rounded.GppGood, "Stop apps from bypassing",
                "Block apps that try to use their own encrypted DNS",
                s.bool("blockBypass", true),
            ) { v -> change { s.put("blockBypass", v) } }
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
fun AppsScreen(s: Settings, change: (() -> Unit) -> Unit, rev: Int) {
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
    val blocked = remember(rev) { s.set("blocked") }
    val proxied = remember(rev) { s.set("proxied") }
    val mode = remember(rev) { s.routeMode() }
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
        Hint(
            if (!proxyOn) "Turn an app off to cut its internet access."
            else "Turn an app off to cut its internet. The globe sends it through ${if (mode == "wg") "WireGuard" else "your proxy"}; pick none to send every app."
        )
        Spacer(Modifier.height(8.dp))
        val list = apps
        if (list == null) Box(Modifier.fillMaxWidth().padding(32.dp), Alignment.Center) { CircularProgressIndicator() }
        else LazyColumn(Modifier.clip(RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp))) {
            items(list.filter { (showSystem || !it.system) && (it.label.contains(query, true) || it.pkg.contains(query, true)) }, key = { it.pkg }) { a ->
                val uid = a.uid.toString()
                val allowed = uid !in blocked
                ListItem(
                    headlineContent = { Text(a.label, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                    supportingContent = { Text(if (allowed) a.pkg else "No internet access", maxLines = 1, overflow = TextOverflow.Ellipsis) },
                    leadingContent = { AppIcon(a.pkg) },
                    trailingContent = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            if (proxyOn) IconToggleButton(uid in proxied, { change { s.toggleIn("proxied", uid) } }) {
                                Icon(Icons.Rounded.Public, "Route through tunnel")
                            }
                            Switch(allowed, null)
                        }
                    },
                    colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
                    modifier = Modifier.toggleable(allowed, role = Role.Switch) { change { s.toggleIn("blocked", uid) } },
                )
            }
        }
    }
}

// Outside the composable so the key(rev) re-read after a refresh doesn't wipe it.
private var refreshStatus by mutableStateOf<String?>(null)

@Composable
fun AdBlockScreen(s: Settings, change: (() -> Unit) -> Unit) {
    val scope = rememberCoroutineScope()
    var newUrl by remember { mutableStateOf("") }
    val lists = s.set("lists")
    val presetUrls = LIST_PRESETS.map { it.url }.toSet()
    fun updated(url: String) = s.listFile(url).let {
        if (it.exists()) "Updated " + DateUtils.getRelativeTimeSpanString(it.lastModified()) else "Not downloaded yet"
    }
    ScreenColumn {
        Group {
            SwitchRow(Icons.Rounded.Block, "Block ads and trackers", "Filtered on this device, nothing leaves it", s.bool("adblock")) { v ->
                change { s.put("adblock", v) }
            }
        }
        Group("Block lists") {
            LIST_PRESETS.forEach { p ->
                SwitchRow(null, p.name, if (p.url in lists) "${p.desc}\n${updated(p.url)}" else p.desc, p.url in lists) {
                    change { s.toggleIn("lists", p.url) }
                }
            }
            (lists - presetUrls).forEach { url ->
                ListItem(
                    headlineContent = { Text(url.substringAfter("://").substringBefore('/')) },
                    supportingContent = { Text(updated(url)) },
                    trailingContent = { IconButton({ change { s.toggleIn("lists", url) } }) { Icon(Icons.Rounded.Delete, "Remove") } },
                    colors = rowColors,
                )
            }
            Row(Modifier.padding(start = 16.dp, end = 8.dp, bottom = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(newUrl, { newUrl = it }, Modifier.weight(1f), placeholder = { Text("Add list by URL") }, singleLine = true)
                IconButton({ newUrl.trim().takeIf { it.startsWith("http") }?.let { u -> change { s.toggleIn("lists", u) }; newUrl = "" } }) {
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
        Hint("Lists also update when the filter starts, if they're more than a day old.")
    }
}

@Composable
fun PrivacyScreen(s: Settings, change: (() -> Unit) -> Unit) {
    ScreenColumn {
        Hint("Helps you reach sites blocked by network filters that look at which sites you visit.")
        Group("Disguise traffic") {
            SwitchRow(Icons.Rounded.Lock, "Hide site names in secure connections", "Splits the site name across packets", s.bool("sniSplit")) { v ->
                change { s.put("sniSplit", v) }
            }
            SwitchRow(Icons.Rounded.CallSplit, "Fragment secure handshakes", "Breaks the opening message into pieces", s.bool("tlsFrag")) { v ->
                change { s.put("tlsFrag", v) }
            }
            SwitchRow(Icons.Rounded.Http, "Disguise unencrypted requests", "For older http:// sites", s.bool("hostTricks")) { v ->
                change { s.put("hostTricks", v) }
            }
            SwitchRow(Icons.Rounded.Speed, "Turn off QUIC", "Makes apps use connections the options above can disguise", s.bool("blockQuic")) { v ->
                change { s.put("blockQuic", v) }
            }
        }
        RouteGroup(s, change)
    }
}

@Composable
fun RouteGroup(s: Settings, change: (() -> Unit) -> Unit) {
    val mode = s.routeMode()
    var proxy by remember { mutableStateOf(s.str("proxyUrl")) }
    Group("Route traffic") {
        listOf(
            Triple("off", "Directly", "No tunnel"),
            Triple("proxy", "Through a proxy", "SOCKS5 or HTTP · TCP only"),
            Triple("wg", "Through WireGuard", "Your own VPN server or provider · TCP and UDP"),
        ).forEach { (key, title, sub) ->
            ListItem(
                headlineContent = { Text(title) }, supportingContent = { Text(sub) },
                trailingContent = { RadioButton(mode == key, null) },
                colors = rowColors,
                modifier = Modifier.selectable(mode == key, role = Role.RadioButton) { change { s.put("routeMode", key) } },
            )
        }
        if (mode == "proxy") Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(proxy, { proxy = it }, Modifier.fillMaxWidth(), label = { Text("Proxy address") },
                placeholder = { Text("socks5://host:port or http://host:port") }, singleLine = true)
            FilledTonalButton({ change { s.put("proxyUrl", proxy.trim()) } }) { Text("Save") }
        }
        if (mode == "wg") WgProfiles(s, change)
    }
    if (mode == "wg") Hint("Only addresses in the peer's AllowedIPs use the tunnel. DNS still goes to your Private DNS provider.")
    if (mode == "proxy") Hint("The proxy only carries TCP. Other traffic still goes directly.")
}

@Composable
fun WgStatus() {
    var age by remember { mutableLongStateOf(-2L) }
    var err by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(Unit) {
        while (true) { age = snf.core.Core.wgHandshakeAge(); err = FilterVpnService.lastError; delay(1000) }
    }
    val (text, ok) = when {
        err != null -> "Couldn't apply: $err" to false
        age == -2L -> "Not connected · start the filter and save a config" to false
        age == -1L -> "Waiting for the server to answer…" to false
        // WireGuard re-handshakes every 2 min only while traffic flows, so silence after that is just idle.
        age <= 180 -> "Connected · last handshake ${age}s ago" to true
        else -> "Connected · idle for ${age / 60} min" to true
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(if (ok) Icons.Rounded.CheckCircle else Icons.Rounded.Pending, null,
            tint = if (ok) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.width(8.dp))
        Text(text, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
fun WgProfiles(s: Settings, change: (() -> Unit) -> Unit) {
    val profiles = s.wgProfiles()
    val active = s.activeWg()?.name
    // Profile being edited; name "" with editOld null means a new one.
    var editing by remember { mutableStateOf<WgProfile?>(if (profiles.isEmpty()) WgProfile("", "") else null) }
    var editOld by remember { mutableStateOf<String?>(null) }
    var deleting by remember { mutableStateOf<String?>(null) }

    if (profiles.isNotEmpty()) Box(Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) { WgStatus() }
    profiles.forEach { p ->
        ListItem(
            headlineContent = { Text(p.name) },
            supportingContent = { Text(p.endpoint) },
            leadingContent = { RadioButton(p.name == active, null) },
            trailingContent = {
                Row {
                    IconButton({ editing = p; editOld = p.name }) { Icon(Icons.Rounded.Edit, "Edit ${p.name}") }
                    IconButton({ deleting = p.name }) { Icon(Icons.Rounded.Delete, "Delete ${p.name}") }
                }
            },
            colors = rowColors,
            modifier = Modifier.selectable(p.name == active, role = Role.RadioButton) { change { s.put("wgActive", p.name) } },
        )
    }
    val e = editing
    if (e == null) TextButton({ editing = WgProfile("", ""); editOld = null }, Modifier.padding(start = 8.dp, bottom = 8.dp)) {
        Icon(Icons.Rounded.Add, null, Modifier.size(18.dp))
        Spacer(Modifier.width(8.dp))
        Text("Add config")
    } else WgEditor(e, editOld, profiles.map { it.name }.toSet(), onCancel = if (profiles.isEmpty()) null else ({ editing = null })) { saved ->
        change {
            s.saveWg(editOld, saved)
            // New profiles become active; renaming the active one keeps it active.
            if (editOld == null || editOld == active) s.put("wgActive", saved.name)
        }
        editing = null
    }

    deleting?.let { name ->
        AlertDialog(
            onDismissRequest = { deleting = null },
            title = { Text("Delete \"$name\"?") },
            text = { Text("Its keys are removed from this device. Keep a copy if you'll need it again.") },
            confirmButton = { TextButton({ change { s.deleteWg(name) }; deleting = null }) { Text("Delete") } },
            dismissButton = { TextButton({ deleting = null }) { Text("Cancel") } },
        )
    }
}

@Composable
fun WgEditor(start: WgProfile, oldName: String?, taken: Set<String>, onCancel: (() -> Unit)?, onSave: (WgProfile) -> Unit) {
    val ctx = LocalContext.current
    var name by remember(start) { mutableStateOf(start.name) }
    var conf by remember(start) { mutableStateOf(start.conf) }
    val import = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        ctx.contentResolver.openInputStream(uri)?.use { conf = it.readBytes().decodeToString() }
        if (name.isBlank()) ctx.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) name = c.getString(0).substringBeforeLast(".conf")
        }
    }
    val nameError = when {
        name.isBlank() -> "Give it a name"
        name.trim() != oldName && name.trim() in taken -> "That name is already used"
        else -> null
    }
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(if (oldName == null) "New config" else "Edit config", style = MaterialTheme.typography.titleSmall)
        OutlinedTextField(name, { name = it }, Modifier.fillMaxWidth(), label = { Text("Name") }, singleLine = true,
            isError = nameError != null && name.isNotEmpty(), supportingText = nameError?.takeIf { name.isNotEmpty() }?.let { { Text(it) } })
        OutlinedTextField(
            conf, { conf = it }, Modifier.fillMaxWidth(), label = { Text("WireGuard config") },
            placeholder = { Text("[Interface]\nPrivateKey = …\nAddress = …\n\n[Peer]\n…") },
            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            minLines = 4, maxLines = 12,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton({ import.launch(arrayOf("*/*")) }) { Text("Import file") }
            if (onCancel != null) TextButton(onCancel) { Text("Cancel") }
            FilledTonalButton({ onSave(WgProfile(name.trim(), conf.trim())) }, enabled = nameError == null && conf.isNotBlank()) { Text("Save") }
        }
    }
}
