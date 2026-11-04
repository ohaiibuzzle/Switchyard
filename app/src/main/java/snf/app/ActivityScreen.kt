package snf.app

import android.content.Context
import android.text.format.DateFormat
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import org.json.JSONArray

/** One activity-log entry from the core (see core/events.go). */
data class Ev(
    val seq: Long, val t: Long, val uid: Int, val proto: String,
    val dst: String?, val host: String?, val action: String, val reason: String?,
)

// Outside the composable so leaving the screen doesn't drop what was fetched.
private val events = mutableStateListOf<Ev>()
private var lastSeq = 0L

private fun fetchEvents() {
    val a = JSONArray(snf.core.Core.events(lastSeq))
    for (i in 0 until a.length()) a.getJSONObject(i).run {
        events += Ev(
            getLong("seq"), getLong("t"), getInt("uid"), getString("proto"),
            optString("dst").ifEmpty { null }, optString("host").ifEmpty { null },
            getString("action"), optString("reason").ifEmpty { null },
        )
    }
    if (a.length() > 0) lastSeq = events.last().seq
    if (events.size > 2000) events.removeRange(0, events.size - 2000)
}

private data class AppId(val label: String, val pkg: String?)

private val appIds = mutableMapOf<Int, AppId>()

private fun appFor(ctx: Context, uid: Int): AppId = appIds.getOrPut(uid) {
    val pm = ctx.packageManager
    val pkgs = pm.getPackagesForUid(uid)
    when {
        pkgs.isNullOrEmpty() -> AppId(if (uid < 0) "Unknown app" else "System (uid $uid)", null)
        else -> {
            val label = runCatching { pm.getApplicationLabel(pm.getApplicationInfo(pkgs[0], 0)).toString() }.getOrDefault(pkgs[0])
            AppId(if (pkgs.size > 1) "$label +${pkgs.size - 1}" else label, pkgs[0])
        }
    }
}

private fun reasonText(e: Ev) = when (e.action) {
    "block" -> when (e.reason) {
        "app" -> "App blocked"
        "rule" -> "Your rule"
        "adblock" -> "Ad list"
        "bypass" -> "DNS bypass"
        "dot" -> "Private DNS port"
        "doh" -> "DoH server"
        "quic" -> "QUIC"
        else -> "Blocked"
    }
    "fail" -> "Failed"
    else -> when (e.reason) { "wireguard" -> "WireGuard"; "proxy" -> "Proxy"; else -> null }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ActivityScreen(s: Settings, change: (() -> Unit) -> Unit, rev: Int) {
    val ctx = LocalContext.current
    val logOn = remember(rev) { s.bool("logOn") }
    val allow = remember(rev) { s.set("allowDomains").sorted() }
    val block = remember(rev) { s.set("blockDomains").sorted() }
    val blockedApps = remember(rev) { s.set("blocked") }
    var blockedOnly by remember { mutableStateOf(true) }
    var appFilter by remember { mutableStateOf<Int?>(null) }
    var selected by remember { mutableStateOf<Ev?>(null) }
    var newRule by remember { mutableStateOf("") }
    LaunchedEffect(Unit) { while (true) { fetchEvents(); delay(1000) } }

    val shown = events.asReversed().filter { (!blockedOnly || it.action != "allow") && (appFilter == null || it.uid == appFilter) }
    val timeFmt = remember { DateFormat.getTimeFormat(ctx) }

    LazyColumn(Modifier.fillMaxSize().padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        item {
            Group {
                SwitchRow(Icons.Rounded.History, "Record activity", "Kept in memory until the filter stops", logOn) { v ->
                    change { s.put("logOn", v) }
                }
            }
        }
        item {
            Group("Your rules") {
                (allow.map { it to true } + block.map { it to false }).forEach { (d, isAllow) ->
                    ListItem(
                        headlineContent = { Text(d) },
                        supportingContent = { Text(if (isAllow) "Always allowed" else "Always blocked") },
                        leadingContent = { Icon(if (isAllow) Icons.Rounded.CheckCircle else Icons.Rounded.Block, null) },
                        trailingContent = {
                            IconButton({ change { s.put(if (isAllow) "allowDomains" else "blockDomains", s.set(if (isAllow) "allowDomains" else "blockDomains") - d) } }) {
                                Icon(Icons.Rounded.Delete, "Remove rule for $d")
                            }
                        },
                        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                    )
                }
                Row(Modifier.padding(start = 16.dp, end = 8.dp, top = 4.dp, bottom = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(newRule, { newRule = it }, Modifier.weight(1f), placeholder = { Text("example.com") }, singleLine = true)
                    val d = newRule.trim().lowercase().trimEnd('.')
                    TextButton({ change { s.addRule(true, d) }; newRule = "" }, enabled = '.' in d) { Text("Allow") }
                    TextButton({ change { s.addRule(false, d) }; newRule = "" }, enabled = '.' in d) { Text("Block") }
                }
            }
            Spacer(Modifier.height(8.dp))
            Hint("Apps may keep a cached address for a few minutes.")
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                FilterChip(blockedOnly, { blockedOnly = !blockedOnly }, label = { Text("Blocked only") })
                appFilter?.let { uid ->
                    InputChip(true, { appFilter = null }, label = { Text(appFor(ctx, uid).label, maxLines = 1) },
                        trailingIcon = { Icon(Icons.Rounded.Close, "Clear app filter", Modifier.size(18.dp)) })
                }
                Spacer(Modifier.weight(1f))
                TextButton({ events.clear(); snf.core.Core.clearEvents() }) { Text("Clear") }
            }
        }
        if (shown.isEmpty()) item {
            Hint(if (logOn) "Nothing yet." else "Turn on recording to see what apps connect to.")
        }
        items(shown, key = { it.seq }) { e ->
            val app = appFor(ctx, e.uid)
            val bad = e.action != "allow"
            ListItem(
                headlineContent = { Text(e.host ?: e.dst ?: "?", maxLines = 1, overflow = TextOverflow.Ellipsis) },
                supportingContent = {
                    val port = if (e.proto == "dns") "DNS" else "${e.proto.uppercase()} ${e.dst?.substringAfterLast(':')}"
                    Text("${app.label} · $port · ${timeFmt.format(e.t)}", maxLines = 1, overflow = TextOverflow.Ellipsis)
                },
                leadingContent = { app.pkg?.let { AppIcon(it) } ?: Icon(Icons.Rounded.Android, null, Modifier.size(40.dp)) },
                trailingContent = reasonText(e)?.let { r ->
                    { Text(r, style = MaterialTheme.typography.labelMedium, color = if (bad) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant) }
                },
                colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
                modifier = Modifier.clickable { selected = e },
            )
        }
        item { Spacer(Modifier.height(16.dp)) }
    }

    selected?.let { e ->
        val app = appFor(ctx, e.uid)
        val close = { selected = null }
        ModalBottomSheet(onDismissRequest = close) {
            ListItem(
                headlineContent = { Text(e.host ?: e.dst ?: "?") },
                supportingContent = {
                    Text(listOfNotNull(app.label, e.dst.takeIf { e.host != null }, reasonText(e), e.reason.takeIf { e.action == "fail" }).joinToString(" · "))
                },
            )
            HorizontalDivider()
            val h = e.host
            if (h != null) {
                SheetAction(Icons.Rounded.CheckCircle, "Always allow $h") { change { s.addRule(true, h) }; close() }
                SheetAction(Icons.Rounded.Block, "Always block $h") { change { s.addRule(false, h) }; close() }
            }
            if (app.pkg != null) {
                val uid = e.uid.toString()
                SheetAction(Icons.Rounded.Apps, if (uid in blockedApps) "Unblock ${app.label}" else "Block ${app.label}") {
                    change { s.toggleIn("blocked", uid) }; close()
                }
            }
            SheetAction(Icons.Rounded.FilterList, "Show only ${app.label}") { appFilter = e.uid; close() }
            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun SheetAction(icon: androidx.compose.ui.graphics.vector.ImageVector, text: String, onClick: () -> Unit) = ListItem(
    headlineContent = { Text(text, maxLines = 1, overflow = TextOverflow.Ellipsis) },
    leadingContent = { Icon(icon, null) },
    modifier = Modifier.clickable(onClick = onClick),
)
