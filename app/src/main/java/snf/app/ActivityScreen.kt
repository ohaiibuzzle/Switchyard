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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.json.JSONArray
import kotlin.time.Duration.Companion.seconds

/** One activity-log entry from the core (see core/events.go). */
data class Ev(
    val seq: Long, val t: Long, val uid: Int, val proto: String,
    val dst: String?, val host: String?, val action: String, val reason: String?, val err: String?,
)

/** The flow's IP, from dst "1.2.3.4:443" or "[::1]:443"; null for DNS entries, whose dst is the resolver we stand in for. */
private val Ev.ip get() = dst?.takeIf { proto != "dns" }?.substringBeforeLast(':')?.trim('[', ']')

// Outside the composable so leaving the screen doesn't drop what was fetched.
private val events = mutableStateListOf<Ev>()
private var lastSeq = 0L

private suspend fun fetchEvents() {
    // Off the main thread: the core call and parsing a full log can take a while.
    val new = withContext(Dispatchers.IO) {
        val a = JSONArray(snf.core.Core.events(lastSeq))
        List(a.length()) { i ->
            a.getJSONObject(i).run {
                Ev(
                    getLong("seq"), getLong("t"), getInt("uid"), getString("proto"),
                    optString("dst").ifEmpty { null }, optString("host").ifEmpty { null },
                    getString("action"), optString("reason").ifEmpty { null }, optString("err").ifEmpty { null },
                )
            }
        }
    }
    events += new
    if (new.isNotEmpty()) lastSeq = new.last().seq
    if (events.size > 2000) events.removeRange(0, events.size - 2000) // mirrors maxEvents in core/events.go
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

// Codes come from core: verdict (tunnel.go), dnsDecision and upstreamDial (routing.go).
private fun reasonText(e: Ev) = when (e.action) {
    "block" -> when (e.reason) {
        "app" -> "App blocked"
        "rule" -> "Custom rule"
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
fun ActivityScreen(s: Settings) {
    val ctx = LocalContext.current
    val logOn = s.logOn
    var blockedOnly by remember { mutableStateOf(true) }
    var appFilter by remember { mutableStateOf<Int?>(null) }
    var selected by remember { mutableStateOf<Ev?>(null) }
    LaunchedEffect(Unit) { while (true) { fetchEvents(); delay(1.seconds) } }

    val shown = events.asReversed().filter { (!blockedOnly || it.action != "allow") && (appFilter == null || it.uid == appFilter) }
    val timeFmt = remember { DateFormat.getTimeFormat(ctx) }

    LazyColumn(Modifier.fillMaxSize().padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        item {
            Group {
                SwitchRow(Icons.Rounded.History, "Record activity", "Kept in memory until the filter stops", logOn) { v ->
                    s.logOn = v
                }
            }
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
                    Text(listOfNotNull(app.label, e.dst.takeIf { e.host != null }, reasonText(e), e.err).joinToString(" · "))
                },
            )
            HorizontalDivider()
            e.host?.let(::domainRule)?.let { DomainRule(s, it) } // null when the "host" is an IP
            e.ip?.let(::ipRule)?.let { ip ->
                if (ip in s.blockRules) SheetAction(Icons.Rounded.CheckCircle, "Unblock $ip") { s.setRule(ip, Rule.Default); close() }
                else SheetAction(Icons.Rounded.Block, "Always block $ip") { s.setRule(ip, Rule.Block); close() }
            }
            app.pkg?.let { pkg ->
                val blocked = s.access(e.uid, pkg) == Access.Blocked
                SheetAction(Icons.Rounded.Apps, if (blocked) "Unblock ${app.label}" else "Block ${app.label}") {
                    s.setAccess(e.uid, pkg, if (blocked) Access.Allowed else Access.Blocked); close()
                }
            }
            SheetAction(Icons.Rounded.FilterList, "Show only ${app.label}") { appFilter = e.uid; close() }
            Spacer(Modifier.height(24.dp))
        }
    }
}

/** Block / Default / Allow for domain [h], naming the parent's rule when that's what decides it. */
@Composable
private fun DomainRule(s: Settings, h: String) {
    val (current, by) = s.rule(h)
    Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
        by?.takeIf { it != h }?.let {
            Text("${if (current == Rule.Allow) "Allowed" else "Blocked"} by rule for $it", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth().padding(top = 4.dp)) {
            Rule.entries.forEachIndexed { i, r ->
                SegmentedButton(r == current, { s.setRule(h, r) }, SegmentedButtonDefaults.itemShape(i, Rule.entries.size)) { Text(r.name) }
            }
        }
    }
}

@Composable
private fun SheetAction(icon: androidx.compose.ui.graphics.vector.ImageVector, text: String, onClick: () -> Unit) = ListItem(
    headlineContent = { Text(text, maxLines = 1, overflow = TextOverflow.Ellipsis) },
    leadingContent = { Icon(icon, null) },
    modifier = Modifier.clickable(onClick = onClick),
)
