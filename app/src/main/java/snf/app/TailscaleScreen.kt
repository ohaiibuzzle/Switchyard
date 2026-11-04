package snf.app

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

@Composable
fun TailscaleScreen(s: Settings) {
    val on = s.routeMode == "ts"
    ScreenColumn {
        Group {
            SwitchRow(Icons.Rounded.Hub, "Use Tailscale", "Reach your tailnet. Proxy and WireGuard pause.", on) { v ->
                if (v) { s.routeBeforeTs = s.routeMode; s.routeMode = "ts" } else s.routeMode = s.routeBeforeTs
            }
            if (on) TsStatus()
        }
        if (on) TsAdvanced(s)
    }
}

@Composable
private fun TsStatus() {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var st by remember { mutableStateOf(JSONObject()) }
    var openWhenReady by remember { mutableStateOf(false) }
    var err by remember { mutableStateOf<String?>(null) }
    // Off the main thread: it waits on the node's local API.
    LaunchedEffect(Unit) { while (true) { st = JSONObject(withContext(Dispatchers.IO) { snf.core.Core.tsStatus() }); delay(1000) } }
    val state = st.optString("state", "Off")
    val url = st.optString("authUrl")
    fun open(u: String) = ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(u)))
    LaunchedEffect(state) { err = null; if (state != "NeedsLogin") openWhenReady = false }
    LaunchedEffect(url, openWhenReady) { if (openWhenReady && url.isNotEmpty()) { openWhenReady = false; open(url) } }
    fun call(onOk: () -> Unit = {}, f: () -> Unit) = scope.launch {
        err = try { withContext(Dispatchers.IO) { f() }; onOk(); null } catch (e: Exception) { e.message }
    }

    val text = when {
        !FilterVpnService.running -> "Turn the filter on to connect"
        err != null -> "Error: $err"
        state == "Running" -> "Connected · ${st.optString("ip")}"
        state == "NeedsLogin" -> "Signed out"
        state == "NeedsMachineAuth" -> "Waiting for an admin to approve this device"
        else -> "Starting…"
    }
    Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            val ok = state == "Running"
            Icon(if (ok) Icons.Rounded.CheckCircle else Icons.Rounded.Pending, null,
                tint = if (ok) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.width(8.dp))
            Text(text, style = MaterialTheme.typography.bodyMedium)
        }
        when (state) {
            // tsLogin re-sends a login that's still in progress, or starts a fresh one if the old URL expired.
            "NeedsLogin" -> FilledTonalButton({ call(onOk = { openWhenReady = true }) { snf.core.Core.tsLogin() } }) { Text("Sign in") }
            "Running" -> TextButton({ call { snf.core.Core.tsLogout() } }) { Text("Sign out") }
        }
    }
}

@Composable
private fun TsAdvanced(s: Settings) {
    val savedUrl = s.tsControlUrl
    val savedKey = s.tsAuthKey
    var url by remember(savedUrl) { mutableStateOf(savedUrl) }
    var key by remember(savedKey) { mutableStateOf(savedKey) }
    Group("Advanced") {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(url, { url = it }, Modifier.fillMaxWidth(), label = { Text("Control server (optional)") },
                placeholder = { Text("https://headscale.example.com") }, singleLine = true)
            OutlinedTextField(key, { key = it }, Modifier.fillMaxWidth(), label = { Text("Auth key (optional)") },
                placeholder = { Text("tskey-auth-…") }, singleLine = true, visualTransformation = PasswordVisualTransformation())
            FilledTonalButton({ s.tsControlUrl = url.trim(); s.tsAuthKey = key.trim() }) { Text("Save") }
        }
    }
}
