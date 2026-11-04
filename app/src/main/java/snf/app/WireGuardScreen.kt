package snf.app

import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.selection.selectable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay

@Composable
fun WgStatus() {
    var age by remember { mutableLongStateOf(-2L) }
    val err = FilterVpnService.lastError
    LaunchedEffect(Unit) { while (true) { age = snf.core.Core.wgHandshakeAge(); delay(1000) } }
    val (text, ok) = when {
        err != null -> "Couldn't apply: $err" to false
        age == -2L -> "Not connected" to false
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
    // Profile being edited; name "" with editOld null means a new one. With no profiles, always a new one.
    var editing by remember { mutableStateOf<WgProfile?>(null) }
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
            modifier = Modifier.selectable(p.name == active, role = Role.RadioButton) { change { s.wgActive = p.name } },
        )
    }
    val e = editing ?: WgProfile("", "").takeIf { profiles.isEmpty() }
    if (e == null) TextButton({ editing = WgProfile("", ""); editOld = null }, Modifier.padding(start = 8.dp, bottom = 8.dp)) {
        Icon(Icons.Rounded.Add, null, Modifier.size(18.dp))
        Spacer(Modifier.width(8.dp))
        Text("Add config")
    } else WgEditor(e, editOld, profiles.map { it.name }.toSet(), onCancel = if (profiles.isEmpty()) null else ({ editing = null })) { saved ->
        // New profiles become active; renaming the active one keeps it active.
        change { s.saveWg(editOld, saved, activate = editOld == null || editOld == active) }
        editing = null
    }

    deleting?.let { name ->
        AlertDialog(
            onDismissRequest = { deleting = null },
            title = { Text("Delete \"$name\"?") },
            text = { Text("This can't be undone.") },
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
