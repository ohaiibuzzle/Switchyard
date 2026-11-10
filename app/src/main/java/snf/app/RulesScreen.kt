package snf.app

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/** Your own rules, one tab each: Blocked (domains, IPs, CIDR ranges) and Allowed (domains only; core has no IP allow). */
@Composable
fun RulesScreen(s: Settings) {
    var allowTab by rememberSaveable { mutableStateOf(false) }
    var input by rememberSaveable { mutableStateOf("") }
    val rules = (if (allowTab) s.allowDomains else s.blockRules).sorted()
    val newRule = parseRule(input, allowTab)

    Column(Modifier.fillMaxSize()) {
        PrimaryTabRow(if (allowTab) 1 else 0) {
            Tab(!allowTab, { allowTab = false }, text = { Text("Blocked") })
            Tab(allowTab, { allowTab = true }, text = { Text("Allowed") })
        }
        LazyColumn(Modifier.fillMaxSize().padding(horizontal = 16.dp), contentPadding = PaddingValues(vertical = 16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            item {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(
                        input, { input = it }, Modifier.weight(1f), singleLine = true,
                        placeholder = { Text(if (allowTab) "example.com" else "example.com or 1.2.3.0/24") },
                    )
                    TextButton({ newRule?.let { s.addRule(allowTab, it) }; input = "" }, enabled = newRule != null) { Text("Add") }
                }
                Spacer(Modifier.height(8.dp))
                Hint(if (allowTab) "Beats ad lists. Domains only." else "Apps may keep a cached address for a few minutes.")
            }
            if (rules.isNotEmpty()) item {
                Group {
                    rules.forEach { r ->
                        ListItem(
                            headlineContent = { Text(r) },
                            leadingContent = { Icon(if (allowTab) Icons.Rounded.CheckCircle else Icons.Rounded.Block, null) },
                            trailingContent = { IconButton({ s.removeRule(r) }) { Icon(Icons.Rounded.Delete, "Remove rule for $r") } },
                            colors = rowColors,
                        )
                    }
                }
            }
        }
    }
}
