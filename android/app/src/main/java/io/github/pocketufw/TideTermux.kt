package io.github.pocketufw

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.*
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp

private const val INSTALL_COPY = "installation"

@Composable
internal fun TideTermuxCommands() {
    var expanded by rememberSaveable { mutableStateOf(false) }
    var setupExpanded by rememberSaveable { mutableStateOf(false) }
    var copied by remember { mutableStateOf<String?>(null) }
    var installError by remember { mutableStateOf(false) }
    var copySequence by remember { mutableIntStateOf(0) }
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    val copy: (String) -> Unit = { command ->
        clipboard.setText(AnnotatedString(command))
        copied = command
        copySequence++
    }
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        // The screen's footer divider already closes this row when collapsed.
        TideSettingExpander("Termux quick commands", "Check your firewall from the terminal", expanded,
            showDivider = expanded) {
            expanded = !expanded
            copied = null
        }
        if (expanded) {
            Text("To use these commands, install the optional helper first. See “Install the helper” below.",
                style = MaterialTheme.typography.bodyMedium, color = Muted)
            Text("Tap any command to copy it, then paste it into Termux.", style = MaterialTheme.typography.bodySmall, color = Muted)
            for ((command, purpose) in listOf(
                "pufw" to "Verified rule status, tunnel summary and counters.",
                "pufw tunnel" to "Tunnel mode, saved authorization and current address verification.",
                "pufw stats" to "Physical and tunnel DROP packets, bytes and established/related returns. Does not recheck PINNED addresses.",
                "pufw clear" to "Reset PocketUFW counters after confirmation in Termux. Rules and Insights samples are kept.",
                "pufw raw" to "Native read-only diagnostic output."
            )) Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                TermuxCommand(command, copy, copied == command, copySequence)
                Text(purpose, style = MaterialTheme.typography.bodySmall, color = Muted)
            }
            TideSettingExpander("Install the helper", "Included in this app · one command", setupExpanded) {
                setupExpanded = !setupExpanded
                copied = null
            }
            if (setupExpanded) {
                Text("Copy the installation command, paste it into a normal Termux session, and run it. The helper is included in this app; no download or storage permission is needed.",
                    style = MaterialTheme.typography.bodySmall, color = Muted)
                TideOutlinedButton("Copy installation command", onClick = {
                    try {
                        copy(bundledTermuxInstallCommand(context))
                        copied = INSTALL_COPY
                        installError = false
                    } catch (_: Exception) {
                        copied = null
                        installError = true
                    }
                }, modifier = Modifier.semantics {
                    if (copied == INSTALL_COPY) stateDescription = "Copied to clipboard"
                })
                if (copied == INSTALL_COPY) key(copySequence) {
                    Text("Installation command copied. Paste it into Termux.",
                        Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                        style = MaterialTheme.typography.bodySmall, color = Muted)
                }
                if (installError) TideNotice("Could not copy the installation command. Reopen PocketUFW and try again.", error = true)
                Text("Installation verifies the helper before replacing an existing copy. After updating PocketUFW, copy and run a fresh command to update the helper.",
                    style = MaterialTheme.typography.bodySmall, color = Muted)
                Text("Then tap Recheck in PocketUFW and run pufw in Termux. Installation needs no root; running pufw still requires root access.",
                    style = MaterialTheme.typography.bodySmall, color = Muted)
            }
            Text("On demand, with no background polling. Only pufw clear changes counters, after confirmation. Separate from the experimental pufw-inspect packet-sampling tool.",
                style = MaterialTheme.typography.bodySmall, color = Muted)
        }
    }
}

@Composable
private fun TermuxCommand(command: String, copy: (String) -> Unit, copied: Boolean, copySequence: Int) {
    Text(command, Modifier.fillMaxWidth().clickable(role = Role.Button, onClickLabel = "Copy command") { copy(command) }
        .heightIn(min = 48.dp).padding(vertical = 12.dp)
        .semantics { if (copied) stateDescription = "Copied to clipboard" },
        style = MaterialTheme.typography.bodyMedium, fontFamily = TideMono, color = Mint)
    // Keep feedback beside the copied text, including repeated copies of the same command.
    if (copied) key(copySequence) {
        Text("Copied: $command", Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            style = MaterialTheme.typography.bodySmall, color = Muted)
    }
}
