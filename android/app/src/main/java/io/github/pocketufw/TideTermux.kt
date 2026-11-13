package io.github.pocketufw

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.semantics.*
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp

internal const val TERMUX_INSTALL = "install -m 700 tools/pufw \"\$PREFIX/bin/pufw\""

@Composable
internal fun TideTermuxCommands() {
    var expanded by rememberSaveable { mutableStateOf(false) }
    var copied by remember { mutableStateOf<String?>(null) }
    var copySequence by remember { mutableIntStateOf(0) }
    val clipboard = LocalClipboardManager.current
    val copy: (String) -> Unit = { command ->
        clipboard.setText(AnnotatedString(command))
        copied = command
        copySequence++
    }
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        TideSettingExpander("Termux quick commands", "Check your firewall from the terminal", expanded) {
            expanded = !expanded
            copied = null
        }
        if (expanded) {
            Text("Install the optional helper first. These commands are unavailable until it is installed in Termux.",
                style = MaterialTheme.typography.bodyMedium, color = Muted)
            Text("From a PocketUFW source folder containing tools/pufw, run this in Termux:",
                style = MaterialTheme.typography.bodySmall, color = Muted)
            TermuxCommand(TERMUX_INSTALL, copy, copied == TERMUX_INSTALL, copySequence)
            Text("Open PocketUFW and tap Recheck once to prepare its engine. Grant Termux root access when prompted. Full setup: docs/termux.md in the source folder.",
                style = MaterialTheme.typography.bodySmall, color = Muted)
            Text("Tap a command to copy it.", style = MaterialTheme.typography.bodySmall, color = Muted)
            for ((command, purpose) in listOf(
                "pufw" to "Verified rule status, tunnel summary and counters.",
                "pufw tunnel" to "Tunnel mode, saved authorization and current address verification.",
                "pufw stats" to "Physical and tunnel DROP packets, bytes and established/related returns. Does not recheck PINNED addresses.",
                "pufw raw" to "Native read-only diagnostic output."
            )) Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                TermuxCommand(command, copy, copied == command, copySequence)
                Text(purpose, style = MaterialTheme.typography.bodySmall, color = Muted)
            }
            Text("Read-only and on demand, with no background polling. Separate from the experimental pufw-inspect packet-sampling tool.",
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
