package io.github.pocketufw

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.semantics.*
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp

internal const val TERMUX_RELEASES = "https://github.com/wingetx/PocketUFW/releases"
internal const val TERMUX_STORAGE = "termux-setup-storage"
internal const val TERMUX_PREPARE = "mkdir -p \"\$HOME/pufw-setup\" &&\n" +
    "cp \"\$HOME/storage/downloads/pufw\" \"\$HOME/storage/downloads/pufw.sha256\" \"\$HOME/pufw-setup/\" &&\n" +
    "cd \"\$HOME/pufw-setup\""
internal const val TERMUX_INSTALL = "sha256sum -c pufw.sha256 &&\ninstall -m 700 pufw \"\$PREFIX/bin/pufw\""

@Composable
internal fun TideTermuxCommands() {
    var expanded by rememberSaveable { mutableStateOf(false) }
    var setupExpanded by rememberSaveable { mutableStateOf(false) }
    var copied by remember { mutableStateOf<String?>(null) }
    var copySequence by remember { mutableIntStateOf(0) }
    val clipboard = LocalClipboardManager.current
    val uriHandler = LocalUriHandler.current
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
            Text("To use these commands, install the optional helper first. See “Install the helper” below.",
                style = MaterialTheme.typography.bodyMedium, color = Muted)
            Text("Tap any command to copy it, then paste it into Termux.", style = MaterialTheme.typography.bodySmall, color = Muted)
            for ((command, purpose) in listOf(
                "pufw" to "Verified rule status, tunnel summary and counters.",
                "pufw tunnel" to "Tunnel mode, saved authorization and current address verification.",
                "pufw stats" to "Physical and tunnel DROP packets, bytes and established/related returns. Does not recheck PINNED addresses.",
                "pufw raw" to "Native read-only diagnostic output."
            )) Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                TermuxCommand(command, copy, copied == command, copySequence)
                Text(purpose, style = MaterialTheme.typography.bodySmall, color = Muted)
            }
            TideSettingExpander("Install the helper", "GitHub Release download and setup", setupExpanded) {
                setupExpanded = !setupExpanded
                copied = null
            }
            if (setupExpanded) {
                Text("Download pufw and pufw.sha256 from the GitHub Release assets to your phone’s Downloads folder. No source code needed. The release also includes a full setup guide (Termux-setup.md).",
                    style = MaterialTheme.typography.bodySmall, color = Muted)
                TideSettingLink("GitHub Releases", "Get the Termux helper") { uriHandler.openUri(TERMUX_RELEASES) }
                Text("Run these setup commands in Termux in order. Start by allowing access to Downloads:",
                    style = MaterialTheme.typography.bodySmall, color = Muted)
                TermuxCommand(TERMUX_STORAGE, copy, copied == TERMUX_STORAGE, copySequence)
                Text("Copy the two downloads into Termux’s private folder:",
                    style = MaterialTheme.typography.bodySmall, color = Muted)
                TermuxCommand(TERMUX_PREPARE, copy, copied == TERMUX_PREPARE, copySequence)
                Text("Verify and install. Continue only if the checksum reports pufw: OK. A failed check prevents installation.",
                    style = MaterialTheme.typography.bodySmall, color = Muted)
                TermuxCommand(TERMUX_INSTALL, copy, copied == TERMUX_INSTALL, copySequence)
                Text("Open PocketUFW and tap Recheck once. Then run pufw in Termux and grant root access when prompted.",
                    style = MaterialTheme.typography.bodySmall, color = Muted)
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
