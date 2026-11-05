package io.github.pocketufw

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** Inline explanatory accordion and deliberately gated advanced UDP editor. */
@Composable
internal fun UdpExceptionsPanel(
    state: FirewallClient.Snapshot,
    report: FirewallClient.KernelReport?,
    busy: Boolean,
    onSetPorts: (String, String, Boolean) -> Unit,
    onUseAutomatic: () -> Unit,
    initiallyExpanded: Boolean = false
) {
    var expanded by remember { mutableStateOf(initiallyExpanded) }
    var warningOpen by remember { mutableStateOf(false) }
    var editorOpen by remember { mutableStateOf(false) }
    var commitConfirmation by remember { mutableStateOf(false) }
    var autoConfirmation by remember { mutableStateOf(false) }
    var committed by remember { mutableStateOf(false) }
    var ipv4Input by remember { mutableStateOf("") }
    var ipv6Input by remember { mutableStateOf("") }
    var inputError by remember { mutableStateOf("") }

    fun currentPort(raw: List<String>): String =
        raw.firstNotNullOfOrNull { rule ->
            Regex("--dport ([1-9][0-9]{0,4})").find(rule)?.groupValues?.get(1)
        } ?: ""

    fun valid(input: String): Boolean {
        if (input.isBlank()) return true
        return Regex("[1-9][0-9]{0,4}").matches(input) &&
            (input.toIntOrNull() ?: 0) in 1..65535
    }

    fun submit() {
        val port4 = ipv4Input.trim()
        val port6 = ipv6Input.trim()
        if (!valid(port4) || !valid(port6)) {
            inputError = "Enter a UDP port from 1 to 65535, or leave blank for none."
            return
        }
        inputError = ""
        if (committed) commitConfirmation = true
        else {
            onSetPorts(port4, port6, false)
            editorOpen = false
        }
    }

    val active = state.protection == FirewallClient.Protection.ACTIVE && report != null && !busy
    val editable = active && state.udpConfigMode in listOf(
        FirewallClient.UdpConfigMode.AUTOMATIC, FirewallClient.UdpConfigMode.COMMITTED
    )
    val saved = state.udpConfigMode == FirewallClient.UdpConfigMode.COMMITTED
    val live4 = report?.ipv4?.vpnExceptions?.let(::currentPort) ?: ""
    val live6 = report?.ipv6?.vpnExceptions?.let(::currentPort) ?: ""

    Surface(color = Background, shape = RoundedCornerShape(0.dp), modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(vertical = 4.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            if (!initiallyExpanded) {
                OutlinedButton(shape = RoundedCornerShape(9.dp), onClick = { expanded = !expanded }, modifier = Modifier.fillMaxWidth()) {
                    Text(if (expanded) "Hide VPN UDP exceptions ▲" else "About / edit VPN UDP exceptions ▼",
                        fontSize = 13.sp)
                }
            }
            if (expanded) {
                Text("Incoming VPN UDP exceptions", fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
                Text(
                    "These narrowly allow inbound UDP to a verified or manually chosen listener. " +
                        "They can help Tailscale peers connect directly. Ordinary outbound VPN " +
                        "connections, such as Proton VPN, usually don't need them.",
                    color = Muted, fontSize = 13.sp, lineHeight = 19.sp
                )
                Text(
                    "Experimental and Committed change only PocketUFW's incoming VPN UDP " +
                        "port exceptions, not Android's global firewall rules or outgoing traffic. " +
                        "An allowed port admits inbound UDP on supported interfaces, not just " +
                        "Tailscale packets. Choose only ports with trusted listeners.",
                    color = Muted, fontSize = 12.sp, lineHeight = 18.sp
                )
                val mode = when (state.udpConfigMode) {
                    FirewallClient.UdpConfigMode.AUTOMATIC -> "Automatic · verified Tailscale listeners"
                    FirewallClient.UdpConfigMode.COMMITTED -> "Committed · saved for future sessions"
                    FirewallClient.UdpConfigMode.DEGRADED -> "Saved configuration needs inspection"
                    FirewallClient.UdpConfigMode.UNKNOWN -> "Saved configuration not verified"
                }
                Text(mode, color = if (saved) Mint else Muted, fontSize = 13.sp)
                if (saved) {
                    Text("Saved IPv4 UDP: ${state.committedUdp4} · IPv6 UDP: ${state.committedUdp6}",
                        color = Muted, fontSize = 12.sp)
                    if ((live4.ifEmpty { "none" } != state.committedUdp4) ||
                        (live6.ifEmpty { "none" } != state.committedUdp6)) {
                        Text("The live rules differ from the committed settings. " +
                            "A firewall rebuild restores the committed ports.",
                            color = Amber, fontSize = 12.sp, lineHeight = 18.sp)
                    }
                }
                Text("Live IPv4 UDP: ${live4.ifEmpty { "none" }} · " +
                    "IPv6 UDP: ${live6.ifEmpty { "none" }}",
                    color = Foreground, fontSize = 12.sp)

                if (!editorOpen) {
                    OutlinedButton(shape = RoundedCornerShape(9.dp),
                        onClick = { warningOpen = true }, enabled = editable,
                        modifier = Modifier.fillMaxWidth()
                    ) { Text("Advanced: Edit UDP exceptions", fontSize = 13.sp) }
                } else {
                    Text("One incoming UDP port per address family. Blank means none.",
                        color = Muted, fontSize = 12.sp)
                    OutlinedTextField(
                        value = ipv4Input,
                        onValueChange = { if (it.length <= 5) { ipv4Input = it; inputError = "" } },
                        label = { Text("IPv4 UDP port") }, singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.fillMaxWidth(), enabled = !busy
                    )
                    OutlinedTextField(
                        value = ipv6Input,
                        onValueChange = { if (it.length <= 5) { ipv6Input = it; inputError = "" } },
                        label = { Text("IPv6 UDP port") }, singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.fillMaxWidth(), enabled = !busy
                    )
                    Row(modifier = Modifier.fillMaxWidth().clickable(enabled = !busy) { committed = false },
                        verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(selected = !committed, onClick = { committed = false }, enabled = !busy)
                        Column {
                            Text("Experimental", fontSize = 14.sp)
                            Text(
                                "Temporary: resets when you turn the firewall off/on or reboot. " +
                                    "Refresh VPN may replace it. Closing this app or reconnecting " +
                                    "Tailscale does not reset it.",
                                color = Muted, fontSize = 12.sp, lineHeight = 18.sp
                            )
                        }
                    }
                    Row(modifier = Modifier.fillMaxWidth().clickable(enabled = !busy) { committed = true },
                        verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(selected = committed, onClick = { committed = true }, enabled = !busy)
                        Column {
                            Text("Committed", fontSize = 14.sp)
                            Text(
                                "Saved until edited or reset to automatic VPN exceptions. " +
                                    "Reapplied when the firewall starts, including after reboot " +
                                    "if Magisk boot restoration is enabled.",
                                color = Muted, fontSize = 12.sp, lineHeight = 18.sp
                            )
                        }
                    }
                    if (inputError.isNotBlank()) Text(inputError, color = Amber, fontSize = 12.sp)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(shape = RoundedCornerShape(9.dp), onClick = { editorOpen = false }, modifier = Modifier.weight(1f),
                            enabled = !busy) { Text("Cancel") }
                        Button(shape = RoundedCornerShape(9.dp), onClick = { submit() }, modifier = Modifier.weight(1f),
                            enabled = editable) { Text(if (committed) "Review save" else "Apply now") }
                    }
                }
                // Reset must also be available after an Experimental edit.
                // That edit changes live kernel rules without changing the
                // saved AUTOMATIC/COMMITTED preference.
                if (!editorOpen) {
                    OutlinedButton(shape = RoundedCornerShape(9.dp), onClick = { autoConfirmation = true }, enabled = active,
                        modifier = Modifier.fillMaxWidth()) {
                        Text("Reset to automatic VPN exceptions", fontSize = 12.sp)
                    }
                }
                Text("Tailscale listener ports may change, making committed manual ports stale. " +
                    "Changing a port may interrupt direct connections; the engine attempts " +
                    "rollback on failed edits. Refresh VPN won't overwrite committed ports.",
                    color = Muted, fontSize = 12.sp, lineHeight = 18.sp)
            }
        }
    }

    if (warningOpen) {
        AlertDialog(
            onDismissRequest = { warningOpen = false },
            title = { Text("Advanced firewall configuration") },
            text = { Text("Warning: advanced users only. Editing inbound UDP exceptions can " +
                "expose services or break VPN connectivity. Only change ports you understand.") },
            confirmButton = {
                TextButton(onClick = {
                    warningOpen = false
                    editorOpen = true
                    committed = false  // Experimental is always the safer default.
                    ipv4Input = live4
                    ipv6Input = live6
                    inputError = ""
                }) { Text("I understand") }
            },
            dismissButton = { TextButton(onClick = { warningOpen = false }) { Text("Cancel") } }
        )
    }
    if (commitConfirmation) {
        AlertDialog(
            onDismissRequest = { commitConfirmation = false },
            title = { Text("Commit these UDP exceptions?") },
            text = { Text("Are you sure? These ports will replace automatic Tailscale " +
                "listener detection in future firewall sessions. If Magisk boot restoration " +
                "is enabled, they'll be restored after reboot too. You can return to automatic later.") },
            confirmButton = {
                TextButton(onClick = {
                    commitConfirmation = false
                    onSetPorts(ipv4Input.trim(), ipv6Input.trim(), true)
                    editorOpen = false
                }, enabled = editable) { Text("Yes, commit") }
            },
            dismissButton = { TextButton(onClick = { commitConfirmation = false }) { Text("Not yet") } }
        )
    }
    if (autoConfirmation) {
        AlertDialog(
            onDismissRequest = { autoConfirmation = false },
            title = { Text("Reset to automatic VPN exceptions?") },
            text = { Text("Replace the current UDP exceptions with ports verified from " +
                "running Tailscale listeners and clear any Committed setting? " +
                "If Tailscale has no verified listeners, no UDP exception will be installed. " +
                "If detection fails, existing settings are preserved.") },
            confirmButton = {
                TextButton(onClick = {
                    autoConfirmation = false
                    onUseAutomatic()
                }, enabled = active) { Text("Reset exceptions") }
            },
            dismissButton = { TextButton(onClick = { autoConfirmation = false }) { Text("Cancel") } }
        )
    }
}
