package io.github.pocketufw.alpha

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.text.DateFormat
import java.util.Date

@Composable
internal fun KernelStatusTab(
    state: FirewallClient.Snapshot,
    report: FirewallClient.KernelReport?,
    busy: Boolean,
    recheck: () -> Unit,
    setUdpPorts: (String, String, Boolean) -> Unit,
    restoreAutomatic: () -> Unit
) {
    var showRaw by remember { mutableStateOf(false) }
    val verified = state.protection == FirewallClient.Protection.ACTIVE
    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Surface(color = Panel, shape = RoundedCornerShape(20.dp),
            modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Firewall status", fontSize = 18.sp,
                    fontWeight = FontWeight.SemiBold)
                KernelStatusLine("Protection",
                    if (verified) "ACTIVE · Verified" else
                        if (state.protection == FirewallClient.Protection.INACTIVE)
                            "INACTIVE" else "NOT VERIFIED", verified)
                KernelStatusLine("PocketUFW incoming",
                    if (verified) "DROP unsolicited¹" else "Not verified", verified)
                KernelStatusLine("Outgoing", "Unchanged", false)
                KernelStatusLine("Packet logging", "Counters only", false)
                KernelStatusLine("Boot restore",
                    when (state.bootRestore) {
                        FirewallClient.BootRestore.ENABLED -> "Enabled"
                        FirewallClient.BootRestore.DISABLED -> "Disabled"
                        FirewallClient.BootRestore.UNSUPPORTED -> "Unsupported"
                        FirewallClient.BootRestore.CONFLICT -> "Conflict"
                        else -> "Unverified"
                    }, state.bootRestore == FirewallClient.BootRestore.ENABLED)
                if (report != null) {
                    Text("Rules read: " + DateFormat.getTimeInstance(DateFormat.SHORT)
                        .format(Date(report.readAt)), color = Muted, fontSize = 12.sp)
                }
                OutlinedButton(onClick = recheck, enabled = !busy,
                    modifier = Modifier.fillMaxWidth()) {
                    Text("Recheck kernel rules", fontSize = 13.sp)
                }
            }
        }

        if (report == null) {
            Surface(color = Panel, shape = RoundedCornerShape(18.dp),
                modifier = Modifier.fillMaxWidth()) {
                Text(
                    if (state.protection == FirewallClient.Protection.INACTIVE)
                        "No PocketUFW rules are installed."
                    else "A complete kernel rule report is unavailable. " +
                        "Recheck before relying on the detailed policy.",
                    modifier = Modifier.padding(18.dp),
                    color = if (verified) Amber else Muted,
                    fontSize = 13.sp
                )
            }
        } else {
            KernelFamilyPanel("IPv4", report.ipv4, showRaw)
            // Both address families are one rules section. Keep its shared
            // raw-view action inside the final (IPv6) rules card.
            KernelFamilyPanel("IPv6", report.ipv6, showRaw,
                onToggleRaw = { showRaw = !showRaw })
        }
        UdpExceptionsPanel(state, report, busy, setUdpPorts, restoreAutomatic)
        Text(
            "¹ PocketUFW hooks supported physical interfaces after Android's " +
                "existing INPUT rules. Earlier Android/OEM ACCEPT rules may " +
                "bypass these hooks. Android owns the INPUT chain policies; " +
                "this is a read-only snapshot, not a continuous monitor.",
            color = Muted, fontSize = 12.sp, lineHeight = 18.sp
        )
    }
}

@Composable
private fun KernelStatusLine(label: String, value: String, good: Boolean) {
    Row(modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, color = Muted, fontSize = 13.sp)
        Text(value, color = if (good) Mint else Foreground, fontSize = 13.sp)
    }
}


private fun describeRule(rule: String): Pair<String, String> = when {
    rule.contains("--ctstate") &&
        rule.contains("ESTABLISHED") && rule.contains("RELATED") ->
        "ALLOW" to "Established / related replies"
    rule.contains("--ctstate INVALID") -> "DROP" to "Invalid packets"
    rule.contains("-p ipv6-icmp") -> "ALLOW" to "ICMPv6 control traffic"
    rule.contains("-p icmp") -> "ALLOW" to "ICMP control traffic"
    rule.contains("--sport 67") && rule.contains("--dport 68") ->
        "ALLOW" to "DHCP replies"
    rule.contains("--sport 547") && rule.contains("--dport 546") ->
        "ALLOW" to "DHCPv6 replies"
    rule.contains("--dport 5353") -> "ALLOW" to "Multicast DNS"
    rule.contains("-p esp") -> "ALLOW" to "ESP / IPsec"
    rule.endsWith("-j POCKETUFW_TS") -> "CHECK" to "VPN listener exceptions"
    rule.endsWith("-j DROP") -> "DROP" to "Other incoming packets"
    rule.startsWith("-A POCKETUFW_TS ") &&
        rule.contains("--dport ") && rule.endsWith("-j ACCEPT") ->
        "ALLOW" to ("Verified VPN UDP port " +
            rule.substringAfter("--dport ").substringBefore(' '))
    else -> "RULE" to rule
}

@Composable
private fun KernelFamilyPanel(
    name: String,
    family: FirewallClient.RuleFamily,
    rawVisible: Boolean,
    onToggleRaw: (() -> Unit)? = null
) {
    val interfaces = family.hooks.map {
        it.substringAfter(" -i ", "").substringBefore(' ')
    }.filter { it.isNotEmpty() }.distinct()

    Surface(color = Panel, shape = RoundedCornerShape(20.dp),
        modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("$name · filter table", fontSize = 16.sp,
                fontWeight = FontWeight.SemiBold)
            KernelStatusLine("Android default", "${family.inputPolicy} (unchanged)", false)
            Text("PocketUFW hooks: " + interfaces.joinToString(", "),
                color = Muted, fontSize = 12.sp)
            Text("Inbound rules (in kernel order)", fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold, color = Foreground)

            family.inbound.forEach { rule ->
                val (action, detail) = describeRule(rule)
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp),
                    modifier = Modifier.fillMaxWidth()) {
                    Text(action, fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                        color = when (action) {
                            "ALLOW" -> Mint
                            "DROP" -> Amber
                            else -> Muted
                        },
                        modifier = Modifier.width(52.dp))
                    Text(detail, fontSize = 13.sp, lineHeight = 18.sp,
                        color = Foreground, modifier = Modifier.weight(1f))
                }
            }

            // A visually distinct, inset subcard makes the optional listener
            // allowances read separately from the main inbound rule sequence.
            Surface(color = Background, shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("VPN UDP exceptions", fontSize = 13.sp,
                        fontWeight = FontWeight.SemiBold, color = Foreground)
                    if (family.vpnExceptions.isEmpty()) {
                        Text("None installed", color = Muted, fontSize = 12.sp)
                    } else {
                        family.vpnExceptions.forEach { raw ->
                            val (action, detail) = describeRule(raw)
                            Text("$action  $detail", color = Mint, fontSize = 13.sp)
                        }
                    }
                }
            }
            if (rawVisible) {
                Surface(color = Background, shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth()) {
                    SelectionContainer {
                        Column(modifier = Modifier.padding(12.dp)
                            .horizontalScroll(rememberScrollState()),
                            verticalArrangement = Arrangement.spacedBy(5.dp)) {
                            Text("INPUT hooks", color = Mint, fontSize = 11.sp)
                            family.hooks.forEach { RawKernelRule(it) }
                            Text("POCKETUFW_IN", color = Mint, fontSize = 11.sp)
                            family.inbound.forEach { RawKernelRule(it) }
                            Text("POCKETUFW_TS", color = Mint, fontSize = 11.sp)
                            if (family.vpnExceptions.isEmpty()) {
                                Text("(no exceptions)", color = Muted, fontSize = 11.sp)
                            } else family.vpnExceptions.forEach { RawKernelRule(it) }
                        }
                    }
                }
            }
            if (onToggleRaw != null) {
                OutlinedButton(onClick = onToggleRaw, modifier = Modifier.fillMaxWidth()) {
                    Text(if (rawVisible) "Hide raw kernel rules" else "Show raw kernel rules",
                        fontSize = 13.sp)
                }
            }
        }
    }
}

@Composable
private fun RawKernelRule(rule: String) {
    Text(rule, fontFamily = FontFamily.Monospace, fontSize = 10.sp,
        color = Muted, softWrap = false)
}
