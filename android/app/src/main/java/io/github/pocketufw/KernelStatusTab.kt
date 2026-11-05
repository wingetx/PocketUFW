package io.github.pocketufw

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
internal fun KernelStatusTab(state: FirewallClient.Snapshot, report: FirewallClient.KernelReport?,
                            busy: Boolean, recheck: () -> Unit, onExceptions: () -> Unit,
                            verificationInDoubt: Boolean = false) {
    var ipv6 by rememberSaveable { mutableStateOf(false) }
    var raw by rememberSaveable { mutableStateOf(false) }
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        if (verificationInDoubt) TideNotice(
            "Last known rule report only. Current kernel protection needs rechecking.", true)
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            listOf("IPv4", "IPv6").forEachIndexed { index, name ->
                FilterChip(selected = ipv6 == (index == 1), onClick = { ipv6 = index == 1 },
                    label = { Text(name) },
                    colors = FilterChipDefaults.filterChipColors(selectedContainerColor = Foreground, selectedLabelColor = Background),
                    modifier = Modifier.heightIn(min = 48.dp))
            }
            Spacer(Modifier.weight(1f))
            TextButton(onClick = { raw = !raw }, modifier = Modifier.heightIn(min = 48.dp)) {
                TideIcon(R.drawable.tide_code, tint = Mint)
                Spacer(Modifier.width(6.dp))
                Text(if (raw) "Readable" else "Raw")
            }
        }
        if (report == null) {
            TideNotice(if (state.protection == FirewallClient.Protection.INACTIVE && !verificationInDoubt) "No PocketUFW rules are installed."
                else "A complete kernel rule report is unavailable. Recheck before relying on the detailed policy.")
        } else {
            val family = if (ipv6) report.ipv6 else report.ipv4
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("${if (ipv6) "IPv6" else "IPv4"} · INPUT / filter", style = MaterialTheme.typography.titleMedium)
                Text("Android default: ${family.inputPolicy} · unchanged", style = MaterialTheme.typography.bodySmall, color = Muted)
                val interfaces = family.hooks.map { it.substringAfter(" -i ", "").substringBefore(' ') }
                    .filter { it.isNotEmpty() }.distinct()
                Text("Hooks: " + interfaces.joinToString(" · "), fontFamily = TideMono,
                    style = MaterialTheme.typography.bodySmall, color = Muted)
                Text("Rules read: " + readTime(report.readAt), style = MaterialTheme.typography.bodySmall, color = Muted)
            }
            TideDivider()
            if (raw) {
                Surface(color = Panel, shape = RoundedCornerShape(8.dp), modifier = Modifier.fillMaxWidth()) {
                    SelectionContainer {
                        Column(Modifier.padding(16.dp).horizontalScroll(rememberScrollState()),
                            verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text("INPUT hooks", color = Mint, style = MaterialTheme.typography.labelMedium)
                            family.hooks.forEach { RawKernelRule(it) }
                            Text("POCKETUFW_IN", color = Mint, style = MaterialTheme.typography.labelMedium)
                            family.inbound.forEach { RawKernelRule(it) }
                            Text("POCKETUFW_TS", color = Mint, style = MaterialTheme.typography.labelMedium)
                            if (family.vpnExceptions.isEmpty()) Text("(no exceptions)", color = Muted)
                            else family.vpnExceptions.forEach { RawKernelRule(it) }
                        }
                    }
                }
            } else {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("POCKETUFW · KERNEL ORDER", style = MaterialTheme.typography.labelSmall,
                        letterSpacing = 1.sp, color = Muted)
                    // The report is already ordered by the kernel. Never sort or group by action.
                    family.inbound.forEachIndexed { index, rule -> KernelRuleRow(index, rule) }
                }
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    TideDivider()
                    Text("VPN UDP exceptions · child chain", style = MaterialTheme.typography.titleSmall)
                    if (family.vpnExceptions.isEmpty()) Text("None installed", style = MaterialTheme.typography.bodyMedium, color = Muted)
                    else family.vpnExceptions.forEachIndexed { index, rule -> KernelRuleRow(index, rule, "vpn") }
                }
            }
        }
        OutlinedButton(onClick = recheck, enabled = !busy && state.protection != FirewallClient.Protection.CHECKING,
            modifier = Modifier.fillMaxWidth().heightIn(min = TideActionMinHeight), shape = RoundedCornerShape(9.dp)) {
            TideIcon(R.drawable.tide_refresh, tint = LocalContentColor.current)
            Spacer(Modifier.width(8.dp)); Text("Recheck kernel rules")
        }
        TideSettingLink("VPN UDP exceptions", "Inspect live ports and edit advanced settings", onExceptions)
        Text("Read-only snapshot, not a continuous monitor. PocketUFW hooks supported physical interfaces after " +
            "Android’s existing INPUT rules. Earlier Android/OEM ACCEPT rules may bypass these hooks. " +
            "Android owns the INPUT chain policies. Outgoing traffic is unchanged. Packet logging: counters only.",
            color = Muted, style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun KernelRuleRow(index: Int, rule: String, chain: String = "inbound") {
    val (action, detail) = describeRule(rule)
    val color = when (action) { "ALLOW" -> Mint; "DROP" -> MaterialTheme.colorScheme.error; else -> Muted }
    val large = LocalDensity.current.fontScale > 1.2f
    Row(Modifier.fillMaxWidth().padding(vertical = 6.dp).testTag("$chain-rule-$index")
        .semantics(mergeDescendants = true) {}, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        Text((index + 1).toString().padStart(2, '0'), color = Muted, fontFamily = TideMono,
            style = MaterialTheme.typography.labelSmall)
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(detail, style = MaterialTheme.typography.bodyMedium)
            if (large) Text(action, color = color, fontFamily = TideMono, style = MaterialTheme.typography.labelSmall)
        }
        if (!large) Text(action, color = color, fontFamily = TideMono, style = MaterialTheme.typography.labelSmall)
    }
}

@Composable
private fun RawKernelRule(rule: String) {
    Text(rule, fontFamily = TideMono, style = MaterialTheme.typography.bodySmall, color = Foreground, softWrap = false)
}

private fun describeRule(rule: String): Pair<String, String> = when {
    rule.contains("--ctstate") &&
        rule.contains("ESTABLISHED") && rule.contains("RELATED") ->
        "ALLOW" to "Established / related replies"
    rule.endsWith("-j NFLOG") || rule.contains("-j NFLOG ") ->
        "LOG" to "Temporary diagnostic probe (non-verdict)"
    rule.contains("--ctstate INVALID") && rule.endsWith("-j DROP") -> "DROP" to "Invalid packets"
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
        "ALLOW" to ("VPN UDP exception, port " +
            rule.substringAfter("--dport ").substringBefore(' '))
    else -> "RULE" to rule
}
