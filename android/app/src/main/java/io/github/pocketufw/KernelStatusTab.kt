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
                            busy: Boolean, recheck: () -> Unit,
                            verificationInDoubt: Boolean = false) {
    var ipv6 by rememberSaveable { mutableStateOf(false) }
    var raw by rememberSaveable { mutableStateOf(false) }
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        if (verificationInDoubt) TideNotice(
            "Last known rule report only. Current kernel protection needs rechecking.", true)
        if (report != null && bypassRules(report).isNotEmpty()) {
            val families = listOfNotNull("IPv4".takeIf { report.ipv4.bypass.isNotEmpty() },
                "IPv6".takeIf { report.ipv6.bypass.isNotEmpty() })
            TideNotice(BYPASS_NOTICE + " Listed under " + families.joinToString(" and ") + ".", true)
        }
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
                            if (family.bypass.isNotEmpty()) {
                                Text("Earlier INPUT rules · bypass PocketUFW", color = Amber,
                                    style = MaterialTheme.typography.labelMedium)
                                family.bypass.forEach { RawKernelRule(it) }
                            }
                            Text("INPUT hooks", color = Mint, style = MaterialTheme.typography.labelMedium)
                            family.hooks.forEach { RawKernelRule(it) }
                            Text("POCKETUFW_IN", color = Mint, style = MaterialTheme.typography.labelMedium)
                            family.inbound.forEach { RawKernelRule(it) }
                            Text("POCKETUFW_TS", color = Mint, style = MaterialTheme.typography.labelMedium)
                            if (family.vpnExceptions.isEmpty()) Text("(no exceptions)", color = Muted)
                            else family.vpnExceptions.forEach { RawKernelRule(it) }
                            if (family.tunnel.isNotEmpty()) {
                                Text("POCKETUFW_VPN", color = Mint, style = MaterialTheme.typography.labelMedium)
                                family.tunnel.forEach { RawKernelRule(it) }
                            }
                        }
                    }
                }
            } else {
                if (family.bypass.isNotEmpty()) Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("EARLIER INPUT RULES · BYPASS POCKETUFW", style = MaterialTheme.typography.labelSmall,
                        letterSpacing = 1.sp, color = Amber)
                    family.bypass.forEachIndexed { index, rule -> KernelRuleRow(index, rule, "bypass") }
                    TideDivider()
                }
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("PHYSICAL INBOUND · KERNEL ORDER", style = MaterialTheme.typography.labelSmall,
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
                if (family.tunnel.isNotEmpty()) Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    TideDivider()
                    Text("Tunnel protection · separate chain", style = MaterialTheme.typography.titleSmall)
                    Text("POCKETUFW_VPN is entered from its own tun+ and WireGuard INPUT hooks, not after the physical DROP.",
                        style = MaterialTheme.typography.bodySmall, color = Muted)
                    family.tunnel.forEachIndexed { index, rule -> KernelRuleRow(index, rule, "tunnel") }
                }
            }
        }
        OutlinedButton(onClick = recheck, enabled = !busy && state.protection != FirewallClient.Protection.CHECKING,
            modifier = Modifier.fillMaxWidth().heightIn(min = TideActionMinHeight), shape = TideActionShape) {
            TideIcon(R.drawable.tide_refresh, tint = LocalContentColor.current)
            Spacer(Modifier.width(8.dp)); Text("Recheck kernel rules")
        }
        Text("Read-only snapshot, not a continuous monitor. Physical hooks enter POCKETUFW_IN; " +
            "optional tun+ and WireGuard hooks enter POCKETUFW_VPN separately. " +
            "Earlier Android/OEM ACCEPT rules may bypass these INPUT hooks. " +
            "Android owns the INPUT chain policies. Outgoing traffic is unchanged. Packet logging: counters only.",
            color = Muted, style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun KernelRuleRow(index: Int, rule: String, chain: String = "inbound") {
    val (action, detail) = describeRule(rule)
    val color = when {
        chain == "bypass" -> Amber
        action == "ALLOW" -> Mint
        action == "DROP" || action == "REJECT" -> MaterialTheme.colorScheme.error
        else -> Muted
    }
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

/**
 * Plain words for the rules PocketUFW installs, exactly as the kernel lists them.
 * A label is a claim about what a rule does, so a rule that differs in any way,
 * target and destination included, is shown as itself rather than as the rule it
 * resembles. `iptables -S` adds "-m udp" on some Android versions and not others.
 */
private val KNOWN_RULES = mapOf(
    "-A POCKETUFW_IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" to ("ALLOW" to "Established / related replies"),
    "-A POCKETUFW_IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT" to ("ALLOW" to "Established / related replies"),
    "-A POCKETUFW_IN -m conntrack --ctstate INVALID -j DROP" to ("DROP" to "Invalid packets"),
    "-A POCKETUFW_IN -p ipv6-icmp -j ACCEPT" to ("ALLOW" to "ICMPv6 control traffic"),
    "-A POCKETUFW_IN -p icmp -j ACCEPT" to ("ALLOW" to "ICMP control traffic"),
    "-A POCKETUFW_IN -p udp --sport 67 --dport 68 -j ACCEPT" to ("ALLOW" to "DHCP replies"),
    "-A POCKETUFW_IN -p udp --sport 547 --dport 546 -j ACCEPT" to ("ALLOW" to "DHCPv6 replies"),
    "-A POCKETUFW_IN -d 224.0.0.251/32 -p udp --dport 5353 -j ACCEPT" to ("ALLOW" to "Multicast DNS"),
    "-A POCKETUFW_IN -d ff02::fb/128 -p udp --dport 5353 -j ACCEPT" to ("ALLOW" to "Multicast DNS"),
    "-A POCKETUFW_IN -p esp -j ACCEPT" to ("ALLOW" to "ESP / IPsec"),
    "-A POCKETUFW_IN -j POCKETUFW_TS" to ("CHECK" to "VPN listener exceptions"),
    "-A POCKETUFW_IN -j DROP" to ("DROP" to "Other incoming packets"),
    "-A POCKETUFW_VPN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" to ("ALLOW" to "Established / related replies"),
    "-A POCKETUFW_VPN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT" to ("ALLOW" to "Established / related replies"),
    "-A POCKETUFW_VPN -m conntrack --ctstate INVALID -j DROP" to ("DROP" to "Invalid packets"),
    "-A POCKETUFW_VPN -j DROP" to ("DROP" to "Other incoming packets"),
)
private val UDP_EXCEPTION = Regex("-A POCKETUFW_TS -p udp --dport ([1-9][0-9]{0,4}) -j ACCEPT")
private val PINNED4 = Regex("-A POCKETUFW_VPN -s 100\\.64\\.0\\.0/10 -d (100\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}(?:/32)?) -i tun\\+ -j ACCEPT")
private val PINNED6 = Regex("-A POCKETUFW_VPN -s fd7a:115c:a1e0::/48 -d (fd7a:115c:a1e0:[0-9a-f:]+(?:/128)?) -i tun\\+ -j ACCEPT")

internal fun describeRule(rule: String): Pair<String, String> {
    val form = rule.replace(" -p udp -m udp ", " -p udp ")
    KNOWN_RULES[form]?.let { return it }
    UDP_EXCEPTION.matchEntire(form)?.let {
        return "ALLOW" to ("VPN UDP exception, port " + it.groupValues[1])
    }
    PINNED4.matchEntire(form)?.groupValues?.get(1)?.let { pin ->
        val octets = pin.substringBefore('/').split('.').map { it.toInt() }
        if (octets[1] in 64..127 && octets.all { it in 0..255 })
            return "ALLOW" to "Pinned tailnet destination: $pin"
    }
    PINNED6.matchEntire(form)?.groupValues?.get(1)?.let { pin ->
        return "ALLOW" to "Pinned tailnet destination: $pin"
    }
    // iptables lists matches, comments included, before the target.
    return when (val target = rule.substringAfterLast(" -j ", "").substringBefore(' ')) {
        "" -> "RULE" to rule
        "ACCEPT" -> "ALLOW" to rule
        "NFLOG" -> "LOG" to "Temporary diagnostic probe (non-verdict)"
        else -> target to rule
    }
}
