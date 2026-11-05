package io.github.pocketufw

import java.util.Collections

/** The `-S` lines rules-report emits for one family, as FakeGateway's report renders them. */
private fun reportLines(fam: Int, port: String?): List<String> {
    val hooks = listOf("wlan+", "rmnet+", "v4-rmnet+").mapIndexed { i, iface ->
        "hook${fam}_%02d=-A INPUT -i $iface -m comment --comment PocketUFW -j POCKETUFW_IN".format(i + 1)
    }
    val rules = if (fam == 4) listOf(
        "-A POCKETUFW_IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
        "-A POCKETUFW_IN -p icmp -j ACCEPT",
        "-A POCKETUFW_IN -m conntrack --ctstate INVALID -j DROP",
        "-A POCKETUFW_IN -p udp -m udp --sport 67 --dport 68 -j ACCEPT",
        "-A POCKETUFW_IN -d 224.0.0.251/32 -p udp -m udp --dport 5353 -j ACCEPT",
        "-A POCKETUFW_IN -p esp -j ACCEPT",
        "-A POCKETUFW_IN -j POCKETUFW_TS",
        "-A POCKETUFW_IN -j DROP",
    ) else listOf(
        "-A POCKETUFW_IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
        "-A POCKETUFW_IN -p ipv6-icmp -j ACCEPT",
        "-A POCKETUFW_IN -m conntrack --ctstate INVALID -j DROP",
        "-A POCKETUFW_IN -p udp -m udp --sport 547 --dport 546 -j ACCEPT",
        "-A POCKETUFW_IN -d ff02::fb/128 -p udp -m udp --dport 5353 -j ACCEPT",
        "-A POCKETUFW_IN -p esp -j ACCEPT",
        "-A POCKETUFW_IN -j POCKETUFW_TS",
        "-A POCKETUFW_IN -j DROP",
    )
    val main = rules.mapIndexed { i, rule -> "main${fam}_%02d=$rule".format(i + 1) }
    val vpn = listOfNotNull(port?.let { "vpn${fam}_01=-A POCKETUFW_TS -p udp -m udp --dport $it -j ACCEPT" })
    return listOf("input_policy$fam=ACCEPT") + hooks + main + vpn
}

/** Distinct per key, so that swapping any two counters changes an assertion. */
internal val SAMPLE_COUNTERS = listOf(
    "ipv4_blocked=11", "ipv6_blocked=22",
    "ipv4_blocked_bytes=33", "ipv6_blocked_bytes=44",
    "ipv4_established_replies=55", "ipv6_established_replies=66",
)

/**
 * What android-bridge prints, in its order. Sections appear only for the states
 * that print them: counters for ACTIVE, the rule report for ACTIVE and DEGRADED.
 */
internal fun bridgeOutput(
    state: String? = "ACTIVE",
    boot: String? = "ENABLED",
    mode: String? = "AUTOMATIC",
    operation: String = "NONE",
    message: String = "",
    previousBoot: String = "UNKNOWN",
    vpnOwner: String = "",
    committed4: String = "none",
    committed6: String = "none",
    uncovered: String? = "",
    counters: List<String> = SAMPLE_COUNTERS,
    bypass4: List<String> = emptyList(),
    bypass6: List<String> = emptyList(),
    port4: String? = "46867",
    port6: String? = "43504",
    reportStatus: String = "READY",
): String = buildList {
    add("root=GRANTED")
    add("vpn_owner=$vpnOwner")
    if (mode != null) add("config_mode=$mode")
    add("committed_udp4=$committed4")
    add("committed_udp6=$committed6")
    add("previous_boot=$previousBoot")
    add("operation=$operation")
    add("message=$message")
    if (state != null) add("state=$state")
    if (boot != null) add("boot=$boot")
    if (uncovered != null) add("uncovered_ifaces=$uncovered")
    if (state == "ACTIVE") addAll(counters)
    if (state == "ACTIVE" || state == "DEGRADED") {
        addAll(reportLines(4, port4))
        addAll(reportLines(6, port6))
        bypass4.forEachIndexed { i, rule -> add("input_bypass4_%02d=$rule".format(i + 1)) }
        bypass6.forEachIndexed { i, rule -> add("input_bypass6_%02d=$rule".format(i + 1)) }
        add("rules_report=$reportStatus")
    }
}.joinToString("\n")

/** Stands in for `su`. Records bridge actions like "toggle ACTIVE"; never starts a process. */
internal class FakeShell(
    @Volatile var respond: (String) -> ShellResult = { ShellResult(0, bridgeOutput()) },
) : RootShell {
    val actions: MutableList<String> = Collections.synchronizedList(mutableListOf())

    override fun run(command: String, maxSeconds: Long): ShellResult {
        val action = command.substringAfter("android-bridge' ").replace("'", "")
        actions += action
        return respond(action)
    }
}
