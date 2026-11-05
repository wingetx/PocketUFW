package io.github.pocketufw

import io.github.pocketufw.FirewallClient.BootRestore
import io.github.pocketufw.FirewallClient.Dashboard
import io.github.pocketufw.FirewallClient.KernelReport
import io.github.pocketufw.FirewallClient.Operation
import io.github.pocketufw.FirewallClient.Protection
import io.github.pocketufw.FirewallClient.RuleActivity
import io.github.pocketufw.FirewallClient.RuleFamily
import io.github.pocketufw.FirewallClient.Snapshot
import io.github.pocketufw.FirewallClient.UdpConfigMode

/** Messages copied verbatim from android-bridge, so banner heights are realistic. */
internal object BridgeMessages {
    const val VPN_OK = "Tailscale UDP exceptions already up to date. No changes needed."
    const val VPN_FAILED = "VPN exceptions could not be refreshed; inspect firewall state."
    const val VPN_COMMITTED = "Committed UDP exceptions are active. Use the Status editor to " +
        "change them or return to automatic detection."
    const val RESET_OK = "PocketUFW counters reset. Rules and VPN exceptions are unchanged."
}

internal const val READ_AT = 1_793_880_000_000L

private fun family(fam: Int, port: String?): RuleFamily {
    val hooks = listOf("wlan+", "rmnet+", "v4-rmnet+").map {
        "-A INPUT -i $it -m comment --comment PocketUFW -j POCKETUFW_IN"
    }
    val inbound = if (fam == 4) listOf(
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
    val vpn = listOfNotNull(port?.let { "-A POCKETUFW_TS -p udp -m udp --dport $it -j ACCEPT" })
    return RuleFamily("ACCEPT", hooks, inbound, vpn)
}

internal fun sampleReport(port4: String? = "46867", port6: String? = "43504") =
    KernelReport(family(4, port4), family(6, port6), READ_AT)

internal fun sampleActivity(lastReset: Long = 0L) = RuleActivity(
    ipv4Blocked = 1204, ipv6Blocked = 312,
    ipv4Bytes = 98664, ipv6Bytes = 31820,
    ipv4Replies = 84112, ipv6Replies = 20377,
    checkedAt = READ_AT, lastManualResetAt = lastReset,
)

internal fun activeDashboard(
    boot: BootRestore = BootRestore.ENABLED,
    mode: UdpConfigMode = UdpConfigMode.AUTOMATIC,
    report: KernelReport? = sampleReport(),
    activity: RuleActivity? = sampleActivity(),
    committed4: String = "none",
    committed6: String = "none",
) = Dashboard(
    Snapshot(
        protection = Protection.ACTIVE, rootReady = true, vpnActive = true,
        details = "IPv4 and IPv6 rules, hooks and default inbound policy verified.",
        bootRestore = boot, udpConfigMode = mode,
        committedUdp4 = committed4, committedUdp6 = committed6,
    ),
    activity, report,
)

internal fun stateDashboard(
    protection: Protection,
    rootReady: Boolean,
    details: String,
    boot: BootRestore = BootRestore.UNKNOWN,
    report: KernelReport? = null,
) = Dashboard(Snapshot(protection, rootReady, false, details, boot), null, report)

/** Records every firewall operation the UI asks for. Nothing here touches root. */
internal class FakeGateway(
    @Volatile var dashboard: Dashboard = activeDashboard(),
    @Volatile var vpnMessage: String = BridgeMessages.VPN_OK,
    @Volatile var vpnSuccess: Boolean = true,
    @Volatile var counterRead: RuleActivity = sampleActivity(),
    /** Set to behave like FirewallClient, which publishes every result to the tile cache. */
    private val tileContext: android.content.Context? = null,
) : FirewallGateway {
    val calls = java.util.Collections.synchronizedList(mutableListOf<String>())
    fun count(name: String) = synchronized(calls) { calls.count { it == name } }

    private fun publish(d: Dashboard) = d.also { dash ->
        tileContext?.let { TileStatusStore.publish(it, dash.snapshot) }
    }

    override fun inspectDashboard(): Dashboard { calls += "inspect"; return publish(dashboard) }
    override fun refreshCounterActivity(): RuleActivity { calls += "counters"; return counterRead }
    override fun changeProtection(activate: Boolean): Operation {
        calls += if (activate) "enable" else "disable"
        return Operation(true, "done", dashboard)
    }
    override fun changeBootRestoration(enabled: Boolean): Operation {
        calls += if (enabled) "boot-enable" else "boot-disable"
        return Operation(true, "done", dashboard)
    }
    override fun refreshVerifiedPorts(): Operation {
        calls += "vpn-refresh"
        return Operation(vpnSuccess, vpnMessage, publish(dashboard))
    }
    override fun resetCounters(): Operation {
        calls += "reset-counters"
        return Operation(true, BridgeMessages.RESET_OK, dashboard)
    }
    override fun updateUdpExceptions(ipv4: String, ipv6: String, committed: Boolean): Operation {
        calls += "set-ports:$ipv4:$ipv6:$committed"
        return Operation(true, "done", dashboard)
    }
    override fun restoreAutomaticUdpExceptions(): Operation {
        calls += "use-auto"
        return Operation(true, "done", dashboard)
    }
}
