package io.github.pocketufw

import io.github.pocketufw.FirewallClient.*

internal enum class TideProtectionHealth { HEALTHY, ATTENTION, INACTIVE, CHECKING }

/** Operational health only. Coverage boundaries never change the enforcement verdict. */
internal data class TideProtectionStatus(
    val health: TideProtectionHealth,
    val label: String,
    val description: String,
    val reviewTunnel: Boolean = false
) {
    val title: String get() = when (health) {
        TideProtectionHealth.HEALTHY -> "Active."
        TideProtectionHealth.ATTENTION -> "Needs attention."
        TideProtectionHealth.INACTIVE -> "Inactive."
        TideProtectionHealth.CHECKING -> "Checking…"
    }
}

internal fun protectionStatus(ui: TideUiState): TideProtectionStatus {
    val state = ui.snapshot
    fun attention(problem: String, description: String, reviewTunnel: Boolean = false) =
        TideProtectionStatus(TideProtectionHealth.ATTENTION,
            "PROTECTION NEEDS ATTENTION · $problem", description, reviewTunnel)
    if (ui.verificationInDoubt) return attention("RECHECK REQUIRED",
        "A later read failed or the Quick Settings tile changed. " +
            "Last known status is not proof of current protection. Recheck the kernel.")
    if (state.protection == Protection.CHECKING) return TideProtectionStatus(TideProtectionHealth.CHECKING,
        "READING KERNEL STATE", "Reading firewall rules and Magisk boot status. Protection has not yet been verified.")
    if (state.protection == Protection.ROOT_REQUIRED) return attention("ROOT ACCESS NEEDED",
        state.details.ifBlank { "Grant root access, then recheck status to verify protection." })
    if (!state.rootReady) return attention("RECHECK REQUIRED", state.details.takeUnless {
        it == "IPv4 and IPv6 rules and hooks verified."
    }?.takeIf { it.isNotBlank() } ?: "Protection could not be verified. Recheck status before relying on it.")
    if (state.tunnelFilter == TunnelFilter.DEGRADED) return attention("TUNNEL RULES DEGRADED",
        degradedProtectionDescription(state))
    if (state.protection == Protection.DEGRADED || state.physicalFilter == PhysicalFilter.DEGRADED) {
        val problem = if (state.physicalFilter == PhysicalFilter.ACTIVE && state.tunnelFilter == TunnelFilter.UNKNOWN)
            "TUNNEL STATUS UNKNOWN" else "RULES NOT VERIFIED"
        return attention(problem, degradedProtectionDescription(state))
    }
    if (state.tunnelFilter == TunnelFilter.ON && state.tunnelMode !in setOf(TunnelMode.PINNED, TunnelMode.DENY_ONLY))
        return attention("TUNNEL MODE UNKNOWN", "Tunnel rules are installed, but their mode is not verified. Recheck status and inspect kernel rules.")
    if (state.tunnelMode == TunnelMode.PINNED && state.tunnelFilter != TunnelFilter.OFF) {
        if (state.tailnetConnectivity == TailnetConnectivity.REAUTHORIZE)
            return attention("REAUTHORIZE TAILSCALE", "Installed filtering remains in place, but Tailscale addresses changed. " +
                "In Settings, turn tunnel protection off, then enable PINNED to verify and authorize the new addresses.", reviewTunnel = true)
        if (state.tailnetConnectivity != TailnetConnectivity.MATCH)
            return attention("TAILNET STATUS UNVERIFIED", "Existing pinned destinations were kept. Recheck status before relying on tailnet access.")
    }
    if (state.tunnelFilter == TunnelFilter.UNKNOWN && state.tunnelMode in setOf(TunnelMode.PINNED, TunnelMode.DENY_ONLY))
        return attention("TUNNEL STATUS UNKNOWN", degradedProtectionDescription(state))
    restoreFailureNotice(state, false)?.let { return attention("RESTORATION NOT RUNNING", it) }
    if (state.protection == Protection.INACTIVE) return TideProtectionStatus(TideProtectionHealth.INACTIVE,
        "PROTECTION INACTIVE", "PocketUFW rules are not installed. Android’s own firewall remains unchanged.")
    return TideProtectionStatus(TideProtectionHealth.HEALTHY, "PROTECTION ACTIVE · RULES VERIFIED",
        "Your firewall is active with verified rules. See Coverage details for protection limits.")
}

internal fun degradedProtectionDescription(state: FirewallClient.Snapshot): String {
    val scope = if (state.rootReady && state.physicalFilter == FirewallClient.PhysicalFilter.ACTIVE) {
        when (state.tunnelFilter) {
            FirewallClient.TunnelFilter.DEGRADED -> "Physical firewall rules are verified, but tunnel protection is degraded."
            FirewallClient.TunnelFilter.UNKNOWN -> "Physical firewall rules are verified, but tunnel protection is not verified."
            else -> "Physical firewall rules are verified, but overall protection is not verified."
        }
    } else ""
    // Generic whole-firewall summaries must not contradict the independently verified scope.
    // Specific diagnostics (timeouts, conflicts, etc.) retain their recovery instructions.
    val detail = state.details.takeUnless { it == "IPv4 and IPv6 rules and hooks verified." ||
        (scope.isNotEmpty() && it == "Firewall state could not be verified. Some rules may be installed. Don't assume " +
            "packets are being filtered, or that they aren't.") }
        ?.takeIf { it.isNotBlank() }
        ?: (if (scope.isEmpty()) "Protection is not verified. " else "") +
            if (scope.isNotEmpty() && state.tunnelFilter in setOf(FirewallClient.TunnelFilter.DEGRADED, FirewallClient.TunnelFilter.UNKNOWN))
                "Recheck status and inspect kernel rules before relying on tunnel protection."
            else "Recheck status and inspect kernel rules before relying on protection."
    return listOf(scope, detail).filter { it.isNotEmpty() }.joinToString(" ")
}
