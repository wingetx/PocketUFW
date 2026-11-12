package io.github.pocketufw

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.unit.dp

internal data class TideCoverageStatus(val incoming: String, val summary: String, val notice: String? = null)

/** One coverage notice, independent of installed-rule verification and disclosure expansion. */
internal fun coverageStatus(ui: TideUiState): TideCoverageStatus {
    if (ui.verificationInDoubt || !ui.snapshot.rootReady)
        return TideCoverageStatus("Not verified", "Coverage not verified · last inspection only")
    val uncovered = ui.snapshot.uncoveredInterfaces
    val nonCarrier = uncovered.filterNot { isCarrierIms(it, ui.snapshot) }
    val bypass = bypassRules(ui.report).isNotEmpty()
    val actionableLimit = nonCarrier.isNotEmpty() || bypass
    val unknown = ui.report == null || !ui.snapshot.interfaceInventoryAvailable
    val summary = when {
        unknown && (uncovered.isNotEmpty() || bypass) -> "Known limits · additional coverage unknown"
        unknown -> "Coverage unknown · inspection incomplete"
        uncovered.isNotEmpty() || bypass -> "Coverage inspected · known limitations"
        else -> "Coverage inspected · no gaps reported"
    }
    val incoming = when {
        actionableLimit -> "Coverage limited"
        unknown -> "Coverage unknown"
        uncovered.isNotEmpty() -> "Carrier calling excluded"
        else -> "Filtering active"
    }
    val notice = when {
        actionableLimit -> {
            val reasons = listOfNotNull(
                nonCarrier.takeIf { it.isNotEmpty() }?.let { "not filtered: ${it.joinToString(", ")}" },
                "earlier Android rules can bypass PocketUFW".takeIf { bypass }
            ).joinToString("; ")
            "Coverage limited — $reasons. " + if (unknown)
                "Other coverage is unknown; recheck status." else "Review Coverage details."
        }
        unknown -> "Coverage unknown. Recheck status to inspect interfaces and earlier Android rules."
        else -> null
    }
    return TideCoverageStatus(incoming, summary, notice)
}

internal fun coverageSummary(ui: TideUiState): String = coverageStatus(ui).summary

@Composable
internal fun TideCoverageDetails(ui: TideUiState, showRules: () -> Unit) {
    var expanded by rememberSaveable { mutableStateOf(false) }
    val state = ui.snapshot
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        TideSettingExpander("Coverage details", coverageSummary(ui), expanded) { expanded = !expanded }
        if (expanded) {
            CoverageDetail("At the last inspection; no continuous monitoring or end-to-end coverage test.")
            if (state.uncoveredInterfaces.isNotEmpty()) {
                CoverageDetail("Not filtered: " + state.uncoveredInterfaces.joinToString(", ") { uncoveredLabel(it, state) } + ".")
                if (state.uncoveredInterfaces.any { isCarrierIms(it, state) }) CoverageDetail(CARRIER_IMS_NOTICE)
            } else if (state.interfaceInventoryAvailable) {
                CoverageDetail("Interface coverage inspected; no uncovered interfaces reported.")
            }
            if (!state.interfaceInventoryAvailable)
                CoverageDetail("Interface coverage unknown. Recheck status to inspect current interfaces.")
            if (ui.report == null)
                CoverageDetail("Earlier Android/OEM rule coverage unknown. Recheck status to inspect INPUT rules.")
            else if (bypassRules(ui.report).isNotEmpty()) CoverageDetail(BYPASS_NOTICE)
            else CoverageDetail("No earlier ACCEPT bypass rules reported at the last inspection.")
            CoverageDetail("Physical filtering covers supported interfaces. Tunnel filtering is separate and optional. Earlier Android/OEM rules may accept traffic before PocketUFW’s hooks.")
            when (state.tunnelFilter) {
                FirewallClient.TunnelFilter.ON -> CoverageDetail(when (state.tunnelMode) {
                    FirewallClient.TunnelMode.DENY_ONLY -> "Tunnel rules are on for listed hooks, until restart. Deny-only has no tailnet exemption: unsolicited peer connections remain filtered if Tailscale starts later."
                    FirewallClient.TunnelMode.PINNED -> "Tunnel rules are on for listed hooks, until restart. Only pinned Tailscale destinations are trusted on tun*. Packet sources and interface ownership are not authenticated."
                    else -> "Tunnel rules are on for listed hooks, until restart. Tunnel mode is not verified."
                })
                FirewallClient.TunnelFilter.OFF -> CoverageDetail("Tunnel filtering is off.")
                FirewallClient.TunnelFilter.UNKNOWN -> CoverageDetail("Tunnel coverage is unknown.")
                FirewallClient.TunnelFilter.DEGRADED -> CoverageDetail("Tunnel protection is degraded; use the recovery controls on Firewall or in Settings.")
            }
            if (state.tunnelMode == FirewallClient.TunnelMode.PINNED) {
                CoverageDetail("Pinned tailnet destinations: ${state.tailnetPin4 ?: "unknown"}, ${state.tailnetPin6 ?: "unknown"}.")
                CoverageDetail("Another tun* interface can inject tailnet-source packets into these local destinations; PINNED does not authenticate packet ingress.")
                if (state.tailnetConnectivity == FirewallClient.TailnetConnectivity.MATCH)
                    CoverageDetail("At the last full inspection, tailnet pins matched verified addresses; reachability has not been tested.")
            }
            TideLink("Inspect kernel rules", showRules)
        }
    }
}

@Composable
private fun CoverageDetail(text: String) {
    Text(text, style = MaterialTheme.typography.bodyMedium, color = Muted)
}
