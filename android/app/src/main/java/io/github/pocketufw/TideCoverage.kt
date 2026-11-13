package io.github.pocketufw

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp

internal const val COVERAGE_SUBTITLE = "Protection and known limitations"
internal data class TideCoverageStatus(val incoming: String, val summary: String)

/** Inspection findings, independent of operational health; shown inside the disclosure. */
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
    return TideCoverageStatus(incoming, summary)
}

@Composable
internal fun TideCoverageDetails(ui: TideUiState, showRules: () -> Unit) {
    var expanded by rememberSaveable { mutableStateOf(false) }
    var technical by rememberSaveable { mutableStateOf(false) }
    val state = ui.snapshot
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        TideSettingExpander("Coverage details", COVERAGE_SUBTITLE, expanded) { expanded = !expanded }
        if (expanded) {
            CoverageHeading("What PocketUFW protects")
            CoverageDetail("When enabled, PocketUFW filters unsolicited incoming connections on supported Wi-Fi and mobile-data interfaces. Outgoing traffic is unchanged.")
            CoverageDetail(when (state.tunnelFilter) {
                FirewallClient.TunnelFilter.ON -> "Optional tunnel protection is on for supported VPN connections. It lasts until restart and is never restored after reboot."
                FirewallClient.TunnelFilter.OFF -> "Optional tunnel protection is off. Enable it in Settings to filter incoming connections inside supported VPNs for this session."
                FirewallClient.TunnelFilter.DEGRADED -> "Optional tunnel protection needs repair. Check the recovery steps below."
                FirewallClient.TunnelFilter.UNKNOWN -> "Optional tunnel protection is separate from physical filtering. Its current state needs verification."
            }.let { if (ui.verificationInDoubt || !state.rootReady)
                "Optional tunnel protection is separate from physical filtering. Its current state is not verified." else it })

            CoverageHeading("What Android and VPNs handle separately")
            if (ui.verificationInDoubt || !state.rootReady) CoverageDetail(
                "These interface and rule findings are from the last inspection. Current coverage is not verified.")
            val carrier = state.uncoveredInterfaces.filter { isCarrierIms(it, state) }
            val other = state.uncoveredInterfaces.filterNot { isCarrierIms(it, state) }
            if (carrier.isNotEmpty()) CoverageDetail("Carrier calling networks (${carrier.joinToString(", ")}) are not filtered by PocketUFW. Android manages them separately; this is an expected coverage boundary.")
            if (other.isNotEmpty()) CoverageDetail("Not filtered: ${other.joinToString(", ") { uncoveredLabel(it, state) }}.")
            CoverageDetail(if (bypassRules(ui.report).isNotEmpty())
                "Earlier Android rules were found that can accept traffic before PocketUFW. Those connections can bypass its filtering."
                else "Android's earlier firewall rules can accept traffic before PocketUFW.")
            CoverageDetail("VPN traffic is filtered only where PocketUFW's tunnel rules are installed. An active VPN alone does not mean its traffic is filtered.")

            CoverageHeading("When action is needed")
            val status = protectionStatus(ui)
            val inspectionIncomplete = ui.report == null || !state.interfaceInventoryAvailable ||
                state.tunnelFilter == FirewallClient.TunnelFilter.UNKNOWN
            when (status.health) {
                TideProtectionHealth.ATTENTION -> CoverageDetail(when {
                    status.reviewTunnel -> "Reauthorize Tailscale in Settings: turn tunnel protection off, then enable PINNED."
                    !ui.verificationInDoubt && state.rootReady && state.tunnelFilter == FirewallClient.TunnelFilter.DEGRADED ->
                        "Use Remove tunnel rules only below or in Settings, then enable the tunnel mode you need. This recovery leaves physical rules in place."
                    else -> "Recheck status, then inspect kernel rules if the issue remains. Use the recovery controls for any incomplete rules."
                })
                TideProtectionHealth.CHECKING -> CoverageDetail("Wait for the current check to finish before relying on protection.")
                TideProtectionHealth.INACTIVE -> CoverageDetail("No action is needed if you intended to leave PocketUFW off. Turn the firewall on when you want its filtering.")
                TideProtectionHealth.HEALTHY -> if (!inspectionIncomplete)
                    CoverageDetail("No action is needed for the configured protection. The limitations above remain part of its coverage.")
            }
            if (inspectionIncomplete) CoverageDetail(
                "Coverage inspection is incomplete. Recheck status to inspect current interfaces, tunnel status, and earlier Android rules.")

            TideSettingExpander("Technical details", "Inspection results and rule evidence", technical) { technical = !technical }
            if (technical) {
                CoverageDetail(coverageStatus(ui).summary)
                CoverageDetail("At the last inspection; no continuous monitoring or end-to-end coverage test. Counter refresh does not recheck addresses.")
                if (ui.verificationInDoubt || !state.rootReady) CoverageDetail("The following results are from the last inspection, not proof of current protection.")
                if (!state.interfaceInventoryAvailable) CoverageDetail("Interface coverage unknown. Recheck status to inspect current interfaces.")
                else if (state.uncoveredInterfaces.isEmpty()) CoverageDetail("Interface coverage inspected; no uncovered interfaces reported.")
                CoverageDetail("Physical rules: ${physicalStatus(ui)}. Tunnel rules: ${state.tunnelFilter.name}. Tunnel mode: ${state.tunnelMode.name}.")
                if (ui.report == null) CoverageDetail("Earlier Android/OEM rule coverage unknown. Recheck status to inspect INPUT rules.")
                else {
                    val report = ui.report
                    if (bypassRules(report).isEmpty()) CoverageDetail("No earlier ACCEPT bypass rules reported at the last inspection.")
                    else {
                        CoverageDetail("Earlier ACCEPT evidence:")
                        report.ipv4.bypass.forEach { CoverageDetail("IPv4: $it") }
                        report.ipv6.bypass.forEach { CoverageDetail("IPv6: $it") }
                    }
                }
                if (state.tunnelMode == FirewallClient.TunnelMode.PINNED) {
                    CoverageDetail("Pinned tailnet destinations: ${state.tailnetPin4 ?: "unknown"}, ${state.tailnetPin6 ?: "unknown"}.")
                    CoverageDetail("Last verified Tailscale addresses: ${state.tailnetObserved4 ?: "unknown"}, ${state.tailnetObserved6 ?: "unknown"}. Tailnet connectivity: ${state.tailnetConnectivity.name}.")
                    CoverageDetail("PINNED trusts destination addresses on tun*, not individual packets. Packet sources and interface ownership are not authenticated. Another tun* interface can inject tailnet-source packets into these local destinations; a WireGuard interface named tun* can share the exemption.")
                    if (state.tailnetConnectivity == FirewallClient.TailnetConnectivity.MATCH)
                        CoverageDetail("At the last full inspection, tailnet pins matched verified addresses; reachability has not been tested.")
                }
                if (state.tunnelMode == FirewallClient.TunnelMode.DENY_ONLY) CoverageDetail("Deny-only has no tailnet exemption: unsolicited peer connections remain filtered if Tailscale starts later.")
            }
            // Recovery states already keep this navigation beside their recovery controls.
            if (state.protection != FirewallClient.Protection.DEGRADED &&
                state.tunnelFilter != FirewallClient.TunnelFilter.DEGRADED) TideLink("Inspect kernel rules", showRules)
        }
    }
}

@Composable
private fun CoverageHeading(text: String) {
    Text(text, Modifier.semantics { heading() }, style = MaterialTheme.typography.titleMedium, color = Foreground)
}

@Composable
private fun CoverageDetail(text: String) {
    Text(text, style = MaterialTheme.typography.bodyMedium, color = Muted)
}
