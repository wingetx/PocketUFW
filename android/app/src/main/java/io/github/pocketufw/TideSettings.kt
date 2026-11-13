package io.github.pocketufw

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.*
import androidx.compose.ui.unit.dp

@Composable
internal fun TideSettings(ui: TideUiState, actions: TideActions, appVersion: String, onExceptions: () -> Unit) {
    val state = ui.snapshot
    val active = state.protection == FirewallClient.Protection.ACTIVE &&
        state.rootReady && !ui.verificationInDoubt
    val bootProgress = when {
        ui.working(TideOperation.ENABLE_BOOT) -> "Enabling…"
        ui.working(TideOperation.DISABLE_BOOT) -> "Disabling…"
        else -> null
    }
    TideHeading("Settings.")
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("STARTUP", color = Muted, style = MaterialTheme.typography.labelSmall)
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Restore after reboot", Modifier.weight(1f), style = MaterialTheme.typography.titleMedium)
            if (bootProblemText(state.bootRestore) == null) {
                Switch(checked = state.bootRestore == FirewallClient.BootRestore.ENABLED,
                    onCheckedChange = { next -> if (!ui.busy && active) actions.changeBootRestoration(next) },
                    enabled = active && !ui.busy,
                    modifier = Modifier.semantics {
                        contentDescription = "Restore after reboot"
                        if (bootProgress != null) {
                            stateDescription = bootProgress
                            progressBarRangeInfo = ProgressBarRangeInfo.Indeterminate
                            liveRegion = LiveRegionMode.Polite
                        }
                    })
            }
        }
        Text("Uses Magisk at startup. No background app. Restores physical filtering only; tunnel filtering never restores.",
            style = MaterialTheme.typography.bodySmall, color = Muted)
        if (bootProgress != null) Row(verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            TideProgressIndicator()
            Text(bootProgress, style = MaterialTheme.typography.bodySmall, color = Mint)
        }
        restoreFailureNotice(state, ui.verificationInDoubt)?.let { TideNotice(it, true) }
        if (!active) Text(if (ui.verificationInDoubt || !state.rootReady)
            "Recheck status before changing boot restoration." else "Enable the firewall to change boot restoration.",
            color = Muted, style = MaterialTheme.typography.bodySmall)
        bootProblemText(state.bootRestore)?.let { TideNotice(it, true) }

        TideDivider()
    }
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("CONNECTIONS", color = Muted, style = MaterialTheme.typography.labelSmall)
        TideSettingLink("VPN UDP exceptions", when (state.udpConfigMode) {
            FirewallClient.UdpConfigMode.AUTOMATIC -> "Saved mode: Automatic · live ports may differ"
            FirewallClient.UdpConfigMode.COMMITTED -> "Committed · saved ports"
            FirewallClient.UdpConfigMode.DEGRADED -> "Saved configuration needs inspection"
            FirewallClient.UdpConfigMode.UNKNOWN -> "Saved configuration not verified"
        }, onExceptions)
        TidePolicyRow(R.drawable.tide_up, "VPN connection",
            if (state.vpnActive) state.vpnProvider ?: "Unrecognized VPN" else "Not detected")
        TideTunnelSettings(ui, actions)
    }
    TideRemoveSection(ui, actions)
    Text("Kernel protection continues when the app closes.\nLocal-only · No accounts or telemetry",
        style = MaterialTheme.typography.bodySmall, color = Muted)
    TideDivider()
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("PocketUFW · Experimental Beta", Modifier.semantics { heading() },
            style = MaterialTheme.typography.labelMedium, color = Muted)
        Text("Some features may be incomplete or behave unexpectedly. Please review known limitations before relying on protection.",
            style = MaterialTheme.typography.bodySmall, color = Muted)
        Text("Version $appVersion", style = MaterialTheme.typography.bodySmall, color = Muted)
    }
}
