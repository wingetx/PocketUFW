package io.github.pocketufw

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp

internal fun physicalStatus(ui: TideUiState): String = when {
    ui.verificationInDoubt || !ui.snapshot.rootReady -> "Not verified"
    ui.snapshot.physicalFilter == FirewallClient.PhysicalFilter.ACTIVE -> "Rules verified"
    ui.snapshot.physicalFilter == FirewallClient.PhysicalFilter.INACTIVE -> "Off"
    ui.snapshot.physicalFilter == FirewallClient.PhysicalFilter.DEGRADED -> "Degraded"
    else -> "Not verified"
}

internal fun canEnableTunnel(ui: TideUiState): Boolean = !ui.busy && !ui.verificationInDoubt &&
    ui.snapshot.rootReady && ui.snapshot.protection == FirewallClient.Protection.ACTIVE &&
    ui.snapshot.tunnelFilter == FirewallClient.TunnelFilter.OFF

internal fun canRemoveTunnel(ui: TideUiState): Boolean = !ui.busy && !ui.verificationInDoubt &&
    ui.snapshot.rootReady && ui.snapshot.tunnelFilter in setOf(
        FirewallClient.TunnelFilter.ON, FirewallClient.TunnelFilter.DEGRADED)

@Composable
internal fun TideTunnelSettings(ui: TideUiState, actions: TideActions) {
    val state = ui.snapshot
    var expanded by rememberSaveable { mutableStateOf(false) }
    var requested by rememberSaveable { mutableStateOf<FirewallClient.TunnelMode?>(null) }
    var remove by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(state, ui.busy, ui.verificationInDoubt) {
        if (!canEnableTunnel(ui)) requested = null
        if (!canRemoveTunnel(ui)) remove = false
    }
    val status = when {
        ui.verificationInDoubt || !state.rootReady -> "Not verified"
        state.tunnelFilter == FirewallClient.TunnelFilter.ON -> when (state.tunnelMode) {
            FirewallClient.TunnelMode.PINNED -> "On · PINNED · until restart"
            FirewallClient.TunnelMode.DENY_ONLY -> "On · DENY-ONLY · until restart"
            else -> "Mode not verified"
        }
        state.tunnelFilter == FirewallClient.TunnelFilter.OFF -> "Off · optional"
        state.tunnelFilter == FirewallClient.TunnelFilter.DEGRADED -> "DEGRADED · recovery available"
        else -> "Not verified"
    }
    TidePolicyRow(R.drawable.tide_down, "Physical protection", physicalStatus(ui))
    TideSettingExpander("Tunnel protection", status, expanded) { expanded = !expanded }
    if (expanded) Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Filters unsolicited incoming traffic at tunnel hooks. Off by default; never restored after reboot. Outgoing traffic is unchanged.",
            style = MaterialTheme.typography.bodySmall, color = Muted)
        if (state.tunnelMode == FirewallClient.TunnelMode.PINNED && state.rootReady && !ui.verificationInDoubt) {
            Text("Pinned destinations: ${state.tailnetPin4 ?: "unknown"}, ${state.tailnetPin6 ?: "unknown"}",
                style = MaterialTheme.typography.bodySmall, color = Muted)
            val connectivity = when (state.tailnetConnectivity) {
                FirewallClient.TailnetConnectivity.MATCH -> "Pins match verified Tailscale addresses. Reachability has not been tested."
                FirewallClient.TailnetConnectivity.REAUTHORIZE ->
                    "REAUTHORIZE: verified addresses are ${state.tailnetObserved4 ?: "unknown"}, ${state.tailnetObserved6 ?: "unknown"}. Turn tunnel protection off, then enable PINNED to authorize them. Existing rules remain installed."
                else -> "Tailnet connectivity UNVERIFIED. Existing pins remain installed; no new addresses are authorized."
            }
            TideNotice(connectivity, state.tailnetConnectivity != FirewallClient.TailnetConnectivity.MATCH)
            Text("Tailnet status is from the last full inspection. Counter refresh does not recheck addresses.",
                style = MaterialTheme.typography.bodySmall, color = Muted)
            Text("Pins are address trust, not packet authentication. Another tun* interface can inject tailnet-source packets into a local pinned destination. A WireGuard interface named tun* can share this exemption.",
                style = MaterialTheme.typography.bodySmall, color = Muted)
        }
        if (state.tunnelMode == FirewallClient.TunnelMode.DENY_ONLY) Text(
            "DENY-ONLY has no tailnet exemption. Incoming Tailscale peer connections remain filtered if Tailscale starts later.",
            style = MaterialTheme.typography.bodySmall, color = Muted)
        when (state.tunnelFilter) {
            FirewallClient.TunnelFilter.OFF -> {
                Text("PINNED verifies Tailscale ownership before authorizing this phone’s /32 and /128. DENY-ONLY is for Proton-only or WireGuard-only use; it grants no tailnet trust.",
                    style = MaterialTheme.typography.bodySmall, color = Muted)
                TidePrimaryButton("Enable PINNED", { requested = FirewallClient.TunnelMode.PINNED },
                    enabled = canEnableTunnel(ui), loading = ui.working(TideOperation.ENABLE_PINNED),
                    loadingLabel = "Activating…")
                TideOutlinedButton("Enable DENY-ONLY", { requested = FirewallClient.TunnelMode.DENY_ONLY },
                    enabled = canEnableTunnel(ui), loading = ui.working(TideOperation.ENABLE_DENY_ONLY),
                    loadingLabel = "Activating…")
                if (state.protection != FirewallClient.Protection.ACTIVE) Text(
                    "Enable and verify the physical firewall first.", style = MaterialTheme.typography.bodySmall, color = Muted)
            }
            FirewallClient.TunnelFilter.ON, FirewallClient.TunnelFilter.DEGRADED -> {
                if (state.tunnelFilter == FirewallClient.TunnelFilter.DEGRADED) TideNotice(
                    "Tunnel rules are incomplete or their trust is unsafe. Remove only tunnel rules to recover; the physical firewall stays installed.", true)
                else Text("To change modes or authorize new addresses, turn tunnel protection off first. Tunnel filtering stops until you enable it again.",
                    style = MaterialTheme.typography.bodySmall, color = Muted)
                TideOutlinedButton(if (state.tunnelFilter == FirewallClient.TunnelFilter.DEGRADED)
                    "Remove tunnel rules only" else "Turn tunnel protection off", { remove = true },
                    enabled = canRemoveTunnel(ui), loading = ui.working(TideOperation.REMOVE_TUNNEL),
                    loadingLabel = "Removing…")
                if (state.tunnelFilter == FirewallClient.TunnelFilter.ON) {
                    TextButton(onClick = actions.refreshTunnelHooks, contentPadding = PaddingValues(vertical = 8.dp),
                        shape = RectangleShape,
                        enabled = !ui.busy && !ui.verificationInDoubt &&
                        state.rootReady && state.protection == FirewallClient.Protection.ACTIVE) {
                        TideActionContent("Refresh tunnel hooks", ui.working(TideOperation.REFRESH_TUNNEL), "Refreshing…")
                    }
                    Text("For added or removed WireGuard interfaces. Does not change pinned addresses. Earlier Android/OEM ACCEPT rules may bypass tunnel hooks.",
                        style = MaterialTheme.typography.bodySmall, color = Muted)
                }
            }
            FirewallClient.TunnelFilter.UNKNOWN -> Text("Recheck status before changing tunnel protection.",
                style = MaterialTheme.typography.bodySmall, color = Muted)
        }
    }
    requested?.let { mode ->
        AlertDialog(containerColor = Background, tonalElevation = 0.dp,
            onDismissRequest = { requested = null }, title = { Text("Enable ${mode.name.replace('_', '-')}?") },
            text = { Column(Modifier.verticalScroll(rememberScrollState())) {
                Text(if (mode == FirewallClient.TunnelMode.PINNED)
                    "Tailscale must be running with verified ownership and both node addresses. Failed verification enables nothing; no fallback is used. Pins allow automatic reconnection with the same addresses. Another tun* interface can inject tailnet-source packets into these local destinations; this does not authenticate packet ingress."
                else "No Tailscale traffic is exempted. Unsolicited incoming Tailscale peer connections will be filtered, including when Tailscale connects later. Use this for Proton-only or WireGuard-only configurations.")
                Text("Tunnel filtering lasts until turned off or restarted. Physical filtering and boot restoration are unchanged.")
            } },
            confirmButton = { TextButton(onClick = {
                requested = null
                if (canEnableTunnel(ui)) actions.enableTunnelProtection(mode)
            }, enabled = canEnableTunnel(ui), modifier = Modifier.testTag("confirm-enable-tunnel")) { Text("Enable") } },
            dismissButton = { TextButton(onClick = { requested = null }) { Text("Cancel") } })
    }
    if (remove) AlertDialog(containerColor = Background, tonalElevation = 0.dp,
        onDismissRequest = { remove = false }, title = { Text("Remove tunnel rules only?") },
        text = { Text("Tunnel filtering stops. The physical firewall and boot restoration stay in place. Enabling PINNED again requires fresh Tailscale ownership verification.") },
        confirmButton = { TextButton(onClick = {
            remove = false
            if (canRemoveTunnel(ui)) actions.removeTunnelRules()
        }, enabled = canRemoveTunnel(ui), modifier = Modifier.testTag("confirm-remove-tunnel")) { Text("Remove tunnel rules") } },
        dismissButton = { TextButton(onClick = { remove = false }) { Text("Cancel") } })
}
