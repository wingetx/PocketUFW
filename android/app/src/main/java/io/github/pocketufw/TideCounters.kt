package io.github.pocketufw

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.*
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
internal fun TideCounters(ui: TideUiState, actions: TideActions) {
    var resetConfirmation by rememberSaveable { mutableStateOf(false) }
    val active = ui.snapshot.protection == FirewallClient.Protection.ACTIVE
    val verified = active && !ui.verificationInDoubt
    val verifiedOff = ui.snapshot.protection == FirewallClient.Protection.INACTIVE &&
        ui.snapshot.rootReady && !ui.verificationInDoubt
    val canReset = verified && ui.snapshot.rootReady && !ui.busy
    // A pending dialog must not outlive a verified, actionable state.
    LaunchedEffect(verified, ui.snapshot.rootReady) {
        if (!verified || !ui.snapshot.rootReady) resetConfirmation = false
    }
    val activity = ui.counters
    val large = LocalDensity.current.fontScale > 1.2f ||
        listOf(activity?.totalBlocked, activity?.totalReplies, activity?.ipv4Blocked, activity?.ipv6Blocked,
            activity?.tunnel?.let { counterSum(it.ipv4Blocked, it.ipv6Blocked) },
            activity?.tunnel?.let { counterSum(it.ipv4Replies, it.ipv6Replies) })
            .any { count(it).length > 8 }
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        if (ui.verificationInDoubt) TideNotice(
            "Last known reading only. Current kernel protection is not verified; recheck before acting.", true)
        if (active && activity?.measured == true) {
            Text("Physical interfaces", style = MaterialTheme.typography.titleMedium)
            CounterTotal("Physical", "Drop-rule matches", activity.totalBlocked,
                counterSum(activity.ipv4Bytes, activity.ipv6Bytes)?.let { byteCount(it) } ?: "Bytes unavailable", large)
            if (!large) CounterHeader()
            CounterFamily("Physical", "IPv4", activity.ipv4Blocked, activity.ipv4Bytes, large)
            CounterFamily("Physical", "IPv6", activity.ipv6Blocked, activity.ipv6Bytes, large)
            TideDivider()
            CounterTotal("Physical", "Return traffic", activity.totalReplies, "Established / related packets", large)
            TidePolicyRow(R.drawable.tide_reply, "IPv4 replies", count(activity.ipv4Replies), TideMono)
            TidePolicyRow(R.drawable.tide_reply, "IPv6 replies", count(activity.ipv6Replies), TideMono)
            TideDivider()
            Text("Tunnel interfaces", style = MaterialTheme.typography.titleMedium)
            val tunnel = activity.tunnel
            if (activity.tunnelFilter == FirewallClient.TunnelFilter.ON && tunnel != null) {
                CounterTotal("Tunnel", "Drop-rule matches", counterSum(tunnel.ipv4Blocked, tunnel.ipv6Blocked),
                    counterSum(tunnel.ipv4Bytes, tunnel.ipv6Bytes)?.let { byteCount(it) } ?: "Bytes unavailable", large)
                if (!large) CounterHeader()
                CounterFamily("Tunnel", "IPv4", tunnel.ipv4Blocked, tunnel.ipv4Bytes, large)
                CounterFamily("Tunnel", "IPv6", tunnel.ipv6Blocked, tunnel.ipv6Bytes, large)
                TideDivider()
                CounterTotal("Tunnel", "Return traffic", counterSum(tunnel.ipv4Replies, tunnel.ipv6Replies),
                    "Established / related packets", large)
                TidePolicyRow(R.drawable.tide_reply, "IPv4 tunnel replies", count(tunnel.ipv4Replies), TideMono)
                TidePolicyRow(R.drawable.tide_reply, "IPv6 tunnel replies", count(tunnel.ipv6Replies), TideMono)
                if (activity.tunnelMode == FirewallClient.TunnelMode.PINNED) {
                    TideDivider()
                    Text("Tailnet exemptions", style = MaterialTheme.typography.titleMedium)
                    TidePolicyRow(R.drawable.tide_check, "IPv4 tailnet matches", count(tunnel.ipv4Tailnet), TideMono)
                    TidePolicyRow(R.drawable.tide_check, "IPv6 tailnet matches", count(tunnel.ipv6Tailnet), TideMono)
                    Text("Tailnet-exempt packets match before the established-reply rule. They are separate from Return traffic.",
                        style = MaterialTheme.typography.bodySmall, color = Muted)
                }
            } else Text(if (activity.tunnelFilter == FirewallClient.TunnelFilter.OFF)
                "Tunnel filtering is off; no current tunnel measurement."
                else "Tunnel counters unavailable.", style = MaterialTheme.typography.bodySmall, color = Muted)
            Text("Last checked: " + readTime(activity.checkedAt), style = MaterialTheme.typography.bodySmall,
                color = Muted)
            if (activity.lastManualResetAt > 0L) Text("Last manual counter reset: " + readTime(activity.lastManualResetAt),
                style = MaterialTheme.typography.bodySmall, color = Muted)
        } else {
            TideNotice(if (verifiedOff) "No counters exist because PocketUFW’s rules aren’t installed."
                else if (!active) "Counters unavailable while protection is not verified."
                else activity?.error ?: "Waiting for the kernel counter read.", error = active && activity?.error != null)
        }
        if (!verifiedOff) {
            val refresh: @Composable (Modifier) -> Unit = { modifier ->
                TidePrimaryButton("Refresh counters", actions.refreshCounters, modifier,
                    enabled = verified && ui.snapshot.rootReady && !ui.busy,
                    loading = ui.counterRefreshing, loadingLabel = "Refreshing…")
            }
            val reset: @Composable (Modifier) -> Unit = { modifier ->
                TideOutlinedButton("Reset counters", { resetConfirmation = true }, enabled = canReset,
                    modifier = modifier.testTag("reset-counters"),
                    loading = ui.working(TideOperation.RESET_COUNTERS), loadingLabel = "Resetting…")
            }
            if (large) Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                refresh(Modifier); reset(Modifier)
            } else Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                refresh(Modifier.weight(1f)); reset(Modifier.weight(1f))
            }
        }
        Text("Rule matches, not attack detections. Counts reset on request or when rules are reinstalled.",
            style = MaterialTheme.typography.bodySmall, color = Muted)
        Text("Last inspection or manual refresh only. Physical and tunnel matches are separate, not unique connections. No continuous monitoring. Earlier Android/OEM rules and other interfaces may bypass PocketUFW’s hooks.",
            style = MaterialTheme.typography.bodySmall, color = Muted)

    }
    if (resetConfirmation) AlertDialog(
        containerColor = Background, tonalElevation = 0.dp,
        onDismissRequest = { resetConfirmation = false },
        title = { Text("Reset counters?") },
        text = { Text("Clear all owned physical and tunnel packet and byte counters for both IPv4 and IPv6? " +
            "This cannot be undone. Firewall rules, VPN exceptions, and boot restoration stay unchanged. " +
            "New packets may increase the counts immediately.") },
        confirmButton = {
            TextButton(onClick = {
                resetConfirmation = false
                actions.resetCounters()
            }, enabled = canReset, modifier = Modifier.testTag("confirm-reset-counters")) { Text("Reset counters") }
        },
        dismissButton = { TextButton(onClick = { resetConfirmation = false }) { Text("Cancel") } }
    )
}

/** The same hierarchy in both planes; accessibility keeps the scope attached to each total. */
@Composable
private fun CounterTotal(scope: String, label: String, total: Long?, detail: String, large: Boolean) {
    val modifier = Modifier.fillMaxWidth().testTag("$scope-$label").clearAndSetSemantics {
        contentDescription = "$scope $label: " +
            (total?.let { "${count(it)} packets" } ?: "unavailable") + ". $detail"
    }
    val description: @Composable () -> Unit = {
        Text(label, style = MaterialTheme.typography.titleMedium)
        Text(detail, style = MaterialTheme.typography.bodySmall, color = Muted)
    }
    if (large) Column(modifier, verticalArrangement = Arrangement.spacedBy(4.dp)) {
        description()
        Text(count(total), fontFamily = TideMono, fontSize = 30.sp, lineHeight = 36.sp)
    } else Row(modifier, verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Column(Modifier.weight(1f)) { description() }
        Text(count(total), fontFamily = TideMono, fontSize = 28.sp, lineHeight = 34.sp)
    }
}

@Composable
private fun CounterHeader() {
    Row(Modifier.fillMaxWidth()) {
        Text("Family", Modifier.weight(1f), style = MaterialTheme.typography.bodySmall, color = Muted)
        Text("Dropped", Modifier.weight(1f), style = MaterialTheme.typography.bodySmall,
            color = Muted, textAlign = TextAlign.End)
        Text("Bytes", Modifier.weight(1f), style = MaterialTheme.typography.bodySmall,
            color = Muted, textAlign = TextAlign.End)
    }
}

@Composable
private fun CounterFamily(scope: String, name: String, packets: Long?, bytes: Long?, large: Boolean) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.clearAndSetSemantics {
        contentDescription = "$scope $name: " +
            (packets?.let { "${count(it)} dropped packets" } ?: "dropped packets unavailable") + ", " +
            (bytes?.let { "${count(it)} bytes" } ?: "bytes unavailable")
    }) {
        TideDivider()
        if (large) {
            Text(name, style = MaterialTheme.typography.titleMedium)
            Text("Dropped: ${count(packets)} packets", style = MaterialTheme.typography.bodyMedium, fontFamily = TideMono)
            Text("Bytes: ${byteCount(bytes)}", style = MaterialTheme.typography.bodyMedium, fontFamily = TideMono)
        } else Row(Modifier.fillMaxWidth()) {
            Text(name, Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
            Text(count(packets), Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium,
                fontFamily = TideMono, textAlign = TextAlign.End)
            Text(byteCount(bytes), Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium,
                fontFamily = TideMono, textAlign = TextAlign.End)
        }
    }
}
