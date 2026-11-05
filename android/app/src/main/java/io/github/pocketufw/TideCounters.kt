package io.github.pocketufw

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
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
    var repliesExpanded by rememberSaveable { mutableStateOf(false) }
    val active = ui.snapshot.protection == FirewallClient.Protection.ACTIVE
    val verified = active && !ui.verificationInDoubt
    val canReset = verified && ui.snapshot.rootReady && !ui.busy
    // A pending dialog must not outlive a verified, actionable state.
    LaunchedEffect(verified, ui.snapshot.rootReady) {
        if (!verified || !ui.snapshot.rootReady) resetConfirmation = false
    }
    val activity = ui.counters
    val large = LocalDensity.current.fontScale > 1.2f ||
        listOf(activity?.totalBlocked, activity?.totalReplies, activity?.ipv4Blocked, activity?.ipv6Blocked)
            .any { count(it).length > 8 }
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        if (ui.verificationInDoubt) TideNotice(
            "Last known reading only. Current kernel protection is not verified; recheck before acting.", true)
        if (active && activity?.measured == true) {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("PACKETS MATCHED DROP RULES", style = MaterialTheme.typography.labelSmall,
                    color = Muted, letterSpacing = 1.sp)
                val bytes = if (activity.ipv4Bytes != null && activity.ipv6Bytes != null)
                    byteCount(activity.ipv4Bytes + activity.ipv6Bytes) else "Bytes unavailable"
                if (large) {
                    Text(count(activity.totalBlocked), color = Mint, fontSize = 48.sp, lineHeight = 54.sp)
                    Text(bytes, style = MaterialTheme.typography.bodySmall, fontFamily = TideMono, color = Muted)
                } else Row(verticalAlignment = Alignment.Bottom) {
                    Text(count(activity.totalBlocked), color = Mint, fontSize = 56.sp,
                        lineHeight = 64.sp, letterSpacing = (-2).sp, modifier = Modifier.weight(1f))
                    Text(bytes, Modifier.padding(bottom = 8.dp), style = MaterialTheme.typography.bodySmall,
                        fontFamily = TideMono, color = Muted)
                }
            }
            if (!large) Row(Modifier.fillMaxWidth()) {
                Text("Family", Modifier.weight(1f), style = MaterialTheme.typography.bodySmall, color = Muted)
                Text("Dropped", Modifier.weight(1f), style = MaterialTheme.typography.bodySmall, color = Muted, textAlign = TextAlign.End)
                Text("Bytes", Modifier.weight(1f), style = MaterialTheme.typography.bodySmall, color = Muted, textAlign = TextAlign.End)
            }
            CounterFamily("IPv4", activity.ipv4Blocked, activity.ipv4Bytes, large)
            CounterFamily("IPv6", activity.ipv6Blocked, activity.ipv6Bytes, large)
            TideDivider()
            if (large) Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text("Return traffic", style = MaterialTheme.typography.titleMedium)
                Text("Established / related packets", style = MaterialTheme.typography.bodySmall, color = Muted)
                Text(count(activity.totalReplies), fontSize = 30.sp, lineHeight = 36.sp)
            } else Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Column(Modifier.weight(1f)) {
                    Text("Return traffic", style = MaterialTheme.typography.titleMedium)
                    Text("Established / related packets", style = MaterialTheme.typography.bodySmall, color = Muted)
                }
                Text(count(activity.totalReplies), fontSize = 28.sp, lineHeight = 34.sp)
            }
            TextButton(onClick = { repliesExpanded = !repliesExpanded }, Modifier.heightIn(min = 48.dp)) {
                Text(if (repliesExpanded) "Hide reply counts by family" else "Reply counts by address family")
            }
            if (repliesExpanded) {
                TidePolicyRow(R.drawable.tide_up, "IPv4 replies", count(activity.ipv4Replies))
                TidePolicyRow(R.drawable.tide_up, "IPv6 replies", count(activity.ipv6Replies))
            }
            Text("Last checked: " + readTime(activity.checkedAt), style = MaterialTheme.typography.bodySmall,
                color = Muted, fontFamily = TideMono)
            if (activity.lastManualResetAt > 0L) Text("Last manual counter reset: " + readTime(activity.lastManualResetAt),
                style = MaterialTheme.typography.bodySmall, color = Muted)
        } else {
            TideNotice(if (!active) "Counters unavailable while protection is not verified."
                else activity?.error ?: "Waiting for the kernel counter read.", error = active && activity?.error != null)
        }
        val refresh: @Composable (Modifier) -> Unit = { modifier ->
            TidePrimaryButton(if (ui.counterRefreshing) "Refreshing…" else "Refresh counters",
                actions.refreshCounters, modifier, enabled = verified && ui.snapshot.rootReady && !ui.busy)
        }
        val reset: @Composable (Modifier) -> Unit = { modifier ->
            OutlinedButton(onClick = { resetConfirmation = true }, enabled = canReset,
                shape = RoundedCornerShape(9.dp), modifier = modifier.fillMaxWidth().heightIn(min = 52.dp)
                    .testTag("reset-counters")) { Text("Reset counters") }
        }
        if (large) Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            refresh(Modifier); reset(Modifier)
        } else Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            refresh(Modifier.weight(1f)); reset(Modifier.weight(1f))
        }
        Text("Rule matches, not attack detections. Counts reset on request or when rules are reinstalled.",
            style = MaterialTheme.typography.bodySmall, color = Muted)
        Text("Updated when opened or refreshed. No continuous monitoring. Earlier Android/OEM rules and other interfaces may bypass PocketUFW’s hooks.",
            style = MaterialTheme.typography.bodySmall, color = Muted)

    }
    if (resetConfirmation) AlertDialog(
        containerColor = Background, tonalElevation = 0.dp,
        onDismissRequest = { resetConfirmation = false },
        title = { Text("Reset counters?") },
        text = { Text("Clear PocketUFW’s packet and byte counters for both IPv4 and IPv6? " +
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

@Composable
private fun CounterFamily(name: String, packets: Long?, bytes: Long?, large: Boolean) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.semantics(mergeDescendants = true) {}) {
        TideDivider()
        if (large) {
            Text(name, style = MaterialTheme.typography.titleMedium)
            Text("Dropped: ${count(packets)} packets", style = MaterialTheme.typography.bodyMedium)
            Text("Bytes: ${byteCount(bytes)}", style = MaterialTheme.typography.bodyMedium)
        } else Row(Modifier.fillMaxWidth()) {
            Text(name, Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
            Text(count(packets), Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium,
                fontFamily = TideMono, textAlign = TextAlign.End)
            Text(byteCount(bytes), Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium,
                fontFamily = TideMono, textAlign = TextAlign.End)
        }
    }
}
