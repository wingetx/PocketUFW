package io.github.pocketufw

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import java.util.Locale

@Composable
internal fun TideInsights(ui: TideUiState, actions: TideActions) {
    // Only a kernel report containing APP1 residue promotes recovery. A failed or
    // interrupted sample alone is not proof that logging probes remain.
    val residue = hasInsightsResidue(ui.report)
    var troubleshootingOpen by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(residue, ui.insights?.recovered) {
        if (residue || ui.insights?.recovered == true) troubleshootingOpen = false
    }
    BackHandler(troubleshootingOpen && !residue) { troubleshootingOpen = false }
    TideHeading("Insights.", "Understand what reaches your DROP rules.")
    if (residue) InsightRecovery(ui, actions, residue = true)
    InsightPanel {
        InsightLabel("ON-DEMAND SAMPLE")
        Text("What’s being dropped now?", style = MaterialTheme.typography.titleLarge)
        InsightDetail("Sample for up to 10 seconds or 256 records. Setup and verified cleanup add time. Metadata stays in memory on this device; leaving the app stops the sample.")
        Text("A short sample cannot explain the entire historical DROP count.", fontWeight = FontWeight.SemiBold,
            style = MaterialTheme.typography.bodyMedium)
        val sampling = ui.working(TideOperation.SAMPLE)
        TidePrimaryButton("Sample dropped traffic", actions.sampleDrops, modifier = Modifier.testTag("sample-drops"),
            enabled = !ui.busy && !ui.verificationInDoubt && ui.snapshot.rootReady && ui.snapshot.protection == FirewallClient.Protection.ACTIVE,
            loading = sampling, loadingLabel = if (ui.insightsStopping) "Cleaning up…" else "Sampling & verifying…")
        if (sampling) TideOutlinedButton("Stop sample", actions.cancelSample,
            enabled = !ui.insightsStopping, modifier = Modifier.testTag("stop-sample"))
        if (!sampling && (ui.verificationInDoubt || ui.snapshot.protection != FirewallClient.Protection.ACTIVE))
            InsightDetail(if (residue) "Recover the detected Insights probes, then recheck protection before sampling."
                else "Sampling requires verified ACTIVE protection. Recheck status, or open “Sample interrupted?” to check for leftover rules.")
    }
    ui.insights?.error?.let { TideNotice(it, error = true) }
    // Recovery also succeeds when nothing was left behind, so state what was verified, not what was removed.
    if (ui.insights?.recovered == true) TideNotice("Recovery verified: no Insights probes remain. Firewall independently verified ACTIVE.")
    ui.insights?.sample?.let { sample ->
        InsightPanel {
            InsightLabel("OBSERVED SAMPLE")
            Text("${sample.packets.size} DROP " + if (sample.packets.size == 1) "match" else "matches", style = MaterialTheme.typography.headlineMedium, fontFamily = TideMono)
            InsightDetail("${String.format(Locale.getDefault(), "%.1f", sample.elapsedMs / 1000.0)} seconds · ${readTime(sample.checkedAt)}")
            InsightDetail(if (sample.hitLimit) "Record limit reached; this sample ended early." else "Time limit reached.")
            for (scope in if (sample.tunnelSampled) listOf("Physical", "Tunnel") else listOf("Physical")) for (family in listOf(4, 6))
                InsightCount("$scope · IPv$family", sample.packets.count { it.scope == scope && it.family == family }.toLong())
            if (!sample.tunnelSampled) InsightDetail("Tunnel filtering was off; tunnel traffic was not sampled.")
            val invalid = sample.packets.count { it.reason == "Invalid state" }
            InsightDetail("$invalid invalid-state matches · ${sample.packets.size - invalid} final-DROP matches. Invalid state is a conntrack classification, not an attack verdict.")
            if (sample.packets.isEmpty()) TideNotice("No readable DROP matches in this window. This does not prove there was no blocked traffic earlier.")
            if (sample.loss || sample.unreadable > 0 || sample.unrelated > 0)
                TideNotice("Coverage limited: ${sample.unreadable} unreadable and ${sample.unrelated} unrelated records excluded." +
                    if (sample.loss) " The collector also detected possible record loss." else "")
            InsightDetail("Collection can miss packets. Probes start one at a time during setup, so scope windows may differ slightly. No percentage of historical traffic is inferred. All probes removed; original rules and ACTIVE status verified.")
        }
        if (sample.packets.isNotEmpty()) {
            InsightPanel {
                Text("Traffic clues", style = MaterialTheme.typography.titleLarge)
                InsightDetail("Observed ports → possible purpose")
                sample.packets.groupingBy { it.category }.eachCount().entries.sortedByDescending { it.value }.forEach { (category, total) ->
                    TideDivider()
                    InsightCount(category.label, total.toLong())
                    InsightLabel("Observed: ${category.observation}")
                    Text(category.explanation, style = MaterialTheme.typography.bodyMedium, color = Muted)
                }
                InsightDetail("These clues do not identify a particular app, router manufacturer or malicious intent.")
            }
            InsightPanel {
                Text("Protocols observed", style = MaterialTheme.typography.titleLarge)
                sample.packets.groupingBy { it.protocolLabel }.eachCount().entries.sortedByDescending { it.value }
                    .forEach { InsightCount(it.key, it.value.toLong()) }
                TideDivider()
                Text("Most frequent sources", style = MaterialTheme.typography.titleLarge)
                InsightDetail("Numeric addresses · no DNS lookups")
                sample.sources.take(10).forEach { (key, total) ->
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(key.first, fontFamily = TideMono, style = MaterialTheme.typography.bodyMedium)
                        InsightDetail("${key.second} · $total sampled matches")
                    }
                }
                if (sample.sources.size > 10) InsightDetail("${sample.sources.size - 10} more source / protocol groups omitted from this list.")
            }
        }
        TideOutlinedButton("Clear sample", actions.clearInsights, enabled = !ui.busy)
    }
    if (!residue) {
        TideSettingExpander("Sample interrupted?", "Check for leftover temporary rules", troubleshootingOpen) {
            troubleshootingOpen = !troubleshootingOpen
        }
        if (troubleshootingOpen) InsightRecovery(ui, actions, residue = false)
    }
}

@Composable private fun InsightRecovery(ui: TideUiState, actions: TideActions, residue: Boolean) {
    InsightPanel {
        Text(if (residue) "Insights cleanup needed" else "Insights recovery", style = MaterialTheme.typography.titleMedium)
        if (residue) TideNotice("Leftover Insights probes detected. Recover them before sampling again.", error = true)
        InsightDetail("If a traffic sample was interrupted, PocketUFW can check for temporary monitoring rules and safely remove any it recognizes.")
        TideOutlinedButton("Check sample cleanup", actions.recoverInsights, modifier = Modifier.testTag("recover-insights"),
            enabled = !ui.busy && ui.snapshot.rootReady, loading = ui.working(TideOperation.RECOVER_INSIGHTS), loadingLabel = "Verifying cleanup…")
    }
}

@Composable private fun InsightPanel(content: @Composable ColumnScope.() -> Unit) {
    Column(Modifier.fillMaxWidth().background(Panel, RoundedCornerShape(16.dp)).padding(18.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp), content = content)
}
@Composable private fun InsightLabel(text: String) {
    Text(text, color = Mint, style = MaterialTheme.typography.labelMedium, fontFamily = TideMono)
}
@Composable private fun InsightDetail(text: String) {
    Text(text, color = Muted, style = MaterialTheme.typography.bodySmall)
}
@Composable private fun InsightCount(label: String, number: Long?) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(label, Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
        Text(count(number), fontFamily = TideMono, color = Mint, style = MaterialTheme.typography.bodyMedium)
    }
}
