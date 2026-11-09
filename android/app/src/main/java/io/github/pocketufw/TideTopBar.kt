package io.github.pocketufw

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.*
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp

@Composable
internal fun TideTopBar(showBack: Boolean, onBack: () -> Unit, checking: Boolean,
                        recheckEnabled: Boolean, onRecheck: () -> Unit) {
    val title = buildAnnotatedString {
        withStyle(SpanStyle(fontWeight = FontWeight.Bold)) { append("Pocket") }
        withStyle(SpanStyle(fontWeight = FontWeight.Normal)) { append("UFW") }
    }
    val titleStyle = MaterialTheme.typography.titleLarge
    val labelStyle = MaterialTheme.typography.labelLarge
    val measurer = rememberTextMeasurer()
    val density = LocalDensity.current
    val titleWidth = with(density) { measurer.measure(title, titleStyle, softWrap = false).size.width.toDp() }
    // Reserve both labels and the icon slot, so starting a check cannot reflow the header.
    val labelWidth = with(density) {
        maxOf(measurer.measure("Recheck", labelStyle, softWrap = false).size.width,
            measurer.measure("Checking…", labelStyle, softWrap = false).size.width).toDp()
    }
    val back: @Composable () -> Unit = {
        if (showBack) IconButton(onClick = onBack) { TideIcon(R.drawable.tide_back, description = "Back") }
    }
    val brand: @Composable () -> Unit = {
        Text(title, style = titleStyle, modifier = Modifier.padding(start = 8.dp).testTag("toolbar-title"))
    }
    val recheck: @Composable () -> Unit = {
        TextButton(onClick = onRecheck, enabled = recheckEnabled && !checking, shape = TideActionShape,
            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp),
            colors = if (checking) ButtonDefaults.textButtonColors(disabledContentColor = Mint)
                else ButtonDefaults.textButtonColors(contentColor = Foreground),
            modifier = Modifier.heightIn(min = 48.dp).widthIn(min = 48.dp).testTag("recheck-status").semantics {
                contentDescription = "Recheck firewall status"
                if (checking) {
                    stateDescription = "Checking…"
                    progressBarRangeInfo = ProgressBarRangeInfo.Indeterminate
                    liveRegion = LiveRegionMode.Polite
                }
            }) {
            Box(Modifier.size(22.dp), contentAlignment = Alignment.Center) {
                if (checking) TideProgressIndicator() else TideIcon(R.drawable.tide_refresh, tint = LocalContentColor.current)
            }
            Spacer(Modifier.width(8.dp))
            Text(if (checking) "Checking…" else "Recheck", Modifier.width(labelWidth), style = labelStyle)
        }
    }
    BoxWithConstraints(Modifier.fillMaxWidth().statusBarsPadding().padding(horizontal = 16.dp)) {
        val requiredWidth = titleWidth + 8.dp + labelWidth + 22.dp + 8.dp + 24.dp + 8.dp +
            if (showBack) 48.dp else 0.dp
        if (requiredWidth <= maxWidth) Row(Modifier.fillMaxWidth().heightIn(min = 64.dp),
            verticalAlignment = Alignment.CenterVertically) {
            back(); brand(); Spacer(Modifier.weight(1f)); recheck()
        } else Column(Modifier.fillMaxWidth().padding(top = 8.dp)) {
            brand()
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                back(); Spacer(Modifier.weight(1f)); recheck()
            }
        }
    }
}
