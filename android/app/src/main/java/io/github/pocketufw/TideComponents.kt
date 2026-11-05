package io.github.pocketufw

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.*
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import java.text.DateFormat
import java.text.NumberFormat
import java.util.Date
import java.util.Locale

internal fun count(value: Long?): String = value?.let { NumberFormat.getIntegerInstance().format(it) } ?: "—"
internal fun byteCount(value: Long?): String = when {
    value == null -> "—"
    value < 1024 -> "$value B"
    value < 1024 * 1024 -> String.format(Locale.getDefault(), "%.1f KiB", value / 1024.0)
    value < 1024L * 1024 * 1024 -> String.format(Locale.getDefault(), "%.1f MiB", value / (1024.0 * 1024))
    else -> String.format(Locale.getDefault(), "%.1f GiB", value / (1024.0 * 1024 * 1024))
}
internal fun readTime(time: Long): String = DateFormat.getTimeInstance(DateFormat.MEDIUM).format(Date(time))
internal fun bootLabel(boot: FirewallClient.BootRestore): String = when (boot) {
    FirewallClient.BootRestore.ENABLED -> "On"
    FirewallClient.BootRestore.DISABLED -> "Off"
    FirewallClient.BootRestore.UNSUPPORTED -> "Unsupported"
    FirewallClient.BootRestore.DEGRADED -> "Needs inspection"
    FirewallClient.BootRestore.CONFLICT -> "Conflict"
    FirewallClient.BootRestore.UNKNOWN -> "Unverified"
}

@Composable
internal fun TideIcon(id: Int, modifier: Modifier = Modifier, description: String? = null, tint: Color = Foreground) {
    Icon(painterResource(id), description, modifier.size(22.dp), tint = tint)
}

@Composable
internal fun TideDivider() { HorizontalDivider(color = Border) }

@Composable
internal fun TideHeading(title: String, subtitle: String? = null) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(title, style = if (LocalDensity.current.fontScale > 1.2f) MaterialTheme.typography.headlineMedium
            else MaterialTheme.typography.headlineLarge, modifier = Modifier.semantics { heading() })
        if (subtitle != null) Text(subtitle, style = MaterialTheme.typography.bodyMedium, color = Muted)
    }
}

@Composable
internal fun TideNotice(message: String, error: Boolean = false) {
    Surface(color = if (error) MaterialTheme.colorScheme.secondaryContainer else Panel,
        shape = RoundedCornerShape(8.dp), modifier = Modifier.fillMaxWidth()
            .semantics { liveRegion = LiveRegionMode.Polite }) {
        Text(message, Modifier.padding(16.dp), style = MaterialTheme.typography.bodyMedium,
            color = if (error) MaterialTheme.colorScheme.onSecondaryContainer else Foreground)
    }
}

@Composable
internal fun TidePrimaryButton(label: String, onClick: () -> Unit, modifier: Modifier = Modifier,
                              icon: Int? = null, enabled: Boolean = true) {
    Button(onClick, modifier.fillMaxWidth().heightIn(min = 52.dp), enabled = enabled,
        shape = RoundedCornerShape(9.dp), contentPadding = PaddingValues(14.dp)) {
        if (icon != null) {
            TideIcon(icon, tint = LocalContentColor.current)
            Spacer(Modifier.width(10.dp))
        }
        Text(label)
    }
}

@Composable
internal fun TideLink(label: String, onClick: () -> Unit) {
    TextButton(onClick, Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
        Text(label, Modifier.weight(1f))
        TideIcon(R.drawable.tide_arrow_out, tint = Mint)
    }
}

@Composable
internal fun TideSettingLink(label: String, detail: String, onClick: () -> Unit) {
    Column {
        Row(Modifier.fillMaxWidth().clickable(role = Role.Button, onClick = onClick)
            .padding(vertical = 16.dp).heightIn(min = 48.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(label, style = MaterialTheme.typography.bodyLarge)
                Text(detail, style = MaterialTheme.typography.bodySmall, color = Muted)
            }
            Spacer(Modifier.width(12.dp))
            TideIcon(R.drawable.tide_chevron)
        }
        TideDivider()
    }
}

@Composable
internal fun TideTabs(labels: List<String>, selected: Int, onSelect: (Int) -> Unit) {
    Column {
        Row(Modifier.fillMaxWidth().selectableGroup(), horizontalArrangement = Arrangement.spacedBy(24.dp)) {
            labels.forEachIndexed { index, label ->
                Column(Modifier.weight(1f).clickable(role = Role.Tab) { onSelect(index) }
                    .semantics { this.selected = index == selected }) {
                    Text(label, Modifier.heightIn(min = 48.dp).padding(vertical = 12.dp),
                        color = if (index == selected) Mint else Muted,
                        style = MaterialTheme.typography.labelLarge)
                    Box(Modifier.fillMaxWidth().height(3.dp).background(if (index == selected) Mint else Color.Transparent))
                }
            }
        }
        TideDivider()
    }
}

@Composable
internal fun TidePolicyRow(icon: Int, label: String, value: String) {
    if (LocalDensity.current.fontScale > 1.2f) {
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalAlignment = Alignment.CenterVertically) {
                TideIcon(icon, tint = Mint); Text(label, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
            }
            Text(value, Modifier.padding(start = 32.dp), style = MaterialTheme.typography.bodyMedium, color = Muted)
        }
    } else Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        TideIcon(icon, tint = Mint)
        Text(label, Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
        Text(value, style = MaterialTheme.typography.bodySmall, color = Muted)
    }
}
