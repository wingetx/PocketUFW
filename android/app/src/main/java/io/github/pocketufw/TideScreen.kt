package io.github.pocketufw

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.graphics.BlendMode
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.CompositingStrategy
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.*
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** Presentation inputs only. Root operations remain in MainActivity / FirewallClient. */
internal data class TideUiState(
    val snapshot: FirewallClient.Snapshot = FirewallClient.Snapshot(),
    val counters: FirewallClient.RuleActivity? = null,
    val report: FirewallClient.KernelReport? = null,
    val busy: Boolean = false,
    val message: String = "",
    val failed: Boolean = false,
    val counterRefreshing: Boolean = false,
    val counterRefreshNote: String = "",
    val counterRefreshError: Boolean = false
)

internal data class TideActions(
    val recheck: () -> Unit = {},
    val changeProtection: (Boolean) -> Unit = {},
    val changeBootRestoration: (Boolean) -> Unit = {},
    val refreshCounters: () -> Unit = {},
    val resetCounters: () -> Unit = {},
    val refreshVpn: () -> Unit = {},
    val removePartialRules: () -> Unit = {},
    val setUdpPorts: (String, String, Boolean) -> Unit = { _, _, _ -> },
    val restoreAutomatic: () -> Unit = {}
)

internal enum class TideDestination(val label: String, val icon: Int) {
    FIREWALL("Firewall", R.drawable.tide_power),
    ACTIVITY("Activity", R.drawable.tide_activity),
    SETTINGS("Settings", R.drawable.tide_settings)
}
internal enum class TideInspection(val label: String) { COUNTERS("Counters"), RULES("Kernel rules") }

@Composable
internal fun TideScreen(
    ui: TideUiState,
    actions: TideActions,
    appVersion: String = BuildConfig.VERSION_NAME,
    initialDestination: TideDestination = TideDestination.FIREWALL,
    initialInspection: TideInspection = TideInspection.COUNTERS
) {
    var destination by rememberSaveable { mutableStateOf(initialDestination) }
    var inspection by rememberSaveable { mutableStateOf(initialInspection) }
    var exceptions by rememberSaveable { mutableStateOf(false) }
    val scroll = rememberScrollState()
    LaunchedEffect(destination, inspection, exceptions) { scroll.scrollTo(0) }
    BackHandler(exceptions || destination != TideDestination.FIREWALL) {
        if (exceptions) exceptions = false else destination = TideDestination.FIREWALL
    }

    Scaffold(
        containerColor = Background,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            Row(Modifier.fillMaxWidth().statusBarsPadding().padding(horizontal = 16.dp)
                .heightIn(min = 64.dp), verticalAlignment = Alignment.CenterVertically) {
                if (exceptions) IconButton(onClick = { exceptions = false }) {
                    TideIcon(R.drawable.tide_back, description = "Back")
                }
                Text("Pocket", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(start = if (exceptions) 0.dp else 8.dp))
                Text("UFW", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Normal)
                Spacer(Modifier.weight(1f))
                IconButton(onClick = actions.recheck, enabled = !ui.busy &&
                    ui.snapshot.protection != FirewallClient.Protection.CHECKING) {
                    TideIcon(R.drawable.tide_refresh, description = "Recheck firewall status")
                }
            }
        },
        bottomBar = {
            Column(Modifier.background(Background).navigationBarsPadding()) {
                TideDivider()
                Row(Modifier.fillMaxWidth().selectableGroup().padding(horizontal = 12.dp)) {
                    TideDestination.entries.forEach { item ->
                        val selected = destination == item
                        Column(Modifier.weight(1f).clickable(role = Role.Tab) {
                            destination = item; exceptions = false
                        }.semantics { this.selected = selected }.padding(horizontal = 2.dp)
                            .heightIn(min = 76.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                            Box(Modifier.width(30.dp).height(3.dp)
                                .background(if (selected) Mint else Color.Transparent))
                            Spacer(Modifier.height(13.dp))
                            TideIcon(item.icon, tint = if (selected) Mint else Muted)
                            Text(item.label, color = if (selected) Mint else Muted,
                                style = MaterialTheme.typography.labelMedium,
                                modifier = Modifier.padding(top = 5.dp, bottom = 10.dp))
                        }
                    }
                }
            }
        }
    ) { inset ->
        Column(Modifier.fillMaxSize().padding(inset).verticalScroll(scroll)
            .padding(horizontal = 24.dp).padding(top = 12.dp, bottom = 28.dp)
            .testTag("tide-content"), verticalArrangement = Arrangement.spacedBy(20.dp)) {
            if (ui.message.isNotEmpty()) TideNotice(ui.message, ui.failed)
            if (ui.busy && !ui.counterRefreshing) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
                    Text("Working…", style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                }
            }
            when {
                exceptions -> {
                    TideHeading("UDP exceptions.", "Allow a listener through incoming rules.")
                    UdpExceptionsPanel(ui.snapshot, ui.report, ui.busy,
                        actions.setUdpPorts, actions.restoreAutomatic, initiallyExpanded = true)
                    OutlinedButton(shape = RoundedCornerShape(9.dp), onClick = actions.refreshVpn, enabled = !ui.busy &&
                        ui.snapshot.protection == FirewallClient.Protection.ACTIVE,
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                        Text("Refresh VPN")
                    }
                }
                destination == TideDestination.FIREWALL -> TideFirewall(ui, actions, appVersion,
                    showCounters = { destination = TideDestination.ACTIVITY; inspection = TideInspection.COUNTERS },
                    showRules = { destination = TideDestination.ACTIVITY; inspection = TideInspection.RULES },
                    showSettings = { destination = TideDestination.SETTINGS })
                destination == TideDestination.ACTIVITY -> {
                    TideHeading(if (inspection == TideInspection.COUNTERS) "Activity." else "Kernel rules.")
                    TideTabs(TideInspection.entries.map { it.label }, inspection.ordinal) {
                        inspection = TideInspection.entries[it]
                    }
                    if (inspection == TideInspection.COUNTERS) TideCounters(ui, actions)
                    else KernelStatusTab(ui.snapshot, ui.report, ui.busy,
                        actions.recheck, onExceptions = { exceptions = true })
                }
                else -> TideSettings(ui, actions, appVersion, onExceptions = { exceptions = true })
            }
        }
    }
}

@Composable
private fun TideFirewall(ui: TideUiState, actions: TideActions, appVersion: String,
                         showCounters: () -> Unit, showRules: () -> Unit, showSettings: () -> Unit) {
    val state = ui.snapshot
    val active = state.protection == FirewallClient.Protection.ACTIVE
    val checking = state.protection == FirewallClient.Protection.CHECKING
    val attention = state.protection in listOf(FirewallClient.Protection.DEGRADED, FirewallClient.Protection.ROOT_REQUIRED)
    val accent = if (active) Mint else if (attention) Amber else Muted
    val title = when (state.protection) {
        FirewallClient.Protection.ACTIVE -> "Active."
        FirewallClient.Protection.INACTIVE -> "Off."
        FirewallClient.Protection.CHECKING -> "Checking…"
        FirewallClient.Protection.DEGRADED -> "Needs\nattention."
        FirewallClient.Protection.ROOT_REQUIRED -> "Root\nrequired."
    }
    val label = when (state.protection) {
        FirewallClient.Protection.ACTIVE -> "Kernel rules verified"
        FirewallClient.Protection.INACTIVE -> "PocketUFW is inactive"
        FirewallClient.Protection.CHECKING -> "Reading kernel state"
        FirewallClient.Protection.DEGRADED -> "Protection not verified"
        FirewallClient.Protection.ROOT_REQUIRED -> "Root permission needed"
    }
    val icon = when (state.protection) {
        FirewallClient.Protection.ACTIVE -> R.drawable.tide_check
        FirewallClient.Protection.INACTIVE -> R.drawable.tide_off
        FirewallClient.Protection.CHECKING -> R.drawable.tide_refresh
        FirewallClient.Protection.DEGRADED -> R.drawable.tide_warning
        FirewallClient.Protection.ROOT_REQUIRED -> R.drawable.tide_key
    }
    Column(Modifier.semantics(mergeDescendants = true) {
        stateDescription = state.protection.name.replace('_', ' ')
        liveRegion = LiveRegionMode.Polite
    }, verticalArrangement = Arrangement.spacedBy(18.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (checking) CircularProgressIndicator(Modifier.size(16.dp), color = accent, strokeWidth = 2.dp)
            else TideIcon(icon, tint = accent, modifier = Modifier.size(16.dp))
            Text(label.uppercase(), color = accent, style = MaterialTheme.typography.labelSmall, letterSpacing = 1.sp)
        }
        BoxWithConstraints(Modifier.fillMaxWidth()) {
            val showMascot = maxWidth >= 310.dp && LocalDensity.current.fontScale <= 1.2f
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(title, color = accent, style = if (active || state.protection == FirewallClient.Protection.INACTIVE)
                    MaterialTheme.typography.displayLarge else MaterialTheme.typography.headlineLarge,
                    modifier = Modifier.weight(1f))
                if (showMascot) {
                    val paper = Background
                    val dark = MaterialTheme.colorScheme.background.red < .3f
                    Image(painterResource(R.drawable.pocket_penguin), contentDescription = null,
                        modifier = Modifier.size(88.dp).then(if (dark) Modifier.clip(CircleShape)
                        else Modifier.graphicsLayer { compositingStrategy = CompositingStrategy.Offscreen }
                            .drawWithContent { drawContent(); drawRect(paper, blendMode = BlendMode.Darken) }))
                }
            }
        }
    }
    Box(Modifier.fillMaxWidth().height(12.dp), contentAlignment = Alignment.CenterEnd) {
        Box(Modifier.fillMaxWidth().height(3.dp).background(accent))
        Box(Modifier.size(12.dp).clip(CircleShape).background(accent))
    }
    Text(when {
        checking -> "Reading firewall rules and Magisk boot status. Protection has not yet been verified."
        active -> "Unsolicited incoming traffic is blocked on supported physical interfaces."
        state.protection == FirewallClient.Protection.INACTIVE -> "PocketUFW rules are not installed. Android’s own firewall remains unchanged."
        else -> state.details.ifEmpty { "Grant root access or recheck the kernel state before relying on protection." }
    }, style = MaterialTheme.typography.bodyMedium, color = Muted)

    // Keep verified appearance steady during other operations; the existing busy guard ignores taps.
    TidePrimaryButton(
        label = when {
            checking -> "Checking kernel protection"
            active -> "Turn firewall off"
            state.protection == FirewallClient.Protection.INACTIVE -> "Turn firewall on"
            state.protection == FirewallClient.Protection.ROOT_REQUIRED -> "Check root access"
            else -> "Recheck status"
        }, icon = if (active || state.protection == FirewallClient.Protection.INACTIVE) R.drawable.tide_power else icon,
        enabled = !checking && (attention || state.rootReady),
        modifier = Modifier.testTag("firewall-action"),
        onClick = { if (!ui.busy) { if (attention) actions.recheck() else actions.changeProtection(!active) } }
    )
    if (state.protection == FirewallClient.Protection.DEGRADED) {
        TideLink("Inspect kernel rules", onClick = showRules)
        if (state.rootReady) OutlinedButton(onClick = actions.removePartialRules, enabled = !ui.busy,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("Remove partial PocketUFW rules") }
    }
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        TidePolicyRow(R.drawable.tide_down, "Unsolicited incoming", if (active) "Blocked¹" else "Not verified")
        TidePolicyRow(R.drawable.tide_up, "Outgoing", "Unchanged")
    }
    if (active) {
        Column(Modifier.fillMaxWidth().clickable(role = Role.Button, onClickLabel = "View counters", onClick = showCounters)) {
            TideDivider()
            Row(Modifier.fillMaxWidth().padding(vertical = 18.dp), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(if (ui.counters?.measured == true) count(ui.counters.totalBlocked) else "—",
                        fontSize = 44.sp, lineHeight = 50.sp, letterSpacing = (-2).sp)
                    Text(if (ui.counters?.measured == true) "Dropped packets · kernel counters" else
                        "Counter verification unavailable", style = MaterialTheme.typography.bodySmall, color = Muted)
                }
                TideIcon(R.drawable.tide_arrow_out)
            }
            TideDivider()
        }
        TideSettingLink("Restore after reboot", bootLabel(state.bootRestore) + " · Magisk", showSettings)
    }
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        TideIcon(R.drawable.tide_root, tint = Muted)
        Text(when {
            checking -> "Reading root access"
            state.rootReady -> "Root access granted · $appVersion"
            else -> "Root access not granted · $appVersion"
        }, style = MaterialTheme.typography.bodySmall, color = Muted)
    }
    Text("¹ Supported physical interfaces only. Earlier Android/OEM rules may accept traffic before PocketUFW’s hooks.",
        style = MaterialTheme.typography.bodySmall, color = Muted)
}
