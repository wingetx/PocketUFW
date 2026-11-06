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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.onSizeChanged
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
    val counterRefreshError: Boolean = false,
    val verificationInDoubt: Boolean = false,
    val checkedAt: Long = 0L,
    val vpnRefreshing: Boolean = false
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
    val restoreAutomatic: () -> Unit = {},
    val dismissMessage: () -> Unit = {}
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
    var removeConfirmOpen by rememberSaveable { mutableStateOf(false) }
    var offConfirmOpen by rememberSaveable { mutableStateOf(false) }
    // Never let a pending OFF confirmation outlive the verified ACTIVE state.
    LaunchedEffect(ui.snapshot.protection, ui.snapshot.rootReady, ui.verificationInDoubt, ui.busy) {
        if (ui.snapshot.protection != FirewallClient.Protection.ACTIVE ||
            !ui.snapshot.rootReady || ui.verificationInDoubt || ui.busy) offConfirmOpen = false
    }
    LaunchedEffect(ui.snapshot.protection, ui.snapshot.rootReady, ui.verificationInDoubt) {
        if (ui.snapshot.protection != FirewallClient.Protection.DEGRADED ||
            !ui.snapshot.rootReady || ui.verificationInDoubt) removeConfirmOpen = false
    }
    val scroll = rememberScrollState()
    LaunchedEffect(destination, inspection, exceptions) { scroll.scrollTo(0) }
    BackHandler(exceptions || destination != TideDestination.FIREWALL) {
        if (exceptions) exceptions = false else destination = TideDestination.FIREWALL
    }

    val note = when {
        ui.busy && !ui.counterRefreshing ->
            if (ui.vpnRefreshing) "Refreshing Tailscale ports…" else "Working…"
        ui.message.isNotEmpty() -> ui.message
        ui.counterRefreshNote.isNotEmpty() -> ui.counterRefreshNote
        else -> ""
    }
    val density = LocalDensity.current
    var bannerHeight by remember { mutableStateOf(0.dp) }

    Scaffold(
        snackbarHost = {
            if (note.isNotEmpty()) {
                val problem = ui.failed || ui.counterRefreshError
                Surface(color = if (problem) MaterialTheme.colorScheme.secondaryContainer else Panel,
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.onSizeChanged { bannerHeight = with(density) { it.height.toDp() } }
                        .testTag(if (problem) "banner-failed" else "banner")
                        .fillMaxWidth().padding(horizontal = 16.dp)
                        .padding(bottom = 6.dp).semantics { liveRegion = LiveRegionMode.Polite }) {
                    Row(Modifier.padding(start = 16.dp, end = 4.dp, top = 8.dp, bottom = 8.dp),
                        verticalAlignment = Alignment.CenterVertically) {
                        Text(note, Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
                        if (!ui.busy) TextButton(onClick = actions.dismissMessage) { Text("Dismiss") }
                    }
                }
            }
        },
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
        // The banner overlays this area. Shrinking the scrolling viewport by its height
        // leaves nothing under it, at any scroll position, to be hidden or to lose a tap.
        Column(Modifier.fillMaxSize().padding(inset)
            .padding(bottom = if (note.isEmpty()) 0.dp else bannerHeight).verticalScroll(scroll)
            .padding(horizontal = 24.dp).padding(top = 12.dp, bottom = 28.dp)
            .testTag("tide-content"), verticalArrangement = Arrangement.spacedBy(20.dp)) {
            when {
                exceptions -> {
                    TideHeading("UDP exceptions.", "Allow a listener through incoming rules.")
                    UdpExceptionsPanel(ui.snapshot, ui.report, ui.busy || ui.verificationInDoubt,
                        actions.setUdpPorts, actions.restoreAutomatic, initiallyExpanded = true)
                    val vpnReason = vpnRefreshBlockedReason(ui.snapshot.udpConfigMode)
                    val vpnAllowed = !ui.busy && !ui.verificationInDoubt &&
                        ui.snapshot.protection == FirewallClient.Protection.ACTIVE &&
                        ui.snapshot.rootReady && vpnReason == null
                    OutlinedButton(shape = TideActionShape, onClick = actions.refreshVpn,
                        enabled = vpnAllowed, modifier = Modifier.fillMaxWidth().heightIn(min = TideActionMinHeight)) {
                        Text(if (ui.vpnRefreshing) "Refreshing Tailscale ports…" else "Refresh Tailscale ports",
                            style = MaterialTheme.typography.labelLarge)
                    }
                    Text("Checks Tailscale's UDP listeners, not your current VPN connection.",
                        style = MaterialTheme.typography.bodySmall, color = Muted)
                    if (vpnReason != null) Text(vpnReason, style = MaterialTheme.typography.bodySmall,
                        color = Muted)
                }
                destination == TideDestination.FIREWALL -> TideFirewall(ui, actions, appVersion,
                    requestRemoval = { removeConfirmOpen = true },
                    requestDisable = { offConfirmOpen = true },
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
                        actions.recheck, verificationInDoubt = ui.verificationInDoubt)
                }
                else -> TideSettings(ui, actions, appVersion, onExceptions = { exceptions = true })
            }
        }
    }
    if (offConfirmOpen) AlertDialog(
        containerColor = Background, tonalElevation = 0.dp,
        onDismissRequest = { offConfirmOpen = false },
        title = { Text("Turn firewall off?") },
        text = { Text("This removes PocketUFW's incoming firewall rules and disarms " +
            "Magisk boot restoration. Android's existing firewall rules remain unchanged.") },
        confirmButton = {
            TextButton(onClick = {
                offConfirmOpen = false
                if (!ui.busy && !ui.verificationInDoubt && ui.snapshot.rootReady &&
                    ui.snapshot.protection == FirewallClient.Protection.ACTIVE) actions.changeProtection(false)
            }, enabled = !ui.busy && !ui.verificationInDoubt && ui.snapshot.rootReady &&
                ui.snapshot.protection == FirewallClient.Protection.ACTIVE,
                modifier = Modifier.testTag("confirm-turn-firewall-off")) { Text("Turn off") }
        },
        dismissButton = { TextButton(onClick = { offConfirmOpen = false }) { Text("Cancel") } }
    )
    if (removeConfirmOpen) AlertDialog(
        containerColor = Background, tonalElevation = 0.dp,
        onDismissRequest = { removeConfirmOpen = false },
        title = { Text("Remove partial PocketUFW rules?") },
        text = { Text("This removes PocketUFW's partial firewall rules and disarms the " +
            "Magisk boot hook. Android's own rules remain unchanged.") },
        confirmButton = {
            TextButton(onClick = {
                removeConfirmOpen = false
                if (!ui.busy && !ui.verificationInDoubt && ui.snapshot.rootReady &&
                    ui.snapshot.protection == FirewallClient.Protection.DEGRADED) actions.removePartialRules()
            }) { Text("Remove rules") }
        },
        dismissButton = { TextButton(onClick = { removeConfirmOpen = false }) { Text("Cancel") } }
    )
}

@Composable
private fun TideFirewall(ui: TideUiState, actions: TideActions, appVersion: String,
                         requestRemoval: () -> Unit, requestDisable: () -> Unit,
                         showCounters: () -> Unit,
                         showRules: () -> Unit, showSettings: () -> Unit) {
    val state = ui.snapshot
    val active = state.protection == FirewallClient.Protection.ACTIVE
    val verified = active && !ui.verificationInDoubt
    val checking = state.protection == FirewallClient.Protection.CHECKING
    val attention = ui.verificationInDoubt || state.protection in listOf(
        FirewallClient.Protection.DEGRADED, FirewallClient.Protection.ROOT_REQUIRED)
    // Rules can verify while traffic still goes around them. The state stays ACTIVE;
    // only what it's allowed to imply changes.
    val bypass = bypassRules(ui.report)
    val coverageGap = active && (state.uncoveredInterfaces.isNotEmpty() || bypass.isNotEmpty())
    val accent = if (coverageGap || attention) Amber else if (verified) Mint else Muted
    val title = if (ui.verificationInDoubt) "Not\nverified." else when (state.protection) {
        FirewallClient.Protection.ACTIVE -> "Active."
        FirewallClient.Protection.INACTIVE -> "Off."
        FirewallClient.Protection.CHECKING -> "Checking…"
        FirewallClient.Protection.DEGRADED -> "Needs\nattention."
        FirewallClient.Protection.ROOT_REQUIRED -> "Root\nrequired."
    }
    val label = if (ui.verificationInDoubt) "Recheck required" else when (state.protection) {
        FirewallClient.Protection.ACTIVE ->
            if (coverageGap) "Rules verified · not all traffic filtered" else "Kernel rules verified"
        FirewallClient.Protection.INACTIVE -> "PocketUFW is inactive"
        FirewallClient.Protection.CHECKING -> "Reading kernel state"
        FirewallClient.Protection.DEGRADED -> "Protection not verified"
        FirewallClient.Protection.ROOT_REQUIRED -> "Root permission needed"
    }
    val icon = if (ui.verificationInDoubt || coverageGap) R.drawable.tide_warning else when (state.protection) {
        FirewallClient.Protection.ACTIVE -> R.drawable.tide_check
        FirewallClient.Protection.INACTIVE -> R.drawable.tide_off
        FirewallClient.Protection.CHECKING -> R.drawable.tide_refresh
        FirewallClient.Protection.DEGRADED -> R.drawable.tide_warning
        FirewallClient.Protection.ROOT_REQUIRED -> R.drawable.tide_key
    }
    Column(Modifier.semantics(mergeDescendants = true) {
        stateDescription = when {
            ui.verificationInDoubt -> "Not verified; recheck required"
            coverageGap -> "Active; not all traffic filtered"
            else -> state.protection.name.replace('_', ' ')
        }
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
                Text(title, color = accent, style = if (!attention && (active || state.protection == FirewallClient.Protection.INACTIVE))
                    MaterialTheme.typography.displayLarge else MaterialTheme.typography.headlineLarge,
                    modifier = Modifier.weight(1f))
                if (showMascot) {
                    // Match the colorful shield penguin used by the app launcher.
                    // This badge is cropped from the existing source art, not a new mascot.
                    Image(painterResource(R.drawable.pocket_penguin_neon_badge),
                        contentDescription = null, modifier = Modifier.size(88.dp))
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
        ui.verificationInDoubt -> "A later read failed or the Quick Settings tile changed. " +
            "Last known status is not proof of current protection. Recheck the kernel."
        coverageGap -> "Unsolicited incoming traffic is blocked only where PocketUFW's rules see it."
        active -> "Unsolicited incoming traffic is blocked on supported physical interfaces."
        state.protection == FirewallClient.Protection.INACTIVE -> "PocketUFW rules are not installed. Android’s own firewall remains unchanged."
        else -> state.details.ifEmpty { "Grant root access or recheck the kernel state before relying on protection." }
    }, style = MaterialTheme.typography.bodyMedium, color = Muted)
    if (active && state.uncoveredInterfaces.isNotEmpty()) {
        TideNotice("Not filtered: " + state.uncoveredInterfaces.joinToString(", ") + ".", true)
    }
    if (active && bypass.isNotEmpty()) TideNotice("$BYPASS_NOTICE See Kernel rules.", true)
    restoreFailureNotice(state, ui.verificationInDoubt)?.let { TideNotice(it, true) }

    // Keep verified appearance steady during other operations; the existing busy guard ignores taps.
    TidePrimaryButton(
        label = when {
            checking -> "Checking kernel protection"
            attention && ui.verificationInDoubt -> "Recheck status"
            active -> "Turn firewall off"
            state.protection == FirewallClient.Protection.INACTIVE -> "Turn firewall on"
            state.protection == FirewallClient.Protection.ROOT_REQUIRED -> "Check root access"
            else -> "Recheck status"
        }, icon = if (!attention && (active || state.protection == FirewallClient.Protection.INACTIVE))
            R.drawable.tide_power else icon,
        enabled = !checking && (attention || state.rootReady),
        modifier = Modifier.testTag("firewall-action"),
        onClick = { if (!ui.busy) {
            if (attention) actions.recheck()
            else if (active) requestDisable()
            else actions.changeProtection(true)
        } }
    )
    if (state.protection == FirewallClient.Protection.DEGRADED) {
        TideLink("Inspect kernel rules", onClick = showRules)
        if (state.rootReady && !ui.verificationInDoubt)
            OutlinedButton(onClick = requestRemoval, enabled = !ui.busy,
            modifier = Modifier.fillMaxWidth().heightIn(min = TideActionMinHeight)) { Text("Remove partial PocketUFW rules") }
    }
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        TidePolicyRow(R.drawable.tide_down, "Unsolicited incoming", when {
            verified && coverageGap -> "Partly filtered¹"
            verified -> "Matched deny policy¹"
            !ui.verificationInDoubt && state.protection == FirewallClient.Protection.INACTIVE -> "Not installed"
            else -> "Not verified"
        })
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
            else -> "Root access not confirmed · $appVersion"
        }, style = MaterialTheme.typography.bodySmall, color = Muted)
    }
    Text("¹ Supported physical interfaces only. Earlier Android/OEM rules may accept traffic before PocketUFW’s hooks.",
        style = MaterialTheme.typography.bodySmall, color = Muted)
}
