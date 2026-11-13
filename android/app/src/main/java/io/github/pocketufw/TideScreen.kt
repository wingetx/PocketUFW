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
import androidx.compose.ui.platform.LocalAccessibilityManager
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.*
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay

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
    val vpnRefreshing: Boolean = false,
    val removal: TideRemoval = TideRemoval.NONE,
    val removalDetail: String = "",
    /** Only routine successful reads/resets expire. Warnings and operation notices stay. */
    val transientMessage: Boolean = false,
    val insights: InsightsResult? = null,
    val insightsStopping: Boolean = false,
    val operation: TideOperation? = null
)

/** Presentation identity only; busy remains the single operation guard. */
internal enum class TideOperation {
    SAMPLE, RECOVER_INSIGHTS, CHECK, ACTIVATE, DEACTIVATE, REFRESH_COUNTERS, RESET_COUNTERS, REFRESH_PORTS,
    ENABLE_PINNED, ENABLE_DENY_ONLY, REMOVE_TUNNEL, REFRESH_TUNNEL, REMOVE_PARTIAL,
    ENABLE_BOOT, DISABLE_BOOT
}
internal fun TideUiState.working(operation: TideOperation) = busy && this.operation == operation
private enum class TideCheckControl { TOOLBAR, FIREWALL, KERNEL }

/** How the last Remove PocketUFW attempt ended. CLEAN means the read-back found nothing left. */
internal enum class TideRemoval { NONE, CLEAN, INCOMPLETE }

internal data class TideActions(
    val sampleDrops: () -> Unit = {},
    val cancelSample: () -> Unit = {},
    val recoverInsights: () -> Unit = {},
    val clearInsights: () -> Unit = {},
    val recheck: () -> Unit = {},
    val changeProtection: (Boolean) -> Unit = {},
    val changeBootRestoration: (Boolean) -> Unit = {},
    val refreshCounters: () -> Unit = {},
    val resetCounters: () -> Unit = {},
    val refreshVpn: () -> Unit = {},
    val removePartialRules: () -> Unit = {},
    val removeTunnelRules: () -> Unit = {},
    val enableTunnelProtection: (FirewallClient.TunnelMode) -> Unit = {},
    val refreshTunnelHooks: () -> Unit = {},
    val prepareUninstall: () -> Unit = {},
    val openAppInfo: () -> Unit = {},
    val setUdpPorts: (String, String, Boolean) -> Unit = { _, _, _ -> },
    val restoreAutomatic: () -> Unit = {},
    val dismissMessage: () -> Unit = {}
)

internal enum class TideDestination(val label: String, val icon: Int) {
    FIREWALL("Firewall", R.drawable.tide_power),
    ACTIVITY("Activity", R.drawable.tide_activity),
    INSIGHTS("Insights", R.drawable.tide_search),
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
    var tunnelRemoveConfirmOpen by rememberSaveable { mutableStateOf(false) }
    var offConfirmOpen by rememberSaveable { mutableStateOf(false) }
    var checkControl by remember { mutableStateOf(TideCheckControl.TOOLBAR) }
    // Never let a pending OFF confirmation outlive the verified ACTIVE state.
    LaunchedEffect(ui.snapshot.protection, ui.snapshot.rootReady, ui.verificationInDoubt, ui.busy) {
        if (ui.snapshot.protection != FirewallClient.Protection.ACTIVE ||
            !ui.snapshot.rootReady || ui.verificationInDoubt || ui.busy) offConfirmOpen = false
    }
    LaunchedEffect(ui.snapshot.protection, ui.snapshot.rootReady, ui.verificationInDoubt) {
        if (ui.snapshot.protection != FirewallClient.Protection.DEGRADED ||
            !ui.snapshot.rootReady || ui.verificationInDoubt) removeConfirmOpen = false
    }
    LaunchedEffect(ui.snapshot.tunnelFilter, ui.snapshot.rootReady, ui.verificationInDoubt, ui.busy) {
        if (ui.snapshot.tunnelFilter != FirewallClient.TunnelFilter.DEGRADED ||
            !ui.snapshot.rootReady || ui.verificationInDoubt || ui.busy) tunnelRemoveConfirmOpen = false
    }
    val scroll = rememberScrollState()
    LaunchedEffect(destination, inspection, exceptions) { scroll.scrollTo(0) }
    BackHandler(exceptions || destination != TideDestination.FIREWALL) {
        if (exceptions) exceptions = false else destination = TideDestination.FIREWALL
    }

    val note = when {
        // Inline progress must not shrink the viewport and push its own control offscreen.
        ui.busy && ui.operation != null -> ""
        ui.busy && !ui.counterRefreshing ->
            if (ui.vpnRefreshing) "Refreshing Tailscale ports…" else "Working…"
        ui.message.isNotEmpty() -> ui.message
        ui.counterRefreshNote.isNotEmpty() -> ui.counterRefreshNote
        else -> ""
    }
    val density = LocalDensity.current
    var bannerHeight by remember { mutableStateOf(0.dp) }
    val problem = ui.failed || ui.counterRefreshError
    val dismissMessage by rememberUpdatedState(actions.dismissMessage)
    val timeout = LocalAccessibilityManager.current?.calculateRecommendedTimeoutMillis(
        originalTimeoutMillis = 6_000L, containsIcons = false, containsText = true, containsControls = true
    ) ?: 6_000L
    LaunchedEffect(note, ui.transientMessage, ui.busy, problem, ui.verificationInDoubt, timeout) {
        if (note.isNotEmpty() && ui.transientMessage && !ui.busy && !problem && !ui.verificationInDoubt) {
            delay(timeout)
            dismissMessage()
        }
    }

    Scaffold(
        snackbarHost = {
            if (note.isNotEmpty()) {
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
            TideTopBar(
                showBack = exceptions, onBack = { exceptions = false },
                checking = ui.working(TideOperation.CHECK) && checkControl == TideCheckControl.TOOLBAR,
                recheckEnabled = !ui.busy && ui.snapshot.protection != FirewallClient.Protection.CHECKING,
                onRecheck = { checkControl = TideCheckControl.TOOLBAR; actions.recheck() }
            )
        },
        bottomBar = {
            Column(Modifier.background(Background).navigationBarsPadding()) {
                TideDivider()
                // Four labels need two rows at enlarged text sizes, without shrinking text.
                val rows = TideDestination.entries.chunked(if (density.fontScale > 1.3f) 2 else 4)
                rows.forEach { items ->
                    Row(Modifier.fillMaxWidth().selectableGroup().padding(horizontal = 12.dp)) {
                        items.forEach { item ->
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
                    TideOutlinedButton("Refresh Tailscale ports", actions.refreshVpn, enabled = vpnAllowed,
                        loading = ui.working(TideOperation.REFRESH_PORTS), loadingLabel = "Refreshing…")
                    Text("Checks Tailscale's UDP listeners, not your current VPN connection.",
                        style = MaterialTheme.typography.bodySmall, color = Muted)
                    if (vpnReason != null) Text(vpnReason, style = MaterialTheme.typography.bodySmall,
                        color = Muted)
                }
                destination == TideDestination.FIREWALL -> TideFirewall(ui, actions.copy(recheck = {
                    checkControl = TideCheckControl.FIREWALL; actions.recheck()
                }), appVersion,
                    checkingAction = ui.working(TideOperation.CHECK) && checkControl == TideCheckControl.FIREWALL,
                    requestRemoval = { removeConfirmOpen = true },
                    requestTunnelRemoval = { tunnelRemoveConfirmOpen = true },
                    requestDisable = { offConfirmOpen = true },
                    showRules = { destination = TideDestination.ACTIVITY; inspection = TideInspection.RULES },
                    showSettings = { destination = TideDestination.SETTINGS })
                destination == TideDestination.INSIGHTS -> TideInsights(ui, actions)
                destination == TideDestination.ACTIVITY -> {
                    TideHeading(if (inspection == TideInspection.COUNTERS) "Activity." else "Kernel rules.")
                    TideTabs(TideInspection.entries.map { it.label }, inspection.ordinal) {
                        inspection = TideInspection.entries[it]
                    }
                    if (inspection == TideInspection.COUNTERS) TideCounters(ui, actions)
                    else KernelStatusTab(ui.snapshot, ui.report, ui.busy,
                        { checkControl = TideCheckControl.KERNEL; actions.recheck() },
                        verificationInDoubt = ui.verificationInDoubt,
                        checking = ui.working(TideOperation.CHECK) && checkControl == TideCheckControl.KERNEL)
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
    if (tunnelRemoveConfirmOpen) AlertDialog(
        containerColor = Background, tonalElevation = 0.dp,
        onDismissRequest = { tunnelRemoveConfirmOpen = false },
        title = { Text("Remove tunnel rules only?") },
        text = { Text("This stops PocketUFW filtering inside VPN tunnels. The physical firewall and boot opt-in stay in place. You can enable tunnel protection again in Settings.") },
        confirmButton = { TextButton(onClick = {
            tunnelRemoveConfirmOpen = false
            if (!ui.busy && !ui.verificationInDoubt && ui.snapshot.rootReady &&
                ui.snapshot.tunnelFilter == FirewallClient.TunnelFilter.DEGRADED) actions.removeTunnelRules()
        }, modifier = Modifier.testTag("confirm-remove-tunnel")) { Text("Remove tunnel rules") } },
        dismissButton = { TextButton(onClick = { tunnelRemoveConfirmOpen = false }) { Text("Cancel") } }
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

/**
 * The kernel's names mean little on their own, so say what each one is when that's known.
 * Only Android's VPN record names an owner. Other names are described by kind, because a
 * tunnel's name doesn't say whose it is. Carrier calling is named only when Android's own
 * network record identifies that interface as carrier IMS; any other `ipsec` stays unidentified.
 * The kernel's name stays, so it can be matched against the rules.
 */
internal fun uncoveredLabel(name: String, state: FirewallClient.Snapshot): String {
    val owner = state.vpnProvider?.removePrefix("Connected via ")?.takeIf { it != "Unrecognized VPN" }
    return when {
        name == state.vpnInterface && owner != null -> "traffic inside $owner ($name)"
        isCarrierIms(name, state) -> "carrier calling network ($name)"
        name.startsWith("tun") -> "VPN tunnel $name"
        name.startsWith("ipsec") -> "unidentified IPsec tunnel $name"
        else -> name
    }
}
// Android's VPN record outranks IMS evidence for the same name.
internal fun isCarrierIms(name: String, state: FirewallClient.Snapshot) =
    name in state.carrierImsInterfaces && name != state.vpnInterface

@Composable
private fun TideFirewall(ui: TideUiState, actions: TideActions, appVersion: String, checkingAction: Boolean,
                         requestRemoval: () -> Unit, requestDisable: () -> Unit,
                         requestTunnelRemoval: () -> Unit,
                         showRules: () -> Unit, showSettings: () -> Unit) {
    val state = ui.snapshot
    val active = state.protection == FirewallClient.Protection.ACTIVE
    val notVerified = ui.verificationInDoubt || (!state.rootReady && state.protection !in setOf(
        FirewallClient.Protection.CHECKING, FirewallClient.Protection.ROOT_REQUIRED))
    val status = protectionStatus(ui)
    val checking = status.health == TideProtectionHealth.CHECKING
    val attention = status.health == TideProtectionHealth.ATTENTION
    val accent = when (status.health) {
        TideProtectionHealth.HEALTHY -> VerifiedProtection
        TideProtectionHealth.ATTENTION -> Amber
        else -> Muted
    }
    val icon = when (status.health) {
        TideProtectionHealth.HEALTHY -> R.drawable.tide_check
        TideProtectionHealth.ATTENTION -> if (state.protection == FirewallClient.Protection.ROOT_REQUIRED)
            R.drawable.tide_key else R.drawable.tide_warning
        TideProtectionHealth.INACTIVE -> R.drawable.tide_off
        TideProtectionHealth.CHECKING -> R.drawable.tide_refresh
    }
    Column(Modifier.testTag("protection-status").semantics(mergeDescendants = true) {
        heading()
        stateDescription = status.label
        liveRegion = LiveRegionMode.Polite
    }, verticalArrangement = Arrangement.spacedBy(18.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (checking) CircularProgressIndicator(Modifier.size(16.dp), color = accent, strokeWidth = 2.dp)
            else TideIcon(icon, tint = accent, modifier = Modifier.size(16.dp))
            Text(status.label, color = accent, style = MaterialTheme.typography.labelSmall, letterSpacing = 1.sp)
        }
        BoxWithConstraints(Modifier.fillMaxWidth()) {
            val showMascot = maxWidth >= 310.dp && LocalDensity.current.fontScale <= 1.2f
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(status.title, color = accent, style = when {
                    LocalDensity.current.fontScale > 1.2f -> MaterialTheme.typography.headlineMedium
                    !attention && (active || state.protection == FirewallClient.Protection.INACTIVE) -> MaterialTheme.typography.displayLarge
                    else -> MaterialTheme.typography.headlineLarge
                },
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
    Box(Modifier.fillMaxWidth().height(12.dp).testTag("protection-divider"), contentAlignment = Alignment.CenterEnd) {
        Box(Modifier.fillMaxWidth().height(3.dp).background(accent))
        Box(Modifier.size(12.dp).clip(CircleShape).background(accent))
    }
    Text(status.description, style = MaterialTheme.typography.bodyMedium, color = Muted)
    if (!checking) TideCoverageDetails(ui, showRules)

    // The last verified status stays steady while the requested action is in progress.
    TidePrimaryButton(
        label = when {
            checking -> "Checking kernel protection"
            notVerified -> "Recheck status"
            status.reviewTunnel -> "Review tunnel protection"
            attention && active -> "Recheck status"
            active -> "Turn firewall off"
            state.protection == FirewallClient.Protection.INACTIVE -> "Turn firewall on"
            state.protection == FirewallClient.Protection.ROOT_REQUIRED -> "Check root access"
            else -> "Recheck status"
        }, icon = if (!attention && (active || state.protection == FirewallClient.Protection.INACTIVE))
            R.drawable.tide_power else icon,
        enabled = !ui.busy && !checking && (attention || state.rootReady),
        loading = checkingAction || ui.working(TideOperation.ACTIVATE) || ui.working(TideOperation.DEACTIVATE),
        loadingLabel = when {
            checkingAction || checking -> "Checking…"
            active -> "Deactivating…"
            else -> "Activating…"
        },
        modifier = Modifier.testTag("firewall-action"),
        onClick = { if (!ui.busy) {
            if (status.reviewTunnel) showSettings()
            else if (notVerified || state.protection in setOf(FirewallClient.Protection.DEGRADED,
                    FirewallClient.Protection.ROOT_REQUIRED) || (attention && active)) actions.recheck()
            else if (active) requestDisable()
            else actions.changeProtection(true)
        } }
    )
    if (state.protection == FirewallClient.Protection.DEGRADED ||
        state.tunnelFilter == FirewallClient.TunnelFilter.DEGRADED) {
        TideLink("Inspect kernel rules", onClick = showRules)
        if (state.rootReady && !ui.verificationInDoubt) {
            if (hasInsightsResidue(ui.report)) {
                Text("Temporary Insights probes detected. Recover those probes before repairing other rules.",
                    style = MaterialTheme.typography.bodyMedium, color = Muted)
                TideOutlinedButton("Recover Insights probes", actions.recoverInsights, enabled = !ui.busy,
                    loading = ui.working(TideOperation.RECOVER_INSIGHTS), loadingLabel = "Verifying cleanup…")
            } else if (state.tunnelFilter == FirewallClient.TunnelFilter.DEGRADED)
                TideOutlinedButton("Remove tunnel rules only", requestTunnelRemoval, enabled = !ui.busy,
                    loading = ui.working(TideOperation.REMOVE_TUNNEL), loadingLabel = "Removing…")
            else TideOutlinedButton("Remove partial PocketUFW rules", requestRemoval, enabled = !ui.busy,
                loading = ui.working(TideOperation.REMOVE_PARTIAL), loadingLabel = "Removing…")
        }
    }
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        TidePolicyRow(R.drawable.tide_down, "Physical protection", physicalStatus(ui))
        TidePolicyRow(R.drawable.tide_down, "Unsolicited incoming", when {
            ui.verificationInDoubt || !state.rootReady -> "Not verified"
            state.physicalFilter == FirewallClient.PhysicalFilter.ACTIVE -> "Filtered where supported"
            state.physicalFilter == FirewallClient.PhysicalFilter.DEGRADED -> "Degraded"
            state.physicalFilter == FirewallClient.PhysicalFilter.INACTIVE ||
                state.protection == FirewallClient.Protection.INACTIVE -> "Not installed"
            else -> "Not verified"
        })
        TidePolicyRow(R.drawable.tide_up, "Outgoing", "Unchanged")
    }
    if (active) {
        TideSettingLink("Restore after reboot", bootLabel(state.bootRestore) + " · Magisk", showSettings)
    }
    TideTermuxCommands()
    TideDivider()
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        TideIcon(R.drawable.tide_root, tint = Muted)
        Text(when {
            checking -> "Reading root access"
            state.rootReady -> "Root access granted · $appVersion"
            else -> "Root access not confirmed · $appVersion"
        }, style = MaterialTheme.typography.bodySmall, color = Muted)
    }
}
