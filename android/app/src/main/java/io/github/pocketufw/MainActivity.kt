package io.github.pocketufw

import android.os.Bundle
import java.text.DateFormat
import java.text.NumberFormat
import java.util.Calendar
import java.util.Date
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

internal val Background = Color(0xFF11181B)
internal val Panel = Color(0xFF1A2529)
internal val Border = Color(0xFF2D3A3C)
internal val Foreground = Color(0xFFF3F4F0)
internal val Muted = Color(0xFFB0BEC0)
internal val Mint = Color(0xFF88BE98)
internal val Amber = Color(0xFFE2B86F)

private enum class PocketTab { HOME, STATUS }

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = android.graphics.Color.rgb(17, 24, 27)
        window.navigationBarColor = android.graphics.Color.rgb(17, 24, 27)
        setContent {
            MaterialTheme(
                colorScheme = darkColorScheme(
                    primary = Mint, onPrimary = Background,
                    background = Background, onBackground = Foreground,
                    surface = Panel, onSurface = Foreground
                )
            ) {
                PocketScreen(remember { FirewallClient(applicationContext) })
            }
        }
    }
}

@Composable
internal fun PocketScreen(client: FirewallGateway) {
    var state by remember { mutableStateOf(FirewallClient.Snapshot()) }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("") }
    var failed by remember { mutableStateOf(false) }
    var activityExpanded by remember { mutableStateOf(false) }
    var counters by remember { mutableStateOf<FirewallClient.RuleActivity?>(null) }
    var counterRefreshing by remember { mutableStateOf(false) }
    var counterRefreshNote by remember { mutableStateOf("") }
    var counterRefreshError by remember { mutableStateOf(false) }
    var kernelReport by remember { mutableStateOf<FirewallClient.KernelReport?>(null) }
    var selectedTab by remember { mutableStateOf(PocketTab.HOME) }
    var resetConfirmOpen by remember { mutableStateOf(false) }
    var removeConfirmOpen by remember { mutableStateOf(false) }
    var vpnRefreshing by remember { mutableStateOf(false) }
    // When this screen last had a live kernel verification; 0 until the first one.
    var checkedAt by remember { mutableStateOf(0L) }
    // Something newer than checkedAt suggests the status above may be out of date.
    var verificationInDoubt by remember { mutableStateOf(false) }
    var tileStamp by remember { mutableStateOf<Long?>(null) }
    var bannerRoomPx by remember { mutableStateOf(0) }
    val scrollState = rememberScrollState()
    // Screen state is only written on the main thread. Compose's own effect dispatcher
    // already does that on a device; test dispatchers don't, so it's stated, not assumed.
    val scope = rememberCoroutineScope { Dispatchers.Main.immediate }
    val context = LocalContext.current.applicationContext
    val density = LocalDensity.current
    val windowInfo = LocalWindowInfo.current

    // Every full inspection or operation result lands here, so the screen knows
    // when it verified and what the Quick Settings cache held at that moment.
    suspend fun adopt(dashboard: FirewallClient.Dashboard) {
        // Read first, then update everything together, so the focus check below
        // can never see a new checkedAt paired with an old stamp.
        val stamp = withContext(Dispatchers.IO) { TileStatusStore.read(context)?.checkedAt }
        state = dashboard.snapshot
        counters = dashboard.activity
        kernelReport = dashboard.kernelReport
        checkedAt = System.currentTimeMillis()
        tileStamp = stamp
        verificationInDoubt = false
        counterRefreshNote = ""
        counterRefreshError = false
    }

    LaunchedEffect(selectedTab) { scrollState.scrollTo(0) }

    LaunchedEffect(client) {
        scope.launch { adopt(withContext(Dispatchers.IO) { client.inspectDashboard() }) }
    }

    fun perform(work: () -> FirewallClient.Operation) {
        if (busy) return
        busy = true
        message = "" // An earlier action's result no longer applies.
        scope.launch {
            val outcome = withContext(Dispatchers.IO) { work() }
            adopt(outcome.dashboard)
            failed = !outcome.success
            message = outcome.explanation
            vpnRefreshing = false
            busy = false
        }
    }

    fun recheck() {
        if (busy) return
        busy = true
        scope.launch {
            adopt(withContext(Dispatchers.IO) { client.inspectDashboard() })
            message = ""
            failed = false
            busy = false
        }
    }

    // A Quick Settings tap can change the firewall while this screen sits behind
    // the shade or another app. The tile cache's stamp only moves when something
    // verified or acted, so regaining focus requests root only in that case.
    LaunchedEffect(windowInfo) {
        snapshotFlow { windowInfo.isWindowFocused }.filter { it }.collect {
            scope.launch {
                if (checkedAt != 0L && !busy) {
                    val latest = withContext(Dispatchers.IO) { TileStatusStore.read(context)?.checkedAt }
                    if (latest != tileStamp) {
                        verificationInDoubt = true
                        recheck()
                    }
                }
            }
        }
    }

    // Counter-only root read: never reset packet counts or reconfigure the firewall.
    fun refreshCounters() {
        if (busy || state.protection != FirewallClient.Protection.ACTIVE) return
        busy = true
        counterRefreshing = true
        counterRefreshNote = ""
        scope.launch {
            try {
                val fresh = withContext(Dispatchers.IO) { client.refreshCounterActivity() }
                if (fresh.measured) {
                    counters = fresh
                    counterRefreshError = false
                    // The engine verifies both families before it reports counters.
                    checkedAt = fresh.checkedAt
                    verificationInDoubt = false
                    val whenChecked = DateFormat.getTimeInstance(DateFormat.MEDIUM)
                        .format(Date(fresh.checkedAt))
                    counterRefreshNote = "Counters refreshed at $whenChecked"
                } else {
                    // Preserve the last verified measurement instead of showing zeros.
                    counterRefreshError = true
                    verificationInDoubt = true
                    counterRefreshNote = fresh.error ?: "Counter refresh failed; previous counts kept."
                }
            } catch (e: Exception) {
                counterRefreshError = true
                verificationInDoubt = true
                counterRefreshNote = "Counter refresh failed; previous counts kept."
            } finally {
                counterRefreshing = false
                busy = false
            }
        }
    }

    val active = state.protection == FirewallClient.Protection.ACTIVE
    val inactive = state.protection == FirewallClient.Protection.INACTIVE
    val attention = verificationInDoubt ||
        state.protection == FirewallClient.Protection.DEGRADED ||
        state.protection == FirewallClient.Protection.ROOT_REQUIRED
    val verified = active && !verificationInDoubt
    // Rules can stay in the kernel when the app can't read them, so a switch
    // position is only drawn when the kernel state is actually known.
    val onOffKnown = !verificationInDoubt && (active || inactive)
    val accent = when {
        verified -> Mint
        attention -> Amber
        else -> Muted
    }
    val status = if (verificationInDoubt) "Needs attention" else when (state.protection) {
        FirewallClient.Protection.CHECKING -> "Checking protection"
        FirewallClient.Protection.ACTIVE -> "Firewall active"
        FirewallClient.Protection.INACTIVE -> "PocketUFW is off"
        FirewallClient.Protection.DEGRADED -> "Needs attention"
        FirewallClient.Protection.ROOT_REQUIRED -> "Root permission needed"
    }

    Surface(modifier = Modifier.fillMaxSize(), color = Background) { Box(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .navigationBarsPadding()
                .verticalScroll(scrollState)
                .padding(horizontal = 22.dp, vertical = 26.dp),
            verticalArrangement = Arrangement.spacedBy(20.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Image(
                    painter = painterResource(id = R.drawable.pocket_penguin_neon_home),
                    contentDescription = "PocketUFW terminal penguin",
                    modifier = Modifier.size(76.dp).clip(RoundedCornerShape(20.dp))
                )
                Spacer(modifier = Modifier.size(16.dp))
                Column {
                    Row {
                        Text("Pocket", color = Foreground, fontWeight = FontWeight.Bold, fontSize = 27.sp)
                        Text("UFW", color = Mint, fontWeight = FontWeight.Bold, fontSize = 27.sp)
                    }
                    Text("Quiet protection for Android", color = Muted, fontSize = 13.sp)
                }
            }

            Text("Simple. Reliable. Yours.", fontSize = 14.sp, color = Muted)

            Row(modifier = Modifier.fillMaxWidth().selectableGroup(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                PocketTabButton("Home", selectedTab == PocketTab.HOME, Modifier.weight(1f)) {
                    selectedTab = PocketTab.HOME
                }
                PocketTabButton("Status", selectedTab == PocketTab.STATUS, Modifier.weight(1f)) {
                    selectedTab = PocketTab.STATUS
                }
            }

            // No false OFF switches while the first root inspection runs.
            // A fresh app launch has no verified state yet, so show a neutral
            // progress panel until the live kernel snapshot arrives.
            if (state.protection == FirewallClient.Protection.CHECKING) {
                Surface(
                    color = Panel,
                    shape = RoundedCornerShape(22.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier.padding(22.dp),
                        verticalArrangement = Arrangement.spacedBy(14.dp)
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(26.dp),
                                color = Mint,
                                strokeWidth = 3.dp
                            )
                            Text("Checking kernel protection",
                                fontSize = 17.sp, fontWeight = FontWeight.SemiBold)
                        }
                        Text(
                            "Reading live firewall rules and Magisk boot status. " +
                                "Nothing is being switched off.",
                            color = Muted, fontSize = 13.sp, lineHeight = 19.sp
                        )
                    }
                }
            } else if (selectedTab == PocketTab.HOME) {

            Surface(
                color = Panel,
                shape = RoundedCornerShape(24.dp),
                modifier = Modifier.fillMaxWidth().border(
                    width = 1.dp,
                    color = if (verified) Mint.copy(alpha = 0.65f) else Border,
                    shape = RoundedCornerShape(24.dp)
                )
            ) {
                Column(modifier = Modifier.padding(22.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier.size(10.dp)
                                .clip(RoundedCornerShape(50))
                                .background(accent)
                        )
                        Spacer(modifier = Modifier.size(10.dp))
                        Text(
                            text = if (verified) "RULES VERIFIED" else if (attention) "CHECK REQUIRED" else "NOT ACTIVE",
                            color = accent,
                            fontWeight = FontWeight.Bold,
                            fontSize = 11.sp,
                            letterSpacing = 1.sp
                        )
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(status, fontSize = 24.sp, fontWeight = FontWeight.SemiBold, color = Foreground,
                                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                if (verificationInDoubt) {
                                    "A later check could not confirm this status. Recheck before relying on it."
                                } else {
                                    state.details.ifEmpty { "Reading Android's firewall rules…" }
                                },
                                color = Muted, fontSize = 13.sp, lineHeight = 19.sp
                            )
                            if (checkedAt > 0L) {
                                Text("Checked " + readingTime(checkedAt), color = Muted, fontSize = 12.sp)
                            }
                        }
                        if (onOffKnown) {
                        Spacer(Modifier.size(12.dp))
                        Switch(
                            checked = active,
                            // Ignore taps during a different operation without
                            // dimming the verified firewall switch.
                            onCheckedChange = { next ->
                                if (!busy) perform { client.changeProtection(next) }
                            },
                            enabled = state.rootReady,
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = Background,
                                checkedTrackColor = Mint,
                                uncheckedThumbColor = Muted,
                                uncheckedTrackColor = Border
                            )
                        )
                        }
                    }
                }
            }

            if (active && state.rootReady) {
                Surface(color = Panel, shape = RoundedCornerShape(18.dp),
                    modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(18.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                            modifier = Modifier.fillMaxWidth()) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text("Restore after reboot", fontSize = 16.sp,
                                    color = Foreground, fontWeight = FontWeight.SemiBold)
                                Text("Uses Magisk at startup. No background app.",
                                    fontSize = 12.sp, color = Muted)
                            }
                            // Only ENABLED and DISABLED are positions a switch can honestly show.
                            if (bootProblemText(state.bootRestore) == null) {
                            Switch(
                                checked = state.bootRestore == FirewallClient.BootRestore.ENABLED,
                                onCheckedChange = { next ->
                                    if (!busy) perform { client.changeBootRestoration(next) }
                                },
                                colors = SwitchDefaults.colors(
                                    checkedThumbColor = Background,
                                    checkedTrackColor = Mint,
                                    uncheckedThumbColor = Muted,
                                    uncheckedTrackColor = Border
                                )
                            )
                            }
                        }
                        bootProblemText(state.bootRestore)?.let { problem ->
                            Text(problem, color = Amber, fontSize = 12.sp)
                        }
                    }
                }
            }

            Surface(color = Panel, shape = RoundedCornerShape(22.dp), modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
                    Text("At a glance", fontWeight = FontWeight.SemiBold, fontSize = 17.sp,
                        modifier = Modifier.semantics { heading() })
                    // No root response can also mean a timeout or an internal failure.
                    StatusLine("Root access", if (state.rootReady) "Granted" else "Not confirmed", state.rootReady)
                    StatusLine("VPN", if (state.vpnActive) "Connected" else "Not detected", state.vpnActive)
                    StatusLine("Firewall policy", when {
                        verified -> "Rules verified"
                        onOffKnown -> "Not installed"
                        else -> "Not verified"
                    }, verified)
                    Text(
                        if (verified) {
                            "Allow outgoing traffic. Deny unsolicited incoming traffic on supported physical interfaces."
                        } else {
                            "When verified active, PocketUFW allows outgoing traffic and denies " +
                                "unsolicited incoming traffic on supported physical interfaces."
                        },
                        color = Muted, fontSize = 13.sp, lineHeight = 19.sp
                    )
                }
            }

            if (active) {
                val activity = counters
                val blockedSummary = when {
                    activity == null -> "Reading kernel counters…"
                    activity.measured -> NumberFormat.getIntegerInstance()
                        .format(activity.totalBlocked ?: 0L) + " packets matched DROP rules"
                    else -> "Counter verification unavailable"
                }
                Surface(
                    color = Panel,
                    shape = RoundedCornerShape(22.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier.padding(20.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .semantics {
                                    stateDescription = if (activityExpanded) "Expanded" else "Collapsed"
                                }
                                .clickable(role = Role.Button) { activityExpanded = !activityExpanded },
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text("Firewall activity", color = Foreground,
                                    fontSize = 17.sp, fontWeight = FontWeight.SemiBold)
                                Spacer(modifier = Modifier.height(5.dp))
                                Text(blockedSummary,
                                    color = if (activity?.measured == true) Mint else Muted,
                                    fontSize = 13.sp)
                            }
                            Text(
                                if (activityExpanded) "Hide ▲" else "Details ▼",
                                color = Mint, fontSize = 12.sp
                            )
                        }

                        if (activityExpanded) {
                            Box(
                                modifier = Modifier.fillMaxWidth().height(1.dp).background(Border)
                            )
                            if (activity?.measured == true) {
                                val fmt = NumberFormat.getIntegerInstance()
                                // Bytes aren't covered by measured, and null never becomes zero.
                                fun dropped(packets: Long?, bytes: Long?) =
                                    fmt.format(packets ?: 0L) + " packets · " +
                                        (bytes?.let { fmt.format(it) + " bytes" } ?: "bytes unavailable")
                                StatusLine("IPv4 dropped", dropped(activity.ipv4Blocked, activity.ipv4Bytes), true)
                                StatusLine("IPv6 dropped", dropped(activity.ipv6Blocked, activity.ipv6Bytes), true)
                                StatusLine("IPv4 established replies accepted",
                                    fmt.format(activity.ipv4Replies ?: 0L) + " packets", true)
                                StatusLine("IPv6 established replies accepted",
                                    fmt.format(activity.ipv6Replies ?: 0L) + " packets", true)
                                Text("Last checked: " + readingTime(activity.checkedAt),
                                    color = Muted, fontSize = 12.sp)
                                if (activity.lastManualResetAt > 0L) {
                                    val resetAt = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)
                                        .format(Date(activity.lastManualResetAt))
                                    Text("Last reset from this app: " + resetAt,
                                        color = Muted, fontSize = 12.sp)
                                }
                            } else {
                                Text(
                                    activity?.error ?: "Waiting for the kernel counter read.",
                                    color = Amber, fontSize = 13.sp, lineHeight = 19.sp
                                )
                            }

                            Text("Updated when opened or refreshed. Counts may stay unchanged.",
                                color = Muted, fontSize = 12.sp)
                            Text("Incoming: deny unsolicited on supported interfaces",
                                color = Foreground, fontSize = 12.sp)
                            Text("Outgoing: unchanged", color = Foreground, fontSize = 12.sp)
                            hookSummaryLines(kernelReport).forEach { line ->
                                Text(line, color = Muted, fontSize = 12.sp)
                            }
                            Text(
                                "These are real matches on PocketUFW rules, not detected attacks. Dropped adds " +
                                    "the INVALID and final DROP rules. Counts restart on reset or when rules are " +
                                    "rebuilt. PocketUFW doesn't record rule rebuilds, so the last reset may not be " +
                                    "when counting began. Earlier Android/OEM rules or other interfaces may " +
                                    "bypass these hooks.",
                                color = Muted, fontSize = 12.sp, lineHeight = 18.sp
                            )
                            OutlinedButton(
                                onClick = { refreshCounters() },
                                enabled = !busy && active && state.rootReady,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text(if (counterRefreshing) "Refreshing…" else "Refresh counters",
                                    fontSize = 13.sp)
                            }
                            if (counterRefreshNote.isNotEmpty()) {
                                Text(counterRefreshNote,
                                    color = if (counterRefreshError) Amber else Mint,
                                    fontSize = 12.sp, lineHeight = 17.sp)
                            } else {
                                // Hold the note's line so its arrival doesn't move Reset below it.
                                // Same text style, so the metrics match at every text size.
                                Text(" ", fontSize = 12.sp, lineHeight = 17.sp,
                                    modifier = Modifier.clearAndSetSemantics {})
                            }
                            OutlinedButton(
                                onClick = { resetConfirmOpen = true },
                                enabled = !busy && active && state.rootReady,
                                modifier = Modifier.fillMaxWidth()
                            ) { Text("Reset counters", fontSize = 13.sp) }
                        }
                    }
                }
            }

            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedButton(
                    onClick = { recheck() },
                    enabled = !busy,
                    modifier = Modifier.weight(1f)
                ) { Text(if (busy) "Working…" else "Recheck status", fontSize = 12.sp) }

                if (active) {
                    // The bridge refuses these modes, so don't spend a root request finding out.
                    val canRefresh = vpnRefreshBlockedReason(state.udpConfigMode) == null
                    Button(
                        onClick = {
                            if (!busy) {
                                vpnRefreshing = true
                                perform { client.refreshVerifiedPorts() }
                            }
                        },
                        enabled = !busy && canRefresh,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = Mint)
                    ) {
                        Text(if (vpnRefreshing) "Refreshing VPN…" else "Refresh VPN", fontSize = 12.sp,
                            color = if (canRefresh) Background else Muted)
                    }
                }
            }

            if (active) {
                vpnRefreshBlockedReason(state.udpConfigMode)?.let { reason ->
                    Text(reason, color = Muted, fontSize = 12.sp, lineHeight = 17.sp)
                }
            }

            if (state.protection == FirewallClient.Protection.DEGRADED && state.rootReady) {
                OutlinedButton(onClick = { removeConfirmOpen = true },
                    enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                    Text("Remove partial PocketUFW rules", color = Amber)
                }
            }

            Surface(
                color = Color(0xFF1C2326),
                shape = RoundedCornerShape(18.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("EXPERIMENTAL BUILD", fontSize = 11.sp, color = Amber, fontWeight = FontWeight.Bold)
                    Text(
                        "Kernel protection continues when the app closes. Optional Magisk boot " +
                            "restoration is available, but automatic repair and VPN monitoring " +
                            "are not yet implemented. Test devices only.",
                        color = Muted, fontSize = 13.sp, lineHeight = 19.sp
                    )
                }
            }

            } else {
                KernelStatusTab(
                    state, kernelReport, busy, verificationInDoubt,
                    recheck = { recheck() },
                    setUdpPorts = { ipv4, ipv6, committed ->
                        perform { client.updateUdpExceptions(ipv4, ipv6, committed) }
                    },
                    restoreAutomatic = { perform { client.restoreAutomaticUdpExceptions() } }
                )
            }

            Text(
                "PocketUFW · " + BuildConfig.VERSION_NAME + " · Local-only · No accounts or telemetry",
                modifier = Modifier.fillMaxWidth(),
                color = Muted.copy(alpha = 0.75f),
                fontSize = 11.sp,
                textAlign = TextAlign.Center
            )

            // Lets the page's end scroll clear of the banner. It only ever grows, and
            // sits below everything else, so neither showing nor dismissing a result
            // can move a control under someone's finger.
            if (bannerRoomPx > 0) {
                Spacer(modifier = Modifier.height(with(density) { bannerRoomPx.toDp() }))
            }
        }

        // A fixed place for results: always visible, and never inserted above a control.
        if (message.isNotEmpty()) {
            OperationResultBanner(
                message, failed,
                onDismiss = { message = "" },
                modifier = Modifier
                    .align(Alignment.BottomCenter)
                    .navigationBarsPadding()
                    .onSizeChanged { bannerRoomPx = maxOf(bannerRoomPx, it.height) }
                    .padding(12.dp)
            )
        }

        if (resetConfirmOpen) {
            val reading = counters?.takeIf { it.measured }
            AlertDialog(
                onDismissRequest = { resetConfirmOpen = false },
                title = { Text("Reset counters?") },
                text = {
                    val fmt = NumberFormat.getIntegerInstance()
                    Text("This zeroes PocketUFW's own packet and byte counters for IPv4 and IPv6. " +
                        "Firewall rules and VPN exceptions don't change." +
                        (reading?.let {
                            " The current dropped counts will be lost: IPv4 " +
                                fmt.format(it.ipv4Blocked ?: 0L) + ", IPv6 " +
                                fmt.format(it.ipv6Blocked ?: 0L) + "."
                        } ?: ""))
                },
                confirmButton = {
                    TextButton(onClick = {
                        resetConfirmOpen = false
                        perform { client.resetCounters() }
                    }) { Text("Reset") }
                },
                dismissButton = {
                    TextButton(onClick = { resetConfirmOpen = false }) { Text("Keep counts") }
                }
            )
        }
        if (removeConfirmOpen) {
            AlertDialog(
                onDismissRequest = { removeConfirmOpen = false },
                title = { Text("Remove partial PocketUFW rules?") },
                text = {
                    Text("This removes PocketUFW's chains and hooks from the kernel and disarms the " +
                        "Magisk boot hook. Any filtering they still provide stops. Android's own " +
                        "rules stay as they are. You can turn the firewall on again afterwards.")
                },
                confirmButton = {
                    TextButton(onClick = {
                        removeConfirmOpen = false
                        perform { client.changeProtection(false) }
                    }) { Text("Remove rules") }
                },
                dismissButton = {
                    TextButton(onClick = { removeConfirmOpen = false }) { Text("Cancel") }
                }
            )
        }
    } }
}

/** A reading can stay on screen for days, so anything not from today carries its date. */
internal fun readingTime(at: Long, now: Long = System.currentTimeMillis()): String {
    val day = { millis: Long ->
        Calendar.getInstance().apply { timeInMillis = millis }
            .let { it.get(Calendar.YEAR) to it.get(Calendar.DAY_OF_YEAR) }
    }
    val format = if (day(at) == day(now)) {
        DateFormat.getTimeInstance(DateFormat.MEDIUM)
    } else {
        DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.MEDIUM)
    }
    return format.format(Date(at))
}

/** Null when a switch can honestly show the state. Each problem needs a different response. */
internal fun bootProblemText(boot: FirewallClient.BootRestore): String? = when (boot) {
    FirewallClient.BootRestore.ENABLED, FirewallClient.BootRestore.DISABLED -> null
    FirewallClient.BootRestore.UNSUPPORTED -> "Magisk boot restoration isn't available on this device."
    FirewallClient.BootRestore.DEGRADED -> "The boot hook is incomplete, so restoring after reboot isn't verified."
    FirewallClient.BootRestore.CONFLICT -> "Something else owns the boot hook path. PocketUFW won't overwrite it."
    FirewallClient.BootRestore.UNKNOWN -> "Boot restoration status couldn't be read."
}

/** Null when Refresh VPN can run. These match the modes android-bridge refuses. */
internal fun vpnRefreshBlockedReason(mode: FirewallClient.UdpConfigMode): String? = when (mode) {
    FirewallClient.UdpConfigMode.COMMITTED ->
        "Refresh VPN is off because Committed ports are saved. Change them under Status."
    FirewallClient.UdpConfigMode.DEGRADED ->
        "Refresh VPN is off because the saved UDP setting needs inspection. See Status."
    else -> null
}

@Composable
private fun PocketTabButton(label: String, selected: Boolean, modifier: Modifier, onClick: () -> Unit) {
    val tab = modifier.semantics {
        role = Role.Tab
        this.selected = selected
    }
    if (selected) {
        Button(onClick = onClick, modifier = tab,
            colors = ButtonDefaults.buttonColors(containerColor = Mint)) {
            Text(label, color = Background)
        }
    } else {
        OutlinedButton(onClick = onClick, modifier = tab) { Text(label) }
    }
}

@Composable
private fun OperationResultBanner(text: String, failed: Boolean, onDismiss: () -> Unit, modifier: Modifier) {
    Surface(
        shape = RoundedCornerShape(14.dp),
        color = if (failed) Color(0xFF423025) else Color(0xFF23382E),
        shadowElevation = 6.dp,
        modifier = modifier.fillMaxWidth()
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(start = 16.dp, end = 6.dp, top = 6.dp, bottom = 6.dp)
        ) {
            Text(
                text,
                color = if (failed) Amber else Foreground,
                fontSize = 13.sp,
                lineHeight = 20.sp,
                modifier = Modifier.weight(1f).semantics { liveRegion = LiveRegionMode.Polite }
            )
            TextButton(onClick = onDismiss) { Text("Dismiss", color = Foreground, fontSize = 13.sp) }
        }
    }
}

@Composable
private fun StatusLine(label: String, value: String, positive: Boolean) {
    // A long count may wrap, but it can't squeeze its label out at large text sizes.
    BoxWithConstraints(modifier = Modifier.fillMaxWidth()) {
        val valueMaxWidth = maxWidth * 0.66f
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(label, color = Muted, fontSize = 13.sp, modifier = Modifier.weight(1f))
            Text(value, color = if (positive) Mint else Foreground, fontSize = 13.sp,
                textAlign = TextAlign.End, modifier = Modifier.widthIn(max = valueMaxWidth))
        }
    }
}
