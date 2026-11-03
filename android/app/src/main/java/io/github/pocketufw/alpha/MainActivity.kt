package io.github.pocketufw.alpha

import android.os.Bundle
import java.text.DateFormat
import java.text.NumberFormat
import java.util.Date
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
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
private fun PocketScreen(client: FirewallClient) {
    var state by remember { mutableStateOf(FirewallClient.Snapshot()) }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("") }
    var failed by remember { mutableStateOf(false) }
    var activityExpanded by remember { mutableStateOf(false) }
    var counters by remember { mutableStateOf<FirewallClient.RuleActivity?>(null) }
    var kernelReport by remember { mutableStateOf<FirewallClient.KernelReport?>(null) }
    var selectedTab by remember { mutableStateOf(PocketTab.HOME) }
    val scrollState = rememberScrollState()
    val scope = rememberCoroutineScope()

    LaunchedEffect(selectedTab) { scrollState.scrollTo(0) }

    LaunchedEffect(client) {
        val dashboard = withContext(Dispatchers.IO) { client.inspectDashboard() }
        state = dashboard.snapshot
        counters = dashboard.activity
        kernelReport = dashboard.kernelReport
    }

    fun perform(work: () -> FirewallClient.Operation) {
        if (busy) return
        busy = true
        scope.launch {
            val outcome = withContext(Dispatchers.IO) { work() }
            state = outcome.dashboard.snapshot
            counters = outcome.dashboard.activity
            kernelReport = outcome.dashboard.kernelReport
            failed = !outcome.success
            message = outcome.explanation
            busy = false
        }
    }

    fun recheck() {
        if (busy) return
        busy = true
        scope.launch {
            val dashboard = withContext(Dispatchers.IO) { client.inspectDashboard() }
            state = dashboard.snapshot
            counters = dashboard.activity
            kernelReport = dashboard.kernelReport
            message = ""
            failed = false
            busy = false
        }
    }

    // One intentional root request refreshes rules, boot status, and counters.
    fun refreshCounters() {
        if (busy || state.protection != FirewallClient.Protection.ACTIVE) return
        busy = true
        scope.launch {
            val dashboard = withContext(Dispatchers.IO) { client.inspectDashboard() }
            state = dashboard.snapshot
            counters = dashboard.activity
            kernelReport = dashboard.kernelReport
            busy = false
        }
    }

    val active = state.protection == FirewallClient.Protection.ACTIVE
    val attention = state.protection == FirewallClient.Protection.DEGRADED ||
        state.protection == FirewallClient.Protection.ROOT_REQUIRED
    val accent = when {
        active -> Mint
        attention -> Amber
        else -> Muted
    }
    val status = when (state.protection) {
        FirewallClient.Protection.CHECKING -> "Checking protection"
        FirewallClient.Protection.ACTIVE -> "Firewall active"
        FirewallClient.Protection.INACTIVE -> "PocketUFW is off"
        FirewallClient.Protection.DEGRADED -> "Needs attention"
        FirewallClient.Protection.ROOT_REQUIRED -> "Root permission needed"
    }

    Surface(modifier = Modifier.fillMaxSize(), color = Background) {
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

            Row(modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                if (selectedTab == PocketTab.HOME) {
                    Button(onClick = { selectedTab = PocketTab.HOME },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = Mint)) {
                        Text("Home", color = Background)
                    }
                } else {
                    OutlinedButton(onClick = { selectedTab = PocketTab.HOME },
                        modifier = Modifier.weight(1f)) { Text("Home") }
                }
                if (selectedTab == PocketTab.STATUS) {
                    Button(onClick = { selectedTab = PocketTab.STATUS },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = Mint)) {
                        Text("Status", color = Background)
                    }
                } else {
                    OutlinedButton(onClick = { selectedTab = PocketTab.STATUS },
                        modifier = Modifier.weight(1f)) { Text("Status") }
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
                    color = if (active) Mint.copy(alpha = 0.65f) else Border,
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
                            text = if (active) "RULES VERIFIED" else if (attention) "CHECK REQUIRED" else "NOT ACTIVE",
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
                            Text(status, fontSize = 24.sp, fontWeight = FontWeight.SemiBold, color = Foreground)
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                state.details.ifEmpty { "Reading Android's firewall rules…" },
                                color = Muted, fontSize = 13.sp, lineHeight = 19.sp
                            )
                        }
                        Spacer(Modifier.size(12.dp))
                        Switch(
                            checked = active,
                            // Ignore taps during a different operation without
                            // dimming the verified firewall switch.
                            onCheckedChange = { next ->
                                if (!busy) perform { client.changeProtection(next) }
                            },
                            enabled = state.rootReady && !attention &&
                                state.protection != FirewallClient.Protection.CHECKING,
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
                            Switch(
                                checked = state.bootRestore == FirewallClient.BootRestore.ENABLED,
                                onCheckedChange = { next ->
                                    if (!busy) perform { client.changeBootRestoration(next) }
                                },
                                enabled = (state.bootRestore ==
                                    FirewallClient.BootRestore.ENABLED ||
                                    state.bootRestore == FirewallClient.BootRestore.DISABLED),
                                colors = SwitchDefaults.colors(
                                    checkedThumbColor = Background,
                                    checkedTrackColor = Mint,
                                    uncheckedThumbColor = Muted,
                                    uncheckedTrackColor = Border
                                )
                            )
                        }
                        if (state.bootRestore !in listOf(
                                FirewallClient.BootRestore.ENABLED,
                                FirewallClient.BootRestore.DISABLED
                            )) {
                            Text("Magisk boot restoration unavailable or needs inspection.",
                                color = Amber, fontSize = 12.sp)
                        }
                    }
                }
            }

            if (message.isNotEmpty()) {
                Surface(
                    shape = RoundedCornerShape(14.dp),
                    color = if (failed) Color(0xFF423025) else Color(0xFF23382E),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        message,
                        color = if (failed) Amber else Foreground,
                        fontSize = 13.sp,
                        lineHeight = 20.sp,
                        modifier = Modifier.padding(16.dp)
                    )
                }
            }

            Surface(color = Panel, shape = RoundedCornerShape(22.dp), modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
                    Text("At a glance", fontWeight = FontWeight.SemiBold, fontSize = 17.sp)
                    StatusLine("Root access", if (state.rootReady) "Granted" else "Not granted", state.rootReady)
                    StatusLine("VPN", if (state.vpnActive) "Connected" else "Not detected", state.vpnActive)
                    StatusLine("Firewall policy", if (active) "Rules verified" else "Not verified", active)
                    Text(
                        "Allow outgoing traffic. Deny unsolicited incoming traffic on supported physical interfaces.",
                        color = Muted, fontSize = 13.sp, lineHeight = 19.sp
                    )
                }
            }

            if (active) {
                val activity = counters
                val blockedSummary = when {
                    activity == null -> "Reading kernel counters…"
                    activity.measured -> NumberFormat.getIntegerInstance()
                        .format(activity.totalBlocked ?: 0L) + " incoming packets blocked"
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
                                .clickable { activityExpanded = !activityExpanded },
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
                                StatusLine("IPv4 dropped",
                                    fmt.format(activity.ipv4Blocked ?: 0L) + " packets", true)
                                StatusLine("IPv6 dropped",
                                    fmt.format(activity.ipv6Blocked ?: 0L) + " packets", true)
                                StatusLine("Established replies accepted",
                                    fmt.format(activity.totalReplies ?: 0L) + " packets", true)
                                val checked = DateFormat.getTimeInstance(DateFormat.SHORT)
                                    .format(Date(activity.checkedAt))
                                Text("Last checked: " + checked, color = Muted, fontSize = 12.sp)
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
                            Text("Hooks: wlan+, rmnet+, v4-rmnet+",
                                color = Muted, fontSize = 12.sp)
                            Text(
                                "These are real matches on PocketUFW rules, not detected attacks. " +
                                    "Counts reset when rules are reinstalled. Earlier Android/OEM " +
                                    "rules or other interfaces may bypass these hooks.",
                                color = Muted, fontSize = 12.sp, lineHeight = 18.sp
                            )
                            OutlinedButton(
                                onClick = { refreshCounters() },
                                enabled = !busy,
                                modifier = Modifier.fillMaxWidth()
                            ) { Text("Refresh counters", fontSize = 13.sp) }
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
                    Button(
                        onClick = { perform { client.refreshVerifiedPorts() } },
                        enabled = !busy,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = Mint)
                    ) { Text("Refresh VPN", fontSize = 12.sp, color = Background) }
                }
            }

            if (state.protection == FirewallClient.Protection.DEGRADED && state.rootReady) {
                OutlinedButton(onClick = {
                    perform { client.changeProtection(false) }
                }, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
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
                    state, kernelReport, busy,
                    recheck = { recheck() },
                    setUdpPorts = { ipv4, ipv6, committed ->
                        perform { client.updateUdpExceptions(ipv4, ipv6, committed) }
                    },
                    restoreAutomatic = { perform { client.restoreAutomaticUdpExceptions() } }
                )
                if (message.isNotEmpty()) {
                    Surface(
                        color = if (failed) Color(0xFF423025) else Color(0xFF23382E),
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(message, color = if (failed) Amber else Foreground,
                            modifier = Modifier.padding(16.dp),
                            fontSize = 13.sp, lineHeight = 19.sp)
                    }
                }
            }

            Text(
                "PocketUFW · " + BuildConfig.VERSION_NAME + " · Local-only · No accounts or telemetry",
                modifier = Modifier.fillMaxWidth(),
                color = Muted.copy(alpha = 0.75f),
                fontSize = 11.sp,
                textAlign = TextAlign.Center
            )
        }
    }
}

@Composable
private fun StatusLine(label: String, value: String, positive: Boolean) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, color = Muted, fontSize = 13.sp)
        Text(value, color = if (positive) Mint else Foreground, fontSize = 13.sp)
    }
}
