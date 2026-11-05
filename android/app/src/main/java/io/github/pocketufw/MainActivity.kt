package io.github.pocketufw

import android.content.SharedPreferences
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalWindowInfo
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * A superseded read gets read again, but a run of them must not become a root loop.
 * Past this the screen stays "Recheck required" until the next explicit recheck.
 */
private const val MAX_SUPERSEDED_RECHECKS = 2

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            TideTheme {
                PocketScreen(remember { FirewallClient(applicationContext) })
            }
        }
    }
}

/**
 * Authoritative firewall state and user operations. Tide owns only presentation.
 * No change is made to the tile, boot scripts, netfilter engine, or root behavior.
 *
 * Exposed to JVM tests through FirewallGateway rather than running root commands.
 */
@Composable
internal fun PocketScreen(client: FirewallGateway) {
    var state by remember { mutableStateOf(FirewallClient.Snapshot()) }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("") }
    var failed by remember { mutableStateOf(false) }
    var counters by remember { mutableStateOf<FirewallClient.RuleActivity?>(null) }
    var counterRefreshing by remember { mutableStateOf(false) }
    var counterRefreshNote by remember { mutableStateOf("") }
    var counterRefreshError by remember { mutableStateOf(false) }
    var kernelReport by remember { mutableStateOf<FirewallClient.KernelReport?>(null) }
    var checkedAt by remember { mutableStateOf(0L) }
    var tileStamp by remember { mutableStateOf<Long?>(null) }
    var verificationInDoubt by remember { mutableStateOf(false) }
    var vpnRefreshing by remember { mutableStateOf(false) }
    var firstRead by remember { mutableStateOf(true) }
    var outsideWritePending by remember { mutableStateOf(false) }
    var supersededRechecks by remember { mutableStateOf(0) }

    // Preserve Claude's tested guarantee that observable UI state is written
    // on the main dispatcher, even under Robolectric's unusual test scheduler.
    val scope = rememberCoroutineScope { Dispatchers.Main.immediate }
    val context = LocalContext.current.applicationContext
    val windowInfo = LocalWindowInfo.current

    suspend fun adopt(dashboard: FirewallClient.Dashboard) {
        // Read the stamp before publishing state, so a subsequent focus check
        // cannot pair a new verification time with an old tile stamp.
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

    /**
     * Called when a root request ends. Decides whether what's on screen can stand:
     * true means read again, because the tile wrote meanwhile or this read lost to
     * a newer one. Until that read lands the old status isn't claimed as verified.
     */
    fun needsAnotherRead(finished: FirewallClient.Dashboard?): Boolean {
        val outsideWrite = outsideWritePending
        outsideWritePending = false
        val superseded = finished?.superseded == true
        supersededRechecks = if (superseded) supersededRechecks + 1 else 0
        if (outsideWrite || superseded) verificationInDoubt = true
        return outsideWrite || (superseded && supersededRechecks <= MAX_SUPERSEDED_RECHECKS)
    }

    /** With [keepResult], the banner still belongs to the operation this read follows. */
    fun recheck(showFeedback: Boolean = false, keepResult: Boolean = false) {
        if (busy) return
        busy = true
        if (!keepResult) message = ""
        counterRefreshNote = ""
        scope.launch {
            var finished: FirewallClient.Dashboard? = null
            try {
                val inspected = withContext(Dispatchers.IO) { client.inspectDashboard() }
                finished = inspected
                adopt(inspected)
                val snapshot = inspected.snapshot
                // Only user-requested rechecks get feedback. Automatic tile/focus
                // synchronization remains silent and does not add root requests.
                if (showFeedback) message = when {
                    snapshot.protection == FirewallClient.Protection.ROOT_REQUIRED ||
                        (!snapshot.rootReady && snapshot.details.isEmpty()) ->
                        "Couldn't check the firewall without root access."
                    // Timed out or failed to run: missing root isn't what happened.
                    !snapshot.rootReady -> snapshot.details
                    snapshot.protection == FirewallClient.Protection.ACTIVE ->
                        "Firewall status rechecked. No rules changed."
                    snapshot.protection == FirewallClient.Protection.INACTIVE ->
                        "Firewall is off. No rules changed."
                    else ->
                        "Status checked, but protection is not verified. No rules changed."
                } else if (!keepResult) message = ""
                val verifiedState = snapshot.protection in listOf(
                    FirewallClient.Protection.ACTIVE, FirewallClient.Protection.INACTIVE)
                failed = !verifiedState || (keepResult && failed)
            } catch (_: Exception) {
                verificationInDoubt = true
                failed = true
                message = "Live firewall state could not be verified."
            } finally {
                busy = false
            }
            if (needsAnotherRead(finished)) recheck(showFeedback, keepResult)
        }
    }

    fun perform(vpn: Boolean = false, work: () -> FirewallClient.Operation) {
        if (busy) return
        busy = true
        message = ""
        counterRefreshNote = ""
        vpnRefreshing = vpn
        scope.launch {
            var finished: FirewallClient.Dashboard? = null
            try {
                val outcome = withContext(Dispatchers.IO) { work() }
                finished = outcome.dashboard
                adopt(outcome.dashboard)
                failed = !outcome.success
                message = outcome.explanation
            } catch (_: Exception) {
                verificationInDoubt = true
                failed = true
                message = "Firewall operation could not be verified. Recheck kernel state."
            } finally {
                busy = false
                vpnRefreshing = false
            }
            if (needsAnotherRead(finished)) recheck(keepResult = true)
        }
    }

    LaunchedEffect(client) {
        var finished: FirewallClient.Dashboard? = null
        try {
            val inspected = withContext(Dispatchers.IO) { client.inspectDashboard() }
            finished = inspected
            adopt(inspected)
        } catch (_: Exception) {
            verificationInDoubt = true
            failed = true
            message = "Could not inspect live firewall state. Check root access and try again."
        }
        firstRead = false
        if (needsAnotherRead(finished)) recheck(keepResult = true)
    }

    // A tile result can land after focus has already returned: a tile switch takes
    // seconds and the shade closes sooner. Without this the app stays on "Active."
    // with the firewall off. The listener itself requests no root; an unfocused
    // window is left to the focus check below.
    DisposableEffect(context, client) {
        val preferences = TileStatusStore.preferences(context)
        val listener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
            if (key == TileStatusStore.WRITTEN_AT &&
                TileStatusStore.lastWriteSource(context) != TileStatusStore.SOURCE_APP) {
                if (busy || firstRead) {
                    outsideWritePending = true
                } else if (windowInfo.isWindowFocused) {
                    verificationInDoubt = true
                    recheck()
                }
            }
        }
        preferences.registerOnSharedPreferenceChangeListener(listener)
        onDispose { preferences.unregisterOnSharedPreferenceChangeListener(listener) }
    }

    // Shade-open never requests root. Regaining focus inspects the inexpensive
    // tile status cache first; root is requested ONLY when that stamp changed.
    LaunchedEffect(windowInfo) {
        snapshotFlow { windowInfo.isWindowFocused }.filter { it }.collect {
            // Keep reads and subsequent state changes on the main dispatcher.
            // This matches the original audited behavior under JVM Compose.
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

    // Read-only counter refresh. Failure invalidates a verified claim but
    // retains the last measured values instead of silently showing zero.
    fun refreshCounters() {
        if (busy || verificationInDoubt || state.protection != FirewallClient.Protection.ACTIVE) return
        busy = true
        counterRefreshing = true
        // Clear the last result, or it would hide this one and lend it its color.
        message = ""
        failed = false
        counterRefreshNote = ""
        scope.launch {
            try {
                val fresh = withContext(Dispatchers.IO) { client.refreshCounterActivity() }
                if (fresh.measured) {
                    counters = fresh
                    checkedAt = fresh.checkedAt
                    verificationInDoubt = false
                    counterRefreshError = false
                    val whenChecked = DateFormat.getTimeInstance(DateFormat.MEDIUM)
                        .format(Date(fresh.checkedAt))
                    counterRefreshNote = "Counters refreshed at $whenChecked"
                } else {
                    counterRefreshError = true
                    verificationInDoubt = true
                    counterRefreshNote = fresh.error ?: "Counter refresh failed; previous counts kept."
                }
            } catch (_: Exception) {
                verificationInDoubt = true
                counterRefreshError = true
                counterRefreshNote = "Counter refresh failed; previous counts kept."
            } finally {
                counterRefreshing = false
                busy = false
            }
            if (needsAnotherRead(null)) recheck(keepResult = true)
        }
    }

    val verifiedActive = state.protection == FirewallClient.Protection.ACTIVE && !verificationInDoubt

    TideScreen(
        ui = TideUiState(
            snapshot = state, counters = counters, report = kernelReport,
            busy = busy, message = message, failed = failed,
            counterRefreshing = counterRefreshing, counterRefreshNote = counterRefreshNote,
            counterRefreshError = counterRefreshError, verificationInDoubt = verificationInDoubt,
            checkedAt = checkedAt, vpnRefreshing = vpnRefreshing
        ),
        appVersion = BuildConfig.VERSION_NAME,
        actions = TideActions(
            recheck = { recheck(showFeedback = true) },
            changeProtection = { next ->
                if (!busy && !verificationInDoubt && state.rootReady &&
                    state.protection in listOf(
                        FirewallClient.Protection.ACTIVE, FirewallClient.Protection.INACTIVE
                    )) perform { client.changeProtection(next) }
            },
            changeBootRestoration = { next ->
                if (!busy && verifiedActive && state.bootRestore in listOf(
                        FirewallClient.BootRestore.ENABLED, FirewallClient.BootRestore.DISABLED
                    )) perform { client.changeBootRestoration(next) }
            },
            refreshCounters = { refreshCounters() },
            resetCounters = {
                if (!busy && verifiedActive && state.rootReady) {
                    perform { client.resetCounters() }
                }
            },
            refreshVpn = {
                if (!busy && verifiedActive &&
                    state.udpConfigMode == FirewallClient.UdpConfigMode.AUTOMATIC) {
                    perform(vpn = true) { client.refreshVerifiedPorts() }
                }
            },
            removePartialRules = {
                if (!busy && !verificationInDoubt && state.rootReady &&
                    state.protection == FirewallClient.Protection.DEGRADED) {
                    perform { client.removePartialRules() }
                }
            },
            setUdpPorts = { ipv4, ipv6, committed ->
                if (verifiedActive && !busy) perform {
                    client.updateUdpExceptions(ipv4, ipv6, committed)
                }
            },
            restoreAutomatic = {
                if (verifiedActive && !busy) perform {
                    client.restoreAutomaticUdpExceptions()
                }
            },
            dismissMessage = {
                message = ""
                failed = false
                counterRefreshNote = ""
                counterRefreshError = false
            }
        )
    )
}
