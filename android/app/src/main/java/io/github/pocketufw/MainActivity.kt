package io.github.pocketufw

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.Uri
import android.provider.Settings
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
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.Lifecycle
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.CancellationException
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
    // Instance-scoped seam for lifecycle/input tests; production always uses FirewallClient.
    internal var newClient: (Context) -> FirewallGateway = { FirewallClient(it) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            TideTheme {
                PocketScreen(remember { newClient(applicationContext) })
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        // Both entry points only bring the existing screen forward. In particular, never
        // rebuild its composition, clear busy, or interpret a launch as a firewall action.
        setIntent(intent)
    }
}

/**
 * Authoritative firewall state and user operations. Tide owns only presentation.
 * Existing firewall operations retain their gateway; Insights adds a bounded root sample.
 *
 * Exposed to JVM tests through FirewallGateway rather than running root commands.
 */
@Composable
internal fun PocketScreen(client: FirewallGateway, openAppInfo: ((Context) -> Boolean) = ::openAndroidAppInfo) {
    var state by remember { mutableStateOf(FirewallClient.Snapshot()) }
    var busy by remember { mutableStateOf(false) }
    var operation by remember { mutableStateOf<TideOperation?>(null) }
    var message by remember { mutableStateOf("") }
    var transientMessage by remember { mutableStateOf(false) }
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
    var removal by remember { mutableStateOf(TideRemoval.NONE) }
    var insights by remember { mutableStateOf<InsightsResult?>(null) }
    var insightsRequest by remember { mutableStateOf<InsightsRequest?>(null) }
    var insightsStopping by remember { mutableStateOf(false) }
    var removalDetail by remember { mutableStateOf("") }

    // Preserve Claude's tested guarantee that observable UI state is written
    // on the main dispatcher, even under Robolectric's unusual test scheduler.
    val scope = rememberCoroutineScope { Dispatchers.Main.immediate }
    val context = LocalContext.current.applicationContext
    val windowInfo = LocalWindowInfo.current
    val lifecycle = LocalLifecycleOwner.current.lifecycle

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
        // "It's all gone" stops being true as soon as the firewall is back, by any route.
        if (removal == TideRemoval.CLEAN &&
            dashboard.snapshot.protection != FirewallClient.Protection.INACTIVE) removal = TideRemoval.NONE
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
        operation = TideOperation.CHECK
        if (!keepResult) {
            message = ""
            transientMessage = false
        }
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
                if (showFeedback) transientMessage = verifiedState && snapshot.rootReady
            } catch (error: Exception) {
                verificationInDoubt = true
                failed = true
                message = "Live firewall state could not be verified."
                if (error is CancellationException) throw error
            } finally {
                busy = false
                operation = null
            }
            if (needsAnotherRead(finished)) recheck(showFeedback, keepResult)
        }
    }

    /** App info needs no permission, and can't exist on every build of Android. */
    fun showAppInfo() {
        if (!openAppInfo(context)) {
            failed = true
            message = "Android's app page didn't open. Go to Settings, then Apps, then PocketUFW, and tap Uninstall."
        }
    }

    fun perform(kind: TideOperation? = null, vpn: Boolean = false, transientSuccess: Boolean = false,
                onResult: (FirewallClient.Operation?) -> Unit = {},
                work: () -> FirewallClient.Operation) {
        // A retained callback from a paused screen cannot authorize a new mutation.
        // Already-started work keeps its busy guard and completes normally across relaunches.
        if (busy || !lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) return
        busy = true
        operation = kind
        message = ""
        transientMessage = false
        counterRefreshNote = ""
        vpnRefreshing = vpn
        // Any new operation makes an earlier removal result out of date.
        removal = TideRemoval.NONE
        removalDetail = ""
        scope.launch {
            var finished: FirewallClient.Dashboard? = null
            try {
                val outcome = withContext(Dispatchers.IO) { work() }
                finished = outcome.dashboard
                adopt(outcome.dashboard)
                failed = !outcome.success
                message = outcome.explanation
                transientMessage = transientSuccess && outcome.success
                onResult(outcome)
            } catch (error: Exception) {
                verificationInDoubt = true
                failed = true
                message = "Firewall operation could not be verified. Recheck kernel state."
                onResult(null)
                if (error is CancellationException) throw error
            } finally {
                busy = false
                operation = null
                vpnRefreshing = false
            }
            if (needsAnotherRead(finished)) recheck(keepResult = true)
        }
    }

    fun sampleDrops(recovery: Boolean = false) {
        if (busy || firstRead || !state.rootReady || !lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) return
        if (!recovery && (verificationInDoubt || state.protection != FirewallClient.Protection.ACTIVE)) return
        val request = InsightsRequest()
        insightsRequest = request
        insightsStopping = false
        busy = true
        operation = if (recovery) TideOperation.RECOVER_INSIGHTS else TideOperation.SAMPLE
        insights = null
        scope.launch {
            try {
                insights = withContext(Dispatchers.IO) { client.inspectDrops(request, recovery) }
                // A cleanup failure must never leave a stale verified protection claim.
                verificationInDoubt = true
            } catch (error: Exception) {
                verificationInDoubt = true
                insights = InsightsResult(error = "Insights interrupted. Recheck status and recover leftover probes if needed.")
                if (error is CancellationException) throw error
            } finally {
                request.cancel()
                insightsRequest = null
                insightsStopping = false
                busy = false
                operation = null
            }
            // Refresh existing counter/status views once, after the helper released both locks.
            recheck()
        }
    }

    DisposableEffect(client, lifecycle) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP && insightsRequest != null) { insightsRequest?.cancel(); insightsStopping = true }
        }
        lifecycle.addObserver(observer)
        onDispose { lifecycle.removeObserver(observer); insightsRequest?.cancel() }
    }

    LaunchedEffect(client) {
        var finished: FirewallClient.Dashboard? = null
        try {
            val inspected = withContext(Dispatchers.IO) { client.inspectDashboard() }
            finished = inspected
            adopt(inspected)
        } catch (error: Exception) {
            verificationInDoubt = true
            failed = true
            message = "Could not inspect live firewall state. Check root access and try again."
            if (error is CancellationException) throw error
        } finally {
            firstRead = false
        }
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
        operation = TideOperation.REFRESH_COUNTERS
        counterRefreshing = true
        // Clear the last result, or it would hide this one and lend it its color.
        message = ""
        transientMessage = false
        failed = false
        counterRefreshNote = ""
        scope.launch {
            try {
                val fresh = withContext(Dispatchers.IO) { client.refreshCounterActivity() }
                if (fresh.measured) {
                    counters = fresh
                    checkedAt = fresh.checkedAt
                    // Counter reads verify enforcement but do not probe ownership. A mode
                    // or pin change must not inherit the previous full inspection's proof.
                    val tunnelChanged = fresh.tunnelFilter != state.tunnelFilter ||
                        fresh.tunnelMode != state.tunnelMode || fresh.tailnetPin4 != state.tailnetPin4 ||
                        fresh.tailnetPin6 != state.tailnetPin6
                    verificationInDoubt = tunnelChanged
                    counterRefreshError = tunnelChanged
                    transientMessage = !tunnelChanged
                    val whenChecked = DateFormat.getTimeInstance(DateFormat.MEDIUM)
                        .format(Date(fresh.checkedAt))
                    counterRefreshNote = if (tunnelChanged) "Counters read, but tunnel policy changed. Recheck status to verify current authorization."
                        else "Counters refreshed at $whenChecked"
                } else {
                    counterRefreshError = true
                    verificationInDoubt = true
                    counterRefreshNote = fresh.error ?: "Counter refresh failed; previous counts kept."
                }
            } catch (error: Exception) {
                verificationInDoubt = true
                counterRefreshError = true
                counterRefreshNote = "Counter refresh failed; previous counts kept."
                if (error is CancellationException) throw error
            } finally {
                counterRefreshing = false
                busy = false
                operation = null
            }
            if (needsAnotherRead(null)) recheck(keepResult = true)
        }
    }

    val verifiedActive = state.protection == FirewallClient.Protection.ACTIVE && !verificationInDoubt

    TideScreen(
        ui = TideUiState(
            snapshot = state, counters = counters, report = kernelReport,
            busy = busy, operation = operation, message = message, failed = failed, transientMessage = transientMessage,
            counterRefreshing = counterRefreshing, counterRefreshNote = counterRefreshNote,
            counterRefreshError = counterRefreshError, verificationInDoubt = verificationInDoubt,
            checkedAt = checkedAt, vpnRefreshing = vpnRefreshing,
            insights = insights, insightsStopping = insightsStopping,
            removal = removal, removalDetail = removalDetail
        ),
        appVersion = BuildConfig.VERSION_NAME,
        actions = TideActions(
            sampleDrops = { sampleDrops() },
            cancelSample = { insightsStopping = true; insightsRequest?.cancel() },
            recoverInsights = { sampleDrops(recovery = true) },
            clearInsights = { if (!busy) insights = null },
            recheck = { recheck(showFeedback = true) },
            changeProtection = { next ->
                if (!busy && !verificationInDoubt && state.rootReady &&
                    state.protection in listOf(
                        FirewallClient.Protection.ACTIVE, FirewallClient.Protection.INACTIVE
                    )) perform(if (next) TideOperation.ACTIVATE else TideOperation.DEACTIVATE) { client.changeProtection(next) }
            },
            changeBootRestoration = { next ->
                if (!busy && verifiedActive && state.bootRestore in listOf(
                        FirewallClient.BootRestore.ENABLED, FirewallClient.BootRestore.DISABLED
                    )) perform(if (next) TideOperation.ENABLE_BOOT else TideOperation.DISABLE_BOOT,
                        onResult = { outcome ->
                            val expected = if (next) FirewallClient.BootRestore.ENABLED else FirewallClient.BootRestore.DISABLED
                            // The gateway already reads boot status back. A command's success alone
                            // cannot confirm this setting, especially if another write superseded it.
                            val verified = outcome?.success == true && outcome.dashboard.snapshot.rootReady &&
                                outcome.dashboard.snapshot.bootRestore == expected &&
                                !outcome.dashboard.superseded && !outsideWritePending
                            failed = !verified
                            message = when {
                                verified -> "Restore after reboot ${if (next) "enabled" else "disabled"}."
                                // The bridge can retain its command message when final read-back fails.
                                outcome?.success == false && outcome.explanation !in setOf(
                                    "Magisk boot restoration enabled.", "Boot restoration disabled; live firewall unchanged."
                                ) ->
                                    "Could not ${if (next) "enable" else "disable"} restore after reboot. " +
                                        outcome.explanation + " Recheck status before trying again."
                                else -> "Restore after reboot could not be verified. Recheck status before trying again."
                            }
                        }) { client.changeBootRestoration(next) }
            },
            refreshCounters = { refreshCounters() },
            resetCounters = {
                if (!busy && verifiedActive && state.rootReady) {
                    perform(TideOperation.RESET_COUNTERS, transientSuccess = true) { client.resetCounters() }
                }
            },
            refreshVpn = {
                if (!busy && verifiedActive &&
                    state.udpConfigMode == FirewallClient.UdpConfigMode.AUTOMATIC) {
                    perform(TideOperation.REFRESH_PORTS, vpn = true) { client.refreshVerifiedPorts() }
                }
            },
            removeTunnelRules = {
                if (!busy && !verificationInDoubt && state.rootReady &&
                    state.tunnelFilter in setOf(FirewallClient.TunnelFilter.ON, FirewallClient.TunnelFilter.DEGRADED)) {
                    perform(TideOperation.REMOVE_TUNNEL) { client.removeTunnelRules() }
                }
            },
            enableTunnelProtection = { mode ->
                if (!busy && verifiedActive && state.rootReady &&
                    state.tunnelFilter == FirewallClient.TunnelFilter.OFF &&
                    mode in setOf(FirewallClient.TunnelMode.PINNED, FirewallClient.TunnelMode.DENY_ONLY)) {
                    perform(if (mode == FirewallClient.TunnelMode.PINNED) TideOperation.ENABLE_PINNED
                        else TideOperation.ENABLE_DENY_ONLY) { client.enableTunnelProtection(mode) }
                }
            },
            refreshTunnelHooks = {
                if (!busy && verifiedActive && state.rootReady && state.tunnelFilter == FirewallClient.TunnelFilter.ON) {
                    perform(TideOperation.REFRESH_TUNNEL) { client.refreshTunnelHooks() }
                }
            },
            removePartialRules = {
                if (!busy && !verificationInDoubt && state.rootReady &&
                    state.protection == FirewallClient.Protection.DEGRADED) {
                    perform(TideOperation.REMOVE_PARTIAL) { client.removePartialRules() }
                }
            },
            prepareUninstall = {
                if (!busy) perform(onResult = { outcome ->
                    if (outcome?.removalClean == true) {
                        removal = TideRemoval.CLEAN
                        removalDetail = outcome.explanation
                        message = ""
                        // Android's page opens only after the read-back found nothing left.
                        showAppInfo()
                    } else {
                        removal = TideRemoval.INCOMPLETE
                        removalDetail = outcome?.explanation ?: message
                        message = "Removal isn't finished."
                    }
                }) { client.prepareUninstall() }
            },
            openAppInfo = { showAppInfo() },
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
                transientMessage = false
                failed = false
                counterRefreshNote = ""
                counterRefreshError = false
            }
        )
    )
}

/** Android's own page for this app, where the user taps Uninstall. Asks for no permission. */
internal fun openAndroidAppInfo(context: Context): Boolean = try {
    context.startActivity(
        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", context.packageName, null))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    )
    true
} catch (_: ActivityNotFoundException) {
    false
}
