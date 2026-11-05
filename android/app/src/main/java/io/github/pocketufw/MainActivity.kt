package io.github.pocketufw

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

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

@Composable
private fun PocketScreen(client: FirewallClient) {
    var state by remember { mutableStateOf(FirewallClient.Snapshot()) }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("") }
    var failed by remember { mutableStateOf(false) }
    var counters by remember { mutableStateOf<FirewallClient.RuleActivity?>(null) }
    var counterRefreshing by remember { mutableStateOf(false) }
    var counterRefreshNote by remember { mutableStateOf("") }
    var counterRefreshError by remember { mutableStateOf(false) }
    var kernelReport by remember { mutableStateOf<FirewallClient.KernelReport?>(null) }
    val scope = rememberCoroutineScope()


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
                    val whenChecked = DateFormat.getTimeInstance(DateFormat.MEDIUM)
                        .format(Date(fresh.checkedAt))
                    counterRefreshNote = "Counters refreshed at $whenChecked"
                } else {
                    // Preserve the last verified measurement instead of showing zeros.
                    counterRefreshError = true
                    counterRefreshNote = fresh.error ?: "Counter refresh failed; previous counts kept."
                }
            } catch (e: Exception) {
                counterRefreshError = true
                counterRefreshNote = "Counter refresh failed; previous counts kept."
            } finally {
                counterRefreshing = false
                busy = false
            }
        }
    }

    TideScreen(
        ui = TideUiState(state, counters, kernelReport, busy, message, failed,
            counterRefreshing, counterRefreshNote, counterRefreshError),
        appVersion = BuildConfig.VERSION_NAME,
        actions = TideActions(
            recheck = { recheck() },
            changeProtection = { next ->
                if (!busy && state.rootReady && state.protection in listOf(
                        FirewallClient.Protection.ACTIVE, FirewallClient.Protection.INACTIVE)) {
                    perform { client.changeProtection(next) }
                }
            },
            changeBootRestoration = { next ->
                if (!busy) perform { client.changeBootRestoration(next) }
            },
            refreshCounters = { refreshCounters() },
            resetCounters = {
                if (!busy && state.rootReady && state.protection == FirewallClient.Protection.ACTIVE) {
                    perform { client.resetCounters() }
                }
            },
            refreshVpn = { perform { client.refreshVerifiedPorts() } },
            removePartialRules = { perform { client.changeProtection(false) } },
            setUdpPorts = { ipv4, ipv6, committed ->
                perform { client.updateUdpExceptions(ipv4, ipv6, committed) }
            },
            restoreAutomatic = { perform { client.restoreAutomaticUdpExceptions() } }
        )
    )
}
