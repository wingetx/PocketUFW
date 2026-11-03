package io.github.pocketufw.alpha

import android.graphics.drawable.Icon
import android.os.Build
import android.os.SystemClock
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.widget.Toast
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * Optional Android-managed Quick Settings switch. No foreground service,
 * resident listener, scheduled checks, or stale "protected" status.
 * Opening Quick Settings checks the live kernel once; tapping toggles from a
 * fresh root verification, never the previous tile color.
 */
class FirewallTileService : TileService() {
    private val client by lazy { FirewallClient(applicationContext) }
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val rootMutex = Mutex()
    private var listening = false
    private var toggling = false
    private var generation = 0L
    private var inspectionJob: Job? = null
    private var lastChecked: FirewallClient.Protection? = null
    private var lastCheckedElapsed = 0L

    // A brief shade collapse/reopen should not spawn another Magisk session.
    // A tile tap ALWAYS uses its own fresh, kernel-verified root action.
    private val quickReopenGraceMs = 5_000L

    override fun onStartListening() {
        super.onStartListening()
        if (listening) return // Android may repeat this callback while visible.
        listening = true
        if (toggling) {
            show(FirewallClient.Protection.CHECKING, switching = true)
            return
        }

        // Use a recently verified result only for rapid shade reopenings.
        // The age label makes clear this is NOT a new live inspection.
        val ageMs = SystemClock.elapsedRealtime() - lastCheckedElapsed
        val recent = lastChecked
        if (recent != null && ageMs in 0..quickReopenGraceMs) {
            show(recent, checkedAgoSeconds = ageMs / 1_000)
            return
        }

        // CHECKING updates the subtitle but never changes the on/off tint.
        show(FirewallClient.Protection.CHECKING)
        if (inspectionJob?.isActive == true) return // Reuse the pending result.
        val ticket = ++generation
        inspectionJob = scope.launch {
            val dashboard = withContext(Dispatchers.IO) {
                rootMutex.withLock { client.inspectDashboard() }
            }
            if (ticket == generation && !toggling) {
                lastChecked = dashboard.snapshot.protection
                lastCheckedElapsed = SystemClock.elapsedRealtime()
                show(dashboard.snapshot.protection)
            }
        }
    }

    override fun onStopListening() {
        listening = false
        super.onStopListening()
    }

    override fun onClick() {
        super.onClick()
        if (toggling) return
        // Turning OFF a firewall must not be possible from a locked screen.
        if (isLocked) unlockAndRun { toggleFromLiveState() }
        else toggleFromLiveState()
    }

    private fun toggleFromLiveState() {
        if (toggling) return
        toggling = true
        ++generation  // Ignore a check started when the shade was opened.
        show(FirewallClient.Protection.CHECKING, switching = true)
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                rootMutex.withLock { client.toggleProtection() }
            }
            lastChecked = result.dashboard.snapshot.protection
            lastCheckedElapsed = SystemClock.elapsedRealtime()
            show(result.dashboard.snapshot.protection)
            if (!result.success) {
                Toast.makeText(applicationContext, result.explanation, Toast.LENGTH_LONG).show()
            }
            toggling = false
        }
    }

    private fun show(
        protection: FirewallClient.Protection,
        switching: Boolean = false,
        checkedAgoSeconds: Long? = null
    ) {
        if (!listening) return
        val tile = qsTile ?: return
        val detail = when {
            switching -> "Switching..."
            protection == FirewallClient.Protection.ACTIVE ->
                checkedAgoSeconds?.let { "On · Checked " + it + "s ago" } ?: "On · Verified now"
            protection == FirewallClient.Protection.INACTIVE ->
                checkedAgoSeconds?.let { "Off · Checked " + it + "s ago" } ?: "Off · Verified now"
            protection == FirewallClient.Protection.CHECKING -> "Checking kernel..."
            protection == FirewallClient.Protection.ROOT_REQUIRED -> "Root access needed"
            else -> "Needs attention"
        }
        tile.icon = Icon.createWithResource(this, R.drawable.penguin_monochrome)
        tile.label = "PocketUFW"
        // Checking never paints a verified-ON tile as OFF. The shade retains
        // its prior tint while the subtitle explicitly says "Checking kernel".
        // Only a completed verification or user action may change on/off.
        tile.state = when (protection) {
            FirewallClient.Protection.ACTIVE -> Tile.STATE_ACTIVE
            FirewallClient.Protection.INACTIVE,
            FirewallClient.Protection.DEGRADED,
            FirewallClient.Protection.ROOT_REQUIRED -> Tile.STATE_INACTIVE
            FirewallClient.Protection.CHECKING -> tile.state
        }
        tile.contentDescription = "PocketUFW: $detail. Tap to toggle after verifying live kernel rules."
        if (Build.VERSION.SDK_INT >= 29) tile.subtitle = detail
        if (Build.VERSION.SDK_INT >= 30) tile.stateDescription = detail
        tile.updateTile()
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }
}
