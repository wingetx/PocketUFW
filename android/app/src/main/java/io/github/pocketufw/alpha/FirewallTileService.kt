package io.github.pocketufw.alpha

import android.graphics.drawable.Icon
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.widget.Toast
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
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

    override fun onStartListening() {
        super.onStartListening()
        listening = true
        if (toggling) return
        val ticket = ++generation
        show(FirewallClient.Protection.CHECKING)
        scope.launch {
            val dashboard = withContext(Dispatchers.IO) {
                rootMutex.withLock { client.inspectDashboard() }
            }
            if (ticket == generation && !toggling) show(dashboard.snapshot.protection)
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
            show(result.dashboard.snapshot.protection)
            if (!result.success) {
                Toast.makeText(applicationContext, result.explanation, Toast.LENGTH_LONG).show()
            }
            toggling = false
        }
    }

    private fun show(protection: FirewallClient.Protection, switching: Boolean = false) {
        if (!listening) return
        val tile = qsTile ?: return
        val detail = when {
            switching -> "Switching..."
            protection == FirewallClient.Protection.ACTIVE -> "On · Verified now"
            protection == FirewallClient.Protection.INACTIVE -> "Off · Verified now"
            protection == FirewallClient.Protection.CHECKING -> "Checking kernel..."
            protection == FirewallClient.Protection.ROOT_REQUIRED -> "Root access needed"
            else -> "Needs attention"
        }
        tile.icon = Icon.createWithResource(this, R.drawable.penguin_monochrome)
        tile.label = "PocketUFW"
        // Unknown state is neutral, not a fabricated green 'protected' badge.
        tile.state = if (protection == FirewallClient.Protection.ACTIVE) {
            Tile.STATE_ACTIVE
        } else {
            Tile.STATE_INACTIVE
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
