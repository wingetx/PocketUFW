package io.github.pocketufw.alpha

import android.graphics.drawable.Icon
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.widget.Toast
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * Active Quick Settings tile: NO root check on shade-open or listening.
 * Status comes from a previously completed app inspection or explicit tap;
 * taps still use the live kernel-verified root toggle (including lock guard).
 * No resident service, polling, periodic su, or inferred protection claims.
 */
class FirewallTileService : TileService() {
    private val client by lazy { FirewallClient(applicationContext) }
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val rootMutex = Mutex()
    private var toggling = false

    override fun onTileAdded() {
        super.onTileAdded()
        TileStatusStore.request(applicationContext)
    }

    override fun onStartListening() {
        super.onStartListening()
        // Active tiles listen ONLY when SystemUI delivers a tap or the app
        // explicitly requests an update. A shade-open does not bind us.
        if (!toggling) show(TileStatusStore.read(applicationContext))
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
        show(TileStatusStore.read(applicationContext), switching = true)
        scope.launch {
            // Never trust the cached tile state to determine what to toggle.
            // FirewallClient publishes the verified result to the tile cache.
            val result = withContext(Dispatchers.IO) {
                rootMutex.withLock { client.toggleProtection() }
            }
            show(TileStatusStore.read(applicationContext))
            if (!result.success) {
                Toast.makeText(applicationContext, result.explanation, Toast.LENGTH_LONG).show()
            }
            toggling = false
        }
    }

    private fun show(last: TileStatusStore.LastChecked?, switching: Boolean = false) {
        val tile = qsTile ?: return
        val status = last?.protection
        val checkedAt = last?.checkedAt?.let {
            DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(it))
        }
        val detail = when {
            switching -> "Switching..."
            status == FirewallClient.Protection.ACTIVE -> "On · Checked $checkedAt"
            status == FirewallClient.Protection.INACTIVE -> "Off · Checked $checkedAt"
            status == FirewallClient.Protection.ROOT_REQUIRED -> "Root access needed"
            status == FirewallClient.Protection.DEGRADED -> "Needs attention"
            else -> "Not verified this boot · Open app"
        }
        tile.icon = Icon.createWithResource(this, R.drawable.penguin_quick_tile)
        tile.label = "PocketUFW"
        // Only a completed verification may display green. Unknown means
        // unknown, not a statement that kernel rules are switched off.
        tile.state = when (status) {
            FirewallClient.Protection.ACTIVE -> Tile.STATE_ACTIVE
            FirewallClient.Protection.INACTIVE -> Tile.STATE_INACTIVE
            FirewallClient.Protection.DEGRADED,
            FirewallClient.Protection.ROOT_REQUIRED -> Tile.STATE_UNAVAILABLE
            else -> Tile.STATE_INACTIVE
        }
        tile.contentDescription =
            "PocketUFW: $detail. Tap to toggle using live kernel verification."
        if (Build.VERSION.SDK_INT >= 29) tile.subtitle = detail
        if (Build.VERSION.SDK_INT >= 30) tile.stateDescription = detail
        tile.updateTile()
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }
}
