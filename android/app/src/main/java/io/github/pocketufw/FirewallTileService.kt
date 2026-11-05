package io.github.pocketufw

import android.content.Context
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
 * Status comes from a previously completed app inspection or explicit tap.
 * A tap toggles only from a state the tile could honestly show as on or off,
 * and the bridge refuses if the kernel disagrees. Otherwise a tap only checks.
 * No resident service, polling, periodic su, or inferred protection claims.
 */
class FirewallTileService : TileService() {
    /** Replaced only by JVM tests, so that they never start a real `su`. */
    internal var newClient: (Context) -> FirewallClient = { FirewallClient(it, TileStatusStore.SOURCE_TILE) }
    private val client by lazy { newClient(applicationContext) }
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
        if (isLocked) unlockAndRun { actOnTap() }
        else actOnTap()
    }

    private fun actOnTap() {
        if (toggling) return
        toggling = true
        val last = TileStatusStore.read(applicationContext)
        // Unknown looks like off, but it may be on: toggling blindly could switch
        // off a firewall the user believed was off. Such a tap only checks.
        val expected = last?.protection?.takeIf {
            it == FirewallClient.Protection.ACTIVE || it == FirewallClient.Protection.INACTIVE
        }
        show(last, if (expected != null) "Switching..." else "Checking...")
        scope.launch {
            // FirewallClient publishes the verified result to the tile cache.
            val problem = withContext(Dispatchers.IO) {
                rootMutex.withLock { if (expected != null) toggleFrom(expected) else verify() }
            }
            show(TileStatusStore.read(applicationContext))
            if (problem != null) Toast.makeText(applicationContext, problem, Toast.LENGTH_LONG).show()
            toggling = false
        }
    }

    /** Returns what went wrong, if anything. */
    private fun toggleFrom(expected: FirewallClient.Protection): String? {
        val result = client.toggleProtection(expected)
        // A newer result reached the cache first, so the cache isn't this result.
        if (result.dashboard.superseded) client.inspectDashboard()
        return result.explanation.takeUnless { result.success }
    }

    /** Returns why the firewall still can't be called on or off, if it can't. */
    private fun verify(): String? {
        val snapshot = client.inspectDashboard().let { first ->
            if (first.superseded) client.inspectDashboard() else first
        }.snapshot
        return snapshot.details.takeUnless {
            snapshot.protection == FirewallClient.Protection.ACTIVE ||
                snapshot.protection == FirewallClient.Protection.INACTIVE
        }
    }

    private fun show(last: TileStatusStore.LastChecked?, pending: String? = null) {
        val tile = qsTile ?: return
        val status = last?.protection
        val checkedAt = last?.checkedAt?.let {
            DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(it))
        }
        val detail = when {
            pending != null -> pending
            status == FirewallClient.Protection.ACTIVE -> "On · Checked $checkedAt"
            status == FirewallClient.Protection.INACTIVE -> "Off · Checked $checkedAt"
            status == FirewallClient.Protection.ROOT_REQUIRED -> "Root access needed"
            status == FirewallClient.Protection.DEGRADED -> "Needs attention"
            else -> "Not verified this boot · Open app"
        }
        tile.icon = Icon.createWithResource(this, R.drawable.shield_quick_tile)
        tile.label = "PocketUFW"
        // Only a completed verification may display green. Unknown means
        // unknown, not a statement that kernel rules are switched off: the subtitle
        // says so. SystemUI drops taps on an unavailable tile, which would leave a
        // tap no way to check the firewall again, so problem states stay tappable.
        tile.state = if (status == FirewallClient.Protection.ACTIVE) Tile.STATE_ACTIVE
            else Tile.STATE_INACTIVE
        val tapMeaning = when (status) {
            FirewallClient.Protection.ACTIVE -> "Tap to turn off."
            FirewallClient.Protection.INACTIVE -> "Tap to turn on."
            else -> "Tap to check the firewall. This doesn't change it."
        }
        tile.contentDescription = "PocketUFW: $detail. $tapMeaning"
        if (Build.VERSION.SDK_INT >= 29) tile.subtitle = detail
        if (Build.VERSION.SDK_INT >= 30) tile.stateDescription = detail
        tile.updateTile()
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }
}
