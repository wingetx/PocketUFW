package io.github.pocketufw.alpha

import android.content.ComponentName
import android.content.Context
import android.os.SystemClock
import android.service.quicksettings.TileService
import android.util.Log
import kotlin.math.abs

/**
 * Unprivileged, last-verified display cache. Never consult this to decide
 * whether to enable/disable kernel rules. No root or background polling.
 *
 * Boot-epoch check invalidates saved "ON" after a reboot, when the Magisk
 * one-shot may or may not have restored the real firewall policy.
 */
internal object TileStatusStore {
    private const val PREFS = "pocketufw_tile"
    private const val STATE = "state"
    private const val CHECKED_AT = "checked_at"
    private const val BOOT_EPOCH = "boot_epoch"
    private const val MAX_BOOT_DRIFT_MS = 120_000L

    data class LastChecked(val protection: FirewallClient.Protection, val checkedAt: Long)

    fun publish(context: Context, snapshot: FirewallClient.Snapshot) {
        if (snapshot.protection == FirewallClient.Protection.CHECKING) return
        try {
            val now = System.currentTimeMillis()
            val epoch = now - SystemClock.elapsedRealtime()
            val written = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString(STATE, snapshot.protection.name)
                .putLong(CHECKED_AT, now)
                .putLong(BOOT_EPOCH, epoch)
                .commit()  // Write is tiny and already runs on Dispatchers.IO.
            if (written) request(context)
        } catch (e: RuntimeException) {
            // A tile UI cache failure must never change firewall operation.
            Log.w("PocketUFW", "Unable to update tile status cache", e)
        }
    }

    fun read(context: Context): LastChecked? {
        val pref = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val savedState = pref.getString(STATE, null) ?: return null
        val state = runCatching { FirewallClient.Protection.valueOf(savedState) }.getOrNull()
            ?: return null
        if (state == FirewallClient.Protection.CHECKING) return null

        val now = System.currentTimeMillis()
        val uptime = SystemClock.elapsedRealtime()
        val checked = pref.getLong(CHECKED_AT, 0L)
        val savedEpoch = pref.getLong(BOOT_EPOCH, 0L)
        if (checked <= 0L || checked > now || savedEpoch <= 0L ||
            abs((now - uptime) - savedEpoch) > MAX_BOOT_DRIFT_MS) return null
        return LastChecked(state, checked)
    }

    fun request(context: Context) {
        try {
            TileService.requestListeningState(
                context, ComponentName(context, FirewallTileService::class.java)
            )
        } catch (e: RuntimeException) {
            // Tile may not be installed, or SystemUI may not be ready.
            Log.w("PocketUFW", "Quick Settings update unavailable", e)
        }
    }
}
