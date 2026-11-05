package io.github.pocketufw

import android.content.ComponentName
import android.content.Context
import android.content.SharedPreferences
import android.os.SystemClock
import android.service.quicksettings.TileService
import android.util.Log
import kotlin.math.abs

/**
 * Unprivileged, last-verified display cache. It never decides what kernel rules
 * become: a tile tap only passes the state it showed, and the bridge checks that
 * against the live rules. No root or background polling.
 *
 * Boot-epoch check invalidates saved "ON" after a reboot, when the Magisk
 * one-shot may or may not have restored the real firewall policy.
 */
internal object TileStatusStore {
    const val SOURCE_APP = "app"
    const val SOURCE_TILE = "tile"
    /** Changes on every write, so it's the key for a change listener to watch. */
    const val WRITTEN_AT = "written_at"
    private const val SOURCE = "source"
    private const val PREFS = "pocketufw_tile"
    private const val STATE = "state"
    private const val CHECKED_AT = "checked_at"
    private const val BOOT_EPOCH = "boot_epoch"
    private const val MAX_BOOT_DRIFT_MS = 120_000L

    data class LastChecked(val protection: FirewallClient.Protection, val checkedAt: Long)

    fun preferences(context: Context): SharedPreferences =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun lastWriteSource(context: Context): String? = preferences(context).getString(SOURCE, null)

    /**
     * Saves what a read found, started at [readStartedAt], unless the cache already
     * holds something newer. Returns false only in that case: the caller's result
     * is out of date and should be read again. A failed write isn't that, so it
     * can't send the caller into another root read.
     */
    @Synchronized
    fun publish(
        context: Context,
        snapshot: FirewallClient.Snapshot,
        readStartedAt: Long = System.currentTimeMillis(),
        source: String = SOURCE_APP,
    ): Boolean {
        if (snapshot.protection == FirewallClient.Protection.CHECKING) return true
        try {
            val preferences = preferences(context)
            val now = System.currentTimeMillis()
            // A stamp ahead of the clock only means the clock moved back.
            if (preferences.getLong(WRITTEN_AT, 0L) in (readStartedAt + 1)..now) return false
            val epoch = now - SystemClock.elapsedRealtime()
            val written = preferences.edit()
                .putString(STATE, snapshot.protection.name)
                .putLong(CHECKED_AT, now)
                .putLong(BOOT_EPOCH, epoch)
                .putLong(WRITTEN_AT, now)
                .putString(SOURCE, source)
                .commit()  // Write is tiny and already runs on Dispatchers.IO.
            if (written) request(context)
        } catch (e: RuntimeException) {
            // A tile UI cache failure must never change firewall operation.
            Log.w("PocketUFW", "Unable to update tile status cache", e)
        }
        return true
    }

    /**
     * Forgets the last verified state, because the firewall may be changing out of
     * sight. The tile then reads as not verified, and stays tappable. Older reads
     * still in flight can't restore what was forgotten.
     */
    @Synchronized
    fun invalidate(context: Context, source: String = SOURCE_APP) {
        try {
            val written = preferences(context).edit()
                .remove(STATE)
                .remove(CHECKED_AT)
                .remove(BOOT_EPOCH)
                .putLong(WRITTEN_AT, System.currentTimeMillis())
                .putString(SOURCE, source)
                .commit()
            if (written) request(context)
        } catch (e: RuntimeException) {
            Log.w("PocketUFW", "Unable to clear tile status cache", e)
        }
    }

    fun read(context: Context): LastChecked? {
        val pref = preferences(context)
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
