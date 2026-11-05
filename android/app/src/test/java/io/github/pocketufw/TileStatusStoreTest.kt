package io.github.pocketufw

import android.content.Context
import io.github.pocketufw.FirewallClient.Protection
import io.github.pocketufw.FirewallClient.Snapshot
import java.time.Duration
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import org.robolectric.shadows.ShadowSystemClock

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class TileStatusStoreTest {
    private val app: Context get() = RuntimeEnvironment.getApplication()
    private val active = Snapshot(Protection.ACTIVE, rootReady = true)
    private val off = Snapshot(Protection.INACTIVE, rootReady = true)

    @Test fun nothingPublishedReadsAsUnknown() = assertNull(TileStatusStore.read(app))

    @Test fun aPublishedStateIsReadBack() {
        assertTrue(TileStatusStore.publish(app, off))
        assertEquals(Protection.INACTIVE, TileStatusStore.read(app)?.protection)
        assertTrue(TileStatusStore.read(app)!!.checkedAt > 0L)
    }

    @Test fun aReadThatStartedBeforeANewerWriteIsRejected() {
        val readStarted = System.currentTimeMillis() - 1_000
        assertTrue(TileStatusStore.publish(app, off, source = TileStatusStore.SOURCE_TILE))
        assertFalse(TileStatusStore.publish(app, active, readStartedAt = readStarted))
        assertEquals(Protection.INACTIVE, TileStatusStore.read(app)?.protection)
        assertEquals(TileStatusStore.SOURCE_TILE, TileStatusStore.lastWriteSource(app))
    }

    @Test fun aReadThatStartedAfterTheLatestWriteIsAccepted() {
        assertTrue(TileStatusStore.publish(app, off))
        Thread.sleep(2)
        assertTrue(TileStatusStore.publish(app, active, readStartedAt = System.currentTimeMillis()))
        assertEquals(Protection.ACTIVE, TileStatusStore.read(app)?.protection)
    }

    @Test fun aWriteStampedInTheFutureCannotBlockEveryLaterRead() {
        // The clock can be set back after a write. That must not freeze the tile.
        TileStatusStore.preferences(app).edit()
            .putLong(TileStatusStore.WRITTEN_AT, System.currentTimeMillis() + 3_600_000).commit()
        assertTrue(TileStatusStore.publish(app, active))
        assertEquals(Protection.ACTIVE, TileStatusStore.read(app)?.protection)
    }

    @Test fun checkingIsNeverCached() {
        assertTrue(TileStatusStore.publish(app, Snapshot(Protection.CHECKING)))
        assertNull(TileStatusStore.read(app))
    }

    @Test fun invalidationMakesTheTileUnknownAndRecordsWhoDidIt() {
        TileStatusStore.publish(app, active)
        TileStatusStore.invalidate(app, TileStatusStore.SOURCE_TILE)
        assertNull(TileStatusStore.read(app))
        assertEquals(TileStatusStore.SOURCE_TILE, TileStatusStore.lastWriteSource(app))
    }

    @Test fun invalidationBlocksReadsStartedBeforeItButNotAfter() {
        val before = System.currentTimeMillis() - 1_000
        TileStatusStore.invalidate(app)
        assertFalse(TileStatusStore.publish(app, active, readStartedAt = before))
        assertNull(TileStatusStore.read(app))
        Thread.sleep(2)
        assertTrue(TileStatusStore.publish(app, active, readStartedAt = System.currentTimeMillis()))
        assertEquals(Protection.ACTIVE, TileStatusStore.read(app)?.protection)
    }

    @Test fun everyWriteAdvancesTheKeyTheAppListensFor() {
        var heard = 0
        val listener = android.content.SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
            if (key == TileStatusStore.WRITTEN_AT) heard++
        }
        val prefs = TileStatusStore.preferences(app)
        prefs.registerOnSharedPreferenceChangeListener(listener)
        TileStatusStore.publish(app, active)
        Thread.sleep(2)
        TileStatusStore.invalidate(app)
        org.robolectric.Shadows.shadowOf(android.os.Looper.getMainLooper()).idle()
        prefs.unregisterOnSharedPreferenceChangeListener(listener)
        assertEquals(2, heard)
    }

    @Test fun aRebootMakesAnActiveCacheUnknown() {
        TileStatusStore.publish(app, active)
        assertNotNull(TileStatusStore.read(app))
        // Wall time minus uptime moves when uptime no longer matches: a different boot.
        ShadowSystemClock.advanceBy(Duration.ofHours(5))
        assertNull(TileStatusStore.read(app))
    }

    @Test fun aRejectedWriteLeavesTheCheckedTimeAlone() {
        TileStatusStore.publish(app, off)
        val stamp = TileStatusStore.read(app)!!.checkedAt
        Thread.sleep(2)
        TileStatusStore.publish(app, active, readStartedAt = stamp - 1_000)
        assertEquals(stamp, TileStatusStore.read(app)!!.checkedAt)
    }
}
