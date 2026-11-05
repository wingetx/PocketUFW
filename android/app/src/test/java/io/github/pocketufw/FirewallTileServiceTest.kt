package io.github.pocketufw

import android.content.ComponentName
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.pm.ActivityInfo
import android.os.Looper
import android.service.quicksettings.Tile
import io.github.pocketufw.FirewallClient.Protection
import io.github.pocketufw.FirewallClient.Snapshot
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import org.robolectric.shadow.api.Shadow
import org.robolectric.shadows.ShadowSystemClock
import org.robolectric.shadows.ShadowTileService
import org.robolectric.shadows.ShadowToast

/** The real tile and real client, with only the root shell faked. */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class FirewallTileServiceTest {
    private val app: Context get() = RuntimeEnvironment.getApplication()
    private val shell = FakeShell()

    @Before fun clearToasts() = ShadowToast.reset()

    private fun tile(): FirewallTileService =
        Robolectric.buildService(FirewallTileService::class.java).create().get().also { service ->
            service.newClient = { FirewallClient(it, TileStatusStore.SOURCE_TILE, shell) }
        }

    private fun cache(protection: Protection) =
        TileStatusStore.publish(app, Snapshot(protection, rootReady = protection != Protection.ROOT_REQUIRED),
            source = TileStatusStore.SOURCE_TILE)

    /** Taps and waits for the coroutine to come back to the main thread. */
    private fun tap(service: FirewallTileService, sessions: Int = 1) {
        service.onClick()
        pumpUntil { shell.actions.size >= sessions && !isSwitching(service) }
    }

    private fun isSwitching(service: FirewallTileService) =
        service.qsTile.subtitle.toString().let { it == "Switching..." || it == "Checking..." }

    private fun pumpUntil(timeoutMs: Long = 5_000, done: () -> Boolean) {
        val end = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < end) {
            shadowOf(Looper.getMainLooper()).idle()
            if (done()) return
            Thread.sleep(10)
        }
        fail("timed out waiting for the tile; actions=${shell.actions}")
    }

    private fun rendered(protection: Protection?): Tile {
        protection?.let(::cache)
        val service = tile()
        service.onStartListening()
        return service.qsTile
    }

    // ---- rendering ----

    @Test fun onIsActiveAndSaysWhenItWasChecked() {
        val shown = rendered(Protection.ACTIVE)
        assertEquals(Tile.STATE_ACTIVE, shown.state)
        assertTrue(shown.subtitle.toString(), shown.subtitle.toString().startsWith("On · Checked "))
    }

    @Test fun offIsInactiveAndSaysWhenItWasChecked() {
        val shown = rendered(Protection.INACTIVE)
        assertEquals(Tile.STATE_INACTIVE, shown.state)
        assertTrue(shown.subtitle.toString(), shown.subtitle.toString().startsWith("Off · Checked "))
    }

    @Test fun unknownIsNeverGreenAndSaysItIsUnverified() {
        val shown = rendered(null)
        assertEquals(Tile.STATE_INACTIVE, shown.state)
        assertEquals("Not verified this boot · Open app", shown.subtitle.toString())
    }

    @Test fun anActiveCacheFromAnEarlierBootIsNotShownAsOn() {
        cache(Protection.ACTIVE)
        ShadowSystemClock.advanceBy(Duration.ofHours(5))
        val shown = rendered(null)
        assertEquals(Tile.STATE_INACTIVE, shown.state)
        assertEquals("Not verified this boot · Open app", shown.subtitle.toString())
    }

    @Test fun problemStatesStayTappableSoATapCanVerifyThem() {
        // SystemUI drops taps on STATE_UNAVAILABLE, so the tile could never recover.
        val attention = rendered(Protection.DEGRADED)
        assertEquals(Tile.STATE_INACTIVE, attention.state)
        assertEquals("Needs attention", attention.subtitle.toString())
        val root = rendered(Protection.ROOT_REQUIRED)
        assertEquals(Tile.STATE_INACTIVE, root.state)
        assertEquals("Root access needed", root.subtitle.toString())
    }

    @Test fun renderingNeverRunsARootCommand() {
        for (state in listOf(null, Protection.ACTIVE, Protection.DEGRADED)) rendered(state)
        assertEquals(emptyList<String>(), shell.actions.toList())
    }

    @Test fun talkBackHearsWhatATapWillDo() {
        assertTrue(rendered(Protection.ACTIVE).contentDescription.toString(),
            rendered(Protection.ACTIVE).contentDescription!!.contains("Tap to turn off"))
        assertTrue(rendered(Protection.INACTIVE).contentDescription!!.contains("Tap to turn on"))
        val unknown = rendered(Protection.DEGRADED).contentDescription!!
        assertTrue(unknown.toString(), unknown.contains("Tap to check"))
        assertFalse(unknown.toString(), unknown.contains("toggle"))
    }

    // ---- tap semantics ----

    @Test fun tapOnUnknownOnlyVerifies() {
        shell.respond = { ShellResult(0, bridgeOutput(state = "ACTIVE")) }
        val service = tile()
        service.onStartListening()
        tap(service)
        assertEquals("a blind toggle could switch off a firewall", listOf("inspect"), shell.actions.toList())
        assertEquals(Tile.STATE_ACTIVE, service.qsTile.state)
        assertTrue(service.qsTile.subtitle.toString().startsWith("On · Checked "))
    }

    @Test fun tapOnDegradedOnlyVerifies() {
        cache(Protection.DEGRADED)
        shell.respond = { ShellResult(0, bridgeOutput(state = "DEGRADED")) }
        tap(tile())
        assertEquals(listOf("inspect"), shell.actions.toList())
    }

    @Test fun tapOnRootRequiredOnlyVerifies() {
        cache(Protection.ROOT_REQUIRED)
        shell.respond = { ShellResult(0, bridgeOutput(state = "INACTIVE", boot = "DISABLED")) }
        val service = tile()
        tap(service)
        assertEquals(listOf("inspect"), shell.actions.toList())
        assertEquals("Off", service.qsTile.subtitle.toString().substringBefore(" ·"))
    }

    @Test fun tapOnOnAsksToTurnOffFromOn() {
        cache(Protection.ACTIVE)
        shell.respond = { ShellResult(0, bridgeOutput(state = "INACTIVE", boot = "DISABLED", operation = "SUCCESS")) }
        val service = tile()
        tap(service)
        assertEquals(listOf("toggle ACTIVE"), shell.actions.toList())
        assertEquals(Tile.STATE_INACTIVE, service.qsTile.state)
        assertEquals(Protection.INACTIVE, TileStatusStore.read(app)?.protection)
        assertEquals(0, ShadowToast.shownToastCount())
    }

    @Test fun tapOnOffAsksToTurnOnFromOff() {
        cache(Protection.INACTIVE)
        shell.respond = { ShellResult(0, bridgeOutput(state = "ACTIVE", operation = "SUCCESS")) }
        val service = tile()
        tap(service)
        assertEquals(listOf("toggle INACTIVE"), shell.actions.toList())
        assertEquals(Tile.STATE_ACTIVE, service.qsTile.state)
    }

    @Test fun tapKeepsAnEarlierBootOptIn() {
        app.getSharedPreferences("pocketufw", Context.MODE_PRIVATE).edit()
            .putBoolean("boot_opted_in", true).commit()
        cache(Protection.INACTIVE)
        tap(tile())
        assertEquals(listOf("toggle-restore INACTIVE"), shell.actions.toList())
    }

    @Test fun aSecondTapWhileBusyRunsNothing() {
        cache(Protection.ACTIVE)
        val release = CountDownLatch(1)
        shell.respond = {
            release.await(5, TimeUnit.SECONDS)
            ShellResult(0, bridgeOutput(state = "INACTIVE", operation = "SUCCESS"))
        }
        val service = tile()
        service.onClick()
        pumpUntil { shell.actions.size == 1 }
        service.onClick()
        service.onClick()
        assertEquals("Switching...", service.qsTile.subtitle.toString())
        release.countDown()
        pumpUntil { !isSwitching(service) }
        assertEquals(listOf("toggle ACTIVE"), shell.actions.toList())
    }

    @Test fun aVerifyInProgressSaysCheckingNotSwitching() {
        val release = CountDownLatch(1)
        shell.respond = {
            release.await(5, TimeUnit.SECONDS)
            ShellResult(0, bridgeOutput(state = "ACTIVE"))
        }
        val service = tile()
        service.onClick()
        pumpUntil { shell.actions.size == 1 }
        assertEquals("Checking...", service.qsTile.subtitle.toString())
        release.countDown()
        pumpUntil { !isSwitching(service) }
    }

    @Test fun aLockedPhoneMustUnlockBeforeATapActs() {
        for (state in listOf(Protection.ACTIVE, Protection.INACTIVE)) {
            cache(state)
            val service = tile()
            Shadow.extract<ShadowTileService>(service).setLocked(true)
            assertTrue(service.isLocked)
            val before = shell.actions.size
            tap(service, sessions = before + 1)
            // The shadow's unlockAndRun clears the lock; nothing else in the path does.
            assertFalse("the tap skipped unlockAndRun", service.isLocked)
        }
        assertEquals(2, shell.actions.size)
    }

    // ---- failure reporting ----

    @Test fun aRefusedToggleShowsWhyAndTheLiveState() {
        cache(Protection.INACTIVE)
        val why = "Firewall state had changed, so nothing was toggled. Status updated."
        shell.respond = { ShellResult(0, bridgeOutput(state = "ACTIVE", operation = "FAILED", message = why)) }
        val service = tile()
        tap(service)
        assertEquals(why, ShadowToast.getTextOfLatestToast())
        assertEquals(Tile.STATE_ACTIVE, service.qsTile.state)
        assertEquals(Protection.ACTIVE, TileStatusStore.read(app)?.protection)
    }

    @Test fun aTimedOutTapStaysTappableAndDoesNotBlameRoot() {
        cache(Protection.ACTIVE)
        shell.respond = { ShellResult(124, "Root command timed out.") }
        val service = tile()
        tap(service)
        assertEquals("Root command timed out; the firewall may still change. Recheck status.",
            ShadowToast.getTextOfLatestToast())
        assertNull(TileStatusStore.read(app))
        assertEquals(Tile.STATE_INACTIVE, service.qsTile.state)
        assertEquals("Not verified this boot · Open app", service.qsTile.subtitle.toString())

        // The next tap verifies rather than repeating a switch that may still finish.
        shell.respond = { ShellResult(0, bridgeOutput(state = "INACTIVE", boot = "DISABLED")) }
        tap(service, sessions = 2)
        assertEquals(listOf("toggle ACTIVE", "inspect"), shell.actions.toList())
    }

    @Test fun aVerifyThatCannotVerifySaysWhy() {
        shell.respond = { ShellResult(3, "root=DENIED") }
        val service = tile()
        tap(service)
        assertEquals("Root access needed", service.qsTile.subtitle.toString())
        assertEquals(FirewallClient(app, shell = shell).protectionDetails(Protection.ROOT_REQUIRED),
            ShadowToast.getTextOfLatestToast())
    }

    @Test fun aSuccessfulVerifyIsQuiet() {
        shell.respond = { ShellResult(0, bridgeOutput(state = "ACTIVE")) }
        tap(tile())
        assertEquals(0, ShadowToast.shownToastCount())
    }

    @Test fun anOvertakenTapReadsTheFirewallAgain() {
        cache(Protection.ACTIVE)
        shell.respond = { action ->
            if (action.startsWith("toggle")) {
                Thread.sleep(5)
                TileStatusStore.publish(app, Snapshot(Protection.DEGRADED, rootReady = true))
                Thread.sleep(5)
                ShellResult(0, bridgeOutput(state = "ACTIVE", operation = "SUCCESS"))
            } else ShellResult(0, bridgeOutput(state = "ACTIVE"))
        }
        val service = tile()
        tap(service, sessions = 2)
        assertEquals(listOf("toggle ACTIVE", "inspect"), shell.actions.toList())
        assertEquals(Protection.ACTIVE, TileStatusStore.read(app)?.protection)
        assertEquals(Tile.STATE_ACTIVE, service.qsTile.state)
    }

    // ---- reboot ----

    @Test fun bootReceiverIsRegisteredAndNotExported() {
        val receivers = app.packageManager.queryBroadcastReceivers(
            Intent(Intent.ACTION_BOOT_COMPLETED).setPackage(app.packageName), 0)
        val info = receivers.single { it.activityInfo.name.endsWith(".BootTileReceiver") }.activityInfo
        assertFalse(info.exported)
    }

    /** On this SDK a rebind request goes through StatusBarManager, so that lookup is the evidence. */
    private fun servicesAskedForDuring(intent: Intent): List<String> {
        val asked = mutableListOf<String>()
        val context = object : ContextWrapper(app) {
            override fun getSystemService(name: String): Any? {
                asked += name
                return super.getSystemService(name)
            }
        }
        BootTileReceiver().onReceive(context, intent)
        return asked
    }

    @Test fun bootOnlyAsksSystemUiToRebindTheTile() {
        assertEquals(listOf(Context.STATUS_BAR_SERVICE),
            servicesAskedForDuring(Intent(Intent.ACTION_BOOT_COMPLETED)))
        assertEquals(emptyList<String>(), shell.actions.toList())
    }

    @Test fun bootReceiverIgnoresOtherBroadcasts() {
        assertEquals(emptyList<String>(), servicesAskedForDuring(Intent(Intent.ACTION_SCREEN_ON)))
    }

    @Test fun afterARebootTheBoundTileSaysItIsUnverified() {
        cache(Protection.ACTIVE)
        ShadowSystemClock.advanceBy(Duration.ofHours(5))
        BootTileReceiver().onReceive(app, Intent(Intent.ACTION_BOOT_COMPLETED))
        val service = tile()
        service.onStartListening() // What SystemUI does after that request.
        assertEquals(Tile.STATE_INACTIVE, service.qsTile.state)
        assertEquals("Not verified this boot · Open app", service.qsTile.subtitle.toString())
        assertEquals(emptyList<String>(), shell.actions.toList())
    }

    // ---- rotation ----

    @Test fun rotationDoesNotRecreateTheActivity() {
        val info = app.packageManager.getActivityInfo(ComponentName(app, MainActivity::class.java), 0)
        for (flag in listOf(ActivityInfo.CONFIG_ORIENTATION, ActivityInfo.CONFIG_SCREEN_SIZE,
            ActivityInfo.CONFIG_SMALLEST_SCREEN_SIZE, ActivityInfo.CONFIG_SCREEN_LAYOUT,
            ActivityInfo.CONFIG_KEYBOARD, ActivityInfo.CONFIG_KEYBOARD_HIDDEN, ActivityInfo.CONFIG_NAVIGATION,
            ActivityInfo.CONFIG_UI_MODE, ActivityInfo.CONFIG_DENSITY, ActivityInfo.CONFIG_FONT_SCALE)) {
            assertTrue("missing configChanges flag $flag", info.configChanges and flag == flag)
        }
    }
}
