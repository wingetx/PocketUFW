package io.github.pocketufw

import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import android.graphics.Bitmap
import android.graphics.Canvas
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Surface
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.*
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.unit.dp
import io.github.pocketufw.FirewallClient.*
import java.util.concurrent.CountDownLatch
import java.io.File
import kotlinx.coroutines.CancellationException
import org.junit.After
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/** Hold real screen gateway calls open: progress must appear before a result exists. */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class TideProgressTest {
    @get:Rule val compose = createEmptyComposeRule()
    private val screens = mutableListOf<ActivityController<ComponentActivity>>()
    private val gates = mutableListOf<CountDownLatch>()
    @After fun close() { gates.forEach { it.countDown() }; drainMainLooper(screens) }
    private fun node(label: String) = compose.onNodeWithText(label)
    private fun click(label: String) = node(label).performScrollTo().performClick()
    private val progress = SemanticsMatcher.expectValue(SemanticsProperties.ProgressBarRangeInfo,
        ProgressBarRangeInfo.Indeterminate)
    private fun open(fake: FakeGateway, dark: Boolean = false) {
        screens += compose.launchScreen(fake, qualifiers = "w412dp-h915dp-${if (dark) "night" else "notnight"}-xxhdpi")
        compose.settle { fake.count("inspect") == 1 && !compose.hasText("Checking…") }
    }
    private fun shot(name: String) {
        val directory = File("build/reports/tide-progress").also { it.mkdirs() }
        val bitmap = draw()
        File(directory, "$name.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
        bitmap.recycle()
    }
    private fun draw(): Bitmap {
        val view = screens.last().get().window.decorView
        val bitmap = Bitmap.createBitmap(view.width, view.height, Bitmap.Config.ARGB_8888)
        compose.runOnIdle { view.draw(Canvas(bitmap)) }
        return bitmap
    }
    private fun hold(fake: FakeGateway) = CountDownLatch(1).also { gates += it; fake.gate = it }
    private fun release(fake: FakeGateway, gate: CountDownLatch) {
        fake.gate = null; gate.countDown()
        compose.settle { compose.onAllNodes(progress).fetchSemanticsNodes().isEmpty() }
    }
    private fun loading(label: String, state: String) {
        compose.onAllNodes(progress).assertCountEquals(1)
        compose.onNodeWithContentDescription(label).assert(progress)
            .assert(SemanticsMatcher.expectValue(SemanticsProperties.StateDescription, state))
            .assert(SemanticsMatcher.expectValue(SemanticsProperties.LiveRegion, LiveRegionMode.Polite))
            .assertIsNotEnabled().assertIsDisplayed()
    }

    @Test fun toolbarRecheckAnimatesImmediatelyAndRejectsDuplicateTaps() {
        val fake = FakeGateway(tunnelDashboard()); open(fake)
        val gate = hold(fake)
        val button = compose.onNodeWithTag("recheck-status")
        val before = button.getUnclippedBoundsInRoot()
        button.performClick()
        compose.settle { fake.count("inspect") == 2 }
        loading("Recheck firewall status", "Checking…")
        assertEquals(before, button.getUnclippedBoundsInRoot())
        repeat(3) { button.performClick() }
        assertEquals(2, fake.count("inspect"))
        release(fake, gate)
        button.assertIsEnabled()
        assertEquals(listOf("inspect", "inspect"), fake.calls.toList())
    }

    private fun firewallChange(active: Boolean) {
        val fake = FakeGateway(if (active) activeDashboard() else stateDashboard(Protection.INACTIVE, true, "Off."))
        open(fake, dark = active); val gate = hold(fake)
        val button = compose.onNodeWithTag("firewall-action")
        val before = button.getUnclippedBoundsInRoot().let { (it.right - it.left) to (it.bottom - it.top) }
        button.performClick()
        if (active) compose.onNodeWithTag("confirm-turn-firewall-off").performClick()
        val request = if (active) "disable" else "enable"
        compose.settle { fake.count(request) == 1 }
        loading(if (active) "Turn firewall off" else "Turn firewall on",
            if (active) "Deactivating…" else "Activating…")
        assertEquals(before, button.getUnclippedBoundsInRoot().let { (it.right - it.left) to (it.bottom - it.top) })
        shot(if (active) "deactivating-dark" else "activating-light")
        button.performClick()
        compose.onNodeWithTag("recheck-status").performClick()
        release(fake, gate)
        button.assertIsEnabled()
        assertEquals(listOf("inspect", request), fake.calls.toList())
    }
    @Test fun activatingUsesTheOriginalControl() = firewallChange(false)
    @Test fun deactivatingStartsOnlyAfterConfirmation() = firewallChange(true)

    @Test fun counterRefreshShowsProgressAndMakesOnlyTheLightweightRequest() {
        val fake = FakeGateway(tunnelDashboard(), counterRead = tunnelActivity()); open(fake)
        click("Statistics"); val gate = hold(fake)
        click("Refresh counters")
        compose.settle { fake.count("counters") == 1 }
        loading("Refresh counters", "Refreshing…")
        shot("refreshing-counters-light")
        compose.onNodeWithTag("reset-counters").assertIsNotEnabled()
        node("Refreshing…").performClick()
        release(fake, gate)
        node("Refresh counters").assertIsEnabled()
        assertEquals(listOf("inspect", "counters"), fake.calls.toList())
    }

    @Test fun resetConfirmationCancellationDoesNoWorkAndResetThenCleansUp() {
        val fake = FakeGateway(tunnelDashboard()); open(fake)
        click("Statistics"); click("Reset counters"); node("Cancel").performClick()
        compose.onAllNodes(progress).assertCountEquals(0)
        assertEquals(listOf("inspect"), fake.calls.toList())
        val gate = hold(fake)
        click("Reset counters"); compose.onNodeWithTag("confirm-reset-counters").performClick()
        compose.settle { fake.count("reset-counters") == 1 }
        loading("Reset counters", "Resetting…")
        compose.onNodeWithTag("banner").assertDoesNotExist()
        shot("resetting-counters-light")
        compose.onNodeWithTag("confirm-reset-counters").assertDoesNotExist()
        node("Refresh counters").assertIsNotEnabled()
        release(fake, gate)
        compose.onNodeWithTag("reset-counters").assertIsEnabled()
        assertEquals(listOf("inspect", "reset-counters"), fake.calls.toList())
    }

    private fun enableTunnel(mode: TunnelMode) {
        val d = activeDashboard().let { it.copy(snapshot = it.snapshot.copy(tunnelFilter = TunnelFilter.OFF)) }
        val fake = FakeGateway(d).apply { operationSuccess = false; operationMessage = "Enable could not be verified." }
        open(fake); node("Settings").performClick(); click("Tunnel protection")
        val gate = hold(fake)
        val name = mode.name.replace('_', '-')
        click("Enable $name"); compose.onNodeWithTag("confirm-enable-tunnel").performClick()
        compose.settle { fake.count("tunnel-on:${mode.name}") == 1 }
        loading("Enable $name", "Activating…")
        node(if (mode == TunnelMode.PINNED) "Enable DENY-ONLY" else "Enable PINNED").assertIsNotEnabled()
        release(fake, gate)
        node(fake.operationMessage).assertExists()
        node("Enable $name").assertIsEnabled()
        assertEquals(listOf("inspect", "tunnel-on:${mode.name}"), fake.calls.toList())
    }
    @Test fun pinnedEnableShowsOnlyItsOwnProgressAndClearsOnFailure() = enableTunnel(TunnelMode.PINNED)
    @Test fun denyOnlyEnableShowsOnlyItsOwnProgressAndClearsOnFailure() = enableTunnel(TunnelMode.DENY_ONLY)

    @Test fun tunnelRefreshAndRecoveryHaveTheirOwnProgressWithoutPhysicalRemoval() {
        val fake = FakeGateway(tunnelDashboard()); open(fake)
        node("Settings").performClick(); click("Tunnel protection")
        val gate = hold(fake)
        click("Refresh tunnel hooks")
        compose.settle { fake.count("tunnel-refresh") == 1 }
        loading("Refresh tunnel hooks", "Refreshing…")
        node("Turn tunnel protection off").assertIsNotEnabled()
        release(fake, gate)
        val removeGate = hold(fake)
        click("Turn tunnel protection off"); compose.onNodeWithTag("confirm-remove-tunnel").performClick()
        compose.settle { fake.count("tunnel-off") == 1 }
        loading("Turn tunnel protection off", "Removing…")
        release(fake, removeGate)
        assertEquals(listOf("inspect", "tunnel-refresh", "tunnel-off"), fake.calls.toList())
    }

    @Test fun kernelRecheckDoesNotAnimateTheToolbarAsWell() {
        val fake = FakeGateway(); open(fake)
        node("Activity").performClick(); click("Kernel rules")
        val gate = hold(fake)
        click("Recheck kernel rules")
        compose.settle { fake.count("inspect") == 2 }
        loading("Recheck kernel rules", "Checking…")
        release(fake, gate)
        assertEquals(2, fake.count("inspect"))
    }

    @Test fun homeRecheckDoesNotAnimateTheToolbarAsWell() {
        val fake = FakeGateway(stateDashboard(Protection.DEGRADED, true, "Needs inspection.")); open(fake)
        val gate = hold(fake)
        compose.onNodeWithTag("firewall-action").performClick()
        compose.settle { fake.count("inspect") == 2 }
        loading("Recheck status", "Checking…")
        release(fake, gate)
        assertEquals(listOf("inspect", "inspect"), fake.calls.toList())
    }

    @Test fun tailscalePortRefreshAnimatesOnlyItsControl() {
        val fake = FakeGateway(); open(fake)
        node("Settings").performClick(); click("VPN UDP exceptions")
        val gate = hold(fake)
        click("Refresh Tailscale ports")
        compose.settle { fake.count("vpn-refresh") == 1 }
        loading("Refresh Tailscale ports", "Refreshing…")
        release(fake, gate)
        node("Refresh Tailscale ports").assertIsEnabled()
        assertEquals(listOf("inspect", "vpn-refresh"), fake.calls.toList())
    }

    @Test fun degradedTunnelRecoveryKeepsProgressOnRecoveryAndNeverDisablesPhysicalRules() {
        val d = tunnelDashboard()
        val fake = FakeGateway(d.copy(snapshot = d.snapshot.copy(protection = Protection.DEGRADED,
            tunnelFilter = TunnelFilter.DEGRADED))); open(fake)
        val gate = hold(fake)
        click("Remove tunnel rules only"); compose.onNodeWithTag("confirm-remove-tunnel").performClick()
        compose.settle { fake.count("tunnel-off") == 1 }
        loading("Remove tunnel rules only", "Removing…")
        release(fake, gate)
        assertEquals(listOf("inspect", "tunnel-off"), fake.calls.toList())
    }

    @Test fun timedOutRecheckClearsProgressWithoutClaimingProtection() {
        val fake = FakeGateway(); open(fake); val gate = hold(fake)
        fake.dashboard = stateDashboard(Protection.DEGRADED, false, "Root command timed out; recheck state.")
        compose.onNodeWithTag("recheck-status").performClick()
        compose.settle { fake.count("inspect") == 2 }
        loading("Recheck firewall status", "Checking…")
        release(fake, gate)
        compose.onNodeWithTag("recheck-status").assertIsEnabled()
        compose.onNodeWithTag("banner-failed").assertExists()
        node("Active.").assertDoesNotExist()
        assertEquals(2, fake.count("inspect"))
    }

    private fun cancelledRequest(request: String) {
        val fake = FakeGateway(); open(fake)
        if (request != "inspect") click("Statistics")
        val gate = hold(fake)
        fake.requestFailure = CancellationException("Test cancelled request")
        when (request) {
            "inspect" -> compose.onNodeWithTag("recheck-status").performClick()
            "counters" -> click("Refresh counters")
            else -> { click("Reset counters"); compose.onNodeWithTag("confirm-reset-counters").performClick() }
        }
        compose.settle { fake.count(request) == if (request == "inspect") 2 else 1 }
        compose.onAllNodes(progress).assertCountEquals(1)
        release(fake, gate)
        compose.onNodeWithTag("banner-failed").assertExists()
        compose.onNodeWithTag("recheck-status").assertIsEnabled()
        node("Turn firewall off").assertDoesNotExist()
        assertEquals(listOf("inspect", request), fake.calls.toList())
    }
    @Test fun cancelledInspectionClearsProgress() = cancelledRequest("inspect")
    @Test fun cancelledCounterReadClearsProgress() = cancelledRequest("counters")
    @Test fun cancelledMutationClearsProgress() = cancelledRequest("reset-counters")

    @Test fun largeTextLoadingLabelsKeepBothButtonBoundsStable() {
        RuntimeEnvironment.setQualifiers("w320dp-h915dp-xxhdpi")
        RuntimeEnvironment.setFontScale(2f)
        val busy = mutableStateOf(false)
        val controller = Robolectric.buildActivity(ComponentActivity::class.java).setup().also { screens += it }
        controller.get().setContent { TideTheme { Surface(Modifier.fillMaxSize(), color = Background) {
            Column(Modifier.padding(24.dp)) {
                TidePrimaryButton("Refresh counters", {}, Modifier.testTag("refresh"),
                    loading = busy.value, loadingLabel = "Refreshing…")
                TideOutlinedButton("Reset counters", {}, Modifier.testTag("reset"),
                    loading = busy.value, loadingLabel = "Resetting…")
            }
        } } }
        val before = listOf("refresh", "reset").map { compose.onNodeWithTag(it).getUnclippedBoundsInRoot() }
        compose.runOnIdle { busy.value = true }
        val after = listOf("refresh", "reset").map { compose.onNodeWithTag(it).getUnclippedBoundsInRoot() }
        assertEquals(before, after)
        compose.onAllNodes(progress).assertCountEquals(2)
        shot("large-text-progress")
        compose.runOnIdle { busy.value = false }
        compose.onAllNodes(progress).assertCountEquals(0)
        compose.onNodeWithTag("refresh").assertIsEnabled()
    }

    @Test fun materialIndicatorActuallyAnimatesWithoutChangingControlSize() {
        RuntimeEnvironment.setQualifiers("w412dp-h915dp-night-xxhdpi")
        RuntimeEnvironment.setFontScale(1f)
        // Compose tests normally freeze infinite animations. Drive this one explicitly.
        compose.mainClock.autoAdvance = false
        val controller = Robolectric.buildActivity(ComponentActivity::class.java).setup().also { screens += it }
        controller.get().setContent { TideTheme { Surface(Modifier.fillMaxSize(), color = Background) {
            Column(Modifier.padding(24.dp)) {
                TidePrimaryButton("Turn firewall on", {}, Modifier.testTag("animated"),
                    loading = true, loadingLabel = "Activating…")
            }
        } } }
        compose.mainClock.advanceTimeBy(300)
        compose.waitForIdle()
        val bounds = compose.onNodeWithTag("animated").getUnclippedBoundsInRoot()
        val first = draw()
        shot("animated-dark-frame-1")
        compose.mainClock.advanceTimeBy(400)
        compose.waitForIdle()
        val second = draw()
        shot("animated-dark-frame-2")
        assertEquals(bounds, compose.onNodeWithTag("animated").getUnclippedBoundsInRoot())
        assertFalse("The indeterminate arc must change between frames", first.sameAs(second))
        first.recycle(); second.recycle()
    }
}
