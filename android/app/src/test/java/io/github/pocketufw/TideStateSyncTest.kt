package io.github.pocketufw

import android.content.Context
import androidx.activity.ComponentActivity
import androidx.compose.ui.test.*
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import io.github.pocketufw.FirewallClient.BootRestore
import io.github.pocketufw.FirewallClient.Protection
import io.github.pocketufw.FirewallClient.RuleActivity
import io.github.pocketufw.FirewallClient.Snapshot
import java.util.concurrent.CountDownLatch
import org.junit.After
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/** PocketScreen against a fake gateway: which root requests it makes, and when. */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class TideStateSyncTest {
    @get:Rule val compose = createEmptyComposeRule()
    private val app: Context get() = RuntimeEnvironment.getApplication()
    private val off = stateDashboard(Protection.INACTIVE, true, "Off.", BootRestore.DISABLED)
    private val offSnapshot = Snapshot(Protection.INACTIVE, rootReady = true)
    private val screens = mutableListOf<ActivityController<ComponentActivity>>()

    @After fun closeScreens() = drainMainLooper(screens)

    private fun launch(fake: FakeGateway) = compose.launchScreen(fake).also { screens += it }

    private fun node(value: String, substring: Boolean = false) =
        compose.onNodeWithText(value, substring = substring)

    private fun open(fake: FakeGateway, expect: String = "Active."): ActivityController<ComponentActivity> =
        launch(fake).also {
            compose.settle { fake.count("inspect") >= 1 && compose.hasText(expect, true) }
            focus(it, true)
        }

    private fun focus(controller: ActivityController<ComponentActivity>, focused: Boolean) {
        controller.windowFocusChanged(focused)
        Thread.sleep(150) // Robolectric's focus listener dispatches asynchronously.
        compose.waitForIdle()
    }

    private fun tileWrites(snapshot: Snapshot = offSnapshot) {
        TileStatusStore.publish(app, snapshot, source = TileStatusStore.SOURCE_TILE)
    }

    /** Lets anything mistakenly scheduled run, then checks it didn't. */
    private fun assertStaysAt(fake: FakeGateway, name: String, expected: Int) {
        Thread.sleep(300)
        compose.waitForIdle()
        assertEquals(fake.calls.toString(), expected, fake.count(name))
    }

    private fun recheckButton() = compose.onNodeWithContentDescription("Recheck firewall status")
    private fun activityTab() { node("Activity").performClick(); compose.waitForIdle() }
    private fun confirmFirewallOff() {
        node("Turn firewall off").performClick()
        node("Turn firewall off?").assertExists()
        compose.onNodeWithTag("confirm-turn-firewall-off").performClick()
    }

    // ---- writes from the tile ----

    @Test fun aTileWriteWhileFocusedUpdatesTheAppSilently() {
        val fake = FakeGateway()
        open(fake)
        fake.dashboard = off
        tileWrites()
        compose.settle { compose.hasText("Off.") }
        assertEquals(2, fake.count("inspect"))
        node("RECHECK REQUIRED", substring = true).assertDoesNotExist()
        node("Firewall is off. No rules changed.").assertDoesNotExist()
    }

    @Test fun anInvalidationFromTheTileAlsoUpdatesTheApp() {
        val fake = FakeGateway()
        open(fake)
        fake.dashboard = off
        TileStatusStore.invalidate(app, TileStatusStore.SOURCE_TILE)
        compose.settle { compose.hasText("Off.") }
        assertEquals(2, fake.count("inspect"))
    }

    @Test fun whileTheRecheckRunsTheOldStatusIsNotClaimed() {
        val fake = FakeGateway()
        open(fake)
        val gate = CountDownLatch(1)
        fake.gate = gate
        tileWrites()
        compose.settle { fake.count("inspect") == 2 }
        node("RECHECK REQUIRED", substring = true).assertExists()
        node("Active.").assertDoesNotExist()
        gate.countDown()
        fake.gate = null
        compose.settle { compose.hasText("Active.") }
    }

    @Test fun theAppsOwnWritesDoNotTriggerAnotherRead() {
        val fake = FakeGateway()
        open(fake)
        TileStatusStore.publish(app, offSnapshot, source = TileStatusStore.SOURCE_APP)
        assertStaysAt(fake, "inspect", 1)
    }

    @Test fun aTileWriteDuringAnOperationIsRecheckedOnceItEnds() {
        val fake = FakeGateway()
        open(fake)
        val gate = CountDownLatch(1)
        fake.gate = gate
        confirmFirewallOff()
        compose.settle { fake.count("disable") == 1 }
        tileWrites()
        assertStaysAt(fake, "inspect", 1) // Nothing overlaps the running operation.
        fake.dashboard = off
        fake.gate = null
        gate.countDown()
        compose.settle { fake.count("inspect") == 2 && compose.hasText("Off.") }
        assertStaysAt(fake, "inspect", 2)
    }

    @Test fun anOperationsResultSurvivesTheRecheckItCaused() {
        val fake = FakeGateway()
        open(fake)
        fake.operationMessage = "Firewall disabled; boot restoration removed."
        val gate = CountDownLatch(1)
        fake.gate = gate
        confirmFirewallOff()
        compose.settle { fake.count("disable") == 1 }
        tileWrites()
        compose.waitForIdle()
        fake.gate = null
        gate.countDown()
        compose.settle { fake.count("inspect") == 2 && compose.hasText("Firewall disabled", true) }
    }

    @Test fun aTileWriteWhileUnfocusedWaitsForFocus() {
        val fake = FakeGateway()
        val controller = open(fake)
        focus(controller, false)
        fake.dashboard = off
        tileWrites()
        assertStaysAt(fake, "inspect", 1)
        focus(controller, true)
        compose.settle { fake.count("inspect") == 2 && compose.hasText("Off.") }
        assertStaysAt(fake, "inspect", 2)
    }

    @Test fun aTileWriteDuringTheFirstReadIsRecheckedAfterIt() {
        val fake = FakeGateway()
        val gate = CountDownLatch(1)
        fake.gate = gate
        // The CHECKING spinner never idles, and this holds the screen there.
        compose.mainClock.autoAdvance = false
        val controller = launch(fake)
        compose.settle { fake.count("inspect") == 1 }
        focus(controller, true)
        tileWrites()
        assertStaysAt(fake, "inspect", 1)
        fake.gate = null
        fake.nextInspections += activeDashboard()
        fake.dashboard = off
        gate.countDown()
        compose.mainClock.autoAdvance = true
        compose.settle { fake.count("inspect") == 2 && compose.hasText("Off.") }
    }

    @Test fun anUnchangedFocusReturnStillRequestsNoRoot() {
        val fake = FakeGateway()
        val controller = open(fake)
        repeat(3) {
            focus(controller, false)
            focus(controller, true)
        }
        assertStaysAt(fake, "inspect", 1)
    }

    // ---- superseded reads ----

    @Test fun aSupersededReadIsReadAgain() {
        val fake = FakeGateway()
        fake.nextInspections += activeDashboard().copy(superseded = true)
        fake.dashboard = off
        launch(fake)
        compose.settle { fake.count("inspect") == 2 && compose.hasText("Off.") }
        assertStaysAt(fake, "inspect", 2)
    }

    @Test fun aSupersededOperationIsReadAgainAndKeepsItsResult() {
        val fake = FakeGateway()
        open(fake)
        fake.operationMessage = "Firewall disabled; boot restoration removed."
        fake.dashboard = off.copy(superseded = true)
        fake.nextInspections += off
        confirmFirewallOff()
        compose.settle { fake.count("inspect") == 2 && compose.hasText("Off.") }
        node("Firewall disabled", substring = true).assertExists()
        node("RECHECK REQUIRED", substring = true).assertDoesNotExist()
    }

    @Test fun endlessSupersessionStopsAndNeverClaimsVerified() {
        val fake = FakeGateway(activeDashboard().copy(superseded = true))
        launch(fake)
        // The first read plus two more, then it stops asking for root.
        compose.settle { fake.count("inspect") >= 3 && compose.hasText("RECHECK REQUIRED", true) }
        assertStaysAt(fake, "inspect", 3)
        node("Turn firewall off").assertDoesNotExist()
        node("Active.").assertDoesNotExist()
    }

    @Test fun aManualRecheckThatIsSupersededReportsTheFinalState() {
        val fake = FakeGateway()
        open(fake)
        fake.nextInspections += activeDashboard().copy(superseded = true)
        fake.dashboard = off
        recheckButton().performClick()
        compose.settle { fake.count("inspect") == 3 && compose.hasText("Firewall is off. No rules changed.") }
        node("Firewall status rechecked. No rules changed.").assertDoesNotExist()
    }

    // ---- recheck wording ----

    @Test fun recheckWithoutRootDoesNotClaimToHaveChecked() {
        val fake = FakeGateway(stateDashboard(Protection.ROOT_REQUIRED, false, "No root."))
        open(fake, expect = "Root")
        recheckButton().performClick()
        compose.settle { compose.hasText("Couldn't check the firewall without root access.") }
        assertFalse(compose.hasText("Status checked", true))
    }

    @Test fun recheckThatTimedOutDoesNotBlameRoot() {
        val details = "A root command timed out and may still finish. Recheck before relying on the firewall."
        val fake = FakeGateway(stateDashboard(Protection.DEGRADED, false, details))
        open(fake, expect = "Needs")
        recheckButton().performClick()
        compose.settle { fake.count("inspect") == 2 }
        compose.waitUntil(5_000) { compose.onAllNodesWithText(details).fetchSemanticsNodes().size == 2 }
        assertFalse(compose.hasText("Couldn't check the firewall without root access."))
        assertFalse(compose.hasText("Status checked", true))
    }

    @Test fun recheckWordingMatchesTheStateFound() {
        val fake = FakeGateway()
        open(fake)
        recheckButton().performClick()
        compose.settle { compose.hasText("Firewall status rechecked. No rules changed.") }
        fake.dashboard = off
        recheckButton().performClick()
        compose.settle { compose.hasText("Firewall is off. No rules changed.") }
    }

    // ---- counter feedback ----

    @Test fun counterResultIsVisibleAfterAnEarlierRecheckBanner() {
        val fake = FakeGateway()
        open(fake)
        recheckButton().performClick()
        compose.settle { compose.hasText("Firewall status rechecked. No rules changed.") }
        activityTab()
        node("Refresh counters").performScrollTo().performClick()
        compose.settle { fake.count("counters") == 1 && compose.hasText("Counters refreshed at", true) }
        node("Firewall status rechecked. No rules changed.").assertDoesNotExist()
    }

    @Test fun aFailedCounterReadIsVisibleAfterAnEarlierSuccessBanner() {
        val error = "Firewall is not active or its policy could not be verified."
        val fake = FakeGateway(counterRead = RuleActivity(error = error))
        open(fake)
        recheckButton().performClick()
        compose.settle { compose.hasText("Firewall status rechecked. No rules changed.") }
        activityTab()
        node("Refresh counters").performScrollTo().performClick()
        compose.settle { compose.hasText(error) }
        node("Firewall status rechecked. No rules changed.").assertDoesNotExist()
        compose.onNodeWithTag("banner-failed").assertExists()
        node("Dismiss").performClick()
        compose.waitForIdle()
        node(error).assertDoesNotExist()
    }

    @Test fun aCounterSuccessAfterAFailedOperationDoesNotLookLikeAFailure() {
        val fake = FakeGateway()
        open(fake)
        fake.operationSuccess = false
        fake.operationMessage = "Could not remove all firewall rules; inspect status."
        confirmFirewallOff()
        compose.settle { compose.hasText(fake.operationMessage) }
        compose.onNodeWithTag("banner-failed").assertExists()
        activityTab()
        node("Refresh counters").performScrollTo().performClick()
        compose.settle { compose.hasText("Counters refreshed at", true) }
        compose.onNodeWithTag("banner").assertExists()
        compose.onNodeWithTag("banner-failed").assertDoesNotExist()
    }

    @Test fun dismissingACounterFailureClearsItsWarningStyle() {
        val fake = FakeGateway(counterRead = RuleActivity(error = "No counters."))
        open(fake)
        activityTab()
        node("Refresh counters").performScrollTo().performClick()
        compose.settle { compose.hasText("No counters.") }
        node("Dismiss").performClick()
        compose.waitForIdle()
        // The next read has inline progress, not the old failure banner/style.
        val gate = CountDownLatch(1)
        fake.gate = gate
        recheckButton().performClick()
        compose.settle { fake.count("inspect") == 2 }
        recheckButton().assert(SemanticsMatcher.expectValue(SemanticsProperties.StateDescription, "Checking…"))
        compose.onNodeWithTag("banner").assertDoesNotExist()
        compose.onNodeWithTag("banner-failed").assertDoesNotExist()
        fake.gate = null
        gate.countDown()
    }

    // ---- actions reach the gateway with the right direction ----

    @Test fun firewallOffNeedsConfirmationAndCancelDoesNotDisable() {
        val fake = FakeGateway()
        open(fake)
        node("Turn firewall off").performClick()
        node("Turn firewall off?").assertExists()
        assertEquals(0, fake.count("disable"))
        node("Cancel").performClick()
        node("Turn firewall off?").assertDoesNotExist()
        assertEquals(0, fake.count("disable"))
        confirmFirewallOff()
        compose.settle { fake.count("disable") == 1 }
        assertEquals(0, fake.count("enable"))
    }

    @Test fun pendingFirewallOffConfirmationDisappearsIfProtectionChanges() {
        val fake = FakeGateway()
        open(fake)
        node("Turn firewall off").performClick()
        node("Turn firewall off?").assertExists()
        fake.dashboard = off
        TileStatusStore.publish(app, offSnapshot, source = TileStatusStore.SOURCE_TILE)
        compose.settle { fake.count("inspect") == 2 && compose.hasText("Off.") }
        node("Turn firewall off?").assertDoesNotExist()
        assertEquals(0, fake.count("disable"))
    }

    @Test fun turnFirewallOffDisables() {
        val fake = FakeGateway()
        open(fake)
        confirmFirewallOff()
        compose.settle { fake.count("disable") == 1 }
        assertEquals(0, fake.count("enable"))
    }

    @Test fun turnFirewallOnEnables() {
        val fake = FakeGateway(off)
        open(fake, expect = "Off.")
        node("Turn firewall on").performClick()
        compose.settle { fake.count("enable") == 1 }
        assertEquals(0, fake.count("disable"))
    }

    @Test fun bootSwitchFollowsItsPosition() {
        val armed = FakeGateway(activeDashboard(boot = BootRestore.ENABLED))
        open(armed)
        node("Settings").performClick()
        compose.waitForIdle()
        compose.onNodeWithContentDescription("Restore after reboot").assertIsOn().performClick()
        compose.settle { armed.count("boot-disable") == 1 }
        assertEquals(0, armed.count("boot-enable"))
    }

    @Test fun bootSwitchEnablesWhenOff() {
        val disarmed = FakeGateway(activeDashboard(boot = BootRestore.DISABLED))
        open(disarmed)
        node("Settings").performClick()
        compose.waitForIdle()
        compose.onNodeWithContentDescription("Restore after reboot").assertIsOff().performClick()
        compose.settle { disarmed.count("boot-enable") == 1 }
        assertEquals(0, disarmed.count("boot-disable"))
    }

    @Test fun aFailedOperationIsPresentedAsAFailure() {
        val fake = FakeGateway()
        open(fake)
        fake.operationSuccess = false
        fake.operationMessage = "Could not remove all firewall rules; inspect status."
        confirmFirewallOff()
        compose.settle { compose.hasText("Could not remove all firewall rules; inspect status.") }
        compose.onNodeWithTag("banner-failed").assertExists()
    }

    @Test fun aSuccessfulOperationIsNotPresentedAsAFailure() {
        val fake = FakeGateway()
        open(fake)
        fake.operationMessage = "Firewall disabled; boot restoration removed."
        confirmFirewallOff()
        compose.settle { compose.hasText("Firewall disabled; boot restoration removed.") }
        compose.onNodeWithTag("banner").assertExists()
        compose.onNodeWithTag("banner-failed").assertDoesNotExist()
    }

    @Test fun aTimedOutDashboardOffersOnlyARecheck() {
        val fake = FakeGateway(stateDashboard(Protection.DEGRADED, false,
            "A root command timed out and may still finish. Recheck before relying on the firewall."))
        open(fake, expect = "Needs")
        node("Recheck status").assertExists()
        node("Remove partial PocketUFW rules").assertDoesNotExist()
        node("Turn firewall off").assertDoesNotExist()
        node("Turn firewall on").assertDoesNotExist()
        assertFalse(compose.hasText("Root\nrequired."))
    }
}
