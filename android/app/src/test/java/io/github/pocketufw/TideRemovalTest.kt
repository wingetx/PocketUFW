package io.github.pocketufw

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import io.github.pocketufw.FirewallClient.Protection
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger
import org.junit.After
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/** Remove PocketUFW: Android's page opens only after the bridge's read-back came back clean. */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class TideRemovalTest {
    @get:Rule val compose = createEmptyComposeRule()
    private val screens = mutableListOf<ActivityController<ComponentActivity>>()
    private val opens = AtomicInteger()
    private var appInfoAvailable = true

    @After fun closeScreens() = drainMainLooper(screens)

    private val off = stateDashboard(Protection.INACTIVE, true, "off", FirewallClient.BootRestore.DISABLED)
    private val row = "Remove PocketUFW"
    private val confirm = "confirm-remove-pocketufw"

    private fun node(value: String, substring: Boolean = false) =
        compose.onNodeWithText(value, substring = substring)

    private fun open(fake: FakeGateway) {
        screens += compose.launchScreen(fake, openAppInfo = { opens.incrementAndGet(); appInfoAvailable })
        compose.settle { compose.hasText("Active.") || compose.hasText("Firewall", true) }
        compose.onAllNodesWithText("Settings").onFirst().performClick()
        compose.waitForIdle()
    }

    private fun tapRow() {
        node(row).performScrollTo().performClick()
        compose.waitForIdle()
    }

    private fun remove(fake: FakeGateway) {
        tapRow()
        compose.onNodeWithTag(confirm).performClick()
        compose.settle { fake.count("prepare-uninstall") >= 1 && !compose.hasText("Working…") }
        compose.waitForIdle()
    }

    private fun clean() = FakeGateway().apply {
        removalDashboard = off
        operationMessage = "PocketUFW's rules and boot files are gone. Tap Uninstall to finish."
    }

    private fun incomplete() = FakeGateway().apply {
        removalClean = false
        operationMessage = "Couldn't confirm everything is gone. Still present: IPv4 rules."
    }

    @Test fun theRowWarnsBeforeAnyoneUninstalls() {
        open(FakeGateway())
        node("Uninstalling without this leaves the firewall running until you restart the phone.")
            .performScrollTo().assertIsDisplayed()
    }

    @Test fun nothingHappensUntilConfirmed() {
        val fake = clean()
        open(fake)
        tapRow()
        node("Remove PocketUFW?").assertIsDisplayed()
        node("This turns the firewall off now", true).assertIsDisplayed()
        node("Rules from Android, VPNs and other apps aren\u2019t touched", true).assertDoesNotExist()
        node("Rules from Android, VPNs and other apps aren't touched", true).assertIsDisplayed()
        assertEquals(0, fake.count("prepare-uninstall"))
        assertEquals(0, opens.get())
        node("Cancel").performClick()
        compose.waitForIdle()
        node("Remove PocketUFW?").assertDoesNotExist()
        assertEquals(0, fake.count("prepare-uninstall"))
        assertEquals(0, opens.get())
    }

    @Test fun aCleanResultOpensAndroidsPageOnce() {
        val fake = clean()
        open(fake)
        remove(fake)
        assertEquals(1, fake.count("prepare-uninstall"))
        assertEquals(1, opens.get())
        node("The firewall is off and PocketUFW is still installed", true).performScrollTo().assertIsDisplayed()
    }

    @Test fun androidsPageWaitsForTheResult() {
        val fake = clean()
        open(fake)
        fake.gate = CountDownLatch(1)
        tapRow()
        compose.onNodeWithTag(confirm).performClick()
        compose.settle { fake.count("prepare-uninstall") == 1 }
        assertEquals(0, opens.get())
        fake.gate?.countDown()
        compose.settle { opens.get() == 1 }
    }

    @Test fun anIncompleteResultNeverOpensAndroidsPageAndSaysWhatIsLeft() {
        val fake = incomplete()
        open(fake)
        remove(fake)
        assertEquals(0, opens.get())
        node("Still present: IPv4 rules", true).performScrollTo().assertIsDisplayed()
        node("Try again").performScrollTo().assertIsDisplayed()
        node("Uninstall anyway").performScrollTo().assertIsDisplayed()
        compose.onNodeWithTag("banner-failed").assertExists()
    }

    @Test fun aFailedCallNeverOpensAndroidsPage() {
        val fake = FakeGateway().apply { removalThrows = true }
        open(fake)
        remove(fake)
        assertEquals(0, opens.get())
        node("Try again").performScrollTo().assertIsDisplayed()
        compose.onNodeWithTag("banner-failed").assertExists()
    }

    @Test fun rootDeniedShowsNoFalseClaim() {
        val fake = FakeGateway().apply {
            removalClean = false
            removalDashboard = stateDashboard(Protection.ROOT_REQUIRED, false, "root needed")
            operationMessage = "Root access is needed for this action."
        }
        open(fake)
        remove(fake)
        assertEquals(0, opens.get())
        node("Root access is needed for this action.").performScrollTo().assertIsDisplayed()
        node("PocketUFW is still installed", true).assertDoesNotExist()
        node("Turn firewall back on").assertDoesNotExist()
    }

    @Test fun tryAgainRunsTheRemovalAgain() {
        val fake = incomplete()
        open(fake)
        remove(fake)
        fake.removalClean = true
        fake.removalDashboard = off
        fake.operationMessage = "PocketUFW's rules and boot files are gone. Tap Uninstall to finish."
        node("Try again").performScrollTo().performClick()
        compose.settle { opens.get() == 1 }
        assertEquals(2, fake.count("prepare-uninstall"))
        node("Try again").assertDoesNotExist()
    }

    @Test fun uninstallAnywayWarnsFirst() {
        val fake = incomplete()
        open(fake)
        remove(fake)
        node("Uninstall anyway").performScrollTo().performClick()
        compose.waitForIdle()
        node("Any rules still in the kernel stay until you restart the phone", true).assertIsDisplayed()
        assertEquals(0, opens.get())
        node("Cancel").performClick()
        compose.waitForIdle()
        assertEquals(0, opens.get())
        node("Uninstall anyway").performScrollTo().performClick()
        compose.waitForIdle()
        compose.onNodeWithTag("confirm-uninstall-anyway").performClick()
        compose.settle { opens.get() == 1 }
    }

    @Test fun afterBackingOutTheAppPageCanBeReopened() {
        val fake = clean()
        open(fake)
        remove(fake)
        node("Open Android's app page").performScrollTo().performClick()
        compose.settle { opens.get() == 2 }
        assertEquals(1, fake.count("prepare-uninstall"))
    }

    @Test fun turningBackOnClearsTheNotice() {
        val fake = clean()
        fake.operationMessage = "gone"
        open(fake)
        remove(fake)
        fake.dashboard = activeDashboard()
        node("Turn firewall back on").performScrollTo().performClick()
        compose.settle { fake.count("enable") == 1 && !compose.hasText("Working…") }
        compose.waitForIdle()
        node("PocketUFW is still installed", true).assertDoesNotExist()
    }

    @Test fun theFirewallReturningAnyOtherWayClearsTheNotice() {
        val fake = clean()
        open(fake)
        remove(fake)
        fake.dashboard = activeDashboard()
        compose.onNodeWithContentDescription("Recheck firewall status").performClick()
        compose.settle { fake.count("inspect") >= 2 && !compose.hasText("Working…") }
        compose.waitForIdle()
        node("PocketUFW is still installed", true).assertDoesNotExist()
    }

    @Test fun anOldCleanResultDoesntReturnWhenTheFirewallGoesOffAgain() {
        val fake = clean()
        open(fake)
        remove(fake)
        fake.dashboard = activeDashboard()
        compose.onNodeWithContentDescription("Recheck firewall status").performClick()
        compose.settle { fake.count("inspect") >= 2 && !compose.hasText("Working…") }
        fake.dashboard = off
        compose.onNodeWithContentDescription("Recheck firewall status").performClick()
        compose.settle { fake.count("inspect") >= 3 && !compose.hasText("Working…") }
        compose.waitForIdle()
        node("PocketUFW is still installed", true).assertDoesNotExist()
    }

    @Test fun anotherOperationClearsAnOldIncompleteResult() {
        val fake = incomplete()
        open(fake)
        remove(fake)
        node("Try again").performScrollTo().assertIsDisplayed()
        fake.operationSuccess = true
        fake.operationMessage = "done"
        node("Restore after reboot").performScrollTo()
        compose.onNode(hasContentDescription("Restore after reboot") and isToggleable()).performClick()
        compose.settle { fake.count("boot-enable") + fake.count("boot-disable") == 1 && !compose.hasText("Working…") }
        compose.waitForIdle()
        node("Try again").assertDoesNotExist()
        node("Uninstall anyway").assertDoesNotExist()
    }

    @Test fun anAndroidWithoutThatPageGetsDirections() {
        appInfoAvailable = false
        val fake = clean()
        open(fake)
        remove(fake)
        compose.settle { compose.hasText("Android's app page didn't open", true) }
        compose.onNodeWithTag("banner-failed").assertExists()
    }

    @Test fun theRowDoesNothingWhileAnOperationRuns() {
        val fake = FakeGateway()
        open(fake)
        fake.gate = CountDownLatch(1)
        compose.onNodeWithContentDescription("Recheck firewall status").performClick()
        compose.settle { fake.count("inspect") >= 2 }
        tapRow()
        node("Remove PocketUFW?").assertDoesNotExist()
        fake.gate?.countDown()
    }

    @Test fun theIntentIsAndroidsAppPageForThisPackage() {
        val app = RuntimeEnvironment.getApplication()
        assertTrue(openAndroidAppInfo(app as Context))
        val started: Intent = Shadows.shadowOf(app).nextStartedActivity
        assertEquals(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, started.action)
        assertEquals(Uri.parse("package:" + app.packageName), started.data)
        assertTrue(started.flags and Intent.FLAG_ACTIVITY_NEW_TASK != 0)
    }
}
