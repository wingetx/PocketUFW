package io.github.pocketufw

import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.platform.AccessibilityManager
import androidx.compose.ui.platform.LocalAccessibilityManager
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import org.junit.After
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class TideFeedbackTest {
    @get:Rule val compose = createEmptyComposeRule()
    private val screens = mutableListOf<ActivityController<ComponentActivity>>()
    @After fun drain() = drainMainLooper(screens)
    private fun click(text: String) = compose.onNodeWithText(text).performScrollTo().performClick()
    private fun open(fake: FakeGateway) {
        screens += compose.launchScreen(fake)
        compose.settle { fake.count("inspect") == 1 && !compose.hasText("Checking…") }
    }
    private fun advance(ms: Long) {
        compose.mainClock.advanceTimeBy(ms)
        compose.waitForIdle()
    }

    @Test fun routineRecheckExpiresWithoutAnotherRootRead() {
        val fake = FakeGateway(tunnelDashboard())
        open(fake)
        compose.onNodeWithContentDescription("Recheck firewall status").performClick()
        compose.settle { compose.hasText("Firewall status rechecked. No rules changed.") }
        advance(3_000)
        compose.onNodeWithTag("banner").assertExists()
        advance(3_500)
        compose.onNodeWithTag("banner").assertDoesNotExist()
        assertEquals(listOf("inspect", "inspect"), fake.calls.toList())
    }

    @Test fun counterResetAndRefreshConfirmationsExpireWithoutChangingCountersOrRules() {
        val fake = FakeGateway(tunnelDashboard(), counterRead = tunnelActivity())
        open(fake)
        compose.onNodeWithText("Activity").performClick(); click("Reset counters")
        compose.onNodeWithTag("confirm-reset-counters").performClick()
        compose.settle { compose.hasText(BridgeMessages.RESET_OK) }
        advance(6_500)
        compose.onNodeWithTag("banner").assertDoesNotExist()
        click("Refresh counters")
        compose.settle { compose.hasText("Counters refreshed at", true) }
        advance(6_500)
        compose.onNodeWithTag("banner").assertDoesNotExist()
        compose.onNodeWithContentDescription("Tunnel Drop-rule matches: 153 packets.", substring = true).assertExists()
        assertEquals(listOf("inspect", "reset-counters", "counters"), fake.calls.toList())
    }

    @Test fun policyChangeWarningsRemainUntilDismissed() {
        val fake = FakeGateway(tunnelDashboard(), counterRead = tunnelActivity().copy(tailnetPin4 = "100.64.0.9/32"))
        open(fake)
        compose.onNodeWithText("Activity").performClick(); click("Refresh counters")
        compose.settle { compose.hasText("Counters read, but tunnel policy changed.", true) }
        advance(60_000)
        compose.onNodeWithTag("banner-failed").assertExists()
        compose.onNodeWithTag("reset-counters").assertIsNotEnabled()
        compose.onNodeWithText("Dismiss").performClick()
        compose.onNodeWithTag("banner-failed").assertDoesNotExist()
        // Dismissal acknowledges a message, never grants verification.
        compose.onNodeWithTag("reset-counters").assertIsNotEnabled()
        assertEquals(listOf("inspect", "counters"), fake.calls.toList())
    }

    @Test fun aNonRoutineSuccessfulOperationRemainsUntilDismissed() {
        val fake = FakeGateway().apply { operationMessage = "Firewall disabled." }
        open(fake)
        click("Turn firewall off")
        compose.onNodeWithTag("confirm-turn-firewall-off").performClick()
        compose.settle { compose.hasText("Firewall disabled.") }
        advance(60_000)
        compose.onNodeWithText("Firewall disabled.").assertExists()
        compose.onNodeWithText("Dismiss").performClick()
        compose.onNodeWithText("Firewall disabled.").assertDoesNotExist()
        assertEquals(listOf("inspect", "disable"), fake.calls.toList())
    }

    @Test fun accessibilityTimeoutIsRespectedAndOldTimersCannotDismissNewFailures() {
        val model = mutableStateOf(TideUiState(message = "Status rechecked", transientMessage = true))
        var dismissals = 0
        var requestedTimeout = 0L
        val accessibility = object : AccessibilityManager {
            override fun calculateRecommendedTimeoutMillis(originalTimeoutMillis: Long,
                containsIcons: Boolean, containsText: Boolean, containsControls: Boolean): Long {
                requestedTimeout = originalTimeoutMillis
                assertTrue(containsText)
                assertTrue(containsControls) // The banner's Dismiss action must remain reachable.
                return 20_000L
            }
        }
        val controller = Robolectric.buildActivity(ComponentActivity::class.java).setup().also { screens += it }
        controller.get().setContent {
            CompositionLocalProvider(LocalAccessibilityManager provides accessibility) {
                TideTheme { TideScreen(model.value, TideActions(dismissMessage = {
                    dismissals++
                    model.value = model.value.copy(message = "", transientMessage = false)
                })) }
            }
        }
        compose.waitForIdle()
        assertEquals(6_000L, requestedTimeout)
        advance(10_000)
        compose.onNodeWithText("Status rechecked").assertExists()
        advance(10_500)
        compose.onNodeWithText("Status rechecked").assertDoesNotExist()
        assertEquals(1, dismissals)
        compose.runOnIdle { model.value = model.value.copy(message = "Counters reset", transientMessage = true) }
        compose.waitForIdle()
        advance(3_000)
        compose.runOnIdle { model.value = model.value.copy(message = "Could not verify", failed = true) }
        compose.waitForIdle()
        advance(60_000)
        compose.onNodeWithText("Could not verify").assertExists()
        assertEquals(1, dismissals)
    }
}
