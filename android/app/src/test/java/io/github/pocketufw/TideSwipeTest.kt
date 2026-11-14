package io.github.pocketufw

import androidx.activity.ComponentActivity
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import org.junit.After
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.util.concurrent.CountDownLatch

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class TideSwipeTest {
    @get:Rule val compose = createEmptyComposeRule()
    private val screens = mutableListOf<ActivityController<ComponentActivity>>()
    @After fun close() = drainMainLooper(screens)
    private fun node(text: String) = compose.onNodeWithText(text)
    private fun open(): FakeGateway {
        val fake = FakeGateway(tunnelDashboard())
        screens += compose.launchScreen(fake)
        compose.settle { compose.hasText("Active.") }
        return fake
    }
    private fun selected(tab: String) = node(tab).assertIsSelected()
    private fun swipeAt(text: String, left: Boolean = true, edge: Boolean = false) {
        val y = node(text).fetchSemanticsNode().boundsInRoot.center.y
        compose.onRoot().performTouchInput {
            val start = if (edge) { if (left) width - 1f else 1f } else width * if (left) .75f else .25f
            swipe(Offset(start, y), Offset(width * if (left) .25f else .75f, y), 250)
        }
    }

    @Test fun adjacentSwipesAndBottomNavigationShareOrderWithoutRootWorkOrWrapping() {
        val fake = open()
        swipeAt("Active.", left = false); selected("Firewall")
        swipeAt("Active."); selected("Activity")
        swipeAt("Activity."); selected("Insights")
        swipeAt("Insights."); selected("Settings")
        swipeAt("Settings."); selected("Settings")
        swipeAt("Settings.", left = false); selected("Insights")
        swipeAt("Insights.", left = false); selected("Activity")
        node("Settings").performClick()
        swipeAt("Settings.", left = false); selected("Insights")
        assertEquals(listOf("inspect"), fake.calls.toList())
    }

    @Test fun verticalDiagonalShortAndEdgeGesturesStayOnTheTab() {
        val fake = open()
        swipeAt("Active.", edge = true); selected("Firewall")
        swipeAt("Active.", left = false, edge = true); selected("Firewall")
        val y = node("Active.").fetchSemanticsNode().boundsInRoot.center.y
        compose.onRoot().performTouchInput {
            swipe(Offset(width * .6f, y), Offset(width * .55f, y), 200)
        }
        selected("Firewall")
        compose.onRoot().performTouchInput {
            swipe(Offset(width * .7f, y + 200), Offset(width * .3f, y - 200), 250)
        }
        selected("Firewall")
        node("Termux quick commands").performScrollTo().performClick()
        node("pufw raw").performScrollTo().assertIsDisplayed()
        val before = node("pufw raw").getUnclippedBoundsInRoot().top
        compose.onRoot().performTouchInput { swipeDown(startY = height * .35f, endY = height * .75f) }
        selected("Firewall")
        assertTrue(node("pufw raw").getUnclippedBoundsInRoot().top > before)
        assertEquals(listOf("inspect"), fake.calls.toList())
    }

    @Test fun swipesStartingOnButtonsNavigateWithoutClicksAndTabStateSurvives() {
        val fake = open()
        node("Turn firewall off").performScrollTo().performTouchInput { swipeLeft() }
        selected("Activity")
        compose.onNodeWithTag("confirm-turn-firewall-off").assertDoesNotExist()
        node("Firewall").performClick()
        node("Termux quick commands").performScrollTo().performClick()
        node("pufw clear").performScrollTo().performTouchInput { swipeLeft() }
        selected("Activity")
        node("Copied: pufw clear").assertDoesNotExist()
        node("Firewall").performClick()
        val before = node("pufw clear").fetchSemanticsNode().boundsInRoot.top
        node("Activity").performClick(); node("Firewall").performClick()
        node("pufw clear").assertIsDisplayed()
        assertEquals(before, node("pufw clear").fetchSemanticsNode().boundsInRoot.top, 1f)
        node("Termux quick commands").assert(SemanticsMatcher.expectValue(SemanticsProperties.StateDescription, "Expanded"))
        assertEquals(listOf("inspect"), fake.calls.toList())
    }

    @Test fun rawRuleHorizontalScrollWinsAndSubpageDoesNotSwipeAway() {
        val fake = open()
        node("Activity").performClick()
        node("Kernel rules").performClick(); node("Raw").performScrollTo().performClick()
        node("INPUT hooks").performScrollTo()
        swipeAt("INPUT hooks")
        selected("Activity")
        node("Settings").performClick()
        node("VPN UDP exceptions").performScrollTo().performClick()
        swipeAt("UDP exceptions.", left = false)
        node("UDP exceptions.").assertExists()
        selected("Settings")
        assertEquals(listOf("inspect"), fake.calls.toList())
    }

    @Test fun switchDoesNotMistakeHorizontalMovementForATapAndRemainsClickable() {
        val fake = open()
        node("Settings").performClick()
        // This Compose version's switch is toggleable, not draggable.
        compose.onNodeWithContentDescription("Restore after reboot").performScrollTo()
            .assertIsOn().performTouchInput { swipeLeft() }
        selected("Settings")
        assertEquals(listOf("inspect"), fake.calls.toList())
        compose.onNodeWithContentDescription("Restore after reboot").assertIsOn().performClick()
        compose.settle { fake.count("boot-disable") == 1 }
        selected("Settings")
        assertEquals(listOf("inspect", "boot-disable"), fake.calls.toList())
    }

    @Test fun startupShortcutIsAbsentWhetherFirewallIsActiveOrInactive() {
        val fake = open()
        node("Restore after reboot").assertDoesNotExist()
        node("Settings").performClick()
        compose.onNodeWithContentDescription("Restore after reboot").assertIsOn().assertIsEnabled()
        node("Firewall").performClick()
        fake.dashboard = fake.dashboard.copy(snapshot = fake.dashboard.snapshot.copy(
            protection = FirewallClient.Protection.INACTIVE,
            physicalFilter = FirewallClient.PhysicalFilter.INACTIVE,
            bootRestore = FirewallClient.BootRestore.DISABLED,
            tunnelFilter = FirewallClient.TunnelFilter.OFF,
            tunnelMode = FirewallClient.TunnelMode.OFF))
        compose.onNodeWithContentDescription("Recheck firewall status").performClick()
        compose.settle { fake.count("inspect") == 2 && compose.hasText("Inactive.") }
        node("Restore after reboot").assertDoesNotExist()
        node("Settings").performClick()
        compose.onNodeWithContentDescription("Restore after reboot").assertExists().assertIsNotEnabled()
        assertEquals(listOf("inspect", "inspect"), fake.calls.toList())
    }

    @Test fun samplingContinuesAcrossSwipesAndResultsSurviveCounterReset() {
        val fake = open()
        fake.insightsResult = parseInsights(ShellResult(0, insightsFixture()))
        node("Insights").performClick()
        val gate = CountDownLatch(1)
        fake.gate = gate
        try {
            compose.onNodeWithTag("sample-drops").performScrollTo().performClick()
            compose.settle { fake.count("insights-capture") == 1 }
            node("Insights.").performScrollTo()
            swipeAt("Insights."); selected("Settings")
            assertFalse(fake.lastInsightsRequest!!.isCancelled)
            swipeAt("Settings.", left = false); selected("Insights")
            compose.onNodeWithTag("stop-sample").assertExists()
            assertEquals(1, fake.count("insights-capture"))
        } finally { fake.gate = null; gate.countDown() }
        compose.settle { fake.count("inspect") == 2 && compose.hasText("1 DROP match") }
        node("Activity").performClick()
        node("Reset counters").performScrollTo().performClick()
        compose.onNodeWithTag("confirm-reset-counters").performClick()
        compose.settle { fake.count("reset-counters") == 1 && !compose.hasText("Resetting…") }
        node("Insights").performClick()
        node("1 DROP match").assertExists()
        assertEquals(1, fake.count("insights-capture"))
    }
}
