package io.github.pocketufw

import android.content.ComponentName
import android.content.Intent
import android.content.pm.ActivityInfo
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import io.github.pocketufw.FirewallClient.Protection
import java.util.concurrent.CountDownLatch
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

/** Pointer dispatch + real MainActivity lifecycle. AMS launch routing is tested on Android. */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class MainActivityLaunchTest {
    @get:Rule val compose = createEmptyComposeRule()
    private lateinit var screen: ActivityController<MainActivity>
    private val fake = FakeGateway(stateDashboard(Protection.INACTIVE, true, "Off."))
    private val gates = mutableListOf<CountDownLatch>()
    private val actions = listOf(Intent.ACTION_MAIN, "android.service.quicksettings.action.QS_TILE_PREFERENCES")
    @After fun close() {
        gates.forEach { it.countDown() }
        if (::screen.isInitialized) runCatching { screen.pause().stop().destroy() }
        drainMainLooper()
    }
    private fun open() {
        RuntimeEnvironment.setQualifiers("w412dp-h915dp-xxhdpi")
        screen = Robolectric.buildActivity(MainActivity::class.java)
        screen.get().newClient = { fake }
        screen.setup()
        compose.settle { fake.count("inspect") == 1 && compose.hasText("Turn firewall on") }
    }
    private fun relaunch(action: String) {
        compose.runOnIdle {
            // Android delivers a singleTask launch through pause -> onNewIntent -> resume.
            screen.pause().newIntent(Intent(action).setComponent(ComponentName(screen.get(), MainActivity::class.java)))
                .resume()
        }
        compose.waitForIdle()
    }
    private fun tapStatistics() {
        // Hit testing is intentional: performClick() invokes semantics, bypassing touch routing.
        compose.onNodeWithTag("statistics-pill").performScrollTo().performTouchInput { click(center) }
    }
    @Test fun bothEntryPointsResolveToTheSameSingleTaskActivity() {
        val context = RuntimeEnvironment.getApplication()
        val component = ComponentName(context, MainActivity::class.java)
        actions.forEach { action ->
            val intent = Intent(action).setPackage(context.packageName)
            if (action == Intent.ACTION_MAIN) intent.addCategory(Intent.CATEGORY_LAUNCHER)
            val info = context.packageManager.resolveActivity(intent, 0)!!.activityInfo
            assertEquals(component.className, info.name)
            assertEquals(ActivityInfo.LAUNCH_SINGLE_TASK, info.launchMode)
        }
    }
    @Test fun repeatedMainAndTileIntentsPreserveStatisticsAndNeverMutate() {
        open()
        repeat(3) {
            actions.forEach { action ->
                relaunch(action)
                assertEquals(action, screen.get().intent.action)
                tapStatistics()
                compose.onNodeWithTag("statistics-pill").assert(SemanticsMatcher.expectValue(
                    SemanticsProperties.StateDescription, "Expanded"))
                relaunch(action)
                // A launch must not reconstruct the composition or collapse its saved state.
                compose.onNodeWithTag("statistics-pill").assert(SemanticsMatcher.expectValue(
                    SemanticsProperties.StateDescription, "Expanded"))
                tapStatistics()
            }
        }
        assertEquals(listOf("inspect"), fake.calls.toList())
    }
    @Test fun pausedScreenCannotStartAnOperationFromAStaleCallback() {
        open()
        val staleAction = compose.onNodeWithTag("firewall-action").fetchSemanticsNode()
            .config[androidx.compose.ui.semantics.SemanticsActions.OnClick].action!!
        compose.runOnIdle { screen.pause(); staleAction() }
        compose.waitForIdle()
        assertEquals(listOf("inspect"), fake.calls.toList())
        screen.resume()
        tapStatistics()
        assertEquals(listOf("inspect"), fake.calls.toList())
    }
    @Test fun relaunchDuringOperationPreservesBusyStateAndDoesNotQueueAnotherEnable() {
        open()
        val gate = CountDownLatch(1).also { gates += it; fake.gate = it }
        compose.onNodeWithTag("firewall-action").performTouchInput { click(center) }
        compose.settle { fake.count("enable") == 1 }
        actions.forEach {
            relaunch(it)
            compose.onNodeWithTag("firewall-action").assertIsNotEnabled()
            compose.onNodeWithText("Activating…").assertIsDisplayed()
            tapStatistics(); tapStatistics()
        }
        assertEquals(listOf("inspect", "enable"), fake.calls.toList())
        fake.gate = null; gate.countDown()
        compose.settle { compose.hasText("Turn firewall on") }
        tapStatistics()
        assertEquals(listOf("inspect", "enable"), fake.calls.toList())
    }
    @Test fun relaunchKeepsNavigationAndBackReturnsToFirewall() {
        open()
        compose.onNodeWithText("Settings").performTouchInput { click(center) }
        actions.forEach { relaunch(it); compose.onNodeWithText("Tunnel protection").assertExists() }
        compose.runOnIdle { screen.get().onBackPressedDispatcher.onBackPressed() }
        tapStatistics()
        assertEquals(listOf("inspect"), fake.calls.toList())
    }

    @Test fun statisticsAfterShutdownAndRepeatedLaunchesCannotReactivate() {
        open()
        fake.dashboard = activeDashboard()
        compose.onNodeWithTag("recheck-status").performClick()
        compose.settle { compose.hasText("Turn firewall off") }
        fake.dashboard = stateDashboard(Protection.INACTIVE, true, "Off.")
        compose.onNodeWithTag("firewall-action").performTouchInput { click(center) }
        compose.onNodeWithTag("confirm-turn-firewall-off").performClick()
        compose.settle { compose.hasText("Turn firewall on") }
        repeat(3) { actions.forEach { relaunch(it); tapStatistics(); tapStatistics() } }
        assertEquals(listOf("inspect", "inspect", "disable"), fake.calls.toList())
    }
}
