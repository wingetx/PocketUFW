package io.github.pocketufw

import android.app.Activity
import android.app.Application
import android.content.Intent
import android.os.Bundle
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import androidx.test.platform.app.InstrumentationRegistry
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Android task/window routing, unlike Robolectric. No root: inject before onCreate. */
@RunWith(AndroidJUnit4::class)
@SdkSuppress(minSdkVersion = 29) // onActivityPreCreated precedes MainActivity.setContent.
class MainActivityEntryPointTest {
    @get:Rule val compose = createEmptyComposeRule()

    @Test fun mainAndTileLaunchesReuseOneScreenAndActivityNeverRequestsRoot() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val app = instrumentation.targetContext.applicationContext as Application
        val fake = OffGateway()
        val created = CopyOnWriteArrayList<MainActivity>()
        val resumes = AtomicInteger()
        val observer = object : Application.ActivityLifecycleCallbacks {
            override fun onActivityPreCreated(activity: Activity, state: Bundle?) {
                if (activity is MainActivity) { activity.newClient = { fake }; created += activity }
            }
            override fun onActivityResumed(activity: Activity) { if (activity is MainActivity) resumes.incrementAndGet() }
            override fun onActivityCreated(activity: Activity, state: Bundle?) = Unit
            override fun onActivityStarted(activity: Activity) = Unit
            override fun onActivityPaused(activity: Activity) = Unit
            override fun onActivityStopped(activity: Activity) = Unit
            override fun onActivitySaveInstanceState(activity: Activity, state: Bundle) = Unit
            override fun onActivityDestroyed(activity: Activity) = Unit
        }
        fun intent(action: String) = Intent(app, MainActivity::class.java).setAction(action)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK).apply {
                if (action == Intent.ACTION_MAIN) addCategory(Intent.CATEGORY_LAUNCHER)
            }
        app.registerActivityLifecycleCallbacks(observer)
        try {
            ActivityScenario.launch<MainActivity>(intent(Intent.ACTION_MAIN)).use {
                compose.waitUntil(10_000) {
                    compose.onAllNodesWithText("Turn firewall on").fetchSemanticsNodes().isNotEmpty()
                }
                compose.onNodeWithText("Turn firewall on").assertIsDisplayed()
                val original = created.single()
                repeat(3) { round ->
                    listOf(Intent.ACTION_MAIN, "android.service.quicksettings.action.QS_TILE_PREFERENCES").forEach { action ->
                        // Also cover a task behind the launcher, not only singleTop's easy case.
                        if (round == 1) {
                            assertTrue(instrumentation.uiAutomation.performGlobalAction(
                                android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_HOME))
                            compose.waitUntil(10_000) {
                                original.lifecycle.currentState == androidx.lifecycle.Lifecycle.State.CREATED
                            }
                        }
                        val before = resumes.get()
                        instrumentation.runOnMainSync { app.startActivity(intent(action)) }
                        compose.waitUntil(10_000) { resumes.get() > before }
                        compose.waitForIdle()
                        assertEquals(listOf(original), created.toList())
                        assertEquals(action, original.intent.action)
                        compose.onNodeWithText("Activity").performTouchInput { click(center) }
                        compose.onNodeWithText("Counters").assertIsDisplayed()
                        compose.onNodeWithText("Firewall").performTouchInput { click(center) }
                        compose.onNodeWithText("Turn firewall on").assertIsDisplayed()
                        assertEquals(listOf("inspect"), fake.calls.toList())
                    }
                }
            }
        } finally {
            // Includes any accidental second Activity if an assertion found a regression.
            instrumentation.runOnMainSync { created.forEach { it.finish() } }
            app.unregisterActivityLifecycleCallbacks(observer)
        }
    }
}

private class OffGateway : FirewallGateway {
    override fun inspectDrops(request: InsightsRequest, recovery: Boolean) = InsightsResult(error = "Unavailable in test")
    val calls = CopyOnWriteArrayList<String>()
    override fun inspectDashboard(): FirewallClient.Dashboard {
        calls += "inspect"
        return FirewallClient.Dashboard(FirewallClient.Snapshot(
            protection = FirewallClient.Protection.INACTIVE, rootReady = true, details = "Off."), null, null)
    }
    private fun unexpected(name: String): Nothing { calls += name; error("Unexpected operation: $name") }
    override fun refreshCounterActivity() = unexpected("counters")
    override fun changeProtection(activate: Boolean) = unexpected(if (activate) "enable" else "disable")
    override fun enableTunnelProtection(mode: FirewallClient.TunnelMode) = unexpected("tunnel-on")
    override fun refreshTunnelHooks() = unexpected("tunnel-refresh")
    override fun removeTunnelRules() = unexpected("tunnel-off")
    override fun removePartialRules() = unexpected("remove-partial")
    override fun prepareUninstall() = unexpected("prepare-uninstall")
    override fun changeBootRestoration(enabled: Boolean) = unexpected("boot")
    override fun refreshVerifiedPorts() = unexpected("vpn-refresh")
    override fun resetCounters() = unexpected("reset-counters")
    override fun updateUdpExceptions(ipv4: String, ipv6: String, committed: Boolean) = unexpected("set-ports")
    override fun restoreAutomaticUdpExceptions() = unexpected("use-auto")
}
