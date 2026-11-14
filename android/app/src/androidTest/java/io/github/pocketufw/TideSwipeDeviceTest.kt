package io.github.pocketufw

import android.graphics.Rect
import android.os.SystemClock
import android.view.accessibility.AccessibilityNodeInfo
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.FileInputStream
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Native Android input dispatch and real window insets; no root or firewall client.
 * Avoid Espresso's legacy InputManager reflection, which fails on Android 17.
 */
@RunWith(AndroidJUnit4::class)
class TideSwipeDeviceTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val automation get() = instrumentation.uiAutomation
    private var actions = 0

    private fun show(block: () -> Unit) {
        ActivityScenario.launch(ComponentActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                activity.enableEdgeToEdge()
                activity.setContent {
                    TideTheme {
                        TideScreen(TideUiState(snapshot = FirewallClient.Snapshot(
                            protection = FirewallClient.Protection.INACTIVE, rootReady = true,
                            bootRestore = FirewallClient.BootRestore.DISABLED)),
                            TideActions(recheck = { actions++ }, changeProtection = { actions++ }))
                    }
                }
            }
            await { find("Inactive.") != null }
            block()
            assertEquals("Navigation must not invoke firewall actions", 0, actions)
        }
    }

    private fun await(condition: () -> Boolean) {
        val deadline = SystemClock.uptimeMillis() + 5_000
        do {
            instrumentation.waitForIdleSync()
            if (condition()) return
            SystemClock.sleep(50)
        } while (SystemClock.uptimeMillis() < deadline)
        fail("Timed out waiting for UI")
    }

    private fun find(text: String): AccessibilityNodeInfo? {
        fun visit(node: AccessibilityNodeInfo): AccessibilityNodeInfo? {
            if (node.text?.toString() == text) return node
            for (i in 0 until node.childCount) node.getChild(i)?.let { visit(it)?.let { found -> return found } }
            return null
        }
        return automation.rootInActiveWindow?.let { visit(it) }
    }

    private fun bounds(text: String): Rect {
        await { find(text) != null }
        return Rect().also { requireNotNull(find(text)).getBoundsInScreen(it) }
    }

    private fun selected(tab: String) = await {
        var node = find(tab)
        while (node != null) {
            if (node.isSelected) return@await true
            node = node.parent
        }
        false
    }

    private fun shell(command: String) {
        automation.executeShellCommand(command).use { fd ->
            FileInputStream(fd.fileDescriptor).use { it.readBytes() }
        }
        instrumentation.waitForIdleSync()
    }

    private fun swipe(text: String, left: Boolean = true) {
        val y = bounds(text).centerY()
        val width = instrumentation.targetContext.resources.displayMetrics.widthPixels
        val start = (width * if (left) .75f else .25f).toInt()
        val end = (width * if (left) .25f else .75f).toInt()
        shell("input touchscreen swipe $start $y $end $y 300")
    }

    private fun tap(text: String) {
        val b = bounds(text)
        shell("input touchscreen tap ${b.centerX()} ${b.centerY()}")
    }

    @Test fun nativeTouchSwipesVisitAllFourTabsAndReturnWithoutActions() = show {
        swipe("Inactive."); selected("Activity")
        swipe("Activity."); selected("Insights")
        swipe("Insights."); selected("Settings")
        swipe("Settings."); selected("Settings")
        swipe("Settings.", left = false); selected("Insights")
        swipe("Insights.", left = false); selected("Activity")
        swipe("Activity.", left = false); selected("Firewall")
        swipe("Inactive.", left = false); selected("Firewall")
    }

    @Test fun nativeSwipeStartingOnButtonNavigatesWithoutClicking() = show {
        // A clickable consumes DOWN. That must not veto the later horizontal drag.
        swipe("Turn firewall on"); selected("Activity")
        swipe("Activity.", left = false); selected("Firewall")
        swipe("Termux quick commands"); selected("Activity")
        swipe("Activity.", left = false); selected("Firewall")
        assertNull(find("pufw")) // Drag did not expand the dropdown.
        tap("Termux quick commands")
        await { find("pufw") != null } // Ordinary taps still work.
    }

    @Test fun verticalScrollAndExpandedCommandsSurviveTabSwipes() = show {
        tap("Termux quick commands")
        await { find("pufw") != null }
        val width = instrumentation.targetContext.resources.displayMetrics.widthPixels
        val height = instrumentation.targetContext.resources.displayMetrics.heightPixels
        val before = bounds("pufw").top
        shell("input touchscreen swipe ${width / 2} ${height * 3 / 4} ${width / 2} ${height / 3} 400")
        selected("Firewall")
        await { find("pufw raw") != null && bounds("pufw").top < before }
        val scrolled = bounds("pufw raw")
        swipe("pufw raw"); selected("Activity")
        tap("Firewall"); selected("Firewall")
        await { find("pufw raw") != null }
        assertEquals("Returning to a tab must retain its scroll position", scrolled, bounds("pufw raw"))
        assertNull(find("Copied: pufw raw"))
    }

    @Test fun insetEdgeSwipesDoNotNavigateTabs() = show {
        tap("Insights"); selected("Insights")
        val y = bounds("Insights.").centerY()
        val width = instrumentation.targetContext.resources.displayMetrics.widthPixels
        // Inside our conservative edge guard, away from the OS's actual back strip.
        val edge = (20 * instrumentation.targetContext.resources.displayMetrics.density).toInt()
        shell("input touchscreen swipe $edge $y ${width / 2} $y 300")
        selected("Insights")
        shell("input touchscreen swipe ${width - edge} $y ${width / 2} $y 300")
        selected("Insights")
    }
}
