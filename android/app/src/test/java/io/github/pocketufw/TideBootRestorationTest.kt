package io.github.pocketufw

import android.graphics.Bitmap
import android.graphics.Canvas
import androidx.activity.ComponentActivity
import androidx.compose.ui.semantics.*
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.text.TextLayoutResult
import io.github.pocketufw.FirewallClient.*
import java.io.File
import java.util.concurrent.CountDownLatch
import kotlinx.coroutines.CancellationException
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

/** Exercises the real Settings screen and presentation state; no root or device access. */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class TideBootRestorationTest {
    @get:Rule val compose = createEmptyComposeRule()
    private val screens = mutableListOf<ActivityController<ComponentActivity>>()
    private val gates = mutableListOf<CountDownLatch>()
    private val progress = SemanticsMatcher.expectValue(SemanticsProperties.ProgressBarRangeInfo,
        ProgressBarRangeInfo.Indeterminate)
    private val unverified = "Restore after reboot could not be verified. Recheck status before trying again."

    @After fun close() { gates.forEach { it.countDown() }; drainMainLooper(screens) }
    private fun toggle() = compose.onNodeWithContentDescription("Restore after reboot")
    private fun open(fake: FakeGateway, dark: Boolean = false, large: Boolean = false) {
        screens += compose.launchScreen(fake,
            qualifiers = "w${if (large) 320 else 412}dp-h915dp-${if (dark) "night" else "notnight"}-xxhdpi",
            fontScale = if (large) 2f else 1f)
        compose.settle { fake.count("inspect") == 1 && compose.hasText("Active.") }
        compose.onNodeWithText("Settings").performClick()
        toggle().performScrollTo().assertIsEnabled()
    }
    private fun begin(fake: FakeGateway, enabling: Boolean): CountDownLatch {
        val gate = CountDownLatch(1).also { gates += it; fake.gate = it }
        toggle().performClick()
        compose.settle { fake.count(if (enabling) "boot-enable" else "boot-disable") == 1 }
        val label = if (enabling) "Enabling…" else "Disabling…"
        toggle().assertIsNotEnabled().assert(progress)
            .assert(SemanticsMatcher.expectValue(SemanticsProperties.StateDescription, label))
            .assert(SemanticsMatcher.expectValue(SemanticsProperties.LiveRegion, LiveRegionMode.Polite))
        if (enabling) toggle().assertIsOff() else toggle().assertIsOn()
        compose.onNodeWithText(label).performScrollTo().assertIsDisplayed()
        compose.onNodeWithTag("banner").assertDoesNotExist()
        compose.onNodeWithTag("banner-failed").assertDoesNotExist()
        return gate
    }
    private fun release(fake: FakeGateway, gate: CountDownLatch) {
        fake.gate = null
        gate.countDown()
        compose.settle { compose.onAllNodes(progress).fetchSemanticsNodes().isEmpty() }
        compose.onNodeWithTag("recheck-status").assertIsEnabled()
    }
    private fun noSuccess() {
        compose.onNodeWithText("Restore after reboot enabled.").assertDoesNotExist()
        compose.onNodeWithText("Restore after reboot disabled.").assertDoesNotExist()
        compose.onNodeWithTag("banner-failed").assertExists()
    }
    private fun shot(name: String) {
        val view = screens.last().get().window.decorView
        val bitmap = Bitmap.createBitmap(view.width, view.height, Bitmap.Config.ARGB_8888)
        compose.runOnIdle { view.draw(Canvas(bitmap)) }
        val directory = File("build/reports/tide-boot").also { it.mkdirs() }
        File(directory, "$name.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
        bitmap.recycle()
    }

    private fun verifiedChange(enabling: Boolean, dark: Boolean = false, large: Boolean = false) {
        val fake = FakeGateway(activeDashboard(if (enabling) BootRestore.DISABLED else BootRestore.ENABLED))
        open(fake, dark, large)
        val gate = begin(fake, enabling)
        if (large) {
            listOf("Restore after reboot", if (enabling) "Enabling…" else "Disabling…",
                "Uses Magisk at startup. No background app. Restores physical filtering only; tunnel filtering never restores."
            ).forEach { text ->
                val layouts = mutableListOf<TextLayoutResult>()
                compose.onNodeWithText(text).performSemanticsAction(SemanticsActions.GetTextLayoutResult) { it(layouts) }
                val layout = layouts.single()
                // As in TidePolishTest, check rendered lines: a short label can retain
                // a wider paragraph constraint without any glyphs actually overflowing.
                for (line in 0 until layout.lineCount) {
                    assertTrue("$text clips horizontally", layout.getLineRight(line) <= layout.size.width + 1)
                    assertTrue("$text clips vertically", layout.getLineBottom(line) <= layout.size.height + 1)
                    assertFalse("$text is ellipsized", layout.isLineEllipsized(line))
                }
                assertEquals(text.length, layout.getLineEnd(layout.lineCount - 1))
            }
        }
        shot("${if (enabling) "enabling" else "disabling"}-${if (dark) "dark" else "light"}-${if (large) "large" else "normal"}")
        repeat(3) { toggle().performClick() }
        compose.onNodeWithTag("recheck-status").performClick()
        // Switching tabs must preserve progress and the operation guard.
        compose.onNodeWithText("Firewall").performClick()
        compose.onNodeWithText("Settings").performClick()
        toggle().assertIsNotEnabled().assert(progress)
        fake.dashboard = activeDashboard(if (enabling) BootRestore.ENABLED else BootRestore.DISABLED)
        release(fake, gate)
        toggle().assertIsEnabled()
        if (enabling) toggle().assertIsOn() else toggle().assertIsOff()
        compose.onNodeWithText("Restore after reboot ${if (enabling) "enabled" else "disabled"}.").assertExists()
        compose.onNodeWithTag("banner-failed").assertDoesNotExist()
        assertEquals(listOf("inspect", if (enabling) "boot-enable" else "boot-disable"), fake.calls.toList())
    }
    @Test fun enablingWaitsForReadBackAndRejectsDuplicates() = verifiedChange(true)
    @Test fun disablingWaitsForReadBackAndRejectsDuplicates() = verifiedChange(false, dark = true)
    @Test fun largeTextLightProgressRemainsReadable() = verifiedChange(true, large = true)
    @Test fun largeTextDarkProgressRemainsReadable() = verifiedChange(false, dark = true, large = true)

    private fun unverifiedChange(boot: BootRestore, enabling: Boolean = true, rootReady: Boolean = true) {
        val fake = FakeGateway(activeDashboard(if (enabling) BootRestore.DISABLED else BootRestore.ENABLED))
        open(fake)
        val gate = begin(fake, enabling)
        val returned = activeDashboard(boot)
        fake.dashboard = returned.copy(snapshot = returned.snapshot.copy(rootReady = rootReady))
        // Even a claimed command success cannot stand in for a matching, readable boot state.
        release(fake, gate)
        noSuccess()
        compose.onNodeWithText(unverified).assertExists()
        if (bootProblemText(boot) != null) {
            toggle().assertDoesNotExist()
            compose.onNodeWithText(bootProblemText(boot)!!).assertExists()
        } else if (!rootReady) toggle().assertIsNotEnabled()
        else {
            if (boot == BootRestore.ENABLED) toggle().assertIsOn() else toggle().assertIsOff()
        }
    }
    @Test fun enablingCannotSucceedWithDisabledReadBack() = unverifiedChange(BootRestore.DISABLED)
    @Test fun disablingCannotSucceedWithEnabledReadBack() = unverifiedChange(BootRestore.ENABLED, enabling = false)
    @Test fun unknownBootStateIsNotSuccess() = unverifiedChange(BootRestore.UNKNOWN)
    @Test fun degradedBootStateIsNotSuccess() = unverifiedChange(BootRestore.DEGRADED)
    @Test fun conflictingBootStateIsNotSuccess() = unverifiedChange(BootRestore.CONFLICT)
    @Test fun unsupportedBootStateIsNotSuccess() = unverifiedChange(BootRestore.UNSUPPORTED)
    @Test fun missingRootVerificationIsNotSuccess() = unverifiedChange(BootRestore.ENABLED, rootReady = false)

    @Test fun failedDisablePreservesTheObservedStateAndFailureDetail() {
        val fake = FakeGateway()
        open(fake)
        val gate = begin(fake, enabling = false)
        fake.operationSuccess = false
        fake.operationMessage = "Could not remove the boot hook; inspect status."
        release(fake, gate)
        noSuccess()
        compose.onNodeWithText("Could not disable restore after reboot. ${fake.operationMessage} Recheck status before trying again.").assertExists()
        toggle().assertIsOn().assertIsEnabled()
    }

    @Test fun failedReadBackDoesNotRepeatTheBridgesEarlierSuccessMessage() {
        val fake = FakeGateway(activeDashboard(BootRestore.DISABLED))
        open(fake)
        val gate = begin(fake, enabling = true)
        fake.operationSuccess = false
        fake.operationMessage = "Magisk boot restoration enabled."
        release(fake, gate)
        noSuccess()
        compose.onNodeWithText(unverified).assertExists()
        compose.onNodeWithText(fake.operationMessage, substring = true).assertDoesNotExist()
        toggle().assertIsOff()
    }

    @Test fun timeoutStopsProgressAndKeepsTheRecheckInstruction() {
        val fake = FakeGateway(activeDashboard(BootRestore.DISABLED))
        open(fake)
        val gate = begin(fake, enabling = true)
        fake.operationSuccess = false
        fake.operationMessage = "Root command timed out; the firewall may still change. Recheck status."
        fake.dashboard = stateDashboard(Protection.DEGRADED, false,
            "A root command timed out and may still finish. Recheck before relying on the firewall.")
        release(fake, gate)
        noSuccess()
        compose.onNodeWithText("Could not enable restore after reboot. ${fake.operationMessage} Recheck status before trying again.").assertExists()
        toggle().assertDoesNotExist()
    }

    private fun thrownRequest(error: Exception) {
        val fake = FakeGateway(activeDashboard(BootRestore.DISABLED))
        open(fake)
        val gate = begin(fake, enabling = true)
        fake.requestFailure = error
        release(fake, gate)
        noSuccess()
        compose.onNodeWithText(unverified).assertExists()
        toggle().assertIsOff().assertIsNotEnabled()
        // An explicit, successful recheck restores interaction after an uncertain result.
        fake.requestFailure = null
        compose.onNodeWithTag("recheck-status").performClick()
        compose.settle { fake.count("inspect") == 2 && compose.hasText("Firewall status rechecked. No rules changed.") }
        toggle().assertIsEnabled()
    }
    @Test fun exceptionClearsProgressWithoutClaimingSuccess() = thrownRequest(IllegalStateException("test failure"))
    @Test fun cancellationClearsProgressWithoutClaimingSuccess() = thrownRequest(CancellationException("test cancellation"))

    private fun staleResult(outsideWrite: Boolean) {
        val fake = FakeGateway(activeDashboard(BootRestore.DISABLED))
        open(fake)
        val gate = begin(fake, enabling = true)
        if (outsideWrite) {
            TileStatusStore.invalidate(RuntimeEnvironment.getApplication(), TileStatusStore.SOURCE_TILE)
            compose.waitForIdle()
        }
        fake.dashboard = activeDashboard().copy(superseded = !outsideWrite)
        fake.nextInspections += activeDashboard(BootRestore.DISABLED)
        release(fake, gate)
        compose.settle { fake.count("inspect") == 2 }
        noSuccess()
        compose.onNodeWithText(unverified).assertExists()
        toggle().assertIsOff()
        assertEquals(listOf("inspect", "boot-enable", "inspect"), fake.calls.toList())
    }
    @Test fun supersededReadBackCannotReportSuccess() = staleResult(outsideWrite = false)
    @Test fun outsideWriteDuringBootChangeCannotReportSuccess() = staleResult(outsideWrite = true)
}
