package io.github.pocketufw

import android.graphics.Bitmap
import android.graphics.Canvas
import androidx.activity.ComponentActivity
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
import java.io.File
import java.util.concurrent.CountDownLatch

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class TideInsightsTest {
    @get:Rule val compose = createEmptyComposeRule()
    private val screens = mutableListOf<ActivityController<ComponentActivity>>()
    @After fun drain() = drainMainLooper(screens)
    private fun open(fake: FakeGateway, scale: Float = 1f, width: Int = 412) {
        screens += compose.launchScreen(fake, "w${width}dp-h915dp-xxhdpi", scale)
        compose.settle { fake.count("inspect") == 1 && !compose.hasText("Checking…") }
        compose.onNodeWithText("Insights").performClick()
    }
    private fun shot(name: String) {
        val view = screens.last().get().window.decorView
        val bitmap = Bitmap.createBitmap(view.width, view.height, Bitmap.Config.ARGB_8888)
        compose.runOnIdle { view.draw(Canvas(bitmap)) }
        File("build/reports/tide-ui").mkdirs()
        File("build/reports/tide-ui/insights-$name.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
    }
    @Test fun navigationDoesNotCaptureAndCountersRemainSeparate() {
        val fake = FakeGateway(tunnelDashboard()); open(fake)
        assertEquals(listOf("inspect"), fake.calls.toList())
        compose.onNodeWithText("COUNTER SNAPSHOT").assertDoesNotExist()
        compose.onNodeWithText("Historical rule matches").assertDoesNotExist()
        compose.onNodeWithText("Refresh counters").assertDoesNotExist()
        compose.onNodeWithText("Reset counters").assertDoesNotExist()
        compose.onNodeWithText("What’s being dropped now?").assertIsDisplayed()
        compose.onNodeWithTag("recover-insights").assertDoesNotExist()
        compose.onNodeWithText("Sample interrupted?").assert(SemanticsMatcher.expectValue(SemanticsProperties.StateDescription, "Collapsed"))
        compose.onNodeWithText("Check for leftover temporary rules").assertExists()
        compose.onNodeWithText("Troubleshooting").assertDoesNotExist()
        shot("overview")
        compose.onNodeWithTag("sample-drops").performScrollTo().assertIsEnabled()
        compose.onNodeWithText("A short sample cannot explain the entire historical DROP count.").assertExists()
        shot("ready")
        compose.onNodeWithText("Activity").performClick()
        compose.onNodeWithText("Counters").assertExists()
        compose.onNodeWithText("IPv4 replies").assertExists()
        compose.onNodeWithText("IPv6 replies").assertExists()
        assertEquals(listOf("inspect"), fake.calls.toList())
    }
    @Test fun sampleIsUserInitiatedAndDisplaysQualifiedResults() {
        val fake = FakeGateway(tunnelDashboard()).apply { insightsResult = parseInsights(ShellResult(0, insightsFixture())) }
        open(fake)
        compose.onNodeWithTag("sample-drops").performScrollTo().performClick()
        compose.settle { fake.count("inspect") == 2 && compose.hasText("1 DROP match") }
        assertEquals(1, fake.count("insights-capture"))
        compose.onNodeWithText("1 DROP match").performScrollTo()
        shot("sample")
        compose.onNodeWithText("Possible SSDP / UPnP").performScrollTo().assertExists()
        compose.onNodeWithText("Observed: UDP port 1900").assertExists()
        shot("clues")
        compose.onNodeWithText("Protocols observed").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("UDP").assertExists()
        compose.onNodeWithText("Most frequent sources").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("192.168.1.1").assertExists()
        compose.onNodeWithText("Physical · IPv4").assertExists()
        shot("sources")
        compose.onNodeWithText("Clear sample").performScrollTo().performClick()
        compose.onNodeWithText("1 DROP match").assertDoesNotExist()
        assertEquals(1, fake.count("insights-capture"))
        assertEquals(listOf("inspect", "insights-capture", "inspect"), fake.calls.toList())
    }
    @Test fun failedSampleWithoutResidueKeepsRecoveryInTroubleshooting() {
        val fake = FakeGateway().apply { insightsResult = InsightsResult(error = "Cleanup not verified.") }
        open(fake)
        compose.onNodeWithTag("sample-drops").performScrollTo().performClick()
        compose.settle { compose.hasText("Cleanup not verified.") && fake.count("inspect") == 2 }
        compose.onNodeWithText("0 DROP matches").assertDoesNotExist()
        compose.onNodeWithTag("recover-insights").assertDoesNotExist()
        compose.onNodeWithText("Sample interrupted?").performScrollTo().performClick()
        fake.insightsResult = InsightsResult(recovered = true)
        compose.onNodeWithTag("recover-insights").performScrollTo().performClick()
        compose.settle { compose.hasText("Recovery verified: no Insights probes remain.", true) }
        // A no-op recovery reports the same success, so the UI must not claim anything was removed.
        compose.onNodeWithText("Insights probes removed.", substring = true).assertDoesNotExist()
        assertEquals(1, fake.count("insights-recover"))
        compose.settle { fake.count("inspect") == 3 }
        compose.onNodeWithTag("recover-insights").assertDoesNotExist()
    }
    @Test fun duplicateSamplingIsDisabledAndStopRemainsAvailable() {
        val fake = FakeGateway(); open(fake)
        val gate = CountDownLatch(1); fake.gate = gate
        try {
            compose.onNodeWithTag("sample-drops").performScrollTo().performClick()
            compose.settle { fake.count("insights-capture") == 1 }
            compose.onNodeWithTag("sample-drops").assertIsNotEnabled()
            compose.onNodeWithTag("stop-sample").performScrollTo().assertIsEnabled().performClick()
            compose.onNodeWithTag("stop-sample").assertIsNotEnabled()
            shot("stopping")
        } finally { gate.countDown(); fake.gate = null }
        compose.settle { fake.count("inspect") == 2 }
    }
    @Test fun withheldSampleUsesFreshProtectionStatusWithoutPromotingRecovery() {
        val withheld = "Probes removed, but other firewall rules changed during the sample; sample withheld. Review firewall rules."
        val fake = FakeGateway().apply {
            insightsResult = parseInsights(ShellResult(1, "error=$withheld\n"))
        }
        open(fake)
        // The initial ACTIVE reading must not outlive the post-sample inspection.
        fake.dashboard = stateDashboard(FirewallClient.Protection.DEGRADED, true,
            "Protection is degraded.", report = sampleReport())
        compose.onNodeWithTag("sample-drops").performScrollTo().performClick()
        compose.settle { fake.count("inspect") == 2 && compose.hasText(withheld) &&
            !compose.hasText("Sampling & verifying…") }
        compose.onNodeWithTag("sample-drops").assertIsNotEnabled()
        compose.onNodeWithTag("recover-insights").assertDoesNotExist()
        compose.onNodeWithText("OBSERVED SAMPLE").assertDoesNotExist()
        compose.onNodeWithText("Firewall independently verified ACTIVE.", substring = true).assertDoesNotExist()
        compose.onNodeWithText("Firewall").performClick()
        compose.onNodeWithText("Active.").assertDoesNotExist()
        assertEquals(listOf("inspect", "insights-capture", "inspect"), fake.calls.toList())
    }
    @Test fun failedFinalVerificationAndFailedStatusReadNeverLeaveStaleActiveClaim() {
        val error = "Firewall is not independently verified ACTIVE."
        val fake = FakeGateway().apply {
            insightsResult = parseInsights(ShellResult(1, "error=$error\n"))
        }
        open(fake)
        fake.inspectionFailure = IllegalStateException("Status read unavailable")
        compose.onNodeWithTag("sample-drops").performScrollTo().performClick()
        compose.settle { fake.count("inspect") == 2 && compose.hasText("Live firewall state could not be verified.") }
        compose.onNodeWithText(error).assertExists()
        compose.onNodeWithTag("sample-drops").assertIsNotEnabled()
        compose.onNodeWithTag("recover-insights").assertDoesNotExist()
        compose.onNodeWithText("OBSERVED SAMPLE").assertDoesNotExist()
        compose.onNodeWithText("Firewall independently verified ACTIVE.", substring = true).assertDoesNotExist()
        compose.onNodeWithText("Firewall").performClick()
        compose.onNodeWithText("Active.").assertDoesNotExist()
        compose.onNodeWithText("RECHECK REQUIRED", substring = true).assertExists()
        assertEquals(listOf("inspect", "insights-capture", "inspect"), fake.calls.toList())
    }
    @Test fun appBackgroundingRequestsCleanup() {
        val fake = FakeGateway(); open(fake)
        val gate = CountDownLatch(1); fake.gate = gate
        try {
            compose.onNodeWithTag("sample-drops").performScrollTo().performClick()
            compose.settle { fake.count("insights-capture") == 1 }
            compose.runOnIdle { screens.last().pause().stop() }
            assertTrue(fake.lastInsightsRequest!!.isCancelled)
        } finally {
            gate.countDown(); fake.gate = null
            compose.runOnIdle { screens.last().start().resume() }
        }
        compose.settle { fake.count("inspect") == 2 }
    }
    @Test fun degradedResidueIsDetectedWithoutStartingAnotherCapture() {
        val dashboard = activeDashboard()
        val report = dashboard.kernelReport!!
        val fake = FakeGateway(dashboard.copy(
            snapshot = dashboard.snapshot.copy(protection = FirewallClient.Protection.DEGRADED),
            kernelReport = report.copy(ipv4 = report.ipv4.copy(inbound = report.ipv4.inbound +
                "-A POCKETUFW_IN -j NFLOG --nflog-prefix PUFW_APP1:0123456789abcdef0123456789abcdef:P:F"))))
        open(fake)
        compose.onNodeWithTag("recover-insights").assertIsDisplayed().assertTextContains("Check sample cleanup")
        shot("residue-prominent")
        compose.onNodeWithTag("sample-drops").performScrollTo().assertIsNotEnabled()
        compose.onNodeWithTag("recover-insights").performScrollTo().assertIsEnabled()
        compose.onNodeWithText("Leftover Insights probes detected.", substring = true).assertExists()
        assertEquals(listOf("inspect"), fake.calls.toList())
        shot("recovery")
        compose.onNodeWithText("Firewall").performClick()
        compose.onNodeWithText("Recover Insights probes").performScrollTo().assertIsEnabled()
        compose.onNodeWithText("Remove partial PocketUFW rules").assertDoesNotExist()
        compose.onNodeWithText("Remove tunnel rules only").assertDoesNotExist()
        assertEquals(listOf("inspect"), fake.calls.toList())
    }
    @Test fun refusedRecoveryNeverDisablesOrRebuildsAndAsksForReview() {
        val dashboard = activeDashboard()
        val report = dashboard.kernelReport!!
        val rule = "-A POCKETUFW_IN -j NFLOG --nflog-prefix PUFW_APP1:0123456789abcdef0123456789abcdef:P:F --nflog-group 18"
        val fake = FakeGateway(dashboard.copy(
            snapshot = dashboard.snapshot.copy(protection = FirewallClient.Protection.DEGRADED),
            kernelReport = report.copy(ipv4 = report.ipv4.copy(inbound = report.ipv4.inbound + rule))))
        // The helper's real refusal text for an unrecognized reserved rule.
        fake.insightsResult = InsightsResult(error = "Unrecognized Insights options; manual rule review needed. Affected IPv4 rule: $rule " +
            "--nflog-size 24 --nflog-threshold 1 Nothing was removed, disabled or rebuilt. Review this rule before recovering.")
        open(fake)
        compose.onNodeWithTag("recover-insights").performScrollTo().performClick()
        compose.settle { compose.hasText("Affected IPv4 rule:", true) && fake.count("inspect") == 2 }
        compose.onNodeWithText("Nothing was removed, disabled or rebuilt.", substring = true).assertExists()
        // Only the refused recovery and its read-only recheck: no removal, disable, enable or tunnel change.
        assertEquals(listOf("inspect", "insights-recover", "inspect"), fake.calls.toList())
        compose.onNodeWithText("Firewall").performClick()
        compose.onNodeWithText("Recover Insights probes").performScrollTo().assertIsEnabled()
        compose.onNodeWithText("Remove partial PocketUFW rules").assertDoesNotExist()
        compose.onNodeWithText("Remove tunnel rules only").assertDoesNotExist()
        compose.onNodeWithText("Turn firewall off").assertDoesNotExist()
        compose.onNodeWithText("Inspect kernel rules").assertExists()
        assertEquals(listOf("inspect", "insights-recover", "inspect"), fake.calls.toList())
    }
    @Test fun narrowLargeTextRemainsScrollable() {
        val fake = FakeGateway(tunnelDashboard()); open(fake, 1.5f, 320)
        compose.onNodeWithTag("sample-drops").performScrollTo().assertIsDisplayed()
        shot("large-text")
        compose.onNodeWithText("Sample interrupted?").performScrollTo().performClick()
        compose.onNodeWithTag("recover-insights").performScrollTo().assertIsDisplayed()
        shot("large-text-troubleshooting")
        assertEquals(listOf("inspect"), fake.calls.toList())
    }

    @Test fun troubleshootingIsExplicitAndBackClosesItBeforeLeavingInsights() {
        val fake = FakeGateway(); open(fake)
        compose.onNodeWithTag("recover-insights").assertDoesNotExist()
        compose.onNodeWithText("Sample interrupted?").performScrollTo().performClick()
        compose.onNodeWithText("Sample interrupted?").assert(SemanticsMatcher.expectValue(SemanticsProperties.StateDescription, "Expanded"))
        compose.onNodeWithText("If a traffic sample was interrupted, PocketUFW can check for temporary monitoring rules and safely remove any it recognizes.").assertExists()
        compose.onNodeWithText("Force-stopping a process", substring = true).assertDoesNotExist()
        compose.onNodeWithTag("recover-insights").performScrollTo().assertIsEnabled().assertTextContains("Check sample cleanup")
        shot("troubleshooting")
        assertEquals(listOf("inspect"), fake.calls.toList())
        compose.runOnIdle { screens.last().get().onBackPressedDispatcher.onBackPressed() }
        compose.onNodeWithTag("recover-insights").assertDoesNotExist()
        compose.onNodeWithText("Sample interrupted?").assert(SemanticsMatcher.expectValue(SemanticsProperties.StateDescription, "Collapsed"))
        compose.onNodeWithText("Insights.").assertExists()
        compose.runOnIdle { screens.last().get().onBackPressedDispatcher.onBackPressed() }
        compose.onNodeWithTag("firewall-action").assertExists()
        assertEquals(listOf("inspect"), fake.calls.toList())
    }

    @Test fun degradedWithoutProbeEvidenceDoesNotPromoteRecovery() {
        val fake = FakeGateway(stateDashboard(FirewallClient.Protection.DEGRADED, true,
            "Unrelated firewall issue.", report = sampleReport()))
        open(fake)
        compose.onNodeWithTag("recover-insights").assertDoesNotExist()
        compose.onNodeWithTag("sample-drops").performScrollTo().assertIsNotEnabled()
        compose.onNodeWithText("Sampling requires verified ACTIVE protection. Recheck status, or open “Sample interrupted?” to check for leftover rules.").assertExists()
        compose.onNodeWithText("Sample interrupted?").performScrollTo().performClick()
        compose.onNodeWithTag("recover-insights").performScrollTo().assertIsEnabled()
        assertEquals(listOf("inspect"), fake.calls.toList())
    }

    @Test fun unknownStateWithoutRootKeepsTroubleshootingReadOnly() {
        val fake = FakeGateway(stateDashboard(FirewallClient.Protection.ROOT_REQUIRED, false, "Root unavailable."))
        open(fake)
        compose.onNodeWithTag("recover-insights").assertDoesNotExist()
        compose.onNodeWithText("Sample interrupted?").performScrollTo().performClick()
        compose.onNodeWithTag("recover-insights").performScrollTo().assertIsNotEnabled()
        assertEquals(listOf("inspect"), fake.calls.toList())
    }

    @Test fun recoveryStopsBeingProminentAfterFreshCleanInspection() {
        val dashboard = activeDashboard()
        val report = dashboard.kernelReport!!
        val fake = FakeGateway(dashboard.copy(
            snapshot = dashboard.snapshot.copy(protection = FirewallClient.Protection.DEGRADED),
            kernelReport = report.copy(ipv6 = report.ipv6.copy(tunnel = listOf(
                "-A POCKETUFW_VPN -j NFLOG --nflog-prefix PUFW_APP1:0123456789abcdef0123456789abcdef:T:F")))))
        open(fake)
        compose.onNodeWithTag("recover-insights").assertIsDisplayed().assertIsEnabled()
        fake.dashboard = dashboard
        fake.insightsResult = InsightsResult(recovered = true)
        compose.onNodeWithTag("recover-insights").performClick()
        compose.settle { fake.count("inspect") == 2 && compose.hasText("Recovery verified:", true) }
        compose.onNodeWithTag("recover-insights").assertDoesNotExist()
        compose.onNodeWithText("Leftover Insights probes detected.", substring = true).assertDoesNotExist()
        compose.onNodeWithText("Sample interrupted?").performScrollTo().assertExists()
        shot("recovered")
        assertEquals(listOf("inspect", "insights-recover", "inspect"), fake.calls.toList())
    }
}
