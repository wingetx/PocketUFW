package io.github.pocketufw

import android.graphics.Bitmap
import android.graphics.Canvas
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.*
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.*
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.unit.Density
import io.github.pocketufw.FirewallClient.*
import java.io.File
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

/** Host rendering and accessibility checks only: no device, root, or firewall operations. */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class TidePolishTest {
    @get:Rule val compose = createEmptyComposeRule()
    private val screens = mutableListOf<ActivityController<ComponentActivity>>()
    @After fun close() = drainMainLooper(screens)
    private fun node(text: String) = compose.onNodeWithText(text)
    private fun click(text: String) = node(text).performScrollTo().performClick()
    private fun fixture(): TideUiState {
        val dashboard = tunnelDashboard()
        return TideUiState(snapshot = dashboard.snapshot, report = dashboard.kernelReport, counters = dashboard.activity)
    }
    private fun show(ui: State<TideUiState>, dark: Boolean = false, scale: Float = 1f,
                     destination: TideDestination = TideDestination.FIREWALL) {
        RuntimeEnvironment.setQualifiers("w320dp-h800dp-xxhdpi")
        val controller = Robolectric.buildActivity(ComponentActivity::class.java).setup().also { screens += it }
        controller.get().setContent {
            CompositionLocalProvider(LocalDensity provides Density(LocalDensity.current.density, scale)) {
                TideTheme(dark) { TideScreen(ui.value, TideActions(), initialDestination = destination) }
            }
        }
        compose.waitForIdle()
    }
    private fun layouts(text: String): TextLayoutResult {
        val results = mutableListOf<TextLayoutResult>()
        compose.onNodeWithText(text, useUnmergedTree = true)
            .performSemanticsAction(SemanticsActions.GetTextLayoutResult) { it(results) }
        return results.single()
    }
    private fun assertNoClippedText() {
        compose.onAllNodes(SemanticsMatcher.keyIsDefined(SemanticsActions.GetTextLayoutResult), useUnmergedTree = true)
            .fetchSemanticsNodes().forEach { node ->
                val results = mutableListOf<TextLayoutResult>()
                node.config[SemanticsActions.GetTextLayoutResult].action!!(results)
                results.forEach {
                    // Compose can retain a wider paragraph constraint after sizing a short
                    // label to its text. Check actual line bounds, not that unused width.
                    for (line in 0 until it.lineCount) {
                        assertTrue("Clipped width: ${it.layoutInput.text}", it.getLineRight(line) <= it.size.width + 1)
                        assertTrue("Clipped height: ${it.layoutInput.text}", it.getLineBottom(line) <= it.size.height + 1)
                        assertFalse("Ellipsized: ${it.layoutInput.text}", it.isLineEllipsized(line))
                    }
                    assertEquals(it.layoutInput.text.length, it.getLineEnd(it.lineCount - 1))
                }
            }
    }
    private fun shot(name: String) {
        compose.waitForIdle()
        val directory = File("build/reports/beta8-status").also { it.mkdirs() }
        val view = screens.last().get().window.decorView
        val bitmap = Bitmap.createBitmap(view.width, view.height, Bitmap.Config.ARGB_8888)
        compose.runOnIdle { view.draw(Canvas(bitmap)) }
        File(directory, "$name.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
        bitmap.recycle()
    }

    private fun assertDividerColor(color: Color) {
        val bounds = compose.onNodeWithTag("protection-divider").performScrollTo().assertIsDisplayed()
            .fetchSemanticsNode().boundsInRoot
        val view = screens.last().get().window.decorView
        val bitmap = Bitmap.createBitmap(view.width, view.height, Bitmap.Config.ARGB_8888)
        compose.runOnIdle { view.draw(Canvas(bitmap)) }
        assertEquals(color.toArgb(), bitmap.getPixel((bounds.left + 8).toInt(), bounds.center.y.toInt()))
        bitmap.recycle()
    }

    private fun verifiedAppearance(dark: Boolean, scale: Float) {
        val base = fixture()
        val model = mutableStateOf(base)
        show(model, dark, scale)
        val green = if (dark) Color(0xFF85DEB4) else Color(0xFF176443)
        val background = if (dark) Color(0xFF141B29) else Color(0xFFF7F6EF)
        val luminances = listOf(green.luminance(), background.luminance()).sorted()
        assertTrue("Status text meets 4.5:1 contrast", (luminances[1] + .05f) / (luminances[0] + .05f) >= 4.5f)
        val report = base.report!!.copy(ipv4 = base.report.ipv4.copy(bypass = listOf("-A INPUT -i wlan0 -j ACCEPT")))
        val limited = base.copy(report = report, snapshot = base.snapshot.copy(uncoveredInterfaces = listOf("eth0", "usb0")))
        val carrier = base.copy(snapshot = base.snapshot.copy(uncoveredInterfaces = listOf("ipsec995"),
            carrierImsInterfaces = setOf("ipsec995")))
        for ((name, state) in listOf("verified" to base, "carrier" to carrier, "limited" to limited,
            "unknown-coverage" to base.copy(report = null, snapshot = base.snapshot.copy(interfaceInventoryAvailable = false)),
            "limited-unknown" to limited.copy(report = null))) {
            compose.runOnIdle { model.value = state }
            node("PROTECTION ACTIVE · RULES VERIFIED").assertExists()
            node("Filtered where supported").assertExists()
            node("Coverage limited").assertDoesNotExist()
            compose.onNodeWithTag("coverage-notice").assertDoesNotExist()
            assertEquals(green, layouts("Active.").layoutInput.style.color)
            assertEquals(green, layouts("PROTECTION ACTIVE · RULES VERIFIED").layoutInput.style.color)
            assertEquals(if (dark) Color(0xFFB3BDCE) else Color(0xFF59606B), layouts(COVERAGE_SUBTITLE).layoutInput.style.color)
            node("Coverage details").assert(SemanticsMatcher.expectValue(SemanticsProperties.StateDescription, "Collapsed"))
            compose.onNodeWithTag("protection-status")
                .assert(SemanticsMatcher.expectValue(SemanticsProperties.LiveRegion, LiveRegionMode.Polite))
                .assert(SemanticsMatcher.keyIsDefined(SemanticsProperties.Heading))
                .assert(SemanticsMatcher.expectValue(SemanticsProperties.StateDescription, "PROTECTION ACTIVE · RULES VERIFIED"))
            assertNoClippedText()
            assertDividerColor(green)
            compose.onNodeWithTag("protection-status").performScrollTo()
            shot("$name-${if (dark) "dark" else "light"}-$scale")
        }
        compose.runOnIdle { model.value = base.copy(report = report,
            snapshot = base.snapshot.copy(uncoveredInterfaces = listOf("ipsec995", "eth0", "usb0"),
                carrierImsInterfaces = setOf("ipsec995"))) }
        click("Coverage details")
        node("Coverage details").assert(SemanticsMatcher.expectValue(SemanticsProperties.StateDescription, "Expanded"))
        for (heading in listOf("What PocketUFW protects", "What Android and VPNs handle separately", "When action is needed"))
            node(heading).assert(SemanticsMatcher.keyIsDefined(SemanticsProperties.Heading))
        compose.onAllNodesWithText("Carrier calling networks (ipsec995)", substring = true).assertCountEquals(1)
        node("Not filtered: eth0, usb0.").assertExists()
        compose.onNodeWithText("Earlier Android rules were found", substring = true).assertExists()
        node("Technical details").assert(SemanticsMatcher.expectValue(SemanticsProperties.StateDescription, "Collapsed"))
        compose.onNodeWithText("Pinned tailnet destinations:", substring = true).assertDoesNotExist()
        assertNoClippedText()
        node("What PocketUFW protects").performScrollTo()
        shot("coverage-${if (dark) "dark" else "light"}-$scale")
        click("Technical details")
        node("Technical details").assert(SemanticsMatcher.expectValue(SemanticsProperties.StateDescription, "Expanded"))
        node("IPv4: -A INPUT -i wlan0 -j ACCEPT").assertExists()
        compose.onNodeWithText("PINNED trusts destination addresses on tun*, not individual packets.", substring = true)
            .performScrollTo().assertIsDisplayed()
        node("At the last full inspection, tailnet pins matched verified addresses; reachability has not been tested.").assertExists()
        assertNoClippedText()
        shot("technical-${if (dark) "dark" else "light"}-$scale")
        click("Coverage details")
        node("Technical details").assertDoesNotExist()
        compose.onNodeWithText("Carrier calling networks", substring = true).assertDoesNotExist()
    }

    @Test fun verifiedAndLimitedProtectionStayGreenInLightMode() = verifiedAppearance(false, 1f)
    @Test fun verifiedAndLimitedProtectionStayGreenInDarkMode() = verifiedAppearance(true, 1f)
    @Test fun largeLightTextKeepsStatusAndDisclosuresAccessible() = verifiedAppearance(false, 2f)
    @Test fun largeDarkTextKeepsStatusAndDisclosuresAccessible() = verifiedAppearance(true, 2f)

    private fun attentionAppearance(dark: Boolean, scale: Float) {
        val base = fixture()
        val model = mutableStateOf(base)
        show(model, dark, scale)
        val amber = if (dark) Color(0xFFF3B778) else Color(0xFF8F4915)
        val neutral = if (dark) Color(0xFFB3BDCE) else Color(0xFF59606B)
        val states = listOf(
            "unverified" to base.copy(verificationInDoubt = true),
            "root" to base.copy(snapshot = base.snapshot.copy(rootReady = false)),
            "degraded" to base.copy(snapshot = base.snapshot.copy(protection = Protection.DEGRADED, physicalFilter = PhysicalFilter.DEGRADED)),
            "tunnel-degraded" to base.copy(snapshot = base.snapshot.copy(protection = Protection.DEGRADED, tunnelFilter = TunnelFilter.DEGRADED)),
            "stale-pins" to base.copy(snapshot = base.snapshot.copy(tailnetConnectivity = TailnetConnectivity.REAUTHORIZE, tailnetObserved4 = "100.64.0.9/32")),
            "unknown-pins" to base.copy(snapshot = base.snapshot.copy(tailnetConnectivity = TailnetConnectivity.UNVERIFIED)),
            "inactive" to base.copy(snapshot = base.snapshot.copy(protection = Protection.INACTIVE, physicalFilter = PhysicalFilter.INACTIVE,
                tunnelFilter = TunnelFilter.OFF, tunnelMode = TunnelMode.OFF, bootRestore = BootRestore.DISABLED))
        )
        for ((name, state) in states) {
            compose.runOnIdle { model.value = state }
            val status = protectionStatus(state)
            val color = if (name == "inactive") neutral else amber
            node(if (name == "inactive") "Inactive." else "Needs attention.").assertExists()
            node("PROTECTION ACTIVE · RULES VERIFIED").assertDoesNotExist()
            assertEquals(color, layouts(status.title).layoutInput.style.color)
            assertEquals(color, layouts(status.label).layoutInput.style.color)
            compose.onNodeWithTag("protection-status").assert(SemanticsMatcher.expectValue(SemanticsProperties.StateDescription, status.label))
            assertDividerColor(color)
            assertNoClippedText()
            if (name == "tunnel-degraded") {
                compose.onNodeWithText("Physical firewall rules are verified, but tunnel protection is degraded.", substring = true).assertExists()
                node("Remove tunnel rules only").assertIsEnabled()
                node("Filtered where supported").assertExists()
            }
            if (name in listOf("unverified", "root", "degraded", "inactive")) node("Filtered where supported").assertDoesNotExist()
            if (name == "stale-pins") node("Review tunnel protection").assertIsEnabled()
            compose.onNodeWithText("Tailnet connectivity: REAUTHORIZE.", substring = true).assertDoesNotExist()
            node("Tunnel protection is degraded. Tunnel-only recovery keeps the physical firewall in place.").assertDoesNotExist()
            compose.onNodeWithTag("protection-status").performScrollTo()
            shot("$name-${if (dark) "dark" else "light"}-$scale")
        }
    }

    @Test fun attentionAndInactiveHaveDistinctLightPresentations() = attentionAppearance(false, 1f)
    @Test fun attentionAndInactiveHaveDistinctDarkPresentations() = attentionAppearance(true, 1f)
    @Test fun largeLightAttentionAndInactiveStayAccessible() = attentionAppearance(false, 2f)
    @Test fun largeDarkAttentionAndInactiveStayAccessible() = attentionAppearance(true, 2f)

    @Test fun tunnelReturnTotalExcludesTailnetAndPreservesZeroAndUnavailable() {
        val base = fixture()
        val model = mutableStateOf(base)
        show(model, destination = TideDestination.ACTIVITY)
        compose.onNodeWithContentDescription("Physical Return traffic: 104,489 packets. Established / related packets").assertExists()
        compose.onNodeWithContentDescription("Tunnel Return traffic: 241 packets. Established / related packets").performScrollTo().assertIsDisplayed()
        node("Tailnet exemptions").assertExists()
        node("137").assertExists()
        node("148").assertExists()
        assertNoClippedText()
        shot("activity-tunnel-total")
        val tunnel = base.counters!!.tunnel!!
        compose.runOnIdle { model.value = base.copy(counters = base.counters.copy(tunnelMode = TunnelMode.DENY_ONLY)) }
        compose.onNodeWithContentDescription("Tunnel Return traffic: 241 packets. Established / related packets").assertExists()
        node("Tailnet exemptions").assertDoesNotExist()
        compose.runOnIdle { model.value = base.copy(counters = base.counters.copy(tunnel = tunnel.copy(ipv4Replies = 0, ipv6Replies = 0))) }
        compose.onNodeWithContentDescription("Tunnel Return traffic: 0 packets. Established / related packets").assertExists()
        compose.runOnIdle { model.value = base.copy(counters = base.counters.copy(tunnel = tunnel.copy(ipv4Replies = Long.MAX_VALUE, ipv6Replies = 1))) }
        compose.onNodeWithContentDescription("Tunnel Return traffic: unavailable. Established / related packets").assertExists()
        compose.runOnIdle { model.value = base.copy(counters = base.counters.copy(tunnel = null)) }
        compose.onNodeWithTag("Tunnel-Return traffic").assertDoesNotExist()
        node("Tunnel counters unavailable.").assertExists()
        compose.runOnIdle { model.value = base.copy(counters = base.counters.copy(tunnelFilter = TunnelFilter.OFF)) }
        compose.onNodeWithTag("Tunnel-Return traffic").assertDoesNotExist()
        node("Tunnel filtering is off; no current tunnel measurement.").assertExists()
    }

    private fun largeActivity(dark: Boolean) {
        show(mutableStateOf(fixture()), dark, 2f, TideDestination.ACTIVITY)
        assertNoClippedText()
        compose.onNodeWithTag("Physical-Return traffic").performScrollTo().assertIsDisplayed()
        shot("activity-physical-large-${if (dark) "dark" else "light"}")
        compose.onNodeWithTag("Tunnel-Return traffic").performScrollTo().assertIsDisplayed()
        shot("activity-tunnel-large-${if (dark) "dark" else "light"}")
        node("Reset counters").performScrollTo().assertIsDisplayed().assertIsEnabled()
    }

    @Test fun activityTotalsFitLargeLightText() = largeActivity(false)
    @Test fun activityTotalsFitLargeDarkText() = largeActivity(true)

    @Test fun disclosureAndRuleNavigationNeverReadRootOrChangeRules() {
        val fake = FakeGateway(tunnelDashboard())
        screens += compose.launchScreen(fake)
        compose.settle { compose.hasText("Active.") }
        click("Coverage details")
        click("Inspect kernel rules")
        node("VPN UDP exceptions · child chain").assertExists()
        assertEquals(listOf("inspect"), fake.calls.toList())
    }
}
