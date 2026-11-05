package io.github.pocketufw

import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.test.click
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTouchInput
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.ParameterizedRobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/**
 * Taps the same physical coordinate twice, the way someone retrying Refresh VPN
 * would, and records which firewall operations actually fired.
 *
 * Positions use positionInRoot because boundsInRoot clips to the viewport.
 */
@RunWith(ParameterizedRobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class ResetHazardReproductionTest(
    private val qualifiers: String,
    private val fontScale: Float,
    private val label: String,
    private val message: String,
    private val scrolledToEnd: Boolean,
) {
    @get:Rule val compose = createEmptyComposeRule()

    private fun topDp(text: String, density: Float) =
        compose.onAllNodesWithText(text).fetchSemanticsNodes().firstOrNull()
            ?.let { it.positionInRoot.y / density }

    @Test fun repeatTapOnRefreshVpn() {
        val fake = FakeGateway(vpnMessage = message)
        compose.launchScreen(fake, qualifiers, fontScale)
        compose.settle { compose.hasText("Firewall activity") }
        compose.onNodeWithText("Firewall activity").performScrollTo().performClick()
        compose.waitForIdle()
        check(compose.hasText("Reset counters")) { "activity panel did not expand" }

        compose.onNodeWithText(if (scrolledToEnd) "PocketUFW ·" else "Refresh VPN", substring = true)
            .performScrollTo()
        compose.waitForIdle()

        val root = compose.onRoot().fetchSemanticsNode()
        val density = root.layoutInfo.density.density
        val node = compose.onNodeWithText("Refresh VPN").fetchSemanticsNode()
        val tapPoint = Offset(
            node.positionInRoot.x + node.size.width / 2f,
            node.positionInRoot.y + node.size.height / 2f,
        )
        val resetBefore = topDp("Reset counters", density)!!

        compose.onRoot().performTouchInput { click(tapPoint) }
        compose.settle { fake.count("vpn-refresh") == 1 && compose.hasText("Recheck status") }

        val resetAfter = topDp("Reset counters", density)!!
        val banner = compose.onAllNodesWithText(message).fetchSemanticsNodes().first()
        val bannerBottomDp = (banner.positionInRoot.y + banner.size.height) / density

        compose.onRoot().performTouchInput { click(tapPoint) }
        compose.waitForIdle()
        Thread.sleep(300)
        compose.waitForIdle()

        val secondTap = when {
            fake.count("reset-counters") > 0 -> "RESET COUNTERS"
            fake.count("vpn-refresh") > 1 -> "Refresh VPN"
            else -> "nothing"
        }
        println(
            "HAZARD|$qualifiers|font=$fontScale|$label|" +
                (if (scrolledToEnd) "scrolled-to-end" else "row-at-bottom-edge") +
                "|shift=${"%.0f".format(resetAfter - resetBefore)}dp" +
                "|banner=${if (bannerBottomDp <= 0) "off-screen" else "on-screen"}" +
                "|second tap: $secondTap",
        )

        // Characterizes the shipped bug. Only the longest banner at 130% text
        // moves far enough to clear Reset counters; every other case hits it.
        val longBannerClearsReset = label == "committed" && fontScale > 1f
        assertEquals(if (longBannerClearsReset) 0 else 1, fake.count("reset-counters"))
    }

    companion object {
        @JvmStatic
        @ParameterizedRobolectricTestRunner.Parameters(name = "{0} font={1} {2} end={4}")
        fun cases(): List<Array<Any>> {
            val messages = listOf(
                "success" to BridgeMessages.VPN_OK,
                "failure" to BridgeMessages.VPN_FAILED,
                "committed" to BridgeMessages.VPN_COMMITTED,
            )
            val out = mutableListOf<Array<Any>>()
            for (q in listOf("w360dp-h780dp-xxhdpi", "w412dp-h915dp-xxhdpi")) {
                for (f in listOf(1f, 1.3f)) {
                    for ((l, m) in messages) for (end in listOf(false, true)) {
                        out += arrayOf<Any>(q, f, l, m, end)
                    }
                }
            }
            return out
        }
    }
}
