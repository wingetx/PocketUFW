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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.ParameterizedRobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/**
 * Taps the same physical coordinate twice, the way someone retrying Refresh VPN
 * would. Before the fix, the result banner pushed Reset counters under that
 * coordinate in 20 of these 24 cases and the second tap zeroed the counters.
 *
 * Positions use positionInRoot because boundsInRoot clips to the viewport.
 */
@RunWith(ParameterizedRobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class ResetHazardRegressionTest(
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

    @Test fun repeatTapOnRefreshVpnNeverReachesReset() {
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
        val bannerTop = banner.positionInRoot.y
        val bannerBottom = bannerTop + banner.size.height

        compose.onRoot().performTouchInput { click(tapPoint) }
        compose.waitForIdle()
        Thread.sleep(300)
        compose.waitForIdle()

        assertEquals("the result moved Reset counters", resetBefore, resetAfter, 0.5f)
        assertEquals("the repeat tap reset the counters", 0, fake.count("reset-counters"))
        assertFalse("the repeat tap reached Reset counters", compose.hasText("Reset counters?"))
        assertTrue("the result is above the screen", bannerTop >= 0f)
        assertTrue("the result is below the screen", bannerBottom <= root.size.height)
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
