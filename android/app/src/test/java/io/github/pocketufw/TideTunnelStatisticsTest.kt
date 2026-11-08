package io.github.pocketufw

import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import android.graphics.Bitmap
import android.graphics.Canvas
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import io.github.pocketufw.FirewallClient.*
import org.junit.After
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.io.File

internal fun tunnelActivity() = sampleActivity().copy(
    tunnelFilter = TunnelFilter.ON, tunnelMode = TunnelMode.PINNED,
    tailnetPin4 = "100.64.0.1/32", tailnetPin6 = "fd7a:115c:a1e0::1/128",
    tunnel = TunnelCounters(71, 82, 930, 1040, 115, 126, 137, 148))

internal fun tunnelDashboard() = activeDashboard(activity = tunnelActivity()).let {
    it.copy(snapshot = it.snapshot.copy(physicalFilter = PhysicalFilter.ACTIVE,
        tunnelFilter = TunnelFilter.ON, tunnelMode = TunnelMode.PINNED,
        tailnetConnectivity = TailnetConnectivity.MATCH,
        tailnetPin4 = "100.64.0.1/32", tailnetPin6 = "fd7a:115c:a1e0::1/128"))
}

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class TideTunnelStatisticsTest {
    @get:Rule val compose = createEmptyComposeRule()
    private val screens = mutableListOf<ActivityController<ComponentActivity>>()
    @After fun drain() = drainMainLooper(screens)
    private fun node(text: String, substring: Boolean = false) = compose.onNodeWithText(text, substring = substring)
    private fun click(text: String) = node(text).performScrollTo().performClick()
    private fun open(fake: FakeGateway, fontScale: Float = 1f, width: Int = 412) {
        screens += compose.launchScreen(fake, qualifiers = "w${width}dp-h915dp-xxhdpi", fontScale = fontScale)
        compose.settle { fake.count("inspect") == 1 && !compose.hasText("Checking…") }
    }
    private fun settings() { node("Settings").performClick(); click("Tunnel protection") }
    private fun shot(name: String) {
        val directory = File("build/reports/tide-ui").also { it.mkdirs() }
        // PixelCopy has no compositor in Robolectric. Draw the real native-graphics
        // decor view instead; fixtures remain test-only and never reach the app.
        val view = screens.last().get().window.decorView
        val bitmap = Bitmap.createBitmap(view.width, view.height, Bitmap.Config.ARGB_8888)
        compose.runOnIdle { view.draw(Canvas(bitmap)) }
        File(directory, "$name.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
    }
    private fun off() = activeDashboard().let { it.copy(snapshot = it.snapshot.copy(
        tunnelFilter = TunnelFilter.OFF, tunnelMode = TunnelMode.OFF, physicalFilter = PhysicalFilter.ACTIVE)) }

    @Test fun denyOnlyRequiresConfirmationAndExplainsLaterTailscaleConnections() {
        val fake = FakeGateway(off())
        open(fake); settings()
        node("Enable DENY-ONLY").performScrollTo()
        shot("tunnel-settings")
        click("Enable DENY-ONLY")
        node("including when Tailscale connects later", true).assertExists()
        assertEquals(0, fake.count("tunnel-on:DENY_ONLY"))
        node("Cancel").performClick()
        click("Enable DENY-ONLY")
        compose.onNodeWithTag("confirm-enable-tunnel").performClick()
        compose.settle { fake.count("tunnel-on:DENY_ONLY") == 1 }
        assertEquals(listOf("inspect", "tunnel-on:DENY_ONLY"), fake.calls.toList())
    }

    @Test fun failedPinnedEnableNeverRequestsDenyOnlyOrPhysicalRemoval() {
        val fake = FakeGateway(off()).apply { operationSuccess = false; operationMessage = "Ownership unverified." }
        open(fake); settings(); click("Enable PINNED")
        node("no fallback is used", true).assertExists()
        node("Another tunnel can inject", true).assertExists()
        compose.onNodeWithTag("confirm-enable-tunnel").performClick()
        compose.settle { compose.hasText("Ownership unverified.") }
        assertEquals(listOf("inspect", "tunnel-on:PINNED"), fake.calls.toList())
    }

    @Test fun staleAuthorizationOffersRemovalAndNeverAnInPlaceModeChange() {
        val d = tunnelDashboard()
        val fake = FakeGateway(d.copy(snapshot = d.snapshot.copy(
            tailnetConnectivity = TailnetConnectivity.REAUTHORIZE, tailnetObserved4 = "100.64.0.9/32")))
        open(fake); settings()
        node("REAUTHORIZE:", true).assertExists()
        node("Enable PINNED").assertDoesNotExist()
        node("Enable DENY-ONLY").assertDoesNotExist()
        click("Turn tunnel protection off")
        node("The physical firewall and boot restoration stay in place.", true).assertExists()
        compose.onNodeWithTag("confirm-remove-tunnel").performClick()
        compose.settle { fake.count("tunnel-off") == 1 }
        assertEquals(listOf("inspect", "tunnel-off"), fake.calls.toList())
    }

    @Test fun settingsRecoveryKeepsPhysicalAndTunnelVerdictsDistinct() {
        val d = tunnelDashboard()
        val fake = FakeGateway(d.copy(snapshot = d.snapshot.copy(
            protection = Protection.DEGRADED, tunnelFilter = TunnelFilter.DEGRADED), activity = null))
        open(fake); settings()
        node("Rules verified").assertExists()
        node("DEGRADED · recovery available").assertExists()
        click("Remove tunnel rules only")
        compose.onNodeWithTag("confirm-remove-tunnel").performClick()
        compose.settle { fake.count("tunnel-off") == 1 }
        assertEquals(0, fake.count("disable"))
        assertEquals(0, fake.count("boot-disable"))
    }

    @Test fun pendingEnableIsCancelledWhenVerificationChanges() {
        val model = mutableStateOf(TideUiState(snapshot = off().snapshot))
        var enables = 0
        val controller = Robolectric.buildActivity(ComponentActivity::class.java).setup().also { screens += it }
        controller.get().setContent { TideTheme { TideScreen(model.value,
            TideActions(enableTunnelProtection = { enables++ }), initialDestination = TideDestination.SETTINGS) } }
        click("Tunnel protection"); click("Enable PINNED")
        compose.runOnIdle { model.value = model.value.copy(verificationInDoubt = true) }
        compose.onNodeWithTag("confirm-enable-tunnel").assertDoesNotExist()
        assertEquals(0, enables)
        node("Enable PINNED").assertIsNotEnabled()
    }

    @Test fun rebootOffStateDoesNotRestoreTunnelChoiceFromBootOptIn() {
        val fake = FakeGateway(off())
        open(fake); settings()
        node("Off · optional").assertExists()
        node("never restored after reboot", true).assertExists()
        assertEquals(listOf("inspect"), fake.calls.toList())
    }

    @Test fun statisticsPillUsesExistingMeasurementsAndRefreshIsCounterOnly() {
        val fake = FakeGateway(tunnelDashboard(), counterRead = tunnelActivity())
        open(fake)
        node("Statistics").performScrollTo()
        shot("statistics-collapsed")
        node("Physical interfaces").assertDoesNotExist()
        click("Statistics")
        node("Physical interfaces").assertExists()
        node("Tunnel interfaces").assertExists()
        node("Drop-rule matches: 153").assertExists()
        node("IPv4 tunnel replies").assertExists()
        node("115").assertExists()
        node("148").assertExists()
        node("Return traffic").performScrollTo()
        shot("statistics-physical")
        node("IPv6 tailnet matches").performScrollTo()
        shot("statistics-tunnel")
        assertEquals(listOf("inspect"), fake.calls.toList())
        click("Refresh counters")
        compose.settle { fake.count("counters") == 1 }
        assertEquals(listOf("inspect", "counters"), fake.calls.toList())
    }

    @Test fun pillResetUsesTheExistingSingleResetForEveryOwnedCounter() {
        val fake = FakeGateway(tunnelDashboard())
        open(fake); click("Statistics"); click("Reset counters")
        node("all owned physical and tunnel", true).assertExists()
        compose.onNodeWithTag("confirm-reset-counters").performClick()
        compose.settle { fake.count("reset-counters") == 1 }
        assertEquals(listOf("inspect", "reset-counters"), fake.calls.toList())
    }

    @Test fun changedPinsOnLightweightRefreshInvalidateOldAuthorization() {
        val fake = FakeGateway(tunnelDashboard(), counterRead = tunnelActivity().copy(tailnetPin4 = "100.64.0.9/32"))
        open(fake); click("Statistics"); click("Refresh counters")
        compose.settle { compose.hasText("tunnel policy changed", true) }
        node("Last known reading only.", true).assertExists()
        compose.onNodeWithTag("reset-counters").assertIsNotEnabled()
        assertEquals(listOf("inspect", "counters"), fake.calls.toList())
    }

    @Test fun physicalOnlyCounterRefreshDoesNotRequireAnOwnershipRecheck() {
        val fake = FakeGateway(off(), counterRead = sampleActivity().copy(
            tunnelFilter = TunnelFilter.OFF, tunnelMode = TunnelMode.OFF))
        open(fake); click("Statistics"); click("Refresh counters")
        compose.settle { compose.hasText("Counters refreshed at", true) }
        node("Tunnel filtering is off; no current tunnel measurement.").assertExists()
        compose.onNodeWithTag("reset-counters").assertIsEnabled()
        assertEquals(listOf("inspect", "counters"), fake.calls.toList())
    }

    @Test fun failedRefreshKeepsBothCounterPlanesAsHistoricalReadings() {
        val fake = FakeGateway(tunnelDashboard(), counterRead = RuleActivity(error = "Tunnel counters unavailable."))
        open(fake); click("Statistics"); click("Refresh counters")
        compose.settle { compose.hasText("Tunnel counters unavailable.") }
        node("Drop-rule matches: 153").assertExists()
        node("Last known reading only.", true).assertExists()
    }

    @Test fun unknownTunnelMeasurementsAreNotZeroesAndControlsFitLargeText() {
        val d = activeDashboard()
        val fake = FakeGateway(d.copy(snapshot = d.snapshot.copy(physicalFilter = PhysicalFilter.ACTIVE)))
        open(fake, fontScale = 2f, width = 320)
        click("Statistics")
        node("Tunnel counters unavailable.").performScrollTo()
        shot("statistics-large-text")
        node("Tunnel counters unavailable.").assertExists()
        click("Reset counters")
        compose.onNodeWithTag("confirm-reset-counters").assertIsDisplayed()
        node("Cancel").performClick()
        node("Settings").performClick(); click("Tunnel protection")
        node("Recheck status before changing tunnel protection.").assertExists()
        assertEquals(listOf("inspect"), fake.calls.toList())
    }
}
