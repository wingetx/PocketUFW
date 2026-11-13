package io.github.pocketufw

import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.*
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import io.github.pocketufw.FirewallClient.BootRestore
import io.github.pocketufw.FirewallClient.Protection
import io.github.pocketufw.FirewallClient.RuleActivity
import io.github.pocketufw.FirewallClient.Snapshot
import io.github.pocketufw.FirewallClient.UdpConfigMode
import java.text.DateFormat
import java.util.Calendar
import java.util.Date
import org.junit.After
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/**
 * The audited promises ported to Codex's Tide screens.
 * The original Claude tests remain in commit 301c393, where the old UI exists.
 * FakeGateway never requests root or edits Android's firewall.
 */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class TideAuditRegressionTest {
    @get:Rule val compose = createEmptyComposeRule()

    @After fun drain() = drainMainLooper()

    private fun node(value: String, substring: Boolean = false) =
        compose.onNodeWithText(value, substring = substring)

    private fun open(fake: FakeGateway, expect: String = "Active.") =
        compose.launchScreen(fake).also {
            compose.settle { fake.count("inspect") >= 1 && compose.hasText(expect, true) }
        }

    private fun activity() { node("Activity").performClick(); compose.waitForIdle() }
    private fun settings() { node("Settings").performClick(); compose.waitForIdle() }
    private fun scrollClick(value: String) {
        node(value).performScrollTo().performClick()
        compose.waitForIdle()
    }

    @Test fun resetRequiresExplicitConfirmationAndCancelDoesNotReset() {
        val fake = FakeGateway()
        open(fake); activity()
        scrollClick("Reset counters")
        node("Reset counters?").assertExists()
        assertEquals(0, fake.count("reset-counters"))
        node("Cancel").performClick()
        assertEquals(0, fake.count("reset-counters"))
        scrollClick("Reset counters")
        compose.onNodeWithTag("confirm-reset-counters").performClick()
        compose.settle { fake.count("reset-counters") == 1 }
        assertEquals(1, fake.count("reset-counters"))
    }

    @Test fun pendingResetIsCancelledWhenVerificationBecomesDoubtful() {
        val model = mutableStateOf(TideUiState(
            snapshot = activeDashboard().snapshot,
            counters = sampleActivity(), report = sampleReport()
        ))
        val controller = Robolectric.buildActivity(ComponentActivity::class.java).setup()
        var calls = 0
        controller.get().setContent {
            TideTheme { TideScreen(model.value, TideActions(resetCounters = { calls++ }),
                initialDestination = TideDestination.ACTIVITY) }
        }
        scrollClick("Reset counters")
        compose.runOnIdle { model.value = model.value.copy(verificationInDoubt = true) }
        compose.onNodeWithTag("confirm-reset-counters").assertDoesNotExist()
        assertEquals(0, calls)
    }

    @Test fun degradedTunnelRecoveryUsesOnlyTunnelRemoval() {
        val initial = stateDashboard(Protection.DEGRADED, true, "Incomplete tunnel rules.")
        val fake = FakeGateway(initial.copy(snapshot = initial.snapshot.copy(
            tunnelFilter = FirewallClient.TunnelFilter.DEGRADED)))
        open(fake, expect = "Needs")
        node("Remove partial PocketUFW rules").assertDoesNotExist()
        scrollClick("Remove tunnel rules only")
        node("The physical firewall and boot opt-in stay in place.", substring = true).assertExists()
        assertEquals(0, fake.count("tunnel-off"))
        node("Cancel").performClick()
        assertEquals(0, fake.count("tunnel-off"))
        scrollClick("Remove tunnel rules only")
        compose.onNodeWithTag("confirm-remove-tunnel").performClick()
        compose.settle { fake.count("tunnel-off") == 1 }
        assertEquals(0, fake.count("remove-partial"))
        assertEquals(0, fake.count("disable"))
        assertEquals(0, fake.count("boot-disable"))
    }

    @Test fun tunnelRecoveryConfirmationClosesAfterUncertainRead() {
        val model = mutableStateOf(TideUiState(snapshot = Snapshot(Protection.DEGRADED,
            rootReady = true, tunnelFilter = FirewallClient.TunnelFilter.DEGRADED), checkedAt = READ_AT))
        val controller = Robolectric.buildActivity(ComponentActivity::class.java).setup()
        var calls = 0
        controller.get().setContent {
            TideTheme { TideScreen(model.value, TideActions(removeTunnelRules = { calls++ })) }
        }
        scrollClick("Remove tunnel rules only")
        compose.runOnIdle { model.value = model.value.copy(verificationInDoubt = true) }
        compose.onNodeWithTag("confirm-remove-tunnel").assertDoesNotExist()
        assertEquals(0, calls)
    }

    @Test fun removalOfPartialRulesRequiresConfirmationAndExplainsBootHook() {
        val fake = FakeGateway(stateDashboard(Protection.DEGRADED, true, "Incomplete firewall."))
        open(fake, expect = "Needs")
        scrollClick("Remove partial PocketUFW rules")
        assertEquals(0, fake.count("remove-partial"))
        node("Remove partial PocketUFW rules?").assertExists()
        node("Magisk boot hook", substring = true).assertExists()
        node("Cancel").performClick()
        assertEquals(0, fake.count("remove-partial"))
        scrollClick("Remove partial PocketUFW rules")
        node("Remove rules").performClick()
        compose.settle { fake.count("remove-partial") == 1 }
        // The plain switch would act on a firewall that had recovered meanwhile.
        assertEquals(0, fake.count("disable"))
    }

    @Test fun failedCounterReadWithdrawsVerifiedClaimButRetainsLastMeasurement() {
        val error = "Firewall is not active or its policy could not be verified."
        val fake = FakeGateway(counterRead = RuleActivity(error = error))
        open(fake); activity()
        scrollClick("Refresh counters")
        compose.settle { fake.count("counters") == 1 && compose.hasText(error, true) }
        compose.onNodeWithContentDescription("Physical IPv4: 1,204 dropped packets, 98,664 bytes").assertExists()
        node("Last known reading only.", substring = true).assertExists()
        compose.onNodeWithTag("reset-counters").assertIsNotEnabled()
        node("Firewall").performClick()
        node("RECHECK REQUIRED", substring = true).assertExists()
        node("Turn firewall off").assertDoesNotExist()
        scrollClick("Recheck status")
        compose.settle { fake.count("inspect") == 2 && compose.hasText("Active.") }
        node("RECHECK REQUIRED", substring = true).assertDoesNotExist()
    }

    @Test fun bootProblemsDoNotLookLikeSwitchedOffSettings() {
        val model = mutableStateOf(TideUiState(
            snapshot = activeDashboard(boot = BootRestore.UNSUPPORTED).snapshot
        ))
        val controller = Robolectric.buildActivity(ComponentActivity::class.java).setup()
        controller.get().setContent {
            TideTheme { TideSettings(model.value, TideActions(), "beta", {}) }
        }
        val problems = listOf(
            BootRestore.UNSUPPORTED to "Magisk boot restoration isn't available on this device.",
            BootRestore.DEGRADED to "The boot hook is incomplete; restoring after reboot isn't verified.",
            BootRestore.CONFLICT to "Something else owns the boot hook path; PocketUFW won't overwrite it.",
            BootRestore.UNKNOWN to "Boot restoration status couldn't be read."
        )
        for ((mode, detail) in problems) {
            compose.runOnIdle { model.value = model.value.copy(snapshot =
                model.value.snapshot.copy(bootRestore = mode)) }
            node(detail).assertExists()
            compose.onNodeWithContentDescription("Restore after reboot").assertDoesNotExist()
        }
        compose.runOnIdle { model.value = model.value.copy(snapshot =
            model.value.snapshot.copy(bootRestore = BootRestore.DISABLED)) }
        compose.onNodeWithContentDescription("Restore after reboot").assertExists()
    }

    @Test fun committedVpnCannotRequestAlwaysRejectedRefresh() {
        val model = mutableStateOf(TideUiState(
            snapshot = activeDashboard(mode = UdpConfigMode.COMMITTED).snapshot
        ))
        val controller = Robolectric.buildActivity(ComponentActivity::class.java).setup()
        controller.get().setContent { TideTheme { TideScreen(model.value, TideActions(),
            initialDestination = TideDestination.SETTINGS) } }
        node("Refresh Tailscale ports").assertDoesNotExist()
        scrollClick("VPN UDP exceptions")
        node("Refresh Tailscale ports").assertIsNotEnabled()
        node("Committed UDP exceptions", substring = true).assertExists()
        compose.runOnIdle { model.value = model.value.copy(snapshot =
            model.value.snapshot.copy(udpConfigMode = UdpConfigMode.DEGRADED)) }
        node("Refresh Tailscale ports").assertIsNotEnabled()
        node("saved UDP configuration", substring = true).assertExists()
    }

    @Test fun onlyTailscaleExceptionsScreenOffersListenerRefresh() {
        var calls = 0
        val model = TideUiState(snapshot = activeDashboard().snapshot, report = sampleReport())
        val controller = Robolectric.buildActivity(ComponentActivity::class.java).setup()
        controller.get().setContent { TideTheme { TideScreen(model,
            TideActions(refreshVpn = { calls++ }), initialDestination = TideDestination.SETTINGS) } }
        node("Refresh Tailscale ports").assertDoesNotExist()
        node("Refresh VPN").assertDoesNotExist()
        scrollClick("VPN UDP exceptions")
        assertEquals(1, compose.onAllNodesWithText("Refresh Tailscale ports").fetchSemanticsNodes().size)
        node("Checks Tailscale's UDP listeners", substring = true).assertExists()
        scrollClick("Refresh Tailscale ports")
        assertEquals(1, calls)
    }

    @Test fun automaticVpnLabelDoesNotClaimLivePortVerification() {
        val fake = FakeGateway()
        open(fake); settings()
        node("Saved mode: Automatic", substring = true).assertExists()
        assertFalse(compose.hasText("Automatic · verified Tailscale listeners"))
        scrollClick("VPN UDP exceptions")
        node("Saved mode: Automatic").assertExists()
        node("Live ports come from Tailscale detection", substring = true).assertExists()
    }

    @Test fun restoreAutomaticTailscalePortsIsExplicitAndConfirmed() {
        val fake = FakeGateway()
        open(fake); settings(); scrollClick("VPN UDP exceptions")
        scrollClick("Restore automatic Tailscale ports")
        node("Restore automatic Tailscale ports?").assertExists()
        node("If Tailscale has no verified listeners", substring = true).assertExists()
        assertEquals(0, fake.count("use-auto"))
        node("Cancel").performClick()
        assertEquals(0, fake.count("use-auto"))
        scrollClick("Restore automatic Tailscale ports")
        node("Restore ports").performClick()
        compose.settle { fake.count("use-auto") == 1 }
        assertEquals(1, fake.count("use-auto"))
    }

    @Test fun rectangularActionsHaveUniformHeightAcrossScreens() {
        // These are actions, not variable-length notices or bottom navigation.
        // Compare actual measured Compose layout across the three screens.
        open(FakeGateway())
        val heights = linkedMapOf<String, Int>()
        fun measure(name: String, key: String = name) {
            heights[key] = node(name).fetchSemanticsNode().size.height
        }
        measure("Turn firewall off")
        activity()
        measure("Refresh counters")
        measure("Reset counters")
        scrollClick("Kernel rules")
        measure("Recheck kernel rules")
        settings()
        scrollClick("VPN UDP exceptions")
        measure("Advanced: Edit UDP exceptions")
        measure("Restore automatic Tailscale ports")
        measure("Refresh Tailscale ports")
        val baseline = heights.getValue("Turn firewall off")
        heights.forEach { (name, height) ->
            assertEquals("$name has a different button height: $heights", baseline, height)
        }
    }

    @Test fun vpnLabelsComeFromConfirmedOwnerAndHaveAnHonestFallback() {
        val client = FirewallClient(RuntimeEnvironment.getApplication())
        assertEquals("Proton VPN", client.vpnProviderLabel("ch.protonvpn.android"))
        assertEquals("Mullvad VPN", client.vpnProviderLabel("net.mullvad.mullvadvpn"))
        assertEquals("WireGuard", client.vpnProviderLabel("com.wireguard.android"))
        assertEquals("Connected via Tailscale", client.vpnProviderLabel("com.tailscale.ipn"))
        assertEquals("Unrecognized VPN", client.vpnProviderLabel("com.example.fakevpn"))
        assertEquals("Unrecognized VPN", client.vpnProviderLabel(null))
    }

    @Test fun vpnConnectionSettingsNeverGuessFromAppInstallation() {
        val model = mutableStateOf(TideUiState(snapshot = activeDashboard().snapshot.copy(
            vpnActive = true, vpnProvider = "Proton VPN")))
        val controller = Robolectric.buildActivity(ComponentActivity::class.java).setup()
        controller.get().setContent { TideTheme { TideSettings(model.value, TideActions(), "beta", {}) } }
        node("Proton VPN").assertExists()
        compose.runOnIdle { model.value = model.value.copy(snapshot =
            model.value.snapshot.copy(vpnProvider = "Connected via Tailscale")) }
        node("Connected via Tailscale").assertExists()
        compose.runOnIdle { model.value = model.value.copy(snapshot =
            model.value.snapshot.copy(vpnProvider = null)) }
        node("Unrecognized VPN").assertExists()
        compose.runOnIdle { model.value = model.value.copy(snapshot =
            model.value.snapshot.copy(vpnActive = false)) }
        node("Not detected").assertExists()
        node("Unrecognized VPN").assertDoesNotExist()
    }

    @Test fun oldReadingsIncludeCalendarDateRatherThanOnlyTime() {
        val old = System.currentTimeMillis() - 4L * 24 * 60 * 60 * 1000
        val label = readTime(old)
        val expected = DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(old))
        assertTrue("historical date omitted from $label", label.contains(expected))
    }

    @Test fun resultsStayOutOfScrolledContentAndCannotMoveReset() {
        val model = mutableStateOf(TideUiState(
            snapshot = activeDashboard().snapshot,
            counters = sampleActivity(), report = sampleReport()
        ))
        val controller = Robolectric.buildActivity(ComponentActivity::class.java).setup()
        controller.get().setContent {
            TideTheme { TideScreen(model.value, TideActions(),
                initialDestination = TideDestination.ACTIVITY) }
        }
        val reset = compose.onNodeWithTag("reset-counters")
        reset.performScrollTo()
        compose.waitForIdle()
        val before = reset.fetchSemanticsNode().positionInRoot.y
        compose.runOnIdle { model.value = model.value.copy(message = BridgeMessages.VPN_OK) }
        compose.waitForIdle()
        val after = reset.fetchSemanticsNode().positionInRoot.y
        assertEquals("operation result shifted the reset button", before, after, 0.5f)
        node(BridgeMessages.VPN_OK).assertExists()
        node("Dismiss").performClick()
        assertEquals(before, reset.fetchSemanticsNode().positionInRoot.y, 0.5f)
    }

    @Test fun manualRecheckReportsItsResultWithoutLeavingSettings() {
        val fake = FakeGateway()
        open(fake); settings()
        node("Settings.").assertExists()
        compose.onNodeWithContentDescription("Recheck firewall status").performClick()
        compose.settle { fake.count("inspect") == 2 &&
            compose.hasText("Firewall status rechecked. No rules changed.") }
        node("Settings.").assertExists()
        assertEquals(listOf("inspect", "inspect"), fake.calls.toList())
        node("Dismiss").performClick()
        node("Firewall status rechecked. No rules changed.").assertDoesNotExist()
    }

    @Test fun recheckNeverClaimsVerifiedWhenFirewallIsDegraded() {
        val fake = FakeGateway(stateDashboard(Protection.DEGRADED, true, "Incomplete firewall"))
        open(fake, expect = "Needs")
        compose.onNodeWithContentDescription("Recheck firewall status").performClick()
        compose.settle { fake.count("inspect") == 2 && compose.hasText(
            "Status checked, but protection is not verified. No rules changed.") }
        assertFalse(compose.hasText("Firewall status rechecked. No rules changed."))
        assertEquals(listOf("inspect", "inspect"), fake.calls.toList())
    }

    @Test fun unchangedWindowFocusReturnNeverRequestsAnotherRootInspection() {
        val fake = FakeGateway()
        val controller = open(fake)
        val initially = fake.count("inspect")
        controller.pause()
        controller.windowFocusChanged(false)
        controller.resume()
        controller.windowFocusChanged(true)
        Thread.sleep(250) // Let Robolectric's async focus dispatcher settle.
        compose.waitForIdle()
        assertEquals(initially, fake.count("inspect"))
    }

    @Test fun changedTileStampRequestsExactlyOneRecheck() {
        val fake = FakeGateway()
        val controller = open(fake)
        controller.windowFocusChanged(false) // Shade remains over the resumed activity.
        Thread.sleep(100) // Let the false focus transition reach snapshotFlow.
        fake.dashboard = stateDashboard(Protection.INACTIVE, true, "Off.", BootRestore.DISABLED)
        TileStatusStore.publish(RuntimeEnvironment.getApplication(),
            Snapshot(protection = Protection.INACTIVE, rootReady = true))
        controller.windowFocusChanged(true)
        Thread.sleep(400) // Robolectric's focus listener dispatches asynchronously.
        // Query Compose first. Its test scheduler needs to pump the focus event
        // before the asynchronous fake's inspection count can increment.
        compose.settle { compose.hasText("Inactive.") && fake.count("inspect") >= 2 }
        node("Turn firewall off").assertDoesNotExist()
        assertEquals(2, fake.count("inspect"))
        // Automatic tile-triggered synchronization never displays a user-tap banner.
        node("Firewall is off. No rules changed.").assertDoesNotExist()
    }
}
