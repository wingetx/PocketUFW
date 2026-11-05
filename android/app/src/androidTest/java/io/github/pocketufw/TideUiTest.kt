package io.github.pocketufw

import android.graphics.Bitmap
import androidx.compose.runtime.*
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.unit.Density
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Real Compose rendering; all inputs are fixtures and callbacks never invoke FirewallClient. */
@RunWith(AndroidJUnit4::class)
class TideUiTest {
    @get:Rule val compose = createComposeRule()

    private fun family(ipv6: Boolean = false) = FirewallClient.RuleFamily(
        inputPolicy = "ACCEPT",
        hooks = listOf("wlan+", "rmnet+", "v4-rmnet+").map {
            "-A INPUT -i $it -m comment --comment PocketUFW -j POCKETUFW_IN"
        },
        // Beta 4 kernel order: control traffic precedes INVALID, as reported.
        inbound = listOf(
            "-A POCKETUFW_IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A POCKETUFW_IN -p ${if (ipv6) "ipv6-icmp" else "icmp"} -j ACCEPT",
            "-A POCKETUFW_IN -m conntrack --ctstate INVALID -j DROP",
            "-A POCKETUFW_IN -p udp -m udp --sport ${if (ipv6) "547 --dport 546" else "67 --dport 68"} -j ACCEPT",
            "-A POCKETUFW_IN -d ${if (ipv6) "ff02::fb/128" else "224.0.0.251/32"} -p udp -m udp --dport 5353 -j ACCEPT",
            "-A POCKETUFW_IN -p esp -j ACCEPT",
            "-A POCKETUFW_IN -j POCKETUFW_TS",
            "-A POCKETUFW_IN -j DROP"
        ), vpnExceptions = listOf("-A POCKETUFW_TS -p udp -m udp --dport 41641 -j ACCEPT")
    )

    private fun sample() = TideUiState(
        snapshot = FirewallClient.Snapshot(FirewallClient.Protection.ACTIVE, rootReady = true,
            vpnActive = true, bootRestore = FirewallClient.BootRestore.ENABLED,
            udpConfigMode = FirewallClient.UdpConfigMode.AUTOMATIC),
        counters = FirewallClient.RuleActivity(1196, 88, 86323, 7987, 21348, 1342, 1793871666000L),
        report = FirewallClient.KernelReport(family(), family(true), 1793871666000L)
    )

    private fun show(ui: TideUiState = sample(), actions: TideActions = TideActions(),
                     destination: TideDestination = TideDestination.FIREWALL,
                     inspection: TideInspection = TideInspection.COUNTERS,
                     dark: Boolean = false, scale: Float = 1f) {
        compose.setContent {
            CompositionLocalProvider(LocalDensity provides Density(LocalDensity.current.density, scale)) {
                TideTheme(dark) { TideScreen(ui, actions, initialDestination = destination, initialInspection = inspection) }
            }
        }
    }

    private fun shot(name: String) {
        compose.waitForIdle()
        val directory = File(InstrumentationRegistry.getInstrumentation().targetContext.getExternalFilesDir(null), "tide-previews")
        directory.mkdirs()
        val roots = compose.onAllNodes(isRoot()).fetchSemanticsNodes()
        // Dialog tests have two roots; the emulator screenshot captures both layers.
        val bitmap = if (roots.size > 1) InstrumentationRegistry.getInstrumentation().uiAutomation.takeScreenshot()
            else compose.onRoot().captureToImage().asAndroidBitmap()
        File(directory, "$name.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
    }

    @Test fun resetRequiresConfirmationAndCancelDoesNothing() {
        var calls = 0
        show(actions = TideActions(resetCounters = { calls++ }), destination = TideDestination.ACTIVITY)
        compose.onNodeWithTag("reset-counters").performScrollTo().performClick()
        compose.onNodeWithText("Reset counters?").assertIsDisplayed()
        assertEquals(0, calls)
        shot("reset-confirmation")
        compose.onNodeWithText("Cancel").performClick()
        assertEquals(0, calls)
        compose.onNodeWithTag("reset-counters").performClick()
        compose.onNodeWithTag("confirm-reset-counters").performClick()
        assertEquals(1, calls)
    }

    @Test fun pendingResetCannotActAfterProtectionChanges() {
        var calls = 0
        val model = mutableStateOf(sample())
        compose.setContent { TideTheme { TideScreen(model.value, TideActions(resetCounters = { calls++ }),
            initialDestination = TideDestination.ACTIVITY) } }
        compose.onNodeWithTag("reset-counters").performScrollTo().performClick()
        compose.runOnIdle { model.value = model.value.copy(snapshot = FirewallClient.Snapshot()) }
        compose.onNodeWithTag("confirm-reset-counters").assertDoesNotExist()
        compose.onNodeWithTag("reset-counters").assertIsNotEnabled()
        assertEquals(0, calls)
    }

    @Test fun kernelOrderAndUnknownRulesAreRetainedInBothViews() {
        val original = family()
        val unknown = "-A POCKETUFW_IN -p tcp --dport 12345 -j RETURN"
        val supplied = listOf(original.inbound[2], unknown, original.inbound[1], original.inbound[0])
        val report = FirewallClient.KernelReport(original.copy(inbound = supplied), family(true), 1793871666000L)
        show(sample().copy(report = report), destination = TideDestination.ACTIVITY, inspection = TideInspection.RULES)
        compose.onNodeWithTag("inbound-rule-0").assertTextContains("Invalid packets")
        compose.onNodeWithTag("inbound-rule-1").assertTextContains(unknown)
        compose.onNodeWithTag("inbound-rule-2").assertTextContains("ICMP control traffic")
        compose.onNodeWithTag("inbound-rule-3").assertTextContains("Established / related replies")
        val positions = (0..3).map { compose.onNodeWithTag("inbound-rule-$it").fetchSemanticsNode().positionInRoot.y }
        assertEquals(positions.sorted(), positions)
        compose.onNodeWithText("Raw", useUnmergedTree = true).performScrollTo().performClick()
        supplied.forEach { compose.onNodeWithText(it, useUnmergedTree = true).assertExists() }
        val rawPositions = supplied.map { compose.onNodeWithText(it, useUnmergedTree = true).fetchSemanticsNode().positionInRoot.y }
        assertEquals(rawPositions.sorted(), rawPositions)
        compose.onNodeWithText("IPv6", useUnmergedTree = true).performScrollTo().performClick()
        compose.onNodeWithText(family(true).inbound[1], useUnmergedTree = true).assertExists()
    }

    @Test fun checkingAndBusyDoNotSwitchTheFirewall() {
        var calls = 0
        var bootCalls = 0
        val model = mutableStateOf(TideUiState())
        compose.setContent { TideTheme { TideScreen(model.value, TideActions(
            changeProtection = { calls++ }, changeBootRestoration = { bootCalls++ })) } }
        compose.onNodeWithTag("firewall-action").assertIsNotEnabled()
        compose.onNodeWithText("Turn firewall on").assertDoesNotExist()
        shot("checking")
        compose.runOnIdle { model.value = sample().copy(busy = true) }
        compose.onNodeWithText("Active.").assertExists()
        compose.onNodeWithTag("firewall-action").performClick()
        assertEquals(0, calls)
        compose.onNodeWithText("Settings").performClick()
        compose.onNodeWithContentDescription("Restore after reboot")
            .assertIsOn().assertIsEnabled().performClick().assertIsOn()
        assertEquals(0, bootCalls)
    }

    @Test fun renderFirewall() { show(); shot("firewall") }
    @Test fun renderCounters() { show(destination = TideDestination.ACTIVITY); shot("counters") }
    @Test fun renderRules() {
        show(destination = TideDestination.ACTIVITY, inspection = TideInspection.RULES)
        shot("rules")
        compose.onNodeWithText("Raw", useUnmergedTree = true).performClick(); shot("raw-rules")
    }
    @Test fun renderSettingsAndExceptions() {
        show(destination = TideDestination.SETTINGS); shot("settings")
        compose.onNodeWithText("VPN UDP exceptions").performScrollTo().performClick(); shot("exceptions")
    }
    @Test fun renderNightAndLargeText() {
        show(dark = true, scale = 1.6f)
        compose.onNodeWithTag("firewall-action").assertIsDisplayed(); shot("dark-large-text")
    }
    @Test fun largeTextKeepsInspectionAndResetReachable() {
        show(destination = TideDestination.ACTIVITY, scale = 1.6f)
        compose.onNodeWithTag("reset-counters").performScrollTo().assertIsDisplayed().performClick()
        compose.onNodeWithText("Cancel").assertIsDisplayed().performClick()
        compose.onNodeWithText("Kernel rules").performScrollTo().performClick()
        compose.onNodeWithText("IPv6", useUnmergedTree = true).performScrollTo().performClick()
        shot("large-text-rules")
        compose.onNodeWithText("Raw", useUnmergedTree = true).performClick()
        compose.onNodeWithText(family(true).inbound[1], useUnmergedTree = true).assertExists()
    }
    @Test fun renderAllProtectionStates() {
        val model = mutableStateOf(sample())
        compose.setContent { TideTheme { TideScreen(model.value, TideActions()) } }
        for (state in FirewallClient.Protection.entries) {
            compose.runOnIdle { model.value = sample().copy(snapshot = sample().snapshot.copy(
                protection = state, rootReady = state != FirewallClient.Protection.ROOT_REQUIRED,
                details = if (state == FirewallClient.Protection.ROOT_REQUIRED) "Grant PocketUFW root access in your root manager, then check again."
                    else "PocketUFW rules are incomplete or could not be verified.")) }
            shot("state-${state.name.lowercase()}")
        }
    }
}
