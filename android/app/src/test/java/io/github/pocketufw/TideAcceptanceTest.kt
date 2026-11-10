package io.github.pocketufw

import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import android.graphics.Bitmap
import android.graphics.Canvas
import androidx.compose.ui.semantics.SemanticsProperties
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
import org.robolectric.RuntimeEnvironment
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.io.File

/** Reproductions of the owner's 2c83438 hardware UI handoff; no device/root calls. */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class TideAcceptanceTest {
    @get:Rule val compose = createEmptyComposeRule()
    private val screens = mutableListOf<ActivityController<ComponentActivity>>()
    @After fun drain() = drainMainLooper(screens)
    private fun node(text: String) = compose.onNodeWithText(text)
    private fun click(text: String) = node(text).performScrollTo().performClick()
    private fun show(ui: TideUiState, destination: TideDestination = TideDestination.ACTIVITY,
                     inspection: TideInspection = TideInspection.COUNTERS, dark: Boolean = false,
                     fontScale: Float = 1f, width: Int = 412) {
        RuntimeEnvironment.setQualifiers("w${width}dp-h915dp-xxhdpi")
        RuntimeEnvironment.setFontScale(fontScale)
        val controller = Robolectric.buildActivity(ComponentActivity::class.java).setup().also { screens += it }
        controller.get().setContent { TideTheme(dark) { TideScreen(ui, TideActions(),
            initialDestination = destination, initialInspection = inspection) } }
    }
    private fun shot(name: String) {
        // Host previews only; never overwrite the owner's git-ignored device evidence.
        val directory = File("build/reports/tide-acceptance").also { it.mkdirs() }
        val view = screens.last().get().window.decorView
        val bitmap = Bitmap.createBitmap(view.width, view.height, Bitmap.Config.ARGB_8888)
        compose.runOnIdle { view.draw(Canvas(bitmap)) }
        File(directory, "$name.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
        bitmap.recycle()
    }
    private fun report(): KernelReport {
        val client = FirewallClient(RuntimeEnvironment.getApplication(), shell = { _, _ -> error("No root") })
        val extra = listOf(4, 6).flatMap { family ->
            val source = if (family == 4) "100.64.0.0/10" else "fd7a:115c:a1e0::/48"
            val pin = if (family == 4) "100.64.0.1/32" else "fd7a:115c:a1e0::1/128"
            listOf("hook${family}_05=-A INPUT -i tun+ -m comment --comment PocketUFW-VPN -j POCKETUFW_VPN",
                "main${family}_09=-A POCKETUFW_VPN -s $source -d $pin -i tun+ -j ACCEPT",
                "main${family}_10=-A POCKETUFW_VPN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
                "main${family}_11=-A POCKETUFW_VPN -m conntrack --ctstate INVALID -j DROP",
                "main${family}_12=-A POCKETUFW_VPN -j DROP")
        }
        val output = bridgeOutput()
            .replace("report_hook4_count=4", "report_hook4_count=5")
            .replace("report_hook6_count=4", "report_hook6_count=5")
            .replace("report_tunnel4_count=0", "report_tunnel4_count=4")
            .replace("report_tunnel6_count=0", "report_tunnel6_count=4")
            .replace("rules_report=READY", extra.joinToString("\n") + "\nrules_report=READY")
        return client.dashboardFromOutput(0, output, false).kernelReport!!
    }

    @Test fun tunnelRulesAreNotPartOfThePhysicalExecutionOrder() {
        val report = report()
        for (family in listOf(report.ipv4, report.ipv6)) {
            assertEquals(8, family.inbound.size)
            assertTrue(family.inbound.all { it.startsWith("-A POCKETUFW_IN ") })
        }
        show(TideUiState(snapshot = tunnelDashboard().snapshot, report = report),
            inspection = TideInspection.RULES)
        compose.onNodeWithTag("tunnel-rule-0").assertTextContains("01")
            .assertTextContains("Pinned tailnet destination: 100.64.0.1/32")
        compose.onNodeWithTag("inbound-rule-8").assertDoesNotExist()
        compose.onNodeWithTag("tunnel-rule-3").performScrollTo()
        shot("kernel-tunnel-light")
        click("IPv6")
        compose.onNodeWithTag("tunnel-rule-0").assertTextContains("01")
            .assertTextContains("Pinned tailnet destination: fd7a:115c:a1e0::1/128")
        compose.onNodeWithTag("tunnel-rule-3").assertTextContains("Other incoming packets")
        click("Raw")
        node("POCKETUFW_VPN").assertExists()
        node("-A POCKETUFW_VPN -j DROP").assertExists()
    }

    @Test fun verifiedOffExplainsAbsentCountersAndHasNoCounterActions() {
        show(TideUiState(snapshot = Snapshot(Protection.INACTIVE, rootReady = true)))
        node("No counters exist because PocketUFW’s rules aren’t installed.").assertExists()
        node("Counters unavailable while protection is not verified.").assertDoesNotExist()
        node("Refresh counters").assertDoesNotExist()
        node("Reset counters").assertDoesNotExist()
        shot("counters-off-light")
    }

    @Test fun unverifiedOffStillRequiresVerification() {
        show(TideUiState(snapshot = Snapshot(Protection.INACTIVE, rootReady = true), verificationInDoubt = true))
        node("Counters unavailable while protection is not verified.").assertExists()
        node("Refresh counters").assertIsNotEnabled()
    }

    @Test fun bothCounterTablesHaveHeadersAndSelfDescribingRows() {
        show(TideUiState(snapshot = tunnelDashboard().snapshot, counters = tunnelActivity()))
        compose.onAllNodesWithText("Family").assertCountEquals(2)
        compose.onAllNodesWithText("Dropped").assertCountEquals(2)
        compose.onAllNodesWithText("Bytes").assertCountEquals(2)
        compose.onNodeWithContentDescription("Tunnel IPv4: 71 dropped packets, 930 bytes").assertExists()
        compose.onNodeWithContentDescription("Physical IPv6: 312 dropped packets, 31,820 bytes").assertExists()
        node("IPv6 tailnet matches").performScrollTo()
        shot("counters-tunnel-light")
    }

    @Test fun tunnelExpanderExposesBothStates() {
        show(TideUiState(snapshot = tunnelDashboard().snapshot), destination = TideDestination.SETTINGS)
        node("Tunnel protection").assert(SemanticsMatcher.expectValue(SemanticsProperties.StateDescription, "Collapsed"))
        click("Tunnel protection")
        node("Tunnel protection").assert(SemanticsMatcher.expectValue(SemanticsProperties.StateDescription, "Expanded"))
        shot("settings-expanded-light")
        click("Tunnel protection")
        node("Tunnel protection").assert(SemanticsMatcher.expectValue(SemanticsProperties.StateDescription, "Collapsed"))
    }

    @Test fun activityShowsBothReplyFamiliesDirectlyInDarkMode() {
        show(TideUiState(snapshot = tunnelDashboard().snapshot,
            counters = tunnelActivity().copy(lastManualResetAt = READ_AT)), dark = true)
        compose.onNodeWithTag("statistics-pill").assertDoesNotExist()
        node("Reply counts by address family").assertDoesNotExist()
        node("IPv4 replies").performScrollTo().assertIsDisplayed()
        node("IPv6 replies").performScrollTo().assertIsDisplayed()
        node("84,112").assertExists()
        node("20,377").assertExists()
        shot("activity-physical-dark")
        node("IPv4 tunnel replies").performScrollTo().assertIsDisplayed()
        node("IPv6 tunnel replies").performScrollTo().assertIsDisplayed()
        node("IPv6 tailnet matches").performScrollTo()
        shot("activity-tunnel-dark")
    }

    @Test fun largeTextKeepsCounterDescriptionsAndActionsAccessible() {
        show(TideUiState(snapshot = tunnelDashboard().snapshot, counters = tunnelActivity()), fontScale = 2f, width = 320)
        compose.onAllNodesWithText("Family").assertCountEquals(0) // Stacked rows have inline labels.
        node("Reply counts by address family").assertDoesNotExist()
        node("IPv4 replies").performScrollTo().assertIsDisplayed()
        node("IPv6 replies").performScrollTo().assertIsDisplayed()
        shot("activity-physical-large-light")
        compose.onNodeWithContentDescription("Tunnel IPv4: 71 dropped packets, 930 bytes")
            .performScrollTo().assertIsDisplayed()
        shot("statistics-tunnel-large-light")
        node("Reset counters").performScrollTo().assertIsDisplayed().assertIsEnabled()
        shot("statistics-actions-large-light")
        node("Settings").performClick(); click("Tunnel protection")
        node("Tunnel protection").assert(SemanticsMatcher.expectValue(SemanticsProperties.StateDescription, "Expanded"))
        node("Refresh tunnel hooks").performScrollTo().assertIsDisplayed().assertIsEnabled()
        shot("tunnel-actions-large-light")
    }

    @Test fun tunnelLabelsDoNotHideUnexpectedConditionsOrBroadDestinations() {
        assertEquals("ALLOW" to "Pinned tailnet destination: 100.64.0.1/32",
            describeRule("-A POCKETUFW_VPN -s 100.64.0.0/10 -d 100.64.0.1/32 -i tun+ -j ACCEPT"))
        for (rule in listOf(
            "-A POCKETUFW_VPN -s 100.64.0.0/10 -d 100.64.0.0/10 -i tun+ -j ACCEPT",
            "-A POCKETUFW_VPN -s fd7a:115c:a1e0::/48 -d fd7a:115c:a1e0::/64 -i tun+ -j ACCEPT",
            "-A POCKETUFW_VPN -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT",
            "-A POCKETUFW_VPN -m conntrack --ctstate INVALID -j ACCEPT")) {
            assertEquals(rule, describeRule(rule).second)
        }
    }
}
