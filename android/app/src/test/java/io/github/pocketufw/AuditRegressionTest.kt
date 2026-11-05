package io.github.pocketufw

import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.SemanticsNodeInteraction
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.hasScrollAction
import androidx.compose.ui.test.isToggleable
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.text.TextLayoutResult
import io.github.pocketufw.FirewallClient.BootRestore
import io.github.pocketufw.FirewallClient.Protection
import io.github.pocketufw.FirewallClient.Snapshot
import io.github.pocketufw.FirewallClient.UdpConfigMode
import java.text.DateFormat
import java.util.Date
import java.util.concurrent.CountDownLatch
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

private const val DAY_MS = 24 * 60 * 60 * 1000L

/** Each test states a promise the screen makes about the firewall, and checks it on the real UI. */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class AuditRegressionTest {
    @get:Rule val compose = createEmptyComposeRule()

    private fun open(fake: FakeGateway, fontScale: Float = 1f) =
        compose.launchScreen(fake, fontScale = fontScale).also {
            compose.settle {
                fake.count("inspect") >= 1 && !compose.hasText("Checking kernel protection")
            }
        }

    private fun node(text: String, substring: Boolean = false) =
        compose.onNodeWithText(text, substring = substring)

    private fun SemanticsNodeInteraction.tap() = performScrollTo().also { performClick(); compose.waitForIdle() }
    private fun expandActivity() = node("Firewall activity").tap()
    private fun openStatus() { node("Status").tap() }
    private fun openUdp() = node("About / edit VPN UDP exceptions", substring = true).tap()
    private fun toggles() = compose.onAllNodes(isToggleable()).fetchSemanticsNodes().size
    private fun assertAbsent(text: String, substring: Boolean = false) =
        assertFalse("should not show: $text", compose.hasText(text, substring))
    private fun assertPresent(text: String, substring: Boolean = false) =
        assertTrue("should show: $text", compose.hasText(text, substring))

    private fun unclippedTop(text: String) =
        compose.onAllNodesWithText(text).fetchSemanticsNodes().first().positionInRoot.y

    // ---- Reset counters must be deliberate ---------------------------------

    @Test fun resetAsksFirstAndKeepCountsDoesNothing() {
        val fake = FakeGateway()
        open(fake); expandActivity()
        node("Reset counters").tap()
        assertPresent("Reset counters?")
        assertEquals(0, fake.count("reset-counters"))
        node("Keep counts").performClick(); compose.waitForIdle()
        assertAbsent("Reset counters?")
        assertEquals(0, fake.count("reset-counters"))
    }

    @Test fun confirmingResetRunsItExactlyOnce() {
        val fake = FakeGateway()
        open(fake); expandActivity()
        node("Reset counters").tap()
        node("Reset").performClick()
        compose.settle { fake.count("reset-counters") == 1 && compose.hasText(BridgeMessages.RESET_OK) }
        assertEquals(1, fake.count("reset-counters"))
        assertAbsent("Reset counters?")
    }

    @Test fun resetDialogSaysWhatChangesAndWhatDoesNot() {
        val fake = FakeGateway()
        open(fake); expandActivity()
        node("Reset counters").tap()
        assertPresent("1,204", substring = true)
        assertPresent("Firewall rules and VPN exceptions don't change", substring = true)
    }

    @Test fun refreshingCountersDoesNotMoveResetCounters() {
        val fake = FakeGateway()
        open(fake); expandActivity()
        node("Reset counters").performScrollTo(); compose.waitForIdle()
        val before = unclippedTop("Reset counters")
        node("Refresh counters").performClick()
        compose.settle { compose.hasText("Counters refreshed at", substring = true) }
        assertEquals(before, unclippedTop("Reset counters"), 0.5f)
    }

    @Test fun refreshingCountersDoesNotMoveResetCountersAtLargerText() {
        val fake = FakeGateway()
        open(fake, fontScale = 1.3f); expandActivity()
        node("Reset counters").performScrollTo(); compose.waitForIdle()
        val before = unclippedTop("Reset counters")
        node("Refresh counters").performClick()
        compose.settle { compose.hasText("Counters refreshed at", substring = true) }
        assertEquals(before, unclippedTop("Reset counters"), 0.5f)
    }

    // ---- Results must be visible and must not move anything ----------------

    @Test fun operationResultIsOnScreenWhereverYouAreScrolled() {
        val fake = FakeGateway()
        open(fake); expandActivity()
        node("PocketUFW ·", substring = true).performScrollTo(); compose.waitForIdle()
        node("Refresh VPN").performClick()
        compose.settle { fake.count("vpn-refresh") == 1 && compose.hasText(BridgeMessages.VPN_OK) }
        val banner = compose.onAllNodesWithText(BridgeMessages.VPN_OK).fetchSemanticsNodes().first()
        val rootHeight = compose.onRoot().fetchSemanticsNode().size.height
        assertTrue("banner above viewport", banner.positionInRoot.y >= 0f)
        assertTrue("banner below viewport", banner.positionInRoot.y + banner.size.height <= rootHeight)
    }

    @Test fun resultCanBeDismissedAndNeverHidesTheEndOfThePage() {
        val fake = FakeGateway()
        open(fake)
        node("Refresh VPN").tap()
        compose.settle { compose.hasText(BridgeMessages.VPN_OK) }
        compose.onNode(hasScrollAction()).performSemanticsAction(SemanticsActions.ScrollBy) { it(0f, 100_000f) }
        compose.waitForIdle()
        val footer = compose.onAllNodesWithText("PocketUFW ·", substring = true).fetchSemanticsNodes().first()
        val banner = compose.onAllNodesWithText(BridgeMessages.VPN_OK).fetchSemanticsNodes().first()
        assertTrue(
            "footer is hidden behind the banner",
            footer.positionInRoot.y + footer.size.height <= banner.positionInRoot.y,
        )
        node("Dismiss").performClick(); compose.waitForIdle()
        assertAbsent(BridgeMessages.VPN_OK)
    }

    /** Stopping a scrolled page from jumping when a result goes away. */
    @Test fun dismissingAResultAtTheEndOfThePageMovesNothing() {
        val fake = FakeGateway()
        open(fake); expandActivity()
        node("Refresh VPN").tap()
        compose.settle { compose.hasText(BridgeMessages.VPN_OK) }
        compose.onNode(hasScrollAction()).performSemanticsAction(SemanticsActions.ScrollBy) { it(0f, 100_000f) }
        compose.waitForIdle()
        val before = unclippedTop("Reset counters")
        node("Dismiss").performClick(); compose.waitForIdle()
        assertEquals(before, unclippedTop("Reset counters"), 0.5f)
    }

    @Test fun resultIsAnnouncedToAccessibilityServices() {
        val fake = FakeGateway()
        open(fake)
        node("Refresh VPN").tap()
        compose.settle { compose.hasText(BridgeMessages.VPN_OK) }
        node(BridgeMessages.VPN_OK).assert(
            SemanticsMatcher.expectValue(SemanticsProperties.LiveRegion, LiveRegionMode.Polite),
        )
    }

    @Test fun refreshVpnShowsItsOwnProgress() {
        val release = CountDownLatch(1)
        val fake = object : FirewallGateway by FakeGateway() {
            override fun refreshVerifiedPorts(): FirewallClient.Operation {
                release.await()
                return FirewallClient.Operation(true, BridgeMessages.VPN_OK, activeDashboard())
            }
        }
        compose.launchScreen(fake)
        compose.settle { compose.hasText("Refresh VPN") }
        node("Refresh VPN").tap()
        compose.settle { compose.hasText("Refreshing VPN…") }
        release.countDown()
        compose.settle { compose.hasText(BridgeMessages.VPN_OK) }
    }

    @Test fun staleRefreshNoteDoesNotOutliveALaterOperation() {
        val fake = FakeGateway()
        open(fake); expandActivity()
        node("Refresh counters").tap()
        compose.settle { compose.hasText("Counters refreshed at", substring = true) }
        node("Refresh VPN").tap()
        compose.settle { fake.count("vpn-refresh") == 1 && compose.hasText(BridgeMessages.VPN_OK) }
        assertAbsent("Counters refreshed at", substring = true)
    }

    // ---- No on/off position unless on/off is known -------------------------

    @Test fun activeShowsFirewallAndBootSwitches() {
        open(FakeGateway())
        assertEquals(2, toggles())
    }

    @Test fun inactiveShowsFirewallSwitchOnly() {
        open(FakeGateway(stateDashboard(Protection.INACTIVE, true, "off", BootRestore.DISABLED)))
        assertEquals(1, toggles())
    }

    @Test fun degradedShowsNoSwitch() {
        open(FakeGateway(stateDashboard(Protection.DEGRADED, true, "degraded")))
        assertEquals(0, toggles())
        assertPresent("Needs attention")
    }

    @Test fun rootRequiredShowsNoSwitchAndDoesNotClaimRootWasRefused() {
        open(FakeGateway(stateDashboard(Protection.ROOT_REQUIRED, false, "no root")))
        assertEquals(0, toggles())
        assertAbsent("Not granted")
        assertPresent("Not confirmed")
    }

    @Test fun checkingShowsNoSwitch() {
        val release = CountDownLatch(1)
        val fake = object : FirewallGateway by FakeGateway() {
            override fun inspectDashboard(): FirewallClient.Dashboard {
                release.await()
                return activeDashboard()
            }
        }
        compose.launchScreen(fake)
        compose.settle { compose.hasText("Checking kernel protection") }
        assertEquals(0, toggles())
        release.countDown()
        compose.settle { compose.hasText("Firewall active") }
    }

    @Test fun removingPartialRulesAsksFirstAndExplainsTheBootHook() {
        val fake = FakeGateway(stateDashboard(Protection.DEGRADED, true, "degraded"))
        open(fake)
        node("Remove partial PocketUFW rules").tap()
        assertEquals(0, fake.count("disable"))
        assertPresent("Magisk boot hook", substring = true)
        node("Remove rules").performClick()
        compose.settle { fake.count("disable") == 1 }
    }

    @Test fun unsupportedBootHasNoOffLookingSwitch() = checkBootProblem(BootRestore.UNSUPPORTED, "isn't available on this device")
    @Test fun degradedBootHasNoOffLookingSwitch() = checkBootProblem(BootRestore.DEGRADED, "incomplete")
    @Test fun conflictingBootHasNoOffLookingSwitch() = checkBootProblem(BootRestore.CONFLICT, "won't overwrite")
    @Test fun unknownBootHasNoOffLookingSwitch() = checkBootProblem(BootRestore.UNKNOWN, "couldn't be read")

    private fun checkBootProblem(boot: BootRestore, expected: String) {
        open(FakeGateway(activeDashboard(boot = boot)))
        assertEquals("only the firewall switch should remain", 1, toggles())
        assertPresent(expected, substring = true)
    }

    @Test fun policySentenceIsNotPresentedAsFactWhenOff() {
        open(FakeGateway(stateDashboard(Protection.INACTIVE, true, "off", BootRestore.DISABLED)))
        assertAbsent("Allow outgoing traffic. Deny unsolicited incoming traffic on supported physical interfaces.")
        assertPresent("Not installed")
        assertAbsent("Not verified")
    }

    @Test fun homeSaysWhenTheStateWasLastChecked() {
        open(FakeGateway())
        assertPresent("Checked ", substring = true)
    }

    @Test fun failedCounterReadWithdrawsTheVerifiedClaimButKeepsTheCounts() {
        val error = "Firewall is not active or its policy could not be verified."
        val fake = FakeGateway(counterRead = FirewallClient.RuleActivity(error = error))
        open(fake); expandActivity()
        assertPresent("RULES VERIFIED")
        node("Refresh counters").tap()
        compose.settle { compose.hasText(error) }
        assertAbsent("RULES VERIFIED")
        assertPresent("CHECK REQUIRED")
        assertEquals("only the boot switch remains; firewall on/off is no longer known", 1, toggles())
        assertPresent("1,516 packets", substring = true)

        node("Recheck status").tap()
        compose.settle { compose.hasText("RULES VERIFIED") }
        assertEquals(2, toggles())
    }

    @Test fun failedCounterReadAlsoWithdrawsTheClaimOnTheStatusTab() {
        val error = "Firewall is not active or its policy could not be verified."
        val fake = FakeGateway(counterRead = FirewallClient.RuleActivity(error = error))
        open(fake); expandActivity()
        node("Refresh counters").tap()
        compose.settle { compose.hasText(error) }
        openStatus()
        assertAbsent("ACTIVE · Verified")
        assertPresent("NOT VERIFIED")
    }

    @Test fun successfulCounterReadUpdatesTheCheckedTime() {
        val fresh = sampleActivity().copy(checkedAt = System.currentTimeMillis() - 3 * DAY_MS)
        val fake = FakeGateway(counterRead = fresh)
        open(fake); expandActivity()
        node("Refresh counters").tap()
        compose.settle { compose.hasText("Counters refreshed at", substring = true) }
        val date = DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(fresh.checkedAt))
        assertPresent("Checked $date", substring = true)
    }

    @Test fun firewallChangedByTheTileIsNoticedOnReturn() {
        val fake = FakeGateway()
        val controller = open(fake)
        assertPresent("Firewall active")
        controller.pause()
        controller.windowFocusChanged(false)
        fake.dashboard = stateDashboard(Protection.INACTIVE, true, "off", BootRestore.DISABLED)
        TileStatusStore.publish(
            RuntimeEnvironment.getApplication(),
            Snapshot(protection = Protection.INACTIVE, rootReady = true),
        )
        controller.resume()
        controller.windowFocusChanged(true)
        compose.settle { compose.hasText("PocketUFW is off") }
        assertAbsent("Firewall active")
        assertEquals(1, toggles())
    }

    /** The notification shade takes window focus but never pauses the activity. */
    @Test fun firewallChangedFromTheShadeIsNoticedWithoutAPause() {
        val fake = FakeGateway()
        val controller = open(fake)
        controller.windowFocusChanged(false)
        fake.dashboard = stateDashboard(Protection.INACTIVE, true, "off", BootRestore.DISABLED)
        TileStatusStore.publish(
            RuntimeEnvironment.getApplication(),
            Snapshot(protection = Protection.INACTIVE, rootReady = true),
        )
        controller.windowFocusChanged(true)
        compose.settle { compose.hasText("PocketUFW is off") }
    }

    @Test fun returningToTheAppWithoutAChangeDoesNotRequestRoot() {
        val fake = FakeGateway()
        val controller = open(fake)
        val inspections = fake.count("inspect")
        controller.pause()
        controller.windowFocusChanged(false)
        controller.resume()
        controller.windowFocusChanged(true)
        compose.waitForIdle()
        Thread.sleep(300)
        compose.waitForIdle()
        assertEquals(inspections, fake.count("inspect"))
    }

    /** FirewallClient publishes to the tile cache on every read, so this must not feed itself. */
    @Test fun theAppsOwnTileCacheUpdatesCannotCauseARootRequestLoop() {
        val fake = FakeGateway(tileContext = RuntimeEnvironment.getApplication())
        val controller = open(fake)
        assertEquals("launch is one root request", 1, fake.count("inspect"))
        repeat(3) {
            controller.pause()
            controller.windowFocusChanged(false)
            controller.resume()
            controller.windowFocusChanged(true)
            compose.waitForIdle()
            Thread.sleep(150)
            compose.waitForIdle()
        }
        assertEquals("returning to the app requested root again", 1, fake.count("inspect"))
        node("Refresh VPN").tap()
        compose.settle { compose.hasText(BridgeMessages.VPN_OK) }
        controller.windowFocusChanged(false)
        controller.windowFocusChanged(true)
        compose.waitForIdle()
        Thread.sleep(150)
        compose.waitForIdle()
        assertEquals("an operation's own publish triggered a recheck", 1, fake.count("inspect"))
    }

    // ---- VPN exception labels ----------------------------------------------

    @Test fun automaticModeDoesNotClaimLivePortsAreVerified() {
        open(FakeGateway())
        openStatus(); openUdp()
        assertAbsent("verified Tailscale listeners", substring = true)
        assertPresent("Saved mode: Automatic", substring = true)
        assertPresent("Experimental edit", substring = true)
    }

    @Test fun ruleTableDoesNotCallAnyPortVerified() {
        open(FakeGateway())
        openStatus()
        assertAbsent("Verified VPN UDP port", substring = true)
        assertPresent("VPN UDP exception, port 46867", substring = true)
    }

    @Test fun refreshVpnIsEnabledInAutomaticMode() {
        open(FakeGateway())
        node("Refresh VPN").assertIsEnabled()
    }

    @Test fun refreshVpnExplainsWhyItIsOffWhenCommitted() {
        open(FakeGateway(activeDashboard(mode = UdpConfigMode.COMMITTED, committed4 = "46867", committed6 = "43504")))
        node("Refresh VPN").assertIsNotEnabled()
        assertPresent("Committed ports are saved", substring = true)
    }

    @Test fun refreshVpnExplainsWhyItIsOffWhenSavedConfigIsBad() {
        open(FakeGateway(activeDashboard(mode = UdpConfigMode.DEGRADED)))
        node("Refresh VPN").assertIsNotEnabled()
        assertPresent("needs inspection", substring = true)
    }

    @Test fun committedPortsDifferingFromLiveStillWarn() {
        open(FakeGateway(activeDashboard(mode = UdpConfigMode.COMMITTED, committed4 = "1000", committed6 = "2000")))
        openStatus(); openUdp()
        assertPresent("The live rules differ from the committed settings", substring = true)
    }

    // ---- Counters report what the engine measured, and only that -----------

    @Test fun bytesAndPerFamilyRepliesAreShown() {
        open(FakeGateway()); expandActivity()
        assertPresent("1,204 packets · 98,664 bytes")
        assertPresent("312 packets · 31,820 bytes")
        assertPresent("IPv4 established replies accepted")
        assertPresent("84,112 packets")
        assertPresent("IPv6 established replies accepted")
        assertPresent("20,377 packets")
    }

    @Test fun missingByteCountsAreNotShownAsZero() {
        val activity = sampleActivity().copy(ipv4Bytes = null, ipv6Bytes = null)
        open(FakeGateway(activeDashboard(activity = activity))); expandActivity()
        assertAbsent("0 bytes", substring = true)
        assertPresent("1,204 packets · bytes unavailable")
    }

    @Test fun summaryDescribesRuleMatchesNotBlockedThreats() {
        open(FakeGateway())
        assertPresent("1,516 packets matched DROP rules", substring = true)
        assertAbsent("blocked", substring = true)
    }

    @Test fun lastResetIncludesTheDate() {
        val at = System.currentTimeMillis() - 3 * DAY_MS
        open(FakeGateway(activeDashboard(activity = sampleActivity(lastReset = at)))); expandActivity()
        val date = DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(at))
        assertPresent("Last reset from this app: $date", substring = true)
    }

    @Test fun oldReadingShowsItsDateButTodaysDoesNot() {
        val old = System.currentTimeMillis() - 3 * DAY_MS
        open(FakeGateway(activeDashboard(activity = sampleActivity().copy(checkedAt = old)))); expandActivity()
        val date = DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(old))
        assertPresent("Last checked: $date", substring = true)
    }

    @Test fun readingFromTodayShowsTimeOnly() {
        val now = System.currentTimeMillis()
        open(FakeGateway(activeDashboard(activity = sampleActivity().copy(checkedAt = now)))); expandActivity()
        val time = DateFormat.getTimeInstance(DateFormat.MEDIUM).format(Date(now))
        assertPresent("Last checked: $time")
    }

    @Test fun readingTimeOnlyOmitsTheDateForToday() {
        val noon = java.util.Calendar.getInstance().apply {
            set(2026, java.util.Calendar.NOVEMBER, 5, 12, 0, 0)
        }.timeInMillis
        val date = DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(noon))
        assertFalse(readingTime(noon, now = noon + 60_000).contains(date))
        assertTrue(readingTime(noon, now = noon + DAY_MS).contains(date))
        assertTrue("same day last year", readingTime(noon - 365 * DAY_MS, now = noon).contains("2025"))
    }

    @Test fun notesSayCountingStartIsNotRecorded() {
        open(FakeGateway()); expandActivity()
        assertPresent("doesn't record rule rebuilds", substring = true)
        assertPresent("INVALID", substring = true)
    }

    @Test fun hooksComeFromTheKernelReportNotAFixedString() {
        val base = sampleReport()
        val only = listOf("-A INPUT -i eth9 -m comment --comment PocketUFW -j POCKETUFW_IN")
        val report = base.copy(ipv4 = base.ipv4.copy(hooks = only), ipv6 = base.ipv6.copy(hooks = only))
        open(FakeGateway(activeDashboard(report = report))); expandActivity()
        assertPresent("Hooks: eth9")
        assertAbsent("Hooks: wlan+, rmnet+, v4-rmnet+")
    }

    @Test fun hooksAdmitWhenTheReportIsUnavailable() {
        open(FakeGateway(activeDashboard(report = null))); expandActivity()
        assertPresent("Hooks: rule report unavailable")
        assertAbsent("Hooks: wlan+, rmnet+, v4-rmnet+")
    }

    @Test fun hooksShowBothFamiliesWhenTheyDiffer() {
        val base = sampleReport()
        val six = listOf("-A INPUT -i wlan+ -m comment --comment PocketUFW -j POCKETUFW_IN")
        open(FakeGateway(activeDashboard(report = base.copy(ipv6 = base.ipv6.copy(hooks = six))))); expandActivity()
        assertPresent("IPv4 hooks: wlan+, rmnet+, v4-rmnet+")
        assertPresent("IPv6 hooks: wlan+")
    }

    // ---- Accessibility -----------------------------------------------------

    @Test fun tabsAreExposedAsTabsWithSelection() {
        open(FakeGateway())
        val isTab = SemanticsMatcher.expectValue(SemanticsProperties.Role, Role.Tab)
        node("Home").assert(isTab).assertIsSelected()
        node("Status").assert(isTab)
        openStatus()
        node("Status").assertIsSelected()
    }

    @Test fun activityRowReportsExpandedState() {
        open(FakeGateway())
        fun state() = compose.onNodeWithText("Firewall activity").fetchSemanticsNode()
            .config.getOrNull(SemanticsProperties.StateDescription)
        assertEquals("Collapsed", state())
        expandActivity()
        assertEquals("Expanded", state())
    }

    @Test fun statusHeadlineIsALiveRegion() {
        open(FakeGateway())
        node("Firewall active").assert(
            SemanticsMatcher.expectValue(SemanticsProperties.LiveRegion, LiveRegionMode.Polite),
        )
    }

    @Test fun sectionTitlesAreHeadings() {
        open(FakeGateway())
        val isHeading = SemanticsMatcher.keyIsDefined(SemanticsProperties.Heading)
        node("At a glance").assert(isHeading)
        openStatus()
        node("Firewall status").assert(isHeading)
    }

    @Test fun longCountsCannotSqueezeTheirLabelsOutAtLargeText() {
        val huge = sampleActivity().copy(
            ipv4Blocked = 9_876_543_210, ipv4Bytes = 987_654_321_098,
        )
        open(FakeGateway(activeDashboard(activity = huge)), fontScale = 2f); expandActivity()
        val label = compose.onAllNodesWithText("IPv4 dropped").fetchSemanticsNodes().first()
        val density = label.layoutInfo.density.density
        assertTrue(
            "label was only ${label.size.width / density}dp wide",
            label.size.width / density >= 60f,
        )
    }

    @Test fun unknownStatesDoNotReadAsOff() {
        val client = FirewallClient(RuntimeEnvironment.getApplication())
        val root = client.protectionDetails(Protection.ROOT_REQUIRED)
        val degraded = client.protectionDetails(Protection.DEGRADED)
        assertTrue(root, root.contains("doesn't mean the firewall is off"))
        assertTrue(degraded, degraded.contains("Don't assume"))
    }

    @Test fun ruleActionsStayOnOneLineAtDoubleTextSize() {
        open(FakeGateway(), fontScale = 2f)
        openStatus()
        val allow = compose.onAllNodesWithText("ALLOW").fetchSemanticsNodes()
        assertTrue("expected rule rows", allow.isNotEmpty())
        allow.forEach { node ->
            val layout = mutableListOf<TextLayoutResult>()
            node.config[SemanticsActions.GetTextLayoutResult].action?.invoke(layout)
            assertEquals("ALLOW wrapped at 200%", 1, layout.first().lineCount)
        }
    }
}
