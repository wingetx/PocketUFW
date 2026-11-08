package io.github.pocketufw

import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import io.github.pocketufw.FirewallClient.BootRestore
import io.github.pocketufw.FirewallClient.Protection
import io.github.pocketufw.FirewallClient.Snapshot
import java.text.DateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
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

/** Exact words on the screen. A firewall UI that overclaims is itself the defect. */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class TideWordingTest {
    @get:Rule val compose = createEmptyComposeRule()

    private fun node(value: String, substring: Boolean = false) =
        compose.onNodeWithText(value, substring = substring)

    private val screens = mutableListOf<ActivityController<ComponentActivity>>()

    @After fun closeScreens() = drainMainLooper(screens)

    private fun activity() = Robolectric.buildActivity(ComponentActivity::class.java).setup().also { screens += it }

    private fun show(
        ui: TideUiState,
        destination: TideDestination = TideDestination.FIREWALL,
        inspection: TideInspection = TideInspection.COUNTERS,
        qualifiers: String = "w412dp-h915dp-xxhdpi",
    ) {
        RuntimeEnvironment.setQualifiers(qualifiers)
        activity().get().setContent {
            TideTheme { TideScreen(ui, TideActions(), initialDestination = destination, initialInspection = inspection) }
        }
        compose.waitForIdle()
    }

    private val active = activeDashboard().snapshot
    private fun ui(snapshot: Snapshot, report: FirewallClient.KernelReport? = sampleReport(), doubt: Boolean = false) =
        TideUiState(snapshot = snapshot, counters = sampleActivity(), report = report,
            verificationInDoubt = doubt, checkedAt = READ_AT)

    // ---- Firewall tab headline ----

    @Test fun cliTunnelFilteringDisclosesSessionAndTrustLimits() {
        show(ui(active.copy(tunnelFilter = FirewallClient.TunnelFilter.ON)))
        node("Tunnel rules are on for listed hooks, until restart. Only pinned Tailscale destinations are trusted on tun*. Packet sources and interface ownership are not authenticated.").assertExists()
        node("Settings").performClick()
        node("Restores physical filtering only; CLI tunnel filtering never restores.", substring = true).assertExists()
    }

    @Test fun stalePinsShowReauthorizationWithoutWithdrawingEnforcement() {
        show(ui(active.copy(tunnelFilter = FirewallClient.TunnelFilter.ON,
            tunnelMode = FirewallClient.TunnelMode.PINNED,
            tailnetConnectivity = FirewallClient.TailnetConnectivity.REAUTHORIZE,
            tailnetPin4 = "100.64.0.1/32", tailnetPin6 = "fd7a:115c:a1e0::1/128",
            tailnetObserved4 = "100.64.0.9/32", tailnetObserved6 = "fd7a:115c:a1e0::9/128")))
        node("Active.").assertExists()
        node("Pinned tailnet destinations: 100.64.0.1/32, fd7a:115c:a1e0::1/128.").assertExists()
        node("Tailnet connectivity: REAUTHORIZE.", substring = true).assertExists()
        node("100.64.0.9/32", substring = true).assertExists()
        node("Installed protection is unchanged.", substring = true).assertExists()
    }

    @Test fun denyOnlyWarnsAboutTailscaleStartingLater() {
        show(ui(active.copy(tunnelFilter = FirewallClient.TunnelFilter.ON,
            tunnelMode = FirewallClient.TunnelMode.DENY_ONLY)))
        node("Deny-only has no tailnet exemption", substring = true).assertExists()
        node("unsolicited peer connections remain filtered if Tailscale starts later", substring = true).assertExists()
        node("Only pinned Tailscale destinations", substring = true).assertDoesNotExist()
    }

    private data class Headline(val title: String, val label: String, val body: String, val button: String)

    private val headlines = listOf(
        Snapshot(Protection.ACTIVE, rootReady = true) to Headline("Active.", "KERNEL RULES VERIFIED",
            "Unsolicited incoming traffic is blocked on supported physical interfaces.", "Turn firewall off"),
        Snapshot(Protection.INACTIVE, rootReady = true) to Headline("Off.", "POCKETUFW IS INACTIVE",
            "PocketUFW rules are not installed. Android’s own firewall remains unchanged.", "Turn firewall on"),
        Snapshot(Protection.DEGRADED, rootReady = true, details = "Incomplete firewall.") to Headline(
            "Needs\nattention.", "PROTECTION NOT VERIFIED", "Incomplete firewall.", "Recheck status"),
        Snapshot(Protection.ROOT_REQUIRED, rootReady = false, details = "No root.") to Headline(
            "Root\nrequired.", "ROOT PERMISSION NEEDED", "No root.", "Check root access"),
    )

    @Test fun udpEditorOnlyOpensFromSettingsNotKernelRules() {
        show(ui(active), TideDestination.ACTIVITY, TideInspection.RULES)
        node("VPN UDP exceptions · child chain").assertExists()
        node("VPN UDP exceptions").assertDoesNotExist()
        node("Settings").performClick()
        node("VPN UDP exceptions").performScrollTo().performClick()
        node("UDP exceptions.").assertExists()
    }

    @Test fun checkingWordingClaimsNothing() {
        // The spinner never idles, so this one is stepped by hand.
        compose.mainClock.autoAdvance = false
        activity().get().setContent { TideTheme { TideScreen(ui(Snapshot(Protection.CHECKING), report = null), TideActions()) } }
        compose.mainClock.advanceTimeByFrame()
        node("Checking…").assertExists()
        node("READING KERNEL STATE").assertExists()
        node("Reading firewall rules and Magisk boot status. Protection has not yet been verified.").assertExists()
        node("Checking kernel protection").assertExists()
        for ((_, other) in headlines) node(other.title).assertDoesNotExist()
    }

    @Test fun firewallTabWordingIsExactForEveryState() {
        val model = mutableStateOf(ui(active))
        activity().get().setContent {
            TideTheme { TideScreen(model.value, TideActions()) }
        }
        for ((snapshot, expected) in headlines) {
            compose.runOnIdle { model.value = ui(snapshot, report = null) }
            compose.waitForIdle()
            val state = snapshot.protection.name
            node(expected.title).assertExists("$state title")
            node(expected.label).assertExists("$state label")
            node(expected.body).assertExists("$state body")
            node(expected.button).assertExists("$state button")
            // Only one headline is ever on screen.
            headlines.filter { it.first !== snapshot }.forEach { (_, other) ->
                node(other.title).assertDoesNotExist()
                node(other.label).assertDoesNotExist()
            }
        }
    }

    @Test fun doubtReplacesEveryClaimAboutTheLastReading() {
        show(ui(active, doubt = true))
        node("Not\nverified.").assertExists()
        node("RECHECK REQUIRED").assertExists()
        node("A later read failed or the Quick Settings tile changed. " +
            "Last known status is not proof of current protection. Recheck the kernel.").assertExists()
        node("Recheck status").assertExists()
        node("Active.").assertDoesNotExist()
        node("KERNEL RULES VERIFIED").assertDoesNotExist()
        node("Turn firewall off").assertDoesNotExist()
        node("Matched deny policy¹").assertDoesNotExist()
    }

    @Test fun policyRowOnlyClaimsTheDenyPolicyWhenVerified() {
        show(ui(active))
        node("Matched deny policy¹").assertExists()
    }

    @Test fun policyRowIsHonestWhenOff() {
        show(ui(Snapshot(Protection.INACTIVE, rootReady = true)))
        node("Not installed").assertExists()
        node("Matched deny policy¹").assertDoesNotExist()
    }

    @Test fun policyRowIsHonestWhenUnverified() {
        show(ui(Snapshot(Protection.DEGRADED, rootReady = true)))
        node("Not verified").assertExists()
        node("Matched deny policy¹").assertDoesNotExist()
    }

    // ---- failed boot restoration ----

    private val notice = "Restore after reboot is on, but the firewall isn't running. " +
        "It may not have started at the last boot."
    private val offButArmed = Snapshot(Protection.INACTIVE, rootReady = true, bootRestore = BootRestore.ENABLED)

    @Test fun offWithRestoreOnIsExplainedOnTheFirewallTab() {
        show(ui(offButArmed))
        node(notice).assertExists()
        node("Off.").assertExists()
    }

    @Test fun offWithRestoreOnIsExplainedInSettings() {
        show(ui(offButArmed), TideDestination.SETTINGS)
        node(notice).assertExists()
    }

    @Test fun offWithRestoreOffHasNoNotice() {
        show(ui(offButArmed.copy(bootRestore = BootRestore.DISABLED)))
        node(notice).assertDoesNotExist()
    }

    @Test fun settingsStillExplainTheSwitchWhenOffWithRestoreOff() {
        show(ui(offButArmed.copy(bootRestore = BootRestore.DISABLED)), TideDestination.SETTINGS)
        node(notice).assertDoesNotExist()
        node("Enable the firewall to change boot restoration.").assertExists()
    }

    @Test fun activeWithRestoreOnHasNoNotice() {
        show(ui(active.copy(bootRestore = BootRestore.ENABLED)))
        node(notice).assertDoesNotExist()
    }

    @Test fun anUnverifiedReadingHasNoNotice() {
        show(ui(offButArmed, doubt = true))
        node(notice).assertDoesNotExist()
    }

    // ---- disclosure: uncovered interfaces and bypass rules ----

    private val bypassWarning = "An earlier rule accepts traffic before PocketUFW's hooks."

    private fun bypassReport(rule4: String? = "-A INPUT -i wlan0 -j ACCEPT", rule6: String? = null): FirewallClient.KernelReport {
        val base = sampleReport()
        return base.copy(ipv4 = base.ipv4.copy(bypass = listOfNotNull(rule4)),
            ipv6 = base.ipv6.copy(bypass = listOfNotNull(rule6)))
    }

    @Test fun aVpnTunnelAloneIsNamedAndTheHeadlineStopsImplyingFullCoverage() {
        show(ui(active.copy(vpnActive = true, vpnProvider = "Proton VPN", vpnInterface = "tun0",
            uncoveredInterfaces = listOf("tun0"))))
        node("Not filtered: traffic inside Proton VPN (tun0).").assertExists()
        node("RULES VERIFIED · NOT ALL TRAFFIC FILTERED").assertExists()
        node("KERNEL RULES VERIFIED").assertDoesNotExist()
    }

    @Test fun everyKindOfTunnelIsDescribedWithoutGuessingItsOwner() {
        val proton = active.copy(vpnActive = true, vpnProvider = "Proton VPN", vpnInterface = "tun0")
        assertEquals("traffic inside Proton VPN (tun0)", uncoveredLabel("tun0", proton))
        val tailscale = active.copy(vpnActive = true, vpnProvider = "Connected via Tailscale", vpnInterface = "tun1")
        assertEquals("traffic inside Tailscale (tun1)", uncoveredLabel("tun1", tailscale))
        // Another tunnel isn't the VPN's just because a VPN is connected.
        assertEquals("VPN tunnel tun0", uncoveredLabel("tun0", tailscale))
        assertEquals("VPN tunnel tun0", uncoveredLabel("tun0", active.copy(vpnActive = true, vpnProvider = "Proton VPN")))
        val unknown = active.copy(vpnActive = true, vpnProvider = "Unrecognized VPN", vpnInterface = "tun0")
        assertEquals("VPN tunnel tun0", uncoveredLabel("tun0", unknown))
        assertEquals("carrier or VPN tunnel ipsec7", uncoveredLabel("ipsec7", proton))
        assertEquals("wg-home", uncoveredLabel("wg-home", proton))
        assertEquals("eth0", uncoveredLabel("eth0", active))
        // A provider that owns a kernel interface gets the same plain words.
        val kernel = active.copy(vpnActive = true, vpnProvider = "WireGuard", vpnInterface = "wg0")
        assertEquals("traffic inside WireGuard (wg0)", uncoveredLabel("wg0", kernel))
    }

    @Test fun severalTunnelsAreListedTogether() {
        show(ui(active.copy(vpnActive = true, vpnProvider = "Connected via Tailscale", vpnInterface = "tun1",
            uncoveredInterfaces = listOf("US-DEN-315", "tun1", "ipsec7"))))
        node("Not filtered: US-DEN-315, traffic inside Tailscale (tun1), carrier or VPN tunnel ipsec7.").assertExists()
    }

    @Test fun uncoveredInterfacesAreNamedAndTheHeadlineStopsImplyingFullCoverage() {
        show(ui(active.copy(uncoveredInterfaces = listOf("eth0", "usb0"))))
        node("Not filtered: eth0, usb0.").assertExists()
        node("Active.").assertExists() // The state itself stays.
        node("KERNEL RULES VERIFIED").assertDoesNotExist()
        node("RULES VERIFIED · NOT ALL TRAFFIC FILTERED").assertExists()
        node("Unsolicited incoming traffic is blocked on supported physical interfaces.").assertDoesNotExist()
        node("Matched deny policy¹").assertDoesNotExist()
        node("Turn firewall off").assertExists()
    }

    @Test fun nothingUncoveredKeepsTheNormalHeadline() {
        show(ui(active))
        node("Not filtered", substring = true).assertDoesNotExist()
        node(bypassWarning, substring = true).assertDoesNotExist()
        node("KERNEL RULES VERIFIED").assertExists()
    }

    @Test fun uncoveredIsOnlyDisclosedWhenActive() {
        show(ui(Snapshot(Protection.INACTIVE, rootReady = true, uncoveredInterfaces = listOf("eth0"))))
        node("Not filtered", substring = true).assertDoesNotExist()
    }

    @Test fun aBypassRuleIsDisclosedOnTheFirewallTab() {
        show(ui(active, report = bypassReport()))
        node(bypassWarning, substring = true).assertExists()
        node("Active.").assertExists()
        node("KERNEL RULES VERIFIED").assertDoesNotExist()
    }

    @Test fun aBypassRuleInEitherFamilyIsDisclosed() {
        show(ui(active, report = bypassReport(rule4 = null, rule6 = "-A INPUT -i wlan0 -j ACCEPT")))
        node(bypassWarning, substring = true).assertExists()
    }

    @Test fun kernelRulesListBypassRulesInReadableView() {
        val rule = "-A INPUT -i wlan0 -j ACCEPT"
        show(ui(active, report = bypassReport(rule)), TideDestination.ACTIVITY, TideInspection.RULES)
        node(bypassWarning, substring = true).assertExists()
        compose.onNodeWithTag("bypass-rule-0").assertTextContains(rule)
        compose.onNodeWithTag("bypass-rule-0").assertTextContains("ALLOW")
    }

    @Test fun kernelRulesListBypassRulesInRawView() {
        val rule = "-A INPUT -s 10.0.0.0/8 -j ACCEPT"
        show(ui(active, report = bypassReport(rule)), TideDestination.ACTIVITY, TideInspection.RULES)
        node("Raw").performClick()
        compose.waitForIdle()
        node(bypassWarning, substring = true).assertExists()
        compose.onNodeWithText(rule, useUnmergedTree = true).assertExists()
    }

    @Test fun kernelRulesShowEachFamilysOwnBypassRules() {
        val six = "-A INPUT -i rmnet0 -j ACCEPT"
        show(ui(active, report = bypassReport(rule4 = null, rule6 = six)), TideDestination.ACTIVITY, TideInspection.RULES)
        node(bypassWarning, substring = true).assertExists()
        compose.onNodeWithTag("bypass-rule-0").assertDoesNotExist()
        compose.onNodeWithText("IPv6", useUnmergedTree = true).performClick()
        compose.waitForIdle()
        compose.onNodeWithTag("bypass-rule-0").assertTextContains(six)
    }

    @Test fun noBypassRulesNoSection() {
        show(ui(active), TideDestination.ACTIVITY, TideInspection.RULES)
        node(bypassWarning, substring = true).assertDoesNotExist()
        compose.onNodeWithTag("bypass-rule-0").assertDoesNotExist()
    }

    // ---- stale wording ----

    @Test fun udpTextNamesTheRealButton() {
        show(ui(active), TideDestination.SETTINGS)
        node("VPN UDP exceptions").performScrollTo().performClick()
        compose.waitForIdle()
        assertFalse(compose.hasText("Refresh VPN", substring = true))
        node("Refresh Tailscale ports won't overwrite committed ports", substring = true).assertExists()
        node("Refresh Tailscale ports runs", substring = true).assertExists()
    }

    @Test fun tileHelpDescribesWhatATapReallyDoes() {
        show(ui(active), TideDestination.SETTINGS)
        node("Quick Settings tile").performScrollTo().performClick()
        compose.waitForIdle()
        node("A tap switches only if the kernel still matches what the tile shows. " +
            "If the tile can't say whether the firewall is on or off, a tap only checks.", substring = true).assertExists()
    }

    // ---- banner ----

    private fun scrollToEnd() {
        compose.onNode(hasScrollAction()).performSemanticsAction(SemanticsActions.ScrollBy) { it(0f, 100_000f) }
        compose.waitForIdle()
    }

    @Test fun nothingIsStrandedUnderTheBannerAtFullScroll() {
        show(ui(active).copy(message = BridgeMessages.VPN_COMMITTED), qualifiers = "w360dp-h640dp-xxhdpi")
        scrollToEnd()
        val footnote = node("Supported physical interfaces only", substring = true).fetchSemanticsNode().boundsInRoot
        val banner = compose.onNodeWithTag("banner").fetchSemanticsNode().boundsInRoot
        assertTrue("footnote ${footnote.bottom} runs under banner ${banner.top}", footnote.bottom <= banner.top)
    }

    @Test fun noControlSitsUnderTheBannerAtAnyScrollPosition() {
        show(ui(active).copy(message = BridgeMessages.VPN_COMMITTED), qualifiers = "w360dp-h640dp-xxhdpi")
        val action = node("Turn firewall off").performScrollTo().fetchSemanticsNode().boundsInRoot
        val banner = compose.onNodeWithTag("banner").fetchSemanticsNode().boundsInRoot
        assertTrue("action ${action.bottom} runs under banner ${banner.top}", action.bottom <= banner.top)
    }

    @Test fun theBannerTakesNoRoomWhenHidden() {
        val model = mutableStateOf(ui(active))
        RuntimeEnvironment.setQualifiers("w360dp-h640dp-xxhdpi")
        activity().get().setContent {
            TideTheme { TideScreen(model.value, TideActions()) }
        }
        compose.waitForIdle()
        val area = compose.onNode(hasScrollAction()).fetchSemanticsNode().boundsInRoot
        compose.runOnIdle { model.value = model.value.copy(message = BridgeMessages.VPN_OK) }
        compose.waitForIdle()
        val withBanner = compose.onNode(hasScrollAction()).fetchSemanticsNode().boundsInRoot
        assertTrue(withBanner.bottom < area.bottom)
        compose.runOnIdle { model.value = model.value.copy(message = "") }
        compose.waitForIdle()
        assertEquals(area.bottom, compose.onNode(hasScrollAction()).fetchSemanticsNode().boundsInRoot.bottom, 0.5f)
    }

    // ---- formatting ----

    @Test fun byteCountUsesTheRightUnitAtEachBoundary() {
        val before = Locale.getDefault()
        Locale.setDefault(Locale.US)
        try {
            val expected = mapOf(
                null to "—", 0L to "0 B", 1023L to "1023 B",
                1024L to "1.0 KiB", 1536L to "1.5 KiB", 1_048_575L to "1024.0 KiB",
                1_048_576L to "1.0 MiB", 1_572_864L to "1.5 MiB",
                1_073_741_824L to "1.0 GiB", 1_610_612_736L to "1.5 GiB",
            )
            for ((value, text) in expected) assertEquals("$value", text, byteCount(value))
        } finally { Locale.setDefault(before) }
    }

    @Test fun countGroupsDigitsAndMarksUnavailable() {
        val before = Locale.getDefault()
        Locale.setDefault(Locale.US)
        try {
            assertEquals("—", count(null))
            assertEquals("0", count(0))
            assertEquals("1,204", count(1204))
        } finally { Locale.setDefault(before) }
    }

    @Test fun readTimeShowsOnlyTheClockForToday() {
        val noon = Calendar.getInstance().apply {
            set(2026, Calendar.MARCH, 10, 12, 0, 0); set(Calendar.MILLISECOND, 0)
        }.timeInMillis
        val earlier = noon - 3_600_000
        assertEquals(DateFormat.getTimeInstance(DateFormat.MEDIUM).format(Date(earlier)), readTime(earlier, now = noon))
    }

    @Test fun readTimeIncludesTheDateForOtherDays() {
        val noon = Calendar.getInstance().apply {
            set(2026, Calendar.MARCH, 10, 12, 0, 0); set(Calendar.MILLISECOND, 0)
        }.timeInMillis
        val yesterday = noon - 24 * 3_600_000L
        val lastYear = Calendar.getInstance().apply { timeInMillis = noon; add(Calendar.YEAR, -1) }.timeInMillis
        val full = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.MEDIUM)
        assertEquals(full.format(Date(yesterday)), readTime(yesterday, now = noon))
        assertEquals("the same day last year is not today", full.format(Date(lastYear)), readTime(lastYear, now = noon))
    }

    // ---- rule descriptions ----

    @Test fun everyRealRuleKeepsItsPlainDescription() {
        val expected = mapOf(
            "-A POCKETUFW_IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" to ("ALLOW" to "Established / related replies"),
            "-A POCKETUFW_IN -p icmp -j ACCEPT" to ("ALLOW" to "ICMP control traffic"),
            "-A POCKETUFW_IN -p ipv6-icmp -j ACCEPT" to ("ALLOW" to "ICMPv6 control traffic"),
            "-A POCKETUFW_IN -m conntrack --ctstate INVALID -j DROP" to ("DROP" to "Invalid packets"),
            "-A POCKETUFW_IN -p udp -m udp --sport 67 --dport 68 -j ACCEPT" to ("ALLOW" to "DHCP replies"),
            "-A POCKETUFW_IN -p udp -m udp --sport 547 --dport 546 -j ACCEPT" to ("ALLOW" to "DHCPv6 replies"),
            "-A POCKETUFW_IN -d 224.0.0.251/32 -p udp -m udp --dport 5353 -j ACCEPT" to ("ALLOW" to "Multicast DNS"),
            "-A POCKETUFW_IN -d ff02::fb/128 -p udp -m udp --dport 5353 -j ACCEPT" to ("ALLOW" to "Multicast DNS"),
            "-A POCKETUFW_IN -p esp -j ACCEPT" to ("ALLOW" to "ESP / IPsec"),
            "-A POCKETUFW_IN -j POCKETUFW_TS" to ("CHECK" to "VPN listener exceptions"),
            "-A POCKETUFW_IN -j DROP" to ("DROP" to "Other incoming packets"),
            "-A POCKETUFW_TS -p udp -m udp --dport 46867 -j ACCEPT" to ("ALLOW" to "VPN UDP exception, port 46867"),
        )
        for ((rule, description) in expected) assertEquals(rule, description, describeRule(rule))
    }

    @Test fun everyRuleTheFixturesRenderHasAPlainDescription() {
        val report = sampleReport()
        for (rule in report.ipv4.inbound + report.ipv6.inbound + report.ipv4.vpnExceptions + report.ipv6.vpnExceptions) {
            assertNotEquals(rule, rule, describeRule(rule).second)
        }
    }

    @Test fun aChangedTargetOrDestinationFallsThroughToTheRawRule() {
        val expected = mapOf(
            "-A POCKETUFW_IN -p icmp -j DROP" to "DROP",
            "-A POCKETUFW_IN -p ipv6-icmp -j REJECT --reject-with icmp6-port-unreachable" to "REJECT",
            "-A POCKETUFW_IN -p udp -m udp --dport 5353 -j ACCEPT" to "ALLOW",
            "-A POCKETUFW_IN -d 192.0.2.1/32 -p udp -m udp --dport 5353 -j ACCEPT" to "ALLOW",
            "-A POCKETUFW_IN -m conntrack --ctstate RELATED,ESTABLISHED -j DROP" to "DROP",
            "-A POCKETUFW_IN -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT" to "ALLOW",
            "-A POCKETUFW_IN -m conntrack --ctstate INVALID -j ACCEPT" to "ALLOW",
            "-A POCKETUFW_IN -p udp -m udp --sport 67 --dport 68 -j DROP" to "DROP",
            "-A POCKETUFW_IN -s 203.0.113.9/32 -p udp -m udp --sport 67 --dport 68 -j ACCEPT" to "ALLOW",
            "-A POCKETUFW_IN -p esp -j DROP" to "DROP",
            "-A POCKETUFW_IN -p tcp -m tcp --dport 22 -j ACCEPT" to "ALLOW",
            "-A POCKETUFW_IN -p tcp -m tcp --dport 22 -j DROP" to "DROP",
            "-A POCKETUFW_IN -s 203.0.113.9/32 -j DROP" to "DROP",
            "-A POCKETUFW_IN -i eth0 -j POCKETUFW_TS" to "POCKETUFW_TS",
            "-A POCKETUFW_TS -p tcp -m tcp --dport 22 -j ACCEPT" to "ALLOW",
            "-A POCKETUFW_TS -p udp -m udp --dport 46867 -j DROP" to "DROP",
            "-A POCKETUFW_IN -p tcp -m tcp --dport 12345 -j RETURN" to "RETURN",
            "-A POCKETUFW_IN -p tcp" to "RULE",
            "-A INPUT -i wlan0 -j ACCEPT" to "ALLOW",
        )
        for ((rule, action) in expected) assertEquals(rule, action to rule, describeRule(rule))
    }

    @Test fun aDiagnosticProbeIsNeverCalledAVerdict() {
        val probe = "-A POCKETUFW_IN -m limit --limit 1/sec -j NFLOG --nflog-prefix probe"
        assertEquals("LOG" to "Temporary diagnostic probe (non-verdict)", describeRule(probe))
        assertEquals("LOG" to "Temporary diagnostic probe (non-verdict)", describeRule("-A POCKETUFW_IN -j NFLOG"))
    }

    @Test fun aTargetNamedInACommentIsNotTheTarget() {
        val rule = "-A POCKETUFW_IN -m comment --comment \"never -j ACCEPT\" -j DROP"
        assertEquals("DROP" to rule, describeRule(rule))
    }
}
