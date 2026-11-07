package io.github.pocketufw

import io.github.pocketufw.FirewallClient.BootRestore
import io.github.pocketufw.FirewallClient.Protection
import io.github.pocketufw.FirewallClient.UdpConfigMode
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/** Parsing of full bridge output. The shell fails the test if anything tries to use root. */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class FirewallClientParsingTest {
    private val client by lazy {
        FirewallClient(RuntimeEnvironment.getApplication(),
            shell = { _, _ -> throw AssertionError("parsing must not run a root command") })
    }
    private fun parse(text: String, exitCode: Int = 0, vpn: Boolean = false) =
        client.dashboardFromOutput(exitCode, text, vpn)

    // ---- protection state ----

    @Test fun tunnelOnNeedsAnActiveVerifiedSnapshotAndNeverComesFromBootOptIn() {
        assertEquals(FirewallClient.TunnelFilter.ON,
            parse(bridgeOutput() + "\ntunnel_filter=ON").snapshot.tunnelFilter)
        assertEquals(FirewallClient.TunnelFilter.UNKNOWN,
            parse(bridgeOutput(state = "DEGRADED") + "\ntunnel_filter=ON").snapshot.tunnelFilter)
        assertEquals(FirewallClient.TunnelFilter.UNKNOWN,
            parse(bridgeOutput(boot = "ENABLED")).snapshot.tunnelFilter)
        assertEquals(FirewallClient.TunnelFilter.OFF,
            parse(bridgeOutput(boot = "ENABLED") + "\ntunnel_filter=OFF").snapshot.tunnelFilter)
        assertEquals(FirewallClient.TunnelFilter.UNKNOWN,
            parse(bridgeOutput() + "\ntunnel_filter=ON", exitCode = 3).snapshot.tunnelFilter)
    }

    @Test fun everyBridgeStateMapsToItsOwnProtection() {
        val expected = mapOf(
            "ACTIVE" to Protection.ACTIVE,
            "INACTIVE" to Protection.INACTIVE,
            "DEGRADED" to Protection.DEGRADED,
        )
        for ((state, protection) in expected) {
            val snapshot = parse(bridgeOutput(state = state)).snapshot
            assertEquals(state, protection, snapshot.protection)
            assertTrue(state, snapshot.rootReady)
            assertEquals(state, client.protectionDetails(protection), snapshot.details)
        }
    }

    @Test fun anUnrecognisedOrMissingStateIsNeverActiveOrOff() {
        for (state in listOf("UNKNOWN", "active", "", "ON", null)) {
            assertEquals("state=$state", Protection.DEGRADED,
                parse(bridgeOutput(state = state)).snapshot.protection)
        }
    }

    // ---- root ----

    @Test fun rootDeniedIsRootRequired() {
        val denied = parse("root=DENIED", exitCode = 3)
        assertEquals(Protection.ROOT_REQUIRED, denied.snapshot.protection)
        assertFalse(denied.snapshot.rootReady)
        assertEquals(client.protectionDetails(Protection.ROOT_REQUIRED), denied.snapshot.details)
        assertNull(denied.activity)
        assertNull(denied.kernelReport)
    }

    @Test fun suRefusalAndMissingSuAreRootRequired() {
        for ((exit, text) in listOf(1 to "Permission denied", 127 to "Unable to request root: su")) {
            assertEquals(Protection.ROOT_REQUIRED, parse(text, exit).snapshot.protection)
        }
    }

    @Test fun outputWithoutARootGrantIsNotBelievedEvenIfItClaimsActive() {
        val claim = bridgeOutput(state = "ACTIVE").replace("root=GRANTED\n", "")
        assertEquals(Protection.ROOT_REQUIRED, parse(claim).snapshot.protection)
        assertEquals(Protection.ROOT_REQUIRED,
            parse(bridgeOutput(state = "ACTIVE"), exitCode = 5).snapshot.protection)
    }

    @Test fun aTimeoutIsNotMissingRoot() {
        val timedOut = parse("Root command timed out. Check the superuser prompt.", exitCode = 124)
        assertEquals(Protection.DEGRADED, timedOut.snapshot.protection)
        assertFalse(timedOut.snapshot.rootReady)
        assertEquals("A root command timed out and may still finish. Recheck before relying on the firewall.",
            timedOut.snapshot.details)
        assertNull(timedOut.activity)
        assertNull(timedOut.kernelReport)
        assertEquals(BootRestore.UNKNOWN, timedOut.snapshot.bootRestore)
    }

    @Test fun lifecycleContentionIsUnverifiedRatherThanMissingRootOrActive() {
        val result = parse(bridgeOutput(), exitCode = 75)
        assertEquals(Protection.DEGRADED, result.snapshot.protection)
        assertTrue(result.snapshot.rootReady)
        assertNull(result.activity)
        assertNull(result.kernelReport)
    }

    // ---- boot and config ----

    @Test fun everyBootValueMapsToItsOwnState() {
        val expected = mapOf(
            "ENABLED" to BootRestore.ENABLED, "DISABLED" to BootRestore.DISABLED,
            "UNSUPPORTED" to BootRestore.UNSUPPORTED, "DEGRADED" to BootRestore.DEGRADED,
            "CONFLICT" to BootRestore.CONFLICT, "UNKNOWN" to BootRestore.UNKNOWN,
            "STALE" to BootRestore.UNKNOWN, null to BootRestore.UNKNOWN,
        )
        for ((boot, state) in expected) {
            assertEquals("boot=$boot", state, parse(bridgeOutput(boot = boot)).snapshot.bootRestore)
        }
    }

    @Test fun everyConfigModeMapsToItsOwnState() {
        val expected = mapOf(
            "AUTOMATIC" to UdpConfigMode.AUTOMATIC, "COMMITTED" to UdpConfigMode.COMMITTED,
            "DEGRADED" to UdpConfigMode.DEGRADED, "EXPERIMENTAL" to UdpConfigMode.UNKNOWN,
            null to UdpConfigMode.UNKNOWN,
        )
        for ((mode, state) in expected) {
            assertEquals("mode=$mode", state, parse(bridgeOutput(mode = mode)).snapshot.udpConfigMode)
        }
    }

    @Test fun committedPortsAreReadPerFamily() {
        val snapshot = parse(bridgeOutput(mode = "COMMITTED", committed4 = "41641", committed6 = "none")).snapshot
        assertEquals("41641", snapshot.committedUdp4)
        assertEquals("none", snapshot.committedUdp6)
    }

    // ---- counters ----

    @Test fun countersMapToTheirOwnFamilyAndKind() {
        val activity = parse(bridgeOutput()).activity!!
        assertTrue(activity.measured)
        assertEquals(11L, activity.ipv4Blocked)
        assertEquals(22L, activity.ipv6Blocked)
        assertEquals(33L, activity.ipv4Bytes)
        assertEquals(44L, activity.ipv6Bytes)
        assertEquals(55L, activity.ipv4Replies)
        assertEquals(66L, activity.ipv6Replies)
        assertEquals(33L, activity.totalBlocked)
        assertEquals(121L, activity.totalReplies)
        assertNull(activity.error)
    }

    @Test fun aMissingOrMalformedCounterNeverBecomesAZero() {
        for (dropped in SAMPLE_COUNTERS) {
            val key = dropped.substringBefore('=')
            val variants = listOf(
                SAMPLE_COUNTERS - dropped,
                SAMPLE_COUNTERS - dropped + "$key=abc",
                SAMPLE_COUNTERS - dropped + "$key=-5",
                SAMPLE_COUNTERS - dropped + "$key=",
                SAMPLE_COUNTERS - dropped + "$key=99999999999999999999",
            )
            for (counters in variants) {
                val activity = parse(bridgeOutput(counters = counters)).activity!!
                assertFalse("$key: $counters", activity.measured)
                assertNull(activity.totalBlocked)
                assertNull(activity.totalReplies)
                assertEquals("Kernel counters are unavailable or malformed.", activity.error)
            }
        }
    }

    @Test fun onlyAnActiveFirewallHasCounters() {
        for (state in listOf("INACTIVE", "DEGRADED")) {
            assertNull(state, parse(bridgeOutput(state = state)).activity)
        }
    }

    // ---- rule report ----

    @Test fun aCompleteReportIsReadInKernelOrderPerFamily() {
        val report = parse(bridgeOutput()).kernelReport!!
        assertEquals("ACCEPT", report.ipv4.inputPolicy)
        assertEquals(3, report.ipv4.hooks.size)
        assertEquals(8, report.ipv4.inbound.size)
        assertEquals("-A POCKETUFW_IN -p icmp -j ACCEPT", report.ipv4.inbound[1])
        assertEquals("-A POCKETUFW_IN -j DROP", report.ipv4.inbound.last())
        assertEquals("-A POCKETUFW_IN -p ipv6-icmp -j ACCEPT", report.ipv6.inbound[1])
        assertEquals(listOf("-A POCKETUFW_TS -p udp -m udp --dport 46867 -j ACCEPT"), report.ipv4.vpnExceptions)
        assertEquals(listOf("-A POCKETUFW_TS -p udp -m udp --dport 43504 -j ACCEPT"), report.ipv6.vpnExceptions)
    }

    @Test fun anIncompleteOrAlteredReportIsNotPresentedAsProof() {
        assertNull(parse(bridgeOutput(reportStatus = "UNAVAILABLE")).kernelReport)
        val good = bridgeOutput()
        assertNotNull(parse(good).kernelReport)
        val broken = mapOf(
            "no READY marker" to good.replace("rules_report=READY", ""),
            "no policy" to good.replace("input_policy6=ACCEPT\n", ""),
            "odd policy" to good.replace("input_policy4=ACCEPT", "input_policy4=RETURN"),
            "no hooks" to good.lines().filterNot { it.startsWith("hook4_") }.joinToString("\n"),
            "no inbound" to good.lines().filterNot { it.startsWith("main6_") }.joinToString("\n"),
            "foreign hook" to good.replace("hook4_01=-A INPUT", "hook4_01=-A OUTPUT"),
            "foreign inbound" to good.replace("main4_01=-A POCKETUFW_IN", "main4_01=-A INPUT"),
            "foreign vpn" to good.replace("vpn4_01=-A POCKETUFW_TS", "vpn4_01=-A INPUT"),
        )
        for ((name, output) in broken) assertNull(name, parse(output).kernelReport)
    }

    @Test fun aReportWithTheTunnelFilterKeepsItsRulesVisibleInKernelOrder() {
        val good = bridgeOutput().replace("rules_report=READY", listOf(
            "hook4_04=-A INPUT -i tun+ -m comment --comment PocketUFW-VPN -j POCKETUFW_VPN",
            "main4_09=-A POCKETUFW_VPN -s 100.64.0.0/10 -d 100.64.0.0/10 -i tun+ -j ACCEPT",
            "main4_10=-A POCKETUFW_VPN -j DROP",
            "rules_report=READY",
        ).joinToString("\n"))
        val family = parse(good).kernelReport!!.ipv4
        assertEquals("tun+", family.hooks.last().substringAfter(" -i ").substringBefore(' '))
        assertEquals("-A POCKETUFW_VPN -j DROP", family.inbound[9])
        assertEquals(10, family.inbound.size)
        // A rule from any other chain still voids the whole report.
        assertNull(parse(good.replace("main4_09=-A POCKETUFW_VPN", "main4_09=-A POCKETUFW_OTHER")).kernelReport)
    }

    @Test fun aReportWithoutRootIsIgnored() {
        assertNull(parse(bridgeOutput(), exitCode = 5).kernelReport)
    }

    // ---- disclosure ----

    @Test fun vpnInterfaceComesOnlyFromARootedBridgeAnswer() {
        val owned = "root=GRANTED\nstate=ACTIVE\nvpn_owner=ch.protonvpn.android\nvpn_iface=tun0"
        assertEquals("tun0", parse(owned).snapshot.vpnInterface)
        assertNull(parse("root=GRANTED\nstate=ACTIVE\nvpn_iface=").snapshot.vpnInterface)
        assertNull(parse("root=GRANTED\nstate=ACTIVE").snapshot.vpnInterface)
        assertNull(parse("state=ACTIVE\nvpn_iface=tun0").snapshot.vpnInterface)
    }

    @Test fun uncoveredInterfacesAreReadFromTheBridge() {
        assertEquals(listOf("eth0", "usb0"), parse(bridgeOutput(uncovered = "eth0,usb0")).snapshot.uncoveredInterfaces)
        assertEquals(listOf("eth0", "usb0"), parse(bridgeOutput(uncovered = " eth0 , usb0, ")).snapshot.uncoveredInterfaces)
        assertEquals(emptyList<String>(), parse(bridgeOutput(uncovered = "")).snapshot.uncoveredInterfaces)
        assertEquals(emptyList<String>(), parse(bridgeOutput(uncovered = null)).snapshot.uncoveredInterfaces)
    }

    @Test fun bypassRulesAreReadPerFamilyInOrder() {
        val first = "-A INPUT -i wlan0 -j ACCEPT"
        val second = "-A INPUT -s 10.0.0.0/8 -j ACCEPT"
        val six = "-A INPUT -i wlan0 -p tcp -m tcp --dport 22 -j ACCEPT"
        val report = parse(bridgeOutput(bypass4 = listOf(first, second), bypass6 = listOf(six))).kernelReport!!
        assertEquals(listOf(first, second), report.ipv4.bypass)
        assertEquals(listOf(six), report.ipv6.bypass)
        assertEquals(emptyList<String>(), parse(bridgeOutput()).kernelReport!!.ipv4.bypass)
    }

    @Test fun aBypassLineOutsideInputMakesTheReportIncomplete() {
        assertNull(parse(bridgeOutput(bypass4 = listOf("-A OUTPUT -j ACCEPT"))).kernelReport)
    }

    @Test fun disclosureDoesNotChangeTheStateItself() {
        val snapshot = parse(bridgeOutput(uncovered = "eth0", bypass4 = listOf("-A INPUT -i eth0 -j ACCEPT"))).snapshot
        assertEquals(Protection.ACTIVE, snapshot.protection)
    }

    // ---- VPN ----

    @Test fun vpnRowUsesWhicheverSourceKnows() {
        data class Case(val appSees: Boolean, val owner: String, val active: Boolean, val label: String?)
        val cases = listOf(
            Case(false, "", false, null),
            Case(true, "", true, "Unrecognized VPN"),
            Case(false, "ch.protonvpn.android", true, "Proton VPN"),
            Case(true, "com.tailscale.ipn", true, "Connected via Tailscale"),
            Case(false, "com.example.other", true, "Unrecognized VPN"),
        )
        for (case in cases) {
            val snapshot = parse(bridgeOutput(vpnOwner = case.owner), vpn = case.appSees).snapshot
            assertEquals("$case", case.active, snapshot.vpnActive)
            assertEquals("$case", case.label, snapshot.vpnProvider)
        }
    }

    @Test fun vpnStillReportedWhenRootIsDenied() {
        val snapshot = parse("root=DENIED", exitCode = 3, vpn = true).snapshot
        assertTrue(snapshot.vpnActive)
        assertEquals("Unrecognized VPN", snapshot.vpnProvider)
    }

    // ---- wording ----

    @Test fun protectionDetailsClaimOnlyWhatTheEngineChecks() {
        assertEquals("IPv4 and IPv6 rules and hooks verified.", client.protectionDetails(Protection.ACTIVE))
        assertEquals("PocketUFW has not installed any firewall chains.", client.protectionDetails(Protection.INACTIVE))
        assertEquals("Firewall state could not be verified. Some rules may be installed. Don't assume " +
            "packets are being filtered, or that they aren't.", client.protectionDetails(Protection.DEGRADED))
    }
}
