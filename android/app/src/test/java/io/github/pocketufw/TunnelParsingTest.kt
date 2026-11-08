package io.github.pocketufw

import io.github.pocketufw.FirewallClient.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class TunnelParsingTest {
    private val client by lazy { FirewallClient(RuntimeEnvironment.getApplication(),
        shell = { _, _ -> throw AssertionError("No root during parsing") }) }
    private val counters = listOf("ipv4_tunnel_blocked=1", "ipv6_tunnel_blocked=2",
        "ipv4_tunnel_blocked_bytes=3", "ipv6_tunnel_blocked_bytes=4",
        "ipv4_tunnel_established_replies=5", "ipv6_tunnel_established_replies=6",
        "ipv4_tunnel_tailnet=7", "ipv6_tunnel_tailnet=8")
    private fun output(values: List<String> = counters) = bridgeOutput() +
        "\ntunnel_filter=ON\ntailnet_trust=PINNED_DESTINATIONS\n" + values.joinToString("\n")
    private fun parse(text: String, exit: Int = 0) = client.dashboardFromOutput(exit, text, false)

    @Test fun allTunnelCountersRetainTheirFamilyAndMeaning() {
        val activity = parse(output()).activity!!
        assertTrue(activity.measured)
        assertEquals(TunnelCounters(1, 2, 3, 4, 5, 6, 7, 8), activity.tunnel)
        assertEquals(11L, activity.ipv4Blocked)
        assertEquals(66L, activity.ipv6Replies)
    }

    @Test fun everyMissingMalformedOrOverflowedTunnelCounterRefusesTheReading() {
        for (line in counters) for (bad in listOf(null, "-1", "bad", "", "18446744073709551615")) {
            val values = counters - line + listOfNotNull(bad?.let { line.substringBefore('=') + "=" + it })
            val activity = parse(output(values)).activity!!
            assertFalse("$line/$bad", activity.measured)
            assertNull(activity.tunnel)
        }
    }

    @Test fun offUnknownAndFailedRootNeverInventTunnelMeasurements() {
        for (suffix in listOf("", "\ntunnel_filter=OFF", "\ntunnel_filter=UNKNOWN")) {
            assertNull(parse(bridgeOutput() + suffix).activity!!.tunnel)
        }
        assertNull(parse(output(), 124).activity)
        assertNull(parse(output() + "\ntailnet_wireguard=CONFLICT").activity)
        // The lightweight OFF reading has no pin_report / tailnet_trust line.
        assertEquals(TunnelMode.OFF, parse(bridgeOutput() + "\ntunnel_filter=OFF").activity!!.tunnelMode)
    }

    @Test fun physicalVerdictIsIndependentAndRequiresRootEvidence() {
        val d = bridgeOutput(state = "DEGRADED") + "\nphysical_state=ACTIVE\ntunnel_filter=DEGRADED"
        assertEquals(PhysicalFilter.ACTIVE, parse(d).snapshot.physicalFilter)
        assertEquals(Protection.DEGRADED, parse(d).snapshot.protection)
        assertEquals(TunnelFilter.DEGRADED, parse(d).snapshot.tunnelFilter)
        assertEquals(PhysicalFilter.UNKNOWN, parse(d, 75).snapshot.physicalFilter)
        assertEquals(PhysicalFilter.UNKNOWN, parse(bridgeOutput()).snapshot.physicalFilter)
        assertEquals(PhysicalFilter.DEGRADED, parse(d + "\nphysical_state=DEGRADED").snapshot.physicalFilter)
    }

    @Test fun totalsDoNotWrapOrTurnMissingMeasurementsIntoZero() {
        assertNull(counterSum(Long.MAX_VALUE, 1))
        assertNull(counterSum(null, 0))
        assertEquals(0L, counterSum(0, 0))
        assertNull(sampleActivity().copy(ipv4Blocked = Long.MAX_VALUE, ipv6Blocked = 1).totalBlocked)
    }
}
