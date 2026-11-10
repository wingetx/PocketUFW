package io.github.pocketufw

import org.junit.Assert.*
import org.junit.Test

internal fun insightsFixture(packets: List<String> = listOf("P|4|F|192.168.1.1|17|1900|49000"),
                             extra: String = "") = "PUFW_INSIGHTS_V1\ncleanup=verified\nstate=ACTIVE\ntunnel=${if (packets.any { it.startsWith("T|") }) 1 else 0}\nelapsed_ms=10000\nrecords=${packets.size}\nunreadable=0\nunrelated=0\nloss=0\n" +
    packets.joinToString("") { "packet=$it\n" } + extra + "end=verified\n"

class InsightsTest {
    @Test fun factsAndGuessesAreSeparateAndNoHistoricalCoverageIsInvented() {
        val sample = parseInsights(ShellResult(0, insightsFixture())).sample!!
        assertEquals(1, sample.packets.size)
        assertEquals(DiscoveryCategory.SSDP, sample.packets.single().category)
        assertEquals("Possible SSDP / UPnP", sample.packets.single().category.label)
        assertEquals("UDP port 1900", sample.packets.single().category.observation)
        assertEquals("Physical", sample.packets.single().scope)
        assertEquals(10000, sample.elapsedMs)
        assertFalse(sample.tunnelSampled)
    }
    @Test fun recognizesBothDirectionsAndDoesNotGuessFromMissingPortsOrTcp() {
        for ((port, category) in listOf(1900 to DiscoveryCategory.SSDP, 5353 to DiscoveryCategory.MDNS,
            5355 to DiscoveryCategory.LLMNR, 3702 to DiscoveryCategory.WSD, 137 to DiscoveryCategory.NETBIOS)) {
            val packets = listOf("P|4|F|10.0.0.1|17|$port|40000", "T|6|I|fe80::1|17|40000|$port")
            assertTrue(parseInsights(ShellResult(0, insightsFixture(packets))).sample!!.packets.all { it.category == category })
        }
        val sample = parseInsights(ShellResult(0, insightsFixture(listOf("P|4|I|10.0.0.1|6|1900|40000", "T|6|F|fe80::1|44|-1|-1")))).sample!!
        assertTrue(sample.packets.all { it.category == DiscoveryCategory.OTHER })
    }
    @Test fun failedIncompleteDuplicateAndUnverifiedReportsAreNeverAccepted() {
        val good = insightsFixture()
        for (bad in listOf(good.replace("end=verified\n", ""), good.replace("cleanup=verified", "cleanup=failed"),
            good.replace("state=ACTIVE", "state=DEGRADED"), good.replace("records=1", "records=2"),
            good.replace("elapsed_ms=10000", "elapsed_ms=10001"), insightsFixture(extra = "records=1\n"),
            insightsFixture(listOf("P|4|F|host.example|17|1900|1")), insightsFixture(listOf("P|4|F|10.0.0.1|17|65536|1")),
            insightsFixture(listOf("T|6|F|::::|17|1900|1")),
            insightsFixture(listOf("T|6|F|fe80::1|17|1900|1")).replace("tunnel=1", "tunnel=0"),
            good + "unexpected\n", good.repeat(3000))) {
            assertNull(parseInsights(ShellResult(0, bad)).sample)
        }
        assertNull(parseInsights(ShellResult(1, good)).sample)
    }
    @Test fun zeroAndLossAreHonestAndCapIsEnforced() {
        assertEquals(0, parseInsights(ShellResult(0, insightsFixture(emptyList()))).sample!!.packets.size)
        val capped = List(256) { "T|6|F|fd7a:115c:a1e0::1|17|1900|40000" }
        val sample = parseInsights(ShellResult(0, insightsFixture(capped).replace("loss=0", "loss=1"))).sample!!
        assertTrue(sample.hitLimit); assertTrue(sample.loss)
        assertEquals(256, sample.sources.single().value)
        assertNotNull(parseInsights(ShellResult(0, insightsFixture(listOf("T|6|F|::ffff:192.0.2.1|17|1900|1")))).sample)
        assertNull(parseInsights(ShellResult(0, insightsFixture(capped + capped.first()))).sample)
    }
    @Test fun recoveryRequiresCompleteIndependentVerification() {
        val text = "PUFW_INSIGHTS_RECOVERED_V1\ncleanup=verified\nstate=ACTIVE\nend=verified\n"
        assertTrue(parseInsights(ShellResult(0, text), true).recovered)
        assertFalse(parseInsights(ShellResult(1, text), true).recovered)
        assertFalse(parseInsights(ShellResult(0, text.replace("ACTIVE", "INACTIVE")), true).recovered)
        assertFalse(parseInsights(ShellResult(0, insightsFixture()), true).recovered)
    }
    @Test fun cancelledBeforeStartupNeverRequestsRoot() {
        val request = InsightsRequest(); request.cancel()
        assertFalse(request.run("must never execute").succeeded)
    }
}
