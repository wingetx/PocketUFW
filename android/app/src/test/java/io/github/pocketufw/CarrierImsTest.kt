package io.github.pocketufw

import org.junit.Assert.assertEquals
import org.junit.Test

/** Only Android's own record can make an uncovered interface read as carrier calling. */
class CarrierImsTest {
    private fun ims(name: String?) = NetworkFacts(name, cellular = true, vpn = false, ims = true, internet = false, notRestricted = false)

    @Test fun restrictedCellularImsWithoutInternetIsIdentified() {
        assertEquals(setOf("ipsec995"), carrierImsInterfaces(listOf(ims("ipsec995"))))
    }

    @Test fun anyMissingOrContradictingFactLeavesItUnidentified() {
        for (facts in listOf(
            ims("ipsec995").copy(cellular = false),      // Wi-Fi or other transport
            ims("ipsec995").copy(vpn = true),            // an app's VPN, even if it claims IMS
            ims("ipsec995").copy(ims = false),           // an ordinary cellular network
            ims("ipsec995").copy(internet = true),       // general data, not just calling
            ims("ipsec995").copy(notRestricted = true),  // usable by ordinary apps
            ims(null), ims(""), ims("bad name"), ims("ipsec-name-too-long")))
            assertEquals(facts.toString(), emptySet<String>(), carrierImsInterfaces(listOf(facts)))
    }

    @Test fun anotherRecordNamingTheSameInterfaceVetoesIt() {
        val vpnSameName = ims("ipsec995").copy(vpn = true, ims = false, cellular = false)
        assertEquals(emptySet<String>(), carrierImsInterfaces(listOf(ims("ipsec995"), vpnSameName)))
        assertEquals(setOf("ipsec1"), carrierImsInterfaces(listOf(ims("ipsec1"), vpnSameName)))
    }

    @Test fun evidenceOnlyDescribesInterfacesAlreadyListedAsUncovered() {
        val dashboard = FirewallClient.Dashboard(FirewallClient.Snapshot(uncoveredInterfaces = listOf("ipsec995", "tun1")))
        assertEquals(setOf("ipsec995"), dashboard.withCarrierIms(setOf("ipsec995", "ipsec4")).snapshot.carrierImsInterfaces)
        // Coverage itself is untouched.
        assertEquals(listOf("ipsec995", "tun1"), dashboard.withCarrierIms(setOf("ipsec995")).snapshot.uncoveredInterfaces)
        assertEquals(emptySet<String>(), dashboard.withCarrierIms(emptySet()).snapshot.carrierImsInterfaces)
    }
}
