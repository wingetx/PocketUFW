package io.github.pocketufw

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.net.NetworkInfo
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowNetwork
import org.robolectric.shadows.ShadowNetworkCapabilities
import org.robolectric.shadows.ShadowNetworkInfo

/** A real inspection reads Android's network records after the root inventory. No real su runs. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class CarrierImsWiringTest {
    private val app: Context get() = RuntimeEnvironment.getApplication()
    private val manager get() = app.getSystemService(ConnectivityManager::class.java)

    private fun network(id: Int, iface: String, transport: Int, vararg add: Int, remove: List<Int> = emptyList()) {
        val network = ShadowNetwork.newInstance(id)
        shadowOf(manager).addNetwork(network, ShadowNetworkInfo.newInstance(NetworkInfo.DetailedState.CONNECTED,
            ConnectivityManager.TYPE_MOBILE, 0, true, NetworkInfo.State.CONNECTED))
        val caps = ShadowNetworkCapabilities.newInstance()
        shadowOf(caps).addTransportType(transport)
        add.forEach { shadowOf(caps).addCapability(it) }
        remove.forEach { shadowOf(caps).removeCapability(it) }
        shadowOf(manager).setNetworkCapabilities(network, caps)
        shadowOf(manager).setLinkProperties(network, LinkProperties().apply { interfaceName = iface })
    }

    private fun inspect(uncovered: String): FirewallClient.Snapshot {
        val shell = FakeShell().apply {
            respond = { ShellResult(0, "root=GRANTED\nstate=ACTIVE\ninterface_report=READY\nuncovered_ifaces=$uncovered\n") }
        }
        return FirewallClient(app, shell = shell).inspectDashboard().snapshot
    }

    private val restricted = listOf(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED, NetworkCapabilities.NET_CAPABILITY_INTERNET)

    @Test fun onlyTheAndroidIdentifiedImsInterfaceIsDescribedAsCarrierCalling() {
        shadowOf(manager).clearAllNetworks()
        network(995, "ipsec995", NetworkCapabilities.TRANSPORT_CELLULAR, NetworkCapabilities.NET_CAPABILITY_IMS, remove = restricted)
        // An app VPN on an ipsec interface claiming IMS is not carrier calling.
        network(7, "ipsec7", NetworkCapabilities.TRANSPORT_VPN, NetworkCapabilities.NET_CAPABILITY_IMS, remove = restricted)
        val snapshot = inspect("ipsec995,ipsec7")
        assertEquals(listOf("ipsec995", "ipsec7"), snapshot.uncoveredInterfaces)
        assertEquals(setOf("ipsec995"), snapshot.carrierImsInterfaces)
    }

    @Test fun noAndroidRecordMeansNoCarrierDescription() {
        shadowOf(manager).clearAllNetworks()
        val snapshot = inspect("ipsec995")
        assertEquals(listOf("ipsec995"), snapshot.uncoveredInterfaces)
        assertEquals(emptySet<String>(), snapshot.carrierImsInterfaces)
    }
}
