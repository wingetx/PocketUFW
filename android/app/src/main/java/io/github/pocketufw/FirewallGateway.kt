package io.github.pocketufw

/**
 * What the Compose UI asks of the firewall. [FirewallClient] is the only
 * production implementation; the interface exists so UI tests can run the real
 * screens against a fake without root. It adds no capability of its own.
 */
internal interface FirewallGateway {
    fun inspectDrops(request: InsightsRequest, recovery: Boolean = false): InsightsResult
    fun inspectDashboard(): FirewallClient.Dashboard
    fun refreshCounterActivity(): FirewallClient.RuleActivity
    fun changeProtection(activate: Boolean): FirewallClient.Operation
    fun enableTunnelProtection(mode: FirewallClient.TunnelMode): FirewallClient.Operation
    fun refreshTunnelHooks(): FirewallClient.Operation
    fun removeTunnelRules(): FirewallClient.Operation
    fun removePartialRules(): FirewallClient.Operation
    fun prepareUninstall(): FirewallClient.Operation
    fun changeBootRestoration(enabled: Boolean): FirewallClient.Operation
    fun refreshVerifiedPorts(): FirewallClient.Operation
    fun resetCounters(): FirewallClient.Operation
    fun updateUdpExceptions(ipv4: String, ipv6: String, committed: Boolean): FirewallClient.Operation
    fun restoreAutomaticUdpExceptions(): FirewallClient.Operation
}
