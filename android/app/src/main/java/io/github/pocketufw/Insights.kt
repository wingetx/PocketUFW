package io.github.pocketufw

import java.util.concurrent.atomic.AtomicBoolean

/** One user gesture, one bounded root process. Closing stdin requests cleanup, never kills it. */
internal class InsightsRequest {
    private val cancelled = AtomicBoolean(false)
    private var process: Process? = null
    val isCancelled: Boolean get() = cancelled.get()
    @Synchronized fun cancel() {
        cancelled.set(true)
        runCatching { process?.outputStream?.close() }
    }
    fun run(command: String): ShellResult {
        val started = synchronized(this) {
            if (isCancelled) return ShellResult(1, "error=Sampling cancelled before startup.")
            ProcessBuilder("su", "-c", command).redirectErrorStream(true).start().also { process = it }
        }
        return try { collectRootOutput(started, 120) }
        finally { synchronized(this) { process = null }; runCatching { started.outputStream.close() } }
    }
}

internal data class DropObservation(
    val scope: String, val family: Int, val reason: String, val source: String,
    val protocol: Int, val sourcePort: Int?, val destinationPort: Int?
) {
    val protocolLabel: String get() = when (protocol) {
        6 -> "TCP"; 17 -> "UDP"; 1 -> "ICMP"; 58 -> "ICMPv6"; 50 -> "ESP"; else -> "IP protocol $protocol"
    }
    val category: DiscoveryCategory get() = if (protocol != 17) DiscoveryCategory.OTHER else when {
        sourcePort == 1900 || destinationPort == 1900 -> DiscoveryCategory.SSDP
        sourcePort == 5353 || destinationPort == 5353 -> DiscoveryCategory.MDNS
        sourcePort == 5355 || destinationPort == 5355 -> DiscoveryCategory.LLMNR
        sourcePort == 3702 || destinationPort == 3702 -> DiscoveryCategory.WSD
        sourcePort == 137 || destinationPort == 137 || sourcePort == 138 || destinationPort == 138 -> DiscoveryCategory.NETBIOS
        else -> DiscoveryCategory.OTHER
    }
}
internal enum class DiscoveryCategory(val label: String, val observation: String, val explanation: String) {
    SSDP("Possible SSDP / UPnP", "UDP port 1900", "Commonly used to discover routers, media devices and network services. Repeated packets can be routine discovery or responses. Ports alone cannot identify the sender's software."),
    MDNS("Possible mDNS", "UDP port 5353", "Commonly used to find nearby devices and services without a DNS server. These are DROP matches; permitted multicast mDNS and accepted replies are not part of this sample."),
    LLMNR("Possible LLMNR", "UDP port 5355", "Commonly used for name lookup on a local network. A matching port suggests a use; it does not establish intent."),
    WSD("Possible device discovery", "UDP port 3702", "Commonly used by WS-Discovery to find printers and other network devices."),
    NETBIOS("Possible NetBIOS discovery", "UDP port 137 or 138", "Commonly associated with local name and device discovery, including Windows networking."),
    OTHER("Other / unclassified", "No recognized discovery port", "Header metadata alone does not establish why a packet was sent or whether it was harmful. Missing ports can result from fragments, IP options or IPv6 extension headers.")
}
internal data class InsightsSample(
    val packets: List<DropObservation>, val elapsedMs: Int, val records: Int,
    val unreadable: Int, val unrelated: Int, val loss: Boolean, val checkedAt: Long, val tunnelSampled: Boolean
) {
    val hitLimit get() = records == 256
    val sources get() = packets.groupingBy { it.source to it.protocolLabel }.eachCount()
        .entries.sortedWith(compareByDescending<Map.Entry<Pair<String, String>, Int>> { it.value }
            .thenBy { it.key.first }.thenBy { it.key.second })
}
internal data class InsightsResult(val sample: InsightsSample? = null, val recovered: Boolean = false, val error: String? = null)

internal fun hasInsightsResidue(report: FirewallClient.KernelReport?): Boolean = report?.let {
    (it.ipv4.inbound + it.ipv4.tunnel + it.ipv6.inbound + it.ipv6.tunnel).any { row -> row.contains("PUFW_APP1:") }
} == true

/** Validate numeric addresses without invoking a resolver, including mapped IPv6. */
private fun numericSource(address: String, family: Int): Boolean {
    fun ipv4(value: String) = value.split('.').let { groups ->
        groups.size == 4 && groups.all { part -> part.length in 1..3 &&
            part.all { it in '0'..'9' } && part.toIntOrNull() in 0..255 }
    }
    if (family == 4) return ipv4(address)
    if (address.length !in 2..45 || !address.contains(':')) return false
    val hex = if (address.contains('.')) {
        val split = address.lastIndexOf(':')
        if (!ipv4(address.substring(split + 1))) return false
        address.substring(0, split + 1) + "0:0"
    } else address
    fun groups(part: String): List<String> = if (part.isEmpty()) emptyList() else part.split(':')
    val halves = hex.split("::")
    if (halves.size > 2) return false
    val parts = halves.flatMap { groups(it) }
    return parts.all { it.length in 1..4 && it.all { c -> c in "0123456789abcdef" } } &&
        if (halves.size == 2) parts.size < 8 else parts.size == 8
}

/** Strict complete-record protocol: incomplete/overflow output can never become a successful sample. */
internal fun parseInsights(result: ShellResult, recovery: Boolean = false, at: Long = System.currentTimeMillis()): InsightsResult {
    if (!result.succeeded) return InsightsResult(error = result.text.lineSequence().firstOrNull { it.startsWith("error=") }
        ?.removePrefix("error=")?.take(400)
        ?: "Insights could not finish. Recheck status and use Recover Insights probes if cleanup is uncertain.")
    return try {
        require(result.text.length <= ROOT_OUTPUT_LIMIT)
        val lines = result.text.trimEnd('\n').split('\n')
        require(lines.first() == if (recovery) "PUFW_INSIGHTS_RECOVERED_V1" else "PUFW_INSIGHTS_V1")
        require(lines.last() == "end=verified")
        val fields = mutableMapOf<String, String>()
        val packets = mutableListOf<DropObservation>()
        for (line in lines.drop(1)) {
            val parts = line.split('=', limit = 2); require(parts.size == 2)
            if (parts[0] == "packet") {
                require(!recovery && packets.size < 256)
                val p = parts[1].split('|'); require(p.size == 7)
                val family = p[1].toInt(); require(family in listOf(4, 6))
                require(p[0] in listOf("P", "T") && p[2] in listOf("I", "F"))
                // Numeric only, never resolve a hostname or consult the network.
                require(numericSource(p[3], family))
                val protocol = p[4].toInt(); require(protocol in 0..255)
                fun port(s: String): Int? = s.toInt().also { require(it in -1..65535) }.takeIf { it >= 0 }
                val sourcePort = port(p[5]); val destinationPort = port(p[6])
                require((sourcePort == null) == (destinationPort == null))
                require(sourcePort == null || protocol in listOf(6, 17))
                packets += DropObservation(if (p[0] == "P") "Physical" else "Tunnel", family,
                    if (p[2] == "I") "Invalid state" else "Final DROP", p[3], protocol, sourcePort, destinationPort)
            } else require(fields.put(parts[0], parts[1]) == null)
        }
        require(fields["cleanup"] == "verified" && fields["state"] == "ACTIVE" && fields["end"] == "verified")
        if (recovery) {
            require(fields.keys == setOf("cleanup", "state", "end"))
            InsightsResult(recovered = true)
        } else {
            require(fields.keys == setOf("cleanup", "state", "end", "elapsed_ms", "records", "unreadable", "unrelated", "loss", "tunnel"))
            fun number(key: String, max: Int) = fields.getValue(key).toInt().also { require(it in 0..max) }
            val records = number("records", 256); val unreadable = number("unreadable", 256); val unrelated = number("unrelated", 256)
            val tunnel = number("tunnel", 1) == 1
            require(tunnel || packets.none { it.scope == "Tunnel" })
            require(packets.size + unreadable + unrelated == records)
            InsightsResult(sample = InsightsSample(packets, number("elapsed_ms", 10000), records, unreadable, unrelated,
                number("loss", 1) == 1, at, tunnel))
        }
    } catch (_: Exception) { InsightsResult(error = "Insights response was incomplete or invalid. Recheck status; no sample accepted.") }
}
