package io.github.pocketufw

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * What Android's own record says about one network. Only booleans and the interface name are
 * kept: no addresses, subscription or carrier identity.
 */
internal data class NetworkFacts(
    val interfaceName: String?, val cellular: Boolean, val vpn: Boolean,
    val ims: Boolean, val internet: Boolean, val notRestricted: Boolean
)

/**
 * Interfaces Android positively identifies as the carrier's calling (IMS) network: cellular,
 * IMS-capable, restricted from ordinary apps, no internet capability and not a VPN. A name such
 * as `ipsec995` proves nothing alone; any other record naming the same interface vetoes it.
 * This only changes how an uncovered interface is described. It never makes it covered.
 */
internal fun carrierImsInterfaces(networks: List<NetworkFacts>): Set<String> {
    val valid = Regex("[A-Za-z0-9_.-]{1,15}")
    fun qualifies(n: NetworkFacts) = n.cellular && n.ims && !n.vpn && !n.internet && !n.notRestricted
    val named = networks.filter { it.interfaceName?.matches(valid) == true }
    val vetoed = named.filterNot(::qualifies).mapNotNull { it.interfaceName }.toSet()
    return named.filter(::qualifies).mapNotNull { it.interfaceName }.filterNot { it in vetoed }.toSet()
}

/** Only interfaces the root inventory already lists as uncovered can be described this way. */
internal fun FirewallClient.Dashboard.withCarrierIms(identified: Set<String>): FirewallClient.Dashboard =
    copy(snapshot = snapshot.copy(carrierImsInterfaces = snapshot.uncoveredInterfaces.filter { it in identified }.toSet()))

/** Exit status for "we stopped waiting". The root shell itself may still be running. */
private const val ROOT_TIMEOUT_EXIT = 124
private const val LIFECYCLE_BUSY_EXIT = 75
internal const val ROOT_OUTPUT_LIMIT = 64 * 1024
private const val ROOT_OUTPUT_INCOMPLETE_EXIT = 122
private const val ROOT_OUTPUT_DETAILS = "Root response was incomplete or too large to verify. Recheck live firewall state."

/** What one privileged command returned. */
internal data class ShellResult(val exitCode: Int, val text: String) {
    val succeeded: Boolean get() = exitCode == 0
    val timedOut: Boolean get() = exitCode == ROOT_TIMEOUT_EXIT
}

/** Runs one privileged command. It exists so JVM tests never start a real `su`. */
internal fun interface RootShell {
    fun run(command: String, maxSeconds: Long): ShellResult
}

private object SuShell : RootShell {
    override fun run(command: String, maxSeconds: Long): ShellResult {
        val process = try {
            ProcessBuilder("su", "-c", command).redirectErrorStream(true).start()
        } catch (e: Exception) {
            return ShellResult(127, "Unable to request root: ${e.message ?: "su unavailable"}")
        }
        return collectRootOutput(process, maxSeconds)
    }
}

/**
 * Drain while the command runs, retaining at most 64 KiB (the bounded report is
 * under 24 KiB). Overflow is discarded and explicitly rejected, never truncated
 * into a successful response. Only read available bytes: a descendant holding
 * stdout open cannot turn an exited command into an unbounded read/reader thread.
 * Short waits belong to this one IO call; there is no service or persistent poller.
 */
internal fun collectRootOutput(process: Process, maxSeconds: Long): ShellResult {
    val started = System.nanoTime()
    val budget = TimeUnit.SECONDS.toNanos(maxSeconds)
    val output = ByteArrayOutputStream(ROOT_OUTPUT_LIMIT)
    val buffer = ByteArray(4096)
    var overflow = false
    try {
        while (true) {
            if (Thread.currentThread().isInterrupted) throw InterruptedException()
            val remaining = budget - (System.nanoTime() - started)
            if (remaining <= 0) {
                process.destroyForcibly()
                return ShellResult(ROOT_TIMEOUT_EXIT, "Root command timed out. Check the superuser prompt.")
            }
            val available = process.inputStream.available()
            if (available > 0) {
                val read = process.inputStream.read(buffer, 0, minOf(available, buffer.size))
                if (read > 0) {
                    val retain = minOf(read, ROOT_OUTPUT_LIMIT - output.size())
                    output.write(buffer, 0, retain)
                    if (read > retain) overflow = true
                }
            } else if (!process.isAlive) {
                return if (overflow) ShellResult(ROOT_OUTPUT_INCOMPLETE_EXIT, ROOT_OUTPUT_DETAILS)
                    else ShellResult(process.exitValue(), output.toString("UTF-8"))
            } else {
                process.waitFor(minOf(remaining, TimeUnit.MILLISECONDS.toNanos(10)), TimeUnit.NANOSECONDS)
            }
        }
    } catch (e: Exception) {
        process.destroyForcibly()
        if (e is InterruptedException) Thread.currentThread().interrupt()
        return ShellResult(ROOT_OUTPUT_INCOMPLETE_EXIT, ROOT_OUTPUT_DETAILS)
    } finally {
        runCatching { process.inputStream.close() }
        runCatching { process.errorStream.close() }
        runCatching { process.outputStream.close() }
    }
}

/**
 * Tiny boundary around Magisk/KernelSU/APatch's standard "su -c" interface.
 * No network access or continuously running service. The opt-in Magisk
 * boot hook lives in root-only storage under /data/adb.
 * Shell scripts are copied from APK assets into private app storage.
 */
internal class FirewallClient(
    private val context: Context,
    private val source: String = TileStatusStore.SOURCE_APP,
    private val shell: RootShell = SuShell,
) : FirewallGateway {
    /** The sentence behind each state. Unknown states must not read as "off". */
    fun protectionDetails(protection: Protection): String = when (protection) {
        Protection.ACTIVE -> "IPv4 and IPv6 rules and hooks verified."
        Protection.INACTIVE -> "PocketUFW has not installed any firewall chains."
        Protection.ROOT_REQUIRED ->
            "PocketUFW couldn't get root access, so it can't read the kernel. This doesn't " +
                "mean the firewall is off: rules installed earlier stay in the kernel."
        Protection.DEGRADED ->
            "Firewall state could not be verified. Some rules may be installed. Don't assume " +
                "packets are being filtered, or that they aren't."
        Protection.CHECKING -> "Checking the firewall."
    }

    enum class Protection { CHECKING, ACTIVE, INACTIVE, DEGRADED, ROOT_REQUIRED }
    enum class BootRestore { ENABLED, DISABLED, UNSUPPORTED, DEGRADED, CONFLICT, UNKNOWN }
    enum class UdpConfigMode { AUTOMATIC, COMMITTED, DEGRADED, UNKNOWN }
    enum class TunnelFilter { ON, OFF, DEGRADED, UNKNOWN }
    enum class TunnelMode { PINNED, DENY_ONLY, OFF, UNKNOWN }
    enum class PhysicalFilter { ACTIVE, INACTIVE, DEGRADED, UNKNOWN }
    enum class TailnetConnectivity { MATCH, REAUTHORIZE, DENY_ONLY, OFF, UNVERIFIED }

    data class Snapshot(
        val protection: Protection = Protection.CHECKING,
        val rootReady: Boolean = false,
        val vpnActive: Boolean = false,
        val details: String = "",
        val bootRestore: BootRestore = BootRestore.UNKNOWN,
        val udpConfigMode: UdpConfigMode = UdpConfigMode.UNKNOWN,
        val committedUdp4: String = "none",
        val committedUdp6: String = "none",
        /** Identity of Android's active VPN when the OS provides its owner. */
        val vpnProvider: String? = null,
        /** Live interfaces PocketUFW has no hook on. Empty does not prove full coverage. */
        val uncoveredInterfaces: List<String> = emptyList(),
        /** Empty interface lists only mean no known gaps after a successful inventory. */
        val interfaceInventoryAvailable: Boolean = false,
        /** Uncovered interfaces Android identifies as carrier IMS. Still uncovered; described calmly. */
        val carrierImsInterfaces: Set<String> = emptySet(),
        /** The interface Android's own record gives the active VPN, when it says. */
        val vpnInterface: String? = null,
        /** Session-only. ON verifies installed hooks, not all interfaces or ownership. */
        val tunnelFilter: TunnelFilter = TunnelFilter.UNKNOWN,
        val tunnelMode: TunnelMode = TunnelMode.UNKNOWN,
        val tailnetConnectivity: TailnetConnectivity = TailnetConnectivity.UNVERIFIED,
        val tailnetPin4: String? = null,
        val tailnetPin6: String? = null,
        val tailnetObserved4: String? = null,
        val tailnetObserved6: String? = null,
        /** Independently audited physical rules, even when tunnel rules are degraded. */
        val physicalFilter: PhysicalFilter = PhysicalFilter.UNKNOWN
    )
    data class TunnelCounters(
        val ipv4Blocked: Long, val ipv6Blocked: Long,
        val ipv4Bytes: Long, val ipv6Bytes: Long,
        val ipv4Replies: Long, val ipv6Replies: Long,
        val ipv4Tailnet: Long, val ipv6Tailnet: Long
    )
    /**
     * Kernel rule counters are read-only measurements, not a universal proof
     * of filtering. Null counts mean "unavailable", never pretend they are zero.
     */
    data class RuleActivity(
        val ipv4Blocked: Long? = null,
        val ipv6Blocked: Long? = null,
        val ipv4Bytes: Long? = null,
        val ipv6Bytes: Long? = null,
        val ipv4Replies: Long? = null,
        val ipv6Replies: Long? = null,
        val checkedAt: Long = 0L,
        val error: String? = null,
        val lastManualResetAt: Long = 0L,
        val tunnel: TunnelCounters? = null,
        val tunnelFilter: TunnelFilter = TunnelFilter.UNKNOWN,
        val tunnelMode: TunnelMode = TunnelMode.UNKNOWN,
        val tailnetPin4: String? = null,
        val tailnetPin6: String? = null
    ) {
        val measured: Boolean
            get() = error == null && ipv4Blocked != null && ipv6Blocked != null &&
                ipv4Replies != null && ipv6Replies != null

        val totalBlocked: Long?
            get() = if (measured) counterSum(ipv4Blocked, ipv6Blocked) else null

        val totalReplies: Long?
            get() = if (measured) counterSum(ipv4Replies, ipv6Replies) else null
    }
    /** Unmodified rules reported by Android's live iptables and ip6tables. */
    data class RuleFamily(
        val inputPolicy: String,
        val hooks: List<String>,
        val inbound: List<String>,
        val vpnExceptions: List<String>,
        /** Earlier INPUT rules that accept traffic before PocketUFW's hooks see it. */
        val bypass: List<String> = emptyList(),
        /** Separate INPUT-hook target, never a continuation after the physical final DROP. */
        val tunnel: List<String> = emptyList()
    )
    data class KernelReport(
        val ipv4: RuleFamily,
        val ipv6: RuleFamily,
        val readAt: Long
    )
    data class Dashboard(
        val snapshot: Snapshot,
        val activity: RuleActivity? = null,
        val kernelReport: KernelReport? = null,
        /** The tile cache already held a newer result than this read, so it wasn't saved. */
        val superseded: Boolean = false
    )
    data class Operation(
        val success: Boolean,
        val explanation: String,
        val dashboard: Dashboard,
        /** The bridge read everything back and found nothing of PocketUFW's left. */
        val removalClean: Boolean = false
    )

    private val engineDir: File get() = File(context.filesDir, "engine")
    private val script: File get() = File(engineDir, "pocketufw")
    // Remember an explicit Magisk opt-in across a temporary firewall OFF.
    // The actual boot hook is always disabled while the firewall is off.
    private val preferences = context.getSharedPreferences("pocketufw", Context.MODE_PRIVATE)
    private fun bootOptedIn(): Boolean = preferences.getBoolean("boot_opted_in", false)
    private fun setBootOptIn(optedIn: Boolean) {
        preferences.edit().putBoolean("boot_opted_in", optedIn).apply()
    }

    private companion object {
        val ENGINE_SCRIPTS = listOf("pocketufw", "vpn-probe", "bootctl", "boot-service",
            "android-bridge", "rules-report", "udp-config")
        val ENGINE_LOCK = Any()
        var enginePrepared = false

        /**
         * One root session at a time across every client in this process. The tile
         * and the app each have a client, and enabling takes seconds: a read during
         * that sees a half-built firewall and offers to remove it as "partial".
         */
        val ROOT_SESSION = Any()

        const val ROOT_TIMEOUT_DETAILS =
            "A root command timed out and may still finish. Recheck before relying on the firewall."
        const val ROOT_TIMEOUT_MESSAGE =
            "Root command timed out; the firewall may still change. Recheck status."
    }

    // Stage APK-owned scripts once per process, however many clients exist.
    // Periodic counter reads must not rewrite files or touch storage unnecessarily.
    internal fun prepareEngine() {
        synchronized(ENGINE_LOCK) {
            val directory = engineDir
            if (enginePrepared && ENGINE_SCRIPTS.all { File(directory, it).isFile }) return
            check(directory.exists() || directory.mkdirs()) { "Cannot create private engine directory" }
            // Magisk's one-shot boot script can read this app-owned directory
            // before the user unlocks; Android removes it on app uninstall.
            check(context.createDeviceProtectedStorageContext().filesDir.isDirectory) {
                "Device-protected configuration directory is unavailable"
            }
            // Only a process killed mid-write leaves one of these behind.
            directory.listFiles { file -> file.name.startsWith(".") }?.forEach { it.delete() }
            for (name in ENGINE_SCRIPTS) {
                val staged = File.createTempFile(".$name.", ".new", directory)
                try {
                    context.assets.open(name).use { input ->
                        staged.outputStream().use { output -> input.copyTo(output) }
                    }
                    // Only this app UID (and root) should read or modify these scripts.
                    staged.setReadable(false, false)
                    staged.setWritable(false, false)
                    staged.setReadable(true, true)
                    staged.setWritable(true, true)
                    // Atomic, so the root shell never finds a truncated script.
                    check(staged.renameTo(File(directory, name))) { "Cannot stage $name" }
                } finally {
                    staged.delete()
                }
            }
            enginePrepared = true
        }
    }

    private fun quote(value: String) =
        "'" + value.replace("'", "'\\''") + "'"

    // Exactly one privileged process per inspection or user-triggered action.
    // android-bridge executes and audits all CLI operations in that process.
    private fun bridge(action: String, args: List<String> = emptyList()): ShellResult {
        check(action in setOf("inspect", "enable", "disable",
            "enable-restore", "toggle", "toggle-restore",
            "boot-enable", "boot-disable", "vpn-refresh", "reset-counters",
            "counters", "set-ports", "use-auto", "remove-partial", "prepare-uninstall", "tunnel-off",
            "tunnel-on", "tunnel-refresh"))
        check(when (action) {
            "set-ports" -> args.size == 3
            "tunnel-on" -> args.size == 1 && args[0] in setOf("PINNED", "DENY_ONLY")
            "toggle", "toggle-restore" -> args.isEmpty() ||
                (args.size == 1 && args[0] in setOf("ACTIVE", "INACTIVE"))
            else -> args.isEmpty()
        })
        val path = File(engineDir, "android-bridge").absolutePath
        val quotedArgs = (listOf(action) + args).joinToString(" ") { quote(it) }
        return shell.run("/system/bin/sh " + quote(path) + " " + quotedArgs, 32)
    }

    override fun inspectDrops(request: InsightsRequest, recovery: Boolean): InsightsResult = synchronized(ROOT_SESSION) {
        prepareEngine()
        val helper = File(context.applicationInfo.nativeLibraryDir, "libpufw_insights.so")
        if (!helper.isFile) return@synchronized InsightsResult(error = "Native Insights helper is unavailable for this installation.")
        val action = if (recovery) "recover" else "capture"
        val command = "exec " + quote(helper.absolutePath) + " " + action + " " + quote(script.absolutePath)
        parseInsights(request.run(command), recovery)
    }

    private fun vpnIsActive(): Boolean {
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        return manager.activeNetwork?.let { network ->
            manager.getNetworkCapabilities(network)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        } ?: false
    }

    private fun readVpn(): Boolean = try {
        vpnIsActive()
    } catch (_: Exception) {
        false
    }

    /** Read after the root inventory, so both describe the same moment. No evidence means none. */
    @Suppress("DEPRECATION") // allNetworks is the synchronous view; callbacks would add a listener.
    private fun readNetworkFacts(): List<NetworkFacts> = try {
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        manager.allNetworks.map { network ->
            val name = manager.getLinkProperties(network)?.interfaceName
            // A record without capabilities is still a record naming the interface: it vetoes.
            val caps = manager.getNetworkCapabilities(network)
                ?: return@map NetworkFacts(name, cellular = false, vpn = false, ims = false, internet = false, notRestricted = false)
            NetworkFacts(name, caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR),
                caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN),
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_IMS),
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET),
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED))
        }
    } catch (_: Exception) {
        emptyList()
    }

    /** Parse, then describe any uncovered carrier IMS interface. Coverage itself is unchanged. */
    private fun observedDashboard(exitCode: Int, text: String, vpn: Boolean): Dashboard =
        dashboardFromOutput(exitCode, text, vpn).let { dashboard ->
            val uncovered = dashboard.snapshot.uncoveredInterfaces
            if (uncovered.isEmpty()) dashboard
            else dashboard.withCarrierIms(carrierImsInterfaces(readNetworkFacts()))
        }

    /** Identify VPN service ownership, never infer a provider from installed apps. */
    internal fun vpnProviderLabel(ownerPackage: String?): String = when (ownerPackage) {
        "ch.protonvpn.android" -> "Proton VPN"
        "net.mullvad.mullvadvpn" -> "Mullvad VPN"
        "com.wireguard.android" -> "WireGuard"
        "com.tailscale.ipn" -> "Connected via Tailscale"
        else -> "Unrecognized VPN"
    }

    private fun fields(output: String): Map<String, String> =
        output.lineSequence().mapNotNull { line ->
            val sep = line.indexOf('=')
            if (sep <= 0) null
            else line.substring(0, sep) to line.substring(sep + 1).trim()
        }.toMap()

    private fun kernelFamily(values: Map<String, String>, fam: Int): RuleFamily? {
        val policy = values["input_policy$fam"] ?: return null
        if (policy !in setOf("ACCEPT", "DROP", "REJECT")) return null
        fun count(kind: String, max: Int): Int? = values["report_${kind}${fam}_count"]
            ?.takeIf { it.matches(Regex("0|[1-9][0-9]?")) }?.toIntOrNull()?.takeIf { it <= max }
        fun lines(prefix: String, count: Int): List<String>? {
            val keys = (1..count).map { prefix + it.toString().padStart(2, '0') }
            if (values.keys.filter { it.startsWith(prefix) }.toSet() != keys.toSet()) return null
            return keys.map { values.getValue(it) }.takeIf { rows ->
                rows.all { it.length <= 190 && it.none(Char::isISOControl) }
            }
        }
        val mainCount = count("main", 12) ?: return null
        val tunnelCount = count("tunnel", 6) ?: return null
        val hooks = lines("hook${fam}_", count("hook", 12) ?: return null) ?: return null
        val inbound = lines("main${fam}_", mainCount + tunnelCount) ?: return null
        val vpn = lines("vpn${fam}_", count("vpn", 3) ?: return null) ?: return null
        val bypass = lines("input_bypass${fam}_", count("bypass", 6) ?: return null) ?: return null
        if (hooks.isEmpty() || mainCount == 0) return null
        if (hooks.any { !it.startsWith("-A INPUT ") } ||
            bypass.any { !it.startsWith("-A INPUT ") } ||
            inbound.take(mainCount).any { !it.startsWith("-A POCKETUFW_IN ") } ||
            inbound.drop(mainCount).any { !it.startsWith("-A POCKETUFW_VPN ") } ||
            vpn.any { !it.startsWith("-A POCKETUFW_TS ") }) return null
        return RuleFamily(policy, hooks, inbound.filter { it.startsWith("-A POCKETUFW_IN ") },
            vpn, bypass, inbound.filter { it.startsWith("-A POCKETUFW_VPN ") })
    }

    /** Parse only complete, nonnegative counters. Never invent zeroes on failure. */
    private fun parseCounterActivity(values: Map<String, String>): RuleActivity {
        val keys = listOf("ipv4_blocked", "ipv6_blocked",
            "ipv4_blocked_bytes", "ipv6_blocked_bytes",
            "ipv4_established_replies", "ipv6_established_replies")
        val counts = keys.map { key ->
            values[key]?.toLongOrNull()?.takeIf { it >= 0L }
        }
        if (counts.any { it == null }) {
            return RuleActivity(error = "Kernel counters are unavailable or malformed.")
        }
        val tunnelFilter = when (values["tunnel_filter"]) {
            "ON" -> TunnelFilter.ON
            "OFF" -> TunnelFilter.OFF
            "DEGRADED" -> TunnelFilter.DEGRADED
            else -> TunnelFilter.UNKNOWN
        }
        val tunnelMode = if (tunnelFilter == TunnelFilter.OFF) TunnelMode.OFF else when (values["tailnet_trust"]) {
            "PINNED_DESTINATIONS" -> TunnelMode.PINNED
            "DENY_ONLY" -> TunnelMode.DENY_ONLY
            "OFF" -> TunnelMode.OFF
            else -> TunnelMode.UNKNOWN
        }
        val tunnel = if (tunnelFilter == TunnelFilter.ON) {
            val tunnelKeys = listOf("ipv4_tunnel_blocked", "ipv6_tunnel_blocked",
                "ipv4_tunnel_blocked_bytes", "ipv6_tunnel_blocked_bytes",
                "ipv4_tunnel_established_replies", "ipv6_tunnel_established_replies",
                "ipv4_tunnel_tailnet", "ipv6_tunnel_tailnet")
            val t = tunnelKeys.map { values[it]?.toLongOrNull()?.takeIf { n -> n >= 0L } }
            if (t.any { it == null } || tunnelMode !in setOf(TunnelMode.PINNED, TunnelMode.DENY_ONLY) ||
                values["tailnet_wireguard"] == "CONFLICT") {
                return RuleActivity(error = "Tunnel counters are unavailable or malformed; previous counts kept.")
            }
            TunnelCounters(t[0]!!, t[1]!!, t[2]!!, t[3]!!, t[4]!!, t[5]!!, t[6]!!, t[7]!!)
        } else null
        if (tunnelFilter == TunnelFilter.DEGRADED) {
            return RuleActivity(error = "Tunnel protection is degraded; recheck before reading counters.")
        }
        return RuleActivity(
            ipv4Blocked = counts[0], ipv6Blocked = counts[1],
            ipv4Bytes = counts[2], ipv6Bytes = counts[3],
            ipv4Replies = counts[4], ipv6Replies = counts[5],
            checkedAt = System.currentTimeMillis(),
            lastManualResetAt = preferences.getLong("last_counter_reset_at", 0L),
            tunnel = tunnel, tunnelFilter = tunnelFilter, tunnelMode = tunnelMode,
            tailnetPin4 = values["tailnet_pin4"].takeIf { tunnelMode == TunnelMode.PINNED },
            tailnetPin6 = values["tailnet_pin6"].takeIf { tunnelMode == TunnelMode.PINNED }
        )
    }

    /** Read-only, one-root-session refresh. Does not inspect boot/VPN or modify rules. */
    override fun refreshCounterActivity(): RuleActivity = synchronized(ROOT_SESSION) {
        try {
            prepareEngine()
            val result = bridge("counters")
            val values = fields(result.text)
            if (result.succeeded && values["root"] == "GRANTED" &&
                values["state"] == "ACTIVE") {
                parseCounterActivity(values)
            } else {
                RuleActivity(error = values["error"] ?: if (!result.succeeded) {
                    "Could not read live kernel counters. Existing counts were kept."
                } else {
                    "Firewall counters could not be verified. Existing counts were kept."
                })
            }
        } catch (e: Exception) {
            RuleActivity(error = "Counter refresh failed: " +
                (e.message ?: "unknown error") + ". Existing counts were kept.")
        }
    }

    internal fun dashboardFromOutput(exitCode: Int, text: String, vpn: Boolean): Dashboard {
        if (exitCode == ROOT_OUTPUT_INCOMPLETE_EXIT || text.length > ROOT_OUTPUT_LIMIT ||
            text.toByteArray(Charsets.UTF_8).size > ROOT_OUTPUT_LIMIT) return Dashboard(Snapshot(
                protection = Protection.DEGRADED, details = ROOT_OUTPUT_DETAILS, vpnActive = vpn))
        if (exitCode == LIFECYCLE_BUSY_EXIT) return Dashboard(Snapshot(
            protection = Protection.DEGRADED, rootReady = true, vpnActive = vpn,
            details = "A firewall operation is still running or its lock is unavailable. Recheck status before retrying."
        ))
        // Not "root is missing": the shell outlives our wait and may finish the job.
        if (exitCode == ROOT_TIMEOUT_EXIT) return Dashboard(Snapshot(
            protection = Protection.DEGRADED,
            vpnActive = vpn,
            vpnProvider = if (vpn) vpnProviderLabel(null) else null,
            details = ROOT_TIMEOUT_DETAILS
        ))
        val values = fields(text)
        val rootGranted = exitCode == 0 && values["root"] == "GRANTED"
        val protection = if (!rootGranted) Protection.ROOT_REQUIRED
        else if (values["tailnet_wireguard"] == "CONFLICT") Protection.DEGRADED
        else when (values["state"]) {
            "ACTIVE" -> Protection.ACTIVE
            "INACTIVE" -> Protection.INACTIVE
            "DEGRADED" -> Protection.DEGRADED
            else -> Protection.DEGRADED
        }
        val boot = when (values["boot"]) {
            "ENABLED" -> BootRestore.ENABLED
            "DISABLED" -> BootRestore.DISABLED
            "UNSUPPORTED" -> BootRestore.UNSUPPORTED
            "DEGRADED" -> BootRestore.DEGRADED
            "CONFLICT" -> BootRestore.CONFLICT
            else -> BootRestore.UNKNOWN
        }
        val udpMode = when (values["config_mode"]) {
            "AUTOMATIC" -> UdpConfigMode.AUTOMATIC
            "COMMITTED" -> UdpConfigMode.COMMITTED
            "DEGRADED" -> UdpConfigMode.DEGRADED
            else -> UdpConfigMode.UNKNOWN
        }
        val details = if (rootGranted && values["tailnet_wireguard"] == "CONFLICT")
            "A kernel WireGuard named tun* can use the pinned tailnet exemption. Rules remain installed; rename that interface or turn tunnel filtering off, then recheck."
        else protectionDetails(protection)

        val activity = if (protection == Protection.ACTIVE) parseCounterActivity(values)
            else null

        val reportEntries = text.lineSequence().filter { line ->
            line.startsWith("input_policy") || line.startsWith("hook") || line.startsWith("main") ||
                line.startsWith("vpn4") || line.startsWith("vpn6") || line.startsWith("input_bypass") ||
                line.startsWith("report_") || line.startsWith("rules_report")
        }.map { it.substringBefore('=') }.toList()
        val reportKey = Regex("input_policy[46]|(hook|main|vpn|input_bypass)[46]_[0-9]{2}|report_(hook|main|tunnel|vpn|bypass)[46]_count|rules_report")
        val reportComplete = text.trimEnd().substringAfterLast('\n') == "rules_report=READY" &&
            reportEntries.distinct().size == reportEntries.size && reportEntries.all { it.matches(reportKey) }
        val policyReport = if (rootGranted && reportComplete) {
            val four = kernelFamily(values, 4)
            val six = kernelFamily(values, 6)
            if (four != null && six != null) {
                KernelReport(four, six, System.currentTimeMillis())
            } else null
        } else null

        // This app's own network view misses a VPN it's excluded from (split tunnel),
        // and the bridge can't always name the owner. Either one seeing it is enough.
        val owner = if (rootGranted) values["vpn_owner"].orEmpty() else ""
        val vpnDetected = vpn || owner.isNotEmpty()

        return Dashboard(Snapshot(
            protection = protection,
            rootReady = rootGranted,
            vpnActive = vpnDetected,
            vpnProvider = if (vpnDetected) vpnProviderLabel(owner.ifEmpty { null }) else null,
            details = details,
            bootRestore = boot,
            udpConfigMode = udpMode,
            committedUdp4 = values["committed_udp4"] ?: "none",
            committedUdp6 = values["committed_udp6"] ?: "none",
            uncoveredInterfaces = if (!rootGranted) emptyList() else
                values["uncovered_ifaces"].orEmpty().split(',').map { it.trim() }.filter { it.isNotEmpty() },
            interfaceInventoryAvailable = rootGranted && values["interface_report"] == "READY" &&
                text.lineSequence().count { it.startsWith("interface_report=") } == 1 &&
                text.lineSequence().count { it.startsWith("uncovered_ifaces=") } == 1 &&
                values["uncovered_ifaces"]?.let { list -> list.isEmpty() ||
                    list.split(',').all { it.matches(Regex("[A-Za-z0-9_.-]{1,15}")) } } == true,
            vpnInterface = if (rootGranted) values["vpn_iface"]?.takeIf { it.isNotEmpty() } else null,
            tunnelFilter = when {
                !rootGranted -> TunnelFilter.UNKNOWN
                values["tunnel_filter"] == "ON" && protection == Protection.ACTIVE &&
                    values["tailnet_trust"] in setOf("PINNED_DESTINATIONS", "DENY_ONLY") -> TunnelFilter.ON
                values["tunnel_filter"] == "DEGRADED" -> TunnelFilter.DEGRADED
                values["tunnel_filter"] == "OFF" -> TunnelFilter.OFF
                else -> TunnelFilter.UNKNOWN
            },
            tunnelMode = if (!rootGranted) TunnelMode.UNKNOWN else when (values["tailnet_trust"]) {
                "PINNED_DESTINATIONS" -> TunnelMode.PINNED
                "DENY_ONLY" -> TunnelMode.DENY_ONLY
                "OFF" -> TunnelMode.OFF
                else -> TunnelMode.UNKNOWN
            },
            tailnetConnectivity = if (!rootGranted) TailnetConnectivity.UNVERIFIED else when (values["tailnet_current"]) {
                "MATCH" -> TailnetConnectivity.MATCH
                "REAUTHORIZE" -> TailnetConnectivity.REAUTHORIZE
                "DENY_ONLY" -> TailnetConnectivity.DENY_ONLY
                "OFF" -> TailnetConnectivity.OFF
                else -> TailnetConnectivity.UNVERIFIED
            },
            tailnetPin4 = if (rootGranted) values["tailnet_pin4"] else null,
            tailnetPin6 = if (rootGranted) values["tailnet_pin6"] else null,
            tailnetObserved4 = if (rootGranted) values["tailnet_observed4"] else null,
            tailnetObserved6 = if (rootGranted) values["tailnet_observed6"] else null,
            physicalFilter = if (!rootGranted) PhysicalFilter.UNKNOWN else when (values["physical_state"]) {
                "ACTIVE" -> PhysicalFilter.ACTIVE
                "INACTIVE" -> PhysicalFilter.INACTIVE
                "DEGRADED" -> PhysicalFilter.DEGRADED
                else -> PhysicalFilter.UNKNOWN
            }
        ), activity, policyReport)
    }

    /** One Magisk root request returns current policy, boot status and counters. */
    override fun inspectDashboard(): Dashboard = synchronized(ROOT_SESSION) {
        val vpn = readVpn()
        val readStartedAt = System.currentTimeMillis()
        var timedOut = false
        val dashboard = try {
            prepareEngine()
            val result = bridge("inspect")
            timedOut = result.timedOut
            observedDashboard(result.exitCode, result.text, vpn).also { dashboard ->
                if (dashboard.snapshot.rootReady &&
                    dashboard.snapshot.bootRestore == BootRestore.ENABLED) setBootOptIn(true)
            }
        } catch (e: Exception) {
            Dashboard(Snapshot(
                protection = Protection.DEGRADED,
                vpnActive = vpn,
                details = "Unable to inspect firewall: " + (e.message ?: "unknown error")
            ))
        }
        saveForTile(dashboard, readStartedAt, timedOut)
    }

    /** Hands a finished read to the tile cache, unless something newer got there first. */
    private fun saveForTile(dashboard: Dashboard, readStartedAt: Long, timedOut: Boolean): Dashboard {
        if (timedOut) {
            // Nothing is known now, and a cached ROOT_REQUIRED would be false as well.
            TileStatusStore.invalidate(context, source)
            return dashboard
        }
        val saved = TileStatusStore.publish(context, dashboard.snapshot, readStartedAt, source)
        return if (saved) dashboard else dashboard.copy(superseded = true)
    }

    /** A single root session performs the action and audits its final state. */
    private fun performAction(action: String, args: List<String> = emptyList()): Operation = synchronized(ROOT_SESSION) {
        val vpn = readVpn()
        val readStartedAt = System.currentTimeMillis()
        var timedOut = false
        val operation = try {
            prepareEngine()
            val result = bridge(action, args)
            timedOut = result.timedOut
            val values = fields(result.text)
            if (action == "reset-counters" && result.succeeded &&
                values["operation"] == "SUCCESS" && values["state"] == "ACTIVE") {
                preferences.edit()
                    .putLong("last_counter_reset_at", System.currentTimeMillis()).apply()
            }
            val dashboard = observedDashboard(result.exitCode, result.text, vpn)
            val success = dashboard.snapshot.rootReady && values["operation"] == "SUCCESS"
            val message = when {
                result.exitCode == ROOT_OUTPUT_INCOMPLETE_EXIT -> ROOT_OUTPUT_DETAILS
                result.exitCode == LIFECYCLE_BUSY_EXIT -> dashboard.snapshot.details
                result.timedOut -> ROOT_TIMEOUT_MESSAGE
                !dashboard.snapshot.rootReady -> "Root access is needed for this action."
                else -> values["message"]?.takeIf { it.isNotBlank() }
                    ?: "Operation could not be verified."
            }
            if (dashboard.snapshot.rootReady) {
                // A single root session reports the previous boot setting
                // before disabling it, so either switch can restore the opt-in.
                if (values["previous_boot"] == "ENABLED" ||
                    dashboard.snapshot.bootRestore == BootRestore.ENABLED) setBootOptIn(true)
                if (success && action == "boot-disable") setBootOptIn(false)
                if (success && action == "boot-enable") setBootOptIn(true)
            }
            Operation(success, message, dashboard,
                removalClean = action == "prepare-uninstall" && success && values["removal"] == "CLEAN")
        } catch (e: Exception) {
            val dashboard = Dashboard(Snapshot(
                protection = Protection.DEGRADED,
                vpnActive = vpn,
                details = "Unable to check firewall after operation."
            ))
            Operation(false, "Operation failed: " + (e.message ?: "unknown error"), dashboard)
        }
        operation.copy(dashboard = saveForTile(operation.dashboard, readStartedAt, timedOut))
    }

    override fun changeProtection(activate: Boolean): Operation =
        performAction(if (!activate) "disable" else if (bootOptedIn()) "enable-restore" else "enable")

    /**
     * Toggle from verified *live* rules in a single privileged session. [expected]
     * is what the caller showed: the bridge refuses if the kernel no longer agrees,
     * so a tap can't do the opposite of what its tile said.
     */
    fun toggleProtection(expected: Protection): Operation {
        require(expected == Protection.ACTIVE || expected == Protection.INACTIVE) {
            "Only a verified on or off state can be toggled from."
        }
        return performAction(if (bootOptedIn()) "toggle-restore" else "toggle", listOf(expected.name))
    }

    /** Removes only the optional tunnel chains, preserving physical policy and boot opt-in. */
    override fun removeTunnelRules(): Operation = performAction("tunnel-off")

    override fun enableTunnelProtection(mode: TunnelMode): Operation {
        require(mode in setOf(TunnelMode.PINNED, TunnelMode.DENY_ONLY))
        return performAction("tunnel-on", listOf(mode.name))
    }

    /** Refreshes interface hooks only; does not replace pinned authorization. */
    override fun refreshTunnelHooks(): Operation = performAction("tunnel-refresh")

    /** Refused by the bridge unless the live state is still DEGRADED. */
    override fun removePartialRules(): Operation = performAction("remove-partial")

    /** Off, plus every boot file and a read-back. Keeps the boot opt-in in case they stay. */
    override fun prepareUninstall(): Operation = performAction("prepare-uninstall")

    override fun changeBootRestoration(enabled: Boolean): Operation =
        performAction(if (enabled) "boot-enable" else "boot-disable")

    override fun refreshVerifiedPorts(): Operation = performAction("vpn-refresh")

    /** Reset ONLY PocketUFW-owned netfilter counters, with no rule changes. */
    override fun resetCounters(): Operation = performAction("reset-counters")

    private fun normalizeManualPort(value: String): String {
        val candidate = value.trim()
        if (candidate.isEmpty()) return "none"
        require(Regex("[1-9][0-9]{0,4}").matches(candidate) &&
            (candidate.toIntOrNull() ?: 0) in 1..65535) {
            "UDP port must be blank (none) or a number between 1 and 65535."
        }
        return candidate
    }

    override fun updateUdpExceptions(ipv4: String, ipv6: String, committed: Boolean): Operation =
        try {
            performAction("set-ports", listOf(
                normalizeManualPort(ipv4), normalizeManualPort(ipv6),
                if (committed) "committed" else "experimental"
            ))
        } catch (e: IllegalArgumentException) {
            Operation(false, e.message ?: "Invalid UDP port.", inspectDashboard())
        }

    override fun restoreAutomaticUdpExceptions(): Operation = performAction("use-auto")
}
