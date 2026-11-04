package io.github.pocketufw

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Tiny boundary around Magisk/KernelSU/APatch's standard "su -c" interface.
 * No network access or continuously running service. The opt-in Magisk
 * boot hook lives in root-only storage under /data/adb.
 * Shell scripts are copied from APK assets into private app storage.
 */
internal class FirewallClient(private val context: Context) {
    enum class Protection { CHECKING, ACTIVE, INACTIVE, DEGRADED, ROOT_REQUIRED }
    enum class BootRestore { ENABLED, DISABLED, UNSUPPORTED, DEGRADED, CONFLICT, UNKNOWN }
    enum class UdpConfigMode { AUTOMATIC, COMMITTED, DEGRADED, UNKNOWN }

    data class Snapshot(
        val protection: Protection = Protection.CHECKING,
        val rootReady: Boolean = false,
        val vpnActive: Boolean = false,
        val details: String = "",
        val bootRestore: BootRestore = BootRestore.UNKNOWN,
        val udpConfigMode: UdpConfigMode = UdpConfigMode.UNKNOWN,
        val committedUdp4: String = "none",
        val committedUdp6: String = "none"
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
        val lastManualResetAt: Long = 0L
    ) {
        val measured: Boolean
            get() = error == null && ipv4Blocked != null && ipv6Blocked != null &&
                ipv4Replies != null && ipv6Replies != null

        val totalBlocked: Long?
            get() = if (measured) (ipv4Blocked ?: 0L) + (ipv6Blocked ?: 0L) else null

        val totalReplies: Long?
            get() = if (measured) (ipv4Replies ?: 0L) + (ipv6Replies ?: 0L) else null
    }
    /** Unmodified rules reported by Android's live iptables and ip6tables. */
    data class RuleFamily(
        val inputPolicy: String,
        val hooks: List<String>,
        val inbound: List<String>,
        val vpnExceptions: List<String>
    )
    data class KernelReport(
        val ipv4: RuleFamily,
        val ipv6: RuleFamily,
        val readAt: Long
    )
    data class Dashboard(
        val snapshot: Snapshot,
        val activity: RuleActivity? = null,
        val kernelReport: KernelReport? = null
    )
    data class Operation(val success: Boolean, val explanation: String, val dashboard: Dashboard)
    private data class ShellResult(val exitCode: Int, val text: String) {
        val succeeded: Boolean get() = exitCode == 0
    }

    private val engineDir: File get() = File(context.filesDir, "engine")
    private val script: File get() = File(engineDir, "pocketufw")
    // Remember an explicit Magisk opt-in across a temporary firewall OFF.
    // The actual boot hook is always disabled while the firewall is off.
    private val preferences = context.getSharedPreferences("pocketufw", Context.MODE_PRIVATE)
    private fun bootOptedIn(): Boolean = preferences.getBoolean("boot_opted_in", false)
    private fun setBootOptIn(optedIn: Boolean) {
        preferences.edit().putBoolean("boot_opted_in", optedIn).apply()
    }

    // Stage APK-owned scripts once per process. Periodic counter reads must
    // not rewrite files or touch storage unnecessarily.
    @Volatile private var enginePrepared = false

    @Synchronized
    private fun prepareEngine() {
        if (enginePrepared) return
        val directory = engineDir
        check(directory.exists() || directory.mkdirs()) { "Cannot create private engine directory" }
        // Magisk's one-shot boot script can read this app-owned directory
        // before the user unlocks; Android removes it on app uninstall.
        check(context.createDeviceProtectedStorageContext().filesDir.isDirectory) {
            "Device-protected configuration directory is unavailable"
        }
        for (name in listOf("pocketufw", "vpn-probe", "bootctl", "boot-service", "android-bridge", "rules-report", "udp-config")) {
            val target = File(directory, name)
            val staged = File(directory, ".$name.new")
            try {
                context.assets.open(name).use { input ->
                    staged.outputStream().use { output -> input.copyTo(output) }
                }
                check(staged.renameTo(target)) { "Cannot stage $name" }
                // Only this app UID (and root) should read or modify these scripts.
                target.setReadable(false, false)
                target.setWritable(false, false)
                target.setReadable(true, true)
                target.setWritable(true, true)
            } finally {
                staged.delete()
            }
        }
        enginePrepared = true
    }

    private fun quote(value: String) =
        "'" + value.replace("'", "'\\''") + "'"

    private fun runAsRoot(command: String, maxSeconds: Long = 20): ShellResult {
        val process = try {
            ProcessBuilder("su", "-c", command).redirectErrorStream(true).start()
        } catch (e: Exception) {
            return ShellResult(127, "Unable to request root: ${e.message ?: "su unavailable"}")
        }
        return try {
            if (!process.waitFor(maxSeconds, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                ShellResult(124, "Root command timed out. Check the superuser prompt.")
            } else {
                val output = process.inputStream.bufferedReader().use { it.readText() }
                ShellResult(process.exitValue(), output.trim().take(8192))
            }
        } catch (e: Exception) {
            process.destroyForcibly()
            ShellResult(125, "Unable to complete root command: ${e.message ?: "unknown error"}")
        }
    }

    // Exactly one privileged process per inspection or user-triggered action.
    // android-bridge executes and audits all CLI operations in that process.
    private fun bridge(action: String, args: List<String> = emptyList()): ShellResult {
        check(action in setOf("inspect", "enable", "disable",
            "enable-restore", "toggle", "toggle-restore",
            "boot-enable", "boot-disable", "vpn-refresh", "reset-counters", "set-ports", "use-auto"))
        check((action == "set-ports" && args.size == 3) ||
            (action != "set-ports" && args.isEmpty()))
        val path = File(engineDir, "android-bridge").absolutePath
        val quotedArgs = (listOf(action) + args).joinToString(" ") { quote(it) }
        return runAsRoot("/system/bin/sh " + quote(path) + " " + quotedArgs,
            maxSeconds = 32)
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

    private fun fields(output: String): Map<String, String> =
        output.lineSequence().mapNotNull { line ->
            val sep = line.indexOf('=')
            if (sep <= 0) null
            else line.substring(0, sep) to line.substring(sep + 1).trim()
        }.toMap()

    private fun kernelFamily(values: Map<String, String>, fam: Int): RuleFamily? {
        val policy = values["input_policy$fam"] ?: return null
        if (policy !in setOf("ACCEPT", "DROP", "REJECT")) return null
        fun lines(prefix: String): List<String> = values.entries
            .filter { (key, _) -> key.matches(Regex("^" + prefix + "[0-9]{2}$")) }
            .sortedBy { it.key }
            .map { it.value }
        val hooks = lines("hook" + fam + "_")
        val inbound = lines("main" + fam + "_")
        val vpn = lines("vpn" + fam + "_")
        if (hooks.isEmpty() || inbound.isEmpty()) return null
        if (hooks.any { !it.startsWith("-A INPUT ") } ||
            inbound.any { !it.startsWith("-A POCKETUFW_IN ") } ||
            vpn.any { !it.startsWith("-A POCKETUFW_TS ") }) return null
        return RuleFamily(policy, hooks, inbound, vpn)
    }

    private fun dashboardFrom(result: ShellResult, vpn: Boolean): Dashboard {
        val values = fields(result.text)
        val rootGranted = result.succeeded && values["root"] == "GRANTED"
        val protection = if (!rootGranted) Protection.ROOT_REQUIRED else when (values["state"]) {
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
        val details = when (protection) {
            Protection.ACTIVE ->
                "IPv4 and IPv6 rules, hooks and default inbound policy verified."
            Protection.INACTIVE -> "PocketUFW has not installed any firewall chains."
            Protection.ROOT_REQUIRED ->
                "Root access is needed to inspect and manage the firewall."
            Protection.DEGRADED ->
                "Firewall state could not be verified. Review root access and installed rules."
            Protection.CHECKING -> "Checking the firewall."
        }

        // Missing / malformed counters are unavailable, not fictitious zeros.
        val activity = if (protection == Protection.ACTIVE) {
            val keys = listOf("ipv4_blocked", "ipv6_blocked",
                "ipv4_blocked_bytes", "ipv6_blocked_bytes",
                "ipv4_established_replies", "ipv6_established_replies")
            val counts = keys.map { key ->
                values[key]?.toLongOrNull()?.takeIf { it >= 0L }
            }
            if (counts.any { it == null }) {
                RuleActivity(error = "Kernel counters are unavailable or malformed.")
            } else {
                RuleActivity(
                    ipv4Blocked = counts[0], ipv6Blocked = counts[1],
                    ipv4Bytes = counts[2], ipv6Bytes = counts[3],
                    ipv4Replies = counts[4], ipv6Replies = counts[5],
                    checkedAt = System.currentTimeMillis(),
                    lastManualResetAt = preferences.getLong("last_counter_reset_at", 0L)
                )
            }
        } else null

        val policyReport = if (rootGranted && values["rules_report"] == "READY") {
            val four = kernelFamily(values, 4)
            val six = kernelFamily(values, 6)
            if (four != null && six != null) {
                KernelReport(four, six, System.currentTimeMillis())
            } else null
        } else null

        return Dashboard(Snapshot(
            protection = protection,
            rootReady = rootGranted,
            vpnActive = vpn,
            details = details,
            bootRestore = boot,
            udpConfigMode = udpMode,
            committedUdp4 = values["committed_udp4"] ?: "none",
            committedUdp6 = values["committed_udp6"] ?: "none"
        ), activity, policyReport)
    }

    /** One Magisk root request returns current policy, boot status and counters. */
    fun inspectDashboard(): Dashboard {
        val vpn = readVpn()
        return (try {
            prepareEngine()
            dashboardFrom(bridge("inspect"), vpn).also { dashboard ->
                if (dashboard.snapshot.rootReady &&
                    dashboard.snapshot.bootRestore == BootRestore.ENABLED) setBootOptIn(true)
            }
        } catch (e: Exception) {
            Dashboard(Snapshot(
                protection = Protection.DEGRADED,
                vpnActive = vpn,
                details = "Unable to inspect firewall: " + (e.message ?: "unknown error")
            ))
        }).also { TileStatusStore.publish(context, it.snapshot) }
    }

    /** A single root session performs the action and audits its final state. */
    private fun performAction(action: String, args: List<String> = emptyList()): Operation {
        val vpn = readVpn()
        return (try {
            prepareEngine()
            val result = bridge(action, args)
            val values = fields(result.text)
            if (action == "reset-counters" && result.succeeded &&
                values["operation"] == "SUCCESS" && values["state"] == "ACTIVE") {
                preferences.edit()
                    .putLong("last_counter_reset_at", System.currentTimeMillis()).apply()
            }
            val dashboard = dashboardFrom(result, vpn)
            val success = dashboard.snapshot.rootReady && values["operation"] == "SUCCESS"
            val message = if (!dashboard.snapshot.rootReady) {
                "Root access is needed for this action."
            } else {
                values["message"]?.takeIf { it.isNotBlank() }
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
            Operation(success, message, dashboard)
        } catch (e: Exception) {
            val dashboard = Dashboard(Snapshot(
                protection = Protection.DEGRADED,
                vpnActive = vpn,
                details = "Unable to check firewall after operation."
            ))
            Operation(false, "Operation failed: " + (e.message ?: "unknown error"), dashboard)
        }).also { TileStatusStore.publish(context, it.dashboard.snapshot) }
    }

    fun changeProtection(activate: Boolean): Operation =
        performAction(if (!activate) "disable" else if (bootOptedIn()) "enable-restore" else "enable")

    /** Toggle from verified *live* rules in a single privileged session. */
    fun toggleProtection(): Operation =
        performAction(if (bootOptedIn()) "toggle-restore" else "toggle")

    fun changeBootRestoration(enabled: Boolean): Operation =
        performAction(if (enabled) "boot-enable" else "boot-disable")

    fun refreshVerifiedPorts(): Operation = performAction("vpn-refresh")

    /** Reset ONLY PocketUFW-owned netfilter counters, with no rule changes. */
    fun resetCounters(): Operation = performAction("reset-counters")

    private fun normalizeManualPort(value: String): String {
        val candidate = value.trim()
        if (candidate.isEmpty()) return "none"
        require(Regex("[1-9][0-9]{0,4}").matches(candidate) &&
            (candidate.toIntOrNull() ?: 0) in 1..65535) {
            "UDP port must be blank (none) or a number between 1 and 65535."
        }
        return candidate
    }

    fun updateUdpExceptions(ipv4: String, ipv6: String, committed: Boolean): Operation =
        try {
            performAction("set-ports", listOf(
                normalizeManualPort(ipv4), normalizeManualPort(ipv6),
                if (committed) "committed" else "experimental"
            ))
        } catch (e: IllegalArgumentException) {
            Operation(false, e.message ?: "Invalid UDP port.", inspectDashboard())
        }

    fun restoreAutomaticUdpExceptions(): Operation = performAction("use-auto")
}
