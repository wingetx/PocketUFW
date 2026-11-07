package io.github.pocketufw

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import java.io.File
import java.util.concurrent.TimeUnit

/** Exit status for "we stopped waiting". The root shell itself may still be running. */
private const val ROOT_TIMEOUT_EXIT = 124

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
        return try {
            if (!process.waitFor(maxSeconds, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                ShellResult(ROOT_TIMEOUT_EXIT, "Root command timed out. Check the superuser prompt.")
            } else {
                val output = process.inputStream.bufferedReader().use { it.readText() }
                ShellResult(process.exitValue(), output.trim().take(8192))
            }
        } catch (e: Exception) {
            process.destroyForcibly()
            ShellResult(125, "Unable to complete root command: ${e.message ?: "unknown error"}")
        }
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
        /** The interface Android's own record gives the active VPN, when it says. */
        val vpnInterface: String? = null
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
        val vpnExceptions: List<String>,
        /** Earlier INPUT rules that accept traffic before PocketUFW's hooks see it. */
        val bypass: List<String> = emptyList()
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
        /** The chains rules-report may list as inbound policy. Anything else voids the report. */
        val INBOUND_CHAINS = listOf("POCKETUFW_IN", "POCKETUFW_VPN", "POCKETUFW_TRUST")
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
            "counters", "set-ports", "use-auto", "remove-partial", "prepare-uninstall"))
        check(when (action) {
            "set-ports" -> args.size == 3
            "toggle", "toggle-restore" -> args.isEmpty() ||
                (args.size == 1 && args[0] in setOf("ACTIVE", "INACTIVE"))
            else -> args.isEmpty()
        })
        val path = File(engineDir, "android-bridge").absolutePath
        val quotedArgs = (listOf(action) + args).joinToString(" ") { quote(it) }
        return shell.run("/system/bin/sh " + quote(path) + " " + quotedArgs, 32)
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
        fun lines(prefix: String): List<String> = values.entries
            .filter { (key, _) -> key.matches(Regex("^" + prefix + "[0-9]{2}$")) }
            .sortedBy { it.key }
            .map { it.value }
        val hooks = lines("hook" + fam + "_")
        val inbound = lines("main" + fam + "_")
        val vpn = lines("vpn" + fam + "_")
        val bypass = lines("input_bypass" + fam + "_")
        if (hooks.isEmpty() || inbound.isEmpty()) return null
        if (hooks.any { !it.startsWith("-A INPUT ") } ||
            bypass.any { !it.startsWith("-A INPUT ") } ||
            inbound.any { rule -> INBOUND_CHAINS.none { rule.startsWith("-A $it ") } } ||
            vpn.any { !it.startsWith("-A POCKETUFW_TS ") }) return null
        return RuleFamily(policy, hooks, inbound, vpn, bypass)
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
        return RuleActivity(
            ipv4Blocked = counts[0], ipv6Blocked = counts[1],
            ipv4Bytes = counts[2], ipv6Bytes = counts[3],
            ipv4Replies = counts[4], ipv6Replies = counts[5],
            checkedAt = System.currentTimeMillis(),
            lastManualResetAt = preferences.getLong("last_counter_reset_at", 0L)
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
        // Not "root is missing": the shell outlives our wait and may finish the job.
        if (exitCode == ROOT_TIMEOUT_EXIT) return Dashboard(Snapshot(
            protection = Protection.DEGRADED,
            vpnActive = vpn,
            vpnProvider = if (vpn) vpnProviderLabel(null) else null,
            details = ROOT_TIMEOUT_DETAILS
        ))
        val values = fields(text)
        val rootGranted = exitCode == 0 && values["root"] == "GRANTED"
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
        val details = protectionDetails(protection)

        val activity = if (protection == Protection.ACTIVE) parseCounterActivity(values)
            else null

        val policyReport = if (rootGranted && values["rules_report"] == "READY") {
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
            vpnInterface = if (rootGranted) values["vpn_iface"]?.takeIf { it.isNotEmpty() } else null
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
            dashboardFromOutput(result.exitCode, result.text, vpn).also { dashboard ->
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
            val dashboard = dashboardFromOutput(result.exitCode, result.text, vpn)
            val success = dashboard.snapshot.rootReady && values["operation"] == "SUCCESS"
            val message = when {
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
