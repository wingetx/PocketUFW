package io.github.pocketufw

import android.content.Context
import io.github.pocketufw.FirewallClient.Protection
import io.github.pocketufw.FirewallClient.Snapshot
import java.io.File
import java.nio.file.Files
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/** What each user action asks the bridge to do, and how it reads the answer. No real su runs. */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class FirewallClientActionTest {
    private val app: Context get() = RuntimeEnvironment.getApplication()
    private val shell = FakeShell()
    private val client by lazy { FirewallClient(app, shell = shell) }

    private fun optIn() = app.getSharedPreferences("pocketufw", Context.MODE_PRIVATE).edit()
        .putBoolean("boot_opted_in", true).commit()

    private fun answer(vararg lines: Pair<String, String>, exit: Int = 0) {
        shell.respond = { ShellResult(exit, lines.joinToString("\n") { "${it.first}=${it.second}" }) }
    }

    // ---- action selection ----

    @Test fun turnOnAndTurnOffAskForOppositeActions() {
        client.changeProtection(true)
        client.changeProtection(false)
        assertEquals(listOf("enable", "disable"), shell.actions.toList())
    }

    @Test fun turnOnKeepsAnEarlierBootOptIn() {
        optIn()
        client.changeProtection(true)
        client.changeProtection(false)
        assertEquals(listOf("enable-restore", "disable"), shell.actions.toList())
    }

    @Test fun bootSwitchFollowsTheRequestedPosition() {
        client.changeBootRestoration(true)
        client.changeBootRestoration(false)
        assertEquals(listOf("boot-enable", "boot-disable"), shell.actions.toList())
    }

    @Test fun removingPartialRulesHasItsOwnAction() {
        client.removePartialRules()
        assertEquals(listOf("remove-partial"), shell.actions.toList())
    }

    @Test fun otherActionsReachTheirOwnBridgeCommand() {
        client.refreshVerifiedPorts()
        client.resetCounters()
        client.restoreAutomaticUdpExceptions()
        client.inspectDashboard()
        client.refreshCounterActivity()
        assertEquals(listOf("vpn-refresh", "reset-counters", "use-auto", "inspect", "counters"),
            shell.actions.toList())
    }

    @Test fun toggleSendsTheStateTheTileShowed() {
        shell.respond = { ShellResult(0, bridgeOutput(boot = "DISABLED")) }
        client.toggleProtection(Protection.ACTIVE)
        client.toggleProtection(Protection.INACTIVE)
        assertEquals(listOf("toggle ACTIVE", "toggle INACTIVE"), shell.actions.toList())
    }

    @Test fun toggleKeepsAnEarlierBootOptIn() {
        optIn()
        client.toggleProtection(Protection.INACTIVE)
        assertEquals(listOf("toggle-restore INACTIVE"), shell.actions.toList())
    }

    @Test fun onlyAKnownStateCanBeToggledFrom() {
        for (state in listOf(Protection.DEGRADED, Protection.ROOT_REQUIRED, Protection.CHECKING)) {
            assertThrows(state.name, IllegalArgumentException::class.java) { client.toggleProtection(state) }
        }
        assertEquals(emptyList<String>(), shell.actions.toList())
    }

    @Test fun udpEditsCarryTheirPortsAndScope() {
        client.updateUdpExceptions(" 41641 ", "", committed = true)
        client.updateUdpExceptions("", "43504", committed = false)
        assertEquals(listOf("set-ports 41641 none committed", "set-ports none 43504 experimental"),
            shell.actions.toList())
    }

    @Test fun invalidUdpPortsNeverReachTheBridge() {
        for (port in listOf("0", "65536", "abc", "01", "-1", "1; reboot")) {
            val result = client.updateUdpExceptions(port, "", committed = false)
            assertFalse(port, result.success)
            assertEquals(port, "UDP port must be blank (none) or a number between 1 and 65535.", result.explanation)
        }
        assertTrue(shell.actions.none { it.startsWith("set-ports") })
    }

    @Test fun everyActionIsOneRootSession() {
        client.changeProtection(true)
        assertEquals(1, shell.actions.size)
    }

    // ---- success and failure ----

    @Test fun onlyAReportedSuccessIsASuccess() {
        val success = bridgeOutput(operation = "SUCCESS", message = "Firewall enabled.")
        shell.respond = { ShellResult(0, success) }
        val ok = client.changeProtection(true)
        assertTrue(ok.success)
        assertEquals("Firewall enabled.", ok.explanation)

        shell.respond = { ShellResult(0, bridgeOutput(operation = "FAILED", message = "Cannot enable firewall.")) }
        val refused = client.changeProtection(true)
        assertFalse(refused.success)
        assertEquals("Cannot enable firewall.", refused.explanation)

        shell.respond = { ShellResult(0, bridgeOutput(operation = "NONE")) }
        val none = client.changeProtection(true)
        assertFalse(none.success)
        assertEquals("Operation could not be verified.", none.explanation)

        shell.respond = { ShellResult(5, success) }
        assertFalse(client.changeProtection(true).success)
    }

    @Test fun rootDenialIsReportedAsSuch() {
        answer("root" to "DENIED", exit = 3)
        val denied = client.changeProtection(true)
        assertFalse(denied.success)
        assertEquals("Root access is needed for this action.", denied.explanation)
        assertEquals(Protection.ROOT_REQUIRED, TileStatusStore.read(app)?.protection)
    }

    @Test fun aTimedOutActionSaysItMayStillChangeTheFirewall() {
        shell.respond = { ShellResult(124, "Root command timed out. Check the superuser prompt.") }
        val result = client.changeProtection(false)
        assertFalse(result.success)
        assertEquals("Root command timed out; the firewall may still change. Recheck status.", result.explanation)
        assertEquals(Protection.DEGRADED, result.dashboard.snapshot.protection)
        assertFalse(result.dashboard.snapshot.rootReady)
    }

    @Test fun aTimeoutInvalidatesTheTileInsteadOfCachingRootRequired() {
        TileStatusStore.publish(app, Snapshot(Protection.ACTIVE, rootReady = true))
        shell.respond = { ShellResult(124, "timed out") }
        client.inspectDashboard()
        assertNull("the tile must read as not verified", TileStatusStore.read(app))

        TileStatusStore.publish(app, Snapshot(Protection.ACTIVE, rootReady = true))
        client.changeProtection(false)
        assertNull("the tile must read as not verified", TileStatusStore.read(app))
    }

    @Test fun aShellFailureIsNotASuccessAndDoesNotReadAsActive() {
        shell.respond = { throw IllegalStateException("broken pipe") }
        val result = client.changeProtection(true)
        assertFalse(result.success)
        assertEquals("Operation failed: broken pipe", result.explanation)
        assertEquals(Protection.DEGRADED, result.dashboard.snapshot.protection)
    }

    @Test fun inspectionsPublishTheirResultToTheTile() {
        shell.respond = { ShellResult(0, bridgeOutput(state = "INACTIVE", boot = "DISABLED")) }
        assertEquals(Protection.INACTIVE, client.inspectDashboard().snapshot.protection)
        assertEquals(Protection.INACTIVE, TileStatusStore.read(app)?.protection)
    }

    // ---- boot opt-in memory ----

    @Test fun switchingOffRemembersAnArmedBootHook() {
        shell.respond = { ShellResult(0, bridgeOutput(state = "INACTIVE", boot = "DISABLED",
            operation = "SUCCESS", previousBoot = "ENABLED")) }
        client.changeProtection(false)
        client.changeProtection(true)
        assertEquals("enable-restore", shell.actions.last())
    }

    @Test fun disablingBootRestorationForgetsTheOptIn() {
        optIn()
        shell.respond = { ShellResult(0, bridgeOutput(boot = "DISABLED", operation = "SUCCESS")) }
        client.changeBootRestoration(false)
        client.changeProtection(true)
        assertEquals("enable", shell.actions.last())
    }

    @Test fun aFailedBootDisableKeepsTheOptIn() {
        optIn()
        shell.respond = { ShellResult(0, bridgeOutput(boot = "ENABLED", operation = "FAILED")) }
        client.changeBootRestoration(false)
        client.changeProtection(true)
        assertEquals("enable-restore", shell.actions.last())
    }

    // ---- counters ----

    @Test fun counterRefreshReadsFamiliesAndNeverInventsZeroes() {
        answer("root" to "GRANTED", "state" to "ACTIVE", "ipv4_blocked" to "11", "ipv6_blocked" to "22",
            "ipv4_blocked_bytes" to "33", "ipv6_blocked_bytes" to "44",
            "ipv4_established_replies" to "55", "ipv6_established_replies" to "66")
        val activity = client.refreshCounterActivity()
        assertEquals(11L, activity.ipv4Blocked)
        assertEquals(44L, activity.ipv6Bytes)
        assertEquals(55L, activity.ipv4Replies)

        answer("root" to "GRANTED", "state" to "ACTIVE", "ipv4_blocked" to "11")
        val partial = client.refreshCounterActivity()
        assertFalse(partial.measured)
        assertNull(partial.totalBlocked)
    }

    @Test fun counterFailuresKeepTheirReason() {
        answer("error" to "Firewall is not active or its policy could not be verified.", exit = 5)
        assertEquals("Firewall is not active or its policy could not be verified.",
            client.refreshCounterActivity().error)

        shell.respond = { ShellResult(1, "denied") }
        assertEquals("Could not read live kernel counters. Existing counts were kept.",
            client.refreshCounterActivity().error)

        answer("root" to "GRANTED", "state" to "INACTIVE")
        assertEquals("Firewall counters could not be verified. Existing counts were kept.",
            client.refreshCounterActivity().error)
    }

    @Test fun onlyASuccessfulResetRecordsAResetTime() {
        shell.respond = { ShellResult(0, bridgeOutput(operation = "FAILED")) }
        client.resetCounters()
        assertEquals(0L, client.inspectDashboard().activity!!.lastManualResetAt)

        shell.respond = { ShellResult(0, bridgeOutput(operation = "SUCCESS")) }
        val before = System.currentTimeMillis()
        client.resetCounters()
        assertTrue(client.inspectDashboard().activity!!.lastManualResetAt >= before)
    }

    // ---- stale results ----

    @Test fun aReadOvertakenByANewerWriteIsNotSaved() {
        shell.respond = {
            Thread.sleep(5)
            TileStatusStore.publish(app, Snapshot(Protection.INACTIVE, rootReady = true),
                source = TileStatusStore.SOURCE_TILE)
            Thread.sleep(5)
            ShellResult(0, bridgeOutput(state = "ACTIVE"))
        }
        val read = client.inspectDashboard()
        assertTrue(read.superseded)
        assertEquals(Protection.INACTIVE, TileStatusStore.read(app)?.protection)

        val action = client.changeProtection(true)
        assertTrue(action.dashboard.superseded)
        assertEquals(Protection.INACTIVE, TileStatusStore.read(app)?.protection)
    }

    @Test fun anUnchallengedReadIsSavedAndNotSuperseded() {
        assertFalse(client.inspectDashboard().superseded)
        assertFalse(client.changeProtection(true).dashboard.superseded)
        assertEquals(Protection.ACTIVE, TileStatusStore.read(app)?.protection)
    }

    @Test fun clientsTagTheirWritesWithTheirSource() {
        client.inspectDashboard()
        assertEquals(TileStatusStore.SOURCE_APP, TileStatusStore.lastWriteSource(app))
        FirewallClient(app, TileStatusStore.SOURCE_TILE, shell).inspectDashboard()
        assertEquals(TileStatusStore.SOURCE_TILE, TileStatusStore.lastWriteSource(app))
    }

    // ---- one root session at a time ----

    @Test fun rootSessionsNeverOverlapAcrossClients() {
        val running = AtomicInteger()
        val worst = AtomicInteger()
        shell.respond = {
            worst.accumulateAndGet(running.incrementAndGet()) { a, b -> maxOf(a, b) }
            Thread.sleep(40)
            running.decrementAndGet()
            ShellResult(0, bridgeOutput())
        }
        val threads = List(4) { index ->
            Thread {
                val own = FirewallClient(app, shell = shell)
                if (index % 2 == 0) own.inspectDashboard() else own.toggleProtection(Protection.ACTIVE)
            }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join() }
        assertEquals(4, shell.actions.size)
        assertEquals("a read could see a half-built firewall", 1, worst.get())
    }

    @Test fun aReadWaitingForAnOperationReportsItsResultAndIsNotSuperseded() {
        val enabled = java.util.concurrent.CountDownLatch(1)
        shell.respond = { action ->
            if (action.startsWith("toggle")) {
                enabled.countDown()
                Thread.sleep(120)
                ShellResult(0, bridgeOutput(state = "ACTIVE", operation = "SUCCESS"))
            } else ShellResult(0, bridgeOutput(state = "ACTIVE"))
        }
        val tile = Thread { FirewallClient(app, TileStatusStore.SOURCE_TILE, shell).toggleProtection(Protection.INACTIVE) }
        tile.start()
        enabled.await()
        val read = client.inspectDashboard()
        tile.join()
        assertEquals(listOf("toggle INACTIVE", "inspect"), shell.actions.toList())
        assertEquals(Protection.ACTIVE, read.snapshot.protection)
        assertFalse("it started after the operation it waited for", read.superseded)
    }

    // ---- staging the engine ----

    private val engine get() = File(app.filesDir, "engine")
    private val scripts = listOf("pocketufw", "vpn-probe", "bootctl", "boot-service",
        "android-bridge", "rules-report", "udp-config")

    @Test fun engineIsStagedOncePerProcessNotPerInstance() {
        FirewallClient(app, shell = shell).prepareEngine()
        val target = File(engine, "pocketufw")
        val inode = Files.getAttribute(target.toPath(), "unix:ino")
        repeat(3) { FirewallClient(app, shell = shell).prepareEngine() }
        assertEquals("a new client rewrote the scripts", inode, Files.getAttribute(target.toPath(), "unix:ino"))
    }

    @Test fun aMissingScriptIsStagedAgain() {
        client.prepareEngine()
        val target = File(engine, "bootctl")
        assertTrue(target.delete())
        FirewallClient(app, shell = shell).prepareEngine()
        assertTrue(target.isFile)
        assertTrue(target.length() > 0)
    }

    @Test fun stagedScriptsAreComplete_ownerOnly_andLeaveNoTempFiles() {
        client.prepareEngine()
        assertEquals(scripts.toSet(), engine.list()!!.toSet())
        for (name in scripts) {
            val target = File(engine, name)
            val expected = app.assets.open(name).use { it.readBytes() }
            assertArrayEquals(name, expected, target.readBytes())
            assertEquals(name, "rw-------",
                java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(target.toPath())))
        }
    }

    @Test fun concurrentStagingNeverFailsOrExposesATruncatedScript() {
        client.prepareEngine()
        val target = File(engine, "pocketufw")
        val fullSize = target.length()
        val stop = AtomicBoolean(false)
        val truncated = AtomicInteger()
        val watcher = Thread {
            while (!stop.get()) if (target.length() < fullSize) truncated.incrementAndGet()
        }
        val failures = java.util.Collections.synchronizedList(mutableListOf<Throwable>())
        watcher.start()
        repeat(60) {
            File(engine, "udp-config").delete() // Forces both threads back into staging.
            val threads = List(2) {
                Thread {
                    try { FirewallClient(app, shell = shell).prepareEngine() }
                    catch (e: Throwable) { failures += e }
                }
            }
            threads.forEach { it.start() }
            threads.forEach { it.join() }
        }
        stop.set(true)
        watcher.join()
        assertEquals(emptyList<Throwable>(), failures.toList())
        assertEquals(0, truncated.get())
        assertEquals(scripts.toSet(), engine.list()!!.toSet())
    }
}
