package io.github.pocketufw

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import java.nio.file.Files
import org.junit.After
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class CoverageReportingTest {
    @get:Rule val compose = createEmptyComposeRule()
    private val screens = mutableListOf<ActivityController<ComponentActivity>>()
    @After fun close() = drainMainLooper(screens)
    private val client get() = FirewallClient(RuntimeEnvironment.getApplication(), shell = FakeShell())
    private fun parse(text: String) = client.dashboardFromOutput(0, text, false)

    private fun expand(label: String) = compose.onNodeWithText(label).performScrollTo().performClick()
    private fun calmStatus() {
        compose.onNodeWithText("PROTECTION ACTIVE · RULES VERIFIED").assertExists()
        compose.onNodeWithText(COVERAGE_SUBTITLE).assertExists()
        compose.onNodeWithTag("coverage-notice").assertDoesNotExist()
        compose.onNodeWithText("Coverage limited").assertDoesNotExist()
        compose.onNodeWithText("Coverage unknown").assertDoesNotExist()
    }

    @Test fun anUnavailableReportCannotImplyFullCoverage() {
        val dashboard = parse(bridgeOutput(reportStatus = "UNAVAILABLE"))
        val fake = FakeGateway(dashboard)
        screens += compose.launchScreen(fake)
        compose.settle { fake.count("inspect") == 1 && compose.hasText("Active.") }
        calmStatus()
        assertEquals("Coverage unknown", coverageStatus(TideUiState(dashboard.snapshot)).incoming)
        expand("Coverage details")
        compose.onNodeWithText("Coverage inspection is incomplete.", substring = true).assertExists()
        expand("Technical details")
        compose.onNodeWithText("Coverage unknown · inspection incomplete").assertExists()
        compose.onNodeWithText("Earlier Android/OEM rule coverage unknown.", substring = true).assertExists()
        compose.onNodeWithText("Coverage inspected · no gaps reported").assertDoesNotExist()
        assertEquals(listOf("inspect"), fake.calls.toList())
    }

    @Test fun anUnavailableInventoryCannotImplyFullCoverageEvenWithACompleteRuleReport() {
        val dashboard = parse(bridgeOutput().replace("interface_report=READY", "interface_report=UNAVAILABLE"))
        assertNotNull(dashboard.kernelReport)
        val fake = FakeGateway(dashboard)
        screens += compose.launchScreen(fake)
        compose.settle { compose.hasText("Active.") }
        calmStatus()
        expand("Coverage details")
        compose.onNodeWithText("Coverage inspection is incomplete.", substring = true).assertExists()
        expand("Technical details")
        compose.onNodeWithText("Coverage unknown · inspection incomplete").assertExists()
        compose.onNodeWithText("Interface coverage unknown. Recheck status to inspect current interfaces.").assertExists()
        compose.onNodeWithText("Coverage inspected · no gaps reported").assertDoesNotExist()
    }

    @Test fun knownGapsRemainAvailableWhenTheRestOfCoverageIsUnknown() {
        val dashboard = parse(bridgeOutput(uncovered = "eth0", reportStatus = "UNAVAILABLE"))
        val fake = FakeGateway(dashboard)
        screens += compose.launchScreen(fake)
        compose.settle { compose.hasText("Active.") }
        calmStatus()
        assertEquals("Coverage limited", coverageStatus(TideUiState(dashboard.snapshot)).incoming)
        expand("Coverage details")
        compose.onNodeWithText("Not filtered: eth0.").assertExists()
        expand("Technical details")
        compose.onNodeWithText("Known limits · additional coverage unknown").assertExists()
        compose.onNodeWithText("Earlier Android/OEM rule coverage unknown.", substring = true).assertExists()
    }

    @Test fun uncoveredEthernetUsbAndEarlierAcceptsStayInsideCoverageDetails() {
        val rule = "-A INPUT -i wlan0 -j ACCEPT"
        val fake = FakeGateway(parse(bridgeOutput(uncovered = "eth0,usb0", bypass4 = listOf(rule))
            .replace("rules_report=READY", "physical_state=ACTIVE\ntunnel_filter=OFF\ntailnet_trust=OFF\nrules_report=READY")))
        screens += compose.launchScreen(fake)
        compose.settle { compose.hasText("Active.") }
        calmStatus()
        compose.onNodeWithText("Not filtered: eth0, usb0.").assertDoesNotExist()
        expand("Coverage details")
        compose.onNodeWithText("Not filtered: eth0, usb0.").assertExists()
        compose.onNodeWithText("Earlier Android rules were found that can accept traffic before PocketUFW.", substring = true).assertExists()
        compose.onNodeWithText("No action is needed for the configured protection.", substring = true).assertExists()
        expand("Technical details")
        compose.onNodeWithText("IPv4: $rule").assertExists()
        expand("Coverage details")
        compose.onNodeWithText("Not filtered: eth0, usb0.").assertDoesNotExist()
        compose.onNodeWithText("IPv4: $rule").assertDoesNotExist()
        calmStatus()
        assertEquals(listOf("inspect"), fake.calls.toList())
    }

    @Test fun nonCarrierExclusionsAndEarlierAcceptsKeepTheirClassificationWithoutHealthWarnings() {
        val fake = FakeGateway(parse(bridgeOutput(uncovered = "usb0")))
        screens += compose.launchScreen(fake)
        compose.settle { compose.hasText("Active.") }
        calmStatus()
        expand("Coverage details")
        compose.onNodeWithText("Not filtered: usb0.").assertExists()
        fake.dashboard = parse(bridgeOutput(bypass6 = listOf("-A INPUT -i wlan0 -j ACCEPT")))
        compose.onNodeWithContentDescription("Recheck firewall status").performClick()
        compose.settle { fake.count("inspect") == 2 && compose.hasText("Firewall status rechecked. No rules changed.") }
        calmStatus()
        compose.onNodeWithText("Not filtered: usb0.").assertDoesNotExist()
        assertEquals("Coverage limited", coverageStatus(TideUiState(fake.dashboard.snapshot, report = fake.dashboard.kernelReport)).incoming)
        expand("Technical details")
        compose.onNodeWithText("IPv6: -A INPUT -i wlan0 -j ACCEPT").assertExists()
    }

    @Test fun carrierClassificationRequiresEvidenceAndCannotOverrideVpnOwnership() {
        val dashboard = parse(bridgeOutput(uncovered = "ipsec995"))
        val fake = FakeGateway(dashboard.copy(snapshot = dashboard.snapshot.copy(carrierImsInterfaces = setOf("ipsec995"))))
        screens += compose.launchScreen(fake)
        compose.settle { compose.hasText("Active.") }
        calmStatus()
        assertEquals("Carrier calling excluded", coverageStatus(TideUiState(fake.dashboard.snapshot, report = dashboard.kernelReport)).incoming)
        expand("Coverage details")
        compose.onAllNodesWithText("Carrier calling networks (ipsec995)", substring = true).assertCountEquals(1)
        for ((index, state) in listOf(dashboard.snapshot, fake.dashboard.snapshot.copy(vpnInterface = "ipsec995")).withIndex()) {
            fake.dashboard = dashboard.copy(snapshot = state)
            compose.onNodeWithContentDescription("Recheck firewall status").performClick()
            compose.settle { fake.count("inspect") == index + 2 && compose.hasText("Not filtered: unidentified IPsec tunnel ipsec995.") }
            calmStatus()
            assertEquals("Coverage limited", coverageStatus(TideUiState(state, report = dashboard.kernelReport)).incoming)
            compose.onNodeWithText("Carrier calling networks", substring = true).assertDoesNotExist()
        }
    }

    @Test fun aReadyMarkerDoesNotHideMissingDuplicateOrMalformedRows() {
        val good = bridgeOutput()
        assertNotNull(parse(good).kernelReport)
        val bad = listOf(
            good.lines().filterNot { it.startsWith("main4_03=") }.joinToString("\n"),
            good.lines().filterNot { it.startsWith("main4_08=") }.joinToString("\n"),
            good.lines().filterNot { it.startsWith("vpn6_01=") }.joinToString("\n"),
            good.replace("hook4_01=", "hook4_1="),
            good.replace("main4_01=-A", "main4_01=\u0000-A"),
            good.replace("report_main4_count=8", "report_main4_count=garbage"),
            good.replace("report_hook4_count=4", "report_hook4_count=99"),
            good.replace("report_bypass6_count=0", ""),
            good.replace("report_tunnel4_count=0", "report_tunnel4_count=0\nreport_tunnel4_count=0"),
            good.replace("rules_report=READY", "hook4_01=-A INPUT -j ACCEPT\nrules_report=READY"),
            good + "\nmain4_09=-A POCKETUFW_IN -j ACCEPT",
            good.replace("rules_report=READY", "rules_report=READY\nrules_report=READY")
        )
        bad.forEachIndexed { i, text -> assertNull("malformation $i", parse(text).kernelReport) }
        assertNull(parse("root=GRANTED\nstate=ACTIVE").kernelReport)
    }

    @Test fun missingMalformedAndDuplicateInventoryFieldsAreUnknown() {
        val good = bridgeOutput()
        assertTrue(parse(good).snapshot.interfaceInventoryAvailable)
        val bad = listOf(
            good.replace("interface_report=READY\n", ""),
            good.replace("uncovered_ifaces=\n", ""),
            good.replace("uncovered_ifaces=", "uncovered_ifaces=bad/name"),
            good.replace("interface_report=READY", "interface_report=UNAVAILABLE\ninterface_report=READY"),
            good.replace("uncovered_ifaces=", "uncovered_ifaces=eth0\nuncovered_ifaces="),
        )
        bad.forEach { assertFalse(parse(it).snapshot.interfaceInventoryAvailable) }
    }

    @Test fun aCompleteLargeReportSurvivesThePipeAndStillExposesEarlierAccepts() {
        // Both families at bounded diagnostic capacities; every row remains <= 190 bytes.
        val text = buildList {
            add("root=GRANTED"); add("state=ACTIVE")
            add("interface_report=READY"); add("uncovered_ifaces=")
            for (family in listOf(4, 6)) {
                add("input_policy$family=ACCEPT")
                for ((kind, count) in listOf("hook" to 12, "main" to 8, "tunnel" to 4, "vpn" to 1, "bypass" to 6)) {
                    add("report_${kind}${family}_count=$count")
                    val chain = when (kind) {
                        "hook", "bypass" -> "INPUT"
                        "main" -> "POCKETUFW_IN"
                        "tunnel" -> "POCKETUFW_VPN"
                        else -> "POCKETUFW_TS"
                    }
                    val prefix = when (kind) { "tunnel" -> "main"; "bypass" -> "input_bypass"; else -> kind }
                    for (i in 1..count) {
                        val n = (i + if (kind == "tunnel") 8 else 0).toString().padStart(2, '0')
                        val start = "-A $chain -m comment --comment "
                        val end = " -j ACCEPT"
                        add("${prefix}${family}_$n=" + start + "x".repeat(190 - start.length - end.length) + end)
                    }
                }
            }
            add("rules_report=READY")
        }.joinToString("\n")
        assertTrue(text.length > 8192)
        val file = Files.createTempFile("pufw-large-report-", ".txt").toFile()
        try {
            file.writeText(text)
            val result = collectRootOutput(ProcessBuilder("cat", file.absolutePath).redirectErrorStream(true).start(), 3)
            assertEquals(text, result.text)
            val dashboard = client.dashboardFromOutput(result.exitCode, result.text, false)
            assertEquals(FirewallClient.Protection.ACTIVE, dashboard.snapshot.protection)
            assertEquals(6, dashboard.kernelReport!!.ipv4.bypass.size)
            assertEquals(6, dashboard.kernelReport.ipv6.bypass.size)
        } finally { file.delete() }
    }

    @Test fun oversizedResponseCannotBeParsedAsAnActiveSnapshot() {
        val dashboard = parse(bridgeOutput() + "\n" + "x".repeat(65537))
        assertEquals(FirewallClient.Protection.DEGRADED, dashboard.snapshot.protection)
        assertNull(dashboard.kernelReport)
        assertNull(dashboard.activity)
    }

    @Test fun transportOverflowCannotReportAnOperationAsSuccessfulOrAskForRoot() {
        val shell = FakeShell { ShellResult(122, "root=GRANTED\nstate=ACTIVE\noperation=SUCCESS") }
        val operation = FirewallClient(RuntimeEnvironment.getApplication(), shell = shell).resetCounters()
        assertFalse(operation.success)
        assertEquals(FirewallClient.Protection.DEGRADED, operation.dashboard.snapshot.protection)
        assertTrue(operation.explanation.contains("incomplete or too large"))
        assertEquals(listOf("reset-counters"), shell.actions.toList())
    }
}
