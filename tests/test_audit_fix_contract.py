"""Promises from the UI audit, checked without Android tooling.

The behaviour itself is tested on the real screens by the JVM Compose tests in
android/app/src/test (./gradlew :app:testDebugUnitTest). These checks exist so
the Python suite alone still notices if a fix is undone or the guards are lost.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'android/app/src/main/java/io/github/pocketufw'
UI_TESTS = ROOT / 'android/app/src/test/java/io/github/pocketufw'


class AuditFixContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (APP / 'MainActivity.kt').read_text()
        cls.status = (APP / 'KernelStatusTab.kt').read_text()
        cls.udp = (APP / 'UdpExceptionsPanel.kt').read_text()

    def test_reset_counters_only_runs_from_its_confirmation(self):
        calls = [m.start() for m in re.finditer(r'client\.resetCounters\(\)', self.main)]
        self.assertEqual(len(calls), 1)
        dialog = self.main.index('if (resetConfirmOpen) {')
        self.assertGreater(calls[0], dialog)
        self.assertIn('title = { Text("Reset counters?") }', self.main)

    def test_removing_partial_rules_only_runs_from_its_confirmation(self):
        dialog = self.main.index('if (removeConfirmOpen) {')
        off = [m.start() for m in re.finditer(r'client\.changeProtection\(false\)', self.main)]
        self.assertEqual(len(off), 1)
        self.assertGreater(off[0], dialog)

    def test_operation_results_stay_out_of_the_scrolling_column(self):
        # Inserting the result into the column is what moved Reset under a repeat tap.
        banner = self.main.index('OperationResultBanner(\n                message, failed,')
        room = self.main.index('if (bannerRoomPx > 0) {')
        self.assertLess(room, banner)
        self.assertEqual(self.main.count('if (message.isNotEmpty())'), 1)

    def test_switches_only_draw_known_positions(self):
        firewall = self.main.index('checked = active,')
        self.assertLess(self.main.rindex('if (onOffKnown) {', 0, firewall), firewall)
        boot = self.main.index('checked = state.bootRestore == FirewallClient.BootRestore.ENABLED,')
        self.assertLess(self.main.rindex('bootProblemText(state.bootRestore) == null', 0, boot), boot)

    def test_ports_are_not_labelled_verified(self):
        self.assertNotIn('Verified VPN UDP port', self.status)
        self.assertNotIn('Automatic · verified Tailscale listeners', self.udp)

    def test_hooks_are_read_from_the_report(self):
        self.assertNotIn('"Hooks: wlan+, rmnet+, v4-rmnet+"', self.main)
        self.assertIn('hookSummaryLines(kernelReport)', self.main)

    def test_regaining_focus_cannot_request_root_unconditionally(self):
        block = self.main[self.main.index('LaunchedEffect(windowInfo) {'):]
        block = block[:block.index('fun refreshCounters() {')]
        self.assertIn('if (latest != tileStamp) {', block)
        self.assertNotIn('client.inspectDashboard()', block)

    def test_jvm_ui_guards_are_present(self):
        for name in ('ResetHazardRegressionTest.kt', 'AuditRegressionTest.kt'):
            self.assertTrue((UI_TESTS / name).exists(), name)
        hazard = (UI_TESTS / 'ResetHazardRegressionTest.kt').read_text()
        self.assertIn('assertEquals("the repeat tap reset the counters", 0,', hazard)

    def test_test_tooling_stays_out_of_the_apk(self):
        gradle = (ROOT / 'android/app/build.gradle.kts').read_text()
        for line in gradle.splitlines():
            if 'robolectric' in line or 'ui-test' in line or 'junit' in line:
                self.assertTrue(line.strip().startswith('testImplementation('), line)


if __name__ == '__main__':
    unittest.main()
