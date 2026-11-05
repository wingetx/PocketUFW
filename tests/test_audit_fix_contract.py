"""Source-level contracts for the Tide UI with Claude's audit behaviors ported.

Detailed UI behavior is exercised in TideAuditRegressionTest under Robolectric.
These inexpensive checks also run when only the Python suite is available.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
KOTLIN = ROOT / "android/app/src/main/java/io/github/pocketufw"
SCREENS = {
    file: (KOTLIN / file).read_text(encoding="utf-8")
    for file in (
        "MainActivity.kt", "TideScreen.kt", "TideCounters.kt",
        "TideSettings.kt", "TideComponents.kt", "KernelStatusTab.kt",
        "UdpExceptionsPanel.kt",
    )
}


class TideAuditContractTests(unittest.TestCase):
    def test_reset_requires_confirmation_and_preserves_busy_guard(self):
        screen = SCREENS["TideCounters.kt"]
        self.assertIn('if (resetConfirmation) AlertDialog(', screen)
        self.assertIn('Text("Reset counters?")', screen)
        self.assertEqual(screen.count('actions.resetCounters()'), 1)
        self.assertIn('verified && ui.snapshot.rootReady && !ui.busy', screen)
        self.assertIn('ui.verificationInDoubt', screen)

    def test_partial_rule_removal_has_separate_confirmation(self):
        screen = SCREENS["TideScreen.kt"]
        self.assertIn('if (removeConfirmOpen) AlertDialog(', screen)
        self.assertIn('Magisk boot hook', screen)
        self.assertEqual(screen.count('actions.removePartialRules()'), 1)
        self.assertIn('if (!ui.busy && !ui.verificationInDoubt', screen)

    def test_result_banner_is_outside_scroll(self):
        screen = SCREENS["TideScreen.kt"]
        self.assertIn('snackbarHost = {', screen)
        self.assertLess(screen.index('snackbarHost = {'),
                        screen.index('Column(Modifier.fillMaxSize().padding(inset).verticalScroll(scroll)'))
        self.assertNotIn('if (ui.message.isNotEmpty()) TideNotice(', screen)
        self.assertNotIn('if (ui.counterRefreshNote.isNotEmpty()) TideNotice(',
                         SCREENS["TideCounters.kt"])

    def test_unknown_firewall_state_never_claims_active_or_off(self):
        main = SCREENS["MainActivity.kt"]
        screen = SCREENS["TideScreen.kt"]
        self.assertIn('verificationInDoubt = true', main)
        self.assertIn('val verified = active && !ui.verificationInDoubt', screen)
        self.assertIn('if (ui.verificationInDoubt) "Not', screen)
        self.assertIn('Last known status is not proof of current protection', screen)

    def test_tile_stamp_recheck_not_unconditional_root_request(self):
        main = SCREENS["MainActivity.kt"]
        self.assertIn('snapshotFlow { windowInfo.isWindowFocused }', main)
        focus = main[main.index('LaunchedEffect(windowInfo) {'):
                     main.index('    // Read-only counter refresh.')]
        self.assertIn('TileStatusStore.read(context)', focus)
        self.assertIn('if (latest != tileStamp)', focus)
        self.assertIn('recheck()', focus)
        self.assertNotIn('client.inspectDashboard()', focus)

    def test_manual_recheck_feedback_is_read_only_and_background_recheck_silent(self):
        main = SCREENS["MainActivity.kt"]
        block = main[main.index('fun recheck(showFeedback: Boolean = false) {'):
                     main.index('    // Shade-open never requests root.')]
        self.assertIn('client.inspectDashboard()', block)
        self.assertIn('if (showFeedback) when', block)
        self.assertIn('No rules changed.', block)
        self.assertNotIn('client.changeProtection(', block)
        self.assertNotIn('client.resetCounters()', block)
        self.assertIn('recheck = { recheck(showFeedback = true) }', main)
        focus = main[main.index('LaunchedEffect(windowInfo) {'):
                     main.index('    // Read-only counter refresh.')]
        self.assertIn('recheck()', focus)
        self.assertNotIn('recheck(showFeedback = true)', focus)

    def test_failed_counter_read_retains_numbers_and_withdraws_claim(self):
        main = SCREENS["MainActivity.kt"]
        self.assertIn('if (fresh.measured)', main)
        failure = main[main.index('if (fresh.measured)'):]
        self.assertIn('verificationInDoubt = true', failure)
        self.assertIn('previous counts kept.', failure)
        self.assertNotIn('counters = null', failure)

    def test_boot_switch_is_absent_when_status_unknown(self):
        settings = SCREENS["TideSettings.kt"]
        self.assertIn('if (bootProblemText(state.bootRestore) == null)', settings)
        self.assertIn('bootProblemText(state.bootRestore)?.let', settings)

    def test_vpn_labels_not_falsely_verified(self):
        for name in ("UdpExceptionsPanel.kt", "KernelStatusTab.kt", "TideSettings.kt"):
            self.assertNotIn('Automatic · verified Tailscale listeners', SCREENS[name])
            self.assertNotIn('Verified VPN UDP port', SCREENS[name])
        self.assertIn('vpnRefreshBlockedReason', SCREENS["TideScreen.kt"])
        self.assertIn('vpnReason == null', SCREENS["TideScreen.kt"])

    def test_only_one_tailscale_specific_refresh_button(self):
        settings = SCREENS["TideSettings.kt"]
        screen = SCREENS["TideScreen.kt"]
        self.assertNotIn('actions.refreshVpn', settings)
        self.assertNotIn('Refresh VPN', settings)
        self.assertNotIn('Refresh Tailscale ports', settings)
        self.assertEqual(screen.count('onClick = actions.refreshVpn'), 1)
        self.assertEqual(screen.count('else "Refresh Tailscale ports"'), 1)
        self.assertNotIn('"Refresh VPN"', screen)
        self.assertIn('not your current VPN connection', screen)

    def test_historical_timestamps_have_date(self):
        self.assertIn('Calendar.getInstance()', SCREENS["TideComponents.kt"])
        self.assertIn('DateFormat.getDateTimeInstance', SCREENS["TideComponents.kt"])

    def test_ui_state_writes_on_main_thread(self):
        self.assertIn('rememberCoroutineScope { Dispatchers.Main.immediate }',
                      SCREENS["MainActivity.kt"])

    def test_regression_tests_follow_new_ui_not_retired_layout(self):
        tests = ROOT / "android/app/src/test/java/io/github/pocketufw"
        self.assertTrue((tests / 'TideAuditRegressionTest.kt').is_file())
        self.assertFalse((tests / 'AuditRegressionTest.kt').exists())
        self.assertFalse((tests / 'ResetHazardRegressionTest.kt').exists())

    def test_test_dependencies_not_in_app_runtime(self):
        gradle = (ROOT / "android/app/build.gradle.kts").read_text()
        for line in gradle.splitlines():
            if ('robolectric' in line or 'junit' in line or 'ui-test' in line):
                if ('testImplementation' in line or 'androidTestImplementation' in line or
                    line.strip().startswith('debugImplementation("androidx.compose.ui:ui-test-manifest"')):
                    continue
                self.assertTrue(line.strip().startswith('//'), line)


if __name__ == "__main__":
    unittest.main()
