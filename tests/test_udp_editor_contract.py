"""Static guardrails for the intentionally opt-in advanced UDP editor."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / 'android/app/src/main/java/io/github/pocketufw/UdpExceptionsPanel.kt'
MAIN = ROOT / 'android/app/src/main/java/io/github/pocketufw/MainActivity.kt'
CLIENT = ROOT / 'android/app/src/main/java/io/github/pocketufw/FirewallClient.kt'
BOOT = ROOT / 'boot-service'


class AdvancedUdpContractTests(unittest.TestCase):
    def test_editor_stays_in_presentation_and_gates_manual_updates(self):
        ui = UI.read_text()
        main = MAIN.read_text()
        self.assertIn('UdpExceptionsPanel(', (ROOT / 'android/app/src/main/java/io/github/pocketufw/TideScreen.kt').read_text())
        self.assertIn('About / edit VPN UDP exceptions', ui)
        self.assertIn('Warning: advanced users only', ui)
        self.assertIn('I understand', ui)
        self.assertIn('committed = false  // Experimental is always the safer default.', ui)
        self.assertIn('Commit these UDP exceptions?', ui)
        self.assertIn('Are you sure?', ui)
        self.assertIn('Yes, commit', ui)
        self.assertIn('Experimental', ui)
        self.assertIn('Committed', ui)
        self.assertIn('Restore automatic Tailscale ports', ui)
        self.assertIn('Restore automatic Tailscale ports?', ui)
        self.assertIn('Text("Restore ports")', ui)
        self.assertNotIn('Reset to automatic VPN exceptions', ui)
        self.assertIn('If detection fails, existing settings are preserved.', ui)
        self.assertIn('Closing this app or reconnecting ', ui)
        self.assertIn('Tailscale does not reset it.', ui)
        self.assertIn('Magisk boot restoration is enabled.', ui)
        # Advanced edit scope must remain clear: port exceptions are real
        # inbound allowances, not edits to Android's global firewall.
        self.assertIn("change only PocketUFW's incoming VPN UDP ", ui)
        self.assertIn("not Android's global firewall rules or outgoing traffic.", ui)
        self.assertIn("not just ", ui)
        self.assertIn("Tailscale packets. Choose only ports with trusted listeners.", ui)
        # The reset is not exclusive to Committed: Experimental leaves the
        # persisted mode unchanged, so we must be able to undo live edits.
        self.assertIn('if (!editorOpen) {\n                    OutlinedButton(shape = TideActionShape, onClick = { autoConfirmation = true }', ui)
        self.assertNotIn('if ((saved || state.udpConfigMode == FirewallClient.UdpConfigMode.DEGRADED) && !editorOpen)', ui)
        self.assertIn('client.updateUdpExceptions(ipv4, ipv6, committed)', main)

    def test_ports_revalidated_in_client_bridge_and_root_engine(self):
        client = CLIENT.read_text()
        bridge = (ROOT / 'android-bridge').read_text()
        engine = (ROOT / 'pocketufw').read_text()
        self.assertIn('normalizeManualPort', client)
        self.assertIn('case "$SCOPE" in experimental|committed)', bridge)
        self.assertIn('read_live_ports()', bridge)
        self.assertIn('verify_family "$IPT4" 4 && verify_family "$IPT6" 6', engine)
        self.assertIn('apply_verified_refresh', engine)

    def test_all_staged_root_helpers_are_present_in_apk_asset_declaration(self):
        gradle = (ROOT / 'android/app/build.gradle.kts').read_text()
        for name in ('pocketufw', 'vpn-probe', 'bootctl', 'boot-service',
                     'android-bridge', 'rules-report', 'udp-config'):
            with self.subTest(asset=name):
                self.assertIn('from(rootProject.file("../' + name + '"))', gradle)
                self.assertIn('"' + name + '"', CLIENT.read_text())

    def test_committed_uses_device_protected_data_not_extra_daemon(self):
        client = CLIENT.read_text()
        bridge = (ROOT / 'android-bridge').read_text()
        boot = BOOT.read_text()
        self.assertIn('createDeviceProtectedStorageContext()', client)
        self.assertIn('sh "$CONFIG" write', bridge)
        self.assertIn('sh "$CONFIG" read', boot)
        self.assertNotIn('source "$CONFIG"', boot)
        self.assertNotIn('startForeground(', UI.read_text())


if __name__ == '__main__':
    unittest.main()
