"""PocketUFW v1's small, non-negotiable public feature boundary.

General-purpose root scripting and advanced A/B customization live on the
separate research branch, never in the one-switch release candidate.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'android/app/src/main/java/io/github/pocketufw'


class MinimalReleaseScope(unittest.TestCase):
    def test_no_general_custom_rule_editor_or_parser_in_android_app(self):
        self.assertFalse((APP / 'AdvancedRulesDraftPanel.kt').exists())
        self.assertFalse((APP / 'CustomFirewallPolicy.java').exists())
        for name in ('MainActivity.kt', 'FirewallClient.kt', 'KernelStatusTab.kt'):
            with self.subTest(source=name):
                source = (APP / name).read_text()
                self.assertNotIn('AdvancedRulesDraftPanel(', source)
                self.assertNotIn('custom-policy-live-dev', source)

    def test_no_general_custom_rule_scripts_in_apk_assets(self):
        source = (ROOT / 'android/app/build.gradle.kts').read_text()
        for name in ('custom-policy-state', 'custom-policy-live-dev',
                     'custom-policy-switch-mock', 'custom-policy-validate'):
            self.assertNotIn('from(rootProject.file("../' + name + '"))', source)
        for name in ('pocketufw', 'bootctl', 'boot-service',
                     'android-bridge', 'rules-report', 'vpn-probe', 'udp-config'):
            self.assertIn('from(rootProject.file("../' + name + '"))', source)

    def test_root_bridge_keeps_public_controls_bounded(self):
        source = (ROOT / 'android-bridge').read_text()
        self.assertIn('inspect|enable|disable|enable-restore|toggle|toggle-restore', source)
        self.assertIn('vpn-refresh', source)
        self.assertNotIn('audit-custom', source)
        self.assertNotIn('custom-policy', source)
        self.assertNotIn('run-custom-script', source)

    def test_outbound_policy_is_not_changed_by_the_baseline_engine(self):
        source = (ROOT / 'pocketufw').read_text()
        self.assertIn('POCKETUFW_IN', source)
        self.assertIn('POCKETUFW_TS', source)
        self.assertNotIn('POCKETUFW_U_A', source)
        self.assertNotIn('POCKETUFW_U_B', source)
        self.assertNotIn('-P OUTPUT DROP', source)
        self.assertNotIn('-F OUTPUT', source)


if __name__ == '__main__':
    unittest.main()
