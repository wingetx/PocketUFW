"""Static Compose UX contracts: no falsely inactive startup or busy switch flicker."""
from pathlib import Path
import unittest

SOURCE = (Path(__file__).resolve().parents[1] /
          'android/app/src/main/java/io/github/pocketufw/alpha/MainActivity.kt')


class LoadingUiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.code = SOURCE.read_text()

    def test_first_inspection_uses_neutral_loading_panel_before_switches(self):
        code = self.code
        loading = code.index('if (state.protection == FirewallClient.Protection.CHECKING) {')
        home = code.index('} else if (selectedTab == PocketTab.HOME) {', loading)
        self.assertLess(loading, home)
        self.assertIn('CircularProgressIndicator(', code[loading:home])
        self.assertIn('Checking kernel protection', code[loading:home])
        self.assertNotIn('Switch(', code[loading:home])
        self.assertIn('checked = active', code[home:])

    def test_boot_root_request_does_not_dim_other_switches(self):
        code = self.code
        firewall = code.index('checked = active,')
        boot = code.index('checked = state.bootRestore == FirewallClient.BootRestore.ENABLED,')
        firewall_switch = code[firewall:code.index('colors = SwitchDefaults.colors(', firewall)]
        boot_switch = code[boot:code.index('colors = SwitchDefaults.colors(', boot)]
        self.assertIn('if (!busy) perform { client.changeProtection(next) }', firewall_switch)
        self.assertIn('if (!busy) perform { client.changeBootRestoration(next) }', boot_switch)
        self.assertNotIn('enabled = !busy', firewall_switch)
        self.assertNotIn('enabled = !busy', boot_switch)


if __name__ == '__main__':
    unittest.main()
