"""What the uninstall work promised, checked without Android tooling.

Behaviour is tested by test_bootctl, test_integration_real_engine, test_real_kernel
and the JVM TideRemovalTest. These guard the limits the design set for itself.
"""
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'android/app/src/main'
SCRIPTS = ('pocketufw', 'android-bridge', 'bootctl', 'boot-service', 'udp-config', 'vpn-probe', 'rules-report')


def code(name):
    """A script without its comments, so that only what runs is judged."""
    lines = (ROOT / name).read_text().splitlines()
    return '\n'.join(line for line in lines if not line.lstrip().startswith('#'))


class UninstallContractTests(unittest.TestCase):
    def test_no_permission_was_added_to_open_the_uninstall_page(self):
        manifest = ET.parse(APP / 'AndroidManifest.xml').getroot()
        name = '{http://schemas.android.com/apk/res/android}name'
        permissions = sorted(item.get(name) for item in manifest.findall('uses-permission'))
        self.assertEqual(permissions, ['android.permission.ACCESS_NETWORK_STATE',
                                       'android.permission.RECEIVE_BOOT_COMPLETED'])

    def test_nothing_new_stays_running(self):
        for name in SCRIPTS:
            with self.subTest(script=name):
                source = code(name)
                for resident in ('inotifyd', 'nohup', 'setsid', 'daemon'):
                    self.assertNotIn(resident, source)
                # The engine's one `while :` is its lock wait, which is bounded below.
                if name == 'pocketufw':
                    self.assertEqual(source.count('while :; do'), 1)
                    self.assertIn('[ "$lock_polls" -lt 150 ] || break', source)
                    source = source.replace('while :; do', '')
                self.assertIsNone(re.search(r'while (true|:|\[ 1 \])', source))
        hook = code('boot-service')
        self.assertIn('[ "$count" -ge 90 ]', hook)

    def test_removal_uses_exact_names_and_never_recursion(self):
        for name in ('bootctl', 'boot-service', 'android-bridge'):
            with self.subTest(script=name):
                source = code(name)
                self.assertIsNone(re.search(r'\brm\s+-[a-zA-Z]*[rR]', source))
                self.assertIsNone(re.search(r'rm [^\n]*(\*|\$STORE/?["\s]*$)', source, re.M))

    def test_the_app_never_uninstalls_itself_through_root(self):
        for name in SCRIPTS:
            with self.subTest(script=name):
                self.assertNotIn('pm uninstall', code(name))

    def test_only_the_clean_branch_opens_androids_page_after_a_removal(self):
        screen = (APP / 'java/io/github/pocketufw/MainActivity.kt').read_text()
        block = screen[screen.index('prepareUninstall = {'):screen.index('openAppInfo = { showAppInfo() }')]
        self.assertEqual(block.count('showAppInfo()'), 1)
        self.assertLess(block.index('outcome?.removalClean == true'), block.index('showAppInfo()'))
        self.assertLess(block.index('showAppInfo()'), block.index('} else {'))

    def test_the_bridge_calls_removal_clean_only_after_a_read_back(self):
        bridge = code('android-bridge')
        self.assertLess(bridge.index('sh "$ENGINE" residue'), bridge.index('removal=CLEAN'))
        self.assertLess(bridge.index('sh "$BOOT" residue'), bridge.index('removal=CLEAN'))
        self.assertEqual(bridge.count('removal=CLEAN'), 1)


if __name__ == '__main__':
    unittest.main()
