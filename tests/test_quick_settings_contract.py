"""Quick Settings manifest security contract, without Android or root access."""
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

PROJECT = Path(__file__).resolve().parents[1]
NAMESPACE = '{http://schemas.android.com/apk/res/android}'


class QuickSettingsContractTests(unittest.TestCase):
    def setUp(self):
        self.root = ET.parse(PROJECT / 'android/app/src/main/AndroidManifest.xml').getroot()

    def test_optional_tile_requires_system_bind_permission(self):
        services = self.root.findall('./application/service')
        self.assertEqual(len(services), 1)
        tile = services[0]
        self.assertEqual(tile.attrib[NAMESPACE + 'name'], '.FirewallTileService')
        self.assertEqual(tile.attrib[NAMESPACE + 'permission'],
                         'android.permission.BIND_QUICK_SETTINGS_TILE')
        actions = [node.attrib[NAMESPACE + 'name'] for node in
                   tile.findall('./intent-filter/action')]
        self.assertEqual(actions, ['android.service.quicksettings.action.QS_TILE'])
        metadata = {node.attrib[NAMESPACE + 'name']: node.attrib[NAMESPACE + 'value']
                    for node in tile.findall('./meta-data')}
        self.assertEqual(metadata['android.service.quicksettings.TOGGLEABLE_TILE'], 'true')
        self.assertNotIn('android.service.quicksettings.ACTIVE_TILE', metadata)

    def test_long_press_resolves_to_dashboard_without_changing_tile_tap(self):
        activities = self.root.findall('./application/activity')
        self.assertEqual(len(activities), 1)
        main = activities[0]
        self.assertEqual(main.attrib[NAMESPACE + 'name'], '.MainActivity')
        filters = main.findall('./intent-filter')
        self.assertEqual(len(filters), 2)
        actions = [{node.attrib[NAMESPACE + 'name'] for node in
                    item.findall('./action')} for item in filters]
        self.assertIn({'android.intent.action.MAIN'}, actions)
        self.assertIn({'android.service.quicksettings.action.QS_TILE_PREFERENCES'}, actions)
        for item in filters:
            names = {node.attrib[NAMESPACE + 'name'] for node in
                     item.findall('./action')}
            if 'android.service.quicksettings.action.QS_TILE_PREFERENCES' in names:
                categories = {node.attrib[NAMESPACE + 'name'] for node in
                              item.findall('./category')}
                self.assertIn('android.intent.category.DEFAULT', categories)

    def test_no_internet_or_permanent_service_permissions(self):
        permissions = {p.attrib[NAMESPACE + 'name'] for p in
                       self.root.findall('./uses-permission')}
        self.assertNotIn('android.permission.INTERNET', permissions)
        self.assertNotIn('android.permission.FOREGROUND_SERVICE', permissions)
        self.assertNotIn('android.permission.POST_NOTIFICATIONS', permissions)

    def test_tile_unlocks_before_security_sensitive_toggle(self):
        code = (PROJECT / 'android/app/src/main/java/io/github/pocketufw/alpha/FirewallTileService.kt').read_text()
        self.assertIn('if (isLocked) unlockAndRun', code)
        self.assertIn('client.toggleProtection()', code)
        self.assertNotIn('startForeground(', code)


if __name__ == '__main__':
    unittest.main()
