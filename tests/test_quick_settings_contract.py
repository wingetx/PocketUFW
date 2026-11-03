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
        self.assertEqual(metadata['android.service.quicksettings.ACTIVE_TILE'], 'true')

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

    @classmethod
    def tile_code(cls):
        return (PROJECT / 'android/app/src/main/java/io/github/pocketufw/alpha/FirewallTileService.kt').read_text()

    @classmethod
    def client_code(cls):
        return (PROJECT / 'android/app/src/main/java/io/github/pocketufw/alpha/FirewallClient.kt').read_text()

    @classmethod
    def store_code(cls):
        return (PROJECT / 'android/app/src/main/java/io/github/pocketufw/alpha/TileStatusStore.kt').read_text()

    def test_quick_tile_has_its_own_recognizable_tint_safe_icon(self):
        import xml.etree.ElementTree as ET
        ns = '{http://schemas.android.com/apk/res/android}'
        icon = PROJECT / 'android/app/src/main/res/drawable/penguin_quick_tile.xml'
        launcher = PROJECT / 'android/app/src/main/res/mipmap-anydpi-v26/ic_launcher.xml'
        root = ET.parse(icon).getroot()
        paths = root.findall('path')
        self.assertEqual(len(paths), 4)
        self.assertEqual(paths[0].attrib[ns + 'strokeColor'], '#FFFFFFFF')
        self.assertEqual(paths[0].attrib[ns + 'fillColor'], '#00000000')
        self.assertEqual(paths[2].attrib[ns + 'fillType'], 'evenOdd')
        self.assertIn('M29,70 Q19,75', paths[1].attrib[ns + 'pathData'])
        self.assertIn('M48,58 L60,58 L54,65 Z', paths[3].attrib[ns + 'pathData'])
        self.assertIn('M54,74 C44,74', paths[3].attrib[ns + 'pathData'])
        self.assertNotIn('M36,86 C34,90', ''.join(p.attrib.get(ns+'pathData','') for p in paths))
        self.assertIn('@drawable/penguin_monochrome', launcher.read_text())
        self.assertIn('R.drawable.penguin_quick_tile', self.tile_code())
        services = self.root.findall('./application/service')
        self.assertEqual(services[0].attrib[ns + 'icon'], '@drawable/penguin_quick_tile')

    def test_tile_unlocks_before_security_sensitive_toggle(self):
        code = self.tile_code()
        self.assertIn('if (isLocked) unlockAndRun', code)
        self.assertIn('rootMutex.withLock { client.toggleProtection() }', code)
        self.assertNotIn('startForeground(', code)

    def test_active_tile_never_requests_root_to_render(self):
        code = self.tile_code()
        listening = code.split('override fun onStartListening()', 1)[1].split('override fun onClick()', 1)[0]
        self.assertIn('TileStatusStore.read(applicationContext)', listening)
        self.assertNotIn('inspectDashboard()', listening)
        self.assertNotIn('toggleProtection()', listening)
        self.assertNotIn('withContext(Dispatchers.IO)', listening)
        self.assertNotIn('client.inspectDashboard()', code)
        self.assertIn('override fun onTileAdded()', code)
        self.assertIn('TileStatusStore.request(applicationContext)', code)
        self.assertNotIn('delay(', code)

    def test_cached_status_cannot_drive_kernel_toggle(self):
        code = self.tile_code()
        self.assertIn('client.toggleProtection()', code)
        self.assertNotIn('client.changeProtection(', code)
        self.assertIn('TileStatusStore.read(applicationContext)', code)
        self.assertIn('Tile.STATE_ACTIVE', code)
        self.assertIn('Tile.STATE_INACTIVE', code)
        self.assertIn('Tile.STATE_UNAVAILABLE', code)
        self.assertIn('Not verified this boot', code)
        self.assertNotIn('Verified now', code)

    def test_tile_cache_only_changes_on_existing_root_actions(self):
        client = self.client_code()
        self.assertIn('}).also { TileStatusStore.publish(context, it.snapshot) }', client)
        self.assertIn('}).also { TileStatusStore.publish(context, it.dashboard.snapshot) }', client)
        self.assertIn('ProcessBuilder("su", "-c", command)', client)
        store = self.store_code()
        self.assertIn('TileService.requestListeningState(', store)
        self.assertIn('ComponentName(context, FirewallTileService::class.java)', store)
        self.assertIn('SystemClock.elapsedRealtime()', store)
        self.assertIn('MAX_BOOT_DRIFT_MS', store)
        self.assertIn('.commit()', store)
        self.assertNotIn('ProcessBuilder(', store)
        self.assertNotIn('su -c', store)
        self.assertNotIn('Thread.sleep(', store)

    def test_tile_boot_freshness_and_timestamp_are_explicit(self):
        store = self.store_code()
        self.assertIn('savedEpoch <= 0L', store)
        self.assertIn('abs((now - uptime) - savedEpoch) > MAX_BOOT_DRIFT_MS', store)
        self.assertIn('return null', store)
        code = self.tile_code()
        self.assertIn('DateFormat.getDateTimeInstance(', code)
        self.assertIn('Checked $checkedAt', code)


if __name__ == '__main__':
    unittest.main()
