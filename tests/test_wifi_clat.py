"""Wi-Fi CLAT coverage through the real engine/bridge, on a disposable fake kernel."""
import unittest
from test_security_regressions import BridgeAudit

HOOK = '-i v4-wlan+ -m comment --comment PocketUFW -j POCKETUFW_IN'


class WifiClat(BridgeAudit):
    def test_install_and_report_cover_wifi_clat_in_both_families(self):
        self.device.add_command('ip', '#!/bin/sh\ncase "$*" in\n'
            '"-o link") echo "8: v4-wlan0: <POINTOPOINT,UP,LOWER_UP> mtu 1500";;\n'
            '"-o addr") echo "8: v4-wlan0 inet 192.0.0.4/32 scope global v4-wlan0";; esac\n')
        values = self.bridge('enable')
        self.assertEqual(values['state'], 'ACTIVE')
        self.assertEqual(values['uncovered_ifaces'], '')
        for fam, number in (('iptables', 4), ('ip6tables', 6)):
            self.assertIn(HOOK, self.chain(fam, 'INPUT'))
            self.assertEqual(values[f'hook{number}_04'], '-A INPUT ' + HOOK)

    def test_missing_wifi_clat_hook_cannot_verify_active(self):
        self.bridge('enable')
        path = self.kernel / 'ip6tables.INPUT'
        path.write_text(path.read_text().replace(HOOK + '\n', ''))
        values = self.bridge('inspect')
        self.assertEqual(values['state'], 'DEGRADED')
        self.assertEqual(values['physical_state'], 'DEGRADED')

    def test_cleanup_removes_only_owned_signatures_and_keeps_oem_rules(self):
        before = {}
        for fam in ('iptables', 'ip6tables'):
            path = self.kernel / (fam + '.INPUT')
            path.write_text(path.read_text() + '-i v4-wlan+ -m comment --comment OEM -j ACCEPT\n'
                '-i v4-wlan0 -m comment --comment Carrier -j DROP\n')
            before[fam] = path.read_text()
        self.bridge('enable')
        for fam in before:
            self.assertIn(HOOK, self.chain(fam, 'INPUT'))
        self.assertEqual(self.bridge('disable')['state'], 'INACTIVE')
        for fam, rules in before.items():
            self.assertEqual((self.kernel / (fam + '.INPUT')).read_text(), rules)

    def test_report_fits_four_physical_and_eight_tunnel_hooks(self):
        self.authorized_tunnel()
        for i in range(7):
            path = self.root / 'sys' / f'wg{i}'
            path.mkdir()
            (path / 'uevent').write_text('DEVTYPE=wireguard\n')
        values = self.bridge('tunnel-refresh')
        self.assertEqual(values['operation'], 'SUCCESS')
        self.assertEqual(values['rules_report'], 'READY')
        for fam in (4, 6):
            self.assertEqual(len([k for k in values if k.startswith(f'hook{fam}_')]), 12)

    def test_legacy_three_hook_install_can_still_be_removed(self):
        self.bridge('enable')
        for fam in ('iptables', 'ip6tables'):
            p = self.kernel / (fam + '.INPUT')
            p.write_text(p.read_text().replace(HOOK + '\n', ''))
        self.assertEqual(self.bridge('inspect')['state'], 'DEGRADED')
        self.assertEqual(self.bridge('disable')['state'], 'INACTIVE')


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(WifiClat(n) for n in WifiClat.__dict__ if n.startswith('test_'))
