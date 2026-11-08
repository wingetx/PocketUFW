"""Regressions for the independent review at ebe9019; disposable devices only."""
import unittest

from test_tunnel_filter import Base, HOOK_TUN
from test_security_regressions import BridgeAudit
from test_bootctl import BootTests


class Modes(Base):
    def test_explicit_deny_only_needs_no_tailscale_and_accepts_tun_named_wireguard(self):
        self.device('tun5', wireguard=True)
        self.ok('enable')
        self.ok('tunnel-on', '--deny-only')
        self.assertEqual(self.verify(), 'ACTIVE')
        for family in ('iptables', 'ip6tables'):
            self.assertEqual(self.read(family, 'POCKETUFW_VPN'),
                             '-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n'
                             '-m conntrack --ctstate INVALID -j DROP\n-j DROP\n')
        self.assertIn('tailnet_trust=DENY_ONLY', self.ok('activity'))

    def test_deny_only_never_switches_to_trust_when_tailscale_appears(self):
        self.ok('enable')
        self.ok('tunnel-on', '--deny-only')
        self.proven_tailscale()
        before = self.read('iptables', 'POCKETUFW_VPN')
        self.ok('tunnel-refresh')
        self.assertEqual(self.read('iptables', 'POCKETUFW_VPN'), before)
        self.assertIn('tailnet_current=DENY_ONLY', self.ok('tunnel-status'))

    def test_failed_authorization_never_falls_back_to_deny_only(self):
        self.ok('enable')
        self.assertNotEqual(self.run_cmd('tunnel-on').returncode, 0)
        self.tunnel_chains_absent()

    def test_mixed_modes_are_degraded(self):
        self.proven_tailscale()
        self.ok('enable')
        self.ok('tunnel-on')
        rules = self.read('ip6tables', 'POCKETUFW_VPN').splitlines(True)
        self.write('ip6tables', 'POCKETUFW_VPN', ''.join(rules[1:]))
        self.assertEqual(self.verify(), 'DEGRADED')

    def test_status_uses_only_two_android_ownership_scans(self):
        self.proven_tailscale()
        self.ok('enable')
        self.ok('tunnel-on')
        calls = self.base / 'probe-calls'
        self.script('dumpsys', f'#!/bin/sh\necho call >> "{calls}"\ncat "$PUFW_TEST_DIR/dumpsys.txt"\n')
        self.ok('tunnel-status')
        self.assertLessEqual(len(calls.read_text().splitlines()), 2)


class Bridge(BridgeAudit):
    def test_stale_pins_reach_bridge_without_degrading_rule_protection(self):
        self.authorized_tunnel()
        ip = self.device.bin / 'ip'
        ip.write_text(ip.read_text().replace('100.64.0.1/32', '100.64.0.9/32'))
        values = self.bridge('inspect')
        self.assertEqual(values['state'], 'ACTIVE')
        self.assertEqual(values.get('tailnet_current'), 'REAUTHORIZE')
        self.assertEqual(values.get('tailnet_pin4'), '100.64.0.1/32')
        self.assertEqual(values.get('tailnet_observed4'), '100.64.0.9/32')

    def test_tunnel_recovery_preserves_physical_rules_and_boot_opt_in(self):
        self.authorized_tunnel()
        self.assertEqual(self.bridge('boot-enable')['operation'], 'SUCCESS')
        before = {(fam, chain): self.chain(fam, chain) for fam in ('iptables', 'ip6tables')
                  for chain in ('POCKETUFW_IN', 'POCKETUFW_TS')}
        path = self.kernel / 'ip6tables.INPUT'
        path.write_text(path.read_text().replace(HOOK_TUN + '\n', ''))
        self.assertEqual(self.bridge('inspect')['state'], 'DEGRADED')
        result = self.bridge('tunnel-off')
        self.assertEqual(result['operation'], 'SUCCESS')
        self.assertEqual(result['state'], 'ACTIVE')
        self.assertEqual(result['boot'], 'ENABLED')
        for (fam, chain), expected in before.items():
            self.assertEqual(self.chain(fam, chain), expected)
        self.assertFalse((self.kernel / 'iptables.POCKETUFW_VPN').exists())

    def test_failed_tunnel_cleanup_does_not_remove_physical_policy(self):
        self.authorized_tunnel()
        self.bridge('boot-enable')
        before = {fam: self.chain(fam, 'POCKETUFW_IN') for fam in ('iptables', 'ip6tables')}
        result = self.bridge('tunnel-off', env={'PUFW_TEST_FAIL': '-X POCKETUFW_VPN',
                                              'PUFW_TEST_FAIL_FAMILY': 'ip6tables'})
        self.assertEqual(result['operation'], 'FAILED')
        self.assertEqual(result['state'], 'DEGRADED')
        self.assertEqual(result['tunnel_filter'], 'DEGRADED')
        self.assertEqual(result['boot'], 'ENABLED')
        for fam, rules in before.items():
            self.assertEqual(self.chain(fam, 'POCKETUFW_IN'), rules)
        self.assertEqual(self.bridge('tunnel-off')['operation'], 'SUCCESS')


class BootContention(BootTests):
    def test_boot_retries_beyond_normal_lock_window(self):
        self.assertEqual(self.call('enable').returncode, 0)
        self.state.write_text('INACTIVE\n')
        real_flock = '/usr/bin/flock'
        attempts = self.root / 'attempts'
        shim = self.fakebin / 'flock'
        shim.write_text(f'#!/bin/sh\nn=$(cat "{attempts}" 2>/dev/null || echo 0)\nn=$((n+1))\n'
                        f'echo "$n" > "{attempts}"\n[ "$n" -gt 170 ] || exit 1\nexec {real_flock} "$@"\n')
        shim.chmod(0o700)
        self.assertEqual(self.boot().returncode, 0)
        self.assertEqual(self.state.read_text().strip(), 'ACTIVE')

    def test_disarming_during_lock_wait_cancels_restore(self):
        self.assertEqual(self.call('enable').returncode, 0)
        self.state.write_text('INACTIVE\n')
        shim = self.fakebin / 'flock'
        shim.write_text('#!/bin/sh\nexit 1\n')
        shim.chmod(0o700)
        result = self.boot({'TEST_REMOVE_WHILE_SLEEPING': str(self.store / 'boot.enabled')})
        self.assertEqual(result.returncode, 0)
        self.assertFalse(self.calls.exists())


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(cls(name) for cls in (Modes, Bridge, BootContention)
                              for name in cls.__dict__ if name.startswith('test_'))
