"""Tide's tunnel actions drive the real scripts on a disposable fake kernel."""
import unittest

from test_security_regressions import BridgeAudit
from test_tunnel_filter import HOOK_TUN


class TideTunnels(BridgeAudit):
    def physical_rules(self):
        return {(fam, chain): self.chain(fam, chain)
                for fam in ('iptables', 'ip6tables')
                for chain in ('POCKETUFW_IN', 'POCKETUFW_TS')}

    def test_modes_require_an_explicit_choice_and_pinned_never_falls_back(self):
        self.bridge('enable')
        before = self.physical_rules()
        for args in ((), ('UNKNOWN',), ('--deny-only',), ('PINNED', 'extra')):
            self.assertEqual(self.script('android-bridge', 'tunnel-on', *args).returncode, 2)
        failed = self.bridge('tunnel-on', 'PINNED')
        self.assertEqual(failed['operation'], 'FAILED')
        self.assertEqual(failed['tunnel_filter'], 'OFF')
        deny = self.bridge('tunnel-on', 'DENY_ONLY')
        self.assertEqual(deny['operation'], 'SUCCESS')
        self.assertEqual(deny['tailnet_trust'], 'DENY_ONLY')
        self.assertEqual(self.physical_rules(), before)
        # A later mode request cannot remove or replace the existing policy.
        self.assertEqual(self.bridge('tunnel-on', 'PINNED')['operation'], 'FAILED')
        self.assertEqual(self.bridge('inspect')['tailnet_trust'], 'DENY_ONLY')

    def test_pinned_enable_and_stale_reauthorization_require_separate_removal(self):
        self.authorized_tunnel()
        self.bridge('tunnel-off')
        self.bridge('boot-enable')
        before = self.physical_rules()
        enabled = self.bridge('tunnel-on', 'PINNED')
        self.assertEqual(enabled['operation'], 'SUCCESS')
        self.assertEqual(enabled['tailnet_current'], 'MATCH')
        ip = self.device.bin / 'ip'
        ip.write_text(ip.read_text().replace('100.64.0.1/32', '100.64.0.9/32'))
        refreshed = self.bridge('tunnel-refresh')
        self.assertEqual(refreshed['operation'], 'SUCCESS')
        self.assertEqual(refreshed['tailnet_current'], 'REAUTHORIZE')
        self.assertEqual(refreshed['tailnet_pin4'], '100.64.0.1/32')
        self.assertEqual(self.bridge('tunnel-off')['operation'], 'SUCCESS')
        again = self.bridge('tunnel-on', 'PINNED')
        self.assertEqual(again['tailnet_current'], 'MATCH')
        self.assertEqual(again['tailnet_pin4'], '100.64.0.9/32')
        self.assertEqual(again['boot'], 'ENABLED')
        self.assertEqual(self.physical_rules(), before)

    def test_physical_verdict_survives_tunnel_degradation_but_not_physical_damage(self):
        self.authorized_tunnel()
        path = self.kernel / 'ip6tables.INPUT'
        path.write_text(path.read_text().replace(HOOK_TUN + '\n', ''))
        values = self.bridge('inspect')
        self.assertEqual(values['state'], 'DEGRADED')
        self.assertEqual(values['physical_state'], 'ACTIVE')
        self.assertEqual(values['tunnel_filter'], 'DEGRADED')
        path = self.kernel / 'iptables.POCKETUFW_IN'
        path.write_text(path.read_text().replace('-j DROP\n', '', 1))
        self.assertEqual(self.bridge('inspect')['physical_state'], 'DEGRADED')

    def test_counter_refresh_has_both_planes_without_vpn_observations(self):
        self.authorized_tunnel()
        calls = self.root / 'unexpected-probe'
        self.device.add_command('dumpsys', f'#!/bin/sh\ntouch "{calls}"\nexit 99\n')
        values = self.bridge('counters', env={'PUFW_TEST_DROP4': '11', 'PUFW_TEST_DROP6': '22',
            'PUFW_TEST_REPLIES4': '33', 'PUFW_TEST_TUNNEL_DROP': '44',
            'PUFW_TEST_TUNNEL_REPLIES': '55', 'PUFW_TEST_TAILNET': '66'})
        self.assertEqual(values['ipv4_blocked'], '11')
        self.assertEqual(values['ipv6_blocked'], '22')
        self.assertEqual(values['ipv4_established_replies'], '33')
        self.assertEqual(values['ipv4_tunnel_blocked'], '44')
        self.assertEqual(values['ipv6_tunnel_established_replies'], '55')
        self.assertEqual(values['ipv4_tunnel_tailnet'], '66')
        self.assertNotIn('tailnet_current', values)
        self.assertFalse(calls.exists())

    def test_one_reset_zeroes_every_owned_chain_without_rule_mutations(self):
        self.authorized_tunnel()
        before = {p.name: p.read_text() for p in self.kernel.glob('*.*')}
        values = self.bridge('reset-counters')
        self.assertEqual(values['operation'], 'SUCCESS')
        self.assertEqual(set((self.kernel / 'zero_events').read_text().splitlines()),
            {f'{fam} {chain}' for fam in ('iptables', 'ip6tables')
             for chain in ('POCKETUFW_IN', 'POCKETUFW_TS', 'POCKETUFW_VPN')})
        for name, rules in before.items():
            self.assertEqual((self.kernel / name).read_text(), rules)
        self.assertEqual(values['state'], 'ACTIVE')
        self.assertEqual(values['tunnel_filter'], 'ON')


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(TideTunnels(name) for name in TideTunnels.__dict__
                              if name.startswith('test_'))
