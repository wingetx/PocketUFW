"""Authorization and lifetime of the optional, address-only tailnet pins."""
import shutil
import unittest

from test_tunnel_filter import Base, TAILNET, FAKE_IP


class PinnedTrust(Base):
    def install(self):
        self.proven_tailscale()
        self.ok('enable')
        self.ok('tunnel-on')

    def test_only_verified_node_destinations_are_authorized(self):
        self.install()
        for family, pin in [('iptables', '100.64.0.1/32'), ('ip6tables', 'fd7a:115c:a1e0::1/128')]:
            rules = self.read(family, 'POCKETUFW_VPN')
            self.assertIn(f'-s {TAILNET[family]} -d {pin} -i tun+ -j ACCEPT', rules)
            self.assertNotIn(f'-d {TAILNET[family]} ', rules)
        status = self.ok('tunnel-status')
        self.assertIn('tailnet_trust=PINNED_DESTINATIONS', status)
        self.assertIn('tailnet_ingress=ADDRESS_ONLY', status)

    def test_initial_authorization_requires_live_ownership(self):
        self.ok('enable')
        for command in ('tunnel-plan', 'tunnel-on'):
            self.assertNotEqual(self.run_cmd(command).returncode, 0)
            self.tunnel_chains_absent()

    def test_android_claim_without_matching_uid_cannot_authorize(self):
        self.proven_tailscale(uid=10999)
        self.ok('enable')
        self.assertNotEqual(self.run_cmd('tunnel-on').returncode, 0)
        self.tunnel_chains_absent()

    def test_failed_dumpsys_cannot_authorize_from_partial_output(self):
        self.proven_tailscale()
        self.script('dumpsys', '#!/bin/sh\ncat "$PUFW_TEST_DIR/dumpsys.txt"\nexit 1\n')
        self.ok('enable')
        self.assertNotEqual(self.run_cmd('tunnel-on').returncode, 0)
        self.tunnel_chains_absent()

    def test_missing_or_ambiguous_addresses_never_install_partial_trust(self):
        self.proven_tailscale()
        self.ok('enable')
        for addresses in [('100.64.0.1',), ('fd7a:115c:a1e0::1',),
                          ('100.64.0.1', '100.64.0.2', 'fd7a:115c:a1e0::1'),
                          ('10.0.0.1', 'fd7a:115c:a1e0::1')]:
            with self.subTest(addresses=addresses):
                self.holds('tun1', *addresses)
                self.assertNotEqual(self.run_cmd('tunnel-on').returncode, 0)
                self.tunnel_chains_absent()

    def test_multiple_verified_tailscale_interfaces_are_ambiguous(self):
        self.proven_tailscale('tun1')
        self.proven_tailscale('tun2')
        self.android_says(('com.tailscale.ipn', 'tun1'), ('com.tailscale.ipn', 'tun2'))
        self.ok('enable')
        self.assertNotEqual(self.run_cmd('tunnel-on').returncode, 0)
        self.tunnel_chains_absent()

    def test_interface_reuse_during_authorization_refuses_before_rule_changes(self):
        self.proven_tailscale()
        self.ok('enable')
        self.script('ip', FAKE_IP + '\necho 999 > "$POCKETUFW_SYS_NET/tun1/ifindex"\n')
        self.assertNotEqual(self.run_cmd('tunnel-on').returncode, 0)
        self.tunnel_chains_absent()

    def test_partial_address_output_and_failed_ownership_recheck_do_not_authorize(self):
        self.proven_tailscale()
        self.ok('enable')
        for suffix in ['\nexit 1\n', '\nrm "$POCKETUFW_PROC_ROOT/1000/fdinfo/138"\n']:
            with self.subTest(suffix=suffix):
                self.script('ip', FAKE_IP + suffix)
                self.assertNotEqual(self.run_cmd('tunnel-on').returncode, 0)
                self.tunnel_chains_absent()

    def test_final_address_read_must_succeed_and_keep_the_same_interface(self):
        self.proven_tailscale()
        self.ok('enable')
        marker = self.base / 'address-read'
        for final_action in ['exit 1', 'echo 999 > "$POCKETUFW_SYS_NET/tun1/ifindex"']:
            with self.subTest(final_action=final_action):
                marker.unlink(missing_ok=True)
                self.script('ip', FAKE_IP + f'\nif [ -e "{marker}" ]; then {final_action}; else : > "{marker}"; fi\n')
                try:
                    self.assertNotEqual(self.run_cmd('tunnel-on').returncode, 0)
                    self.tunnel_chains_absent()
                finally:
                    self.ok('tunnel-off')

    def test_kernel_wireguard_cannot_be_authorized_by_an_android_claim(self):
        self.proven_tailscale()
        (self.sys / 'tun1' / 'uevent').write_text('DEVTYPE=wireguard\n')
        self.ok('enable')
        self.assertNotEqual(self.run_cmd('tunnel-on').returncode, 0)
        self.tunnel_chains_absent()

    def test_pins_survive_disconnect_and_interface_renumbering(self):
        self.install()
        before = {f: self.read(f, 'POCKETUFW_VPN') for f in TAILNET}
        shutil.rmtree(self.sys / 'tun1')
        shutil.rmtree(self.proc)
        self.proc.mkdir()
        self.android_says()
        self.ok('tunnel-refresh')
        self.assertEqual(self.verify(), 'ACTIVE')
        self.proven_tailscale('tun8')
        self.assertIn('tailnet_current=MATCH', self.ok('tunnel-status'))
        for family, rules in before.items():
            self.assertEqual(self.read(family, 'POCKETUFW_VPN'), rules)

    def test_new_addresses_require_explicit_reauthorization(self):
        self.install()
        before = {f: self.read(f, 'POCKETUFW_VPN') for f in TAILNET}
        self.holds('tun1', '100.99.1.2', 'fd7a:115c:a1e0::99')
        self.ok('tunnel-refresh')
        self.assertIn('tailnet_current=REAUTHORIZE', self.ok('tunnel-status'))
        for family, rules in before.items():
            self.assertEqual(self.read(family, 'POCKETUFW_VPN'), rules)
        self.ok('tunnel-off')
        self.ok('tunnel-on')
        self.assertIn('-d 100.99.1.2/32 ', self.read('iptables', 'POCKETUFW_VPN'))

    def test_failed_reauthorization_never_falls_back_to_previous_or_range_trust(self):
        self.install()
        self.ok('tunnel-off')
        self.android_says()
        self.assertNotEqual(self.run_cmd('tunnel-on').returncode, 0)
        self.tunnel_chains_absent()
        self.assertEqual(self.verify(), 'ACTIVE')

    def test_kernel_wireguard_named_tun_cannot_authorize_or_coexist_at_enable(self):
        self.proven_tailscale()
        self.device('tun5', wireguard=True)
        self.ok('enable')
        self.assertNotEqual(self.run_cmd('tunnel-on').returncode, 0)
        self.tunnel_chains_absent()

    def test_later_tun_named_wireguard_is_reported_as_a_live_conflict(self):
        self.install()
        self.device('tun5', wireguard=True)
        self.assertEqual(self.verify(), 'DEGRADED')
        status = self.ok('tunnel-status')
        self.assertIn('tailnet_wireguard=CONFLICT', status)
        self.assertIn('tailnet_ingress=ADDRESS_ONLY', status)
        self.assertNotIn('tunnel_filter=ON', status)
        self.assertNotEqual(self.run_cmd('tunnel-refresh').returncode, 0)
        self.ok('tunnel-off')

    def test_legacy_whole_range_rules_are_degraded_not_silently_migrated(self):
        self.install()
        for family, pin in [('iptables', '100.64.0.1/32'), ('ip6tables', 'fd7a:115c:a1e0::1/128')]:
            self.write(family, 'POCKETUFW_VPN', self.read(family, 'POCKETUFW_VPN').replace(
                f'-d {pin} ', f'-d {TAILNET[family]} '))
        self.assertEqual(self.verify(), 'DEGRADED')
        self.assertNotEqual(self.run_cmd('tunnel-refresh').returncode, 0)
        self.ok('tunnel-off')


if __name__ == '__main__':
    unittest.main()
