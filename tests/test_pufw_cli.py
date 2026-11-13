"""Optional Termux companion: fake su responses and existing mock-kernel reads only."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_tunnel_filter import Base, ROOT

HELPER = ROOT / 'tools' / 'pufw'
SU = '#!/bin/sh\n[ "$1" = -c ] || exit 99\necho su >> "$CLI_LOG"\nexec sh -c "$2"\n'


def snapshot(**changes):
    values = dict(
        state='ACTIVE', physical_state='ACTIVE', hook_patterns='wlan+ rmnet+ v4-rmnet+ v4-wlan+',
        tunnel_filter='ON', tunnel_mode='PINNED', tailnet_trust='PINNED_DESTINATIONS',
        tailnet_ingress='ADDRESS_ONLY', tailnet_wireguard='NONE_OBSERVED',
        tailnet_pin4='100.64.0.1/32', tailnet_pin6='fd7a:115c:a1e0::1/128',
        tailnet_observed4='100.64.0.1/32', tailnet_observed6='fd7a:115c:a1e0::1/128',
        tailnet_current='MATCH', tunnel_hooks='tun+,wg0',
        ipv4_blocked='1204', ipv6_blocked='80', ipv4_blocked_bytes='98664', ipv6_blocked_bytes='31820',
        ipv4_established_replies='48100', ipv6_established_replies='191',
        ipv4_tunnel_blocked='30', ipv6_tunnel_blocked='7',
        ipv4_tunnel_blocked_bytes='3000', ipv6_tunnel_blocked_bytes='700',
        ipv4_tunnel_established_replies='200', ipv6_tunnel_established_replies='41',
        ipv4_tunnel_tailnet='137', ipv6_tunnel_tailnet='148',
    )
    values.update(changes)
    return values


class PufwCliTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='pufw-cli-')
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        self.log = self.base / 'calls'
        self.response = self.base / 'response'
        self.engine = self.base / 'pocketufw'
        self.engine.write_text('#!/bin/sh\necho "$1" >> "$CLI_LOG"\ncat "$CLI_RESPONSE"\nexit "${CLI_EXIT:-0}"\n')
        self.script('su', SU)
        self.script('id', '#!/bin/sh\necho "${CLI_UID:-0}"\n')
        self.env = {**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}',
                    'PUFW_ENGINE': str(self.engine), 'CLI_RESPONSE': str(self.response), 'CLI_LOG': str(self.log)}

    def script(self, name, text):
        path = self.bin / name
        path.write_text(text)
        path.chmod(0o755)

    def run_cli(self, *args, values=None, text=None, native_exit=0, extra=None):
        if values is None:
            values = snapshot()
        if text is None:
            text = ''.join(f'{k}={v}\n' for k, v in values.items())
            text += 'tunnel_status=READY\n' if args == ('tunnel',) else '' if args == ('stats',) else 'inspection=READY\n'
        self.response.write_text(text)
        return subprocess.run(['/bin/sh', str(HELPER), *args], text=True, capture_output=True, timeout=5,
                              env=self.env | {'CLI_EXIT': str(native_exit)} | (extra or {}))

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_four_views_each_make_only_one_native_read(self):
        for args, native in [((), 'inspect'), (('tunnel',), 'tunnel-status'), (('stats',), 'activity'), (('raw',), 'inspect')]:
            with self.subTest(args=args):
                self.log.unlink(missing_ok=True)
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.calls(), ['su', native])

    def test_help_and_invalid_arguments_never_request_root(self):
        for args, status in [(('--help',), 0), (('-h',), 0), (('enable',), 2), (('disable',), 2),
                             (('reset-counters',), 2), (('status',), 2), (('tunnel', '--on'), 2),
                             (('raw', 'enable'), 2), (('; touch nope',), 2)]:
            with self.subTest(args=args):
                self.assertEqual(self.run_cli(*args).returncode, status)
                self.assertEqual(self.calls(), [])

    def test_engine_override_is_not_shell_code(self):
        for path in ['relative/pocketufw', '/tmp/a b', '/tmp/a;touch-nope', '/tmp/$(id)', "/tmp/a'b", '/tmp/a\nb']:
            self.assertEqual(self.run_cli(extra={'PUFW_ENGINE': path}).returncode, 2)
            self.assertEqual(self.calls(), [])

    def test_default_formats_counts_without_claiming_universal_coverage(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        for text in ['● PocketUFW ACTIVE', 'Physical: Rules verified', 'Tunnel: PINNED (rules verified)',
                     'Coverage: Filtered where supported', 'Physical drops: 1,284 packets',
                     'Physical return traffic: 48,291 packets', 'Tunnel drops: 37 packets',
                     'Tunnel return traffic: 241 packets', 'MATCH; addresses verified in this inspection',
                     'Earlier Android rules and unsupported interfaces can bypass filtering.']:
            self.assertIn(text, result.stdout)

    def test_stats_has_bytes_and_never_claims_current_address_verification(self):
        result = self.run_cli('stats')  # Even a stray MATCH field cannot authorize this view.
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Physical drops: 1,284 packets / 130,484 bytes', result.stdout)
        self.assertIn('Tunnel drops: 37 packets / 3,700 bytes', result.stdout)
        self.assertIn('Current addresses not checked; use pufw tunnel', result.stdout)
        self.assertNotIn('MATCH', result.stdout)
        self.assertIn('Tunnel return traffic: 241 packets', result.stdout)  # Not the 285 tailnet exemptions.

    def test_large_decimal_totals_are_exact_and_zero_is_a_measurement(self):
        a, b = 9007199254740993, 9007199254740995
        result = self.run_cli('stats', values=snapshot(ipv4_blocked=str(a), ipv6_blocked=str(b),
            ipv4_tunnel_blocked='0', ipv6_tunnel_blocked='0'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'Physical drops: {a + b:,} packets', result.stdout)
        self.assertIn('Tunnel drops: 0 packets', result.stdout)

    def test_missing_or_invalid_counters_are_never_replaced_by_zero(self):
        for bad in [None, '', '-1', 'NaN', '3e6', '1.5', '18446744073709551616']:
            with self.subTest(counter=bad):
                values = snapshot(ipv6_blocked=bad)
                if bad is None:
                    del values['ipv6_blocked']
                result = self.run_cli(values=values)
                self.assertEqual(result.returncode, 1)
                self.assertIn('Physical drops: Unavailable', result.stdout)
                self.assertNotIn('Physical drops: 0', result.stdout)
                self.assertEqual(self.run_cli('stats', values=values).returncode, 1)
                self.assertIn('UNKNOWN', self.run_cli('stats', values=values).stdout)

    def test_truncated_duplicate_failed_or_unlocked_results_are_unknown(self):
        base = ''.join(f'{k}={v}\n' for k, v in snapshot().items())
        for text, code in [(base, 0), (base + 'state=ACTIVE\ninspection=READY\n', 0),
                           (base + 'inspection=READY\ntrailing data\n', 0),
                           (base + 'inspection=READY\n', 5),
                           ('pocketufw: reading without the lock\n' + base + 'inspection=READY\n', 0)]:
            result = self.run_cli(text=text, native_exit=code)
            self.assertEqual(result.returncode, 1)
            self.assertIn('PocketUFW UNKNOWN', result.stdout)
            self.assertNotIn('Rules verified', result.stdout)
            self.assertNotIn('Physical drops:', result.stdout)

    def test_inconsistent_verdict_does_not_claim_active(self):
        for changes in [dict(physical_state='DEGRADED'), dict(tunnel_filter='DEGRADED'),
                        dict(tunnel_filter='OFF'), dict(tunnel_mode='UNKNOWN')]:
            result = self.run_cli(values=snapshot(**changes))
            self.assertEqual(result.returncode, 1)
            self.assertIn('PocketUFW UNKNOWN', result.stdout)

    def test_inactive_and_degraded_discard_any_leaked_counters(self):
        inactive = snapshot(state='INACTIVE', physical_state='INACTIVE', tunnel_filter='OFF', tunnel_mode='OFF')
        for view, values, native_exit, expected_exit in [
            ((), inactive, 0, 0), (('stats',), {'state': 'INACTIVE'}, 3, 0),
            ((), snapshot(state='DEGRADED', tunnel_filter='DEGRADED'), 0, 1),
            (('stats',), {'state': 'DEGRADED', 'ipv4_blocked': '999'}, 4, 1)
        ]:
            result = self.run_cli(*view, values=values, native_exit=native_exit)
            self.assertEqual(result.returncode, expected_exit, result.stderr)
            self.assertIn('Counters: Unavailable', result.stdout)
            self.assertNotIn('Physical drops:', result.stdout)
            self.assertNotIn('Tunnel drops:', result.stdout)

    def test_partial_tunnel_failure_preserves_verified_physical_scope(self):
        result = self.run_cli(values=snapshot(state='DEGRADED', tunnel_filter='DEGRADED'))
        self.assertIn('PocketUFW DEGRADED', result.stdout)
        self.assertIn('Physical: Rules verified', result.stdout)
        self.assertIn('Tunnel: DEGRADED / full ruleset not verified', result.stdout)
        self.assertNotIn('MATCH;', result.stdout)

    def test_stale_pins_are_actionable_without_withdrawing_verified_rules(self):
        for view in [(), ('tunnel',)]:
            result = self.run_cli(*view, values=snapshot(tailnet_current='REAUTHORIZE', tailnet_observed4='100.64.0.9/32'))
            self.assertEqual(result.returncode, 1)
            self.assertIn('REAUTHORIZE; addresses changed, installed rules unchanged', result.stdout)
            self.assertNotIn('MATCH;', result.stdout)
            if view:
                self.assertIn('Saved destinations: 100.64.0.1/32', result.stdout)
                self.assertIn('Observed addresses: 100.64.0.9/32', result.stdout)

    def test_incomplete_or_contradictory_address_evidence_never_claims_match(self):
        for changes in [dict(tailnet_observed6=''), dict(tailnet_observed4='100.64.0.9/32'),
                        dict(tailnet_current='UNVERIFIED'), dict(tailnet_wireguard='CONFLICT'),
                        dict(inventory='UNAVAILABLE'), dict(tailnet_pin4='100.64.0.1/24')]:
            for view in [(), ('tunnel',)]:
                result = self.run_cli(*view, values=snapshot(**changes))
                self.assertEqual(result.returncode, 1)
                self.assertIn('Authorization: UNVERIFIED', result.stdout)
                self.assertNotIn('MATCH;', result.stdout)
        result = self.run_cli('tunnel', text='tunnel_filter=ON\ntunnel_mode=PINNED\ntailnet_current=MATCH\n')
        self.assertIn('UNKNOWN', result.stdout)
        self.assertNotIn('MATCH;', result.stdout)

    def test_deny_only_and_off_do_not_invent_pin_authorization(self):
        deny = snapshot(tunnel_mode='DENY_ONLY', tailnet_trust='DENY_ONLY', tailnet_current='DENY_ONLY')
        result = self.run_cli('tunnel', values=deny)
        self.assertEqual(result.returncode, 0)
        self.assertIn('Tunnel: DENY-ONLY (rules verified)', result.stdout)
        self.assertIn('DENY-ONLY; no tailnet exemption', result.stdout)
        self.assertNotIn('Saved destinations', result.stdout)
        result = self.run_cli(values=snapshot(tunnel_filter='OFF', tunnel_mode='OFF'))
        self.assertEqual(result.returncode, 0)
        self.assertIn('Tunnel counters: Not installed (not zero)', result.stdout)

    def test_tunnel_view_keeps_packet_authentication_and_session_limits_clear(self):
        result = self.run_cli('tunnel')
        self.assertEqual(result.returncode, 0)
        self.assertIn('PINNED trusts addresses, not individual packets or ingress interface ownership.', result.stdout)
        self.assertIn('Session only; tunnel filtering never restores after reboot.', result.stdout)

    def test_unavailable_probe_vetoes_match_even_with_contradictory_fields(self):
        text = 'vpn-probe: one verified Tailscale tun with both node addresses is required\n'
        text += ''.join(f'{k}={v}\n' for k, v in snapshot().items()) + 'tunnel_status=READY\n'
        result = self.run_cli('tunnel', text=text)
        self.assertEqual(result.returncode, 1)
        self.assertIn('Authorization: UNVERIFIED', result.stdout)
        self.assertNotIn('MATCH;', result.stdout)

    def test_root_denial_and_missing_engine_are_not_inactive(self):
        for extra, expected in [({'CLI_UID': '2000'}, 'Root access was not granted'),
                                ({'PUFW_ENGINE': '/not/a/pocketufw/engine'}, 'engine unavailable')]:
            result = self.run_cli(extra=extra)
            self.assertEqual(result.returncode, 1)
            self.assertIn(expected, result.stderr)
            self.assertNotIn('INACTIVE', result.stdout)
        self.script('su', '#!/bin/sh\necho "Permission denied" >&2\nexit 1\n')
        result = self.run_cli()
        self.assertIn('UNKNOWN', result.stdout)
        self.assertIn('Check root access', result.stderr)

    def test_timeout_discards_even_a_successful_looking_partial_read(self):
        self.script('timeout', '#!/bin/sh\necho state=ACTIVE\necho inspection=READY\nexit 137\n')
        result = self.run_cli()
        self.assertEqual(result.returncode, 1)
        self.assertIn('timed out', result.stderr)
        self.assertNotIn('ACTIVE', result.stdout)
        self.assertEqual(self.calls(), [])

    def test_missing_dependency_stops_before_requesting_root(self):
        result = self.run_cli(extra={'PATH': str(self.bin)})
        self.assertEqual(result.returncode, 1)
        self.assertIn('Required command unavailable: timeout', result.stderr)
        self.assertEqual(self.calls(), [])

    def test_raw_preserves_native_evidence_and_marks_partial_output(self):
        result = self.run_cli('raw')
        self.assertEqual(result.stdout, self.response.read_text())
        self.assertEqual(result.returncode, 0)
        result = self.run_cli('raw', text='state=ACTIVE\n')
        self.assertEqual(result.stdout, 'state=ACTIVE\n')
        self.assertEqual(result.returncode, 1)
        self.assertIn('Could not verify', result.stderr)

    def test_raw_exit_status_keeps_missing_measurements_and_stale_authorization_visible(self):
        for values in [snapshot(ipv4_blocked_bytes=''), snapshot(tailnet_current='UNVERIFIED'),
                       snapshot(tailnet_current='REAUTHORIZE', tailnet_observed4='100.64.0.9/32')]:
            result = self.run_cli('raw', values=values)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, self.response.read_text())


class PufwNativeReadOnlyTests(Base):
    """Execute real native read paths against disposable fake iptables/proc/sys."""
    def cli(self, *args):
        log = self.base / 'cli-calls'
        self.script('su', SU)
        return subprocess.run(['sh', str(HELPER), *args], text=True, capture_output=True, timeout=35,
                              env=self.env | {'PUFW_ENGINE': str(ROOT / 'pocketufw'), 'CLI_LOG': str(log)})

    def kernel_files(self):
        return {p.name: p.read_bytes() for p in self.base.glob('ip*.*') if p.is_file()}

    def test_native_inactive_reads_do_not_install_any_rules(self):
        before = self.kernel_files()
        for args in [(), ('stats',), ('tunnel',), ('raw',)]:
            result = self.cli(*args)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(self.kernel_files(), before)

    def test_native_pinned_reads_do_not_change_rules_or_counters(self):
        self.proven_tailscale()
        self.ok('enable')
        self.ok('tunnel-on')
        before = self.kernel_files()
        for args in [(), ('stats',), ('tunnel',), ('raw',)]:
            result = self.cli(*args)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(self.kernel_files(), before)
        self.assertIn('MATCH; addresses verified', self.cli('tunnel').stdout)
        self.holds('tun1', '100.64.0.9', 'fd7a:115c:a1e0::9')
        stale = self.cli()
        self.assertEqual(stale.returncode, 1)
        self.assertIn('REAUTHORIZE;', stale.stdout)
        self.assertEqual(self.kernel_files(), before)

    def test_native_degraded_read_keeps_physical_verification_without_repair(self):
        self.proven_tailscale()
        self.ok('enable')
        self.ok('tunnel-on')
        path = self.base / 'ip6tables.INPUT'
        path.write_text(path.read_text().replace('-i tun+ -m comment --comment PocketUFW-VPN -j POCKETUFW_VPN\n', ''))
        before = self.kernel_files()
        result = self.cli()
        self.assertEqual(result.returncode, 1)
        self.assertIn('Physical: Rules verified', result.stdout)
        self.assertIn('PocketUFW DEGRADED', result.stdout)
        self.assertNotIn('Physical drops:', result.stdout)
        self.assertEqual(self.kernel_files(), before)

    def test_native_deny_only_needs_no_tailscale_authorization(self):
        self.ok('enable')
        self.ok('tunnel-on', '--deny-only')
        before = self.kernel_files()
        for args in [(), ('stats',), ('tunnel',), ('raw',)]:
            result = self.cli(*args)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(self.kernel_files(), before)
        self.assertIn('DENY-ONLY; no tailnet exemption', self.cli('tunnel').stdout)

    def test_native_counter_failure_is_unknown_without_zeroing_or_retrying(self):
        self.ok('enable')
        before = self.kernel_files()
        self.env['PUFW_TEST_LIST_FAIL'] = '1'
        for args in [(), ('stats',)]:
            result = self.cli(*args)
            self.assertEqual(result.returncode, 1)
            self.assertIn('UNKNOWN', result.stdout)
            self.assertNotIn('Physical drops:', result.stdout)
            self.assertEqual(self.kernel_files(), before)


if __name__ == '__main__':
    unittest.main()
