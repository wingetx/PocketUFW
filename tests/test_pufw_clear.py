"""Confirmed Termux resets through the real app bridge, on a disposable fake kernel."""
import subprocess
import unittest

from test_security_regressions import BridgeAudit
from test_pufw_cli import HELPER, SU


class PufwClearTests(BridgeAudit):
    def clear(self, answer='yes\n', extra=None):
        self.device.add_command('su', SU)
        return subprocess.run(['sh', str(HELPER), 'clear'], input=answer, text=True,
                              capture_output=True, timeout=35, env=self.env | {
                                  'PUFW_ENGINE': str(self.device.engine / 'pocketufw'),
                                  'CLI_LOG': str(self.root / 'cli-log'),
                              } | (extra or {}))

    def rules(self):
        return {p.name: p.read_bytes() for p in self.kernel.glob('ip*.*') if not p.name.endswith('.counters')}

    def test_clear_preserves_rules_pins_boot_and_samples_and_shares_reset_time(self):
        self.authorized_tunnel()
        self.bridge('boot-enable')
        before = self.rules()
        sample = self.device.app_data / 'saved-diagnostic.txt'
        sample.write_text('previous sample, retained by its owner')
        boot_before = {p.name: p.read_bytes() for p in self.device.store.iterdir()}
        result = self.clear()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(before, self.rules())
        self.assertEqual(boot_before, {p.name: p.read_bytes() for p in self.device.store.iterdir()})
        self.assertEqual(sample.read_text(), 'previous sample, retained by its owner')
        self.assertEqual((self.kernel / 'zero_events').read_text().splitlines(), [
            'iptables POCKETUFW_IN', 'ip6tables POCKETUFW_IN',
            'iptables POCKETUFW_TS', 'ip6tables POCKETUFW_TS',
            'iptables POCKETUFW_VPN', 'ip6tables POCKETUFW_VPN'])
        record = self.device.engine / 'counter-reset-at'
        at = record.read_text().strip()
        self.assertTrue(at.isdigit())
        self.assertEqual(record.stat().st_mode & 0o777, 0o600)
        for action in ('inspect', 'counters'):
            self.assertEqual(self.bridge(action)['last_counter_reset_at'], at)
        self.assertEqual(self.bridge('inspect')['tailnet_pin4'], '100.64.0.1/32')

    def test_cancel_inactive_degraded_and_partial_failure_do_not_advance_timestamp(self):
        record = self.device.engine / 'counter-reset-at'
        record.write_text('1700000000000\n')
        self.assertNotEqual(self.clear('').returncode, 0)
        self.assertFalse((self.root / 'cli-log').exists())
        self.assertNotEqual(self.clear().returncode, 0)  # inactive
        self.assertFalse((self.kernel / 'zero_events').exists())
        self.authorized_tunnel()
        before = self.rules()
        failed = self.clear(extra={'PUFW_TEST_FAIL_FAMILY': 'ip6tables', 'PUFW_TEST_FAIL': '-Z POCKETUFW_IN'})
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn('Some counters may have reset', failed.stderr)
        self.assertEqual(before, self.rules())
        (self.kernel / 'zero_events').unlink()
        path = self.kernel / 'ip6tables.POCKETUFW_IN'
        path.write_text(path.read_text().replace('-j DROP\n', ''))
        self.assertNotEqual(self.clear().returncode, 0)
        self.assertFalse((self.kernel / 'zero_events').exists())
        self.assertEqual(record.read_text(), '1700000000000\n')

    def test_timestamp_write_failure_is_reported_without_changing_link_target(self):
        self.authorized_tunnel()
        target = self.root / 'unrelated'
        target.write_text('keep this')
        (self.device.engine / 'counter-reset-at').symlink_to(target)
        before = self.rules()
        result = self.clear()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('shared reset time could not be saved', result.stderr)
        self.assertEqual(target.read_text(), 'keep this')
        self.assertEqual(before, self.rules())
        self.assertNotIn('last_counter_reset_at', self.bridge('inspect'))

    def test_busy_lifecycle_does_not_reset_or_retry(self):
        self.authorized_tunnel()
        self.device.add_command('flock', '#!/bin/sh\necho busy >&2\nexit 1\n')
        before = self.rules()
        result = self.clear()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(before, self.rules())
        self.assertFalse((self.kernel / 'zero_events').exists())
        self.assertFalse((self.device.engine / 'counter-reset-at').exists())


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(PufwClearTests(name) for name in PufwClearTests.__dict__ if name.startswith('test_'))
