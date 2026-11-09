"""Bridge diagnostics use a small allowlist, never raw probe/netfilter output."""
import os
import shutil
import unittest

from test_android_bridge import AndroidBridgeTests

WG_REASON = ('Kernel WireGuard tun* conflict or unreadable interface types; '
             'rename conflicting WireGuard before enabling. Nothing changed.')
AUTH_REASON = ('Cannot authorize tailnet destinations; start Tailscale and verify both node addresses. '
               'No deny-only fallback; nothing changed.')
MKSH = os.environ.get('POCKETUFW_TEST_MKSH') or shutil.which('mksh')


class TunnelFailureMessages(AndroidBridgeTests):
    def setUp(self):
        super().setUp()
        engine = self.engine / 'pocketufw'
        engine.write_text(engine.read_text().replace('case "$1" in\n', '''case "$1" in
tunnel-on|tunnel-refresh)
  printf '%s\\n' "$TEST_TUNNEL_OUTPUT"
  printf '%s\\n' "$TEST_TUNNEL_ERROR" >&2
  exit 1 ;;
''', 1))

    def failure(self, action, mode=None, error='', output=''):
        result, values = self.run_bridge(action,
            {'TEST_TUNNEL_ERROR': error, 'TEST_TUNNEL_OUTPUT': output},
            args=(mode,) if mode else ())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(values['operation'], 'FAILED')
        # Reporting a failure must not retry or invoke another operation.
        mutations = [s for s in self.log_lines() if s.startswith(('engine:tunnel-', 'engine:enable', 'engine:disable'))]
        self.assertEqual(mutations, ['engine:' + action])
        self.log.unlink()
        return values['message'], result.stdout

    def test_wireguard_reason_survives_probe_noise_and_cleanup_notice(self):
        message, _ = self.failure('tunnel-on', 'PINNED',
            error='vpn-probe: one verified Tailscale tun with both node addresses is required\n'
                  'pocketufw: ' + WG_REASON + '\npocketufw: tunnel-on failed, removing tunnel rules')
        self.assertEqual(message, WG_REASON)

    def test_actual_ownership_failure_preserves_no_fallback_explanation(self):
        message, _ = self.failure('tunnel-on', 'PINNED', error='pocketufw: ' + AUTH_REASON)
        self.assertEqual(message, AUTH_REASON)

    def test_busy_has_its_own_reason(self):
        reason = 'Another PocketUFW operation is still running; no changes made. Try again.'
        for action, mode in [('tunnel-on', 'PINNED'), ('tunnel-on', 'DENY_ONLY'), ('tunnel-refresh', None)]:
            with self.subTest(action=action, mode=mode):
                message, _ = self.failure(action, mode, error='pocketufw: ' + reason)
                self.assertEqual(message, reason)

    def test_deny_only_and_refresh_preserve_specific_failures(self):
        for action, mode, reason in [
            ('tunnel-on', 'DENY_ONLY', 'Could not read the current tunnels; nothing changed'),
            ('tunnel-on', 'DENY_ONLY', 'Firewall disabled or degraded; tunnel filter not installed'),
            ('tunnel-refresh', None, 'Firewall degraded; no refresh attempted'),
            ('tunnel-refresh', None, 'Tunnel filter is off; nothing to refresh'),
        ]:
            with self.subTest(reason=reason):
                message, _ = self.failure(action, mode, error='pocketufw: ' + reason)
                self.assertEqual(message, reason)
                self.assertNotIn('Tailscale', message)

    def test_refresh_hook_error_is_not_hidden_by_rollback_output(self):
        message, _ = self.failure('tunnel-refresh', error=(
            'iptables: private diagnostic\npocketufw: Could not add a tunnel hook; inspect tunnel-status\n'
            'pocketufw: tunnel refresh rollback incomplete; inspect tunnel-status'))
        self.assertEqual(message, 'Could not add a tunnel hook. Recheck tunnel protection.')

    def test_unknown_errors_use_action_specific_fallback_without_raw_output(self):
        for action, mode, expected in [
            ('tunnel-on', 'PINNED', 'PINNED tunnel protection could not be enabled. Recheck status before retrying.'),
            ('tunnel-on', 'DENY_ONLY', 'DENY-ONLY tunnel protection could not be enabled. Recheck status before retrying.'),
            ('tunnel-refresh', None, 'Tunnel hooks could not be refreshed. Recheck tunnel protection before retrying.'),
        ]:
            with self.subTest(action=action, mode=mode):
                marker = self.root / 'must-not-be-created'
                private = f'private-address $(touch {marker})\nmessage=injected\npocketufw: unrecognized internal error'
                message, output = self.failure(action, mode, error=private + '\x1b[0m', output=private)
                self.assertEqual(message, expected)
                self.assertNotIn('private-address', output)
                self.assertNotIn('injected', output)
                self.assertNotIn('unrecognized internal error', output)
                self.assertFalse(marker.exists())


@unittest.skipUnless(MKSH, 'set POCKETUFW_TEST_MKSH to an AOSP mksh host build')
class MkshTunnelFailureMessages(TunnelFailureMessages):
    def setUp(self):
        super().setUp()
        (self.bin / 'sh').symlink_to(MKSH)
        # The harness starts /bin/sh. Re-exec the bridge with mksh, including inherited FD 8.
        bridge = self.engine / 'android-bridge'
        implementation = self.engine / 'android-bridge-mksh'
        bridge.rename(implementation)
        bridge.write_text(f'#!/bin/sh\nexec "{MKSH}" "{implementation}" "$@"\n')


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(cls(name) for cls in (TunnelFailureMessages, MkshTunnelFailureMessages)
        for name in TunnelFailureMessages.__dict__ if name.startswith('test_'))
