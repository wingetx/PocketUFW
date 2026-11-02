"""Offline, unprivileged tests for Android VPN socket inspection."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'vpn-probe'

V4 = 'UNCONN 0 0 0.0.0.0:46867 0.0.0.0:* users:(("m.tailscale.ipn",pid=6283,fd=128))\n'
V6 = 'UNCONN 0 0 [::]:43504 [::]:* users:(("m.tailscale.ipn",pid=6283,fd=129))\n'


class VPNProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bindir = self.root / 'bin'
        self.proc = self.root / 'proc'
        self.bindir.mkdir()
        self.proc.mkdir()
        (self.proc / '6283').mkdir()
        (self.proc / '6283' / 'cmdline').write_bytes(b'com.tailscale.ipn\0')
        (self.root / 'ss4').write_text(V4)
        (self.root / 'ss6').write_text(V6)
        (self.bindir / 'id').write_text('#!/bin/sh\nif [ "$1" = "-u" ]; then echo "${PUFW_TEST_UID:-0}"; fi\n')
        (self.bindir / 'pidof').write_text(
            '#!/bin/sh\n'
            '[ "$1" = "com.tailscale.ipn" ] || exit 1\n'
            '[ "${PUFW_PIDOF_RUNNING:-0}" = "1" ] && echo 6283\n'
        )
        (self.bindir / 'ss').write_text(
            '#!/bin/sh\n'
            'for a do case "$a" in -4) file="$PUFW_TEST_DIR/ss4";; -6) file="$PUFW_TEST_DIR/ss6";; esac; done\n'
            '[ -n "${file:-}" ] || exit 3\n'
            'cat "$file"\n'
        )
        for f in (self.bindir / 'id', self.bindir / 'ss', self.bindir / 'pidof'):
            f.chmod(0o755)
        self.env = {
            **os.environ,
            'PATH': str(self.bindir) + os.pathsep + os.environ.get('PATH', ''),
            'POCKETUFW_PROC_ROOT': str(self.proc),
            'POCKETUFW_SS_BIN': 'ss',
            'PUFW_TEST_DIR': str(self.root),
        }

    def run_probe(self, extra=None):
        return subprocess.run(
            ['sh', str(SCRIPT)],
            capture_output=True, text=True, timeout=10,
            env=self.env | (extra or {}),
        )

    def test_verified_android_tailscale_both_families(self):
        out = self.run_probe()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.splitlines(), [
            'tailscale_udp4=46867', 'tailscale_udp6=43504'
        ])

    def test_absent_app_has_no_exceptions(self):
        (self.root / 'ss4').write_text('')
        (self.root / 'ss6').write_text('')
        out = self.run_probe()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.splitlines(), ['tailscale_udp4=', 'tailscale_udp6='])

    def test_malformed_or_missing_proc_identity_is_rejected(self):
        (self.proc / '6283' / 'cmdline').write_bytes(b'com.example.rogue\0')
        out = self.run_probe()
        self.assertNotEqual(out.returncode, 0)
        self.assertIn('unverified', out.stderr)
        (self.proc / '6283' / 'cmdline').unlink()
        self.assertNotEqual(self.run_probe().returncode, 0)

    def test_ambiguous_ports_rejected(self):
        (self.root / 'ss4').write_text(V4 + V4.replace(':46867', ':46868'))
        out = self.run_probe()
        self.assertNotEqual(out.returncode, 0)
        self.assertIn('ambiguous', out.stderr)
        self.assertNotIn('tailscale_udp4=', out.stdout)

    def test_invalid_port_rejected(self):
        (self.root / 'ss4').write_text(V4.replace(':46867', ':99999'))
        out = self.run_probe()
        self.assertNotEqual(out.returncode, 0)
        self.assertIn('unverified', out.stderr)

    def test_root_required_for_owner_verification(self):
        out = self.run_probe({'PUFW_TEST_UID': '2000'})
        self.assertNotEqual(out.returncode, 0)
        self.assertIn('root needed', out.stderr)

    def test_ss_failure_is_not_misreported_as_absent(self):
        (self.bindir / 'ss').write_text('#!/bin/sh\nexit 9\n')
        out = self.run_probe()
        self.assertNotEqual(out.returncode, 0)
        self.assertIn('lookup unavailable', out.stderr)

    def test_running_app_with_hidden_sockets_fails_closed(self):
        (self.root / 'ss4').write_text('')
        (self.root / 'ss6').write_text('')
        out = self.run_probe({'PUFW_PIDOF_RUNNING': '1'})
        self.assertNotEqual(out.returncode, 0)
        self.assertIn('running, but no verified UDP sockets', out.stderr)

    def test_repeated_same_port_is_safe(self):
        (self.root / 'ss4').write_text(V4 + V4)
        out = self.run_probe()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.count('tailscale_udp4=46867'), 1)


if __name__ == '__main__':
    unittest.main()
