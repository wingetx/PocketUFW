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
        self.data_dir = self.root / 'ts-data'
        self.data_dir.mkdir()
        self.uid = self.data_dir.stat().st_uid
        self.write_status(self.uid)
        self.packages = self.root / 'packages.list'
        self.packages.write_text(f'com.tailscale.ipn {self.uid} 0 /data/user/0/com.tailscale.ipn default:targetSdkVersion=34 3003\n')
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
            'POCKETUFW_PACKAGES_LIST': str(self.packages),
            'PUFW_TEST_DIR': str(self.root),
        }

    def write_status(self, real, others=None):
        others = real if others is None else others
        (self.proc / '6283' / 'status').write_text(
            f'Name:\tm.tailscale.ipn\nUmask:\t0077\nState:\tS (sleeping)\n'
            f'Pid:\t6283\nPPid:\t600\nUid:\t{real}\t{others}\t{others}\t{others}\n'
            f'Gid:\t{real}\t{real}\t{real}\t{real}\n')

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

    def assert_refused_as_unverified(self, out):
        self.assertNotEqual(out.returncode, 0)
        self.assertIn('unverified', out.stderr)
        self.assertNotIn('tailscale_udp4=46867', out.stdout)

    def test_spoofed_process_with_the_right_name_but_another_uid_is_refused(self):
        # Any app can set its process name and cmdline with android:process.
        # The kernel-assigned UID is what it cannot forge.
        self.write_status(self.uid + 1)
        self.assert_refused_as_unverified(self.run_probe())

    def test_only_the_real_uid_field_counts(self):
        self.write_status(self.uid + 1, others=self.uid)
        self.assert_refused_as_unverified(self.run_probe())
        self.write_status(self.uid, others=self.uid + 1)
        out = self.run_probe()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.splitlines(), ['tailscale_udp4=46867', 'tailscale_udp6=43504'])

    def test_real_android_uid_sample_matches_package_list(self):
        self.packages.write_text('com.tailscale.ipn 10429 0 /data/user/0/com.tailscale.ipn default:targetSdkVersion=34 3003\n')
        (self.proc / '6283' / 'status').write_text('Name:\tm.tailscale.ipn\nUid:\t10429\t10429\t10429\t10429\n')
        out = self.run_probe()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.splitlines(), ['tailscale_udp4=46867', 'tailscale_udp6=43504'])
        (self.proc / '6283' / 'status').write_text('Name:\tm.tailscale.ipn\nUid:\t10430\t10430\t10430\t10430\n')
        self.assert_refused_as_unverified(self.run_probe())

    def test_secondary_user_uid_matches_by_app_id(self):
        self.packages.write_text('com.tailscale.ipn 10429 0\n')
        (self.proc / '6283' / 'status').write_text('Uid:\t1010429\t1010429\t1010429\t1010429\n')
        self.assertEqual(self.run_probe().returncode, 0)

    def test_only_the_exact_package_counts(self):
        self.packages.write_text(f'com.tailscale.ipn.evil {self.uid} 0\nxcom.tailscale.ipn {self.uid} 0\n')
        self.assert_refused_as_unverified(self.run_probe())

    def test_other_apps_data_directories_are_never_consulted(self):
        # Regression, found on a real phone: su from the app inherits its mount
        # namespace, where data isolation hides other apps' data directories, so a
        # check based on them rejected real Tailscale whenever the app asked.
        self.assertNotIn('/data/user_de', SCRIPT.read_text())
        (self.bindir / 'stat').write_text('#!/bin/sh\nexit 1\n')
        (self.bindir / 'stat').chmod(0o755)
        self.assertEqual(self.run_probe().returncode, 0)

    def test_unreadable_or_malformed_status_is_refused(self):
        for content in ('Name:\tm.tailscale.ipn\n', 'Uid:\n', 'XUid:\t{0}\n', '', 'Uid:\tabc\t1\n'):
            with self.subTest(status=content):
                (self.proc / '6283' / 'status').write_text(content.format(self.uid))
                self.assert_refused_as_unverified(self.run_probe())
        (self.proc / '6283' / 'status').unlink()
        self.assert_refused_as_unverified(self.run_probe())

    def test_package_not_in_list_is_refused(self):
        # A process merely named like Tailscale, with Tailscale not installed.
        self.packages.write_text('com.example.other 10001 0\n')
        self.assert_refused_as_unverified(self.run_probe())

    def test_unreadable_package_list_is_refused(self):
        self.assert_refused_as_unverified(self.run_probe({'POCKETUFW_PACKAGES_LIST': str(self.root / 'missing')}))

    def test_unknown_owner_and_unknown_process_uid_are_not_a_match(self):
        (self.proc / '6283' / 'status').write_text('Name:\tm.tailscale.ipn\n')
        self.assert_refused_as_unverified(self.run_probe({'POCKETUFW_PACKAGES_LIST': str(self.root / 'missing')}))
        (self.proc / '6283' / 'status').unlink()
        self.assert_refused_as_unverified(self.run_probe({'POCKETUFW_PACKAGES_LIST': str(self.root / 'missing')}))

    def test_one_spoofed_socket_among_real_ones_refuses_the_family(self):
        spoof = V4.replace(':46867', ':31337').replace('pid=6283', 'pid=7000')
        (self.proc / '7000').mkdir()
        (self.proc / '7000' / 'cmdline').write_bytes(b'com.tailscale.ipn\0')
        (self.proc / '7000' / 'status').write_text(f'Uid:\t{self.uid + 1}\t0\t0\t0\n')
        (self.root / 'ss4').write_text(V4 + spoof)
        self.assert_refused_as_unverified(self.run_probe())

    def test_absent_tailscale_needs_no_package_entry(self):
        (self.root / 'ss4').write_text('')
        (self.root / 'ss6').write_text('')
        out = self.run_probe({'POCKETUFW_PACKAGES_LIST': str(self.root / 'missing')})
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.splitlines(), ['tailscale_udp4=', 'tailscale_udp6='])

    def test_default_package_list_is_androids(self):
        self.assertIn('${POCKETUFW_PACKAGES_LIST:-/data/system/packages.list}', SCRIPT.read_text())

    def test_ipv6_failure_is_not_treated_as_no_listener(self):
        (self.root / 'ss6').write_text(V6.replace(':43504', ':99999'))
        out = self.run_probe()
        self.assertNotEqual(out.returncode, 0)
        self.assertNotIn('tailscale_udp4=', out.stdout)

    def test_other_processes_sockets_are_ignored(self):
        other = 'UNCONN 0 0 0.0.0.0:5353 0.0.0.0:* users:(("mdnsd",pid=900,fd=4))\n'
        (self.root / 'ss4').write_text(other + V4)
        out = self.run_probe()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.splitlines()[0], 'tailscale_udp4=46867')

    def test_repeated_same_port_is_safe(self):
        (self.root / 'ss4').write_text(V4 + V4)
        out = self.run_probe()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.count('tailscale_udp4=46867'), 1)


if __name__ == '__main__':
    unittest.main()
