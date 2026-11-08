"""Targeted mksh execution, using a caller-supplied Android/AOSP mksh host build.

POCKETUFW_TEST_MKSH=/path/to/mksh python -m unittest discover -s tests -p test_android_shell.py
No phone or host firewall is used. This is not a Bionic/toybox/device test.
"""
import os
from pathlib import Path
import shutil
import subprocess
import time
import unittest

from test_tunnel_filter import ENGINE, ROOT, ROLLBACK, HOOK_TUN, MOCK
from test_security_regressions import BridgeAudit, TunnelAudit
from test_review_followup import BootContention

MKSH = os.environ.get('POCKETUFW_TEST_MKSH') or shutil.which('mksh')


def wait_file(test, path):
    until = time.monotonic() + 8
    while not path.exists() and time.monotonic() < until:
        time.sleep(.02)
    test.assertTrue(path.exists(), str(path))


@unittest.skipUnless(MKSH, 'set POCKETUFW_TEST_MKSH to an AOSP mksh host build')
class ShellEngine(TunnelAudit):
    def setUp(self):
        super().setUp()
        (self.bin / 'sh').symlink_to(MKSH)

    def test_shipped_scripts_parse_with_mksh(self):
        for script in ('pocketufw', 'android-bridge', 'bootctl', 'boot-service',
                       'vpn-probe', 'rules-report', 'udp-config', 'tools/tunnel-rollback'):
            result = subprocess.run([MKSH, '-n', str(ROOT / script)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_sigterm_cleans_partial_tunnel_install(self):
        super().test_termination_during_tunnel_install_cleans_partial_hooks()

    def test_sigterm_cleans_partial_physical_install_and_returns_failure(self):
        seen, gate = self.base / 'seen', self.base / 'gate'
        self.script('iptables', MOCK.replace('echo "$*" >> "$file"', f'''echo "$*" >> "$file"
    if [ "$name" = INPUT ] && [ "$2" = wlan+ ]; then
      : > "{seen}"
      while [ ! -f "{gate}" ]; do sleep .02; done
    fi'''))
        process = subprocess.Popen(['sh', str(ENGINE), 'enable'], env=self.env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            wait_file(self, seen)
            process.terminate()
        finally:
            gate.touch()
            process.communicate(timeout=10)
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(self.verify(), 'INACTIVE')
        for fam in ('iptables', 'ip6tables'):
            self.assertEqual(self.read(fam), '-j oem_in\n-j bw_INPUT\n-j fw_INPUT\n')

    def test_sigterm_rolls_back_refresh(self):
        self.ok('enable')
        self.ok('tunnel-on')
        before = {fam: self.read(fam) for fam in ('iptables', 'ip6tables')}
        self.device('WG-NEW', wireguard=True)
        seen, gate = self.base / 'seen', self.base / 'gate'
        self.script('iptables', MOCK.replace('echo "$*" >> "$file"', f'''echo "$*" >> "$file"
    if [ "$name" = INPUT ] && [ "$1" = -i ] && [ "$2" = WG-NEW ]; then
      : > "{seen}"
      while [ ! -f "{gate}" ]; do sleep .02; done
    fi'''))
        process = subprocess.Popen(['sh', str(ENGINE), 'tunnel-refresh'], env=self.env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            wait_file(self, seen)
            process.terminate()
        finally:
            gate.touch()
            process.communicate(timeout=10)
        self.assertNotEqual(process.returncode, 0)
        for fam, expected in before.items():
            self.assertEqual(self.read(fam), expected)
        self.assertEqual(self.verify(), 'ACTIVE')

    def test_installer_keeps_rollback_lock_if_parent_is_killed(self):
        self.ok('enable')
        seen, gate = self.base / 'seen', self.base / 'gate'
        self.script('iptables', MOCK.replace('echo "$*" >> "$file"', f'''echo "$*" >> "$file"
    if [ "$name" = INPUT ] && [ "$*" = "{HOOK_TUN}" ]; then
      : > "{seen}"
      while [ ! -f "{gate}" ]; do sleep .02; done
    fi'''))
        state = self.base / 'rollback'
        with (self.base / 'output').open('w') as out:
            process = subprocess.Popen(['sh', str(ROLLBACK), 'on', '2', str(ENGINE)], env=self.env,
                                       stdout=out, stderr=out)
            try:
                wait_file(self, seen)
                process.kill()
                process.wait(timeout=5)
                time.sleep(2.2)
                self.assertNotEqual(state.read_text().split()[0], 'FIRED')
            finally:
                gate.touch()
                until = time.monotonic() + 10
                while state.read_text().split()[0] != 'FIRED' and time.monotonic() < until:
                    time.sleep(.05)
        self.assertEqual(state.read_text().split()[0], 'FIRED')
        self.tunnel_chains_absent()
        self.assertEqual(self.verify(), 'ACTIVE')

    def test_hung_probe_is_bounded_and_never_authorizes_partial_output(self):
        self.ok('enable')
        self.ok('tunnel-on')
        self.script('ip', '#!/bin/sh\nexec sleep 30\n')
        start = time.monotonic()
        output = self.ok('tunnel-status')
        self.assertLess(time.monotonic() - start, 12)
        self.assertIn('tunnel_filter=ON', output)
        self.assertIn('tailnet_current=UNVERIFIED', output)
        self.assertNotIn('tailnet_current=REAUTHORIZE', output)
        self.assertIn('inventory=UNAVAILABLE', output)
        self.assertIn('tunnel_status=READY', output)
        # The timed-out child must not retain either lock.
        self.ok('tunnel-off')
        self.assertEqual(self.verify(), 'ACTIVE')

    def test_nested_android_probe_cannot_leave_a_term_ignoring_child(self):
        self.ok('enable')
        self.ok('tunnel-on')
        marker = self.base / 'dumpsys-pid'
        self.script('dumpsys', f'#!/bin/sh\ntrap "" TERM\necho $$ > "{marker}"\nexec sleep 30\n')
        start = time.monotonic()
        try:
            output = self.ok('tunnel-status')
            self.assertLess(time.monotonic() - start, 12)
            self.assertIn('tailnet_current=UNVERIFIED', output)
            pid = int(marker.read_text())
            stat = Path(f'/proc/{pid}/stat')
            self.assertTrue(not stat.exists() or stat.read_text().split()[2] == 'Z',
                            'timed-out dumpsys child is still running')
        finally:
            if marker.exists():
                try:
                    os.kill(int(marker.read_text()), 9)
                except ProcessLookupError:
                    pass

    def test_outer_deadline_kills_a_stalled_second_android_scan(self):
        self.ok('enable')
        self.ok('tunnel-on')
        marker, calls = self.base / 'dumpsys-pid', self.base / 'calls'
        self.script('dumpsys', f'''#!/bin/sh
if [ ! -f "{calls}" ]; then
  : > "{calls}"
  sleep 3
  cat "$PUFW_TEST_DIR/dumpsys.txt"
else
  trap "" TERM
  echo $$ > "{marker}"
  exec sleep 30
fi
''')
        start = time.monotonic()
        try:
            output = self.ok('tunnel-status')
            self.assertLess(time.monotonic() - start, 12)
            self.assertIn('tailnet_current=UNVERIFIED', output)
            pid = int(marker.read_text())
            stat = Path(f'/proc/{pid}/stat')
            self.assertTrue(not stat.exists() or stat.read_text().split()[2] == 'Z',
                            'second Android scan escaped the outer process-group deadline')
        finally:
            if marker.exists():
                try:
                    os.kill(int(marker.read_text()), 9)
                except ProcessLookupError:
                    pass

    def test_slow_valid_probe_completes_with_two_android_scans(self):
        self.ok('enable')
        self.ok('tunnel-on')
        calls = self.base / 'calls'
        self.script('dumpsys', f'#!/bin/sh\necho call >> "{calls}"\nsleep 1\ncat "$PUFW_TEST_DIR/dumpsys.txt"\n')
        start = time.monotonic()
        output = self.ok('tunnel-status')
        self.assertLess(time.monotonic() - start, 8)
        self.assertEqual(len(calls.read_text().splitlines()), 2)
        self.assertIn('tailnet_current=MATCH', output)


@unittest.skipUnless(MKSH, 'set POCKETUFW_TEST_MKSH to an AOSP mksh host build')
class ShellBridge(BridgeAudit):
    def setUp(self):
        super().setUp()
        (self.device.bin / 'sh').symlink_to(MKSH)

    def test_nested_lifecycle_locks_keep_the_same_open_descriptor(self):
        # These enter bridge -> bootctl -> engine (FD8), then engine snapshots (FD9).
        self.assertEqual(self.bridge('enable-restore')['operation'], 'SUCCESS')
        self.authorized_tunnel()
        seen, gate = self.root / 'seen', self.root / 'gate'
        self.device.add_command('dumpsys', f'#!/bin/sh\n: > "{seen}"\nwhile [ ! -f "{gate}" ]; do sleep .02; done\n')
        with (self.root / 'output').open('w') as out:
            process = subprocess.Popen(['sh', str(self.device.engine / 'android-bridge'), 'inspect'],
                                       env=self.env, stdout=out, stderr=out)
            try:
                wait_file(self, seen)
                # A separate open description cannot acquire the bridge's FD8 lock.
                blocked = subprocess.run(['flock', '-n', str(self.device.lock) + '.operation', 'true'])
                self.assertNotEqual(blocked.returncode, 0)
            finally:
                gate.touch()
                process.wait(timeout=12)
        self.assertEqual(process.returncode, 0)
        self.assertEqual(self.bridge('tunnel-off')['operation'], 'SUCCESS')
        self.assertEqual(self.bridge('prepare-uninstall')['removal'], 'CLEAN')
        self.assertFalse(self.device.store.exists())

    def test_engine_keeps_lifecycle_lock_after_bridge_is_killed(self):
        seen, gate = self.root / 'seen', self.root / 'gate'
        self.device.add_command('iptables', MOCK.replace('echo "$*" >> "$file"', f'''echo "$*" >> "$file"
    if [ "$name" = INPUT ] && [ "$2" = wlan+ ]; then
      : > "{seen}"
      while [ ! -f "{gate}" ]; do sleep .02; done
    fi'''))
        with (self.root / 'output').open('w') as out:
            process = subprocess.Popen(['sh', str(self.device.engine / 'android-bridge'), 'enable'],
                                       env=self.env, stdout=out, stderr=out)
            try:
                wait_file(self, seen)
                process.kill()
                process.wait(timeout=5)
                blocked = subprocess.run(['flock', '-n', str(self.device.lock) + '.operation', 'true'])
                self.assertNotEqual(blocked.returncode, 0)
            finally:
                gate.touch()
                # A subsequent mutation waits for the orphan installer, then cleans.
                self.assertEqual(self.bridge('prepare-uninstall')['removal'], 'CLEAN')
        self.assertEqual(self.verify(), 'INACTIVE')


@unittest.skipUnless(MKSH, 'set POCKETUFW_TEST_MKSH to an AOSP mksh host build')
class ShellBoot(BootContention):
    def setUp(self):
        super().setUp()
        (self.fakebin / 'sh').symlink_to(MKSH)
        # mksh has a builtin sleep, so explicitly use the fixture's virtual clock.
        service = self.app / 'boot-service'
        service.write_text(service.read_text().replace('set -u',
            f'set -u\nsleep() {{ "{self.fakebin}/sleep" "$@"; }}'))

    def call(self, command, env=None):
        return subprocess.run([MKSH, str(self.app / 'bootctl'), command], capture_output=True,
                              text=True, env=self.env | (env or {}), timeout=15)

    def boot(self, env=None):
        self.order.unlink(missing_ok=True)
        return subprocess.run([MKSH, str(self.hook)], capture_output=True,
                              text=True, env=self.env | (env or {}), timeout=15)

    def test_boot_contention_retries_then_restores(self):
        super().test_boot_retries_beyond_normal_lock_window()

    def test_boot_contention_cancels_when_disarmed(self):
        super().test_disarming_during_lock_wait_cancels_restore()

    def test_permanently_busy_boot_lock_has_bounded_attempts(self):
        # More than 248 days: multiplying uptime by 100 would overflow mksh.
        self.clock.write_text("30000000.99 0.00\n")
        self.assertEqual(self.call('enable').returncode, 0)
        self.state.write_text('INACTIVE\n')
        shim = self.fakebin / 'flock'
        shim.write_text('#!/bin/sh\nexit 1\n')
        shim.chmod(0o700)
        result = self.boot()
        self.assertEqual(result.returncode, 75)
        self.assertEqual(self.order.read_text().count('sleep 0.1\n'), 1200)
        self.assertFalse(self.calls.exists())


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(cls(name) for cls in (ShellEngine, ShellBridge, ShellBoot)
                              for name in cls.__dict__ if name.startswith('test_'))
