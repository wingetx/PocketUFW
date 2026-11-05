"""The real scripts working together, on the mock iptables.

Every other offline suite fakes the script next to the one it tests. Here the
real android-bridge drives the real pocketufw, bootctl, boot-service, vpn-probe,
rules-report and udp-config, so a disagreement between them cannot hide behind a fake.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from device_sandbox import Device
from test_pocketufw import MOCK

BASELINE = '-j oem_in\n-j bw_INPUT\n-j fw_INPUT\n'
FAMILIES = ('iptables', 'ip6tables')
NO_RULES = 'Firewall enabled without saved UDP exceptions because the saved settings could not be read.'
NO_PORTS = ('Firewall enabled. Tailscale ports could not be verified, so no VPN exception was added. '
            'Use Refresh Tailscale ports later.')
EXPECTED_MAIN4 = [
    '-A POCKETUFW_IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
    '-A POCKETUFW_IN -p icmp -j ACCEPT',
    '-A POCKETUFW_IN -m conntrack --ctstate INVALID -j DROP',
    '-A POCKETUFW_IN -p udp --sport 67 --dport 68 -j ACCEPT',
    '-A POCKETUFW_IN -p udp -d 224.0.0.251 --dport 5353 -j ACCEPT',
    '-A POCKETUFW_IN -p esp -j ACCEPT',
    '-A POCKETUFW_IN -j POCKETUFW_TS',
    '-A POCKETUFW_IN -j DROP',
]


class RealEngineTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='pufw-integration-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.device = Device(self.root / 'device', '/usr/bin:/bin')
        self.kernel = self.root / 'kernel'
        self.kernel.mkdir()
        for family in FAMILIES:
            self.device.add_command(family, MOCK)
        self.device.add_command('id', '#!/bin/sh\n[ "$1" = -u ] || exit 2\necho 0\n')
        self.device.add_command('ip', '#!/bin/sh\nexit 0\n')
        self.device.add_command(
            'ss',
            '#!/bin/sh\n'
            'for arg do case "$arg" in -4) file="$PUFW_TEST_DIR/ss4";; -6) file="$PUFW_TEST_DIR/ss6";; esac; done\n'
            'cat "$file"\n')
        self.proc = self.root / 'proc'
        (self.proc / '6283').mkdir(parents=True)
        self.ts_data = self.root / 'tailscale-data'
        self.ts_data.mkdir()
        self.packages = self.root / 'packages.list'
        self.packages.write_text(f'com.tailscale.ipn {self.ts_data.stat().st_uid} 0\n')
        self.env = {
            **self.device.env(dict(os.environ)),
            'PUFW_TEST_DIR': str(self.kernel),
            'POCKETUFW_SS_BIN': 'ss',
            'POCKETUFW_PROC_ROOT': str(self.proc),
            'POCKETUFW_PACKAGES_LIST': str(self.packages),
        }
        self.power_cycle_kernel()
        self.tailscale(None, None)

    def tailscale(self, port4, port6, uid=None):
        uid = self.ts_data.stat().st_uid if uid is None else uid
        (self.proc / '6283' / 'cmdline').write_bytes(b'com.tailscale.ipn\0')
        (self.proc / '6283' / 'status').write_text(f'Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n')
        line = 'UNCONN 0 0 {}:{} {}:* users:(("m.tailscale.ipn",pid=6283,fd=128))\n'
        (self.kernel / 'ss4').write_text(line.format('0.0.0.0', port4, '0.0.0.0') if port4 else '')
        (self.kernel / 'ss6').write_text(line.format('[::]', port6, '[::]') if port6 else '')

    def power_cycle_kernel(self):
        """A reboot loses every kernel rule, and keeps every file."""
        for family in FAMILIES:
            for chain in ('POCKETUFW_IN', 'POCKETUFW_TS'):
                (self.kernel / f'{family}.{chain}').unlink(missing_ok=True)
            (self.kernel / f'{family}.INPUT').write_text(BASELINE)

    def chain(self, family, chain):
        return (self.kernel / f'{family}.{chain}').read_text().splitlines()

    def chain_exists(self, family, chain):
        return (self.kernel / f'{family}.{chain}').exists()

    def script(self, name, *args, env=None):
        return subprocess.run(['sh', str(self.device.engine / name), *args], text=True, capture_output=True,
                              env={**self.env, **(env or {})}, timeout=40)

    def bridge(self, action, *args, env=None):
        result = self.script('android-bridge', action, *args, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('STALE', result.stdout)
        return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)

    def verify(self):
        return self.script('pocketufw', 'verify').stdout.strip()

    def run_boot_hook(self, env=None):
        return subprocess.run(['sh', str(self.device.hook)], text=True, capture_output=True,
                              env={**self.env, **(env or {})}, timeout=40)

    def assert_succeeded(self, values, state, boot=None):
        self.assertEqual(values['operation'], 'SUCCESS', values)
        self.assertEqual(values['state'], state)
        if boot:
            self.assertEqual(values['boot'], boot)

    def arm_boot(self):
        self.assert_succeeded(self.bridge('enable'), 'ACTIVE')
        self.assert_succeeded(self.bridge('boot-enable'), 'ACTIVE', 'ENABLED')

    # --- Everyday use. ---

    def test_first_run_inspect_enable_disable(self):
        values = self.bridge('inspect')
        self.assertEqual(values['state'], 'INACTIVE')
        self.assertEqual(values['operation'], 'NONE')
        self.assertEqual(values['boot'], 'DISABLED')
        self.assertEqual(values['config_mode'], 'AUTOMATIC')
        self.assertNotIn('ipv4_blocked', values)
        self.assertNotIn('rules_report', values)

        values = self.bridge('enable')
        self.assert_succeeded(values, 'ACTIVE', 'DISABLED')
        self.assertEqual(values['message'], 'Firewall enabled.')
        for key in ('ipv4_blocked', 'ipv6_blocked', 'ipv4_established_replies', 'ipv6_established_replies'):
            self.assertEqual(values[key], '0')
        # The report the Status screen shows is the rule set the kernel really has.
        self.assertEqual(values['rules_report'], 'READY')
        self.assertEqual(values['input_policy4'], 'ACCEPT')
        self.assertEqual([values[f'main4_0{n}'] for n in range(1, 9)], EXPECTED_MAIN4)
        self.assertEqual(values['hook6_03'], '-A INPUT -i v4-rmnet+ -m comment --comment PocketUFW -j POCKETUFW_IN')
        self.assertFalse([key for key in values if key.startswith('input_bypass')])

        self.assert_succeeded(self.bridge('disable'), 'INACTIVE', 'DISABLED')
        for family in FAMILIES:
            self.assertEqual((self.kernel / f'{family}.INPUT').read_text(), BASELINE)
            self.assertFalse(self.chain_exists(family, 'POCKETUFW_IN'))
            self.assertFalse(self.chain_exists(family, 'POCKETUFW_TS'))

    def test_counters_action_reads_the_real_engine(self):
        self.bridge('enable')
        result = self.script('android-bridge', 'counters', env={'PUFW_TEST_DROP4': '12', 'PUFW_TEST_INVALID4': '3'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('ipv4_blocked=15\n', result.stdout)
        values = self.bridge('reset-counters', env={'PUFW_TEST_DROP4': '12', 'PUFW_TEST_INVALID4': '3'})
        self.assert_succeeded(values, 'ACTIVE')
        self.assertEqual(values['ipv4_blocked'], '0')

    def test_counters_action_fails_closed_when_inactive(self):
        self.assertNotEqual(self.script('android-bridge', 'counters').returncode, 0)

    def test_tile_toggles_and_opt_in_round_trip(self):
        self.arm_boot()
        values = self.bridge('toggle', 'ACTIVE')
        self.assert_succeeded(values, 'INACTIVE', 'DISABLED')
        self.assertEqual(values['previous_boot'], 'ENABLED')
        self.assertFalse(self.device.hook.exists())
        self.assert_succeeded(self.bridge('toggle-restore', 'INACTIVE'), 'ACTIVE', 'ENABLED')
        self.assertTrue(self.device.hook.exists())

    def test_tile_showing_an_old_state_changes_nothing(self):
        self.bridge('enable')
        before = self.chain('iptables', 'POCKETUFW_IN')
        values = self.bridge('toggle', 'INACTIVE')
        self.assertEqual(values['operation'], 'FAILED')
        self.assertEqual(values['message'], 'Firewall state had changed, so nothing was toggled. Status updated.')
        self.assertEqual(values['state'], 'ACTIVE')
        self.assertEqual(self.chain('iptables', 'POCKETUFW_IN'), before)

    def test_enabling_an_enabled_firewall_is_not_an_error(self):
        self.bridge('enable')
        values = self.bridge('enable')
        self.assert_succeeded(values, 'ACTIVE')
        self.assertEqual(values['message'], 'Firewall is already on.')

    def test_earlier_accept_surfaces_while_state_stays_active(self):
        self.bridge('enable')
        path = self.kernel / 'iptables.INPUT'
        lines = path.read_text().splitlines()
        lines.insert(0, '-i wlan0 -j ACCEPT')
        path.write_text('\n'.join(lines) + '\n')
        values = self.bridge('inspect')
        self.assertEqual(values['state'], 'ACTIVE')
        self.assertEqual(values['input_bypass4_01'], '-A INPUT -i wlan0 -j ACCEPT')
        self.assertNotIn('input_bypass6_01', values)

    # --- Tailscale can only ever affect its own exception. ---

    def test_verified_tailscale_ports_reach_the_rules_and_report(self):
        self.tailscale(46867, 43504)
        values = self.bridge('enable')
        self.assert_succeeded(values, 'ACTIVE')
        self.assertEqual(values['message'], 'Firewall enabled.')
        self.assertEqual(values['vpn4_01'], '-A POCKETUFW_TS -p udp --dport 46867 -j ACCEPT')
        self.assertEqual(values['vpn6_01'], '-A POCKETUFW_TS -p udp --dport 43504 -j ACCEPT')

    def test_spoofed_tailscale_gets_a_firewall_and_no_hole(self):
        self.tailscale(31337, None, uid=self.ts_data.stat().st_uid + 1)
        values = self.bridge('enable')
        self.assert_succeeded(values, 'ACTIVE')
        self.assertEqual(values['message'], NO_PORTS)
        self.assertEqual(self.chain('iptables', 'POCKETUFW_TS'), [])
        self.assertEqual(self.chain('ip6tables', 'POCKETUFW_TS'), [])
        # Refresh, unlike enable, must not treat that as "no listeners".
        values = self.bridge('vpn-refresh')
        self.assertEqual(values['operation'], 'FAILED')
        self.assertEqual(self.chain('iptables', 'POCKETUFW_TS'), [])
        # The real app appears: refresh opens exactly its port.
        self.tailscale(46867, None)
        values = self.bridge('vpn-refresh')
        self.assert_succeeded(values, 'ACTIVE')
        self.assertIn('exceptions updated', values['message'])
        self.assertEqual(self.chain('iptables', 'POCKETUFW_TS'), ['-p udp --dport 46867 -j ACCEPT'])

    def test_missing_probe_still_gives_a_firewall(self):
        (self.device.engine / 'vpn-probe').unlink()
        values = self.bridge('enable')
        self.assert_succeeded(values, 'ACTIVE')
        self.assertEqual(values['message'], NO_PORTS)

    def test_invalid_saved_settings_give_a_firewall_without_exceptions(self):
        self.tailscale(46867, 43504)
        self.device.config_file.write_text('udp4=$(id)\nudp6=none\n')
        values = self.bridge('enable')
        self.assert_succeeded(values, 'ACTIVE')
        self.assertEqual(values['message'], NO_RULES)
        self.assertEqual(values['config_mode'], 'DEGRADED')
        self.assertEqual(self.chain('iptables', 'POCKETUFW_TS'), [])
        values = self.bridge('use-auto')
        self.assert_succeeded(values, 'ACTIVE')
        self.assertEqual(values['config_mode'], 'AUTOMATIC')
        self.assertEqual(self.chain('iptables', 'POCKETUFW_TS'), ['-p udp --dport 46867 -j ACCEPT'])

    def test_refresh_is_refused_on_a_degraded_firewall(self):
        self.tailscale(46867, 43504)
        self.bridge('enable')
        path = self.kernel / 'ip6tables.POCKETUFW_IN'
        path.write_text(path.read_text().replace('-j DROP\n', '', 1))
        self.tailscale(46877, 43514)
        values = self.bridge('vpn-refresh')
        self.assertEqual(values['operation'], 'FAILED')
        self.assertEqual(values['state'], 'DEGRADED')
        self.assertEqual(self.chain('iptables', 'POCKETUFW_TS'), ['-p udp --dport 46867 -j ACCEPT'])

    def test_committed_refresh_refusal_and_return_to_automatic(self):
        self.tailscale(46867, None)
        self.bridge('enable')
        values = self.bridge('set-ports', '41476', 'none', 'committed')
        self.assert_succeeded(values, 'ACTIVE')
        self.assertEqual(values['config_mode'], 'COMMITTED')
        self.assertEqual(self.chain('iptables', 'POCKETUFW_TS'), ['-p udp --dport 41476 -j ACCEPT'])
        values = self.bridge('vpn-refresh')
        self.assertEqual(values['operation'], 'FAILED')
        self.assertIn('Use the VPN UDP exceptions editor', values['message'])
        values = self.bridge('use-auto')
        self.assert_succeeded(values, 'ACTIVE')
        self.assertEqual(values['config_mode'], 'AUTOMATIC')
        self.assertEqual(self.chain('iptables', 'POCKETUFW_TS'), ['-p udp --dport 46867 -j ACCEPT'])

    def test_experimental_ports_leave_saved_settings_alone(self):
        self.bridge('enable')
        values = self.bridge('set-ports', '45678', '45679', 'experimental')
        self.assert_succeeded(values, 'ACTIVE')
        self.assertEqual(values['config_mode'], 'AUTOMATIC')
        self.assertFalse(self.device.config_file.exists())
        self.assertEqual(self.chain('ip6tables', 'POCKETUFW_TS'), ['-p udp --dport 45679 -j ACCEPT'])

    def test_commit_save_failure_restores_the_live_ports(self):
        if os.geteuid() == 0:
            self.skipTest('root ignores the read-only directory this relies on')
        self.bridge('enable')
        self.assert_succeeded(self.bridge('set-ports', '50000', 'none', 'experimental'), 'ACTIVE')
        self.device.config_dir.chmod(0o500)
        self.addCleanup(self.device.config_dir.chmod, 0o700)
        values = self.bridge('set-ports', '41476', '45567', 'committed')
        self.assertEqual(values['operation'], 'FAILED')
        self.assertEqual(self.chain('iptables', 'POCKETUFW_TS'), ['-p udp --dport 50000 -j ACCEPT'])
        self.assertEqual(self.chain('ip6tables', 'POCKETUFW_TS'), [])
        self.assertEqual(values['state'], 'ACTIVE')

    # --- Boot. ---

    def test_boot_restore_in_automatic_mode_probes_again(self):
        self.tailscale(46867, 43504)
        self.arm_boot()
        self.power_cycle_kernel()
        self.tailscale(46900, None)
        result = self.run_boot_hook()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.verify(), 'ACTIVE')
        self.assertEqual(self.chain('iptables', 'POCKETUFW_TS'), ['-p udp --dport 46900 -j ACCEPT'])
        self.assertEqual(self.chain('ip6tables', 'POCKETUFW_TS'), [])
        values = self.bridge('inspect')
        self.assertEqual(values['boot'], 'ENABLED')

    def test_boot_restore_with_committed_ports_does_not_probe(self):
        self.tailscale(46867, 43504)
        self.arm_boot()
        self.assert_succeeded(self.bridge('set-ports', '41476', 'none', 'committed'), 'ACTIVE', 'ENABLED')
        self.power_cycle_kernel()
        result = self.run_boot_hook()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.chain('iptables', 'POCKETUFW_TS'), ['-p udp --dport 41476 -j ACCEPT'])
        self.assertEqual(self.chain('ip6tables', 'POCKETUFW_TS'), [])

    def test_boot_restore_never_depends_on_tailscale_or_saved_settings(self):
        self.arm_boot()
        problems = {
            'spoofed listener': lambda: self.tailscale(31337, None, uid=self.ts_data.stat().st_uid + 1),
            'corrupt saved settings': lambda: self.device.config_file.write_text('garbage\n'),
            'missing probe copy': lambda: (self.device.store / 'vpn-probe').unlink(),
            'missing config copy': lambda: (self.device.store / 'udp-config').unlink(),
        }
        for name, cause in problems.items():
            with self.subTest(problem=name):
                self.power_cycle_kernel()
                cause()
                result = self.run_boot_hook()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.verify(), 'ACTIVE')
                self.assertEqual(self.chain('iptables', 'POCKETUFW_TS'), [])
                self.assertEqual(self.chain('ip6tables', 'POCKETUFW_TS'), [])

    def test_boot_restore_after_the_wait_limit_still_installs(self):
        self.arm_boot()
        self.power_cycle_kernel()
        self.device.add_command('sleep', '#!/bin/sh\nexit 0\n')
        result = self.run_boot_hook(env={'TEST_BOOT_COMPLETED': '0', 'TEST_PM_MODE': 'gone'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.verify(), 'ACTIVE')
        self.assertTrue(self.device.hook.exists())

    def test_boot_never_replaces_a_partial_firewall(self):
        self.arm_boot()
        path = self.kernel / 'iptables.POCKETUFW_IN'
        path.write_text(path.read_text().replace('-j DROP\n', '', 1))
        partial = path.read_text()
        result = self.run_boot_hook()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(path.read_text(), partial)
        self.assertEqual(self.verify(), 'DEGRADED')

    def test_uninstalled_app_disarms_without_touching_the_kernel(self):
        self.arm_boot()
        self.power_cycle_kernel()
        self.device.app_data.rmdir()
        result = self.run_boot_hook(env={'TEST_PM_MODE': 'gone'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.device.hook.exists())
        self.assertFalse(self.device.store.exists())
        self.assertEqual(self.verify(), 'INACTIVE')

    def test_package_manager_trouble_keeps_the_firewall_and_the_hook(self):
        for mode, remove_data in (('transient', True), ('gone', False)):
            with self.subTest(pm=mode):
                self.arm_boot()
                self.power_cycle_kernel()
                if remove_data:
                    self.device.app_data.rmdir()
                result = self.run_boot_hook(env={'TEST_PM_MODE': mode})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(self.device.hook.exists())
                self.assertEqual(self.verify(), 'ACTIVE')
                if remove_data:
                    self.device.app_data.mkdir()
                self.assert_succeeded(self.bridge('disable'), 'INACTIVE', 'DISABLED')

    def test_status_read_replaces_three_day_old_boot_copies(self):
        self.arm_boot()
        old = self.device.store / 'pocketufw'
        old.write_text(old.read_text() + '# an older build\n')
        self.assertEqual(self.script('bootctl', 'status').stdout.strip(), 'boot=STALE')
        rules = self.chain('iptables', 'POCKETUFW_IN')
        values = self.bridge('inspect')
        self.assertEqual(values['boot'], 'ENABLED')
        self.assertEqual(old.read_bytes(), (self.device.engine / 'pocketufw').read_bytes())
        self.assertEqual(self.script('bootctl', 'status').stdout.strip(), 'boot=ENABLED')
        self.assertEqual(self.chain('iptables', 'POCKETUFW_IN'), rules)

    def test_stale_copies_are_left_while_the_firewall_is_off(self):
        self.arm_boot()
        self.power_cycle_kernel()
        old = self.device.store / 'pocketufw'
        old.write_text(old.read_text() + '# an older build\n')
        values = self.bridge('inspect')
        self.assertEqual(values['state'], 'INACTIVE')
        self.assertEqual(values['boot'], 'ENABLED')
        self.assertEqual(self.script('bootctl', 'status').stdout.strip(), 'boot=STALE')

    def test_failed_refresh_of_stale_copies_is_degraded(self):
        self.arm_boot()
        old = self.device.store / 'pocketufw'
        old.write_text(old.read_text() + '# an older build\n')
        (self.device.engine / 'boot-service').unlink()  # bootctl enable now cannot install.
        values = self.bridge('inspect')
        self.assertEqual(values['boot'], 'DEGRADED')

    # --- The switches that must always work. ---

    def test_off_switch_with_another_modules_boot_hook(self):
        self.bridge('enable')
        self.device.hook.write_text('#!/bin/sh\n# someone else\n')
        values = self.bridge('disable')
        self.assert_succeeded(values, 'INACTIVE', 'CONFLICT')
        self.assertEqual(values['message'], 'Firewall disabled. Another module owns the boot hook path, so it was left alone.')
        self.assertEqual(values['previous_boot'], 'CONFLICT')
        self.assertEqual(self.device.hook.read_text(), '#!/bin/sh\n# someone else\n')
        self.assertEqual((self.kernel / 'iptables.INPUT').read_text(), BASELINE)

    def test_arming_is_refused_with_another_modules_boot_hook(self):
        self.bridge('enable')
        self.device.hook.write_text('#!/bin/sh\n# someone else\n')
        values = self.bridge('boot-enable')
        self.assertEqual(values['operation'], 'FAILED')
        self.assertEqual(values['boot'], 'CONFLICT')
        self.assertEqual(self.device.hook.read_text(), '#!/bin/sh\n# someone else\n')

    def test_remove_partial_needs_a_firewall_that_is_really_partial(self):
        self.bridge('enable')
        values = self.bridge('remove-partial')
        self.assertEqual(values['operation'], 'FAILED')
        self.assertEqual(values['message'], 'Firewall state had changed, so nothing was removed. Status updated.')
        self.assertEqual(self.verify(), 'ACTIVE')
        path = self.kernel / 'ip6tables.POCKETUFW_IN'
        path.write_text(path.read_text().replace('-j DROP\n', '', 1))
        self.assertEqual(self.verify(), 'DEGRADED')
        values = self.bridge('remove-partial')
        self.assert_succeeded(values, 'INACTIVE', 'DISABLED')
        self.assertEqual((self.kernel / 'ip6tables.INPUT').read_text(), BASELINE)

    def test_a_tile_never_toggles_a_partial_firewall(self):
        self.bridge('enable')
        path = self.kernel / 'iptables.POCKETUFW_IN'
        path.write_text(path.read_text().replace('-j DROP\n', '', 1))
        values = self.bridge('toggle')
        self.assertEqual(values['operation'], 'FAILED')
        self.assertIn('degraded or unknown', values['message'])
        self.assertTrue(self.chain_exists('iptables', 'POCKETUFW_IN'))

    def test_afwall_blocks_enable_with_a_truthful_failure(self):
        values = self.bridge('enable', env={'PUFW_TEST_AFWALL': '1'})
        self.assertEqual(values['operation'], 'FAILED')
        self.assertEqual(values['state'], 'INACTIVE')

    # --- Concurrency. ---

    @unittest.skipUnless(shutil.which('flock'), 'host has no flock')
    def test_two_bridges_enabling_at_once_both_report_truthfully(self):
        for attempt in range(3):
            with self.subTest(attempt=attempt):
                self.power_cycle_kernel()
                env = {**self.env, 'PUFW_TEST_SLOW_ADD': '0.005'}
                command = ['sh', str(self.device.engine / 'android-bridge'), 'enable']
                first = subprocess.Popen(command, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                second = subprocess.Popen(command, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                outputs = [first.communicate(timeout=40)[0], second.communicate(timeout=40)[0]]
                results = [dict(line.split('=', 1) for line in out.splitlines() if '=' in line) for out in outputs]
                self.assertEqual(sorted(r['message'] for r in results), ['Firewall enabled.', 'Firewall is already on.'])
                for result in results:
                    self.assert_succeeded(result, 'ACTIVE')
                self.assertEqual(self.verify(), 'ACTIVE')


if __name__ == '__main__':
    unittest.main()
