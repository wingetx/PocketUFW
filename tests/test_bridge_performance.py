"""Invocation budgets and elapsed deadlines, on disposable devices only."""
import fcntl
from pathlib import Path
import shutil
import time
import unittest

from test_security_regressions import BridgeAudit
from test_tunnel_filter import Base, HOOK_TUN
from test_bootctl import BootTests


class Inspection(BridgeAudit):
    def instrument(self, delay='0'):
        trace = self.root / 'calls'
        for name in ('iptables', 'ip6tables', 'dumpsys'):
            path = self.device.bin / name
            source = path.read_text()
            path.write_text(source.replace('#!/bin/sh\n',
                f'#!/bin/sh\necho "{name} $*" >> "{trace}"\nsleep {delay}\n', 1))
        return trace

    def test_dashboard_uses_one_rule_audit_and_two_ownership_observations(self):
        self.authorized_tunnel()
        trace = self.instrument()
        values = self.bridge('inspect')
        calls = trace.read_text().splitlines()
        self.assertEqual(values['state'], 'ACTIVE')
        self.assertEqual(values['tailnet_current'], 'MATCH')
        self.assertEqual(sum(c.startswith('dumpsys ') for c in calls), 2)
        self.assertEqual(sum('-C POCKETUFW_IN -p esp -j ACCEPT' in c for c in calls), 2)
        self.assertLessEqual(sum(c.startswith(('iptables ', 'ip6tables ')) for c in calls), 64)

    def test_tunnel_status_reuses_its_verified_rules_and_pins(self):
        self.authorized_tunnel()
        trace = self.instrument('0.10')
        started = time.monotonic()
        result = self.script('pocketufw', 'tunnel-status')
        elapsed = time.monotonic() - started
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('tunnel_filter=ON', result.stdout)
        self.assertIn('tailnet_current=MATCH', result.stdout)
        calls = trace.read_text().splitlines()
        self.assertLessEqual(sum(c.startswith(('iptables ', 'ip6tables ')) for c in calls), 45)
        self.assertEqual(sum(c.startswith('dumpsys ') for c in calls), 2)
        self.assertLess(elapsed, 8)
        print(f'\nTunnel-status cost model: {elapsed:.2f}s', flush=True)

    def test_reduced_work_still_reports_stale_pins_and_broken_hooks(self):
        self.authorized_tunnel()
        ip = self.device.bin / 'ip'
        ip.write_text(ip.read_text().replace('100.64.0.1/32', '100.64.0.9/32'))
        values = self.bridge('inspect')
        self.assertEqual(values['state'], 'ACTIVE')
        self.assertEqual(values['tailnet_current'], 'REAUTHORIZE')
        path = self.kernel / 'ip6tables.INPUT'
        path.write_text(path.read_text().replace(HOOK_TUN + '\n', ''))
        values = self.bridge('inspect')
        self.assertEqual(values['state'], 'DEGRADED')
        self.assertEqual(values['tunnel_filter'], 'DEGRADED')
        self.assertEqual(values['uncovered_ifaces'], 'tun0')

    def test_phone_cost_model_has_headroom_below_the_32_second_ui_limit(self):
        self.authorized_tunnel()
        trace = self.instrument('0.10')
        for name in ('awk', 'sed', 'grep', 'sort', 'tail', 'cat', 'tr', 'readlink', 'dirname', 'cmp'):
            real = shutil.which(name)
            self.device.add_command(name, f'#!/bin/sh\nsleep .03\nexec "{real}" "$@"\n')
        started = time.monotonic()
        values = self.bridge('inspect')
        elapsed = time.monotonic() - started
        self.assertEqual(values['state'], 'ACTIVE')
        self.assertEqual(values['tailnet_current'], 'MATCH')
        self.assertLess(elapsed, 16, f'{elapsed:.2f}s; {len(trace.read_text().splitlines())} kernel/probe calls')
        print(f'\nPinned dashboard cost model: {elapsed:.2f}s', flush=True)

    def test_busy_dashboard_returns_promptly_without_reading_half_installed_rules(self):
        lock = Path(str(self.device.lock) + '.operation')
        with lock.open('w') as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            started = time.monotonic()
            result = self.script('android-bridge', 'inspect')
        self.assertEqual(result.returncode, 75)
        self.assertLess(time.monotonic() - started, 3.5)
        self.assertNotIn('state=ACTIVE', result.stdout)

    def test_snapshot_lock_contention_also_returns_busy_without_unlocked_fallback(self):
        with self.device.lock.open('w') as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            started = time.monotonic()
            result = self.script('android-bridge', 'inspect')
        self.assertEqual(result.returncode, 75)
        self.assertLess(time.monotonic() - started, 3.5)
        self.assertNotIn('state=ACTIVE', result.stdout)

    def test_large_android_record_is_streamed_without_the_old_sed_patterns(self):
        self.authorized_tunnel()
        dump = self.root / 'large-dumpsys'
        dump.write_text('NetworkAgentInfo{ni{VPN CONNECTED extra: VPN:com.tailscale.ipn} ' +
                        'filler ' * 30000 + ' LinkProperties{InterfaceName: tun0 }}\n')
        self.device.add_command('dumpsys', f'#!/bin/sh\ncat "{dump}"\n')
        real = shutil.which('sed')
        self.device.add_command('sed', f'#!/bin/sh\ncase "$*" in *"ni{{VPN CONNECTED"*|*InterfaceName:*) exit 9;; esac\nexec "{real}" "$@"\n')
        started = time.monotonic()
        values = self.bridge('inspect')
        self.assertLess(time.monotonic() - started, 4)
        self.assertEqual(values['tailnet_current'], 'MATCH')
        self.assertEqual(values['vpn_owner'], 'com.tailscale.ipn')
        self.assertEqual(values['vpn_iface'], 'tun0')

    def test_timed_out_probe_is_not_retried_and_does_not_change_pin_protection(self):
        self.authorized_tunnel()
        ip = self.device.bin / 'ip'
        ip.write_text(ip.read_text().replace('#!/bin/sh\n',
            '#!/bin/sh\n[ "$*" != "-o addr show dev tun0 scope global" ] || exec sleep 30\n', 1))
        trace = self.instrument()
        started = time.monotonic()
        values = self.bridge('inspect')
        self.assertLess(time.monotonic() - started, 12)
        self.assertEqual(values['state'], 'ACTIVE')
        self.assertEqual(values['tailnet_current'], 'UNVERIFIED')
        self.assertEqual(values['tailnet_pin4'], '100.64.0.1/32')
        self.assertEqual(values['vpn_owner'], '')
        self.assertEqual(sum(c.startswith('dumpsys ') for c in trace.read_text().splitlines()), 1)

    def test_wireguard_conflict_appearing_during_probe_withdraws_active(self):
        self.authorized_tunnel()
        conflict = self.root / 'sys' / 'tun5'
        path = self.device.bin / 'dumpsys'
        path.write_text(path.read_text().replace('#!/bin/sh\n',
            f'#!/bin/sh\nmkdir -p "{conflict}"\necho DEVTYPE=wireguard > "{conflict}/uevent"\n', 1))
        values = self.bridge('inspect')
        self.assertEqual(values['state'], 'DEGRADED')
        self.assertEqual(values['tailnet_wireguard'], 'CONFLICT')
        self.assertEqual(values['tunnel_filter'], 'DEGRADED')
        self.assertNotIn('ipv4_blocked', values)
        self.assertEqual(values['uncovered_ifaces'], 'tun0')

    def test_deny_only_and_off_need_one_advisory_scan_each(self):
        self.authorized_tunnel()
        self.script('pocketufw', 'tunnel-off')
        trace = self.instrument()
        for mode in ('OFF', 'DENY_ONLY'):
            if mode == 'DENY_ONLY':
                self.script('pocketufw', 'tunnel-on', '--deny-only')
            trace.write_text('')
            values = self.bridge('inspect')
            self.assertEqual(values['state'], 'ACTIVE')
            self.assertEqual(sum(c.startswith('dumpsys ') for c in trace.read_text().splitlines()), 1)
            self.assertEqual(values['tailnet_current'], mode)


class Deadlines(Base):
    def test_slow_flock_counts_towards_the_actual_mutation_deadline(self):
        attempts = self.base / 'attempts'
        self.script('flock', f'#!/bin/sh\necho try >> "{attempts}"\nsleep .10\nexit 1\n')
        started = time.monotonic()
        result = self.run_cmd('enable')
        elapsed = time.monotonic() - started
        self.assertEqual(result.returncode, 75)
        self.assertLess(elapsed, 16.5)
        self.assertGreater(elapsed, 13.5)
        self.assertFalse(self.exists('iptables', 'POCKETUFW_IN'))

    def test_unreadable_monotonic_clock_cannot_authorize_a_mutation(self):
        result = self.run_cmd('enable', POCKETUFW_UPTIME=str(self.base / 'missing'))
        self.assertEqual(result.returncode, 75)
        self.assertFalse(self.exists('iptables', 'POCKETUFW_IN'))


class BootDeadlines(BootTests):
    def slow_attempts(self):
        attempts = self.root / 'attempts'
        shim = self.fakebin / 'flock'
        shim.write_text(f'''#!/bin/sh
read -r stamp rest < "$POCKETUFW_UPTIME"
seconds=${{stamp%.*}}
echo "$((seconds + 45)).00 0.00" > "$POCKETUFW_UPTIME"
echo try >> "{attempts}"
exit 1
''')
        shim.chmod(0o700)
        return attempts

    def test_boot_command_latency_consumes_the_120_second_budget(self):
        self.assertEqual(self.call('enable').returncode, 0)
        self.state.write_text('INACTIVE\n')
        attempts = self.slow_attempts()
        self.assertEqual(self.boot().returncode, 75)
        self.assertEqual(len(attempts.read_text().splitlines()), 3)
        self.assertFalse(self.calls.exists())
        self.assertTrue((self.store / 'boot.enabled').exists())

    def test_bootctl_uses_elapsed_time_too(self):
        attempts = self.slow_attempts()
        self.assertEqual(self.call('enable').returncode, 75)
        self.assertEqual(len(attempts.read_text().splitlines()), 1)
        self.assertFalse(self.hook.exists())


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(cls(name) for cls in (Inspection, Deadlines, BootDeadlines)
                              for name in cls.__dict__ if name.startswith('test_'))
