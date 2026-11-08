"""Independent-audit failures, exercised with disposable devices and fake iptables."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_tunnel_filter as tunnel
import test_integration_real_engine as integration
import test_bootctl as boot


class TunnelAudit(tunnel.Base):
    def setUp(self):
        super().setUp()
        self.proven_tailscale()

    def test_termination_during_tunnel_install_cleans_partial_hooks(self):
        self.ok('enable')
        seen, gate = self.base / 'entered', self.base / 'release'
        pause = f'''echo "$*" >> "$file"
    if [ "$name" = INPUT ] && [ "$*" = "{tunnel.HOOK_TUN}" ]; then
      : > "{seen}"
      while [ ! -f "{gate}" ]; do sleep 0.02; done
    fi'''
        self.script('iptables', tunnel.MOCK.replace('echo "$*" >> "$file"', pause))
        process = subprocess.Popen(['sh', str(tunnel.ENGINE), 'tunnel-on'], env=self.env,
                                   text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            until = time.monotonic() + 5
            while not seen.exists() and time.monotonic() < until:
                time.sleep(.02)
            self.assertTrue(seen.exists())
            os.kill(process.pid, signal.SIGTERM)
        finally:
            gate.touch()
            process.communicate(timeout=10)
        self.assertNotEqual(process.returncode, 0)
        self.tunnel_chains_absent()
        self.assertEqual(self.verify(), 'ACTIVE')

    def test_activity_rejects_a_missing_ipv6_hook(self):
        self.ok('enable')
        self.ok('tunnel-on')
        self.write('ip6tables', 'INPUT', self.read('ip6tables').replace(tunnel.HOOK_TUN + '\n', ''))
        result = self.run_cmd('activity')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), 'state=DEGRADED')

    def test_failed_refresh_restores_both_previous_hook_sets_and_can_retry(self):
        self.device('WG-OLD', wireguard=True)
        self.ok('enable')
        self.ok('tunnel-on')
        before = {fam: self.read(fam) for fam in tunnel.TAILNET}
        self.device('WG-NEW', wireguard=True)
        result = self.run_cmd('tunnel-refresh', PUFW_TEST_FAIL_FAMILY='ip6tables',
                             PUFW_TEST_FAIL='-A INPUT -i WG-NEW -m comment --comment PocketUFW-VPN -j POCKETUFW_VPN')
        self.assertNotEqual(result.returncode, 0)
        for fam, rules in before.items():
            self.assertEqual(self.read(fam), rules)
        self.ok('tunnel-refresh')
        self.assertEqual(self.verify(), 'ACTIVE')

    def test_failed_hook_removal_restores_the_previous_hooks(self):
        self.device('WG-OLD', wireguard=True)
        self.ok('enable')
        self.ok('tunnel-on')
        before = {fam: self.read(fam) for fam in tunnel.TAILNET}
        shutil.rmtree(self.sys / 'WG-OLD')
        result = self.run_cmd('tunnel-refresh', PUFW_TEST_FAIL_FAMILY='ip6tables',
                             PUFW_TEST_FAIL='-D INPUT -i WG-OLD -m comment --comment PocketUFW-VPN -j POCKETUFW_VPN')
        self.assertNotEqual(result.returncode, 0)
        for fam, rules in before.items():
            self.assertEqual(self.read(fam), rules)
        self.ok('tunnel-refresh')

    def test_accept_before_a_later_wireguard_hook_is_reported(self):
        self.device('WG-A', wireguard=True)
        self.ok('enable')
        self.ok('tunnel-on')
        accept = '-i WG-A -p udp --dport 51820 -j ACCEPT\n'
        self.write('iptables', 'INPUT', self.read('iptables').replace('-i WG-A -m comment', accept + '-i WG-A -m comment'))
        result = subprocess.run(['sh', str(tunnel.REPORT)], env=self.env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('input_bypass4_01=-A INPUT ' + accept, result.stdout)

    def test_status_names_unhooked_wireguard_as_partial_coverage(self):
        self.ok('enable')
        self.ok('tunnel-on')
        self.device('WG-NEW', wireguard=True)
        self.assertIn('tunnel_uncovered=WG-NEW', self.ok('tunnel-status'))
        self.ok('tunnel-refresh')
        self.assertIn('tunnel_uncovered=\n', self.ok('tunnel-status'))


class BridgeAudit(integration.RealEngineTests):
    def test_failed_discovery_closes_a_port_reused_by_another_uid(self):
        self.tailscale(46867, None)
        self.bridge('enable')
        self.device.add_command('pidof', '#!/bin/sh\necho 6283\n')
        (self.proc / '8888').mkdir()
        (self.proc / '8888' / 'status').write_text(f'Uid:\t{self.ts_data.stat().st_uid + 1}\n')
        (self.kernel / 'ss4').write_text('UNCONN 0 0 0.0.0.0:46867 0.0.0.0:* users:(("another.app",pid=8888,fd=2))\n')
        values = self.bridge('vpn-refresh')
        self.assertEqual(values['operation'], 'FAILED')
        self.assertIn('Proven-stale', values['message'])
        self.assertEqual(self.chain('iptables', 'POCKETUFW_TS'), [])

    def test_failed_refresh_closes_proven_retired_ports_without_opening_unverified_ones(self):
        self.tailscale(46867, 43504)
        self.bridge('enable')
        # Discovery sees a different UID; both old ports are now absent.
        self.tailscale(31337, 31338, uid=self.ts_data.stat().st_uid + 1)
        values = self.bridge('vpn-refresh')
        self.assertEqual(values['operation'], 'FAILED')
        self.assertEqual(self.chain('iptables', 'POCKETUFW_TS'), [])
        self.assertEqual(self.chain('ip6tables', 'POCKETUFW_TS'), [])

    def test_failed_refresh_preserves_a_still_owned_port_in_the_other_family(self):
        self.tailscale(46867, 43504)
        self.bridge('enable')
        (self.kernel / 'ss6').write_text('')
        # A second, invisible process makes new discovery ambiguous. The old IPv4
        # socket is still Tailscale-owned and must survive the failed refresh.
        with (self.kernel / 'ss4').open('a') as out:
            out.write('UNCONN 0 0 0.0.0.0:31337 0.0.0.0:* users:(("m.tailscale.ipn",pid=99999,fd=2))\n')
        values = self.bridge('vpn-refresh')
        self.assertEqual(values['operation'], 'FAILED')
        self.assertEqual(self.chain('iptables', 'POCKETUFW_TS'), ['-p udp --dport 46867 -j ACCEPT'])
        self.assertEqual(self.chain('ip6tables', 'POCKETUFW_TS'), [])

    def test_unreadable_socket_ownership_never_closes_an_exception(self):
        self.tailscale(46867, 43504)
        self.bridge('enable')
        (self.proc / '6283' / 'status').unlink()
        before = {f: self.chain(f, 'POCKETUFW_TS') for f in integration.FAMILIES}
        self.assertEqual(self.bridge('vpn-refresh')['operation'], 'FAILED')
        for family in integration.FAMILIES:
            self.assertEqual(self.chain(family, 'POCKETUFW_TS'), before[family])

    def test_ipv6_socket_might_still_serve_an_old_ipv4_port(self):
        self.tailscale(46867, 43504)
        self.bridge('enable')
        self.tailscale(None, 46867)
        with (self.kernel / 'ss6').open('a') as out:
            out.write('UNCONN 0 0 [::]:31337 [::]:* users:(("m.tailscale.ipn",pid=99999,fd=2))\n')
        self.assertEqual(self.bridge('vpn-refresh')['operation'], 'FAILED')
        self.assertEqual(self.chain('iptables', 'POCKETUFW_TS'), ['-p udp --dport 46867 -j ACCEPT'])

    def authorized_tunnel(self):
        self.env['POCKETUFW_SYS_NET'] = str(self.root / 'sys')
        dev = self.root / 'sys' / 'tun0'
        dev.mkdir(parents=True)
        (dev / 'ifindex').write_text('6\n')
        (dev / 'uevent').write_text('INTERFACE=tun0\n')
        (dev / 'tun_flags').write_text('0x1001\n')
        proc = self.proc / '6283'
        (proc / 'fd').mkdir()
        (proc / 'fdinfo').mkdir()
        (proc / 'fd' / '9').symlink_to('/dev/tun')
        (proc / 'fdinfo' / '9').write_text('iff:\ttun0\n')
        self.env.update(TEST_VPN_OWNER='com.tailscale.ipn', TEST_VPN_IFACE='tun0')
        self.device.add_command('ip', '#!/bin/sh\ncase "$*" in\n'
                                '"-o link") echo "6: tun0: <POINTOPOINT,UP,LOWER_UP> mtu 1500";;\n'
                                '"-o addr"|"-o addr show dev tun0 scope global")\n'
                                'echo "6: tun0 inet 100.64.0.1/32 scope global tun0"\n'
                                'echo "6: tun0 inet6 fd7a:115c:a1e0::1/128 scope global";;\nesac\n')
        self.bridge('enable')
        result = self.script('pocketufw', 'tunnel-on')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_broken_tunnel_stays_uncovered_and_degraded_in_the_actual_bridge(self):
        self.authorized_tunnel()
        path = self.kernel / 'ip6tables.INPUT'
        path.write_text(path.read_text().replace(tunnel.HOOK_TUN + '\n', ''))
        values = self.bridge('inspect')
        self.assertEqual(values['state'], 'DEGRADED')
        self.assertEqual(values['uncovered_ifaces'], 'tun0')

    def test_bridge_reports_pins_and_later_wireguard_conflict(self):
        self.authorized_tunnel()
        values = self.bridge('inspect')
        self.assertEqual(values['tailnet_trust'], 'PINNED_DESTINATIONS')
        self.assertEqual(values['tailnet_pin4'], '100.64.0.1/32')
        conflict = self.root / 'sys' / 'tun5'
        conflict.mkdir()
        (conflict / 'uevent').write_text('DEVTYPE=wireguard\n')
        values = self.bridge('inspect')
        self.assertEqual(values['state'], 'DEGRADED')
        self.assertEqual(values['tailnet_wireguard'], 'CONFLICT')
        self.assertEqual(values['tunnel_filter'], 'DEGRADED')
        self.assertEqual(values['uncovered_ifaces'], 'tun0')

    def test_boot_enable_cannot_recreate_files_after_clean_removal(self):
        self.bridge('enable')
        gate, seen = self.root / 'release', self.root / 'entered'
        self.device.add_command('mkdir', f'#!/bin/sh\nif [ "$*" = "-p {self.device.store}" ]; then\n'
                                f': > "{seen}"\nwhile [ ! -f "{gate}" ]; do sleep 0.02; done\nfi\n'
                                f'exec "{shutil.which("mkdir")}" "$@"\n')
        process = subprocess.Popen(['sh', str(self.device.engine / 'bootctl'), 'enable'], env=self.env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            until = time.monotonic() + 5
            while not seen.exists() and time.monotonic() < until:
                time.sleep(.02)
            self.assertTrue(seen.exists())
            removal = subprocess.Popen(['sh', str(self.device.engine / 'android-bridge'), 'prepare-uninstall'],
                                       env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                try:
                    out, _ = removal.communicate(timeout=1)
                except subprocess.TimeoutExpired:
                    out = ''
                self.assertNotIn('removal=CLEAN', out)
            finally:
                gate.touch()
                process.communicate(timeout=5)
                removal.communicate(timeout=10)
            self.assertEqual(self.bridge('prepare-uninstall')['removal'], 'CLEAN')
            self.assertFalse(self.device.hook.exists())
            self.assertFalse(self.device.store.exists())
        finally:
            gate.touch()
            process.communicate(timeout=5)


class BootAudit(boot.BootTests):
    def test_foreign_staging_file_is_not_overwritten(self):
        stage = Path(str(self.hook) + '.stage')
        foreign = '#!/bin/sh\n# another owner\n'
        stage.write_text(foreign)
        result = self.call('enable')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(stage.read_text(), foreign)
        self.assertFalse(self.hook.exists())

    def test_failed_self_cleanup_keeps_a_disarmed_retry_hook(self):
        self.assertEqual(self.call('enable').returncode, 0)
        rm = self.fakebin / 'rm'
        rm.write_text(f'#!/bin/sh\nfor arg do [ "$arg" != "{self.store}/pocketufw" ] || exit 1; done\n'
                      f'exec "{shutil.which("rm")}" "$@"\n')
        rm.chmod(0o700)
        result = self.boot({'TEST_PM_MODE': 'gone'})
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.hook.exists())
        self.assertFalse((self.store / 'boot.enabled').exists())
        rm.unlink()
        self.assertEqual(self.boot({'TEST_PM_MODE': 'gone'}).returncode, 0)
        self.assertFalse(self.hook.exists())
        self.assertFalse(self.store.exists())


class RollbackAudit(tunnel.Rollback):
    def test_expiry_cannot_fire_before_a_pending_installer_finishes(self):
        gate, seen = self.base / 'release', self.base / 'entered'
        engine = self.base / 'delayed-engine'
        engine.write_text(f'if [ "$1" = tunnel-on ]; then\n: > "{seen}"\n'
                          f'while [ ! -f "{gate}" ]; do sleep 0.02; done\nfi\n'
                          f'exec sh "{tunnel.ENGINE}" "$@"\n')
        process = subprocess.Popen(['sh', str(tunnel.ROLLBACK), 'on', '1', str(engine)], env=self.env,
                                   text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            until = time.monotonic() + 5
            while not seen.exists() and time.monotonic() < until:
                time.sleep(.02)
            self.assertTrue(seen.exists())
            time.sleep(2.2)
            self.assertNotEqual(self.status(), 'rollback=FIRED')
        finally:
            gate.touch()
            out, err = process.communicate(timeout=10)
            self.wait_for_status('rollback=FIRED')
        self.assertNotEqual(process.returncode, 0, out + err)
        self.tunnel_chains_absent()


def load_tests(loader, tests, pattern):
    # Reuse fixture methods, without rerunning the parent suites here.
    return unittest.TestSuite(cls(name) for cls in (TunnelAudit, BridgeAudit, BootAudit, RollbackAudit)
                              for name in cls.__dict__ if name.startswith('test_'))


if __name__ == '__main__':
    unittest.main()
