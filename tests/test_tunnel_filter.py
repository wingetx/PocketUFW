"""The optional tunnel filter, offline: rule text, verification, ownership, refusals.

What packets actually do is tested in test_tunnel_real_kernel. These cover what a real
kernel can't easily be made to show: forged ownership, tampered rules, failed commands.
"""
import os
import pathlib
import re
import signal
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_pocketufw import MOCK

ROOT = pathlib.Path(__file__).resolve().parents[1]
ENGINE = ROOT / 'pocketufw'
PROBE = ROOT / 'vpn-probe'
REPORT = ROOT / 'rules-report'
ROLLBACK = ROOT / 'tools' / 'tunnel-rollback'
TAG = 'PocketUFW-VPN'

FAKE_IP = r'''#!/bin/sh
# ip -o -4 addr show dev NAME scope global
[ "$1 $3 $4 $5" = "-o addr show dev" ] || exit 2
if [ "$2" = -4 ] && [ -n "${PUFW_TEST_ADDR4:-}" ]; then echo "52: $6    inet $PUFW_TEST_ADDR4/32 scope global $6"; fi
if [ "$2" = -6 ] && [ -n "${PUFW_TEST_ADDR6:-}" ]; then echo "52: $6    inet6 $PUFW_TEST_ADDR6/128 scope global"; fi
'''
HOOK_TUN = f'-i tun+ -m comment --comment {TAG} -j POCKETUFW_VPN'


class Base(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='pufw-tunnel-')
        self.addCleanup(temp.cleanup)
        self.base = pathlib.Path(temp.name)
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        for name in ('iptables', 'ip6tables'):
            self.script(name, MOCK)
            (self.base / f'{name}.INPUT').write_text('-j oem_in\n-j bw_INPUT\n-j fw_INPUT\n')
        self.script('id', '#!/bin/sh\necho 0\n')
        self.script('ip', FAKE_IP)
        self.script('dumpsys', '#!/bin/sh\ncat "$PUFW_TEST_DIR/dumpsys.txt" 2>/dev/null\n')
        self.sys = self.base / 'sys'
        self.proc = self.base / 'proc'
        self.sys.mkdir()
        self.proc.mkdir()
        self.packages = self.base / 'packages.list'
        self.packages.write_text('com.tailscale.ipn 10345 0\nch.protonvpn.android 10328 0\ncom.termux 10378 0\n')
        self.env = {**os.environ, 'PATH': f'{self.bin}{os.pathsep}{os.environ["PATH"]}',
                    'PUFW_TEST_DIR': str(self.base), 'POCKETUFW_LOCK': str(self.base / 'lock'),
                    'POCKETUFW_SYS_NET': str(self.sys), 'POCKETUFW_PROC_ROOT': str(self.proc),
                    'POCKETUFW_PACKAGES_LIST': str(self.packages),
                    'POCKETUFW_ROLLBACK_STATE': str(self.base / 'rollback')}

    def script(self, name, source):
        path = self.bin / name
        path.write_text(source)
        path.chmod(0o755)

    def device(self, name, wireguard=False, tun_flags=None):
        path = self.sys / name
        path.mkdir()
        (path / 'uevent').write_text(f'{"DEVTYPE=wireguard" + chr(10) if wireguard else ""}INTERFACE={name}\n')
        if tun_flags:
            (path / 'tun_flags').write_text(tun_flags + '\n')

    def process(self, pid, uid, **held):
        """held maps a descriptor name like fd138 to the interface fdinfo reports."""
        path = self.proc / str(pid)
        (path / 'fd').mkdir(parents=True)
        (path / 'fdinfo').mkdir()
        (path / 'status').write_text(f'Name:\tx\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n')
        os.symlink('/dev/null', path / 'fd' / '0')
        (path / 'fdinfo' / '0').write_text('pos:\t0\n')
        for fd, iface in held.items():
            number = fd.removeprefix('fd')
            os.symlink('/dev/tun', path / 'fd' / number)
            (path / 'fdinfo' / number).write_text(f'pos:\t76\nflags:\t02404002\niff:\t{iface}\n')

    def android_says(self, *claims):
        (self.base / 'dumpsys.txt').write_text(''.join(
            f'NetworkAgentInfo{{ni{{VPN CONNECTED extra: VPN:{owner}}} LinkProperties{{InterfaceName: {iface} }}}}\n'
            for owner, iface in claims))

    def proven_tailscale(self, iface='tun1', uid=10345):
        self.device(iface, tun_flags='0x1001')
        self.process(1000 + len(list(self.proc.iterdir())), uid, fd138=iface)
        self.android_says(('com.tailscale.ipn', iface))
        self.env |= {'PUFW_TEST_ADDR4': '100.64.0.1', 'PUFW_TEST_ADDR6': 'fd7a:115c:a1e0::1'}

    def run_cmd(self, *args, **extra):
        return subprocess.run(['sh', str(ENGINE), *args], text=True, capture_output=True,
                              env=self.env | extra, timeout=60)

    def ok(self, *args, **extra):
        result = self.run_cmd(*args, **extra)
        self.assertEqual(result.returncode, 0, f'{args}: {result.stdout}{result.stderr}')
        return result.stdout

    def read(self, fam, chain='INPUT'):
        return (self.base / f'{fam}.{chain}').read_text()

    def write(self, fam, chain, text):
        (self.base / f'{fam}.{chain}').write_text(text)

    def exists(self, fam, chain):
        return (self.base / f'{fam}.{chain}').exists()

    def tunnel_chains_absent(self):
        for fam in ('iptables', 'ip6tables'):
            for chain in ('POCKETUFW_VPN', 'POCKETUFW_TRUST'):
                self.assertFalse(self.exists(fam, chain), f'{fam} {chain}')
            self.assertNotIn(TAG, self.read(fam))

    def verify(self):
        return self.run_cmd('verify').stdout.strip()


class OptionalAndSeparate(Base):
    def test_nothing_about_the_filter_appears_unless_asked_for(self):
        self.proven_tailscale()
        self.ok('enable')
        self.tunnel_chains_absent()
        self.assertEqual(self.verify(), 'ACTIVE')
        self.assertIn('tunnel_filter=OFF', self.ok('activity'))
        self.assertNotIn('POCKETUFW_VPN', self.ok('plan'))

    def test_the_physical_policy_is_byte_identical_with_the_filter_on_and_after_it_is_off(self):
        self.ok('enable', '--tailscale-udp4', '46867', '--tailscale-udp6', '43504')
        before = {(fam, chain): self.read(fam, chain) for fam in ('iptables', 'ip6tables')
                  for chain in ('INPUT', 'POCKETUFW_IN', 'POCKETUFW_TS')}
        self.device('tun1', tun_flags='0x1001')
        self.ok('tunnel-on')
        for (fam, chain), text in before.items():
            if chain == 'INPUT':
                self.assertTrue(self.read(fam).startswith(text), f'{fam}: new hooks must only follow')
            else:
                self.assertEqual(self.read(fam, chain), text)
        self.ok('tunnel-off')
        for (fam, chain), text in before.items():
            self.assertEqual(self.read(fam, chain), text)
        self.assertEqual(self.verify(), 'ACTIVE')

    def test_it_needs_a_verified_firewall_and_otherwise_changes_nothing(self):
        result = self.run_cmd('tunnel-on')
        self.assertNotEqual(result.returncode, 0)
        self.tunnel_chains_absent()
        self.ok('enable')
        self.write('iptables', 'POCKETUFW_IN', self.read('iptables', 'POCKETUFW_IN').replace('-j DROP\n', '', 1))
        self.assertNotEqual(self.run_cmd('tunnel-on').returncode, 0)
        self.tunnel_chains_absent()

    def test_it_refuses_to_install_twice_or_alongside_afwall(self):
        self.ok('enable')
        self.ok('tunnel-on')
        self.assertNotEqual(self.run_cmd('tunnel-on').returncode, 0)
        self.ok('tunnel-off')
        self.assertNotEqual(self.run_cmd('tunnel-on', PUFW_TEST_AFWALL='1').returncode, 0)
        self.tunnel_chains_absent()

    def test_plan_prints_rules_and_changes_nothing(self):
        self.proven_tailscale()
        self.ok('enable')
        before = sorted(path.name for path in self.base.iterdir())
        output = self.ok('tunnel-plan', '--trust', 'tcp:100.64.0.2:22000')
        self.assertIn('DRY RUN', output)
        self.assertIn('-s 100.64.0.2/32 -d 100.64.0.1/32 -i tun1 -p tcp --dport 22000 -j ACCEPT', output)
        self.assertEqual(sorted(path.name for path in self.base.iterdir()), before)
        self.tunnel_chains_absent()

    def test_exact_rules_in_both_families(self):
        self.ok('enable')
        self.ok('tunnel-on')
        for fam in ('iptables', 'ip6tables'):
            self.assertEqual(self.read(fam, 'POCKETUFW_VPN'), (
                '-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n'
                '-m conntrack --ctstate INVALID -j DROP\n'
                '-j POCKETUFW_TRUST\n-j DROP\n'))
            self.assertEqual(self.read(fam, 'POCKETUFW_TRUST'), '')
            self.assertEqual(self.read(fam).count(HOOK_TUN), 1)
        self.assertEqual(self.verify(), 'ACTIVE')

    def test_a_failed_install_removes_only_tunnel_rules(self):
        self.ok('enable')
        physical = self.read('iptables', 'POCKETUFW_IN')
        result = self.run_cmd('tunnel-on', PUFW_TEST_FAIL=f'-A INPUT {HOOK_TUN}', PUFW_TEST_FAIL_FAMILY='ip6tables')
        self.assertNotEqual(result.returncode, 0)
        self.tunnel_chains_absent()
        self.assertEqual(self.read('iptables', 'POCKETUFW_IN'), physical)
        self.assertEqual(self.verify(), 'ACTIVE')


class WhatGetsHooked(Base):
    def hooks(self, fam='iptables'):
        return [line.split()[1] for line in self.read(fam).splitlines() if TAG in line]

    def test_kernel_wireguard_is_found_by_kernel_type_never_by_name(self):
        self.device('US-TEST-1', wireguard=True)
        self.device('wg0')
        self.device('wireguard0')
        self.ok('enable')
        self.ok('tunnel-on')
        self.assertEqual(self.hooks(), ['tun+', 'US-TEST-1'])
        self.assertEqual(self.hooks('ip6tables'), ['tun+', 'US-TEST-1'])

    def test_a_wireguard_named_like_a_tun_is_not_hooked_twice(self):
        self.device('tun5', wireguard=True)
        self.ok('enable')
        self.ok('tunnel-on')
        self.assertEqual(self.hooks(), ['tun+'])

    def test_other_tunnels_and_names_that_could_mislead_iptables_are_left_alone(self):
        self.device('ipsec0')
        self.device('v4-rmnet16', tun_flags='0x1001')
        self.device('wlan9', wireguard=True)
        self.device('rmnet9', wireguard=True)
        self.device('-j', wireguard=True)
        self.device('bad+name', wireguard=True)
        self.device('sixteen-chars-xx', wireguard=True)
        self.ok('enable')
        self.ok('tunnel-on')
        self.assertEqual(self.hooks(), ['tun+'])

    def test_too_many_tunnels_refuses_rather_than_covering_some(self):
        for number in range(8):
            self.device(f'wgx{number}', wireguard=True)
        self.ok('enable')
        result = self.run_cmd('tunnel-on')
        self.assertNotEqual(result.returncode, 0)
        self.tunnel_chains_absent()

    def test_an_unfinished_inventory_decides_nothing(self):
        self.ok('enable')
        self.assertNotEqual(self.run_cmd('tunnel-on', POCKETUFW_SYS_NET=str(self.base / 'missing')).returncode, 0)
        self.tunnel_chains_absent()


class Ownership(Base):
    def probe(self):
        result = subprocess.run(['sh', str(PROBE), 'tunnels'], text=True, capture_output=True, env=self.env, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines()[-1], 'inventory=COMPLETE')
        return result.stdout.splitlines()[:-1]

    def test_verified_needs_android_and_the_kernel_to_agree(self):
        self.proven_tailscale()
        self.assertEqual(self.probe(), ['tunnel=tun1 kind=tun owner=com.tailscale.ipn proof=verified'])

    def test_the_interface_number_means_nothing(self):
        self.proven_tailscale('tun0', uid=10345)
        self.assertEqual(self.probe(), ['tunnel=tun0 kind=tun owner=com.tailscale.ipn proof=verified'])

    def test_a_proton_tun0_is_protons(self):
        self.device('tun0', tun_flags='0x1001')
        self.process(50, 10328, fd9='tun0')
        self.android_says(('ch.protonvpn.android', 'tun0'))
        self.assertEqual(self.probe(), ['tunnel=tun0 kind=tun owner=ch.protonvpn.android proof=verified'])

    def test_another_users_copy_of_the_package_still_proves_it(self):
        self.proven_tailscale(uid=1010345)
        self.assertEqual(self.probe(), ['tunnel=tun1 kind=tun owner=com.tailscale.ipn proof=verified'])

    def test_a_process_with_the_wrong_app_id_proves_nothing(self):
        self.device('tun1', tun_flags='0x1001')
        self.process(50, 10999, fd9='tun1')
        self.android_says(('com.tailscale.ipn', 'tun1'))
        self.assertEqual(self.probe(), ['tunnel=tun1 kind=tun owner=com.tailscale.ipn proof=android-only'])

    def test_the_right_app_holding_a_different_tun_proves_nothing(self):
        self.device('tun1', tun_flags='0x1001')
        self.process(50, 10345, fd9='tun2')
        self.android_says(('com.tailscale.ipn', 'tun1'))
        self.assertEqual(self.probe(), ['tunnel=tun1 kind=tun owner=com.tailscale.ipn proof=android-only'])

    def test_a_package_android_has_no_app_id_for_proves_nothing(self):
        self.device('tun1', tun_flags='0x1001')
        self.process(50, 10345, fd9='tun1')
        self.android_says(('com.example.unlisted', 'tun1'))
        self.assertEqual(self.probe(), ['tunnel=tun1 kind=tun owner=com.example.unlisted proof=android-only'])

    def test_the_kernel_alone_names_no_owner(self):
        self.device('tun1', tun_flags='0x1001')
        self.process(50, 10345, fd9='tun1')
        self.assertEqual(self.probe(), ['tunnel=tun1 kind=tun owner=unknown proof=none'])

    def test_conflicting_android_claims_name_no_owner(self):
        self.device('tun1', tun_flags='0x1001')
        self.process(50, 10345, fd9='tun1')
        self.android_says(('com.tailscale.ipn', 'tun1'), ('ch.protonvpn.android', 'tun1'))
        self.assertEqual(self.probe(), ['tunnel=tun1 kind=tun owner=unknown proof=none'])

    def test_a_tap_device_is_not_a_vpn_tun(self):
        self.device('tun7', tun_flags='0x1002')
        self.assertEqual(self.probe(), [])

    def test_kernel_wireguard_is_labelled_by_type(self):
        self.device('US-TEST-1', wireguard=True)
        self.assertEqual(self.probe(), ['tunnel=US-TEST-1 kind=wireguard owner=kernel proof=kernel-type'])

    def test_the_existing_udp_probe_is_unchanged_by_the_new_subcommand(self):
        env = self.env | {'POCKETUFW_SS_BIN': str(self.bin / 'ss')}
        self.script('ss', '#!/bin/sh\nexit 0\n')
        result = subprocess.run(['sh', str(PROBE)], text=True, capture_output=True, env=env, timeout=30)
        self.assertEqual(result.stdout, 'tailscale_udp4=\ntailscale_udp6=\n')


class Allowances(Base):
    def rule(self, fam='iptables'):
        return self.read(fam, 'POCKETUFW_TRUST')

    def test_an_allowance_binds_peer_own_address_interface_protocol_and_port(self):
        self.proven_tailscale()
        self.ok('enable')
        self.ok('tunnel-on', '--trust', 'tcp:100.64.0.2:22000', '--trust', 'udp:fd7a:115c:a1e0::2:22000')
        self.assertEqual(self.rule(), '-s 100.64.0.2/32 -d 100.64.0.1/32 -i tun1 -p tcp --dport 22000 -j ACCEPT\n')
        self.assertEqual(self.rule('ip6tables'),
                         '-s fd7a:115c:a1e0::2/128 -d fd7a:115c:a1e0::1/128 -i tun1 -p udp --dport 22000 -j ACCEPT\n')
        self.assertEqual(self.verify(), 'ACTIVE')

    def test_no_allowance_without_proof_that_the_tunnel_is_tailscales(self):
        cases = {
            'no tunnel at all': lambda: None,
            'unclaimed tun': lambda: (self.device('tun1', tun_flags='0x1001'), self.process(50, 10345, fd9='tun1')),
            'android only': lambda: (self.device('tun1', tun_flags='0x1001'),
                                     self.android_says(('com.tailscale.ipn', 'tun1'))),
            'impostor process': lambda: (self.device('tun1', tun_flags='0x1001'), self.process(50, 10999, fd9='tun1'),
                                         self.android_says(('com.tailscale.ipn', 'tun1'))),
            'proton owns it': lambda: (self.device('tun1', tun_flags='0x1001'), self.process(50, 10328, fd9='tun1'),
                                       self.android_says(('ch.protonvpn.android', 'tun1'))),
        }
        self.ok('enable')
        for name, arrange in cases.items():
            with self.subTest(name):
                for tree in (self.sys, self.proc):
                    for child in tree.iterdir():
                        subprocess.run(['rm', '-rf', str(child)], check=True)
                (self.base / 'dumpsys.txt').write_text('')
                self.env |= {'PUFW_TEST_ADDR4': '100.64.0.1', 'PUFW_TEST_ADDR6': 'fd7a:115c:a1e0::1'}
                arrange()
                result = self.run_cmd('tunnel-on', '--trust', 'tcp:100.64.0.2:22')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('proven', result.stderr)
                self.tunnel_chains_absent()

    def test_two_proven_tailscale_tunnels_are_ambiguous(self):
        self.proven_tailscale('tun1')
        self.device('tun2', tun_flags='0x1001')
        self.process(77, 10345, fd9='tun2')
        self.android_says(('com.tailscale.ipn', 'tun1'), ('com.tailscale.ipn', 'tun2'))
        self.ok('enable')
        self.assertNotEqual(self.run_cmd('tunnel-on', '--trust', 'tcp:100.64.0.2:22').returncode, 0)
        self.tunnel_chains_absent()

    def test_only_one_tailscale_address_and_one_port_is_accepted(self):
        self.proven_tailscale()
        self.ok('enable')
        for spec in ('tcp:0.0.0.0:22', 'tcp:8.8.8.8:22', 'tcp:192.168.1.5:22', 'tcp:100.63.255.255:22',
                     'tcp:100.128.0.1:22', 'tcp:100.64.0.1/10:22', 'tcp:100.64.0:22', 'tcp:100.64.0.1.2:22',
                     'tcp:100.064.0.1:22', 'tcp:::1:22', 'tcp:fd7a:115c:a1e1::1:22', 'tcp:2001:db8::1:22',
                     'tcp:fe80::1:22', 'icmp:100.64.0.2:22', 'all:100.64.0.2:22', 'tcp:100.64.0.2',
                     'tcp:100.64.0.2:', 'tcp:100.64.0.2:0', 'tcp:100.64.0.2:65536', 'tcp:100.64.0.2:022',
                     'tcp:100.64.0.2:22 -j ACCEPT', 'tcp:100.64.0.2:1-65535', 'TCP:100.64.0.2:22', 'x'):
            with self.subTest(spec):
                self.assertNotEqual(self.run_cmd('tunnel-on', '--trust', spec).returncode, 0)
                self.tunnel_chains_absent()

    def test_an_allowance_for_a_family_tailscale_has_no_address_in_is_refused(self):
        self.proven_tailscale()
        self.ok('enable')
        result = self.run_cmd('tunnel-on', '--trust', 'tcp:fd7a:115c:a1e0::2:22', PUFW_TEST_ADDR6='')
        self.assertNotEqual(result.returncode, 0)
        self.tunnel_chains_absent()

    def test_too_many_allowances_are_refused(self):
        self.proven_tailscale()
        self.ok('enable')
        args = [arg for port in range(1, 8) for arg in ('--trust', f'tcp:100.64.0.2:{port}')]
        self.assertNotEqual(self.run_cmd('tunnel-on', *args).returncode, 0)
        self.tunnel_chains_absent()

    def test_trust_is_accepted_only_where_it_means_something(self):
        for command in ('enable', 'tunnel-refresh', 'tunnel-status', 'tunnel-off', 'verify', 'disable'):
            with self.subTest(command):
                self.assertNotEqual(self.run_cmd(command, '--trust', 'tcp:100.64.0.2:22').returncode, 0)


class Verification(Base):
    def fresh_tables(self):
        """A hook edited by hand isn't ours to delete, so start over rather than disable."""
        for fam in ('iptables', 'ip6tables'):
            for chain in ('POCKETUFW_IN', 'POCKETUFW_TS', 'POCKETUFW_VPN', 'POCKETUFW_TRUST'):
                (self.base / f'{fam}.{chain}').unlink(missing_ok=True)
            self.write(fam, 'INPUT', '-j oem_in\n-j bw_INPUT\n-j fw_INPUT\n')

    def tampered(self, fam, chain, change):
        self.write(fam, chain, change(self.read(fam, chain)))
        self.assertEqual(self.verify(), 'DEGRADED')

    def test_any_change_to_the_tunnel_rules_is_degraded(self):
        ok_trust = '-s 100.64.0.2/32 -d 100.64.0.1/32 -i tun1 -p tcp --dport 22 -j ACCEPT\n'
        cases = {
            'unconditional accept first': ('POCKETUFW_VPN', lambda t: '-j ACCEPT\n' + t),
            'unconditional accept last': ('POCKETUFW_VPN', lambda t: t + '-j ACCEPT\n'),
            'final drop gone': ('POCKETUFW_VPN', lambda t: t.replace('-j DROP\n', '')),
            'final drop becomes accept': ('POCKETUFW_VPN', lambda t: t.replace('-j DROP\n', '-j ACCEPT\n')),
            'established gone': ('POCKETUFW_VPN', lambda t: t.split('\n', 1)[1]),
            'established widened to all states': ('POCKETUFW_VPN', lambda t: t.replace('ESTABLISHED,RELATED', 'NEW,ESTABLISHED,RELATED')),
            'reordered': ('POCKETUFW_VPN', lambda t: ''.join(reversed(t.splitlines(True)))),
            'wide open allowance': ('POCKETUFW_TRUST', lambda t: '-j ACCEPT\n'),
            'any port': ('POCKETUFW_TRUST', lambda t: '-s 100.64.0.2/32 -d 100.64.0.1/32 -i tun1 -j ACCEPT\n'),
            'any peer': ('POCKETUFW_TRUST', lambda t: '-d 100.64.0.1/32 -i tun1 -p tcp --dport 22 -j ACCEPT\n'),
            'any interface': ('POCKETUFW_TRUST', lambda t: '-s 100.64.0.2/32 -d 100.64.0.1/32 -p tcp --dport 22 -j ACCEPT\n'),
            'any destination': ('POCKETUFW_TRUST', lambda t: '-s 100.64.0.2/32 -i tun1 -p tcp --dport 22 -j ACCEPT\n'),
            'peer range': ('POCKETUFW_TRUST', lambda t: '-s 100.64.0.0/10 -d 100.64.0.1/32 -i tun1 -p tcp --dport 22 -j ACCEPT\n'),
            'peer off the tailnet': ('POCKETUFW_TRUST', lambda t: '-s 8.8.8.8/32 -d 100.64.0.1/32 -i tun1 -p tcp --dport 22 -j ACCEPT\n'),
            'wildcard interface': ('POCKETUFW_TRUST', lambda t: '-s 100.64.0.2/32 -d 100.64.0.1/32 -i tun+ -p tcp --dport 22 -j ACCEPT\n'),
            'physical interface': ('POCKETUFW_TRUST', lambda t: '-s 100.64.0.2/32 -d 100.64.0.1/32 -i wlan0 -p tcp --dport 22 -j ACCEPT\n'),
            'jumps elsewhere': ('POCKETUFW_TRUST', lambda t: '-s 100.64.0.2/32 -d 100.64.0.1/32 -i tun1 -p tcp --dport 22 -j RETURN\n'),
            'too many': ('POCKETUFW_TRUST', lambda t: ok_trust * 7),
            'hook gone': ('INPUT', lambda t: t.replace(HOOK_TUN + '\n', '')),
            'hook narrowed': ('INPUT', lambda t: t.replace(HOOK_TUN, f'-i tun+ -p tcp -m comment --comment {TAG} -j POCKETUFW_VPN')),
            'hook retagged': ('INPUT', lambda t: t.replace(TAG, 'Other')),
        }
        for fam in ('iptables', 'ip6tables'):
            if fam == 'ip6tables':
                cases = {k: v for k, v in cases.items() if v[0] != 'POCKETUFW_TRUST'}
            for name, (chain, change) in cases.items():
                with self.subTest(fam=fam, case=name):
                    self.ok('enable')
                    self.ok('tunnel-on')
                    self.assertEqual(self.verify(), 'ACTIVE')
                    self.tampered(fam, chain, change)
                    for command in ('refresh', 'tunnel-refresh', 'reset-counters'):
                        self.assertNotEqual(self.run_cmd(command).returncode, 0, command)
                    self.fresh_tables()

    def test_a_chain_missing_from_one_family_is_degraded(self):
        for fam in ('iptables', 'ip6tables'):
            for chain in ('POCKETUFW_VPN', 'POCKETUFW_TRUST'):
                with self.subTest(fam=fam, chain=chain):
                    self.ok('enable')
                    self.ok('tunnel-on')
                    (self.base / f'{fam}.{chain}').unlink()
                    self.assertEqual(self.verify(), 'DEGRADED')
                    self.ok('disable')

    def test_hooks_that_differ_between_families_are_degraded(self):
        self.device('US-TEST-1', wireguard=True)
        self.ok('enable')
        self.ok('tunnel-on')
        self.write('ip6tables', 'INPUT', self.read('ip6tables').replace(
            f'-i US-TEST-1 -m comment --comment {TAG} -j POCKETUFW_VPN\n', ''))
        self.assertEqual(self.verify(), 'DEGRADED')

    def test_tunnel_rules_without_the_physical_policy_are_degraded_not_inactive(self):
        self.ok('enable')
        self.ok('tunnel-on')
        for fam in ('iptables', 'ip6tables'):
            for chain in ('POCKETUFW_IN', 'POCKETUFW_TS'):
                (self.base / f'{fam}.{chain}').unlink()
            self.write(fam, 'INPUT', ''.join(line for line in self.read(fam).splitlines(True) if 'POCKETUFW_IN' not in line))
        self.assertEqual(self.verify(), 'DEGRADED')
        self.assertNotEqual(self.run_cmd('activity').returncode, 0)
        self.ok('disable')
        self.assertEqual(self.verify(), 'INACTIVE')


class Counters(Base):
    def values(self, **extra):
        return dict(line.split('=', 1) for line in self.ok('activity', **extra).splitlines() if '=' in line)

    def test_tunnel_counters_are_their_own_and_do_not_change_the_physical_ones(self):
        self.proven_tailscale()
        self.ok('enable')
        self.ok('tunnel-on', '--trust', 'tcp:100.64.0.2:22')
        values = self.values(PUFW_TEST_DROP4='3', PUFW_TEST_REPLIES4='9', PUFW_TEST_DROP_BYTES4='30',
                             PUFW_TEST_TUNNEL_DROP='5', PUFW_TEST_TUNNEL_INVALID='2', PUFW_TEST_TUNNEL_REPLIES='11',
                             PUFW_TEST_TUNNEL_BYTES='70', PUFW_TEST_TRUSTED='4')
        self.assertEqual(values['ipv4_blocked'], '3')
        self.assertEqual(values['ipv4_established_replies'], '9')
        self.assertEqual(values['ipv4_tunnel_blocked'], '7')
        self.assertEqual(values['ipv4_tunnel_blocked_bytes'], '70')
        self.assertEqual(values['ipv4_tunnel_established_replies'], '11')
        self.assertEqual(values['ipv4_tunnel_trusted'], '4')
        self.assertEqual(values['tunnel_hooks'], 'tun+')
        self.assertEqual(values['tunnel_filter'], 'ON')

    def test_a_listing_that_cannot_be_read_is_never_a_zero(self):
        self.ok('enable')
        self.ok('tunnel-on')
        for shape in ('no_header', 'no_established', 'no_invalid', 'no_final_drop', 'extra_drop'):
            with self.subTest(shape):
                result = self.run_cmd('activity', PUFW_TEST_TUNNEL_SHAPE=shape)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('ipv4_tunnel_blocked', result.stdout)

    def test_verbose_reports_the_filter(self):
        self.ok('enable')
        self.assertIn('Tunnel filter: OFF', self.ok('verbose'))
        self.ok('tunnel-on')
        output = self.ok('verbose', PUFW_TEST_TUNNEL_DROP='5')
        self.assertIn('Tunnel filter: ON', output)
        self.assertIn('Tunnel hooks: tun+', output)
        self.assertIn('Tunnel IPv4 blocked: 5 packets', output)

    def test_reset_zeroes_tunnel_chains_only_when_they_exist(self):
        self.ok('enable')
        self.ok('reset-counters')
        events = (self.base / 'zero_events').read_text()
        self.assertNotIn('POCKETUFW_VPN', events)
        self.ok('tunnel-on')
        (self.base / 'zero_events').unlink()
        self.ok('reset-counters')
        events = (self.base / 'zero_events').read_text().splitlines()
        for fam in ('iptables', 'ip6tables'):
            for chain in ('POCKETUFW_IN', 'POCKETUFW_TS', 'POCKETUFW_VPN', 'POCKETUFW_TRUST'):
                self.assertIn(f'{fam} {chain}', events)
        self.assertEqual(len(events), 8)


class Lifecycle(Base):
    def test_disable_removes_everything_and_residue_agrees(self):
        self.proven_tailscale()
        self.device('US-TEST-1', wireguard=True)
        self.ok('enable')
        baseline = '-j oem_in\n-j bw_INPUT\n-j fw_INPUT\n'
        self.ok('tunnel-on', '--trust', 'tcp:100.64.0.2:22')
        self.assertIn('residue_ipv4=', self.ok('residue'))
        self.assertNotIn('residue_ipv4=0', self.ok('residue'))
        self.ok('disable')
        self.assertEqual(self.ok('residue'), 'residue_ipv4=0\nresidue_ipv6=0\n')
        self.tunnel_chains_absent()
        for fam in ('iptables', 'ip6tables'):
            self.assertEqual(self.read(fam), baseline)
        self.assertEqual(self.verify(), 'INACTIVE')

    def test_tunnel_off_is_idempotent_and_leaves_the_firewall_on(self):
        self.ok('enable')
        self.ok('tunnel-off')
        self.ok('tunnel-on')
        self.ok('tunnel-off')
        self.ok('tunnel-off')
        self.tunnel_chains_absent()
        self.assertEqual(self.verify(), 'ACTIVE')

    def test_a_failed_removal_says_so(self):
        self.ok('enable')
        self.ok('tunnel-on')
        result = self.run_cmd('tunnel-off', PUFW_TEST_FAIL='-X POCKETUFW_VPN')
        self.assertNotEqual(result.returncode, 0)
        result = self.run_cmd('disable', PUFW_TEST_FAIL='-X POCKETUFW_VPN')
        self.assertNotEqual(result.returncode, 0)

    def test_someone_elses_rule_naming_the_chain_is_never_deleted(self):
        self.ok('enable')
        self.ok('tunnel-on')
        foreign = '-i wlan0 -p tcp -j POCKETUFW_VPN\n'
        self.write('iptables', 'INPUT', self.read('iptables') + foreign)
        self.assertNotEqual(self.run_cmd('tunnel-off').returncode, 0)
        self.assertIn(foreign, self.read('iptables'))

    def test_enable_refuses_while_tunnel_rules_remain(self):
        self.ok('enable')
        self.ok('tunnel-on')
        result = self.run_cmd('enable')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.verify(), 'ACTIVE')


class Refresh(Base):
    def test_allowances_follow_tailscale_to_its_new_tun(self):
        self.proven_tailscale('tun1')
        self.ok('enable')
        self.ok('tunnel-on', '--trust', 'tcp:100.64.0.2:22', '--trust', 'udp:fd7a:115c:a1e0::2:53')
        self.assertIn('binding=BOUND', self.ok('tunnel-status'))
        # Android re-established the VPN on the next free number.
        subprocess.run(['rm', '-rf', str(self.sys / 'tun1'), str(self.proc)], check=True)
        self.proc.mkdir()
        self.proven_tailscale('tun2')
        status = self.ok('tunnel-status')
        self.assertIn('allowance=tcp:100.64.0.2:22 iface=tun1 binding=STALE', status)
        self.assertEqual(self.verify(), 'ACTIVE')
        self.ok('tunnel-refresh')
        self.assertEqual(self.read('iptables', 'POCKETUFW_TRUST'),
                         '-s 100.64.0.2/32 -d 100.64.0.1/32 -i tun2 -p tcp --dport 22 -j ACCEPT\n')
        self.assertEqual(self.read('ip6tables', 'POCKETUFW_TRUST'),
                         '-s fd7a:115c:a1e0::2/128 -d fd7a:115c:a1e0::1/128 -i tun2 -p udp --dport 53 -j ACCEPT\n')
        self.assertIn('allowance=tcp:100.64.0.2:22 iface=tun2 binding=BOUND', self.ok('tunnel-status'))

    def test_an_allowance_never_moves_to_a_tunnel_that_is_not_proven(self):
        self.proven_tailscale('tun1')
        self.ok('enable')
        self.ok('tunnel-on', '--trust', 'tcp:100.64.0.2:22')
        before = self.read('iptables', 'POCKETUFW_TRUST')
        subprocess.run(['rm', '-rf', str(self.sys / 'tun1'), str(self.proc)], check=True)
        self.proc.mkdir()
        self.device('tun2', tun_flags='0x1001')
        self.process(50, 10328, fd9='tun2')
        self.android_says(('ch.protonvpn.android', 'tun2'))
        self.ok('tunnel-refresh')
        self.assertEqual(self.read('iptables', 'POCKETUFW_TRUST'), before)
        self.assertIn('binding=STALE', self.ok('tunnel-status'))

    def test_a_new_wireguard_is_hooked_and_a_gone_one_unhooked(self):
        self.device('US-TEST-1', wireguard=True)
        self.ok('enable')
        self.ok('tunnel-on')
        subprocess.run(['rm', '-rf', str(self.sys / 'US-TEST-1')], check=True)
        self.device('US-TEST-2', wireguard=True)
        self.ok('tunnel-refresh')
        for fam in ('iptables', 'ip6tables'):
            input_rules = self.read(fam)
            self.assertIn('-i US-TEST-2 ', input_rules)
            self.assertNotIn('-i US-TEST-1 ', input_rules)
            self.assertIn(HOOK_TUN, input_rules)
        self.assertEqual(self.verify(), 'ACTIVE')

    def test_refresh_refuses_too_many_tunnels_and_changes_nothing(self):
        self.ok('enable')
        self.ok('tunnel-on')
        before = self.read('iptables')
        for number in range(8):
            self.device(f'wgx{number}', wireguard=True)
        self.assertNotEqual(self.run_cmd('tunnel-refresh').returncode, 0)
        self.assertEqual(self.read('iptables'), before)
        self.assertEqual(self.verify(), 'ACTIVE')

    def test_refresh_has_nothing_to_do_when_off(self):
        self.ok('enable')
        self.assertNotEqual(self.run_cmd('tunnel-refresh').returncode, 0)
        self.assertEqual(self.ok('tunnel-status').splitlines()[0], 'tunnel_filter=OFF')

    def test_status_reports_owners_and_degradation(self):
        self.proven_tailscale('tun1')
        self.device('US-TEST-1', wireguard=True)
        self.ok('enable')
        self.ok('tunnel-on')
        status = self.ok('tunnel-status')
        self.assertIn('tunnel_filter=ON', status)
        self.assertIn('tunnel=tun1 kind=tun owner=com.tailscale.ipn proof=verified', status)
        self.assertIn('tunnel=US-TEST-1 kind=wireguard owner=kernel proof=kernel-type', status)
        self.assertIn('tunnel_hooks=tun+,US-TEST-1', status)
        self.write('iptables', 'POCKETUFW_VPN', '-j ACCEPT\n')
        self.assertIn('tunnel_filter=DEGRADED', self.ok('tunnel-status'))


class Report(Base):
    def report(self):
        return subprocess.run(['sh', str(REPORT)], text=True, capture_output=True, env=self.env, timeout=30)

    def test_with_the_filter_off_the_report_is_what_it_always_was(self):
        self.ok('enable')
        result = self.report()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('POCKETUFW_VPN', result.stdout)
        self.assertEqual(result.stdout.count('hook4_'), 3)

    def test_with_the_filter_on_its_hooks_and_rules_continue_the_same_lists(self):
        self.proven_tailscale()
        self.ok('enable')
        self.ok('tunnel-on', '--trust', 'tcp:100.64.0.2:22')
        result = self.report()
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertIn(f'hook4_04=-A INPUT {HOOK_TUN}', lines)
        self.assertIn('main4_09=-A POCKETUFW_VPN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT', lines)
        self.assertIn('main4_12=-A POCKETUFW_VPN -j DROP', lines)
        self.assertIn('main4_13=-A POCKETUFW_TRUST -s 100.64.0.2/32 -d 100.64.0.1/32 -i tun1 -p tcp --dport 22 -j ACCEPT', lines)
        self.assertEqual(lines[-1], 'rules_report=READY')

    def test_a_hooked_chain_that_cannot_be_read_voids_the_report(self):
        self.ok('enable')
        self.ok('tunnel-on')
        (self.base / 'ip6tables.POCKETUFW_VPN').unlink()
        result = self.report()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('rules_report=READY', result.stdout)

    def test_an_accept_ahead_of_the_tunnel_hook_is_reported_as_a_bypass(self):
        self.ok('enable')
        self.ok('tunnel-on')
        text = self.read('iptables')
        self.write('iptables', 'INPUT', text.replace(HOOK_TUN, f'-i tun+ -j ACCEPT\n{HOOK_TUN}'))
        result = self.report()
        self.assertIn('input_bypass4_01=-A INPUT -i tun+ -j ACCEPT', result.stdout)

    def test_an_accept_after_every_hook_is_not_a_bypass(self):
        self.ok('enable')
        self.ok('tunnel-on')
        self.write('iptables', 'INPUT', self.read('iptables') + '-i tun+ -j ACCEPT\n')
        self.assertNotIn('input_bypass4', self.report().stdout)


class Rollback(Base):
    def setUp(self):
        super().setUp()
        self.ok('enable')

    def tool(self, *args, **extra):
        return subprocess.run(['sh', str(ROLLBACK), *args], text=True, capture_output=True,
                              env=self.env | {'POCKETUFW_ROLLBACK_RETRY_SECONDS': '0'} | extra, timeout=30)

    def status(self):
        return self.tool('status').stdout.strip().split()[0]

    def wait_for_status(self, wanted, seconds=8):
        deadline = time.time() + seconds
        while time.time() < deadline:
            if self.status() == wanted:
                return
            time.sleep(0.05)
        self.fail(f'status stayed {self.status()}, wanted {wanted}')

    def wait_for_no_timer(self):
        deadline = time.time() + 5
        while (self.base / 'rollback.timer').exists() and time.time() < deadline:
            time.sleep(0.05)
        self.assertFalse((self.base / 'rollback.timer').exists())

    def test_unconfirmed_it_removes_the_tunnel_rules_and_only_those(self):
        physical = self.read('iptables', 'POCKETUFW_IN')
        result = self.tool('on', '1', str(ENGINE))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('rollback=ARMED', result.stdout)
        self.assertTrue(self.exists('iptables', 'POCKETUFW_VPN'))
        self.wait_for_status('rollback=FIRED')
        self.tunnel_chains_absent()
        self.assertEqual(self.read('iptables', 'POCKETUFW_IN'), physical)
        self.assertEqual(self.verify(), 'ACTIVE')
        self.wait_for_no_timer()

    def test_confirmed_the_rules_stay_and_the_timer_is_gone(self):
        self.tool('on', '2', str(ENGINE))
        result = self.tool('confirm')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'rollback=CONFIRMED')
        self.assertFalse((self.base / 'rollback.timer').exists())
        time.sleep(2.5)
        self.assertTrue(self.exists('iptables', 'POCKETUFW_VPN'))
        self.assertEqual(self.status(), 'rollback=CONFIRMED')

    def test_losing_the_shell_that_started_it_does_not_stop_it(self):
        shell = subprocess.Popen(['sh', '-c', f'sh "{ROLLBACK}" on 1 "{ENGINE}" >/dev/null 2>&1; sleep 30'],
                                 env=self.env, start_new_session=True)
        self.wait_for_status('rollback=ARMED', 5)
        os.killpg(shell.pid, signal.SIGKILL)
        shell.wait()
        self.wait_for_status('rollback=FIRED')
        self.tunnel_chains_absent()

    def test_the_timer_is_armed_before_any_rule_exists(self):
        # An engine that records whether the timer already answered when it was called.
        recorder = self.base / 'recording-engine'
        seen = self.base / 'seen'
        recorder.write_text(f'[ "$1" != tunnel-on ] || cat "{self.base}/rollback.timer" > "{seen}"\nexit 0\n')
        self.tool('on', '1', str(recorder))
        self.assertTrue(seen.read_text().strip().isdigit())
        self.wait_for_status('rollback=FIRED')

    def test_if_tunnel_on_fails_it_stands_down_and_says_so(self):
        result = self.tool('on', '1', str(ENGINE), '--trust', 'tcp:8.8.8.8:22')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.status(), 'rollback=CANCELLED')
        self.wait_for_no_timer()
        self.tunnel_chains_absent()

    def test_a_rollback_that_cannot_remove_the_rules_reports_failure(self):
        result = self.tool('on', '1', str(ENGINE), PUFW_TEST_FAIL='-X POCKETUFW_VPN')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.wait_for_status('rollback=FAILED', 12)

    def test_a_dead_timer_is_reported_as_lost(self):
        self.tool('on', '30', str(ENGINE))
        pid = int((self.base / 'rollback.timer').read_text())
        os.kill(pid, signal.SIGKILL)
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        self.assertEqual(self.status(), 'rollback=LOST')
        self.ok('tunnel-off')

    def test_it_refuses_bad_arguments_and_a_second_arming(self):
        for args in (['on', '0', str(ENGINE)], ['on', '3601', str(ENGINE)], ['on', 'x', str(ENGINE)],
                     ['on', '60', str(self.base / 'missing')], ['bogus']):
            with self.subTest(args):
                self.assertNotEqual(self.tool(*args).returncode, 0)
        self.tunnel_chains_absent()
        self.assertEqual(self.tool('on', '30', str(ENGINE)).returncode, 0)
        self.assertNotEqual(self.tool('on', '30', str(ENGINE)).returncode, 0)
        self.tool('confirm')

    def test_nothing_to_confirm_is_an_error(self):
        self.assertEqual(self.status(), 'rollback=NONE')
        self.assertNotEqual(self.tool('confirm').returncode, 0)


class Limits(unittest.TestCase):
    def source(self, name):
        lines = (ROOT / name).read_text().splitlines()
        return '\n'.join(line for line in lines if not line.lstrip().startswith('#'))

    def test_the_rollback_tool_stays_out_of_the_app(self):
        gradle = (ROOT / 'android/app/build.gradle.kts').read_text()
        client = (ROOT / 'android/app/src/main/java/io/github/pocketufw/FirewallClient.kt').read_text()
        self.assertNotIn('tunnel-rollback', gradle)
        self.assertNotIn('tunnel-rollback', client)

    def test_boot_restoration_never_restores_the_tunnel_filter(self):
        for name in ('boot-service', 'bootctl'):
            self.assertNotIn('tunnel', self.source(name))

    def test_the_app_has_no_way_to_turn_it_on(self):
        for name in ('android-bridge',):
            source = self.source(name)
            self.assertNotIn('tunnel-on', source)
            self.assertNotIn('--trust', source)

    def test_no_dns_rules_and_no_output_or_forward_hook(self):
        source = self.source('pocketufw')
        self.assertIsNone(re.search(r'--[ds]port 53\b', source))
        for word in ('-A FORWARD', 'fw4 -A OUTPUT', 'fw6 -A OUTPUT', '-P INPUT', '-F INPUT', 'iptables-restore'):
            self.assertNotIn(word, source)


if __name__ == '__main__':
    unittest.main()
