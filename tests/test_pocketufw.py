"""Offline tests using shell-only mock iptables. Never touch the host firewall."""
import fcntl
import os
import pathlib
import shutil
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'pocketufw'
needs_flock = unittest.skipUnless(shutil.which('flock'), 'host has no flock')

MOCK = r'''#!/bin/sh
set -u
fam=${0##*/}
state=$PUFW_TEST_DIR
[ "${1:-}" = '-w' ] && shift
action=${1:-}; shift
name=${1:-}; [ "$#" -eq 0 ] || shift
file="$state/$fam.$name"
case "$action" in
  -L)
    [ -f "$file" ] || exit 1
    [ "${PUFW_TEST_LIST_FAIL:-0}" = 0 ] || exit 7
    # A real kernel prints "12K" without -x and resolves names without -n.
    [ "$*" = '-n -v -x' ] || exit 9
    case "$fam" in
      iptables)
        dropped="${PUFW_TEST_DROP4:-0}"; replies="${PUFW_TEST_REPLIES4:-0}"
        invalid="${PUFW_TEST_INVALID4:-0}"
        drop_bytes="${PUFW_TEST_DROP_BYTES4:-888}"; invalid_bytes="${PUFW_TEST_INVALID_BYTES4:-0}" ;;
      ip6tables)
        dropped="${PUFW_TEST_DROP6:-0}"; replies="${PUFW_TEST_REPLIES6:-0}"
        invalid="${PUFW_TEST_INVALID6:-0}"
        drop_bytes="${PUFW_TEST_DROP_BYTES6:-888}"; invalid_bytes="${PUFW_TEST_INVALID_BYTES6:-0}" ;;
    esac
    # Test-only persistent counters: reset must survive a CLI subprocess.
    if [ -f "$state/$fam.counters" ]; then
      read dropped replies invalid drop_bytes invalid_bytes < "$state/$fam.counters"
    fi
    shape="${PUFW_TEST_LIST_SHAPE:-}"
    # The tunnel filter's chains report their own numbers, so that a mix-up shows.
    if [ "$name" = POCKETUFW_VPN ]; then
      shape="${PUFW_TEST_TUNNEL_SHAPE:-$shape}"
      dropped="${PUFW_TEST_TUNNEL_DROP:-0}"; replies="${PUFW_TEST_TUNNEL_REPLIES:-0}"
      invalid="${PUFW_TEST_TUNNEL_INVALID:-0}"; drop_bytes="${PUFW_TEST_TUNNEL_BYTES:-0}"; invalid_bytes=0
    fi
    [ "$shape" = no_header ] || printf 'Chain %s (3 references)\n' "$name"
    printf '    pkts      bytes target     prot opt in out source destination\n'
    if [ "$name" = POCKETUFW_VPN ] && [ "$shape" != no_tailnet ]; then
      printf '      %s        1 ACCEPT     all  --  tun+ * 100.64.0.0/10 100.64.0.0/10\n' "${PUFW_TEST_TAILNET:-0}"
    fi
    [ "$shape" = no_established ] || printf '      %s        500 ACCEPT     all  --  * * 0/0 0/0 ctstate ESTABLISHED,RELATED\n' "$replies"
    [ "$shape" = no_invalid ] || printf '      %s        %s DROP       all  --  * * 0/0 0/0 ctstate INVALID\n' "$invalid" "$invalid_bytes"
    [ "$shape" = no_final_drop ] || printf '      %s        %s DROP       all  --  * * 0/0 0/0\n' "$dropped" "$drop_bytes"
    [ "$shape" != extra_drop ] || printf '      1        1 DROP       all  --  * * 0/0 0/0\n'
    exit 0 ;;
  -S)
    if [ -z "$name" ]; then
      [ "${PUFW_TEST_TABLE_FAIL:-0}" = 0 ] || exit 7
      [ "${PUFW_TEST_TABLE_FAIL_FAMILY:-}" != "$fam" ] || exit 7
      [ ! -e "$state/table_fail" ] || exit 7
      for chain_file in "$state/$fam".*; do
        [ -f "$chain_file" ] || continue
        chain=${chain_file##*/}; chain=${chain#"$fam".}
        case "$chain" in counters|*.tmp|tmp) continue ;; esac
        [ "$chain" = INPUT ] || echo "-N $chain"
        while IFS= read -r line; do echo "-A $chain $line"; done < "$chain_file"
      done
      exit 0
    fi
    if [ "$name" = OUTPUT ]; then
      if [ "${PUFW_TEST_AFWALL:-0}" = 1 ]; then echo '-A OUTPUT -j afwall'; fi
      exit 0
    fi
    [ -f "$file" ] || exit 1
    if [ "$name" = INPUT ]; then echo '-P INPUT ACCEPT'; else echo "-N $name"; fi
    while IFS= read -r line; do
      if [ "${PUFW_TEST_CORRUPT_REPORT:-0}" = 1 ] &&
         [ "$name" = POCKETUFW_IN ] && [ "$line" = '-j DROP' ]; then
        echo "-A $name -j ACCEPT"
      else
        echo "-A $name $line"
      fi
    done < "$file"
    exit 0 ;;
  -C)
    [ -f "$file" ] || exit 1
    grep -Fqx -- "$*" "$file" ; exit $? ;;
esac
if [ -n "${PUFW_TEST_FAIL:-}" ] &&
   { [ "$action $name $*" = "$PUFW_TEST_FAIL" ] ||
     [ "$action $name" = "$PUFW_TEST_FAIL" ]; } &&
   { [ -z "${PUFW_TEST_FAIL_FAMILY:-}" ] || [ "$fam" = "$PUFW_TEST_FAIL_FAMILY" ]; }; then exit 7; fi
# Failures a test can start and stop while a process that inherited its environment runs.
if [ -f "$state/fail_commands" ]; then
  for attempt in "$action $name $*" "$action $name" "$fam $action $name $*" "$fam $action $name"; do
    if grep -Fqx -- "$attempt" "$state/fail_commands"; then exit 7; fi
  done
fi
case "$action" in
  -I)
    [ -f "$file" ] || exit 1
    position=$1; shift
    awk -v pos="$position" -v rule="$*" 'NR == pos { print rule } { print } END { if (pos == NR+1) print rule }' "$file" > "$file.tmp"
    mv "$file.tmp" "$file" ;;
  -Z)
    [ -f "$file" ] || exit 1
    case "$name" in POCKETUFW_IN|POCKETUFW_TS|POCKETUFW_VPN) : ;; *) exit 7 ;; esac
    echo "$fam $name" >> "$state/zero_events"
    if [ "$name" = POCKETUFW_IN ]; then
      printf '0 0 0 0 0\n' > "$state/$fam.counters"
    fi ;;
  -N)
    [ -f "$file" ] && exit 1
    : > "$file" ;;
  -A)
    [ -f "$file" ] || exit 1
    if [ -n "${PUFW_TEST_SLOW_ADD:-}" ]; then sleep "$PUFW_TEST_SLOW_ADD"; fi
    echo "$*" >> "$file"
    # Something else breaks our policy while a UDP exception is being changed.
    if [ "${PUFW_TEST_BREAK_DURING_TS_ADD:-0}" = 1 ] && [ "$name" = POCKETUFW_TS ]; then
      grep -Fvx -- '-j DROP' "$state/$fam.POCKETUFW_IN" > "$state/$fam.tmp" || :
      mv "$state/$fam.tmp" "$state/$fam.POCKETUFW_IN"
    fi ;;
  -D)
    [ -f "$file" ] || exit 1
    grep -Fqx -- "$*" "$file" || exit 1
    # Remove exactly one matching rule, keeping all other rules intact
    tmp="$file.tmp"
    awk -v tgt="$*" 'BEGIN{done=0} {if (!done && $0 == tgt) {done=1; next} print}' "$file" > "$tmp"
    mv "$tmp" "$file" ;;
  -F)
    [ -f "$file" ] || exit 1
    : > "$file" ;;
  -X)
    [ -f "$file" ] || exit 1
    if grep -Fq -- "-j $name" "$state/$fam.INPUT"; then exit 1; fi
    rm -- "$file" ;;
  *) echo "Unsupported mocked action: $action $name $*" >&2; exit 2 ;;
esac
'''

class PocketUFWTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = pathlib.Path(self.temp.name)
        bindir = self.base / 'bin'
        bindir.mkdir()
        for name in ('iptables', 'ip6tables'):
            path = bindir / name
            path.write_text(MOCK)
            path.chmod(0o755)
            (self.base / f'{name}.INPUT').write_text('-j oem_in\n-j bw_INPUT\n-j fw_INPUT\n')
        # Simulate root only inside the mock process; never require host sudo.
        fake_id = bindir / 'id'
        fake_id.write_text('#!/bin/sh\n[ "$1" = "-u" ] || exit 2\necho "${PUFW_TEST_UID:-0}"\n')
        fake_id.chmod(0o755)
        (self.base / 'locks').mkdir()
        self.lock = self.base / 'locks' / 'pocketufw.lock'
        self.env = {**os.environ, 'PATH': str(bindir) + os.pathsep + os.environ['PATH'],
                    'PUFW_TEST_DIR': str(self.base), 'POCKETUFW_LOCK': str(self.lock)}

    def run_cmd(self, *args, extra_env=None):
        return subprocess.run(['sh', str(SCRIPT), *args], text=True, capture_output=True,
                              env=self.env | (extra_env or {}), timeout=60)

    def read(self, fam, chain='INPUT'):
        return (self.base / f'{fam}.{chain}').read_text()

    def test_plan_does_not_touch_firewall(self):
        before = list(self.base.iterdir())
        res = self.run_cmd('plan', '--tailscale-udp4', '46867', '--tailscale-udp6', '43504')
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn('iptables -w -N POCKETUFW_IN', res.stdout)
        self.assertIn('--dport 46867', res.stdout)
        self.assertIn('--dport 43504', res.stdout)
        self.assertEqual(sorted(before), sorted(self.base.iterdir()))

    def test_invalid_ports_fail_without_changes(self):
        for port in ('0', '65536', '-2', 'abc', '40; id'):
            self.assertNotEqual(self.run_cmd('plan', '--tailscale-udp4', port).returncode, 0)
        self.assertEqual(self.read('iptables'), '-j oem_in\n-j bw_INPUT\n-j fw_INPUT\n')

    def test_enable_and_disable_preserve_android_rules(self):
        enabled = self.run_cmd('enable', '--tailscale-udp4', '46867', '--tailscale-udp6', '43504')
        self.assertEqual(enabled.returncode, 0, enabled.stderr)
        for family in ('iptables', 'ip6tables'):
            self.assertTrue((self.base / f'{family}.POCKETUFW_IN').exists())
            self.assertEqual(self.read(family).count('PocketUFW'), 3)
            self.assertTrue(self.read(family).startswith('-j oem_in\n-j bw_INPUT\n-j fw_INPUT\n'))
            self.assertTrue(self.read(family, 'POCKETUFW_IN').endswith('-j DROP\n'))
        self.assertEqual(self.run_cmd('status').returncode, 0)
        disabled = self.run_cmd('disable')
        self.assertEqual(disabled.returncode, 0, disabled.stderr)
        for family in ('iptables', 'ip6tables'):
            self.assertEqual(self.read(family), '-j oem_in\n-j bw_INPUT\n-j fw_INPUT\n')
            self.assertFalse((self.base / f'{family}.POCKETUFW_IN').exists())
            self.assertFalse((self.base / f'{family}.POCKETUFW_TS').exists())

    def test_afwall_blocks_enable(self):
        res = self.run_cmd('enable', extra_env={'PUFW_TEST_AFWALL': '1'})
        self.assertNotEqual(res.returncode, 0)
        self.assertIn('AFWall+', res.stderr)
        self.assertFalse((self.base / 'iptables.POCKETUFW_IN').exists())

    def test_mid_install_failure_rolls_back(self):
        res = self.run_cmd('enable', extra_env={'PUFW_TEST_FAIL': '-A POCKETUFW_IN -p icmp -j ACCEPT'})
        self.assertNotEqual(res.returncode, 0)
        for family in ('iptables', 'ip6tables'):
            self.assertEqual(self.read(family), '-j oem_in\n-j bw_INPUT\n-j fw_INPUT\n')
            self.assertFalse((self.base / f'{family}.POCKETUFW_IN').exists())
            self.assertFalse((self.base / f'{family}.POCKETUFW_TS').exists())

    def test_enable_rolls_back_if_installed_policy_cannot_be_verified(self):
        # All simulated iptables writes succeed, but the subsequent readback
        # is corrupted. Never say enabled or leave partial owned chains.
        result = self.run_cmd('enable', extra_env={'PUFW_TEST_CORRUPT_REPORT': '1'})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('cleaning own chains', result.stderr)
        for family in ('iptables', 'ip6tables'):
            self.assertEqual(self.read(family), '-j oem_in\n-j bw_INPUT\n-j fw_INPUT\n')
            self.assertFalse((self.base / f'{family}.POCKETUFW_IN').exists())
            self.assertFalse((self.base / f'{family}.POCKETUFW_TS').exists())

    def test_duplicate_enable_rejected(self):
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        duplicate = self.run_cmd('enable')
        self.assertNotEqual(duplicate.returncode, 0)
        self.assertIn('already exists', duplicate.stderr)
        self.assertEqual(self.run_cmd('disable').returncode, 0)

    def test_unrooted_cannot_enable_or_fake_status(self):
        for cmd in ('enable', 'disable', 'status', 'doctor'):
            res = self.run_cmd(cmd, extra_env={'PUFW_TEST_UID': '2000'})
            self.assertNotEqual(res.returncode, 0)
            self.assertIn('Requires root', res.stderr)
        # A dry-run is safe and helpful on unrooted devices.
        self.assertEqual(self.run_cmd('plan', extra_env={'PUFW_TEST_UID': '2000'}).returncode, 0)
        self.assertEqual(self.read('iptables'), '-j oem_in\n-j bw_INPUT\n-j fw_INPUT\n')

    def test_stale_hook_guard_does_not_modify_existing_rules(self):
        with (self.base / 'iptables.INPUT').open('a') as fh:
            fh.write('-i wlan+ -m comment --comment PocketUFW -j POCKETUFW_IN\n')
        res = self.run_cmd('enable')
        self.assertNotEqual(res.returncode, 0)
        self.assertIn('Stale PocketUFW hook', res.stderr)
        self.assertEqual(self.read('iptables').count('PocketUFW'), 1)

    def test_partial_ipv6_failure_rolls_back_both_families(self):
        res = self.run_cmd('enable', extra_env={
            'PUFW_TEST_FAIL': '-A POCKETUFW_IN -p ipv6-icmp -j ACCEPT'
        })
        self.assertNotEqual(res.returncode, 0)
        self.assertIn('cleaning own chains', res.stderr)
        for family in ('iptables', 'ip6tables'):
            self.assertEqual(self.read(family), '-j oem_in\n-j bw_INPUT\n-j fw_INPUT\n')
            self.assertFalse((self.base / f'{family}.POCKETUFW_IN').exists())
            self.assertFalse((self.base / f'{family}.POCKETUFW_TS').exists())

    def test_three_enable_disable_cycles_leave_no_cruft(self):
        baseline = '-j oem_in\n-j bw_INPUT\n-j fw_INPUT\n'
        for _ in range(3):
            enabled = self.run_cmd('enable')
            self.assertEqual(enabled.returncode, 0, enabled.stderr)
            for family in ('iptables', 'ip6tables'):
                self.assertEqual(self.read(family).count('PocketUFW'), 3)
            disabled = self.run_cmd('disable')
            self.assertEqual(disabled.returncode, 0, disabled.stderr)
            for family in ('iptables', 'ip6tables'):
                self.assertEqual(self.read(family), baseline)
                self.assertFalse((self.base / f'{family}.POCKETUFW_IN').exists())
            self.assertFalse((self.base / f'{family}.POCKETUFW_TS').exists())

    def test_disable_is_idempotent(self):
        for _ in range(2):
            res = self.run_cmd('disable')
            self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn('disabled', self.run_cmd('status').stdout)

    def test_stateful_ipv6_and_ipv4_rules_have_final_default_drop(self):
        res = self.run_cmd('enable')
        self.assertEqual(res.returncode, 0, res.stderr)
        for family in ('iptables', 'ip6tables'):
            rules = self.read(family, 'POCKETUFW_IN').splitlines()
            self.assertIn('-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT', rules)
            self.assertIn('-m conntrack --ctstate INVALID -j DROP', rules)
            self.assertEqual(rules[-1], '-j DROP')
        self.assertIn('-p ipv6-icmp -j ACCEPT', self.read('ip6tables', 'POCKETUFW_IN'))
        self.assertIn('-p icmp -j ACCEPT', self.read('iptables', 'POCKETUFW_IN'))

    def add_mock_tailscale_listener(self, valid=True):
        """Simulate Android's verified Tailscale sockets without touching networking."""
        proc = self.base / 'proc'
        (proc / '6283').mkdir(parents=True, exist_ok=True)
        name = b'com.tailscale.ipn\0' if valid else b'com.example.other\0'
        (proc / '6283' / 'cmdline').write_bytes(name)
        data_dir = self.base / 'ts-data'
        data_dir.mkdir(exist_ok=True)
        uid = data_dir.stat().st_uid
        (proc / '6283' / 'status').write_text(f'Name:\tm.tailscale.ipn\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n')
        packages = self.base / 'packages.list'
        packages.write_text(f'com.tailscale.ipn {uid} 0\n')
        self.env['POCKETUFW_PACKAGES_LIST'] = str(packages)
        (self.base / 'ss4').write_text(
            'UNCONN 0 0 0.0.0.0:46867 0.0.0.0:* '
            'users:(("m.tailscale.ipn",pid=6283,fd=128))\n'
        )
        (self.base / 'ss6').write_text(
            'UNCONN 0 0 [::]:43504 [::]:* '
            'users:(("m.tailscale.ipn",pid=6283,fd=129))\n'
        )
        ss = self.base / 'bin' / 'ss'
        ss.write_text(
            '#!/bin/sh\n'
            'for arg do case "$arg" in -4) file="$PUFW_TEST_DIR/ss4";; '
            '-6) file="$PUFW_TEST_DIR/ss6";; esac; done\n'
            'cat "$file"\n'
        )
        ss.chmod(0o755)
        self.env['POCKETUFW_SS_BIN'] = 'ss'
        self.env['POCKETUFW_PROC_ROOT'] = str(proc)

    def test_auto_tailscale_plan_is_read_only(self):
        self.add_mock_tailscale_listener()
        before = self.read('iptables')
        res = self.run_cmd('plan', '--auto-tailscale')
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn('--dport 46867', res.stdout)
        self.assertIn('--dport 43504', res.stdout)
        self.assertEqual(self.read('iptables'), before)
        self.assertFalse((self.base / 'iptables.POCKETUFW_IN').exists())

    def test_auto_tailscale_enable_verifies_owner_and_cleans_up(self):
        self.add_mock_tailscale_listener()
        res = self.run_cmd('enable', '--auto-tailscale')
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn('--dport 46867', self.read('iptables', 'POCKETUFW_TS'))
        self.assertIn('--dport 43504', self.read('ip6tables', 'POCKETUFW_TS'))
        self.assertIn('Use refresh after a port change', res.stdout)
        self.assertEqual(self.run_cmd('disable').returncode, 0)
        self.assertEqual(self.read('iptables'), '-j oem_in\n-j bw_INPUT\n-j fw_INPUT\n')

    def test_unverified_auto_tailscale_still_enables_without_exceptions(self):
        # The firewall must never depend on Tailscale: a probe failure withholds
        # only the UDP exception.
        self.add_mock_tailscale_listener(valid=False)
        res = self.run_cmd('enable', '--auto-tailscale')
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn('tailscale_probe=FAILED', res.stdout.splitlines())
        self.assertTrue(any(line.startswith('NOTE:') for line in res.stdout.splitlines()), res.stdout)
        self.assertNotIn('No verified Tailscale listeners found', res.stdout)
        self.assertEqual(self.read('iptables', 'POCKETUFW_TS'), '')
        self.assertEqual(self.read('ip6tables', 'POCKETUFW_TS'), '')
        self.assertEqual(self.run_cmd('verify').stdout.strip(), 'ACTIVE')

    def engine_copy_with_probe(self, probe_source):
        """A private copy of the engine, so the probe beside it can be faked or absent."""
        directory = self.base / 'alt'
        directory.mkdir(exist_ok=True)
        shutil.copy(SCRIPT, directory / 'pocketufw')
        if probe_source is not None:
            (directory / 'vpn-probe').write_text(probe_source)
        return directory / 'pocketufw'

    def run_copy(self, copy, *args):
        return subprocess.run(['sh', str(copy), *args], text=True, capture_output=True,
                              env=self.env, timeout=15)

    def test_missing_or_broken_probe_never_stops_enable(self):
        cases = {
            'missing': None,
            'exits nonzero': '#!/bin/sh\nexit 7\n',
            'invalid port': '#!/bin/sh\necho tailscale_udp4=99999\necho tailscale_udp6=\n',
            'non numeric port': '#!/bin/sh\necho "tailscale_udp4=1; id"\necho tailscale_udp6=443\n',
        }
        for name, source in cases.items():
            with self.subTest(probe=name):
                shutil.rmtree(self.base / 'alt', ignore_errors=True)
                copy = self.engine_copy_with_probe(source)
                res = self.run_copy(copy, 'enable', '--auto-tailscale')
                self.assertEqual(res.returncode, 0, res.stderr)
                self.assertIn('tailscale_probe=FAILED', res.stdout.splitlines())
                self.assertEqual(self.read('iptables', 'POCKETUFW_TS'), '')
                self.assertEqual(self.read('ip6tables', 'POCKETUFW_TS'), '')
                self.assertEqual(self.run_cmd('verify').stdout.strip(), 'ACTIVE')
                self.assertEqual(self.run_cmd('disable').returncode, 0)

    def test_plan_stays_strict_when_probe_fails(self):
        for source in (None, '#!/bin/sh\nexit 7\n', '#!/bin/sh\necho tailscale_udp4=99999\n'):
            with self.subTest(probe=source):
                shutil.rmtree(self.base / 'alt', ignore_errors=True)
                res = self.run_copy(self.engine_copy_with_probe(source), 'plan', '--auto-tailscale')
                self.assertNotEqual(res.returncode, 0)
                self.assertNotIn('tailscale_probe=', res.stdout)
                self.assertNotIn('-w -N', res.stdout)

    def test_refresh_stays_strict_when_probe_fails(self):
        self.assertEqual(self.run_cmd('enable', '--tailscale-udp4', '41641').returncode, 0)
        for source in (None, '#!/bin/sh\nexit 7\n', '#!/bin/sh\necho tailscale_udp4=99999\n'):
            with self.subTest(probe=source):
                shutil.rmtree(self.base / 'alt', ignore_errors=True)
                res = self.run_copy(self.engine_copy_with_probe(source), 'refresh')
                self.assertNotEqual(res.returncode, 0)
                self.assertNotIn('tailscale_probe=', res.stdout)
                self.assertNotIn('refresh_result=', res.stdout)
                self.assertEqual(self.read('iptables', 'POCKETUFW_TS'),
                                 '-p udp --dport 41641 -j ACCEPT\n')

    def test_working_probe_does_not_claim_a_probe_failure(self):
        self.add_mock_tailscale_listener()
        res = self.run_cmd('enable', '--auto-tailscale')
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertNotIn('tailscale_probe=', res.stdout)

    def test_manual_enable_never_runs_the_probe(self):
        res = self.run_copy(self.engine_copy_with_probe('#!/bin/sh\nexit 7\n'), 'enable',
                            '--tailscale-udp4', '41641')
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertNotIn('tailscale_probe=', res.stdout)
        self.assertEqual(self.read('iptables', 'POCKETUFW_TS'), '-p udp --dport 41641 -j ACCEPT\n')

    def test_auto_and_manual_tailscale_are_mutually_exclusive(self):
        res = self.run_cmd('plan', '--auto-tailscale', '--tailscale-udp4', '41641')
        self.assertNotEqual(res.returncode, 0)
        self.assertIn('Choose automatic detection OR', res.stderr)

    def test_refresh_updates_both_ports_without_touching_main_chain(self):
        self.add_mock_tailscale_listener()
        self.assertEqual(self.run_cmd('enable', '--auto-tailscale').returncode, 0)
        main_before = {fam: self.read(fam, 'POCKETUFW_IN')
                       for fam in ('iptables', 'ip6tables')}
        self.assertIn('--dport 46867', self.read('iptables', 'POCKETUFW_TS'))
        self.assertIn('--dport 43504', self.read('ip6tables', 'POCKETUFW_TS'))
        (self.base / 'ss4').write_text((self.base / 'ss4').read_text().replace(':46867', ':46877'))
        (self.base / 'ss6').write_text((self.base / 'ss6').read_text().replace(':43504', ':43514'))
        res = self.run_cmd('refresh')
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn('refresh_result=UPDATED', res.stdout)
        self.assertIn('46877', res.stdout)
        self.assertIn('43514', res.stdout)
        self.assertEqual(self.read('iptables', 'POCKETUFW_TS').count('--dport 46877'), 1)
        self.assertEqual(self.read('ip6tables', 'POCKETUFW_TS').count('--dport 43514'), 1)
        self.assertNotIn('46867', self.read('iptables', 'POCKETUFW_TS'))
        self.assertNotIn('43504', self.read('ip6tables', 'POCKETUFW_TS'))
        no_change = self.run_cmd('refresh')
        self.assertEqual(no_change.returncode, 0, no_change.stderr)
        self.assertIn('refresh_result=UNCHANGED', no_change.stdout)
        for family in ('iptables', 'ip6tables'):
            self.assertEqual(self.read(family, 'POCKETUFW_IN'), main_before[family])
        self.assertEqual(self.run_cmd('disable').returncode, 0)

    def test_refresh_removes_ports_when_app_stops(self):
        self.add_mock_tailscale_listener()
        self.assertEqual(self.run_cmd('enable', '--auto-tailscale').returncode, 0)
        (self.base / 'ss4').write_text('')
        (self.base / 'ss6').write_text('')
        out = self.run_cmd('refresh')
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn('IPv4: none', out.stdout)
        self.assertIn('refresh_result=UPDATED', out.stdout)
        self.assertEqual(self.read('iptables', 'POCKETUFW_TS'), '')
        self.assertEqual(self.read('ip6tables', 'POCKETUFW_TS'), '')
        self.assertEqual(self.run_cmd('disable').returncode, 0)

    def test_refresh_rejects_unverified_listener_without_changing_rules(self):
        self.add_mock_tailscale_listener()
        self.assertEqual(self.run_cmd('enable', '--auto-tailscale').returncode, 0)
        orig4 = self.read('iptables', 'POCKETUFW_TS')
        orig6 = self.read('ip6tables', 'POCKETUFW_TS')
        (self.base / 'proc' / '6283' / 'cmdline').write_bytes(b'com.example.rogue\\0')
        res = self.run_cmd('refresh')
        self.assertNotEqual(res.returncode, 0)
        self.assertNotIn('refresh_result=', res.stdout)
        self.assertIn('discovery failed', res.stderr)
        self.assertEqual(self.read('iptables', 'POCKETUFW_TS'), orig4)
        self.assertEqual(self.read('ip6tables', 'POCKETUFW_TS'), orig6)
        self.assertEqual(self.run_cmd('disable').returncode, 0)

    def test_refresh_ipv6_add_failure_rolls_back_ipv4_add(self):
        self.add_mock_tailscale_listener()
        self.assertEqual(self.run_cmd('enable', '--auto-tailscale').returncode, 0)
        (self.base / 'ss4').write_text((self.base / 'ss4').read_text().replace(':46867', ':46877'))
        (self.base / 'ss6').write_text((self.base / 'ss6').read_text().replace(':43504', ':43514'))
        res = self.run_cmd('refresh', extra_env={
            'PUFW_TEST_FAIL': '-A POCKETUFW_TS -p udp --dport 43514 -j ACCEPT'})
        self.assertNotEqual(res.returncode, 0)
        self.assertEqual(self.read('iptables', 'POCKETUFW_TS'), '-p udp --dport 46867 -j ACCEPT\n')
        self.assertEqual(self.read('ip6tables', 'POCKETUFW_TS'), '-p udp --dport 43504 -j ACCEPT\n')
        self.assertIn('previous verified ports restored', res.stderr)
        self.assertEqual(self.run_cmd('disable').returncode, 0)

    def test_refresh_ipv6_delete_failure_restores_both_previous_ports(self):
        self.add_mock_tailscale_listener()
        self.assertEqual(self.run_cmd('enable', '--auto-tailscale').returncode, 0)
        (self.base / 'ss4').write_text((self.base / 'ss4').read_text().replace(':46867', ':46877'))
        (self.base / 'ss6').write_text((self.base / 'ss6').read_text().replace(':43504', ':43514'))
        res = self.run_cmd('refresh', extra_env={
            'PUFW_TEST_FAIL': '-D POCKETUFW_TS -p udp --dport 43504 -j ACCEPT'})
        self.assertNotEqual(res.returncode, 0)
        self.assertEqual(self.read('iptables', 'POCKETUFW_TS'), '-p udp --dport 46867 -j ACCEPT\n')
        self.assertEqual(self.read('ip6tables', 'POCKETUFW_TS'), '-p udp --dport 43504 -j ACCEPT\n')
        self.assertIn('previous verified ports restored', res.stderr)
        self.assertEqual(self.run_cmd('disable').returncode, 0)

    def test_auto_tailscale_with_no_app_has_no_false_port_warning(self):
        self.add_mock_tailscale_listener()
        (self.base / 'ss4').write_text('')
        (self.base / 'ss6').write_text('')
        res = self.run_cmd('enable', '--auto-tailscale')
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn('No verified Tailscale listeners found', res.stdout)
        self.assertNotIn('direct peer connectivity may degrade', res.stdout)
        self.assertEqual(self.read('iptables', 'POCKETUFW_TS'), '')
        self.assertEqual(self.read('ip6tables', 'POCKETUFW_TS'), '')
        self.assertEqual(self.run_cmd('disable').returncode, 0)

    def test_get_ports_is_read_only_and_requires_verification(self):
        self.assertNotEqual(self.run_cmd('get-ports').returncode, 0)
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        before = {f: self.read(f, 'POCKETUFW_TS') for f in ('iptables', 'ip6tables')}
        res = self.run_cmd('get-ports')
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(res.stdout.splitlines(), ['udp4=none', 'udp6=none'])
        for family in before:
            self.assertEqual(self.read(family, 'POCKETUFW_TS'), before[family])
        self.assertEqual(self.run_cmd('disable').returncode, 0)

    def test_get_ports_refuses_a_degraded_firewall_in_either_family(self):
        self.assertEqual(self.run_cmd('enable', '--tailscale-udp4', '41641').returncode, 0)
        for family in ('iptables', 'ip6tables'):
            with self.subTest(family=family):
                path = self.base / f'{family}.POCKETUFW_IN'
                original = path.read_text()
                path.write_text(original.replace('-j DROP\n', '', 1))
                result = self.run_cmd('get-ports')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
                self.assertIn('no verified ports available', result.stderr)
                path.write_text(original)

    def test_manual_udp_ports_replace_only_owned_exceptions(self):
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        baseline = {family: self.read(family, 'INPUT') for family in ('iptables', 'ip6tables')}
        main = {family: self.read(family, 'POCKETUFW_IN') for family in ('iptables', 'ip6tables')}
        result = self.run_cmd('set-ports', '--udp4', '45678', '--udp6', '45679')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('session-only', result.stdout)
        self.assertIn('--dport 45678', self.read('iptables', 'POCKETUFW_TS'))
        self.assertIn('--dport 45679', self.read('ip6tables', 'POCKETUFW_TS'))
        self.assertEqual(self.run_cmd('verify').stdout.strip(), 'ACTIVE')
        for family in ('iptables', 'ip6tables'):
            self.assertEqual(self.read(family, 'INPUT'), baseline[family])
            self.assertEqual(self.read(family, 'POCKETUFW_IN'), main[family])
        result = self.run_cmd('set-ports', '--udp4', 'none', '--udp6', 'none')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.read('iptables', 'POCKETUFW_TS'), '')
        self.assertEqual(self.read('ip6tables', 'POCKETUFW_TS'), '')
        self.assertEqual(self.run_cmd('verify').stdout.strip(), 'ACTIVE')
        self.assertEqual(self.run_cmd('disable').returncode, 0)

    def test_manual_udp_ports_reject_invalid_inputs_without_changing_rules(self):
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        before = {family: self.read(family, 'POCKETUFW_TS') for family in ('iptables', 'ip6tables')}
        for port in ('0', '65536', '0x50', '00080', '-5', '10; id', 'all', ''):
            with self.subTest(port=port):
                result = self.run_cmd('set-ports', '--udp4', port, '--udp6', 'none')
                self.assertNotEqual(result.returncode, 0)
                for family in before:
                    self.assertEqual(self.read(family, 'POCKETUFW_TS'), before[family])
        for args in (('set-ports', '--udp4', '42'),
                     ('set-ports', '--udp4', '42', '--udp6', '42', '--auto-tailscale'),
                     ('set-ports', '--tailscale-udp4', '42')):
            self.assertNotEqual(self.run_cmd(*args).returncode, 0)
        self.assertEqual(self.run_cmd('verify').stdout.strip(), 'ACTIVE')
        self.assertEqual(self.run_cmd('disable').returncode, 0)

    def test_manual_udp_ports_refuse_disabled_or_degraded_firewall(self):
        result = self.run_cmd('set-ports', '--udp4', '45678', '--udp6', 'none')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.base / 'iptables.POCKETUFW_TS').exists())
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        path = self.base / 'iptables.POCKETUFW_IN'
        path.write_text(path.read_text().replace('-j DROP\n', '', 1))
        previous = {family: self.read(family, 'POCKETUFW_TS') for family in ('iptables', 'ip6tables')}
        result = self.run_cmd('set-ports', '--udp4', '45678', '--udp6', '45679')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('no manual changes made', result.stderr)
        for family, content in previous.items():
            self.assertEqual(self.read(family, 'POCKETUFW_TS'), content)
        self.assertEqual(self.run_cmd('disable').returncode, 0)

    def test_manual_udp_ipv6_failure_rolls_back_ipv4(self):
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        result = self.run_cmd('set-ports', '--udp4', '45678', '--udp6', '45679',
                              extra_env={'PUFW_TEST_FAIL': '-A POCKETUFW_TS -p udp --dport 45679 -j ACCEPT'})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('previous verified ports restored', result.stderr)
        self.assertEqual(self.read('iptables', 'POCKETUFW_TS'), '')
        self.assertEqual(self.read('ip6tables', 'POCKETUFW_TS'), '')
        self.assertEqual(self.run_cmd('verify').stdout.strip(), 'ACTIVE')
        self.assertEqual(self.run_cmd('disable').returncode, 0)

    def test_refresh_does_not_enable_disabled_firewall(self):
        self.add_mock_tailscale_listener()
        res = self.run_cmd('refresh')
        self.assertNotEqual(res.returncode, 0)
        self.assertIn('disabled', res.stderr)
        self.assertFalse((self.base / 'iptables.POCKETUFW_IN').exists())

    def test_verify_requires_complete_rules_and_physical_hooks(self):
        self.assertEqual(self.run_cmd('verify').stdout.strip(), 'INACTIVE')
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        active = self.run_cmd('verify')
        self.assertEqual(active.returncode, 0, active.stderr)
        self.assertEqual(active.stdout.strip(), 'ACTIVE')
        # Remove one of our own interface hooks to simulate lost enforcement.
        infile = self.base / 'iptables.INPUT'
        lines = infile.read_text().splitlines()
        self.assertEqual(len(lines), 6)
        infile.write_text('\n'.join(lines[:-1]) + '\n')
        broken = self.run_cmd('verify')
        self.assertNotEqual(broken.returncode, 0)
        self.assertEqual(broken.stdout.strip(), 'DEGRADED')
        self.assertEqual(self.run_cmd('disable').returncode, 0)

    def test_verify_rejects_missing_default_drop(self):
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        path = self.base / 'ip6tables.POCKETUFW_IN'
        rules = path.read_text().splitlines()
        self.assertEqual(rules[-1], '-j DROP')
        path.write_text('\n'.join(rules[:-1]) + '\n')
        result = self.run_cmd('verify')
        self.assertEqual(result.stdout.strip(), 'DEGRADED')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.run_cmd('disable').returncode, 0)

    def test_verify_rejects_unexpected_allow_rule(self):
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        path = self.base / 'iptables.POCKETUFW_IN'
        rules = path.read_text().splitlines()
        self.assertEqual(rules[-1], '-j DROP')
        rules.insert(-1, '-p tcp --dport 12345 -j ACCEPT')
        path.write_text('\n'.join(rules) + '\n')
        result = self.run_cmd('verify')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), 'DEGRADED')
        self.assertEqual(self.run_cmd('disable').returncode, 0)

    def test_verify_accepts_exact_vpn_listener_exceptions(self):
        installed = self.run_cmd('enable', '--tailscale-udp4', '46867', '--tailscale-udp6', '43504')
        self.assertEqual(installed.returncode, 0, installed.stderr)
        self.assertEqual(self.run_cmd('verify').stdout.strip(), 'ACTIVE')
        self.assertIn('state=ACTIVE', self.run_cmd('activity').stdout)
        self.assertEqual(self.run_cmd('disable').returncode, 0)

    def test_verify_rejects_out_of_order_inbound_policy(self):
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        path = self.base / 'iptables.POCKETUFW_IN'
        rules = path.read_text().splitlines()
        self.assertEqual(rules[1], '-p icmp -j ACCEPT')
        self.assertEqual(rules[2], '-m conntrack --ctstate INVALID -j DROP')
        # Same eight expected rules, but INVALID ICMP packets would now bypass
        # the INVALID drop. A membership check must not claim ACTIVE.
        rules[1], rules[2] = rules[2], rules[1]
        path.write_text('\n'.join(rules) + '\n')
        result = self.run_cmd('verify')
        self.assertEqual(result.stdout.strip(), 'DEGRADED')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.run_cmd('activity').stdout.strip(), 'state=DEGRADED')
        self.assertEqual(self.run_cmd('disable').returncode, 0)

    def test_verify_rejects_unexpected_vpn_child_accept(self):
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        path = self.base / 'ip6tables.POCKETUFW_TS'
        # A child-chain unconditional ACCEPT would bypass the final DROP.
        with path.open('a') as fh:
            fh.write('-j ACCEPT\n')
        result = self.run_cmd('verify')
        self.assertEqual(result.stdout.strip(), 'DEGRADED')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.run_cmd('activity').stdout.strip(), 'state=DEGRADED')
        self.assertEqual(self.run_cmd('disable').returncode, 0)

    def test_activity_reads_realistic_ipv4_and_ipv6_kernel_counters(self):
        self.assertEqual(self.run_cmd("enable").returncode, 0)
        before = {
            fam: self.read(fam, "POCKETUFW_IN")
            for fam in ("iptables", "ip6tables")
        }
        result = self.run_cmd("activity", extra_env={
            "PUFW_TEST_DROP4": "12", "PUFW_TEST_DROP6": "4",
            "PUFW_TEST_REPLIES4": "76", "PUFW_TEST_REPLIES6": "138"
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        values = dict(line.split("=", 1) for line in result.stdout.splitlines())
        self.assertEqual(values["state"], "ACTIVE")
        self.assertEqual(values["ipv4_blocked"], "12")
        self.assertEqual(values["ipv6_blocked"], "4")
        self.assertEqual(values["ipv4_established_replies"], "76")
        self.assertEqual(values["ipv6_established_replies"], "138")
        self.assertEqual(values["ipv4_blocked_bytes"], "888")
        self.assertEqual(values["hook_patterns"], "wlan+ rmnet+ v4-rmnet+")
        for fam in before:
            self.assertEqual(self.read(fam, "POCKETUFW_IN"), before[fam])
        self.assertEqual(self.run_cmd("disable").returncode, 0)

    def test_verbose_is_descriptive_and_read_only(self):
        self.assertEqual(self.run_cmd("enable").returncode, 0)
        result = self.run_cmd("verbose", extra_env={"PUFW_TEST_DROP4": "7"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Status: ACTIVE", result.stdout)
        self.assertIn("IPv4 blocked: 7 packets", result.stdout)
        self.assertIn("Outgoing: unchanged", result.stdout)
        self.assertIn("preceding Android/OEM rules", result.stdout)
        self.assertEqual(self.run_cmd("disable").returncode, 0)

    def test_activity_disabled_never_reports_zero_as_protection(self):
        result = self.run_cmd("activity")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "state=INACTIVE")
        self.assertNotIn("ipv4_blocked=0", result.stdout)

    def test_activity_degraded_never_claims_measurements(self):
        self.assertEqual(self.run_cmd("enable").returncode, 0)
        path = self.base / "ip6tables.POCKETUFW_IN"
        rules = path.read_text().splitlines()
        path.write_text("\n".join(rules[:-1]) + "\n")
        result = self.run_cmd("activity")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "state=DEGRADED")
        self.assertNotIn("ipv4_blocked", result.stdout)
        self.assertEqual(self.run_cmd("disable").returncode, 0)

    def test_activity_counter_failure_never_invents_statistics(self):
        self.assertEqual(self.run_cmd("enable").returncode, 0)
        result = self.run_cmd("activity", extra_env={"PUFW_TEST_LIST_FAIL": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cannot read IPv4 counters", result.stderr)
        self.assertNotIn("ipv4_blocked=", result.stdout)
        self.assertEqual(self.run_cmd("disable").returncode, 0)

    def test_reset_counters_only_owned_chains_no_rule_changes(self):
        self.assertEqual(self.run_cmd('enable', '--tailscale-udp4', '46867',
                                      '--tailscale-udp6', '43504').returncode, 0)
        before = {
            fam: {name: self.read(fam, name)
                  for name in ('INPUT', 'POCKETUFW_IN', 'POCKETUFW_TS')}
            for fam in ('iptables', 'ip6tables')
        }
        env = {'PUFW_TEST_DROP4': '120', 'PUFW_TEST_DROP6': '9',
               'PUFW_TEST_REPLIES4': '600', 'PUFW_TEST_REPLIES6': '80'}
        self.assertIn('ipv4_blocked=120', self.run_cmd('activity', extra_env=env).stdout)
        reset = self.run_cmd('reset-counters', extra_env=env)
        self.assertEqual(reset.returncode, 0, reset.stderr)
        self.assertIn('owned counters reset', reset.stdout)
        self.assertEqual(self.run_cmd('verify').stdout.strip(), 'ACTIVE')
        counters = self.run_cmd('activity')
        self.assertEqual(counters.returncode, 0, counters.stderr)
        for name in ('ipv4_blocked', 'ipv6_blocked',
                     'ipv4_established_replies', 'ipv6_established_replies'):
            self.assertIn(f'{name}=0', counters.stdout)
        self.assertEqual((self.base/'zero_events').read_text().splitlines(), [
            'iptables POCKETUFW_IN', 'ip6tables POCKETUFW_IN',
            'iptables POCKETUFW_TS', 'ip6tables POCKETUFW_TS'
        ])
        for fam, chains in before.items():
            for name, original in chains.items():
                self.assertEqual(self.read(fam, name), original)
        self.assertEqual(self.run_cmd('disable').returncode, 0)

    def test_reset_counters_refuses_inactive_and_degraded(self):
        inactive = self.run_cmd('reset-counters')
        self.assertNotEqual(inactive.returncode, 0)
        self.assertIn('inactive or degraded', inactive.stderr)
        self.assertFalse((self.base/'zero_events').exists())
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        broken = self.base / 'ip6tables.POCKETUFW_IN'
        broken.write_text(broken.read_text().replace('-j DROP\n', ''))
        degraded = self.run_cmd('reset-counters')
        self.assertNotEqual(degraded.returncode, 0)
        self.assertFalse((self.base/'zero_events').exists())
        self.assertEqual(self.run_cmd('disable').returncode, 0)

    def test_reset_counters_partial_ipv6_failure_keeps_rules(self):
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        original = self.read('iptables', 'INPUT')
        failed = self.run_cmd('reset-counters', extra_env={
            'PUFW_TEST_FAIL': '-Z POCKETUFW_IN',
            'PUFW_TEST_FAIL_FAMILY': 'ip6tables'
        })
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn('IPv6 parent counter reset failed', failed.stderr)
        self.assertEqual(self.read('iptables', 'INPUT'), original)
        self.assertEqual(self.run_cmd('verify').stdout.strip(), 'ACTIVE')
        self.assertEqual((self.base/'zero_events').read_text().splitlines(),
                         ['iptables POCKETUFW_IN'])
        self.assertEqual(self.run_cmd('disable').returncode, 0)

    # --- Exact policy. Membership checks cannot notice a broadened installer. ---

    EXPECTED_MAIN = {
        'iptables': [
            '-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
            '-p icmp -j ACCEPT',
            '-m conntrack --ctstate INVALID -j DROP',
            '-p udp --sport 67 --dport 68 -j ACCEPT',
            '-p udp -d 224.0.0.251 --dport 5353 -j ACCEPT',
            '-p esp -j ACCEPT',
            '-j POCKETUFW_TS',
            '-j DROP',
        ],
        'ip6tables': [
            '-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
            '-p ipv6-icmp -j ACCEPT',
            '-m conntrack --ctstate INVALID -j DROP',
            '-p udp --sport 547 --dport 546 -j ACCEPT',
            '-p udp -d ff02::fb --dport 5353 -j ACCEPT',
            '-p esp -j ACCEPT',
            '-j POCKETUFW_TS',
            '-j DROP',
        ],
    }
    EXPECTED_HOOKS = [
        '-i wlan+ -m comment --comment PocketUFW -j POCKETUFW_IN',
        '-i rmnet+ -m comment --comment PocketUFW -j POCKETUFW_IN',
        '-i v4-rmnet+ -m comment --comment PocketUFW -j POCKETUFW_IN',
    ]
    ANDROID_INPUT = ['-j oem_in', '-j bw_INPUT', '-j fw_INPUT']

    # (rule index, tampered rule): one broader and one narrower form per rule.
    TAMPERS = {
        'iptables': [
            (0, '-m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT'),
            (0, '-m conntrack --ctstate ESTABLISHED -j ACCEPT'),
            (1, '-j ACCEPT'),
            (1, '-p icmp --icmp-type 8 -j ACCEPT'),
            (2, '-m conntrack --ctstate NEW -j DROP'),
            (2, '-p tcp -m conntrack --ctstate INVALID -j DROP'),
            (3, '-p udp --dport 68 -j ACCEPT'),
            (3, '-p udp -s 10.0.0.1 --sport 67 --dport 68 -j ACCEPT'),
            (4, '-p udp --dport 5353 -j ACCEPT'),
            (4, '-p udp -s 10.0.0.1 -d 224.0.0.251 --dport 5353 -j ACCEPT'),
            (5, '-j ACCEPT'),
            (5, '-s 10.0.0.1 -p esp -j ACCEPT'),
            (6, '-p tcp -j POCKETUFW_TS'),
            (6, '-p udp -j POCKETUFW_TS'),
            (7, '-p tcp -j DROP'),
            (7, '-s 10.0.0.1 -j DROP'),
        ],
        'ip6tables': [
            (0, '-m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT'),
            (0, '-m conntrack --ctstate ESTABLISHED -j ACCEPT'),
            (1, '-j ACCEPT'),
            (1, '-p ipv6-icmp --icmpv6-type 128 -j ACCEPT'),
            (2, '-m conntrack --ctstate NEW -j DROP'),
            (2, '-p tcp -m conntrack --ctstate INVALID -j DROP'),
            (3, '-p udp --dport 546 -j ACCEPT'),
            (3, '-p udp -s fe80::1 --sport 547 --dport 546 -j ACCEPT'),
            (4, '-p udp --dport 5353 -j ACCEPT'),
            (4, '-p udp -s fe80::1 -d ff02::fb --dport 5353 -j ACCEPT'),
            (5, '-j ACCEPT'),
            (5, '-s fe80::1 -p esp -j ACCEPT'),
            (6, '-p tcp -j POCKETUFW_TS'),
            (6, '-p udp -j POCKETUFW_TS'),
            (7, '-p tcp -j DROP'),
            (7, '-s fe80::1 -j DROP'),
        ],
    }

    def test_enable_installs_exactly_the_documented_policy_in_order(self):
        res = self.run_cmd('enable', '--tailscale-udp4', '46867', '--tailscale-udp6', '43504')
        self.assertEqual(res.returncode, 0, res.stderr)
        ports = {'iptables': '46867', 'ip6tables': '43504'}
        for family in ('iptables', 'ip6tables'):
            with self.subTest(family=family):
                self.assertEqual(self.read(family, 'POCKETUFW_IN').splitlines(), self.EXPECTED_MAIN[family])
                self.assertEqual(self.read(family, 'POCKETUFW_TS').splitlines(),
                                 [f'-p udp --dport {ports[family]} -j ACCEPT'])
                self.assertEqual(self.read(family, 'INPUT').splitlines(),
                                 self.ANDROID_INPUT + self.EXPECTED_HOOKS)

    def test_enable_with_no_exceptions_installs_an_empty_child_chain(self):
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        for family in ('iptables', 'ip6tables'):
            with self.subTest(family=family):
                self.assertEqual(self.read(family, 'POCKETUFW_IN').splitlines(), self.EXPECTED_MAIN[family])
                self.assertEqual(self.read(family, 'POCKETUFW_TS'), '')

    def test_plan_prints_exactly_what_enable_installs(self):
        res = self.run_cmd('plan', '--tailscale-udp4', '46867', '--tailscale-udp6', '43504')
        self.assertEqual(res.returncode, 0, res.stderr)
        for family, ipt, port in (('iptables', 'iptables', '46867'), ('ip6tables', 'ip6tables', '43504')):
            planned = [line[len(f'{ipt} -w '):] for line in res.stdout.splitlines()
                       if line.startswith(f'{ipt} -w ')]
            main = [line[len('-A POCKETUFW_IN '):] for line in planned if line.startswith('-A POCKETUFW_IN ')]
            child = [line[len('-A POCKETUFW_TS '):] for line in planned if line.startswith('-A POCKETUFW_TS ')]
            hooks = [line[len('-A INPUT '):] for line in planned if line.startswith('-A INPUT ')]
            self.assertEqual(main, self.EXPECTED_MAIN[family])
            self.assertEqual(child, [f'-p udp --dport {port} -j ACCEPT'])
            self.assertEqual(hooks, self.EXPECTED_HOOKS)

    def test_every_tampered_rule_is_degraded_in_both_families(self):
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        self.assertEqual(self.run_cmd('verify').stdout.strip(), 'ACTIVE')
        for family, tampers in self.TAMPERS.items():
            path = self.base / f'{family}.POCKETUFW_IN'
            original = path.read_text()
            lines = original.splitlines()
            for index, tampered in tampers:
                with self.subTest(family=family, rule=lines[index], tampered=tampered):
                    changed = list(lines)
                    changed[index] = tampered
                    path.write_text('\n'.join(changed) + '\n')
                    result = self.run_cmd('verify')
                    self.assertEqual(result.stdout.strip(), 'DEGRADED')
                    self.assertEqual(result.returncode, 4)
                    self.assertEqual(self.run_cmd('activity').stdout.strip(), 'state=DEGRADED')
                    path.write_text(original)
            self.assertEqual(self.run_cmd('verify').stdout.strip(), 'ACTIVE')

    def test_every_tampered_hook_is_degraded_in_both_families(self):
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        for family in ('iptables', 'ip6tables'):
            path = self.base / f'{family}.INPUT'
            original = path.read_text()
            for hook in self.EXPECTED_HOOKS:
                for tampered in (hook.replace('-j POCKETUFW_IN', '-j POCKETUFW_TS'),
                                 hook.replace('+ ', '0 ', 1),
                                 '-p tcp ' + hook):
                    with self.subTest(family=family, tampered=tampered):
                        path.write_text(original.replace(hook, tampered))
                        result = self.run_cmd('verify')
                        self.assertEqual(result.stdout.strip(), 'DEGRADED')
                        self.assertEqual(result.returncode, 4)
                        path.write_text(original)

    def test_every_broadened_child_rule_is_degraded_in_both_families(self):
        self.assertEqual(self.run_cmd('enable', '--tailscale-udp4', '41641',
                                      '--tailscale-udp6', '41642').returncode, 0)
        for family in ('iptables', 'ip6tables'):
            path = self.base / f'{family}.POCKETUFW_TS'
            original = path.read_text()
            for tampered in ('-p udp -j ACCEPT\n', '-j ACCEPT\n', '-p tcp --dport 41641 -j ACCEPT\n',
                             '-p udp --sport 41641 -j ACCEPT\n',
                             original + '-p udp --dport 9999 -j ACCEPT\n',
                             '-p udp --dport 99999 -j ACCEPT\n'):
                with self.subTest(family=family, tampered=tampered):
                    path.write_text(tampered)
                    self.assertEqual(self.run_cmd('verify').stdout.strip(), 'DEGRADED')
                    path.write_text(original)
            self.assertEqual(self.run_cmd('verify').stdout.strip(), 'ACTIVE')

    # --- Counters: blocked is the sum of BOTH DROP rules (a real past bug). ---

    def test_blocked_counts_both_drop_rules_per_family(self):
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        result = self.run_cmd('activity', extra_env={
            'PUFW_TEST_DROP4': '12', 'PUFW_TEST_INVALID4': '5',
            'PUFW_TEST_DROP_BYTES4': '888', 'PUFW_TEST_INVALID_BYTES4': '100',
            'PUFW_TEST_DROP6': '40', 'PUFW_TEST_INVALID6': '3',
            'PUFW_TEST_DROP_BYTES6': '6000', 'PUFW_TEST_INVALID_BYTES6': '44',
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        values = dict(line.split('=', 1) for line in result.stdout.splitlines())
        self.assertEqual(values['ipv4_blocked'], '17')
        self.assertEqual(values['ipv4_blocked_bytes'], '988')
        self.assertEqual(values['ipv6_blocked'], '43')
        self.assertEqual(values['ipv6_blocked_bytes'], '6044')

    def test_verbose_counts_both_drop_rules(self):
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        result = self.run_cmd('verbose', extra_env={
            'PUFW_TEST_DROP4': '12', 'PUFW_TEST_INVALID4': '5',
            'PUFW_TEST_DROP_BYTES4': '888', 'PUFW_TEST_INVALID_BYTES4': '100',
            'PUFW_TEST_DROP6': '40', 'PUFW_TEST_INVALID6': '3',
            'PUFW_TEST_DROP_BYTES6': '6000', 'PUFW_TEST_INVALID_BYTES6': '44',
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('IPv4 blocked: 17 packets (988 bytes)', result.stdout)
        self.assertIn('IPv6 blocked: 43 packets (6044 bytes)', result.stdout)

    def test_counters_stay_exact_past_32_bits(self):
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        result = self.run_cmd('activity', extra_env={
            'PUFW_TEST_DROP4': '1099511627776', 'PUFW_TEST_INVALID4': '1',
            'PUFW_TEST_DROP_BYTES4': '281474976710656', 'PUFW_TEST_INVALID_BYTES4': '1',
        })
        self.assertIn('ipv4_blocked=1099511627777\n', result.stdout)
        self.assertIn('ipv4_blocked_bytes=281474976710657\n', result.stdout)

    def test_reset_zeroes_packets_and_bytes_of_both_drop_rules(self):
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        env = {'PUFW_TEST_DROP4': '12', 'PUFW_TEST_INVALID4': '5', 'PUFW_TEST_INVALID_BYTES4': '100'}
        self.assertEqual(self.run_cmd('reset-counters', extra_env=env).returncode, 0)
        values = dict(line.split('=', 1) for line in self.run_cmd('activity', extra_env=env).stdout.splitlines())
        for key in ('ipv4_blocked', 'ipv4_blocked_bytes', 'ipv6_blocked', 'ipv6_blocked_bytes'):
            self.assertEqual(values[key], '0', key)

    def test_a_counter_listing_of_the_wrong_shape_never_becomes_numbers(self):
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        for shape in ('no_header', 'no_established', 'no_invalid', 'no_final_drop', 'extra_drop'):
            with self.subTest(shape=shape):
                result = self.run_cmd('activity', extra_env={'PUFW_TEST_LIST_SHAPE': shape})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Cannot read IPv4 counters', result.stderr)
                self.assertNotIn('ipv4_blocked', result.stdout)

    def test_mock_rejects_a_counter_listing_without_exact_numeric_flags(self):
        # A real kernel would print 12K or resolve names; the engine must ask for -n -v -x.
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        for flags in (['-n', '-v'], ['-v', '-x'], ['-n', '-x']):
            with self.subTest(flags=flags):
                listing = subprocess.run(['iptables', '-w', '-L', 'POCKETUFW_IN', *flags],
                                         env=self.env, capture_output=True, text=True, timeout=5)
                self.assertNotEqual(listing.returncode, 0)

    # --- Refresh: reports what happened in each family alone, on a verified firewall only. ---

    def test_one_family_refresh_change_reports_updated(self):
        self.add_mock_tailscale_listener()
        self.assertEqual(self.run_cmd('enable', '--auto-tailscale').returncode, 0)
        # IPv6 only.
        (self.base / 'ss6').write_text((self.base / 'ss6').read_text().replace(':43504', ':43514'))
        res = self.run_cmd('refresh')
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn('refresh_result=UPDATED', res.stdout)
        self.assertEqual(self.read('iptables', 'POCKETUFW_TS'), '-p udp --dport 46867 -j ACCEPT\n')
        self.assertEqual(self.read('ip6tables', 'POCKETUFW_TS'), '-p udp --dport 43514 -j ACCEPT\n')
        # IPv4 only.
        (self.base / 'ss4').write_text((self.base / 'ss4').read_text().replace(':46867', ':46877'))
        res = self.run_cmd('refresh')
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn('refresh_result=UPDATED', res.stdout)
        self.assertEqual(self.read('iptables', 'POCKETUFW_TS'), '-p udp --dport 46877 -j ACCEPT\n')
        self.assertEqual(self.read('ip6tables', 'POCKETUFW_TS'), '-p udp --dport 43514 -j ACCEPT\n')
        self.assertIn('refresh_result=UNCHANGED', self.run_cmd('refresh').stdout)

    def test_refresh_refuses_a_degraded_firewall_in_either_family(self):
        self.add_mock_tailscale_listener()
        self.assertEqual(self.run_cmd('enable', '--auto-tailscale').returncode, 0)
        (self.base / 'ss4').write_text((self.base / 'ss4').read_text().replace(':46867', ':46877'))
        (self.base / 'ss6').write_text((self.base / 'ss6').read_text().replace(':43504', ':43514'))
        children = {f: self.read(f, 'POCKETUFW_TS') for f in ('iptables', 'ip6tables')}
        for family in ('iptables', 'ip6tables'):
            for name, tamper in (('parent', 'POCKETUFW_IN'), ('hook', 'INPUT')):
                with self.subTest(family=family, broken=name):
                    path = self.base / f'{family}.{tamper}'
                    original = path.read_text()
                    path.write_text('\n'.join(original.splitlines()[:-1]) + '\n')
                    res = self.run_cmd('refresh')
                    self.assertNotEqual(res.returncode, 0)
                    self.assertIn('no refresh attempted', res.stderr)
                    self.assertNotIn('refresh_result=', res.stdout)
                    for other, content in children.items():
                        self.assertEqual(self.read(other, 'POCKETUFW_TS'), content)
                    path.write_text(original)
        self.assertEqual(self.run_cmd('refresh').returncode, 0)

    def test_refresh_does_not_report_success_if_policy_breaks_during_the_change(self):
        self.add_mock_tailscale_listener()
        self.assertEqual(self.run_cmd('enable', '--auto-tailscale').returncode, 0)
        (self.base / 'ss4').write_text((self.base / 'ss4').read_text().replace(':46867', ':46877'))
        res = self.run_cmd('refresh', extra_env={'PUFW_TEST_BREAK_DURING_TS_ADD': '1'})
        self.assertNotEqual(res.returncode, 0)
        self.assertNotIn('refresh_result=', res.stdout)
        self.assertEqual(self.run_cmd('verify').stdout.strip(), 'DEGRADED')

    def test_refresh_refuses_afwall(self):
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        res = self.run_cmd('refresh', extra_env={'PUFW_TEST_AFWALL': '1'})
        self.assertNotEqual(res.returncode, 0)
        self.assertIn('AFWall+', res.stderr)
        self.assertNotIn('refresh_result=', res.stdout)

    def test_set_ports_refuses_afwall(self):
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        res = self.run_cmd('set-ports', '--udp4', '45678', '--udp6', 'none',
                           extra_env={'PUFW_TEST_AFWALL': '1'})
        self.assertNotEqual(res.returncode, 0)
        self.assertIn('AFWall+', res.stderr)
        self.assertEqual(self.read('iptables', 'POCKETUFW_TS'), '')

    def test_set_ports_does_not_report_success_if_policy_breaks_during_the_change(self):
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        res = self.run_cmd('set-ports', '--udp4', '45678', '--udp6', 'none',
                           extra_env={'PUFW_TEST_BREAK_DURING_TS_ADD': '1'})
        self.assertNotEqual(res.returncode, 0)
        self.assertNotIn('session-only', res.stdout)

    def test_enable_refuses_if_a_final_readback_is_wrong_in_either_family(self):
        res = self.run_cmd('enable', extra_env={'PUFW_TEST_FAIL': '-A INPUT -i v4-rmnet+ -m comment --comment PocketUFW -j POCKETUFW_IN',
                                                'PUFW_TEST_FAIL_FAMILY': 'ip6tables'})
        self.assertNotEqual(res.returncode, 0)
        self.assertEqual(self.read('iptables'), '-j oem_in\n-j bw_INPUT\n-j fw_INPUT\n')
        self.assertEqual(self.read('ip6tables'), '-j oem_in\n-j bw_INPUT\n-j fw_INPUT\n')

    def test_disable_reports_failure_when_a_chain_survives(self):
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        res = self.run_cmd('disable', extra_env={'PUFW_TEST_FAIL': '-X POCKETUFW_TS',
                                                 'PUFW_TEST_FAIL_FAMILY': 'ip6tables'})
        self.assertNotEqual(res.returncode, 0)
        self.assertNotIn('PocketUFW: disabled', res.stdout)

    def test_disable_removes_every_copy_of_a_duplicated_hook(self):
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        with (self.base / 'iptables.INPUT').open('a') as fh:
            fh.write(self.EXPECTED_HOOKS[0] + '\n')
        self.assertEqual(self.run_cmd('disable').returncode, 0)
        self.assertEqual(self.read('iptables').splitlines(), self.ANDROID_INPUT)

    # --- Cross-process lock. ---

    def record_flock_calls(self):
        """Toybox-shaped flock: fd operand only, no -w. Records how it was called."""
        real = shutil.which('flock', path=os.environ['PATH'])
        if real is None:
            self.skipTest('host has no flock')
        shim = self.base / 'bin' / 'flock'
        shim.write_text(
            '#!/bin/sh\n'
            'echo "$*" >> "$PUFW_TEST_DIR/flock_calls"\n'
            'for arg do case "$arg" in -s|-x|-u|-n|[0-9]) ;; *) echo "flock: bad $arg" >&2; exit 2 ;; esac; done\n'
            f'exec {real} "$@"\n')
        shim.chmod(0o755)
        return self.base / 'flock_calls'

    def test_locks_use_the_right_mode_for_each_command(self):
        calls = self.record_flock_calls()
        self.add_mock_tailscale_listener()
        sequence = [
            ('enable', '--auto-tailscale'), ('verify',), ('activity',), ('verbose',), ('status',),
            ('get-ports',), ('refresh',), ('set-ports', '--udp4', 'none', '--udp6', 'none'),
            ('reset-counters',), ('disable',),
        ]
        exclusive = {'enable', 'refresh', 'set-ports', 'reset-counters', 'disable'}
        for command in sequence:
            with self.subTest(command=command[0]):
                calls.unlink(missing_ok=True)
                result = self.run_cmd(*command)
                self.assertEqual(result.returncode, 0, result.stderr)
                mode = '-x' if command[0] in exclusive else '-s'
                lifecycle = ['-n -x 8'] if command[0] in exclusive else []
                self.assertEqual(calls.read_text().splitlines(), lifecycle + [f'-n {mode} 9'])

    def test_plan_and_doctor_take_no_lock(self):
        calls = self.record_flock_calls()
        for command in ('plan', 'doctor'):
            with self.subTest(command=command):
                self.assertEqual(self.run_cmd(command).returncode, 0)
                self.assertFalse(calls.exists())

    def test_descriptor_is_passed_to_flock_explicitly_for_mksh(self):
        # mksh, Android's sh, keeps exec'd descriptors above 2 from child commands
        # unless the command says n>&n. No test shell here reproduces that.
        self.assertIn('flock -n "$1" 9 9>&9 2>&1', SCRIPT.read_text())

    def test_default_lock_path_is_the_documented_one(self):
        self.assertIn('${POCKETUFW_LOCK:-/dev/.pocketufw.lock}', SCRIPT.read_text())

    def hold_lock(self, mode):
        """Hold the engine lock from this process, as a concurrent engine would."""
        fd = os.open(self.lock, os.O_CREAT | os.O_RDWR, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, mode)
        return fd

    @needs_flock
    def test_exclusive_holder_times_out_writers_with_a_message_but_not_readers(self):
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        before = self.read('iptables', 'POCKETUFW_TS')
        self.hold_lock(fcntl.LOCK_EX)
        results = {}

        def timed(name, *args):
            started = time.monotonic()
            results[name] = (self.run_cmd(*args), time.monotonic() - started)

        threads = [threading.Thread(target=timed, args=('write', 'set-ports', '--udp4', '45678', '--udp6', 'none')),
                   threading.Thread(target=timed, args=('read', 'verify'))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        written, write_time = results['write']
        self.assertNotEqual(written.returncode, 0)
        self.assertIn('Another PocketUFW operation is still running', written.stderr)
        self.assertEqual(self.read('iptables', 'POCKETUFW_TS'), before)
        read, read_time = results['read']
        self.assertEqual(read.returncode, 0, read.stderr)
        self.assertEqual(read.stdout.strip(), 'ACTIVE')
        # About 15 s of polling; the upper bound only allows for a busy machine.
        for elapsed in (write_time, read_time):
            self.assertGreater(elapsed, 12)
            self.assertLess(elapsed, 45)

    def engine_in_background(self, *args):
        process = subprocess.Popen(['sh', str(SCRIPT), *args], env=self.env, text=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(process.wait)
        self.addCleanup(process.kill)
        return process

    @needs_flock
    def test_shared_holder_blocks_writers_only(self):
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        fd = self.hold_lock(fcntl.LOCK_SH)
        started = time.monotonic()
        self.assertEqual(self.run_cmd('verify').stdout.strip(), 'ACTIVE')
        self.assertEqual(self.run_cmd('activity').returncode, 0)
        self.assertLess(time.monotonic() - started, 10)  # Neither waited out the lock.
        writer = self.engine_in_background('disable')
        time.sleep(0.5)
        self.assertIsNone(writer.poll())
        self.assertTrue((self.base / 'iptables.POCKETUFW_IN').exists())
        fcntl.flock(fd, fcntl.LOCK_UN)
        writer.communicate(timeout=30)
        self.assertEqual(writer.returncode, 0)
        self.assertFalse((self.base / 'iptables.POCKETUFW_IN').exists())

    @needs_flock
    def test_writer_waits_for_a_shorter_exclusive_holder_and_then_succeeds(self):
        fd = self.hold_lock(fcntl.LOCK_EX)
        writer = self.engine_in_background('enable')
        time.sleep(0.5)
        self.assertIsNone(writer.poll())
        self.assertFalse((self.base / 'iptables.POCKETUFW_IN').exists())
        fcntl.flock(fd, fcntl.LOCK_UN)
        writer.communicate(timeout=30)
        self.assertEqual(writer.returncode, 0)
        self.assertEqual(self.run_cmd('verify').stdout.strip(), 'ACTIVE')

    @needs_flock
    def test_reader_waits_for_a_shorter_exclusive_holder(self):
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        fd = self.hold_lock(fcntl.LOCK_EX)
        for command, expected in (('verify', 'ACTIVE'), ('get-ports', 'udp4=none')):
            with self.subTest(command=command):
                fcntl.flock(fd, fcntl.LOCK_EX)
                reader = self.engine_in_background(command)
                time.sleep(0.5)
                self.assertIsNone(reader.poll())
                fcntl.flock(fd, fcntl.LOCK_UN)
                self.assertIn(expected, reader.communicate(timeout=30)[0])
                self.assertEqual(reader.returncode, 0)

    @needs_flock
    def test_lock_is_released_when_the_engine_exits(self):
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        self.assertNotEqual(self.run_cmd('enable').returncode, 0)  # a failure must release too
        fd = os.open(self.lock, os.O_RDWR)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    @needs_flock
    def test_two_simultaneous_enables_do_not_destroy_each_other(self):
        for attempt in range(5):
            with self.subTest(attempt=attempt):
                extra = {**self.env, 'PUFW_TEST_SLOW_ADD': '0.005'}
                first = subprocess.Popen(['sh', str(SCRIPT), 'enable'], env=extra, text=True,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                second = subprocess.Popen(['sh', str(SCRIPT), 'enable'], env=extra, text=True,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                outcomes = [first.communicate(timeout=30), second.communicate(timeout=30)]
                self.assertEqual(sorted((first.returncode, second.returncode)), [0, 1], outcomes)
                self.assertEqual(self.run_cmd('verify').stdout.strip(), 'ACTIVE')
                self.assertEqual(self.run_cmd('disable').returncode, 0)

    @needs_flock
    def test_concurrent_read_never_sees_a_half_installed_firewall(self):
        extra = {**self.env, 'PUFW_TEST_SLOW_ADD': '0.01'}
        enable = subprocess.Popen(['sh', str(SCRIPT), 'enable'], env=extra, text=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        seen = set()
        for _ in range(8):
            seen.add(self.run_cmd('verify').stdout.strip())
        enable.communicate(timeout=30)
        self.assertEqual(enable.returncode, 0)
        self.assertLessEqual(seen, {'INACTIVE', 'ACTIVE'})
        self.assertEqual(self.run_cmd('verify').stdout.strip(), 'ACTIVE')

    def test_refresh_with_probe_child_does_not_deadlock_on_its_own_lock(self):
        self.add_mock_tailscale_listener()
        self.assertEqual(self.run_cmd('enable', '--auto-tailscale').returncode, 0)
        started = time.monotonic()
        self.assertEqual(self.run_cmd('refresh').returncode, 0)
        self.assertLess(time.monotonic() - started, 14)

    def test_unusable_snapshot_lock_needs_a_usable_lifecycle_lock_for_mutations(self):
        cases = {'parent missing': str(self.base / 'no' / 'such' / 'dir' / 'x'),
                 'is a directory': str(self.base / 'locks')}
        for name, path in cases.items():
            with self.subTest(case=name):
                started = time.monotonic()
                enabled = self.run_cmd('enable', extra_env={'POCKETUFW_LOCK': path})
                if name == 'parent missing':
                    self.assertNotEqual(enabled.returncode, 0)
                    self.assertEqual(self.run_cmd('verify').stdout.strip(), 'INACTIVE')
                    continue
                self.assertEqual(enabled.returncode, 0, enabled.stderr)
                self.assertEqual(self.run_cmd('verify', extra_env={'POCKETUFW_LOCK': path}).stdout.strip(), 'ACTIVE')
                self.assertEqual(self.run_cmd('disable', extra_env={'POCKETUFW_LOCK': path}).returncode, 0)
                self.assertLess(time.monotonic() - started, 14)  # Nothing waited out the lock.

    def test_absent_flock_refuses_mutations_but_allows_inspection(self):
        tools = self.base / 'tools'
        tools.mkdir()
        for tool in ('sh', 'awk', 'sed', 'grep', 'tail', 'cat', 'mv', 'rm', 'sleep'):
            (tools / tool).symlink_to(shutil.which(tool))
        for tool in ('id', 'iptables', 'ip6tables'):
            (tools / tool).symlink_to(self.base / 'bin' / tool)
        path = {'PATH': str(tools)}
        run = lambda *args: subprocess.run([str(tools / 'sh'), str(SCRIPT), *args], text=True,
                                           capture_output=True, env=self.env | path, timeout=15)
        self.assertNotEqual(run('enable').returncode, 0)
        self.assertEqual(run('verify').stdout.strip(), 'INACTIVE')
        self.assertNotEqual(run('disable').returncode, 0)
        self.assertFalse(self.lock.exists())

    def test_broken_flock_refuses_mutations_without_waiting(self):
        # Contention is silent. A diagnostic means flock itself cannot work on this
        # shell or filesystem. Inspection remains available, mutation must refuse.
        shim = self.base / 'bin' / 'flock'
        shim.write_text('#!/bin/sh\necho "flock: 9: Bad file descriptor" >&2\nexit 1\n')
        shim.chmod(0o755)
        started = time.monotonic()
        result = self.run_cmd('enable')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.run_cmd('verify').stdout.strip(), 'INACTIVE')
        self.assertLess(time.monotonic() - started, 14)  # Nothing waited out the lock.

    def test_no_output_forward_changes(self):
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        filenames = [p.name for p in self.base.iterdir() if not p.is_dir()]
        self.assertEqual(set(filenames), {
            'iptables.INPUT', 'ip6tables.INPUT', 'iptables.POCKETUFW_IN', 'ip6tables.POCKETUFW_IN',
            'iptables.POCKETUFW_TS', 'ip6tables.POCKETUFW_TS'})
        self.assertEqual(self.run_cmd('disable').returncode, 0)

if __name__ == '__main__':
    unittest.main()
