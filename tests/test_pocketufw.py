"""Offline tests using shell-only mock iptables. Never touch the host firewall."""
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'pocketufw'

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
    case "$fam" in
      iptables) dropped="${PUFW_TEST_DROP4:-0}"; replies="${PUFW_TEST_REPLIES4:-0}" ;;
      ip6tables) dropped="${PUFW_TEST_DROP6:-0}"; replies="${PUFW_TEST_REPLIES6:-0}" ;;
    esac
    # Test-only persistent counters: reset must survive a CLI subprocess.
    if [ -f "$state/$fam.counters" ]; then
      read dropped replies < "$state/$fam.counters"
    fi
    printf 'Chain %s (3 references)\n' "$name"
    printf '    pkts      bytes target     prot opt in out source destination\n'
    printf '      %s        500 ACCEPT     all  --  * * 0/0 0/0 ctstate ESTABLISHED,RELATED\n' "$replies"
    printf '       0          0 DROP       all  --  * * 0/0 0/0 ctstate INVALID\n'
    printf '      %s        888 DROP       all  --  * * 0/0 0/0\n' "$dropped"
    exit 0 ;;
  -S)
    if [ "$name" = OUTPUT ]; then
      if [ "${PUFW_TEST_AFWALL:-0}" = 1 ]; then echo '-A OUTPUT -j afwall'; fi
      exit 0
    fi
    [ -f "$file" ] || exit 1
    echo "-N $name"
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
case "$action" in
  -Z)
    [ -f "$file" ] || exit 1
    case "$name" in POCKETUFW_IN|POCKETUFW_TS) : ;; *) exit 7 ;; esac
    echo "$fam $name" >> "$state/zero_events"
    if [ "$name" = POCKETUFW_IN ]; then
      printf '0 0\n' > "$state/$fam.counters"
    fi ;;
  -N)
    [ -f "$file" ] && exit 1
    : > "$file" ;;
  -A)
    [ -f "$file" ] || exit 1
    echo "$*" >> "$file" ;;
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
        self.env = {**os.environ, 'PATH': str(bindir) + os.pathsep + os.environ['PATH'], 'PUFW_TEST_DIR': str(self.base)}

    def run_cmd(self, *args, extra_env=None):
        return subprocess.run(['sh', str(SCRIPT), *args], text=True, capture_output=True,
                              env=self.env | (extra_env or {}), timeout=15)

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

    def test_unverified_auto_tailscale_fails_without_creating_rules(self):
        self.add_mock_tailscale_listener(valid=False)
        res = self.run_cmd('enable', '--auto-tailscale')
        self.assertNotEqual(res.returncode, 0)
        self.assertIn('discovery failed', res.stderr)
        self.assertFalse((self.base / 'iptables.POCKETUFW_IN').exists())
        self.assertEqual(self.read('iptables'), '-j oem_in\n-j bw_INPUT\n-j fw_INPUT\n')

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
        self.assertIn('46877', res.stdout)
        self.assertIn('43514', res.stdout)
        self.assertEqual(self.read('iptables', 'POCKETUFW_TS').count('--dport 46877'), 1)
        self.assertEqual(self.read('ip6tables', 'POCKETUFW_TS').count('--dport 43514'), 1)
        self.assertNotIn('46867', self.read('iptables', 'POCKETUFW_TS'))
        self.assertNotIn('43504', self.read('ip6tables', 'POCKETUFW_TS'))
        self.assertEqual(self.run_cmd('refresh').returncode, 0)
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
        previous = self.read('ip6tables', 'POCKETUFW_TS')
        self.assertNotEqual(self.run_cmd('set-ports', '--udp4', '45678', '--udp6', 'none').returncode, 0)
        self.assertEqual(self.read('ip6tables', 'POCKETUFW_TS'), previous)
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

    def test_no_output_forward_changes(self):
        self.assertEqual(self.run_cmd('enable').returncode, 0)
        filenames = [p.name for p in self.base.iterdir() if not p.is_dir()]
        self.assertEqual(set(filenames), {
            'iptables.INPUT', 'ip6tables.INPUT', 'iptables.POCKETUFW_IN', 'ip6tables.POCKETUFW_IN',
            'iptables.POCKETUFW_TS', 'ip6tables.POCKETUFW_TS'})
        self.assertEqual(self.run_cmd('disable').returncode, 0)

if __name__ == '__main__':
    unittest.main()
