"""Host parser and real NFLOG tests. No device or host firewall is modified."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import test_real_kernel as kernel

ROOT = Path(__file__).resolve().parents[1]
COMPILER = shutil.which('clang++') or shutil.which('g++')

@unittest.skipUnless(COMPILER, 'C++ compiler unavailable')
class NativeCoreTests(unittest.TestCase):
    def test_bounded_parser_and_exact_rule_ownership(self):
        with tempfile.TemporaryDirectory() as folder:
            binary = str(Path(folder) / 'core')
            subprocess.run([COMPILER, '-std=c++17', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                            '-fno-omit-frame-pointer', '-no-pie', str(ROOT / 'tests/insights_native_test.cpp'), '-o', binary], check=True)
            subprocess.run([binary], check=True, timeout=10)

@unittest.skipIf(kernel.UNUSABLE or not COMPILER, kernel.UNUSABLE or 'C++ compiler unavailable')
class NativeKernelTests(unittest.TestCase):
    namespace = kernel.RealKernelTests.namespace
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.temp.name) / 'insights'
        subprocess.run([COMPILER, '-std=c++17', '-Wall', '-Wextra', '-Werror', '-DPUFW_HOST_TEST',
                        str(ROOT / 'android/app/src/main/cpp/insights.cpp'), '-o', str(cls.binary)], check=True)
    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()
    def setUp(self):
        kernel.RealKernelTests.setUp(self)
        shutil.copy(self.binary, self.device.root / 'insights')
    def run_sample(self, body):
        return self.namespace(r'''
        export PUFW_TEST_SH="${POCKETUFW_TEST_MKSH:-/bin/sh}"
        export POCKETUFW_IPTABLES4=$(command -v iptables)
        export POCKETUFW_IPTABLES6=$(command -v ip6tables)
        I="$DEVICE/insights"
        link wlan0 9
        sh "$ENG" enable >/dev/null || exit 91
        mkfifo "$WORK/control"
        exec 7<>"$WORK/control"
        start_sample() {
          iptables -S > "$WORK/before4"; ip6tables -S > "$WORK/before6"
          "$I" capture "$ENG" <&7 > "$WORK/report" 2> "$WORK/errors" &
          inspector=$!
        }
        ready() {
          for retry in $(seq 1 400); do
            if grep -q 'Sampling ready' "$WORK/errors"; then return; fi
            kill -0 "$inspector" 2>/dev/null || { cat "$WORK/report" >&2; exit 92; }
            sleep .01
          done
          cat "$WORK/report" >&2; exit 93
        }
        observe_verification() {
          export TEST_INSIGHTS_ENGINE="$ENG"
          cat > "$WORK/engine-shim" <<'SHIM'
if [ "$1" = verify ]; then
  echo verify >> "$WORK/verifications"
  if [ -e "$WORK/verified-once" ]; then
    for ipt in "$POCKETUFW_IPTABLES4" "$POCKETUFW_IPTABLES6"; do
      "$ipt" -w 2 -S > "$WORK/verification-rules" || exit 96
      grep -q PUFW_APP1 "$WORK/verification-rules" && exit 97
    done
    flock -n "$POCKETUFW_LOCK" true || exit 98
    echo cleaned >> "$WORK/verifications"
    case "${TEST_INSIGHTS_VERIFY_MODE:-active}" in
      inactive) echo INACTIVE; exit 3 ;;
      bad-exit) echo ACTIVE; exit 4 ;;
      unavailable) exit 127 ;;
    esac
  fi
  touch "$WORK/verified-once"
fi
exec sh "$TEST_INSIGHTS_ENGINE" "$@"
SHIM
          ENG="$WORK/engine-shim"
        }
        unchanged() {
          iptables -S > "$WORK/after4"; ip6tables -S > "$WORK/after6"
          cmp "$WORK/before4" "$WORK/after4" || exit 94
          cmp "$WORK/before6" "$WORK/after6" || exit 95
          say state "$(sh "$ENG" verify)"
        }
        ''' + body, timeout=45)
    def report(self):
        return (self.work / 'report').read_text()
    def test_real_drops_both_families_tunnel_and_accepted_replies(self):
        result = self.run_sample(r'''
        link tun0 10
        sh "$ENG" tunnel-on --deny-only >/dev/null || exit 96
        near_mac=$(ip -o link show tun0 | awk '{for(i=1;i<=NF;i++)if($i=="link/ether")print $(i+1)}')
        far_mac=$(peer ip -o link show peer2 | awk '{for(i=1;i<=NF;i++)if($i=="link/ether")print $(i+1)}')
        ip -6 neigh replace fd10::2 lladdr "$far_mac" nud permanent dev tun0
        peer ip -6 neigh replace fd10::1 lladdr "$near_mac" nud permanent dev peer2
        peer $N send 4 10.9.0.1 47931 7
        start_sample; ready
        peer ping -c 1 -W 1 10.9.0.1 >/dev/null || exit 97
        peer $N echo 4 7777 "$WORK/echo4" &
        wait_for "$WORK/echo4"
        say replies "$($N ask 4 10.9.0.2 7777 3)"
        say physical4 "$(deliver 4 9 1900 3)"
        say physical6 "$(deliver 6 9 1900 3)"
        say tunnel4 "$(deliver 4 10 47931 3)"
        say tunnel6 "$(deliver 6 10 47931 3)"
        peer $N invalid_tcp 4 10.9.0.2 10.9.0.1 2
        peer $N invalid_tcp 6 fd9::2 fd9::1 2
        wait "$inspector" || { cat "$WORK/report" >&2; exit 98; }
        unchanged
        say count4 "$(kv ipv4_blocked)"
        ''')
        self.assertEqual(result['state'], 'ACTIVE')
        self.assertEqual(result['replies'], '3')
        for name in ('physical4', 'physical6', 'tunnel4', 'tunnel6'): self.assertEqual(result[name], '0')
        self.assertEqual(result['count4'], '12')
        report = self.report()
        self.assertIn('end=verified', report)
        for scope in ('P', 'T'):
            for family in (4, 6): self.assertIn(f'packet={scope}|{family}|F|', report)
        self.assertIn('packet=P|4|I|', report)
        self.assertIn('packet=P|6|I|', report)
        self.assertNotIn('|7777\n', report)
        self.assertNotIn('|1|-1|-1', report)
    def test_packet_cap_stops_early(self):
        result = self.run_sample(r'''
        start_sample; ready
        peer $N send 4 10.9.0.1 1900 300
        wait "$inspector" || { cat "$WORK/report" >&2; exit 97; }
        unchanged
        ''')
        self.assertEqual(result['state'], 'ACTIVE')
        self.assertIn('records=256\n', self.report())
        self.assertEqual(self.report().count('packet='), 256)
    def test_term_and_stop_cleanup_withhold_report(self):
        for stop in ('kill -TERM "$inspector"', 'echo stop >&7'):
            with self.subTest(stop=stop):
                if stop.startswith('echo'): self.setUp()
                result = self.run_sample('start_sample; ready\n' + stop + r'''
                wait "$inspector" && exit 98
                unchanged
                ''')
                self.assertEqual(result['state'], 'ACTIVE')
                self.assertNotIn('PUFW_INSIGHTS_V1', self.report())
                self.assertIn('Cleanup verified', self.report())
    def test_sigkill_detected_and_exact_recovery_is_repeatable(self):
        result = self.run_sample(r'''
        start_sample; ready
        kill -KILL "$inspector"; wait "$inspector" || :
        "$I" capture "$ENG" <&7 > "$WORK/refused" && exit 97
        "$I" recover "$ENG" > "$WORK/recovered" || exit 98
        "$I" recover "$ENG" > "$WORK/recovered-again" || exit 99
        unchanged
        ''')
        self.assertEqual(result['state'], 'ACTIVE')
        self.assertIn('Diagnostic residue detected', (self.work / 'refused').read_text())
        self.assertIn('end=verified', (self.work / 'recovered').read_text())
    def test_partial_insertion_failure_rolls_back(self):
        result = self.run_sample(r'''
        real6="$POCKETUFW_IPTABLES6"
        printf '#!/bin/sh\ncase " $* " in *" -I "*) exit 1;; esac\nexec %s "$@"\n' "$real6" > "$WORK/ip6tables"
        chmod +x "$WORK/ip6tables"
        ln -s "$real6-save" "$WORK/ip6tables-save"
        export POCKETUFW_IPTABLES6="$WORK/ip6tables"
        start_sample
        wait "$inspector" && exit 98
        unchanged
        ''')
        self.assertEqual(result['state'], 'ACTIVE')
        self.assertIn('Cleanup verified', self.report())
        self.assertNotIn('end=verified', self.report())
    def test_cleanup_failure_withholds_sample_and_recovery_removes_only_probes(self):
        result = self.run_sample(r'''
        real4="$POCKETUFW_IPTABLES4"
        printf '#!/bin/sh\ncase " $* " in *" -D "*) [ ! -e "%s" ] || exit 1;; esac\nexec %s "$@"\n' "$WORK/fail-delete" "$real4" > "$WORK/iptables"
        chmod +x "$WORK/iptables"; ln -s "$real4-save" "$WORK/iptables-save"
        export POCKETUFW_IPTABLES4="$WORK/iptables"
        touch "$WORK/fail-delete"
        start_sample; ready
        echo stop >&7
        wait "$inspector" && exit 97
        iptables -S | grep -q PUFW_APP1 || exit 98
        rm "$WORK/fail-delete"
        "$I" recover "$ENG" > "$WORK/recovered" || exit 99
        unchanged
        ''')
        self.assertEqual(result['state'], 'ACTIVE')
        self.assertIn('Cleanup not verified', self.report())
        self.assertNotIn('end=verified', self.report())
    def test_lock_contention_and_group_conflict_install_nothing(self):
        for setup in ('exec 8>>"$POCKETUFW_LOCK.operation"; flock -x 8',
                      'iptables -t mangle -A INPUT -j NFLOG --nflog-group 17'):
            with self.subTest(setup=setup):
                if setup.startswith('iptables'): self.setUp()
                result = self.run_sample(setup + r'''
                start_sample
                wait "$inspector" && exit 97
                exec 8>&-
                unchanged
                ''')
                self.assertEqual(result['state'], 'ACTIVE')
                self.assertNotIn('end=verified', self.report())
    def test_malformed_reserved_rule_is_never_deleted(self):
        result = self.run_sample(r'''
        tag=PUFW_APP1:0123456789abcdef0123456789abcdef:P:F
        iptables -I POCKETUFW_IN 8 -j NFLOG --nflog-prefix "$tag" --nflog-group 18 --nflog-size 24 --nflog-threshold 1
        iptables -S > "$WORK/before4"
        "$I" recover "$ENG" > "$WORK/report" && exit 97
        iptables -S > "$WORK/after4"
        cmp "$WORK/before4" "$WORK/after4" || exit 98
        ''')
        self.assertIn('Unrecognized Insights options', self.report())
    def test_app_pipe_closure_cleans_up(self):
        result = self.run_sample(r'''
        iptables -S > "$WORK/before4"; ip6tables -S > "$WORK/before6"
        python3 - "$I" "$ENG" "$WORK" <<'PYINNER'
import pathlib, subprocess, sys, time
root = pathlib.Path(sys.argv[3])
with (root / 'report').open('w') as out, (root / 'errors').open('w') as err:
    process = subprocess.Popen(sys.argv[1:2] + ['capture', sys.argv[2]], stdin=subprocess.PIPE, stdout=out, stderr=err)
    try:
        deadline = time.monotonic() + 10
        while 'Sampling ready' not in (root / 'errors').read_text():
            assert process.poll() is None and time.monotonic() < deadline
            time.sleep(.01)
        process.stdin.close()  # Same event as app/process death: no writer left.
        assert process.wait(timeout=15) != 0
    finally:
        if process.poll() is None: process.kill(); process.wait()
PYINNER
        [ "$?" = 0 ] || exit 97
        unchanged
        ''')
        self.assertEqual(result['state'], 'ACTIVE')
        self.assertIn('Cleanup verified', self.report())
    def test_non_active_policy_refuses_instrumentation(self):
        result = self.run_sample(r'''
        iptables -I POCKETUFW_IN 1 -p udp -j ACCEPT
        start_sample
        wait "$inspector" && exit 97
        iptables -S > "$WORK/after4"
        cmp "$WORK/before4" "$WORK/after4" || exit 98
        ''')
        self.assertNotIn('end=verified', self.report())
        self.assertNotIn('PUFW_APP1:', (self.work / 'after4').read_text())
    def test_leftover_tunnel_probes_are_readable_in_android_report(self):
        result = self.run_sample(r'''
        link tun0 10
        sh "$ENG" tunnel-on --deny-only >/dev/null || exit 96
        start_sample; ready
        kill -KILL "$inspector"; wait "$inspector" || :
        sh "$DEVICE/engine/rules-report" > "$WORK/rules" || exit 97
        "$I" recover "$ENG" >/dev/null || exit 98
        unchanged
        ''')
        self.assertEqual(result['state'], 'ACTIVE')
        text = (self.work / 'rules').read_text()
        self.assertIn('PUFW_APP1:', text)
        self.assertIn('report_tunnel4_count=5', text)
        self.assertTrue(text.endswith('rules_report=READY\n'))
    def test_outside_change_during_sample_is_withheld_kept_and_not_sent_to_recovery(self):
        # Another root program bypasses PocketUFW's locks while probes are live. The engine does
        # not audit this chain, so only the helper's final baseline comparison can notice it.
        result = self.run_sample(r'''
        observe_verification
        start_sample; ready
        iptables -w -N OTHER_APP; iptables -w -A OTHER_APP -j ACCEPT
        wait "$inspector" && exit 97
        iptables -S | grep -q PUFW_APP1 && exit 98
        iptables -S OTHER_APP | grep -q -- '-A OTHER_APP -j ACCEPT' || exit 99
        say state "$(sh "$TEST_INSIGHTS_ENGINE" verify)"
        ''')
        self.assertEqual(result['state'], 'ACTIVE')
        self.assertNotIn('PUFW_INSIGHTS_V1', self.report())
        self.assertIn('Probes removed, but other firewall rules changed', self.report())
        # Probes were verified absent, so recovery is not the remedy.
        self.assertNotIn('Cleanup not verified', self.report())
        self.assertEqual((self.work / 'verifications').read_text().splitlines(),
                         ['verify', 'verify', 'cleaned'])

    def test_withheld_sample_cannot_skip_or_claim_failed_final_verification(self):
        for index, mode in enumerate(('inactive', 'bad-exit', 'unavailable')):
            with self.subTest(mode=mode):
                if index: self.setUp()
                result = self.run_sample(f'export TEST_INSIGHTS_VERIFY_MODE={mode}\n' + r'''
                observe_verification
                start_sample; ready
                ip6tables -w -N OTHER_APP; ip6tables -w -A OTHER_APP -j ACCEPT
                echo stop >&7
                wait "$inspector" && exit 97
                ip6tables -S OTHER_APP | grep -q -- '-A OTHER_APP -j ACCEPT' || exit 99
                say state "$(sh "$TEST_INSIGHTS_ENGINE" verify)"
                ''')
                self.assertEqual(result['state'], 'ACTIVE')
                self.assertEqual((self.work / 'verifications').read_text().splitlines(),
                                 ['verify', 'verify', 'cleaned'])
                report = self.report()
                self.assertIn('not independently verified ACTIVE', report)
                self.assertNotIn('firewall ACTIVE', report)
                self.assertNotIn('state=ACTIVE', report)
                self.assertNotIn('end=verified', report)
                self.assertNotIn('packet=', report)
                self.assertNotIn('Cleanup not verified', report)
                self.assertNotIn('Use Recover', report)
    def test_recovery_with_nothing_to_recover_leaves_unrelated_nflog_alone(self):
        result = self.run_sample(r'''
        iptables -w -N OTHER_LOG
        iptables -w -A OTHER_LOG -j NFLOG --nflog-prefix PUFW_APP2:near-miss --nflog-group 17 --nflog-size 24
        iptables -S > "$WORK/before4"; ip6tables -S > "$WORK/before6"
        "$I" recover "$ENG" > "$WORK/report" || exit 97
        unchanged
        ''')
        self.assertEqual(result['state'], 'ACTIVE')
        self.assertEqual(self.report(), 'PUFW_INSIGHTS_RECOVERED_V1\ncleanup=verified\nstate=ACTIVE\nend=verified\n')
    def test_final_engine_verification_withholds_completed_sample(self):
        # Rules come back exactly, but the engine stops reporting ACTIVE. Only the helper's last
        # independent verify can see that. The record cap ends collection early.
        result = self.run_sample(r'''
        printf 'if [ "$1" = verify ] && [ -e %s ]; then echo DEGRADED; exit 4; fi\n[ "$1" != verify ] || : > %s\nexec sh %s "$@"\n' \
          "$WORK/verified-once" "$WORK/verified-once" "$ENG" > "$WORK/engine-shim"
        iptables -S > "$WORK/before4"; ip6tables -S > "$WORK/before6"
        "$I" capture "$WORK/engine-shim" <&7 > "$WORK/report" 2> "$WORK/errors" &
        inspector=$!
        ready
        peer $N send 4 10.9.0.1 1900 300
        wait "$inspector" && exit 97
        unchanged
        ''')
        self.assertEqual(result['state'], 'ACTIVE')
        self.assertNotIn('PUFW_INSIGHTS_V1', self.report())
        self.assertIn('not independently verified ACTIVE', self.report())
        self.assertNotIn('Cleanup not verified', self.report())
    def test_rule_change_during_setup_stops_before_collection(self):
        # An outside change lands between probe insertions. The setup comparison must stop the
        # run before collection starts; the final comparison alone would collect first.
        result = self.run_sample(r'''
        real4="$POCKETUFW_IPTABLES4"
        printf '#!/bin/sh\ncase " $* " in *" -I "*) [ -e %s ] || { : > %s; %s -w -N OTHER_APP; };; esac\nexec %s "$@"\n' \
          "$WORK/changed" "$WORK/changed" "$real4" "$real4" > "$WORK/iptables"
        chmod +x "$WORK/iptables"; ln -s "$real4-save" "$WORK/iptables-save"
        export POCKETUFW_IPTABLES4="$WORK/iptables"
        start_sample
        wait "$inspector" && exit 97
        [ -e "$WORK/changed" ] || exit 96
        grep -q 'Sampling ready' "$WORK/errors" && exit 98
        iptables -S | grep -q PUFW_APP1 && exit 99
        iptables -S OTHER_APP > /dev/null || exit 95
        say state "$(sh "$ENG" verify)"
        ''')
        self.assertEqual(result['state'], 'ACTIVE')
        self.assertNotIn('PUFW_INSIGHTS_V1', self.report())
    def test_android_quota_countdown_does_not_withhold_sample_or_fail_recovery(self):
        # Seen on Frankenpixel: netd's xt_quota2 rules list their remaining bytes, which fall
        # with traffic. Mainline has no quota2, so a wrapper appends the phone's row to each full
        # listing with a smaller value every time. Rule structure is unchanged throughout.
        result = self.run_sample(r'''
        real4="$POCKETUFW_IPTABLES4"
        printf '#!/bin/sh\nlast=; for a; do last=$a; done\nif [ "$last" = -S ]; then n=$(cat %s 2>/dev/null || echo 105720333316); echo $((n - 172)) > %s\n%s "$@" || exit\necho "-A bw_costly_rmnet16 -m quota2 ! --name rmnet16  --quota $n  -j REJECT --reject-with icmp-port-unreachable"; exit 0; fi\nexec %s "$@"\n' \
          "$WORK/quota" "$WORK/quota" "$real4" "$real4" > "$WORK/iptables"
        chmod +x "$WORK/iptables"; ln -s "$real4-save" "$WORK/iptables-save"
        export POCKETUFW_IPTABLES4="$WORK/iptables"
        start_sample; ready
        peer $N send 4 10.9.0.1 1900 300
        wait "$inspector" || { cat "$WORK/report" >&2; exit 97; }
        cp "$WORK/report" "$WORK/sampled"
        unchanged
        "$WORK/iptables" -S | grep -c quota2 > "$WORK/quota-rows"
        cat "$WORK/quota" > "$WORK/quota-final"
        start_sample; ready
        kill -KILL "$inspector"; wait "$inspector" || :
        "$I" recover "$ENG" > "$WORK/recovered" || { cat "$WORK/recovered" >&2; exit 98; }
        unchanged
        ''')
        self.assertEqual(result['state'], 'ACTIVE')
        self.assertEqual((self.work / 'quota-rows').read_text().strip(), '1')
        # The listing really changed between the helper's snapshots.
        self.assertLess(int((self.work / 'quota-final').read_text()), 105720333316 - 172 * 4)
        sampled = (self.work / 'sampled').read_text()
        self.assertIn('PUFW_INSIGHTS_V1', sampled)
        self.assertIn('records=256\n', sampled)
        self.assertIn('PUFW_INSIGHTS_RECOVERED_V1', (self.work / 'recovered').read_text())
    def test_unrecognized_probe_stops_recovery_and_keeps_protection(self):
        # Genuine leftover probes plus one unrecognized reserved rule. Recovery must change
        # nothing, not even the recognized probes, and real packets must still be dropped.
        result = self.run_sample(r'''
        start_sample; ready
        kill -KILL "$inspector"; wait "$inspector" || :
        tag=PUFW_APP1:0123456789abcdef0123456789abcdef:P:F
        iptables -I POCKETUFW_IN 1 -j NFLOG --nflog-prefix "$tag" --nflog-group 18 --nflog-size 24 --nflog-threshold 1
        iptables -S > "$WORK/held4"; ip6tables -S > "$WORK/held6"
        [ "$(grep -c PUFW_APP1 "$WORK/held4")" -ge 3 ] || exit 96
        "$I" recover "$ENG" > "$WORK/report" && exit 97
        iptables -S | cmp -s - "$WORK/held4" || exit 98
        ip6tables -S | cmp -s - "$WORK/held6" || exit 99
        say blocked4 "$(deliver 4 9 1900 3)"
        say blocked6 "$(deliver 6 9 1900 3)"
        # After explicit review removes the unrecognized rule, recovery can finish.
        iptables -D POCKETUFW_IN -j NFLOG --nflog-prefix "$tag" --nflog-group 18 --nflog-size 24 --nflog-threshold 1
        "$I" recover "$ENG" > "$WORK/recovered" || exit 94
        unchanged
        ''')
        self.assertEqual(result['state'], 'ACTIVE')
        self.assertEqual((result['blocked4'], result['blocked6']), ('0', '0'))
        report = self.report()
        self.assertIn('Unrecognized Insights options', report)
        self.assertIn('Affected IPv4 rule: -A POCKETUFW_IN -j NFLOG --nflog-prefix ' + 'PUFW_APP1:0123456789abcdef0123456789abcdef:P:F --nflog-group 18', report)
        self.assertIn('Nothing was removed, disabled or rebuilt', report)
        self.assertNotIn('Use Recover', report)
        self.assertLess(len(report.splitlines()[0]), 400)
