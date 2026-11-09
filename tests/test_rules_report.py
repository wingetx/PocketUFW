"""Read-only kernel policy snapshot tests with mocked iptables."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

MOCK = r'''#!/bin/sh
fam=$(basename "$0")
printf '%s %s\n' "$fam" "$*" >> "$TEST_CALLS"
[ "$1" = '-w' ] || exit 7
shift
[ "$1" = '-S' ] || exit 7
shift
chain=$1
[ "$fam" != ip6tables ] || [ "$TEST_IPV6_FAIL" = 0 ] || exit 8
case "$chain" in
  INPUT)
    if [ "$fam" = iptables ]; then
      echo "-P INPUT $TEST_POLICY4"
    else
      echo '-P INPUT DROP'
    fi
    echo '-A INPUT -j unrelated_oem_chain'
    if [ "$fam" = iptables ]; then printf '%s' "${TEST_INPUT_BEFORE4:-}"; else printf '%s' "${TEST_INPUT_BEFORE6:-}"; fi
    if [ "${TEST_NO_HOOKS:-0}" = 0 ]; then
      echo '-A INPUT -i wlan+ -m comment --comment PocketUFW -j POCKETUFW_IN'
      echo '-A INPUT -i rmnet+ -m comment --comment PocketUFW -j POCKETUFW_IN'
      echo '-A INPUT -i v4-rmnet+ -m comment --comment PocketUFW -j POCKETUFW_IN'
      echo '-A INPUT -i v4-wlan+ -m comment --comment PocketUFW -j POCKETUFW_IN'
    fi
    printf '%s' "${TEST_INPUT_AFTER:-}"
    ;;
  POCKETUFW_IN)
    echo '-N POCKETUFW_IN'
    echo '-A POCKETUFW_IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT'
    if [ "$fam" = iptables ]; then
      echo '-A POCKETUFW_IN -p icmp -j ACCEPT'
    else
      echo '-A POCKETUFW_IN -p ipv6-icmp -j ACCEPT'
    fi
    echo '-A POCKETUFW_IN -m conntrack --ctstate INVALID -j DROP'
    echo '-A POCKETUFW_IN -j POCKETUFW_TS'
    echo '-A POCKETUFW_IN -j DROP'
    if [ "$TEST_MANY_RULES" = 1 ]; then
      n=0
      while [ "$n" -lt 16 ]; do
        echo '-A POCKETUFW_IN -p udp -j ACCEPT'
        n=$((n+1))
      done
    fi
    ;;
  POCKETUFW_TS)
    echo '-N POCKETUFW_TS'
    if [ "$fam" = iptables ]; then
      echo '-A POCKETUFW_TS -p udp --dport 41641 -j ACCEPT'
    else
      echo '-A POCKETUFW_TS -p udp --dport 51233 -j ACCEPT'
    fi
    ;;
  *) exit 8 ;;
esac
'''


class RuleReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pufw-rules-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.bin = self.base / "bin"
        self.bin.mkdir()
        self.calls = self.base / "calls"
        for name in ("iptables", "ip6tables"):
            target = self.bin / name
            target.write_text(MOCK)
            target.chmod(0o755)
        fake_id = self.bin / "id"
        fake_id.write_text(
            '#!/bin/sh\n[ "$1" = "-u" ] || exit 7\n'
            '[ "$TEST_UID" = 2000 ] && echo 2000 || echo 0\n'
        )
        fake_id.chmod(0o755)
        self.env = {**os.environ, "PATH": str(self.bin) + ":" + os.environ["PATH"],
                    "TEST_CALLS": str(self.calls), "TEST_UID": "0",
                    "TEST_POLICY4": "ACCEPT", "TEST_IPV6_FAIL": "0",
                    "TEST_MANY_RULES": "0"}

    def run_report(self, **changes):
        return subprocess.run(
            ["/bin/sh", str(ROOT / "rules-report")],
            text=True, capture_output=True, timeout=7,
            env={**self.env, **{k: str(v) for k, v in changes.items()}}
        )

    def test_two_families_report_kernel_rules_without_other_input_chains(self):
        result = self.run_report()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines()[-1], "rules_report=READY")
        self.assertIn("input_policy4=ACCEPT", result.stdout)
        self.assertIn("input_policy6=DROP", result.stdout)
        self.assertIn("hook4_03=-A INPUT -i v4-rmnet+", result.stdout)
        self.assertIn("main4_05=-A POCKETUFW_IN -j DROP", result.stdout)
        self.assertIn("vpn4_01=-A POCKETUFW_TS -p udp --dport 41641", result.stdout)
        self.assertIn("vpn6_01=-A POCKETUFW_TS -p udp --dport 51233", result.stdout)
        self.assertNotIn("unrelated_oem_chain", result.stdout)

    REAL_ANDROID_INPUT = ('-A INPUT -j oem_in\n-A INPUT -j bw_INPUT\n-A INPUT -j fw_INPUT\n'
                          '-A INPUT -j nm_mdnsd_block\n-A INPUT -j pl_INPUT\n')

    def report_lines(self, prefix, **changes):
        result = self.run_report(**changes)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines()[-1], 'rules_report=READY')
        return [line for line in result.stdout.splitlines() if line.startswith(prefix)]

    def test_real_android_input_chains_are_not_flagged(self):
        self.assertEqual(self.report_lines('input_bypass', TEST_INPUT_BEFORE4=self.REAL_ANDROID_INPUT,
                                           TEST_INPUT_BEFORE6=self.REAL_ANDROID_INPUT), [])

    def test_earlier_accept_rules_are_reported_per_family_and_in_order(self):
        lines = self.report_lines(
            'input_bypass',
            TEST_INPUT_BEFORE4=self.REAL_ANDROID_INPUT + '-A INPUT -i wlan0 -j ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT\n',
            TEST_INPUT_BEFORE6='-A INPUT -j ACCEPT\n')
        self.assertEqual(lines, ['input_bypass4_01=-A INPUT -i wlan0 -j ACCEPT',
                                 'input_bypass4_02=-A INPUT -p tcp --dport 22 -j ACCEPT',
                                 'input_bypass6_01=-A INPUT -j ACCEPT'])

    def test_accept_rules_after_the_first_hook_are_not_a_bypass(self):
        self.assertEqual(self.report_lines('input_bypass', TEST_INPUT_AFTER='-A INPUT -i wlan0 -j ACCEPT\n'), [])

    def test_only_a_final_accept_target_is_flagged(self):
        before = ('-A INPUT -m comment --comment "-j ACCEPT here" -j oem_in\n'
                  '-A INPUT -i wlan0 -j DROP\n'
                  '-A INPUT -j ACCEPTANCE\n'
                  '-A OTHER -j ACCEPT\n')
        self.assertEqual(self.report_lines('input_bypass', TEST_INPUT_BEFORE4=before), [])

    def test_no_hook_means_nothing_can_be_bypassed(self):
        before = '-A INPUT -i wlan0 -j ACCEPT\n'
        self.assertEqual(self.report_lines('input_bypass', TEST_NO_HOOKS=1, TEST_INPUT_BEFORE4=before,
                                           TEST_INPUT_BEFORE6=before), [])

    def test_too_many_earlier_accept_rules_refuses_a_complete_claim(self):
        rule = '-A INPUT -i wlan0 -j ACCEPT\n'
        self.assertEqual(len(self.report_lines('input_bypass', TEST_INPUT_BEFORE4=rule * 6)), 6)
        result = self.run_report(TEST_INPUT_BEFORE4=rule * 7)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('rules_report=READY', result.stdout)

    def test_overlong_earlier_accept_rule_refuses_a_complete_claim(self):
        result = self.run_report(TEST_INPUT_BEFORE4='-A INPUT -m comment --comment ' + 'x' * 200 + ' -j ACCEPT\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('rules_report=READY', result.stdout)

    def test_read_only_commands_only(self):
        self.assertEqual(self.run_report().returncode, 0)
        for line in self.calls.read_text().splitlines():
            self.assertIn(" -w -S ", line)
            self.assertNotIn(" -A ", line)
            self.assertNotIn(" -D ", line)

    def test_missing_family_is_never_marked_ready(self):
        result = self.run_report(TEST_IPV6_FAIL=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("rules_report=READY", result.stdout)

    def test_excess_rules_refuses_complete_claim(self):
        result = self.run_report(TEST_MANY_RULES=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("rules_report=READY", result.stdout)

    def test_unknown_input_policy_not_assumed(self):
        result = self.run_report(TEST_POLICY4="INVALID")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("rules_report=READY", result.stdout)

    def test_root_required(self):
        result = self.run_report(TEST_UID=2000)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("rules_report=READY", result.stdout)


if __name__ == "__main__":
    unittest.main()
