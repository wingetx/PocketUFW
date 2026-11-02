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
    echo '-A INPUT -i wlan+ -m comment --comment PocketUFW -j POCKETUFW_IN'
    echo '-A INPUT -i rmnet+ -m comment --comment PocketUFW -j POCKETUFW_IN'
    echo '-A INPUT -i v4-rmnet+ -m comment --comment PocketUFW -j POCKETUFW_IN'
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
