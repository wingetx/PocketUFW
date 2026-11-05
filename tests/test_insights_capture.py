"""Strict offline simulation of on-demand NFLOG sessions.

Mocks NEVER invoke real iptables, tcpdump, or a network namespace. Each test
copies the capture script into a temporary directory with isolated mock state.
"""
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import insights_report

IPTABLES_MOCK = r'''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
fam=Path(sys.argv[0]).name
p=Path(os.environ["TEST_STATE"])/f"{fam}.json"
rules=json.loads(p.read_text())
args=sys.argv[1:]
if not args or args[0]!="-w":sys.exit(80)
args=args[1:]
if len(args)<2 or args[1]!="POCKETUFW_IN":sys.exit(81)
op=args[0]
if op=="-I":
    if len(args)<4:sys.exit(82)
    pos=int(args[2])
    if os.environ.get("TEST_FAIL_INSERT")==f"{fam}:{pos}":sys.exit(83)
    spec=args[3:]
    if not 1<=pos<=len(rules)+1:sys.exit(84)
    rules.insert(pos-1,spec)
    p.write_text(json.dumps(rules))
elif op in ("-C","-D"):
    spec=args[2:]
    if spec not in rules:sys.exit(1)
    if op=="-D":
        tag=spec[spec.index("--nflog-prefix")+1].rsplit(":",1)[-1]
        if os.environ.get("TEST_FAIL_REMOVE")==f"{fam}:{tag}":sys.exit(85)
        rules.remove(spec)
        p.write_text(json.dumps(rules))
else:sys.exit(86)
'''

TIMEOUT_MOCK = r'''#!/bin/sh
[ "$1" = -s ] && [ "$2" = INT ] || exit 80
[ "$3" = -k ] && [ "$4" = 2 ] || exit 81
[ "$5" = 10 ] || exit 82
shift 5
"$@" || exit $?
[ "${TEST_TIMED:-0}" = 0 ] || exit 124
'''

TCPDUMP_MOCK = r'''#!/usr/bin/env python3
import ipaddress,json,os,struct,sys
from pathlib import Path
args=sys.argv[1:]
if args != ["-i","nflog:17","-nn","-s","512","-U","-w","-","-c","1024"]:
    sys.exit(80)
state=Path(os.environ["TEST_STATE"])
for fam in ("iptables","ip6tables"):
    rules=json.loads((state/f"{fam}.json").read_text())
    if len(rules)!=10:sys.exit(81)
    targets=[r[r.index("-j")+1] for r in rules]
    if targets != ["ACCEPT","ACCEPT","NFLOG","DROP","ACCEPT",
                   "ACCEPT","ACCEPT","POCKETUFW_TS","NFLOG","DROP"]:
        sys.exit(82)
    if "--ctstate" not in rules[2] or "INVALID" not in rules[2]:sys.exit(83)
    if "--ctstate" in rules[8]:sys.exit(84)
    if rules[2][rules[2].index("--nflog-size")+1] != ("24" if fam=="iptables" else "44"):
        sys.exit(85)
if os.environ.get("TEST_DUMP_ERROR")=="1":sys.exit(44)
if os.environ.get("TEST_MUTATE_DURING_CAPTURE")=="1":
    altered=json.loads((state/"iptables.json").read_text())
    altered.insert(2, ["-j", "ACCEPT"])
    (state/"iptables.json").write_text(json.dumps(altered))
rules=json.loads((state/"iptables.json").read_text())
prefix=rules[8][rules[8].index("--nflog-prefix")+1]
ip=struct.pack("!BBHHHBBH4s4s",0x45,0,120,1,0,64,17,0,
               ipaddress.IPv4Address("169.254.100.1").packed,
               ipaddress.IPv4Address("10.0.0.147").packed)+struct.pack("!HH",60000,1900)
def attr(t,data):
    val=struct.pack("<HH",len(data)+4,t)+data
    return val+b"\0"*((-len(val))%4)
# Simulate the non-payload NFLOG attributes which can make even a tiny
# copied IP header exceed 128 bytes of PCAP frame data.
record=(bytes((2,0,0,17))+attr(1,b"m"*108)
        +attr(10,prefix.encode()+b"\0")+attr(9,ip))
assert len(record)>128 and len(record)<512
out=b"\xd4\xc3\xb2\xa1"+struct.pack("<HHiiII",2,4,0,0,65535,239)
out+=struct.pack("<IIII",1790000000,0,len(record),len(record))+record
sys.stdout.buffer.write(out)
'''


class InsightsCaptureTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="pufw-insights-")
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.bin = self.base / "bin"
        self.bin.mkdir()
        self.state = self.base / "mockstate"
        self.state.mkdir()
        self.engine = self.base / "pocketufw"
        self.engine.write_text("""#!/bin/sh
[ "$1" = verify ] || exit 2
[ "${TEST_VERIFIED:-1}" = 1 ] || { echo DEGRADED; exit 4; }
python3 - "$TEST_STATE" <<'CHECK'
import json, pathlib, sys
root=pathlib.Path(sys.argv[1])
expected=json.loads((root/'reference.json').read_text())
for family in ('iptables', 'ip6tables'):
    current=json.loads((root/(family+'.json')).read_text())
    if current != expected:
        print('DEGRADED')
        sys.exit(4)
print('ACTIVE')
CHECK
""")
        self.capture = self.base / "insights-capture"
        shutil.copy2(ROOT / "insights-capture", self.capture)
        baseline = [
            ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            ["-p", "icmp", "-j", "ACCEPT"],
            ["-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP"],
            ["-p", "udp", "--sport", "67", "--dport", "68", "-j", "ACCEPT"],
            ["-p", "udp", "--dport", "5353", "-j", "ACCEPT"],
            ["-p", "esp", "-j", "ACCEPT"],
            ["-j", "POCKETUFW_TS"],
            ["-j", "DROP"],
        ]
        self.baseline = baseline
        (self.state / "reference.json").write_text(json.dumps(baseline))
        for fam in ("iptables", "ip6tables"):
            (self.state / f"{fam}.json").write_text(json.dumps(baseline))
            self.make_mock(fam, IPTABLES_MOCK)
        self.make_mock("timeout", TIMEOUT_MOCK)
        self.make_mock("tcpdump", TCPDUMP_MOCK)
        self.make_mock("id", '#!/bin/sh\n[ "$1" = "-u" ] || exit 2\n'
                             'echo "${TEST_UID:-0}"\n')
        self.env = {**os.environ, "PATH": str(self.bin) + ":" + os.environ["PATH"],
                    "TEST_STATE": str(self.state), "TEST_VERIFIED": "1",
                    "TEST_UID": "0", "TEST_FAIL_INSERT": "",
                    "TEST_FAIL_REMOVE": "", "TEST_DUMP_ERROR": "0",
                    "TEST_TIMED": "0"}

    def make_mock(self, name, content):
        p = self.bin / name
        p.write_text(content)
        p.chmod(0o755)

    def run_capture(self, action="capture", **kwargs):
        return subprocess.run(
            ["/bin/sh", str(self.capture), action],
            capture_output=True, timeout=8,
            env={**self.env, **{k: str(v) for k, v in kwargs.items()}},
        )

    def rules(self, family):
        return json.loads((self.state / f"{family}.json").read_text())

    def assert_clean(self):
        self.assertEqual(self.rules("iptables"), self.baseline)
        self.assertEqual(self.rules("ip6tables"), self.baseline)
        self.assertFalse((self.base / ".insights-capture.lock").exists())

    def test_preflight_is_read_only(self):
        p = self.run_capture("preflight")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(b"insights=READY", p.stdout)
        self.assertIn(b"live_firewall_modified=no", p.stdout)
        self.assert_clean()

    def test_capture_sees_both_drop_points_and_cleans_up(self):
        r = self.run_capture()
        self.assertEqual(r.returncode, 0, r.stderr)
        report = insights_report.summarize(io.BytesIO(r.stdout))
        self.assertEqual(report["samples_counted"], 1)
        self.assertEqual(report["sampled_ip_bytes"], 120)
        self.assertEqual(report["top_flows"][0]["source"], "169.254.100.1")
        self.assertEqual(report["top_flows"][0]["destination_port"], 1900)
        self.assertEqual(report["top_flows"][0]["drop_rule"], "FINAL")
        self.assert_clean()

    def test_expected_timeout_still_cleans_up(self):
        r = self.run_capture(TEST_TIMED=1)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(insights_report.summarize(io.BytesIO(r.stdout))["samples_counted"], 1)
        self.assert_clean()

    def test_insertion_failure_removes_earlier_probes(self):
        for fail in ("iptables:3", "ip6tables:3", "iptables:9", "ip6tables:9"):
            with self.subTest(fail=fail):
                r = self.run_capture(TEST_FAIL_INSERT=fail)
                self.assertNotEqual(r.returncode, 0)
                self.assert_clean()

    def test_concurrent_kernel_edit_fails_closed_and_preserves_external_rule(self):
        result = self.run_capture(TEST_MUTATE_DURING_CAPTURE=1)
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertIn(b"firewall changed during capture", result.stderr)
        self.assertIn(b"discard sample", result.stderr)
        self.assertEqual(len(self.rules("iptables")), 9)
        self.assertIn(["-j", "ACCEPT"], self.rules("iptables"))
        self.assertEqual(self.rules("ip6tables"), self.baseline)
        self.assertTrue((self.base / ".insights-capture.lock").exists())
        self.assertFalse(any("NFLOG" in spec for row in self.rules("iptables") for spec in row))

    def test_capture_failure_keeps_original_firewall_rules(self):
        r = self.run_capture(TEST_DUMP_ERROR=1)
        self.assertEqual(r.returncode, 9)
        self.assertIn(b"capture failed", r.stderr)
        self.assert_clean()

    def test_failed_cleanup_retains_warning_and_lock(self):
        r = self.run_capture(TEST_FAIL_REMOVE="ip6tables:F")
        self.assertEqual(r.returncode, 7)
        self.assertIn(b"MANUAL INSPECTION REQUIRED", r.stderr)
        self.assertTrue((self.base / ".insights-capture.lock").exists())
        self.assertEqual(len(self.rules("ip6tables")), 9)
        self.assertEqual(self.rules("iptables"), self.baseline)

    def test_unverified_firewall_refuses_to_add_rules(self):
        r = self.run_capture(TEST_VERIFIED=0)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(b"not independently verified ACTIVE", r.stderr)
        self.assert_clean()

    def test_unprivileged_call_refused(self):
        r = self.run_capture(TEST_UID=2000)
        self.assertEqual(r.returncode, 3)
        self.assert_clean()

    def test_lock_refuses_concurrent_capture(self):
        lock = self.base / ".insights-capture.lock"
        lock.mkdir()
        r = self.run_capture()
        self.assertEqual(r.returncode, 6)
        self.assertIn(b"capture lock", r.stderr)
        self.assertEqual(self.rules("iptables"), self.baseline)
        self.assertEqual(self.rules("ip6tables"), self.baseline)

    def test_capture_never_deletes_unrelated_preexisting_rules(self):
        before = self.rules("iptables")
        before.append(["-j", "LOG", "--log-prefix", "OTHER"])
        (self.state / "iptables.json").write_text(json.dumps(before))
        r = self.run_capture(TEST_VERIFIED=0)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.rules("iptables"), before)


if __name__ == "__main__":
    unittest.main()
