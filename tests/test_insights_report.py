"""Offline tests for Insights NFLOG metadata parsing; no root/network required."""
import io
import ipaddress
import json
import os
import pathlib
import struct
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import insights_report as insights


def ip4(src="169.254.100.1", dst="10.0.0.147", dport=1900,
        pkt_size=1450, frag=False):
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, pkt_size, 1, 1 if frag else 0,
        64, 17, 0, ipaddress.IPv4Address(src).packed,
        ipaddress.IPv4Address(dst).packed
    )
    return header + (b"" if frag else struct.pack("!HHHH", 56789, dport, 8, 0))


def ip6(src="2001:db8::2", dst="2001:db8::1", dport=443, payload_len=8):
    return (struct.pack("!IHBB16s16s", 6 << 28, payload_len, 17, 64,
                        ipaddress.IPv6Address(src).packed,
                        ipaddress.IPv6Address(dst).packed)
            + struct.pack("!HHHH", 24000, dport, 8, 0))


def attribute(endian, kind, data):
    unpadded = struct.pack(endian + "HH", 4 + len(data), kind) + data
    return unpadded + b"\0" * ((-len(unpadded)) % 4)


def packet(ip, endian="<", marker=insights.MARKER, bad_attr=None):
    fam = 2 if (ip[0] >> 4) == 4 else 10
    record = bytes((fam, 0, 0, 17))
    if bad_attr is not None:
        return record + bad_attr
    return record + attribute(endian, 10, marker + b"\0") + attribute(endian, 9, ip)


def capture(records, endian="<", link=239, snaplen=65535):
    magic = b"\xd4\xc3\xb2\xa1" if endian == "<" else b"\xa1\xb2\xc3\xd4"
    head = magic + struct.pack(endian + "HHiiII", 2, 4, 0, 0, snaplen, link)
    for i, record in enumerate(records):
        head += struct.pack(endian + "IIII", 1790000000 + i, 0,
                            len(record), len(record)) + record
    return head


class InsightsReportTests(unittest.TestCase):
    def summary(self, records, endian="<"):
        return insights.summarize(io.BytesIO(capture(records, endian=endian)))

    def test_empty_capture_is_no_evidence_not_an_attack_claim(self):
        result = self.summary([])
        self.assertEqual(result["samples_counted"], 0)
        self.assertFalse(result["complete_drop_history"])
        self.assertEqual(result["top_sources"], [])

    def test_group_ipv4_by_sender_and_destination_port(self):
        events = [packet(ip4(dport=1900))] * 3 + [packet(ip4(dport=22))]
        r = self.summary(events)
        self.assertEqual(r["samples_counted"], 4)
        self.assertEqual(r["sampled_ip_bytes"], 5800)
        self.assertEqual(r["top_sources"][0]["source"], "169.254.100.1")
        self.assertEqual(r["top_flows"][0]["destination_port"], 1900)
        self.assertEqual(r["top_flows"][0]["sampled_packets"], 3)
        self.assertIn("last_seen_utc", r["top_flows"][0])

    def test_ipv6_udp(self):
        r = self.summary([packet(ip6())])
        self.assertEqual(r["top_flows"][0]["family"], 6)
        self.assertEqual(r["top_flows"][0]["protocol"], "UDP")
        self.assertEqual(r["top_flows"][0]["destination_port"], 443)
        self.assertEqual(r["sampled_ip_bytes"], 48)

    def test_fragment_without_ports_does_not_invent_ports(self):
        r = self.summary([packet(ip4(frag=True))])
        self.assertEqual(r["samples_counted"], 1)
        self.assertIsNone(r["top_flows"][0]["destination_port"])

    def test_reject_other_nflog_prefix(self):
        r = self.summary([packet(ip4(), marker=b"ANOTHER_FIREWALL")])
        self.assertEqual(r["samples_counted"], 0)
        self.assertEqual(r["unrelated_packets"], 1)

    def test_corrupt_tlv_is_reported_not_counted(self):
        r = self.summary([packet(ip4(), bad_attr=struct.pack("<HH", 800, 9) + b"\0")])
        self.assertEqual(r["samples_counted"], 0)
        self.assertEqual(r["unreadable_packets"], 1)

    def test_missing_payload_is_reported(self):
        data = b"\x02\0\0\0" + attribute("<", 10, insights.MARKER + b"\0")
        r = self.summary([data])
        self.assertEqual(r["unreadable_packets"], 1)

    def test_big_endian_capture(self):
        r = self.summary([packet(ip4(), endian=">")], endian=">")
        self.assertEqual(r["samples_counted"], 1)
        self.assertEqual(r["top_flows"][0]["destination"], "10.0.0.147")

    def test_reject_raw_pcap_not_actual_nf_log_evidence(self):
        with self.assertRaisesRegex(insights.CaptureError, "DLT_NFLOG"):
            insights.summarize(io.BytesIO(capture([], link=101)))

    def test_reject_truncated_capture_and_giant_frames(self):
        with self.assertRaisesRegex(insights.CaptureError, "truncated"):
            insights.summarize(io.BytesIO(capture([packet(ip4())])[:-1]))
        with self.assertRaisesRegex(insights.CaptureError, "invalid or truncated"):
            insights.summarize(io.BytesIO(capture([packet(ip4())], snaplen=10)))

    def test_reject_non_pcap(self):
        with self.assertRaises(insights.CaptureError):
            insights.summarize(io.BytesIO(b"not a pcap"))

    def test_ignore_unknown_protocol_without_fabricating_port(self):
        raw = bytearray(ip4())
        raw[9] = 253
        r = self.summary([packet(bytes(raw))])
        self.assertEqual(r["samples_counted"], 1)
        self.assertEqual(r["top_flows"][0]["protocol"], "253")
        self.assertIsNone(r["top_flows"][0]["destination_port"])

    def test_portless_fragment_and_normal_flow_tie_can_sort(self):
        events = [packet(ip4(frag=True)), packet(ip4())]
        r = self.summary(events)
        self.assertEqual(r["samples_counted"], 2)
        self.assertEqual(len(r["top_flows"]), 2)
        self.assertEqual({v["destination_port"] for v in r["top_flows"]}, {None, 1900})

    def test_cli_json_on_stdin(self):
        sample = capture([packet(ip4())])
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        run = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "insights_report.py"), "--json"],
            input=sample, capture_output=True, timeout=10, env=env
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        parsed = json.loads(run.stdout)
        self.assertEqual(parsed["samples_counted"], 1)
        self.assertFalse(parsed["complete_drop_history"])

    def test_cli_rejects_unsupported_link_type(self):
        run = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "insights_report.py")],
            input=capture([], link=101), capture_output=True, timeout=10
        )
        self.assertEqual(run.returncode, 2)
        self.assertIn(b"DLT_NFLOG", run.stderr)


if __name__ == "__main__":
    unittest.main()
