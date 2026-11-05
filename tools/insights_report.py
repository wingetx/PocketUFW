#!/usr/bin/env python3
"""Summarize bounded, marked NFLOG captures without retaining packet payloads.

This is an OFFLINE parser, not a capture launcher. It accepts only classic PCAP
DLT_NFLOG frames with the unique PocketUFW Insights prefix. A matching NFLOG
event is a sample from a diagnostic probe placed before a DROP rule; it is
NOT a complete firewall history or proof of an attack.
"""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import ipaddress
import json
import struct
import sys
from typing import BinaryIO

PCAP_ENDIAN = {
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">",
    b"\x4d\x3c\xb2\xa1": "<",
    b"\xa1\xb2\x3c\x4d": ">",
}
DLT_NFLOG = 239
ATTR_PAYLOAD = 9
ATTR_PREFIX = 10
MARKER = b"PUFW_INSIGHTS"
MAX_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 50000
MAX_FRAME = 262144
PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 50: "ESP", 58: "ICMPv6"}


class CaptureError(ValueError):
    """Capture is absent, corrupt, unsupported, or exceeds safety limits."""


def _ip_info(raw: bytes):
    if not raw:
        raise ValueError("empty IP payload")
    version = raw[0] >> 4
    if version == 4:
        if len(raw) < 20:
            raise ValueError("truncated IPv4 header")
        ihl = (raw[0] & 15) * 4
        length = struct.unpack_from("!H", raw, 2)[0]
        if ihl < 20 or len(raw) < ihl or length < ihl:
            raise ValueError("invalid IPv4 header")
        proto = raw[9]
        src = str(ipaddress.IPv4Address(raw[12:16]))
        dst = str(ipaddress.IPv4Address(raw[16:20]))
        fragmented = bool(struct.unpack_from("!H", raw, 6)[0] & 0x1FFF)
        offset = ihl
        family = 4
    elif version == 6:
        if len(raw) < 40:
            raise ValueError("truncated IPv6 header")
        proto = raw[6]
        length = 40 + struct.unpack_from("!H", raw, 4)[0]
        src = str(ipaddress.IPv6Address(raw[8:24]))
        dst = str(ipaddress.IPv6Address(raw[24:40]))
        offset = 40
        fragmented = False
        # Bounded extension walk; refuse to infer ports from unknown headers.
        for _ in range(8):
            if proto in (0, 43, 60):  # hop-by-hop, routing, destination
                if len(raw) < offset + 2:
                    raise ValueError("truncated IPv6 extension")
                nxt, ext_len = raw[offset], (raw[offset + 1] + 1) * 8
            elif proto == 44:  # IPv6 fragment
                if len(raw) < offset + 8:
                    raise ValueError("truncated IPv6 fragment")
                nxt, ext_len = raw[offset], 8
                fragmented = bool(struct.unpack_from("!H", raw, offset + 2)[0] & 0xFFF8)
            elif proto == 51:  # AH
                if len(raw) < offset + 2:
                    raise ValueError("truncated AH header")
                nxt, ext_len = raw[offset], (raw[offset + 1] + 2) * 4
            else:
                break
            if len(raw) < offset + ext_len:
                raise ValueError("truncated IPv6 extension body")
            offset += ext_len
            proto = nxt
        family = 6
    else:
        raise ValueError("not IPv4 or IPv6")

    port = None
    if proto in (6, 17) and not fragmented and len(raw) >= offset + 4:
        port = struct.unpack_from("!H", raw, offset + 2)[0]
    return (family, src, dst, PROTOCOLS.get(proto, str(proto)), port, length)


def _nflog_payload(record: bytes, endian: str):
    if len(record) < 4 or record[1] != 0:
        raise ValueError("invalid NFLOG header/version")
    # nfgenmsg.res_id uses network byte order, independent of PCAP byte order.
    if struct.unpack_from("!H", record, 2)[0] != 17:
        return None
    offset = 4
    marker = None
    payload = None
    while offset + 4 <= len(record):
        size, kind = struct.unpack_from(endian + "HH", record, offset)
        if size < 4 or offset + size > len(record):
            raise ValueError("invalid NFLOG attribute length")
        val = record[offset + 4:offset + size]
        if kind == ATTR_PREFIX:
            marker = val.split(b"\x00", 1)[0]
        elif kind == ATTR_PAYLOAD:
            payload = val
        offset += (size + 3) & ~3
    if offset != len(record):
        raise ValueError("truncated NFLOG attributes")
    if marker == MARKER:
        reason = "UNSPECIFIED"  # prior diagnostic captures
    elif marker and marker.startswith(MARKER + b":"):
        parts = marker.split(b":")
        if len(parts) != 3 or not parts[1].isdigit() or parts[2] not in (b"I", b"F"):
            return None
        reason = "INVALID" if parts[2] == b"I" else "FINAL"
    else:
        return None
    if payload is None:
        raise ValueError("marked NFLOG record without IP payload")
    return payload, reason


def summarize(stream: BinaryIO) -> dict:
    raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise CaptureError("capture too large (>16 MiB); use a shorter session")
    if len(raw) < 24 or raw[:4] not in PCAP_ENDIAN:
        raise CaptureError("not a complete classic PCAP file")
    endian = PCAP_ENDIAN[raw[:4]]
    major, minor, _tz, _sig, snaplen, link = struct.unpack_from(
        endian + "HHiiii", raw, 4
    )
    if (major, minor) != (2, 4) or link != DLT_NFLOG or not (1 <= snaplen <= MAX_FRAME):
        raise CaptureError("expected classic PCAP v2.4 with DLT_NFLOG (239)")
    offset = 24
    inspected = 0
    mismatched = 0
    malformed = 0
    groups = collections.defaultdict(lambda: [0, 0, 0])
    sources = collections.defaultdict(lambda: [0, 0])
    while offset < len(raw):
        if offset + 16 > len(raw):
            raise CaptureError("truncated PCAP packet header")
        timestamp, _fract, incl, orig = struct.unpack_from(endian + "IIII", raw, offset)
        offset += 16
        if incl > MAX_FRAME or incl > snaplen or orig < incl or offset + incl > len(raw):
            raise CaptureError("invalid or truncated PCAP packet")
        record = raw[offset:offset + incl]
        offset += incl
        inspected += 1
        if inspected > MAX_RECORDS:
            raise CaptureError("too many packet records; use a shorter capture")
        try:
            sample = _nflog_payload(record, endian)
            if sample is None:
                mismatched += 1
                continue
            ip, reason = sample
            fam, src, dst, proto, port, size = _ip_info(ip)
        except ValueError:
            malformed += 1
            continue
        key = (fam, src, dst, proto, port, reason)
        if key not in groups and len(groups) >= 4096:
            raise CaptureError("too many distinct flows; use a shorter capture")
        entry = groups[key]
        entry[0] += 1
        entry[1] += size
        entry[2] = max(entry[2], timestamp)
        sources[(fam, src)][0] += 1
        sources[(fam, src)][1] += size
    top_flows = []
    for (fam, src, dst, proto, port, reason), (count, size, last) in sorted(
        groups.items(), key=lambda x: (-x[1][0], -x[1][1], str(x[0]))
    ):
        top_flows.append({
            "family": fam, "source": src, "destination": dst,
            "protocol": proto, "destination_port": port, "drop_rule": reason,
            "sampled_packets": count, "sampled_ip_bytes": size,
            "last_seen_utc": dt.datetime.fromtimestamp(last, dt.timezone.utc).isoformat(),
        })
    top_sources = [
        {"family": fam, "source": src, "sampled_packets": cnt, "sampled_ip_bytes": size}
        for ((fam, src), (cnt, size)) in sorted(
            sources.items(), key=lambda x: (-x[1][0], -x[1][1], x[0])
        )
    ]
    return {
        "evidence": "marked NFLOG samples at a planned PocketUFW drop-probe",
        "complete_drop_history": False,
        "capture_packets_inspected": inspected,
        "samples_counted": sum(x[0] for x in groups.values()),
        "sampled_ip_bytes": sum(x[1] for x in groups.values()),
        "unrelated_packets": mismatched, "unreadable_packets": malformed,
        "top_sources": top_sources, "top_flows": top_flows,
    }


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("capture", nargs="?", default="-", help="NFLOG PCAP or - for stdin")
    cli.add_argument("--json", action="store_true", help="machine-readable report")
    cli.add_argument("--top", type=int, default=10, help="top entries (1..30)")
    args = cli.parse_args()
    if not 1 <= args.top <= 30:
        cli.error("--top must be between 1 and 30")
    try:
        if args.capture == "-":
            report = summarize(sys.stdin.buffer)
        else:
            with open(args.capture, "rb") as stream:
                report = summarize(stream)
    except (CaptureError, OSError) as exc:
        print(f"insights: {exc}", file=sys.stderr)
        return 2
    report["top_sources"] = report["top_sources"][:args.top]
    report["top_flows"] = report["top_flows"][:args.top]
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Insights NFLOG sample: {report['samples_counted']} candidate DROP packets,"
              f" {report['sampled_ip_bytes']} IP bytes")
        print(f"Not a full history; unrelated={report['unrelated_packets']}, "
              f"unreadable={report['unreadable_packets']}")
        for row in report["top_flows"]:
            port = row["destination_port"] if row["destination_port"] is not None else "-"
            print(f"{row['sampled_packets']:>6} {row['sampled_ip_bytes']:>10}B  "
                  f"IPv{row['family']} {row['protocol']} [{row['drop_rule']}] {row['source']} -> "
                  f"{row['destination']}:{port}  last={row['last_seen_utc']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
