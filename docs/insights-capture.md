# On-demand dropped-packet Insights (development branch)

**Status:** isolated prototype on feature/drop-insights. **Not shipped**, not installed on Frankenpixel, not integrated into Android UI, and not enabled in the boot path. This document is an engineering handoff, not permission to activate it on a real device.

## Purpose

Identify **which packets matched PocketUFW's own two DROP rules**, without inventing per-app attribution, attack labels, a connection history, or measurements outside hooked interfaces. Use this evidence to investigate bursts like the unexplained drop count Jay observed before starting Tailscale and kernel WireGuard. Past bursts **cannot** be reconstructed from current cumulative counters.

The tools/insights_report.py script reads classic PCAP (NFLOG link type 239, group 17), accepts only PUFW_INSIGHTS diagnostic tags, and produces top-source and top-flow summaries: IP family, source/destination addresses, protocol, destination port if present, DROP location (invalid or final), sampled packet count, sampled IP-byte count, and last-seen timestamp.

The report says **sample**, never "all attacks blocked." A count represents only the duration and scope of the diagnostic capture. Packet payloads are not stored in the JSON report.

## Prototype capture contract

The insights-capture preflight action is read-only. It requires root, relevant tools, an unlocked private engine directory, no prior capture lock, and an independently verified ACTIVE firewall.

The insights-capture capture action is a privileged developer-only action:

1. Refuse degraded/unknown firewalls or stale session locks. Use an atomic private directory lock.
2. Add exactly four NFLOG probes using iptables/ip6tables -w -I:
   - Just before each family's INVALID DROP (position 3).
   - Just before each family's final DROP (position 9 after the first probe).
3. Check for the exact installed session-tagged rules, with no ACCEPT, DROP, or NFQUEUE verdict changes.
4. Capture **at most 10 seconds or 1,024 NFLOG packets** using timeout and tcpdump -i nflog:17. Emit PCAP only on stdout; messages only on stderr. The caller owns any files it chooses to create.
5. Remove only the precise per-process diagnostic rules, in reverse insertion order. Do not flush, reset counters, change VPN exceptions, or modify Android/OEM rules. If removal fails, warn loudly, fail, and **keep the lock**.

Netfilter NFLOG is a nonterminal target. **Actual DROP remains the next intended verdict.** The diagnostic has no persistent service or scheduled monitoring.

The maximum copied packet-header bytes are **24 for IPv4 and 44 for IPv6**, generally sufficient for IP addresses, protocol and destination port. The tcpdump snaplen is 512 bytes to retain **NFLOG's own netlink metadata** alongside that limited header; it does not increase the packet bytes copied by the kernel. Unusual IP protocols may still expose a few payload bytes; treat a raw PCAP as potentially sensitive. No raw capture is committed, sent over the network, or retained by the parser itself. The session prefix selects diagnostic events, **not cryptographic proof** of authenticity.

Usage for **offline test fixtures only**, not a suggestion to run live:

    python3 -m unittest tests.test_insights_capture tests.test_insights_report
    python3 tools/insights_report.py --json < mock-nflog.pcap

## Important blockers before Android integration

- **Verifier conflict:** Current pocketufw verify requires exactly eight rules per family and reports **DEGRADED** while temporary NFLOG rules are installed. Do not ship the runner into the app unchanged. Coordinate a narrowly scoped, verifiable "diagnostic capture active" state with the audited engine, including an unambiguous cancel path.
- **Recovery:** SIGKILL, a reboot, or power loss cannot run shell traps; unattended use is forbidden. A stale probe may cause verify to fail until manually examined and removed. Need guarded recovery that never deletes other owners' rules, and serialization with app enable/disable/reset/VPN-refresh operations.
- **Collector availability:** tcpdump was present on Jay's rooted Pixel 9a during read-only preflight, but it is **not a portable Android dependency**. Production implementation will need a bundled or native NFLOG collector, scoped capability checks, and privacy-preserving metadata parsing on device.
- **Concurrent changes:** After cleaning up probes, the runner independently re-verifies the original strict policy. If another process rewrites the rules during capture, the sample is rejected, the unexpected rule is not modified, and the session lock remains for inspection. Integrating with the app still requires real serialization to prevent mid-capture policy changes.
- **Live safety:** Test ordering, byte-counter preservation and cleanup on a spare test device before allowing diagnostic activation on Frankenpixel. Keep app UI in an explicit "diagnostic" state for the entire run, and show failure if cleanup cannot be confirmed.
- **No fabricated history:** There is no durable time-series in Beta 4. Insights must distinguish an *on-demand sample* from kernel counters, which can reset after reboot, rebuild, or command invocation.

The existing Android UI remains unchanged on this branch. Another engineer is addressing the audit defects on a separate branch and a third is exploring an independent UI. **Do not merge their files by copying directories**. Reconcile via Git after reviewing the branch contracts.

## Offline validation

The fake binaries in tests/test_insights_capture.py verify exact insertion positions, both families, timeout completion, malformed/rejected states, rollback after each possible insertion failure, cleanup failure with retained lock, and identity of the parsed report. Tests do not require root and **never access host iptables**.

The real Pixel was checked **read-only** for NFLOG support, tcpdump NFLOG listener support, timeout options and owned DROP counters. No live probes were installed during this development step.
