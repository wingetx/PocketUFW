# Medium findings after the final audit of 78bea22

The original follow-up below was prepared on `feature/tunnel-inbound-filter`.
The Beta 7 presentation follow-up is isolated on `feature/beta7-tide-ui`; its
coverage contract is recorded under M2. No signing or deployment is authorized
by either follow-up. Earlier acceptance evidence and unrelated work are preserved.

## M1: Wi-Fi 464XLAT

The physical hook list now includes `v4-wlan+` after `wlan+`, `rmnet+` and
`v4-rmnet+`, in both families. Installation, exact-signature verification and
cleanup use the same list. The bridge and tunnel inventory classify `v4-wlan*`
as physical coverage; the detailed report accommodates four physical hooks plus
the existing maximum of eight tunnel hooks. Tunnel policy and Android/OEM rules
are unchanged.

An older three-hook installation is deliberately DEGRADED under the new verifier.
It remains removable with exact owned signatures. Moving to the four-hook policy
requires an explicit removal and enable; inspection never silently rebuilds live
rules. This transition temporarily removes protection and should be planned before
deploying the next beta. Existing boot snapshots also need to be refreshed through
the normal enable/restore flow; installing an APK alone does not migrate them.

Four new regressions failed before the fix. Focused validation covered 96 Python
cases, including a real Linux namespace packet test on `v4-wlan0`, exact OEM-rule
preservation, missing IPv6 hooks, legacy cleanup and maximum tunnel-hook reporting.
Two old report assertions were updated for the fourth hook and passed their
targeted rerun. This proves hook matching and packet filtering on that interface
name, not a real Android 464XLAT translation path; that is a targeted device check.

## M2: Unknown coverage must stay unknown

Tide requires both a complete kernel report and a successful live interface
inventory before displaying **Filtering active**, and neither may report a gap.
In the Beta 7 follow-up to the audit of `e764a2e`, the green verified-rules headline
remains independent of traffic coverage. Earlier direct INPUT accepts or uncovered
non-carrier interfaces produce **Coverage limited** and one concise amber notice
outside the Coverage details expander. Missing or malformed evidence produces
**Coverage unknown** with a visible instruction to recheck status. When both apply,
the same notice names the known limits and asks for a recheck of unknown coverage.

Positively identified carrier-IMS-only exclusions remain neutral, with **Carrier
calling excluded** and the names and explanation available in Coverage details.
An interface name alone is not evidence, and Android VPN ownership overrides IMS
attribution. All other limitations, including PINNED's trust boundary, remain in
the expander. Stale PINNED authorization and verification/recovery warnings remain
visible when it is collapsed. No state claims universal coverage or end-to-end
enforcement; an unavailable diagnostic report does not mean installed rules have
disappeared.

The report protocol includes counts for every section in both families, including
empty sections. Android requires consecutive numbered rows matching those counts,
bounded row lengths and counts, correct chain names, unique report keys and a
final READY marker. Failure of either existing `ip` inventory command, malformed
records, or interfaces appearing between the two reads makes inventory coverage
unknown. This adds no root sessions or ownership probes.

Root output is drained while the process runs, under its original monotonic
deadline. At most 64 KiB is retained; the bounded rule report is under 24 KiB.
Further bytes are discarded while draining so the producer can finish, but the
entire response is rejected as incomplete and cannot authorize ACTIVE or operation
success. A read failure is likewise rejected. Timeout and interruption clean up
the local process and streams; an exited parent does not wait for descendants to
close stdout. The process may have already changed rules before an error, so the
user must recheck live state. No timeout increase, new service or polling task was
introduced.

Targeted Android validation should inspect with PINNED filtering and enough hooks
and earlier accepts to exceed the old 8 KiB response limit, then confirm both
families and every bypass remain visible. Also force a missing/incomplete report
and verify coverage becomes unknown while independently verified rules remain
active. Confirm inspection timing remains within the existing 32-second limit.

These fixes do not expand the inspection into Android/OEM child-chain verdicts,
forwarded traffic or future interface changes between manual checks. Pinned
tailnet trust still permits packets injected into pinned destinations through
another `tun*` interface; ingress ownership is not continuously authenticated.

### Beta 7 presentation regressions

Parsed bridge output with uncovered `eth0,usb0` and an earlier
`-A INPUT -i wlan0 -j ACCEPT` must retain a green verified-rules headline while
showing **Coverage limited**, one amber coverage notice, and no **Filtering active**
claim. The notice remains visible with Coverage details collapsed. Independent
bypass-only and uncovered-interface cases, unknown evidence, and the carrier-only
exception are covered as well.

Parsed DEGRADED output with `physical_state=ACTIVE` and `tunnel_filter=DEGRADED`
must identify verified physical rules and degraded tunnel protection separately.
The generic whole-firewall failure description is replaced in that case; specific
diagnostics, including WireGuard conflicts and timeouts, retain their guidance.
The Python source contract follows the actual uncertainty guard, checking both
the title and on/off action paths. Compose regressions also exercise uncertain
cached ACTIVE/INACTIVE states and missing root evidence. These changes affect
presentation, documentation and tests only, not the engine or bridge protocol.

Local validation: 81 targeted JVM/Compose tests and 18 Python contracts passed;
the final coverage/render fixture refinements passed a 21-test rerun. Debug and
release Kotlin compiled. Light/dark and 200% text host renders were inspected.
An in-memory contract check accepted an uncertainty-guard rename and rejected
four mutations that removed verification or on/off safeguards. No device tests,
signing, installation, push, merge or publication were performed.

## Original follow-up verification

- 280 focused Python checks cover engine verification and exact cleanup, bridge
  reporting, report bounds, security regressions, probe budgets and Android mksh
  execution. Three legacy assertions still expected three hooks; after updating
  them for four hooks, their targeted rerun passed. The earlier M1 run additionally
  covered the actual Linux `v4-wlan0` packet path and all tunnel-filter regressions.
- All 288 Android JVM tests passed after targeted reruns of three adjusted UI
  fixtures. New cases cover missing, malformed and duplicate report fields, unknown
  interface evidence, known partial coverage, a complete report above 8 KiB,
  64 KiB boundaries, overflow draining, interruption, read failure and deadlines.
- Android lint: zero errors, three existing warnings and two informational notices
  in unchanged files. Instrumented-test Kotlin sources compile; device tests were
  not run. No APK assembly or signing task ran.
- The existing timing model remains 9.74 seconds for pinned dashboard inspection;
  this is a host-side model, not a new phone measurement.
- All 702 preserved evidence/build/design files match their original hashes and
  modification times, including both untracked uninstall design documents.

Logs and isolated test outputs are in the ignored
`android/build/medium-fixes-20261109T053650Z/` directory. The targeted rerun logs
resolve the fixture failures recorded in the first full-run logs.
