# Medium findings after the final audit of 78bea22

These changes remain local on `feature/tunnel-inbound-filter`. No APK is built,
signed or deployed for this follow-up. Earlier acceptance evidence and the two
untracked uninstall design documents are preserved.

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

Tide now requires both a complete kernel report and a successful live interface
inventory before displaying its normal matched-policy coverage wording. Missing
or malformed evidence shows an amber **coverage unknown** state. Known uncovered
interfaces or earlier direct INPUT accepts still show partial coverage. The
independent ruleset verification is preserved: an unavailable diagnostic report
does not mean installed physical or tunnel rules have disappeared.

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
another eligible tunnel; ingress ownership is not continuously authenticated.

## Local verification

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
