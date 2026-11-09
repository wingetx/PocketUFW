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
deploying the next beta.

Four new regressions failed before the fix. Focused validation covered 96 Python
cases, including a real Linux namespace packet test on `v4-wlan0`, exact OEM-rule
preservation, missing IPv6 hooks, legacy cleanup and maximum tunnel-hook reporting.
Two old report assertions were updated for the fourth hook and passed their
targeted rerun. This proves hook matching and packet filtering on that interface
name, not a real Android 464XLAT translation path; that is a targeted device check.
