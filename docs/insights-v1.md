# Insights v1

Current candidate: **0.1.0-beta6 / code 27**. See the [Beta 6 release notes and
verification](releases/0.1.0-beta6.md) for current build results and limitations.

Insights is a user-initiated, local explanation of **sampled DROP matches**.
Historical counters live on Activity; Insights contains only sampling and its
explanations. A ten-second
sample cannot attribute earlier drops, estimate a historical coverage percentage,
identify an application or router vendor, or establish malicious intent.

Counter measurements and refresh/reset behavior, physical policy, PINNED and
DENY-ONLY policies are unchanged. Activity now shows physical IPv4/IPv6 replies
directly, like tunnel replies; the redundant Statistics dropdown is removed. No ACCEPT exception, boot restoration change,
background service, notification, wake lock, network permission, telemetry, or
capture timer is added. The only timer belongs to a requested sample.

## Using it

Open **Insights**, then **Sample dropped traffic** while protection is verified
ACTIVE. Sampling ends after ten seconds from the start of probe installation or
256 received records, whichever comes first. Setup and cleanup add wall time.
The sample states whether tunnel rules were sampled and reports physical/tunnel,
IPv4/IPv6, final/invalid-state matches,
protocol frequencies, the ten most frequent source/protocol groups, and possible
SSDP, mDNS, LLMNR, WS-Discovery and NetBIOS categories.

Categories use observed UDP source/destination ports, with separate observations
and explanations. Ports are clues, not protocol validation. Accepted replies and
permitted discovery packets are excluded because only actual DROP locations are
instrumented. Missing ports, fragments and IPv6 extension headers remain
unclassified. A zero sample means no readable matches were collected in this
window, not that earlier drops did not occur.

**Stop sample**, app backgrounding and Activity disposal close the helper's input
pipe and request cleanup. The app waits for cleanup rather than forcibly killing
the collector. Results live only in the current screen's memory; **Clear sample**
or destroying the Activity discards them. There is no export, disk cache, packet
file, DNS lookup or logcat packet logging.

## Native boundary

`android/app/src/main/cpp/insights.cpp` builds a small PIE executable, packaged as
`libpufw_insights.so` in the APK's extracted native-library directory. It is
executed through the existing root capability, never loaded into the app process.
Supported APK ABIs: arm64-v8a, armeabi-v7a and x86_64. NDK 27.2.12479018 and CMake
3.22.1 are pinned; C++ support is statically linked, with 16 KiB ELF alignment.
There is no Termux, Python, tcpdump, libpcap or libnetfilter_log dependency.

The app passes only `capture` or `recover` plus its private staged engine path.
The helper has no arbitrary command, rule, interface, duration, group or output
path interface. Its subprocesses use fixed argv commands, not generated shell
text. Production backends are `/system/bin/iptables`, `ip6tables`, their matching
`-save` tools, and `/system/bin/sh` for the APK engine's fixed `verify` command.
Environment overrides are compiled in only for the host test executable.

The helper follows the safety principles of the standalone `pufw-inspect`
development tool:

1. Hold the existing lifecycle lock, then obtain the snapshot lock. Both are
   nonblocking exclusive `flock` locks; unsafe symlink, owner, link-count or file
   types and lock failures refuse sampling. Never unlink a lock inode.
2. Detect diagnostic residue and independently require engine `ACTIVE` before
   instrumentation. Read bounded original filter-table snapshots for both IP
   families; accept only the known physical and optional tunnel DROP shapes.
3. Reject group 17 use in all loaded tables. Bind/configure the NFLOG socket and
   require kernel acknowledgements **before** inserting anything. Never issue
   PF_UNBIND or displace an existing group listener.
4. Insert a nonterminating NFLOG match immediately before each original INVALID
   and final DROP, in reverse order. Keep original DROP rules and counters intact.
   Check exact adjacency, unique session membership and the entire stripped
   filter ruleset against the original snapshot. Snapshots mask only the
   remaining-bytes value of Android's `quota2` rules (netd's `bw_costly_*` and
   `bw_global_alert`), which counts down with traffic; on a Pixel 9a it changed
   within a single sample and made every comparison fail. Rule structure, names
   and targets are still compared.
5. Accept only kernel netlink messages with this session's exact tag, IP family,
   group and INPUT hook. Family is part of attribution even when tags match
   across IPv4/IPv6. Keep at most 256 decoded metadata records.
6. Close NFLOG before removing probes. Validate every reserved rule's complete
   signature before deleting any, then delete by full rule specification.
   Verify no reserved probes remain and compare both filter tables with the original
   snapshots. Release the snapshot lock and independently require engine ACTIVE
   again, even if that comparison failed and the sample will be withheld. Only
   matching tables and successful verification permit the terminated metadata protocol.
7. On any installation/collection failure, perform the same cleanup and withhold
   the sample. A cleanup failure remains an error with an explicit recovery
   instruction. If every probe was removed but other rules changed meanwhile, or
   ACTIVE cannot be re-verified, the sample is withheld with that reason and no
   recovery instruction, because recovery would not help. Recovery's success
   message says no probes remain, not that any were removed, because recovery
   also succeeds when nothing was left behind. Never disable, rebuild, flush, zero
   or otherwise repair firewall policy as a capture error response.

The Android client serializes sampling with existing root operations. The helper
also holds both engine locks so app, CLI, boot and tile writers cannot interleave.
The engine verifier remains strict: external readers that bypass/time out waiting
for locks can see DEGRADED during instrumentation. Other root firewall managers
are outside these locks; concurrent changes cause verification failure and
withhold the report rather than being overwritten.

## Bounds and privacy

- Collection deadline uses `CLOCK_BOOTTIME`, including suspend. The deadline is
  checked between operations; a suspended or descheduled process cleans up when
  it can run again. No wake lock keeps the phone awake.
- At most 256 received records are processed, including excluded/unreadable
  records. A 16 KiB receive buffer, requested 64 KiB socket buffer (Linux normally
  doubles it for accounting), and a fixed 256-element metadata array bound
  collection memory. Kernel queues can discard additional traffic.
- Each command retains at most 256 KiB. Each family snapshot has at most 2,048
  rows and 16,384 tokens; each row is at most 4,096 bytes / 64 tokens. Multiple
  bounded snapshots are necessary for exact restoration checks. Bounds apply to
  retained data, not the Android allocator's large virtual address reservation.
- Rule subprocesses have three-second deadlines, including a two-second xtables
  lock wait; independent engine verification gets fifteen seconds. Timed-out
  command groups are killed and reaped. Writers inherit the locks, preventing
  late insertion racing recovery after parent death. The app bounds root output
  at 64 KiB and waiting at 120 seconds; timeout is failure, never success.
- The kernel copies at most 24 IPv4 or 44 IPv6 bytes. Only numeric source IP,
  protocol, available TCP/UDP ports, scope and DROP reason leave the helper.
  Unusual protocols/fragments can put a few payload bytes in transient buffers;
  no payload is interpreted, retained in a report, printed or written to disk.
  Core dumps are disabled. Snapshot and packet content is not sent to stderr.
- Sequence gaps, netlink overflow and excluded/unreadable records limit coverage.
  Even without a detected gap, loss is possible. Per-rule observation windows
  differ slightly because installation is sequential. No claim of complete
  capture or unique connections is made.

## Crash recovery

Normal HUP/INT/TERM and input-pipe closure cause cleanup; repeated ordinary signals
are ignored during cleanup. SIGKILL or termination of the entire process tree
cannot run a cleanup handler. Kernel socket release ends collection, and any
remaining NFLOG rules remain nonterminating before their unchanged DROP rules.
The strict verifier may report DEGRADED until cleanup.

Insights recognizes its reserved `PUFW_APP1:` rules in the existing read-only
kernel report, including tunnel rules. The Firewall tab prioritizes narrow
Insights recovery over its general removal buttons when probes are detected.
During healthy operation, **Troubleshooting** holds the recovery controls and
stays collapsed by default. An inspected kernel report containing APP1 residue
promotes **Recover Insights probes** above the sampling controls on Insights; the Firewall
tab retains its existing narrow-recovery priority. A generic failure or degraded
state alone does not imply residue. The native helper remains the authority for
full rule-signature validation, including refusal of malformed reserved rules.
Recovery is available with root even when protection is degraded. It uses the same locks and removes
only complete, recognized APP1 probe signatures. It checks that all other current
rules are unchanged and requires ACTIVE. It is repeatable after partial deletion.
No session file or saved snapshot is needed, and none is written. Recovery cannot
prove the pre-crash ruleset was unchanged by another root program while the app
was gone; ACTIVE and current rules minus exact probes are checked instead.

Malformed reserved rules require manual review and are never automatically
removed. Every reserved rule is checked before anything is deleted, so one
unrecognized rule stops recovery (and capture cleanup) with no change at all: the
recognized probes stay too, and nothing is disabled, flushed or rebuilt. The error
names the affected rule (family and rule text, at most 180 characters) for review,
and the Firewall tab keeps offering only recovery, not general removal, while
reserved text remains. Termux `PUFW_INSPECT:` and the older `PUFW_INSIGHTS` prototype are not
owned by APK recovery; capture refuses their presence. Use the originating tool's
recovery for those. Do not use enable/disable, table flushes or lock deletion to
recover a diagnostic session.

`rules-report`'s read-only tunnel row bound increases from four to six so two
leftover probes remain visible. This does not broaden engine rule verification
or authorize any new rule shape.

## Validation

Host parser tests run with AddressSanitizer and UndefinedBehaviorSanitizer,
including truncated headers, fragments, IP options, IPv6 extensions, malformed
ownership, reordered options, exact adjacency and randomized bounded inputs.
Real NFLOG tests run only in disposable user/network namespaces: they verify
actual packet delivery, retained counters, physical/tunnel IPv4/IPv6 DROP
attribution, accepted-reply exclusion, record cap, cancellation, pipe closure,
partial installation rollback, lock/group conflicts, invalid policy refusal,
cleanup failure, SIGKILL, exact recovery, and read-only residue reporting.

Kotlin tests reject incomplete/duplicate/malformed/unverified results, check
classification and grouping, and exercise user-only capture, failure/recovery,
busy/stop, clearing and accessibility layout. Native-graphics Robolectric renders
are written to `android/app/build/reports/tide-ui/insights-*.png`.

Historical initial-implementation validation on 2026-11-10 (before the later
ACTIVE fix and final Tide cleanup; current totals are in the Beta 6 notes):

- Full Python regression run: **672 tests, 650 passed, 22 skipped, no failures**.
  The 21 skipped mksh cases passed in supplemental runs using the documented AOSP
  revision `1548076841f243748a3f56da23b38794d437bc12` (15 shell tests and 6 mksh
  error-message tests). The remaining skip is the existing icon-alpha test,
  because Pillow is not installed.
- **301 JVM/Robolectric tests passed**, including seven Insights UI scenarios.
  The native suite's **12 tests passed**, also with AOSP mksh as its verifier.
- Debug APK and instrumentation-test APK built for all three ABIs. Native
  executable extraction and 16 KiB ELF alignment checked in the APK. No new
  manifest permissions; the enforcement engine/bridge/boot scripts are unchanged.
- Android lint: **0 errors, 3 existing warnings** (target API, resource qualifier,
  unused artwork). Clang static analysis: no diagnostics. Normal and enlarged
  text screenshots inspected; enlarged navigation uses two rows.
- Two stale test assumptions were corrected: selecting the tile listener's own
  disposal block, and locating a tunnel hook by target instead of a fixed index.
  Neither fix changes firewall behavior.

The AOSP mksh build and tests still use host libc; they do not replace the device
acceptance boundary below. To run the native tests with that verifier, set
`POCKETUFW_TEST_MKSH=/path/to/mksh` when invoking `test_native_insights.py`.

Re-run from the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests
ANDROID_HOME=/path/to/Sdk android/gradlew -p android --offline \
  :app:testDebugUnitTest :app:compileDebugAndroidTestKotlin :app:lintRelease :app:assembleRelease
```

Device boundary as of 2026-11-10: the pre-polish debug APK passed normal capture,
Stop, Home/screen-off cancellation, controlled app death, native-helper SIGKILL,
and exact-probe recovery on the Moto. With both app and collector absent and
four probes left behind, the original DROP rules still dropped all controlled
IPv4/IPv6 packets. See [Moto acceptance evidence](insights-moto-acceptance.md).
A later release-signed code-26 APK was installed in place on Frankenpixel and
verified ACTIVE with Tailscale, kernel WireGuard and PINNED/MATCH. Its supervised
capture intercepted all six controlled physical UDP packets; accepted Tailscale
traffic worked and did not hit tunnel probes. All eight probes were removed and
NFLOG group 17 released, with unchanged PocketUFW rules and non-decreasing owned
counters. Android carrier/OEM rule churn caused strict verification to withhold
that sample, so displayed source/protocol/category results were **not** accepted.
WireGuard unsolicited inbound blocking remains untested in that APK session.

The subsequent refusal-path fix independently verifies ACTIVE after successful
cleanup even when strict comparison fails. The UI requires a fresh status read
and cannot retain a stale ACTIVE claim after failure. Host regressions cover both
paths. The final Beta 6 candidate, including this fix and the latest Tide cleanup,
has not been installed or tested on either phone. Earlier device results do not
replace final candidate acceptance. Unsupported kernels fail before probes are
installed. See [Beta 6 scope and verification](releases/0.1.0-beta6.md).

**Known limitation:** Android/OEM filter-rule maintenance can withhold a sample
even while PocketUFW's rules remain intact. No carrier-interface exemption or
qualified sampling is implemented. The [design](insights-verification-design.md)
and [investigation](insights-verification-investigation.md) remain on hold;
they are not descriptions of shipped acceptance exceptions.

## Focused UI polish — 2026-11-10

Changes are confined to the Insights worktree. Healthy operation now shows Tide's
existing disclosure-row style for Troubleshooting. Expanding it does not invoke
root. Back collapses it before leaving Insights. Detected APP1 residue instead
shows the existing recovery explanation and button immediately below the page
heading. Verified recovery and a clean reinspection return to the quiet state.
The capture, cancellation, recovery protocol, native rule validation, firewall
engine, boot logic, and Claude's audited native fixes are unchanged.

The app now explicitly enables Android 13+ `OnBackInvokedCallback` integration
in the manifest. Existing AndroidX `BackHandler`/`OnBackPressedDispatcher` logic
is retained, with no new dependency or navigation mechanism. A tools-only API
annotation documents that older devices ignore this attribute. Android's
[back-navigation guidance](https://developer.android.com/guide/navigation/custom-back/predictive-back-gesture)
supports this opt-in with the existing Activity 1.8.1 dependency. The matching
[AOSP warning path](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android15-release/core/java/android/window/WindowOnBackInvokedDispatcher.java)
rejects platform callback registration when the opt-in is disabled. Host tests
verify navigation and operation guards; disappearance of the warning on the Moto
still needs a later authorized install of the polished build.

### Carrier calling coverage wording

Uncovered interfaces still come only from the root inventory, and the coverage
status stays "not all traffic filtered". After each inspection the app also reads
Android's own network records through `ConnectivityManager`, with no root and no
engine or boot-script change. An uncovered interface is described as a **carrier
calling network** only when Android lists it as a cellular, IMS-capable network
that is restricted, has no internet capability, isn't a VPN, and that no other
record contradicts. It also mustn't be the interface Android's VPN record owns.
Only then does Firewall add: "Carrier calling network is managed separately from
PocketUFW. This is normal and does not indicate a firewall failure." Any other
`ipsec*` interface reads "unidentified IPsec tunnel". A missing or redacted
record leaves an interface unidentified, never covered. Whether an unprivileged
app sees Frankenpixel's `ipsec995` IMS record is unverified: no `ipsec` interface
was up during the 2026-11-10 read-only check, and only an APK on the device can
tell.

### Vendor-display denial attribution

A read-only check of the Moto found the exact
`vendor.display.enable_optimal_refresh_rate` string in `/system/lib64/libgui.so`.
Static disassembly identifies its only immediate string reference in
`android::libguiextension::QtiSurfaceExtension::QtiSurfaceExtension(android::Surface*)`:
the constructor at `0x144d9c` passes the key at `0x5e79f` and default string `"0"`
to `property_get` at `0x144dfc`, then parses the result with `atoi`.
The inspected library SHA-256 is
`45acbdcfd47b75aba8230d6013b4ac5d6c9112e38badfb9f89316062543ff2bd`.
PocketUFW source contains no call or string for this property. The app-scoped
denial therefore belongs to the device's QTI surface extension executing under
the app's ordinary SELinux domain, not the root capture helper. The recorded
denial appeared on foreground/cold-start rendering, and capture/recovery passed.

No app permission, property write, root workaround, renderer change, or SELinux
policy relaxation is appropriate for this vendor access. No such change was
made. Binary attribution, warning logs and the original timestamps remain in
private build evidence for independent review. Back-navigation warnings are the
separate app issue addressed above. Other cold-start HWUI, Compose performance,
skipped-frame and missing `libdolphin.so` warnings remain recorded observations;
their causes have not been assigned to the collector or silently "fixed."

### Focused regression evidence

- 51 JVM/Robolectric tests passed: Insights parser (6), Insights UI (12), root
  output handling (7), real MainActivity entry/navigation (6), and Tide audit
  regressions (20). The UI suite covers healthy/error/degraded/unknown evidence,
  root availability, explicit troubleshooting, Back behavior, top-of-page
  residue recovery, post-recovery collapse, malformed-probe refusal, capture,
  Stop/backgrounding, and large text.
- 38 Python audit, Quick Settings and uninstall-contract tests passed.
- The final 12-test Insights UI rerun passed after the manifest annotation and
  additional screenshot checkpoints. Lint reports zero errors and three existing
  warnings (target API, redundant v26 resource directory and unused resource),
  plus two existing state-autoboxing informational findings.
- UI renders cover healthy, expanded troubleshooting, prominent residue,
  recovered state and narrow large text. Final UI/lint results and fingerprint
  verification are retained in the ignored polish evidence directory.
- No APK assembly, signing, installation, merge, push or publication is part of
  this polish pass. Test tasks only compile classes/resources; their task graph
  was checked to exclude signing and APK packaging.

## Frankenpixel final preparation and full-APK test-update plan

**Historical code-26 plan and evidence, retained for audit.** The artifact hashes,
same-code rollback strategy and pending-test wording below describe the earlier
preparation checkpoint, not Beta 6. Later installation/capture results are
summarized above. Beta 6 increments to code 27; do not reuse this same-code
rollback procedure for it. See the current [Beta 6 notes](releases/0.1.0-beta6.md).

This is a proposed private device-test update, not a release or permission to
deploy. The owner reports Claude's final audit passed. All uncommitted audited
source, including carrier IMS classification/wiring/wording and tests, is included
unchanged in the final unsigned release APK. Read-only package inspection and
backup of Frankenpixel's installed signed Beta 5 were completed on 2026-11-10;
no app launch, signing, installation, capture or firewall operation was performed.
The live network gates below must be checked in the separately authorized device
session. The complete APK still needs its own root-manager, SELinux, lifecycle
and UI acceptance.

### Prepared artifacts and verification — 2026-11-10

Private evidence directory (mode 0700):
`android/app/build/outputs/frankenpixel-preparation/20261110T215530Z/`.
Verified copies of the unsigned candidate, installed signed rollback APK and
intake records are also preserved outside build output in the private directory
`/home/winget/.bak/PocketUFW-artifacts/frankenpixel-insights-v1/20261110T215530Z/`.
Use this durable rollback copy; future build cleanup must not remove it.

| Artifact | Verified identity |
| --- | --- |
| `PocketUFW-insights-v1-final-unsigned.apk` | SHA-256 `202e6d525818032985eaac1189c82384359fa155077669366dfb8aa643655b68`; 7,134,669 bytes; deliberately unsigned |
| `rollback/PocketUFW-installed-Beta5-code26.apk` | SHA-256 `4c77c176613e6c587915a2703fece413d9cecc0d1ce1176e8c66f5aee2086b2c`; 6,660,148 bytes; installed Beta 5, APK v2/v3 signatures verified |
| Both packages | `io.github.pocketufw`, code 26, name `0.1.0-beta5`, no version-code major or base revision (both default to 0), single base/no splits, non-debuggable, no `testOnly` |
| Installed signer | SHA-256 `29cac70ee30ed8ab26676aeb60809bdf668f3ad3428eab556316970ce1f99ad2`; one signer, PocketUFW Release, RSA-4096 |
| Device intake | Pixel 9a / Android 17; serial `58301JEBF13901`; app ID 10371; first install and last update `2026-11-09 00:05:11` |

The rollback APK was streamed from its current PackageManager path without
creating a phone-side copy. Its on-phone hashes before/after transfer and local
hash agree; APK and private intake records are mode 0600. Recheck the installed
hash before deployment: a subsequent update invalidates this intake.

The unsigned release was built with a guard that rejects a release signing
configuration. Signature verification fails as expected for the unsigned APK.
No private signing key was read. The required signer is established from the
installed APK; the future signed candidate's compatibility cannot be verified
until signing is separately authorized and its certificate matches exactly.
Package/version/revision metadata already permits same-code replacement in both
directions, subject to the device's installer accepting the final signed APK.

All seven packaged scripts match the current audited source. Comparing the
candidate against the installed Beta 5 confirms byte-identical `pocketufw`,
`android-bridge`, `bootctl`, `boot-service`, `udp-config` and `vpn-probe`.
Only `rules-report` differs among these scripts, for the audited bounded Insights
residue display. DEX contains the audited carrier calling and Troubleshooting
code. Native helpers for arm64-v8a, armeabi-v7a and x86_64 are present; their ELF
LOAD alignment is 16 KiB, stacks are non-executable, and BIND_NOW is enabled.
APK alignment checks pass and `extractNativeLibs=true` is present.

Fresh regression results: **314 JVM/UI tests passed**, including carrier IMS
classifier, Android wiring and wording cases; **39 contract/native parser tests
passed**, including ASan/UBSan. Release lint has zero errors, three existing
warnings and two existing informational findings. No live firewall tests were
run in preparation. Source fingerprints and the frozen artifact are retained
with the build/test logs. No source promotion or worktree cleanup occurred.

### 1. Choose a reversible package/version strategy

Use the normal **release variant**, application ID `io.github.pocketufw`, the
original PocketUFW release key, `debuggable=false`, and no `testOnly` flag or
package suffix. The prepared private candidate retains **version code 26** and
version name `0.1.0-beta5`; distinguish it using its recorded digest and artifact
filename. No version change was made to the audited source.

A same-code replacement permits retaining the exact original code-26 APK for
in-place rollback, provided the full version code, base revision and any split
revisions permit replacement **in both directions**. Both prepared artifacts
are single base APKs with revision zero; revalidate the live installation at
deployment. Android's
[versioning rules](https://developer.android.com/studio/publish/versioning) and
[package downgrade checks](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android15-release/services/core/java/com/android/server/pm/PackageManagerServiceUtils.java)
reject lower version codes, and check base/split revisions when codes are equal.
This is a private sideload strategy; public releases need increasing codes.

Do not casually bump the test APK to 27 and describe the original code-26 APK as
an assured rollback. `adb install -d` is not a dependable downgrade path for a
non-debuggable release app on a production build, and root alone does not make
it one. If a higher test code becomes necessary, stop this plan and prepare a
separately reviewed, release-signed forward-rollback build of the exact prior
implementation at an equal or higher code. That is a rebuilt rescue artifact,
not the preserved original APK. Do not bypass PackageManager or wipe data.

### 2. Preserve the exact installation and establish signing identity

Before any future installation, explicitly verify Frankenpixel's USB serial,
model, Android user, package path(s), app UID, full version/revision metadata,
native ABI and first-install time. Use that serial on every command. Do not use
an implicit ADB target or select the Moto by mistake.

Pull the **actually installed** base APK and every split, if any, into a private
mode-0700 rollback directory. Hash them and verify signatures with
`apksigner verify --print-certs`. A similarly named download is not a substitute
for this exact installed artifact. The historical release-certificate SHA-256
recorded in the repository is
`29cac70ee30ed8ab26676aeb60809bdf668f3ad3428eab556316970ce1f99ad2`;
it must be revalidated against the installed APK and original release key before
future signing. The Moto's debug certificate beginning `da710b89` is unsuitable.
Stop on a mismatch; do not rotate keys, change package ID, or uninstall.

Preserve app data through same-package `install -r`; there is no schema migration
in this polish. Record hashes/metadata for PocketUFW preferences and its
device-protected UDP configuration, including absent-file state, and retain an
additional private root-readable backup of those app-owned settings if approved
for the future device session. Do not collect VPN private keys or other apps'
data. `allowBackup=false` means ordinary Android backup is not a rollback promise.
Do not restore a raw archive over live app data; any incompatible data change
requires separate review. Insights samples are memory-only and need no migration.

### 3. Baseline the live firewall, VPNs and boot snapshot

**Abort unless `wlan0`, `tun1` and `US-DEN-315` are all active, and the
independent tunnel status reports `tunnel_mode=PINNED` and
`tailnet_current=MATCH`.** Confirm Wi-Fi link/address/route, Android/process
ownership of Tailscale's `tun1`, and the existing kernel WireGuard interface
`US-DEN-315` with its current address/routes. Use the interface UP flag and actual
path evidence; tunnel operstate `UNKNOWN` alone is not a failure or proof of
activity. Require `tunnel_filter=ON`, expected hooks and both families ACTIVE.
Missing, down, changed, ambiguous or unreadable evidence stops acceptance; do not
bring an interface up, reconnect a VPN, refresh hooks or re-pin to satisfy a gate.
Recheck these gates before capture and after cleanup.

Require independent ACTIVE for both families, no diagnostic residue or active
collector, no group-17 conflict, and a known healthy root path. Keep USB ADB
available independently of VPN connectivity. Save all loaded netfilter tables
and separate per-rule counters, policies, hook order, physical/tunnel chains,
UDP exceptions, PINNED destination addresses, interface names and routes. Read
the existing engine's `verify`, `activity`, `tunnel-status`, `get-ports`, saved
UDP configuration and `bootctl status`. Require PINNED mode and current ownership
proof/MATCH; do not silently reauthorize stale pins.

**Never reset counters.** Save full `iptables-save -c` and `ip6tables-save -c`
readings (all available tables) before installation, after installation/before
launch, after launch, immediately before capture, after cleanup, and after any
authorized rollback. Keep packet and byte counts, including chain-policy and
unrelated-rule counters. Match each original row by family/table/chain/full rule
signature and duplicate occurrence; compare original rule order after excluding
only verified temporary Insights probes. Each observed original counter must
be **greater than or equal to its previous value**, not merely the initial
baseline. A decrease, missing/replaced original row or unexpected policy change
aborts for review; never zero counters or restore a saved table to simplify the
comparison. Ambient traffic can increase them. Numeric quota2 remaining bytes
are a separate countdown field, not a packet/byte counter.

Record Android's VPN ownership/interface information, current Tailscale listener
ports and the existing kernel WireGuard interface. Prove the current useful
paths with small IPv4/IPv6 HTTPS/DNS checks and approved tailnet/WireGuard peer
checks; record paths that are unavailable. Keep Tailscale, WireGuard, network
attachments, tunnel mode, pins and exceptions unchanged. Do not stop VPNs,
refresh ports, change modes, or manufacture a test tunnel to pass a check.

Preserve Frankenpixel's **actual boot preference**, whether enabled or disabled;
do not copy the Moto's disabled preference. Save root-owned boot-file hashes and
read whether their sources match. The existing bridge can refresh a STALE boot
snapshot during ordinary inspection, so a stale/unknown/conflicting boot state
blocks this focused plan until separately resolved.

Before launch, compare candidate assets with the installed and boot-stored
`pocketufw`, `vpn-probe`, `udp-config`, `bootctl`, `boot-service` and
`android-bridge`. Behavior-affecting differences require explicit review as a
separate migration, not an automatic enable/rebuild. The audited `rules-report`
extension for Insights residue is a known display change that must be identified
in the manifest of expected differences. An APK install must not migrate the
active kernel policy or unexpectedly refresh boot enforcement code.

### 4. Prepare and approve the exact future artifacts

The final unsigned release and source manifest above are frozen and verified.
Use that artifact rather than rebuilding different source at signing time.
After separate signing authorization, verify its input hash and sign a separate
output with the original PocketUFW release key. The intended command shape is
`apksigner sign --ks "$PUFW_RELEASE_KEYSTORE" --ks-key-alias "$PUFW_RELEASE_ALIAS" --out "$PUFW_SIGNED_APK" "$PUFW_UNSIGNED_APK"`.
Use the established private key location and secure password input; do not log
secrets or create a substitute key. Then run `apksigner verify --verbose
--print-certs`, require the exact installed signer above, recheck manifest
identity/version/revisions and `zipalign -c -P 16 4`, and record the signed APK's
new SHA-256. Signing changes the APK digest. These signing steps were not run.

Before approval to install, present the candidate hash, matching certificate,
preserved rollback hashes, compatible version/revision pair, baseline findings,
data compatibility and boot-snapshot check. Rehearse replacing and restoring
same-code artifacts on a disposable environment when available; do not claim
that rehearsal has happened. No signing or install was performed to prepare
this plan, and no signing key was read.

### 5. Authorized installation and the first checkpoint

Only after those gates and explicit deployment approval, the intended update is
the equivalent of
`adb -s 58301JEBF13901 install -r --no-incremental "$PUFW_SIGNED_APK"`.
First require that this exact serial is connected over an authorized USB ADB
path and still identifies the verified Pixel 9a. Only the Moto was attached to
Arch's USB ADB during preparation; Pixel package backup used its existing SSH
bridge. Do not silently substitute the Moto, a generic ADB target or a VPN-only
deployment/control path.
Use the appropriate complete split set if intake found splits; do not improvise
a base-only update. No uninstall, clear-data, downgrade flags, reboot, or policy
toggle. Stop on an installer error.

Read back the installed APK hash and version, preserved UID/first-install time,
preferences and device-protected settings. Confirm all rules/counters are
preserved before launch, then open the actual app and confirm its own root grant.
App-owned staged code and observation/cache timestamps may update on launch;
saved UDP choices, protection preferences and existing user data must persist.
Verify extracted native and staged asset hashes, both IP families' ACTIVE state,
unchanged PINNED destinations and MATCH/ownership proof, Tailscale/WireGuard paths,
UDP exceptions and boot files. No capture should start merely by navigating to
Insights. **Stop at this verified installation checkpoint for review.**

### 6. Later full-APK capture checkpoint

After separate approval, recheck the three active interfaces, PINNED/MATCH,
ACTIVE and clean-probe gates, then run one ordinary sample through the installed
release APK. Start the actual app's sample and verify its logging probes are in
place before sending traffic; do not substitute a standalone helper capture.

1. **Physical IPv4 drops:** record the phone's current `wlan0` IPv4 address and
   Arch's LAN source address/route. Confirm the selected UDP ports are not live
   exceptions/listeners. From Arch, bind a UDP socket to that LAN address and an
   unused source port, and send three small packets to port 1900 and three to
   49191 (about 0.2 seconds apart) during the sample. If either port is exempt,
   stop and review the probe choice rather than modifying exceptions. Require
   the actual app to identify the six controlled records as **Physical / IPv4 /
   UDP**, with the recorded source and corresponding possible-SSDP/unclassified
   clues, and the original physical DROP packet counter to increase by at least
   six. Save the send timestamps/counts and original-rule counter deltas. Account
   for ambient traffic separately; a deficient/loss-limited sample is not a pass.
2. **Accepted Tailscale traffic:** in the same window, use a few ordinary IP
   pings from Arch's recorded Tailscale address to the phone's already pinned
   Tailscale address, over `tun1`. Do not use a diagnostic that sends only through
   a relay control channel. Require successful replies and the appropriate
   original accepted-path counter increase. Check the sampled source/protocol
   groups and available packet evidence: none of this controlled accepted
   Tailscale traffic may appear as a sampled DROP. Successful connectivity and
   absence from the sample are both required; an empty sample alone is not proof.
3. **WireGuard:** preserve normal existing connectivity on `US-DEN-315`, but
   record **WireGuard unsolicited inbound blocking: UNTESTED**. Do not generate
   unsolicited WireGuard-inner probes or infer a blocking result from physical
   UDP, tunnel counters or native-only history. Other unexercised paths/families
   remain explicitly untested in this APK session.
4. **Carrier IMS:** if `ipsec995` is available, compare Android's network evidence
   and the actual app warning. When the app can positively identify restricted
   cellular IMS without internet/VPN capability, expect "carrier calling network
   (ipsec995)" and the normal system-managed calling explanation, while retaining
   **not filtered / not all traffic filtered** coverage wording. Contradictory or
   app-redacted records must retain the unidentified-IPsec fallback. If absent,
   record IMS UI verification as untested; do not toggle cellular/calling or
   manufacture an `ipsec` interface. The name alone is never ownership proof.

The prior native-only Frankenpixel run does not satisfy this full-APK milestone.

Afterwards require exact probe cleanup, independently verified ACTIVE, retained
counter values, unchanged original/unrelated rules, boot preference and VPN
configuration, and continued useful connectivity. For structural comparison,
separate counters and normalize only numeric quota2 remaining bytes; independently
enforce counter monotonicity as specified above. Also require no collector,
Insights group-17 listener or diagnostic probe residue, and check Magisk/SELinux
and app logs with the known vendor-display attribution retained. Record whether
the back-navigation warning is absent on the installed build. Stop and report
after this first successful capture.
Stop, backgrounding and fault injection on Frankenpixel are separate approvals;
the successful Moto tests do not authorize repeating them on the daily device.

### 7. In-place rollback and stop conditions

Rollback means reinstalling the preserved original, same-code, same-certificate
APK set with replacement semantics, without deleting app data or kernel rules.
Before replacement, stop sampling and verify that no diagnostic probes remain;
the older app might not recognize or recover them. If recognized APP1 residue
exists, use the new app's narrow recovery and independently verify cleanup first.
If its UI cannot run, an explicitly approved maintenance fallback may use the
exact installed, hash-verified helper's `recover` action against its staged
engine. Do not blindly remove tagged rows, use broad rule removal, delete locks,
or substitute a different helper.

Any recovery refusal, unknown probe, signature/version/data mismatch, policy
change, counter reset, lost PINNED proof, unexpected boot-file update, or broken
connectivity stops the session for review. No disable/re-enable, full-table
restore, uninstall, data clearing, or reboot is an automatic fallback. Preserve
the USB control path and evidence. If rollback installation itself fails, stop
instead of forcing a downgrade. After a permitted rollback, verify the original
APK and assets, unchanged data, ACTIVE physical/tunnel policy, pins, counters,
boot snapshot and VPN paths again. Source promotion, merging, pushing and public
release remain outside this plan.

References: [Linux NFLOG ABI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nfnetlink_log.h),
[Linux NFLOG socket lifecycle](https://github.com/torvalds/linux/blob/master/net/netfilter/nfnetlink_log.c),
[Netfilter group handling](https://www.netfilter.org/projects/libnetfilter_log/doxygen/html/group__Log.html),
[Android CMake configuration](https://developer.android.com/studio/projects/configure-cmake).
