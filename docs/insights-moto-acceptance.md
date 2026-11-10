# Insights v1 — Moto G APK acceptance

Prepared 2026-11-10. **Moto checkpoint: normal capture, Stop, Home backgrounding,
screen-off cancellation, controlled app death, native-helper SIGKILL, and narrow
probe recovery passed. Testing stopped at the approved recovery checkpoint.**
The owner reports that Claude's independent audit and Frankenpixel native-helper
validation passed. This pass checks the actual APK, root-manager interface and
Tide UI on the rooted Moto G. Frankenpixel's installed Beta 5 is outside this
procedure; it was not accessed or changed during these Moto tests.

## Recorded Moto checkpoint — 2026-11-10

The candidate below was installed in place over debug Beta 4 (code 25 → 26),
with matching certificates, a preserved original APK, and no uninstall or data
clearing. Protection was then enabled through the app and independently verified
ACTIVE. Boot restoration remained disabled throughout.

- **Normal capture:** one app-initiated ten-second sample observed exactly 12
  controlled UDP datagrams from Arch: six IPv4 and six IPv6, all Physical,
  final-DROP matches. Source addresses matched the sender; six port-1900 packets
  were labeled possible SSDP/UPnP and six other packets remained unclassified.
  Successful phone-initiated ping replies were not included. Tunnel filtering
  was off, and the UI correctly said tunnel traffic was not sampled.
- **Stop:** pressed while all four probes were present and the root collector
  was running. The app discarded the sample and reported verified cleanup and
  ACTIVE protection. No completed or zero-count sample was substituted.
- **Home and screen off:** separate app-initiated samples were cancelled while
  their probes and collectors were live. On return, each showed the discarded
  sample/verified-cleanup result, with no automatic new capture. The app process
  stayed alive throughout; these are not process-death tests.
- **After every case:** the staged engine independently returned ACTIVE; both
  complete filter listings were byte-identical to the pre-test listings. All
  loaded tables also matched with only traffic counters and quota2 remaining
  bytes normalized. No diagnostic probes or capture helper remained, counters
  were preserved, and boot restoration stayed disabled. Final IPv4/IPv6 HTTPS
  and ADB checks passed. Optional tunnel filtering stayed off.
- **Helper identity:** the interruption cases verified UID 0, the live command
  line, and `/proc/<pid>/exe` pointing to this installed APK's arm64 helper.
- **Controlled app death:** force-stopping only PocketUFW during a confirmed live
  capture killed the app; the helper remained briefly alive to verify its own
  cleanup, then exited. No probes remained and the staged engine returned ACTIVE.
  With the app still absent, four controlled packets per family increased the
  original final-DROP counters by exactly four. Relaunch showed ACTIVE without
  restarting capture. This tests force-stop behavior, not every possible crash.
- **Native-helper SIGKILL:** after all four probes were installed, the helper's
  executable, command line, UID and process start time were checked immediately
  before SIGKILL of that PID only. Four exact APP1 logging probes remained; the
  app withheld the incomplete sample, detected residue and offered recovery.
  Strict verification correctly reported DEGRADED because of the extra rules.
- **Protection with both processes absent and residue present:** the app was
  force-stopped while those four probes remained. With neither app nor collector
  running, another four packets per family increased the original final-DROP
  counters by exactly four. Each probe was independently checked as a complete,
  nonterminating NFLOG rule directly before its unchanged original DROP rule;
  removing only those recognized rows from the snapshots reproduced the entire
  baseline policy. This proves continued blocking for the controlled traffic,
  without claiming strict ACTIVE while diagnostic residue exists.
- **Recovery:** on relaunch, the Firewall screen prominently identified Insights
  residue and offered narrow recovery instead of general rule removal. One tap
  removed exactly the four validated probes. Both families returned to
  independently verified ACTIVE with all original rules and counters retained.
  Final DROP counts were 14 IPv4 and 18 IPv6, up from 6 and 10 at this stage's
  baseline; the eight test packets per family account for the entire increase.
  No collector, group-17 listener, diagnostic probe or new app file remained.

Private evidence is retained under the candidate bundle's ignored `evidence/`
directory: `moto-active-20261110T205326Z`, `moto-capture1-20261110T210700Z`, and
`moto-stop-background-20261110T211426Z`, and
`moto-death-recovery-20261110T212312Z`. The Stop/background evidence includes a
non-test tap on a moved page that did not start sampling; it is excluded from
acceptance results. No firewall disable/re-enable, broad rule removal, rule
flush, reboot, signing, publishing, merge, or Frankenpixel access was performed.
Packet-cap testing, a completed normal capture after interruption/recovery,
tunnel attribution, and repeated recovery with no residue remain unexercised
on this device at this checkpoint. Malformed-probe refusal was not injected on
the Moto; existing offline tests cover that behavior.

## UI polish backlog and warning attribution

- **Carrier IMS explanation:** the owner reports that Android identifies
  Frankenpixel's `ipsec995` as a cellular IMS network. Consider explaining an
  interface positively identified by Android as carrier IMS as normal
  system-managed traffic, while keeping the explicit firewall coverage warning.
  The `ipsec*` name alone is not ownership evidence. No Frankenpixel inspection
  or change was performed for this report.
- **Recovery visibility:** hide the prominent recovery section during healthy
  operation, retaining an accessible troubleshooting entry. Promote recovery
  when actual Insights probe residue is detected; do not equate every degraded
  firewall or interrupted sample with leftover probes.
- **Retained integration warnings:** app-scoped logs recorded an SELinux denial
  reading `vendor_display_prop` / `vendor.display.enable_optimal_refresh_rate`
  and `WindowOnBackDispatcher` reporting that `OnBackInvokedCallback` is not
  enabled. They appeared on opening the app before the first sample and recurred
  on returning from Home and screen off. Keep their timestamps and logs for
  final UI attribution; do not attribute them to the collector without evidence.
  No capture/root execution failure or app crash was observed during normal
  capture or the Stop/backgrounding tests.
  Later controlled-death tests retained the same warnings on cold launch, plus
  HWUI dataspace warnings, Compose method lock-verification/performance warnings,
  skipped cold-start frames, and a missing `libdolphin.so` warning. These logs
  need UI/runtime attribution; no recovery failure or additional unrequested
  crash was observed. The intentionally killed collector's sample was correctly
  rejected as incomplete rather than reported as a successful capture.

These are backlog items only. The installed candidate and implementation were
not changed during this acceptance stage.

Subsequent source-only polish implemented the quiet Troubleshooting entry and
residue-driven recovery prominence, and added the Android back-dispatch opt-in.
Read-only Moto library inspection attributed the display-property denial to
the system QTI surface extension. See the [polish findings and focused regression
results](insights-v1.md#focused-ui-polish--2026-11-10). The polished UI has not been
installed on either phone; the acceptance results above still describe the
frozen pre-polish debug candidate. Claude subsequently implemented and audited
the carrier IMS wording using positive Android ownership evidence rather than a
name pattern. It is included in the final unsigned release preparation; actual
At this historical checkpoint, Frankenpixel APK/IMS acceptance was pending.
See [current validation status](insights-v1.md#validation) for the later installed
APK and withheld sample; the final Beta 6 candidate remains untested on hardware.

## Candidate and provenance

- Worktree: `/home/winget/toolbox/projects/PocketUFW-insights-v1`
- Branch: `feature/insights-v1`, base commit `383255c`.
- The candidate includes the current **uncommitted** audited sources. The Git
  commit alone does not identify this build; use the source manifest and APK hash.
- Bundle: `android/app/build/outputs/moto-acceptance/20261110T200802Z/`
- APK: `PocketUFW-insights-moto-debug.apk`
- Package: `io.github.pocketufw`; version remains `0.1.0-beta5`, code `26`.
  The unchanged version string is not evidence that the audited candidate is installed.
- APK SHA-256:
  `2499348238fba6178ca1c88b2e7cac7236ed9eb5b14529f2b4e30723bebab6a0`
- Debug signing-certificate SHA-256:
  `da710b8962373c833603fa1b3a63e6f928fc52838b87babb2ab2aebd9ef740aa`
- The bundle also contains `source-manifest.json`, `verification.json`,
  `SHA256SUMS`, build/test/lint logs and an instrumentation-test APK. The latter
  is available for UI diagnosis; acceptance below uses the real app and root
  gateway, not fake-gateway instrumentation tests.

Build preparation passed: a forced debug rebuild of all three ABIs; 21 focused
JVM tests (`InsightsTest`, `TideInsightsTest`, `RootOutputTest`); native parser
fixtures with ASan/UBSan; lint with zero errors and three existing warnings.
All seven packaged scripts match source. Native executable extraction, 16 KiB
alignment and the packaged audit-fix strings were checked. All 110 fingerprinted
source/input files were unchanged through the build. The full host regression
suite was not repeated.

The APK includes Claude's quota2 countdown normalization, distinction between
probe cleanup and unrelated policy/verification failures, no-op recovery wording,
and bounded identification of unrecognized diagnostic rules.

## What is needed

The unlocked, rooted Moto G, a USB data connection with USB debugging authorized,
and its owner available for the app's Magisk/root prompt. A host on the same LAN
will supply a small number of synthetic packets. IPv6 and tunnel tests depend on
routes/peers actually present on the Moto; unavailable paths are recorded as
**not exercised**, never as passed.

Allow roughly 20–30 minutes after installation. Keep the current Wi-Fi, VPN,
tunnel mode, pinned addresses, UDP exceptions and boot-restoration preference
stable. This is not a reboot, policy-migration, VPN-mode-change or carrier test.

## 1. Identify and baseline the Moto before installation

Every device command uses an explicit verified serial. Do not use an implicit ADB
target, broad process-name kill, or any Pixel/Frankenpixel connector. Discovery
and the commands below are for the later device session; none ran during preparation.

```sh
adb devices -l
MOTO_SERIAL='replace-with-verified-Moto-serial'
adb -s "$MOTO_SERIAL" shell getprop ro.product.manufacturer
adb -s "$MOTO_SERIAL" shell getprop ro.product.model
adb -s "$MOTO_SERIAL" shell getprop ro.build.version.release
adb -s "$MOTO_SERIAL" shell getprop ro.product.cpu.abilist
adb -s "$MOTO_SERIAL" shell am get-current-user
adb -s "$MOTO_SERIAL" shell pm path io.github.pocketufw
adb -s "$MOTO_SERIAL" shell pm path io.github.pocketufw.alpha
```

Confirm Motorola/Moto identity against the physical handset. Record its serial
locally. Use a host evidence directory under the ignored build bundle with mode
0700; keep addresses, screenshots and private device metadata out of public Git.

Before changing the installation:

1. Identify which installed package owns the current firewall and its version.
   Pull its installed APK to the local evidence directory and use
   `apksigner verify --print-certs` to compare its certificate with the candidate.
   Retain that APK as a reference; an APK rollback must not require wiping data.
2. Save raw `iptables -w 2 -S` and `ip6tables -w 2 -S` filter listings. These
   include INPUT/OUTPUT/FORWARD policies and all PocketUFW rule structures.
   Save owned-chain packet/byte counters separately with `-L ... -n -v -x`.
3. With the currently installed trusted engine, record `verify`, `activity`,
   `tunnel-status`, and `get-ports`; record `bootctl status` and `udp-config read`.
   Record pinned destinations, current tunnel mode, hooks, UDP exceptions and
   normal connectivity. These are inspections, not enable/refresh/reset actions.
4. Require an understood, ACTIVE starting policy and no diagnostic residue or
   running capture. If root, policy, ownership, signature or backend compatibility
   is uncertain, stop at intake and resolve that specific mismatch. Do not
   uninstall, clear app data, rebuild rules, or install alongside an older active
   `.alpha` owner merely to get past a gate.
5. Compare the staged enforcement/boot scripts with candidate assets. A different
   legacy policy is a separate migration. Also inspect the saved boot copies:
   the existing Android bridge can refresh a stale boot snapshot during app
   inspection. Record/resolve a stale snapshot before this focused acceptance;
   do not describe that path as a purely read-only boot check.

Read-only filter snapshot command examples (host redirections retain evidence):

```sh
adb -s "$MOTO_SERIAL" exec-out su -c '/system/bin/iptables -w 2 -S' > "$EVIDENCE/before4.rules"
adb -s "$MOTO_SERIAL" exec-out su -c '/system/bin/ip6tables -w 2 -S' > "$EVIDENCE/before6.rules"
```

Set `EVIDENCE` to the private local evidence directory first. Check each exit code;
a failed/empty read is not a baseline. The private engine path for the current
package and Android user must be confirmed rather than inferred from old Moto notes.

## 2. Install and establish the APK boundary

After the identity, signature and starting-policy checks pass:

```sh
adb -s "$MOTO_SERIAL" install -r "$APK"
adb -s "$MOTO_SERIAL" shell am start -n io.github.pocketufw/.MainActivity
```

Set `APK` to the exact candidate above. Use the same-package in-place update;
no uninstall, data clearing, signing substitution or version downgrade flags.
Pull/read the newly installed base APK and confirm its SHA-256 equals the candidate.
Record `nativeLibraryDir` and the Moto's selected ABI. Verify the extracted
`libpufw_insights.so` digest against `verification.json`, and confirm that the app
staged the seven expected script assets.

Grant root to **PocketUFW itself** through the phone's root manager. A successful
ADB `su` command does not prove the application's root access. The opening
inspection should show current ACTIVE protection. Compare baseline rules,
counters and settings before proceeding: the upgrade must not reinstall or zero
firewall rules.

Navigate to Insights without pressing Sample: no helper process or new probe
should appear. Keep capture initiation in the app for every acceptance case;
do not substitute a standalone native-helper command for an APK result.

## 3. Common verification after every case

Record case ID, start/end time, action, screenshot, observed sample totals,
coverage warnings, helper lifetime and postcondition evidence.

After the helper exits and the UI finishes its verification:

- Independently run the **new APK's staged** `pocketufw verify`: require `ACTIVE`.
  Check the app's fresh status/inspection time as well as its capture message.
- Read both complete filter listings. Require no `PUFW_APP1:` probe anywhere.
  Compare rule order, matches, targets, policies, hooks, exceptions and pins with
  the baseline. Retain the raw listings. Only the numeric remaining-byte value
  following `--quota` on a `quota2` row may be normalized as in the audited helper;
  names, rule structure and targets remain significant. Other differences are
  investigated, not silently ignored or restored from a full-table dump.
- Require original DROP rules/counters to remain in place. Counters may increase
  with live traffic; they must not reset. No counter-reset or firewall-toggle
  action is part of this test.
- Require no helper still capturing, no persistent capture notification/service,
  and no packet/payload files or new metadata journal. Do not collect full device
  logcat, packet captures, or unrelated private app files as routine evidence.
- Confirm the starting VPN/tunnel mode, pins, UDP exceptions and boot opt-in, plus
  the same basic connectivity and inbound-blocking behavior.

Do not interpret a direct verification performed *during* instrumentation as the
postcondition: the helper intentionally holds both locks and the strict engine
can report busy/DEGRADED while probes exist.

## 4. Focused acceptance matrix

| ID | Action through the real APK | Required result |
| --- | --- | --- |
| M1 — root execution and deadline | Tap **Sample dropped traffic**; let it finish normally. Briefly identify the actual root helper by `/proc/<pid>/exe`, UID and complete command line while it runs. | Executable comes from this installation's `nativeLibraryDir`, uses `capture` and this app's staged engine, and runs as root. UI produces a complete verified sample or an explicit failure, never success from truncated output. Normal collection ends at 10 seconds from probe installation or the record cap. Setup/cleanup and final status inspection add wall time. Common verification passes. |
| M2 — controlled results | During a fresh sample, send 12 unicast UDP datagrams from a known LAN peer to the Moto's IPv4 address on a closed/non-exempt port. Use port 1900 for a **possible SSDP** clue only after confirming it is not an allowed UDP exception. Repeat for IPv6 if routed. Include a successful phone-initiated ping to that peer as an accepted-reply control. | Known source and UDP appear under Physical and the correct IP family; relevant DROP counters rise. Port 1900 is an observed fact with a possible purpose, not proof of SSDP software, a vendor or an attack. Accepted ping replies are absent from that peer's DROP observations. Source counts match the controlled burst when isolated and loss-free; otherwise retain the limitation rather than forcing an exact count. Historical counters stay separate. |
| M3 — packet cap | On a fresh app sample, send at most 300 small UDP datagrams to a verified non-exempt port, with 5 ms spacing, starting only after probes are installed. | Capture stops at 256 received records, possibly before 10 seconds. UI says the record cap was reached, with exclusions/loss honestly reflected. Later packets still hit the original DROP rule. Common verification passes. |
| M4 — Stop | Start a sample and press **Stop sample** while the actual collector is still active. | UI changes to cleanup; helper exits, sample is discarded, and verified interruption/cleanup is reported. No fabricated zero or successful completed sample. All common postconditions hold; a later manually started sample works. |
| M5 — background/screen off | Start a sample, then go Home while collecting. Repeat once by locking/switching off the screen. Return after cleanup. | Lifecycle cancellation closes the request pipe. No persistent capture/notification or automatic new sample on return. Any already-completed sample is distinguished from an interrupted one by timing; an action after the collector ended does not count as a cancellation test. Common verification passes. |
| M6 — app process death | During a confirmed active sample, `am force-stop io.github.pocketufw` on the verified Moto serial, then relaunch. | Helper either cleans up on pipe closure or exits by its bounded deadline. The reopened app does not auto-capture. If the root manager killed the helper and left probes, the app detects them and offers narrow recovery. Verify the actual outcome instead of assuming the app's death killed root too. |
| M7 — native SIGKILL and recovery | Start in the app; confirm this exact helper PID, `capture` command and installed probes. Send SIGKILL to that PID only. Let the app report failure/recheck, then press **Recover Insights probes**. Repeat recovery once when clean. | No successful capture is accepted. Leftover probes are visible as diagnostic residue; following DROP rules remain intact. The UI prioritizes narrow Insights recovery over general rule removal. Recovery requires all probes absent plus independent ACTIVE verification. The repeat says **no Insights probes remain**, not that it removed anything. Common verification passes. |
| M8 — final protection | After all cases, repeat the original inbound UDP and accepted-reply checks and compare the final snapshots/settings with intake. | Original physical protection and existing PINNED/DENY-ONLY/off choice remain intact. No helper/probe residue, no counter reset, no newly opened exception and no changed boot opt-in. |

For an existing enabled tunnel, repeat one small controlled burst over an already
available **non-exempt** inner path and verify Tunnel attribution. In PINNED mode,
traffic covered by the pinned tailnet exemption should be accepted and absent
from DROP samples. Do not change modes, pins or VPNs just to manufacture a tunnel
example. If filtering is off, verify the UI says tunnel traffic was not sampled.
Record any unavailable path as not exercised.

Use at most a short, bounded readiness observation (e.g. one read per second for
up to five seconds) to identify app-created probes before sending synthetic
traffic. There is no persistent test watcher. Keep sender and device clocks/times
in the evidence so traffic outside the sample window is not counted as missing.

Small host-only UDP burst example; all arguments must refer to the verified Moto
and the selected test case, never a broadcast/multicast or third-party address:

```sh
python3 - "$FAMILY" "$MOTO_ADDRESS" "$TEST_PORT" "$PACKETS" <<'PY'
import ipaddress, socket, sys, time
family, target, port, count = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
address = ipaddress.ip_address(target)
assert family in (4, 6) and address.version == family
assert not address.is_multicast and not address.is_unspecified
assert 1 <= port <= 65535 and 1 <= count <= 300
sock = socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6, socket.SOCK_DGRAM)
try:
    sock.connect((target, port))
    print('sender', sock.getsockname(), 'target', target, 'count', count, flush=True)
    for _ in range(count):
        sock.send(b'\0')
        time.sleep(.005)
finally:
    sock.close()
PY
```

Confirm the host route reaches the Moto's intended physical/inner interface. If
ICMP errors or routing prevent delivery, stop the burst and record it as
inconclusive. Do not count a sender's attempted datagrams as observed drops.

For M7, validate `/proc/<pid>/exe` and `/proc/<pid>/cmdline` immediately before
signalling, and ensure it is this APK's root **capture** helper, not `su`, Magisk,
a verifier, the app process or another session. Never use a blanket `pkill -f`.
The only deliberately disruptive action is termination of that temporary sample.

## Timeouts, failures and completion

The normal 10-second collection deadline and 256-record limit are on-device
acceptance cases. The separate 120-second outer root-response deadline is covered
by the focused `RootOutputTest` cases (including continuous output and failure
responses); it is **not claimed as device fault-injection coverage** in this pass.
A naturally occurring root/setup stall must end in a clear failure without a
successful sample. Record its timing and independently establish cleanup.

If an ordinary case is not finished within 30 seconds after the collector started,
record a timing failure and inspect the exact helper/UI state. The outer wait can
last up to 120 seconds. Do not continue starting samples or remove lock files.
If probes remain after termination, use the app's narrow recovery, then independently
verify both families. A cleanup/verification failure stops the acceptance session.
An unrecognized reserved rule requires review; do not alter or flush it, reinstall
policy, reset counters, or turn protection off as a diagnostic workaround.

Do not inject malformed rules or change unrelated firewall policy just to repeat
an audit result. Those paths already have focused audit coverage. This acceptance
pass verifies the actual app boundary and legitimate interruption/recovery paths.

A device result is complete only after M8 and recorded outcomes for each case,
including explicit unavailable/inconclusive paths. Leave the Moto's original
protection configuration in place, with no diagnostic residue. No release
signing, publishing, push, merge, Frankenpixel update, or reboot is part of this pass.
