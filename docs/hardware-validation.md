# PocketUFW hardware validation

*Public edition: test account identifiers, host-local addresses and private VPN tunnel addresses have been anonymized; test results and packet counts remain unchanged.*

## Moto G 5G (2024), Android 15

**Test date:** 2026-10-31 (America/Denver)  
**Scope:** Manual, temporary firewall validation on an authorized rooted test phone connected to Arch via USB ADB.

Environment: Motorola kernel 5.4.284, SELinux Enforcing, Magisk root, legacy iptables/ip6tables 1.8.10. Both `conntrack` and `comment` extensions were accepted. Wi-Fi interface was `wlan0`; cellular interface naming included `rmnet_data*`, but **this Moto has no usable cellular service**. All live network tests are Wi-Fi only.

### Observed results

| Check | Observation |
| --- | --- |
| Local Python mock unit tests | **13/13 passing** after new rollback/idempotence regressions |
| Real-device read-only doctor and rule plan | Passed |
| Install PocketUFW-owned IPv4/IPv6 chains | Passed |
| Hook three physical interface patterns per family | Passed |
| Established-return, protocol allowance and final-DROP rules present | Passed |
| Outgoing IPv4 ping during firewall test | Passed |
| Incoming IPv4 UDP blocking | **12 of 12 datagrams accounted for by final DROP counter** |
| Repeated enable/disable | Passed in initial smoke test and network test |
| Exact IPv4/IPv6 INPUT baseline after disabling | Passed |
| PocketUFW chains and test files absent afterward | Confirmed |
| IPv6 LAN reachability with firewall enabled | Passed: ICMPv6 ping replied |
| IPv6 internet reachability | Not established: upstream test failed/was unavailable; this does not contradict LAN IPv6 success |
| IPv4 UDP/TCP enforcement | Passed: 12 UDP datagrams and 2 unsolicited TCP attempts dropped; TCP connections timed out instead of immediately refusing |
| IPv6 UDP/TCP enforcement | Passed: 12 UDP datagrams and 2 unsolicited TCP attempts dropped; TCP connections timed out instead of immediately refusing |
| Wi-Fi/cellular handover and carrier IMS | **Not applicable on this Moto** (no cellular service); requires a different test phone |
| Tailscale dynamic UDP and Proton kernel WireGuard coexistence | Not tested on Moto |
| Reboot, crash recovery, automatic port discovery | Not implemented/tested |

### Packet-level evidence

Arch and Moto were on the same private Wi-Fi LAN. With PocketUFW enabled, Arch sent twelve unsolicited UDP datagrams toward a closed high-numbered port on the Moto. The IPv4 `POCKETUFW_IN` chain's final DROP-rule packet counter rose **0 → 12**, with the preceding `ctstate INVALID` DROP counter remaining at zero.

The initial diagnostic incorrectly reported zero because its parser selected the **first** DROP rule (invalid-state filtering) instead of the **last** DROP rule (default inbound deny). Rerunning with both counters visible corrected the measurement. Future automated tests must identify the intended rule by full rule specification, not the first matching target.

A later dual-stack LAN test independently confirmed 12 unsolicited UDP datagrams plus two TCP connection attempts were counted by the **final** DROP rule for each address family. IPv4 and IPv6 final-DROP counters each reached **14 packets**. Both TCP attempts timed out with the firewall on; without it, the closed test port immediately returned connection refused. IPv4 and IPv6 ping both replied with the firewall enabled.

### Safety and cleanup

A separate-process-group device-side rollback timer was armed for each live test. Manual disable succeeded; the timers did not need to fire. Device firewall policies and Android/OEM chains were not flushed or modified. All staged test scripts and markers were deleted from `/data/local/tmp` after verification. No code was installed persistently and nothing was changed on the Pixel 9a.

**Status:** Promising hardware prototype, not production-ready. LAN IPv4/IPv6 TCP+UDP filtering is hardware-verified. Remaining work: dynamic Tailscale UDP, IPv6 internet path, different Android hardware, safe recovery, and cellular/IMS testing on a separate phone with service before public release.

### Proton VPN and live-exception refresh (Moto follow-up)

With Proton VPN connected through Android's normal `VpnService` tunnel (`tun0`), PocketUFW was enabled temporarily with an independent rollback timer.

- IPv4 and IPv6 public routes remained on `tun0`.
- HTTPS requests from the Moto returned **HTTP 200 over both IPv4 and IPv6** while PocketUFW was enabled.
- `--auto-tailscale` detected no Tailscale listeners on the Moto and installed no unnecessary VPN exceptions.
- In a separate test, two temporary UDP exception rules were installed into PocketUFW's owned child chains. `refresh` correctly removed both after verifying no Tailscale listeners were present, without rebuilding the inbound policy.
- IPv4 and IPv6 HTTPS via Proton returned **HTTP 200** after the refresh.
- Manual `disable` removed all owned IPv4 and IPv6 chains, and temporary staging files and rollback markers were cleaned up. Proton configuration was untouched.

**Not yet tested:** Proton reconnecting while the firewall stays active, real Tailscale port changes with the Android app running, automatic monitoring, cellular handoff, or reboot recovery.

### Android alpha2 activity counters and external LAN proof (November 1, 2026)

The new `pocketufw activity` and `pocketufw verbose` commands read packet counters directly from the installed IPv4/IPv6 `POCKETUFW_IN` chains. The Android app surfaces the same values in an expandable `Firewall activity` panel.

- The Moto's active rules initially showed an observed IPv4 DROP count and established-reply ACCEPT counts. The per-rule counters reset after the user's next activation.
- With **PocketUFW active**, the test sent **five UDP datagrams over IPv4 and five over IPv6** from Arch over the same Wi-Fi LAN to a checked, unbound high UDP port on the Moto.
- Before the probes, both family DROP counters were **0**. Afterward the app-installed `activity` command reported **`ipv4_blocked=5`** and **`ipv6_blocked=5`**, with exact deltas of five in each family.
- Counters and the result of `pocketufw verify` were read without changing firewall rules. Verification remained **ACTIVE** after the probe.
- `verbose` also reported the inbound/outbound policy, configured physical-interface patterns, accepted established-reply packet counts, and the explicit limitation that earlier Android/OEM ACCEPTs and unsupported interfaces are not proven protected.
- The new APK was built and installed as **0.1.0-alpha2**. Android launched successfully, the pre/post installation firewall state matched, and Android Lint had **0 errors**.

**Interpretation:** This is strong evidence that selected real unsolicited LAN packets reached PocketUFW and were dropped. The counters cannot alone prove comprehensive coverage of every network path or classify a dropped packet as an attack. Zero drops is normal on quiet networks. Counters reset when rules are removed and reinstalled.

### Alpha8 upstream INPUT ordering audit (November 1, 2026)

**Scope:** Read-only inspection and controlled packet probes on the Moto over its local Wi-Fi, with the installed alpha8 firewall already ACTIVE and Magisk boot restoration ENABLED. Repo HEAD was `ba69589`. No firewall policy, chains, hooks or boot settings were changed.

- IPv4 and IPv6 `INPUT` policies were both `ACCEPT`. In both families, the ordered rules jumped first to `oem_in`, `bw_INPUT`, `fw_INPUT`, and `pl_INPUT`, then to PocketUFW for `wlan+`, `rmnet+`, and `v4-rmnet+`.
- `oem_in` and `fw_INPUT` were empty in both families. `bw_INPUT` invoked `bw_global_alert` (quota/accounting rule without a terminal ACCEPT), then used RETURN and MARK operations; it had no ACCEPT. IPv4 `pl_INPUT` only DROPs ICMP echo requests arriving on `rmnet+`; IPv6 `pl_INPUT` was empty. **No upstream ACCEPT bypass was present in this inspected ruleset.** This does not establish what other OEMs, later rule changes, or other interfaces might do.
- Arch (`<ARCH_LAN_IP>`) and Moto (`<MOTO_LAN_IP>`) were on the same Wi-Fi LAN; both had native IPv6 LAN routes. No UDP listener was found on test port `47931`. Arch sent exactly four small unsolicited UDP datagrams to Moto port 47931 over each family.
- PocketUFW's verified counters increased **IPv4 7 → 11** and **IPv6 3 → 7**, matching all eight probes exactly. `verify` remained `ACTIVE` and Magisk boot state `ENABLED`. The upstream INPUT rule list was unchanged after the test.
- A post-test check did **not** find `tun0` or its routes; therefore Proton VPN coexistence **was not revalidated in this particular session**. Earlier documented Proton-on tests remain separate evidence.

**Conclusion:** This Moto snapshot shows no earlier ACCEPT bypass and demonstrates real IPv4/IPv6 Wi-Fi ingress enforcement through the current hooks. The generic design risk remains on unknown or changed Android/OEM rule sets, and unsupported interface names and VPN inner interfaces remain outside this proof. Next prioritize targeted reliability/rollback and VPN reconnect behavior, not speculative kernel policy rewrites.

### Alpha8 Proton activation with firewall enabled (November 1, 2026)

**Scope:** The tester manually activated Proton VPN on the Moto while PocketUFW remained ACTIVE. Inspection, HTTPS requests, and controlled UDP probes only; no rules or VPN configuration were changed by these checks.

- Proton Android process was present; `tun0` was `UP,LOWER_UP`, with default IPv4 and IPv6 VPN routing tables installed.
- From the Moto's unprivileged ADB shell, `curl -4` and `curl -6` to `https://www.google.com/generate_204` each returned **HTTP 204, exit 0**. The local socket addresses were Proton tunnel addresses `<VPN_PRIVATE_IPV4>` and `<VPN_PRIVATE_IPV6>`, respectively, confirming these HTTPS tests used the VPN interface.
- While Proton remained up, Arch sent three unsolicited UDP datagrams per family to the Moto's Wi-Fi addresses on unbound port `47931`. The live PocketUFW final-drop counters increased **IPv4 11 → 14** and **IPv6 9 → 12**, matching all six packets. Proton `tun0` remained up.
- Final state: PocketUFW `ACTIVE`, boot restoration `ENABLED`. The Git tree remained clean before writing this report.

**Conclusion:** Proton's first activation from the earlier off state did not disrupt PocketUFW on this Moto. Both IPv4/IPv6 HTTPS through the VPN and simultaneous unsolicited Wi-Fi inbound DROP enforcement worked. Repeated Proton disconnect/reconnect cycles, longer operation, and other VPNs/devices remain untested.

### Alpha8 Proton disconnect/reconnect round trip (November 1, 2026)

The tester manually disconnected and reconnected Proton once with PocketUFW continuously enabled. The tests below did not change firewall rules or VPN settings.

- **VPN off:** `tun0` disappeared, VPN routes were absent, and the original IPv4/IPv6 `INPUT` hooks were unchanged. PocketUFW remained `ACTIVE`, boot restore `ENABLED`. Three controlled LAN UDP datagrams per address family to port `47931` increased final DROP counters **IPv4 29 → 32**, **IPv6 16 → 19**. IPv4/IPv6 HTTPS to Google's 204 endpoint both succeeded using Wi-Fi source addresses (HTTP 204).
- **VPN reconnected:** `tun0` reappeared `UP,LOWER_UP` with IPv4/IPv6 VPN default routing tables. The same HTTPS endpoint returned HTTP 204 in both families, using Proton-assigned `<VPN_PRIVATE_IPV4>` and `<VPN_PRIVATE_IPV6>` local socket addresses. All six PocketUFW physical-interface INPUT hooks remained installed.
- **After reconnect:** Three additional unsolicited LAN UDP datagrams per address family increased PocketUFW final DROP counters **IPv4 32 → 35** and **IPv6 20 → 23**. (One additional background IPv6 DROP was observed between test reads.) Final state remained `ACTIVE`, `boot=ENABLED`, and Proton `tun0` up.

**Conclusion:** One complete manual disconnect/reconnect cycle preserved firewall enforcement and both families' outbound HTTPS connectivity, with no firewall intervention required. This does not yet establish repeated-cycle endurance, network handoff, all app traffic routing, or other VPN implementations.

### Alpha9 verifier/rollback upgrade acceptance (November 1, 2026)

- **Regression first:** two offline tests demonstrated false `ACTIVE` from reordering the inbound chain and injecting an unconditional `ACCEPT` in the VPN exception child chain. Another offline test demonstrated that a successful sequence of rule writes could be reported as enabled before a final readback audit.
- **Fixed:** verify checks the ordered eight-rule target sequence, checks each expected rule semantically, and rejects any VPN child chain except empty or a single explicit UDP-port `ACCEPT`. New enables perform full dual-stack readback verification before reporting success and invoke owned-rule cleanup on failed postconditions. The synthetic failure test confirmed both Android/OEM `INPUT` baselines were preserved and all PocketUFW chains removed.
- **Automated/build:** 71 Python tests passed; `sh -n pocketufw`, `:app:assembleDebug`, `:app:lintDebug`, and `git diff --check` succeeded. Existing warnings: two Kotlin deprecated system-bar setters and Android Gradle Plugin 8.7's compileSdk 36 compatibility warning. No lint errors.
- **Actual upgrade:** built debug APK `0.1.0-alpha9` (versionCode 9), verified its embedded `pocketufw` SHA-256 matched the repository source, upgraded the Moto alpha8 installation in place, and launched the app. Firewall remained `ACTIVE`, Magisk boot restoration `ENABLED`, and Proton `tun0` UP without rule reinstalls.
- **Boot snapshot:** refreshed the already-opted-in Magisk boot snapshot; its engine hash matched the new installed app engine hash. The old temporary verifier preview at `/data/local/tmp/pocketufw-verify-preview` was absent after cleanup. A physical reboot using alpha9's boot copy was **not performed** in this acceptance run.
- **Live enforcement:** three unsolicited Wi-Fi LAN UDP datagrams per address family raised observed kernel DROP counters exactly **IPv4 40 → 43**, **IPv6 23 → 26**. Simultaneously, IPv4 and IPv6 HTTPS over Proton both returned HTTP 204 with local tunnel socket addresses `<VPN_PRIVATE_IPV4>` and `<VPN_PRIVATE_IPV6>`.

**Interpretation:** Alpha9's stricter status check is compatible with this Moto's actual kernel rules, and existing VPN connectivity plus physical Wi-Fi inbound blocking survived the upgrade. Tampered-rule scenarios were tested with a mocked firewall only, not by intentionally corrupting live kernel rules. Remaining work includes physical reboot validation with the refreshed boot engine, failures during cleanup, changes by other rule owners, and interface/network changes on additional devices.

### Alpha10 Quick Settings toggle (local-only preparation, November 2, 2026)

- New optional Android system `TileService` toggles protection on a user tap after a fresh kernel verification, with lock-screen unlock requirement, no foreground process, notification, or polling timer. On showing Quick Settings, its standard lifecycle performs one root inspection to display live status.
- The `android-bridge` supports transactional `toggle` / `toggle-restore` actions and rejects DEGRADED or unknown state; the Home switch can also restore a previously enabled boot setting. Magisk boot hooks remain disarmed while protection is OFF; the explicit opt-in preference is preserved locally.
- **82 local tests passed**; `sh -n android-bridge` and Android alpha10 offline `assembleDebug` and `lintDebug` succeeded. The compiled APK manifest includes the Quick Settings service, `BIND_QUICK_SETTINGS_TILE` permission, and toggle metadata. Existing build warnings unchanged.
- **Initial preparation was local-only.** The follow-up below records alpha9 reboot proof and the subsequent alpha10 upgrade. The Quick Settings tile itself still requires the tester's manual on-device tests.

### Alpha9 post-reboot hardware proof and alpha10 upgrade (November 2, 2026)

- The tester physically rebooted the Moto without reopening PocketUFW. ADB confirmed a new boot (~323 seconds uptime) with `sys.boot_completed=1`, alpha9 still installed, and **no PocketUFW app process**. The root-run kernel verifier reported `ACTIVE`, Magisk `bootctl status` returned `boot=ENABLED`, and the root boot snapshot matched the installed alpha9 engine by SHA-256. No Magisk app-start notification was required.
- Confirmed dual-stack ordered inbound rules and verified no listener on test UDP port `47931`. Four LAN UDP probes per family raised kernel DROP counters **IPv4 9 → 13** and **IPv6 1 → 5**, precisely 4/4 in each. IPv4 and IPv6 HTTPS returned HTTP 204 via Wi-Fi. This demonstrates a working one-shot Magisk boot restoration with the Android GUI never launched. Proton's `tun0` was not present after reboot and its automatic boot behavior was not tested.
- Only after the alpha9 reboot proof, installed the debug-signed alpha10 APK (`versionCode=10`) in place on the Moto. The tile service was visible to Android's PackageManager, and the app was opened once so it could stage its new bridge and remember the existing boot opt-in. The freshly staged `android-bridge` SHA-256 matched both the alpha10 APK asset and repo source; the Magisk boot copy still matched the common alpha9/alpha10 firewall engine.
- Alpha10 post-upgrade: `state=ACTIVE`, `boot=ENABLED`, persistent `boot_opted_in=true`. Three controlled UDP LAN probes per family increased DROP counters **IPv4 13 → 16** and **IPv6 5 → 8**. Unprivileged IPv4 and IPv6 HTTPS returned HTTP 204 on the normal Wi-Fi interface. No firewall rule toggling occurred during the upgrade.
- **Pending:** The tester manually adds the tile from Android Quick Settings, inspects the shown verification state, then performs a supervised tile OFF/ON test, checking Magisk opt-in rearming and VPN coexistence. No claim of tile interaction hardware validation yet.

### Alpha10 tile OFF/ON and alpha11 UI acceptance (November 2, 2026)

- The tester added the optional PocketUFW tile to Moto Quick Settings. It showed `Checking kernel...` and then correctly displayed the active state; while the shade remained open, The tester observed an additional short checking transition. No timer exists in the tile.
- The tester tapped OFF and then ON. The UI showed `Switching...` and correctly changed state by his observation. Our first ADB read caught it back `ACTIVE`, so **a live OFF state was not independently audited before re-enabling**. The later ADB snapshot showed `boot=ENABLED`, `boot_opted_in=true`, all three IPv4 and three IPv6 INPUT hooks present, and reset packet counters. Four controlled unsolicited LAN UDP packets per family then increased counters exactly **IPv4 0 → 4** and **IPv6 0 → 4**; boot restoration remained enabled.
- The tester reported two alpha10 GUI glitches: initially unchecked switches for approximately two seconds before kernel verification, and a transient dimming of the firewall switch while toggling Magisk boot restoration. He also noted that a tile long press opened Android App Info instead of the dashboard.
- Alpha11 addresses these as UI/manifest changes only: neutral spinner panel while initially verifying; a controlled busy-action handler that does not dim unrelated switches; and `ACTION_QS_TILE_PREFERENCES` to `MainActivity`. The alpha11 APK built/linted, **85 Python tests passed**, and it was installed in place without changing firewall rules. Android's on-device package resolver explicitly selected `io.github.pocketufw.alpha/.MainActivity` for the preferences action. Verified post-upgrade `ACTIVE` and `boot=ENABLED`.
- **Still pending human confirmation:** tile long press must physically open the dashboard, launch should not flash false OFF controls, and boot-restoration changes should not flash the main firewall switch.

### Alpha12 advanced UDP exception editor (November 2, 2026)

- At the time of planning, Tailscale on Moto exposed verified listeners IPv4/UDP `41476` and IPv6/UDP `45567`. PocketUFW `Refresh VPN` installed the corresponding two child-chain ACCEPT exceptions with firewall `ACTIVE` and boot `ENABLED`. Before refresh, Arch-to-Moto Tailscale ping was DERP-only; after refresh, the next ping succeeded via direct IPv6 endpoint (48 ms) and `tailscale status` reported a direct IPv4 endpoint. This is grounded device evidence, not a guarantee that NAT always permits direct connections.
- Alpha12 adds an inline explanation and an advanced UDP editor with Experimental/Committed options and two warnings for committed saves. `udp-config` is strictly parsed app-owned device-protected persistence; a Magisk root snapshot stores only code, not lingering configuration. Tests cover corrupted files, symlinks, rollback, manual one-per-family restrictions, boot restoration of committed values, and clearing to automatic. The engine leaves Android global chains untouched.
- **Do not claim the new committed-mode persistence has passed a real physical Moto reboot yet.** Hardware installation and UI acceptance should be performed carefully while preserving current Tailscale listener exceptions, with a separate subsequent reboot test only after the user explicitly exercises Committed mode.

### Alpha12 first Moto hardware acceptance (November 2, 2026)

- Offline 109 Python tests and final Gradle `assembleDebug` + `lintDebug` succeeded; all seven packaged script assets have matching SHA-256 against repo source. An initial candidate omitted `udp-config`; corrected Gradle staging and added a regression test **before installing**. Existing Android AGP 8.7/compileSdk 36 compatibility warning remains (and prior Kotlin system bar deprecations).
- In-place upgraded Moto from alpha11 to alpha12 using ADB (`versionCode=12`). After the UI's startup inspection completed, the new helper, `android-bridge`, and all scripts were staged. `Context.createDeviceProtectedStorageContext().filesDir` created the app-owned `/data/user_de/0/io.github.pocketufw.alpha/files` directory; read-only `udp-config read` reported `mode=AUTOMATIC` and no committed configuration file. `android-bridge inspect` returned `root=GRANTED`, `config_mode=AUTOMATIC`, and `state=ACTIVE`. Magisk boot hook remains `ENABLED`.
- No manual rule or committed setting was applied. Live IPv4 UDP `41476` and IPv6 UDP `45567` exception rules were unchanged. Four unsolicited Wi-Fi UDP probes per family raised IPv4 DROP counters **140 → 144** and IPv6 **42 → 46**. Tailscale ping from Arch initially used DERP for one probe and then returned via a direct LAN IPv4 endpoint at `<MOTO_LAN_IP>:41476` in 93 ms.
- **Pending:** human opens Status → About/edit VPN exceptions to confirm explanatory UI and two warning dialogs; later a deliberate Experimental trial (same ports first) and Committed→Automatic round trip, plus a **separate user-approved Moto reboot** to prove committed ports truly restore. Do not claim that the advanced editor's manual workflow or committed reboot is yet validated on real hardware.

### Alpha13 editor wording and reset semantics (November 2, 2026)

- The tester requested less ambiguous descriptions of Experimental and Committed UDP exception lifetimes and a clearly named reset control. Experimental changes do **not** disappear when the app is closed or Tailscale reconnects. A firewall rebuild (off/on or reboot) discards temporary edits; Refresh VPN may replace them in automatic mode. Committed values are saved until edited, reset, or app data cleared and are restored on firewall re-enable, including after reboot when Magisk boot restoration is enabled.
- The UI now makes `Reset to automatic VPN exceptions` available while the verified firewall is ACTIVE, regardless of whether saved mode is Automatic or Committed. It calls the existing verified Tailscale refresh and clears any committed choice; if no listeners are detected, the resulting exception list may be empty. An explicit confirmation describes this, and failure does not claim success.
- This is an **editor presentation and access-control** change, not a new kernel policy. Final alpha13 built and linted with 110 passing tests, and all seven APK script assets matched source. Installed alpha13 (`versionCode=13`) in place on the Moto over alpha12. Before and after installation, verified firewall `ACTIVE`, Magisk boot `ENABLED`, saved `mode=AUTOMATIC`, and unchanged Tailscale UDP exceptions IPv4 `41476` and IPv6 `45567`. Arch's Tailscale ping used DERP on the first probe, then a direct LAN IPv4 endpoint on the second. No port edit was performed during the upgrade.
- **Pending on-device human test:** The tester confirms the new text and Reset button, including its visibility after an Experimental edit. No live Experimental or Committed port edit, reset action, or committed-mode reboot has yet been verified on the Moto.


## Pixel 9a, Android 17 alpha14 acceptance (November 2-3, 2026)

**Scope:** Owner-authorized, USB ADB-assisted beta validation on a rooted Pixel 9a running Android 17 (API 37), kernel 6.1.162, Magisk 31.1 and legacy `iptables`/`ip6tables` 1.8.11. All host-, carrier-, LAN-, and VPN-specific addresses, identifiers, and ports are intentionally omitted from this public report. This is experimental acceptance evidence, not a general Android 17 certification.

- **Build:** `0.1.0-alpha14` adds explanatory text limiting Experimental/Committed changes to PocketUFW-owned incoming VPN UDP port exceptions; no rule-engine logic change. The 114 Python tests, offline debug APK build and lint passed. The seven bundled shell assets matched source bytes. The debug-signed APK installed successfully on Pixel; the owner granted Magisk superuser access through Magisk's UI.
- **Initial enable and teardown:** PocketUFW's own bridge reported `ACTIVE` with three physical-interface `INPUT` hooks per IP family and `boot=DISABLED`; the original Android/WireGuard policies were preserved. A tested OFF operation removed all PocketUFW-owned hooks and chains from both families; ON rebuilt and verified them, again with boot restore off. Android's independently changing mobile-data quota values were not PocketUFW edits.
- **Wi-Fi ingress:** With VPNs operating, four deliberately unsolicited LAN UDP datagrams to an unbound port per address family increased kernel DROP matches by exactly 4 IPv4 and 4 IPv6. This tests actual selected packet enforcement, not total inbound coverage or an intrusion detector.
- **Automatic Magisk boot restore:** After opt-in, a physical reboot and USB-only audit **before opening PocketUFW** found the app process absent, all six `INPUT` hooks and both ordered chains present, the engine returning `ACTIVE`, packet counters collecting, and the boot hook enabled. Magisk's boot log recorded the service.d hook before Android boot completion. No app launch was required.
- **Tailscale after reboot:** With Tailscale initially stopped, the one-shot boot hook correctly created empty incoming UDP exception child chains. Starting Tailscale later required **Refresh VPN** to add its newly verified IPv4/IPv6 listener ports. A first peer probe timed out, but a later direct connection succeeded. The current design has no continuous VPN-port watcher; do not imply that boot restoration discovers later-created listeners automatically.
- **VPN coexistence:** The rooted kernel WireGuard interface carried the public IPv4/IPv6 routes, and Tailscale used a separate Android `tun` interface for its private routes. Public IPv4/IPv6 probes, DNS resolution, and bidirectional tailnet reachability worked while PocketUFW remained `ACTIVE` and Magisk restoration `ENABLED`.
- **Wi-Fi → mobile data → Wi-Fi:** With both VPNs and PocketUFW still active, USB ADB disabled Wi-Fi temporarily. Cellular data remained enabled; public IPv4/IPv6 probes and DNS succeeded over the kernel WireGuard route, and Tailscale traffic remained reachable in both directions (direct over cellular IPv6 in one probe). Wi-Fi was automatically re-enabled via a host-side cleanup trap. The phone rejoined Wi-Fi, internet probes passed, and Tailscale eventually selected a direct local endpoint without VPN or firewall reconfiguration.
- **Post-handoff packet proof:** Three controlled LAN UDP datagrams per family after Wi-Fi reconnection raised the verified IPv4 and IPv6 DROP counts by exactly 3 each. PocketUFW remained `ACTIVE`, boot restoration stayed enabled, and the saved VPN listener exceptions matched the running listeners.

**Limitations:** The cellular tests prove connectivity and survival of the transition, **not end-to-end unsolicited cellular inbound blocking**; carrier filtering and upstream Android/OEM rules may bypass or precede PocketUFW hooks. Voice, SMS, IMS, emergency calls, Alfred Camera, battery/standby impact, unusual kernel resets, and long-term repeated handoff cycles still require testing. The app does not filter inner VPN tunnel traffic and does not claim universal Android firewall coverage.


## Pixel 9a, Android 17 uninstall lifecycle and Proton reporting (November 5, 2026)

**Scope:** Owner-approved, supervised testing on the owner's rooted Pixel 9a (Magisk 31.1). The owner did the screen steps and unlocked the phone after each restart. A baseline was taken first, and the phone was returned to the signed Beta 5 it started on, with byte-identical boot files. Test packets were unsolicited UDP from a LAN host. A packet that reached the phone's stack was detected by its ICMP refusal, and a dropped one by the kernel counter.

**Ordinary uninstall, unmodified signed Beta 5, firewall on, boot restoration armed:**

- Android reported the app gone (`pm path` exit 1, no output) and its data deleted. All PocketUFW rule lines and boot files stayed, `verify` still said ACTIVE, and 5 of 5 packets were dropped.
- After a restart, Magisk ran the hook, the hook and data folder were gone, no rule lines remained, and 5 of 5 packets arrived. This is the first recorded hardware run of boot self-cleanup.

**Remove PocketUFW, debug build with the fix:**

| Case | Result |
| --- | --- |
| Armed and active | No rule lines or boot files, 5 of 5 packets arrived, and `INPUT` identical to baseline, all before Android's App info page was used |
| Back out, then Turn firewall back on | Rules returned, and boot restoration returned with them |
| Stage hook plus a file PocketUFW didn't install | Stage hook removed, the other file left untouched, App info not opened, "Still present: boot data folder" shown |
| PocketUFW's root turned off in Magisk | "Root access is needed for this action", App info not opened |
| Root restored, Try again, Uninstall, OK | Nothing left but an empty lock file in `/dev` |
| Restart afterwards | Nothing came back, and the lock file was gone |

**Changed boot hook:** a real restart with the app installed and closed restored the firewall, and 5 of 5 packets were dropped. With its marker deleted and the app uninstalled, a hand-run of the hook removed itself and its files and left the kernel alone. The README's manual cleanup commands then removed every rule. The rules of a kernel WireGuard tunnel appear and disappear with that tunnel, so comparing `INPUT` needs the same tunnels up.

**Uninstall keeping data:** after `pm uninstall -k`, `pm path` exits 1 and the data stays. Two hand-run boots both reinstalled the firewall, as documented in the README.

**Not tested on hardware:** `pm archive` failed with "No installer found" on this USB-installed build. A power cut during removal, a secondary user and an ordinary uninstall with boot restoration off were not run. Partial rules, another owner's hook, an interrupted removal and a transient package-manager answer were tested off-device only. Android removes the Quick Settings tile with the app, as it does for any app, so it has to be added again after a reinstall.

**Proton VPN, with kernel WireGuard and Tailscale off:**

- PocketUFW named the owner `ch.protonvpn.android`, and Proton used a `tun` interface. No earlier ACCEPT rule from Proton appeared. On Wi-Fi, 5 of 5 packets were still dropped.
- The first reading said "Not filtered" for a short-lived `ipsec` interface. Logs point to the carrier's Wi-Fi calling tunnel, not Proton, and it was gone seconds later. The screen kept showing it until the next recheck, because there is deliberately no polling.
- With only Proton's `tun` left, the app showed `KERNEL RULES VERIFIED` with no warning about the tunnel, apart from the footnote limiting coverage to physical interfaces.
- With Tailscale, 5 of 5 packets sent through its `tun` from a tailnet peer reached the phone and the drop counters did not change. So traffic inside a `tun` is not filtered. I had no way to send packets into Proton's tunnel, so this wasn't measured for Proton itself. With kernel WireGuard the app correctly says "Not filtered" and flags WireGuard's earlier ACCEPT rule.

**Interpretation:** every reading was true when taken, but the same limit is reported differently: named for kernel WireGuard and `ipsec`, and only in a footnote for `tun`.

The app now lists a `tun` VPN as not filtered too, named from Android's own VPN record, for example "traffic inside Proton VPN (tun0)", and describes `ipsec` as a carrier or VPN tunnel. The new bridge code ran on this phone under Proton and reported the right owner and interface. The wording itself ran only in JVM tests, because the phone stays on the older signed build until a new one is signed.

**An IPv6 drop spike after switching VPNs, identified:** the owner noticed IPv6 drops jump after switching to Proton, then go quiet. A repeat run with a read-only header capture on Wi-Fi and counters logged every 2 seconds found one sender for the captured Tailscale-port traffic: the owner's own PC, whose Tailscale kept trying the phone after Tailscale on the phone was turned off. Drops rose in steps of 3 about every 5 seconds and stopped about 9 minutes later. Part of each step was on a cellular hook, which was not captured. This was ordinary retry traffic correctly dropped, not an attack, and not an effect of Proton. It's also a reminder that a quiet counter says nothing about a VPN's quality: traffic inside a tunnel never reaches these counters. Most of those packets were aimed at ports other than the exceptions PocketUFW had open, which fits the documented gap that exceptions don't follow Tailscale's port changes, though the capture didn't confirm which ports Tailscale was using.

**Why IPv4 drops stop under Proton:** a follow-up capture of IPv4 and IPv6 headers on Wi-Fi, split by which tunnels were up.

| State | Phone's SSDP queries on Wi-Fi | SSDP replies to the phone | IPv4 drops |
| --- | --- | --- | --- |
| Kernel WireGuard and Tailscale, 97 s | 8 | 40, from one LAN device | +40 |
| Kernel WireGuard and Tailscale, 16 s | 2 | 18, from one LAN device | +16 |
| Proton, 260 s | 0 | 0 | +0 |
| No VPN at all, 297 s | 0 | 0 | +0 |

Proton did not cause the quiet: IPv4 was just as quiet with no VPN at all. The queries appeared only while Tailscale was up, including a moment without kernel WireGuard. That fits Tailscale's port-mapping probe, which looks for a router through SSDP, but the sending process wasn't identified. A LAN device answers by unicast, conntrack can't tie that answer to a multicast query, and the answer reaches the final DROP. Turning Tailscale off, as switching to Proton did here, stops the queries and so the answers.

**Side effect, not yet assessed:** answers to the phone's own SSDP queries are dropped while PocketUFW is active. If these are Tailscale's probes, it may not be able to map a port on the router, which could mean fewer direct connections. Any other app that finds devices through SSDP would be affected the same way. Neither effect was tested.

### Physical firewall and tunnel filter on the Pixel 9a (November 6, 2026)

**Why:** the owner saw zero drops with no VPN active, and earlier captures suggested that was because Tailscale's SSDP traffic had stopped. A quiet firewall is fine, but one that can't catch deliberate test packets isn't, so this tested that directly.

**Method:** development branch scripts pushed over adb, not an app build. Every run had a rollback timer armed, and the owner approved it first. Probes came from a host on the same Wi-Fi, to an unused port. A capture on the phone, limited to that port, counted what arrived.

**Physical firewall, no VPN at all:**

| Probe | Sent | Arrived at Wi-Fi | DROP count | DROP bytes | Other family |
| --- | --- | --- | --- | --- | --- |
| UDP IPv4, 64 bytes | 20 | 20 | +20 | +1840 | +0 |
| UDP IPv6, 64 bytes | 20 | 20 | +20 | +2240 | +0 |
| TCP SYN IPv4 | 10 | 10 | +10 | +600 | +0 |
| TCP SYN IPv6 | 10 | 10 | +10 | +800 | +0 |
| UDP IPv4, 200 bytes | 7 | 7 | +7 | +1596 | +0 |
| UDP IPv6, 300 bytes | 13 | 13 | +13 | +4524 | +0 |

- While filtered, the host got no replies, and the kernel's `NoPorts` counters didn't move.
- With the firewall off, the same probes raised `NoPorts` by exactly the UDP count, and every SYN was refused. So they did reach an unbound port.
- Nothing was sent for 25 s beforehand, and the counters stayed at 0.

**Interpretation:** the physical firewall works without any VPN, so the zero was a quiet network. With Tailscale up, IPv4 drops returned without any probes, 86 in one window of about a minute. That fits the earlier SSDP explanation, but SSDP wasn't captured again here.

**Rules ahead of the hooks:** the physical interfaces were `wlan0`, `rmnet16`, `rmnet17` and `v4-rmnet16`, all matched by the hooks. `fw_INPUT` was empty and `bw_INPUT` had no ACCEPT. `oem_in` was empty at first, then later held IPv6 DROP rules for the carrier IMS address on SIP-related ports, which came and went. Those packets never reach PocketUFW's counters, but nothing there accepts anything. Kernel WireGuard's port rule, ACCEPT on IPv4 and DROP on IPv6, exists only while that tunnel is up. Cellular hooks weren't probed, because a LAN host can't reach them.

**Rollback:** left unconfirmed, the physical timer fired at 180 s and the tables matched the baseline. With a tunnel install forced to fail partway and its cleanup also failing, one IPv4 hook stayed in the kernel, `verify` said `DEGRADED`, the state was `UNCLEAN`, and `confirm` and a second arming were refused. Once cleanup could work, the timer removed the rules within 3 s. With only the install failing, the engine's own cleanup worked and the rollback cancelled after reading the tables back clean.

**Tailnet, with both filters on and no refresh, tested three ways:** Tailscale already up, Tailscale coming up after the filter, and a force stop and restart.

- Ping 5 of 5 on IPv4 and IPv6, and new TCP connections carrying data on both.
- UDP to a closed port reached the kernel, 10 of 10 on each family, where it was tested. The force-stop run didn't include this check.
- A TCP connection opened before the firewall kept working after both filters went on.
- The owner's real file transfer, `scp` run in Termux to pull from another tailnet host over Tailscale SSH, delivered a file with a matching hash after the force stop.
- Rules stayed byte-identical through each restart. `tailnet=VERIFIED` followed Tailscale each time.
- A real Syncthing listener on the tailnet address accepted a TCP connection, but no sync was tested.
- Taildrop's peer API answered on both families, and the request reached the app, which was waiting for a folder to be chosen. The transfer didn't complete, for that reason.
- LAN probes still hit the physical DROP rules. The IPv4 and post-toggle IPv6 counts were exact. One IPv6 window read 14 for 11 probes, with the bytes showing 3 extra packets of other traffic.

**A gap this confirmed:** after the force stop, Tailscale's UDP ports changed and the physical exceptions kept the old ones until a `refresh`. The peers still reached a direct path in this run. This is the documented limit of having no watcher, and it isn't new.

**Not tested here:** a real unsolicited packet dropped inside a tunnel, which is lab only because nothing else can be sent into these tunnels from outside. Also kernel WireGuard with Tailscale, Proton, cellular, a completed Taildrop, a real Syncthing sync, and the SSH bridge.
