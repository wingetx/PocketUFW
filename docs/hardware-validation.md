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
