# PocketUFW Android alpha

**v1 scope:** one-switch inbound firewall with honest counters, optional
Magisk restore, and verified VPN exceptions. Arbitrary custom iptables and
an advanced-rule builder are *not* part of this app. The research prototype
is not included in this public minimal v1 branch. See
[`docs/v1-scope.md`](../docs/v1-scope.md).

This directory contains the **Kotlin + Jetpack Compose** application for
PocketUFW. Experimental betas have been tested on a Moto G 5G (2024) and a
Pixel 9a; this is not a production release.

## New in the source-only alpha15 build (not yet installed on Pixel)

- The approved neon terminal penguin is the official launcher/adaptive icon
  and Home illustration; the themed monochrome icon and Quick Settings tile
  remain unchanged.
- About text reads the version from the generated BuildConfig, so a future
  alpha will no longer display a stale hardcoded alpha13 string.
- An optional, separate, permission-free Niagara icon-pack APK can be built
  with Gradle task :iconpack:assembleDebug. Its source and installation notes
  are in iconpack/README.md. Blaze Backless is never modified.
- This alpha15 debug APK was built and linted on Arch; live Pixel testing
  and installation are separate from the already verified alpha14 beta.

## Alpha17 active-tile candidate (local hardware acceptance pending)

The optional Quick Settings tile now uses Android's **active tile** mode:
opening the shade does not bind PocketUFW or call root. A completed
in-app root inspection or a deliberate tile tap updates a small unprivileged
last-verified-state cache and requests a one-shot tile repaint. The tile
shows the last check's date/time, never claiming a cached result is
"verified now." The cache is invalidated across reboot; opening the app
refreshes a post-boot status without modifying firewall rules. A short tile
tap still toggles using fresh kernel verification, with locked-screen
protection intact. No background service, root timer, or firewall-engine
changes were added.

## Alpha18 cosmetic tile icon (local hardware acceptance pending)

Quick Settings now uses its own tint-safe vector with transparent eyes, beak,
belly, flippers, and feet that remain legible when reduced to 24dp. The
original monochrome themed launcher icon and the neon app art remain unchanged.
No changes to root operations, Android tile behavior, or kernel rules.

## Hardware-tested capabilities in alpha14

- The selected terminal-penguin branding and simple one-switch interface
- Requests root via the device's existing `su` implementation (Magisk/KernelSU/APatch-style CLI)
- Each launch, explicit refresh, or control action uses **one** privileged session, combining command execution, rule verification, boot status, and counters; no repeated `su` requests just to redraw the dashboard
- The **Status** tab displays read-only IPv4/IPv6 firewall rules in a friendly format, clearly distinguishing Android’s unchanged INPUT default from PocketUFW’s incoming DROP policy; exact kernel syntax is available on demand and tab changes do not trigger root access
- Installs no daemon and requests no Internet permission
- Reads the real firewall state through the CLI's `verify` command before showing rules as active
- Expandable **Firewall activity** view displays real IPv4/IPv6 DROP counters, accepted established replies, a last-read time, and limitations. Counts are read on app open, after an operation, or with the explicit **Refresh counters** button. Magisk is not invoked on a timer. Run `pocketufw verbose` for a read-only CLI report
- Enables or removes PocketUFW-owned IPv4/IPv6 chains through the bundled CLI
- Uses verified Tailscale UDP listener detection on enable; offers manual port refresh
- Reports errors and permits removing partially installed rules

**New installations start with protection off.** Installing or opening the app does not itself modify firewall rules. An app upgrade preserves the existing kernel firewall state.

## Limitations

- **Optional** Magisk late-start boot restoration, disabled until the owner enables it. No persistent Android process; supported only on Magisk for now.
- No continuous VPN monitoring, and no automatic repair of degraded or unexpectedly reset rules after boot
- The Android GUI checks the existence of required firewall rules, not end-to-end
  packet enforcement. Upstream Android or OEM chains may still bypass these hooks.
- Currently assumes Android devices with `iptables` legacy support and physical
  interfaces matching the CLI's documented patterns
- Root authorization must be granted by the phone owner in their root manager.
  A superuser toast **may still appear once** per user-triggered operation,
  depending on Magisk/root-manager settings; PocketUFW does not suppress it.
- No stable release signing key; **debug-signed only**

## Build on Arch

Install a Java 17 JDK and Android SDK with Android API level 36. Set the
`ANDROID_HOME` environment variable or configure an **ignored**
`android/local.properties` with `sdk.dir=/path/to/android-sdk`.
The wrapper uses Gradle 8.9.

```sh
cd android
./gradlew :app:assembleDebug
```

The build automatically bundles the current repository-root `pocketufw` and
`vpn-probe`, `bootctl`, `boot-service`, and `android-bridge` scripts. The
CLI remains the sole source of firewall-rule logic.

The APK is produced at:

```text
android/app/build/outputs/apk/debug/app-debug.apk
```

## Deploy to an authorized test phone

```sh
adb devices -l
adb -s DEVICE_SERIAL install -r --no-incremental app/build/outputs/apk/debug/app-debug.apk
adb -s DEVICE_SERIAL shell am start -n io.github.pocketufw.alpha/.MainActivity
```

Approve the app's Magisk/KernelSU/APatch root prompt **manually**, if prompted.
A new installation is initially off. Do not enable PocketUFW alongside AFWall+'s active
rules. Keep USB ADB access and a tested rule-cleanup path available while testing.

If the app cannot be used but USB ADB and root remain available:

```sh
adb -s DEVICE_SERIAL shell 'su -c "sh /data/user/0/io.github.pocketufw.alpha/files/engine/pocketufw disable"'
```

Do not delete the app's private files while its firewall rules are active.

## First device smoke test (Moto G 5G, Android 15)

- Built from the local SDK using offline Gradle.
- APK installed and launched without a detected application crash.
- Verified the APK bundles byte-identical current firewall scripts.
- The root-side CLI reported `INACTIVE` before activation.
- A separate supervised test of the updated engine on Moto returned `ACTIVE`
  with all expected rules installed and `INACTIVE` after removal.
- Actual UI switch operation still requires the phone owner to approve the
  Android root-manager prompt; this approval is deliberately **not automated**.

## Alpha3 kernel-counter validation (Moto, Android 15)

- Updated the existing app in place while PocketUFW rules were active. The
  kernel firewall remained `ACTIVE` before and after installation.
- The bundled `activity` command returned verified IPv4/IPv6 DROP counters.
- Arch sent four controlled unsolicited UDP packets over Wi-Fi to the Moto.
  The Moto's IPv4 DROP counter increased from **27 to 31**, exactly four.
- No NFLOG experiment rule remained installed, and no packet payloads were
  collected. The existing Proton VPN configuration and firewall policy were
  left unchanged.
- Alpha3 briefly polled counters every 10 seconds, but Magisk produced a
  superuser toast on every read. Alpha4 intentionally removes the timer and
  restores **Refresh counters** as a user-triggered action.
- No background app service or durable counter history is created.

## Alpha4 Magisk boot-restoration validation (Moto, Android 15)

- Optional boot restoration was installed under root-owned `/data/adb/pocketufw/`
  and a Magisk `service.d` hook, with restrictive permissions.
- The installed one-shot hook was idempotent when PocketUFW was already ACTIVE.
- Removing only PocketUFW's active rules, then running the hook, restored the
  verified firewall from INACTIVE to ACTIVE. Proton's route was still in place.
- A physical reboot completed successfully. USB ADB reconnected afterward,
  and a root-side audit confirmed Android boot complete, PocketUFW `ACTIVE`,
  and Magisk restoration `ENABLED`.
- After that reboot, four unsolicited UDP test packets sent from Arch increased
  the Moto's verified IPv4 DROP counter from **35 to 39**. IPv6 remained zero.
  This verifies both restored firewall rules and live kernel counting.
- Boot restoration is not continuous VPN monitoring. If Android/OEM resets
  the rules later or Tailscale ports change, automatic repair is not provided.
- Disabling the firewall from the app first removes the Magisk startup hook.
  To uninstall the app safely, switch protection off first.

## Alpha5 single-root-session validation (Moto, Android 15)

- The older Moto Magisk build reported version code **30700**. Alpha4's
  dashboard previously started separate `su` commands for root identity,
  rules, boot status, and counters, and the root manager showed repeated toasts.
- Alpha5 bundles these checks into one root process per screen opening, manual
  refresh, or user-triggered operation. One process executes the desired
  action and immediately audits its result before reporting success.
- The Android GUI does not run a privileged daemon or periodic poller.
  Root-manager notifications remain under the owner's control.
- **58 automated tests** pass, including isolation tests that refuse to
  overwrite existing rules on a failed enable and verify rollback after
  incomplete installation. Android Lint reports zero errors.
- The updated APK was installed on Moto. The single-session bridge returned
  `ACTIVE`, `boot=ENABLED`, and genuine IPv4/IPv6 counters.
- In live Moto tests, the bundled bridge switched PocketUFW off and back on,
  restored the Magisk boot setting, and refreshed VPN exceptions. Each action
  returned its verified final state without additional UI-level `su`
  invocations. Proton remained connected; the final state was `ACTIVE` with
  boot restoration `ENABLED`.
- Reinstalling firewall rules resets the kernel's per-rule counters. Packet
  totals are not persisted across restarts or on/off cycles.
- The actual number of *visible* Magisk toasts still needs confirmation from
  the phone owner, since this may differ between Magisk versions.

## Alpha6 faster dashboard audit (Moto, Android 15)

- On Alpha5, the root bridge invoked the CLI's full `verify` check and
  then `activity`, which performs that same verification before reading
  the kernel counters. Those duplicated tests took ~2,016 ms total in one
  timed Moto sample (not including launching `su` or rendering Compose).
- Alpha6 uses `activity` as the verified status **and** counter source,
  falling back to `verify` only when counters cannot be read reliably.
  It never substitutes zero for unavailable counters.
- The optimized bridge returned `ACTIVE`, `boot=ENABLED`, and kernel
  counters in ~1,130 ms on Moto in the equivalent single sample.
- **59 automated tests** pass. Android Lint reports zero errors.
  The updated APK launched and left the firewall ACTIVE, boot restore
  ENABLED, and the VPN setup unchanged.
- Opening the dashboard still asks Magisk for root once to verify live
  protection; it does not generate repeated requests or run a background
  app service.
- A truly silent dashboard would need an independently maintained status
  snapshot with a freshness label. Showing stale state as newly verified
  protection is intentionally out of scope.

## Alpha7 read-only Status tab (Moto, Android 15)

- A new **Home / Status** tab shows a compact UFW-style policy summary and
  ordered IPv4/IPv6 rules. The optional "Show raw kernel rules" control exposes
  the actual PocketUFW INPUT hooks, POCKETUFW_IN chain, and POCKETUFW_TS
  exceptions obtained from live iptables/ip6tables reads.
- Reports include the **actual Android-owned INPUT policy**, configured
  physical interface hooks, listener UDP exceptions, and a read time.
  The Android ACCEPT policy is not misrepresented as system-wide DROP.
- Rule reporting is **read-only**, bounded in size, and requires both families
  to succeed before the GUI accepts a complete report. Missing, malformed,
  or incomplete reports display as unavailable, never invented rules.
- The same single-root session supplies verification, counters, boot status,
  and rule snapshots. Switching tabs or expanding raw rules does **not**
  request another Magisk authorization or change the firewall.
- This snapshot describes PocketUFW-owned rules, **not** proof that earlier
  Android/OEM INPUT rules cannot accept traffic before our hooks.
  No packet-event logger is installed; DROP counters remain available.
- On the Moto, Alpha7 installed successfully. The integrated root bridge
  returned a complete kernel rule report for both address families, including
  Android INPUT policies of ACCEPT, the three physical-interface hooks per
  family, all eight inbound rules per family, and no current VPN exceptions.
  The firewall remained ACTIVE and Magisk boot restoration ENABLED.
- **67 automated tests** pass; Android Lint reports zero errors.
- A device-side accessibility visual check was inconclusive because Android
  was showing its notification shade rather than the app content. The UI
  compiles and the rule data path is verified, but the Status tab still needs
  a human visual check on the test phone.

## Security and privacy

- No accounts, analytics, advertisements, or INTERNET permission
- `ACCESS_NETWORK_STATE` is used only to show whether Android reports a VPN
- No network telemetry or upload code
- Scripts come from the APK, staged in the app's private data directory
- App does not alter other managers' rules or default chain policies

The broader product goals, remaining tasks, and limitations are in the root
[README](../README.md).

## Alpha8 Status labels (Moto, Android 15)

- Made the distinction explicit: Android's live INPUT fallback policy appears
  as `Android default: ACCEPT (unchanged)` and the verified PocketUFW policy as
  `PocketUFW incoming: DROP unsolicited`. This does **not** change the actual
  firewall rules or claim PocketUFW supersedes earlier Android/OEM ACCEPTs.
- Upgraded the existing Moto alpha7 installation in place. PocketUFW remained
  `ACTIVE`, Magisk boot restoration `ENABLED`, and Proton's `tun0` route intact.
  The Status-tab accessibility tree showed both updated labels after launch.
- All **67 automated tests** passed; Android `assembleDebug` and `lintDebug`
  succeeded. The two existing Kotlin system-bar deprecation warnings remain.

## Alpha9 rule-verification and rollback hardening (November 1, 2026)

- The engine now requires the installed eight-rule inbound target sequence in each address family, not just unordered membership and final DROP.
- VPN exception child chains must contain zero or one explicit UDP port ACCEPT rule; an unexpected broad ACCEPT degrades verification rather than allowing a false ACTIVE status.
- After a fresh enable, the engine verifies both installed families before committing success; an invalid readback triggers the existing owned-rule rollback.
- Two regression tests first reproduced false ACTIVE from reordered inbound rules and an injected child-chain ACCEPT; additional tests cover legitimate VPN ports and a simulated bad post-install readback. **71 Python tests pass locally.**
- This hardens verification, not system-wide enforcement: earlier Android/OEM ACCEPTs, unsupported interfaces, and other firewall managers still require separate coverage checks.
- **Moto validation passed:** alpha8 upgraded in place to alpha9, the new engine and updated Magisk boot copy matched by SHA-256, live IPv4/IPv6 UDP drops rose by 3 each, and both HTTPS families worked over Proton. The firewall remained ACTIVE and boot restore ENABLED. Build/lint completed successfully with existing system-bar deprecations and AGP compileSdk warning. Physical reboot with alpha9 is still untested. See `docs/hardware-validation.md`.

## Alpha10 optional Quick Settings on/off tile (November 2, 2026)

- **This is a toggle**, not merely a status-check button. Tapping reads the *current* kernel state under one `su -c` session, then enables or disables PocketUFW and checks the result. A DEGRADED/unknown state refuses the switch; errors show a transient message. No continuous process watches the firewall.
- When Android opens Quick Settings, its non-active (standard) tile service briefly binds, issues one read-only root inspection, and reports ON/OFF only after verification. It does not claim a remembered green tile is fresh. Frequent shade openings may show Magisk superuser toasts; this is a tradeoff to validate live state without a resident service. There are **no periodic root calls**.
- Turning protection OFF also disables Magisk boot restoration; app preferences remember whether the user had opted into it. Turning ON rearms it only if previously enabled. Explicitly switching boot restoration off in the app clears that preference. Root reporting includes the prior boot setting, so even an immediate tile tap can preserve it.
- Android requires unlocking before a Quick Settings tap can change the firewall, including when the tile is visible on the lock screen. Long press follows Android's normal tile behavior.
- Tested locally: **82 Python tests passed**, including mocked toggle on/off, boot opt-in restoration and failure, unknown-state refusal, plus tile manifest security checks. Debug APK **alpha10** assembled and Android lint succeeded; same existing AGP compileSdk warning and Kotlin system-bar deprecations. The built APK contains the declared `FirewallTileService`, toggle metadata, and system bind permission.
- **Moto upgrade performed after alpha9 reboot validation.** Alpha9 restored automatically without opening the app, dropped 4/4 Wi-Fi UDP probes in each IP family, and maintained IPv4/IPv6 HTTPS. Alpha10 then upgraded in place; the new bridge file and remembered Magisk opt-in were verified, followed by 3/3 post-upgrade drops per IP family and successful dual-stack HTTPS. The tile's UI behavior, one-shot root checks, Magisk toasts, and OFF/ON round trip still await hands-on interaction. See `docs/hardware-validation.md`.

## Alpha11 long press and UI loading polish (November 2, 2026)

- the tester's hardware testing of alpha10's optional QS tile showed the expected live initial ACTIVE verification and successful OFF/ON toggle, including the transient `Switching...` label. After re-enabling, a supervised check showed the saved Magisk boot opt-in enabled, 3 hooks per IP family, reset counters, and 4/4 controlled unsolicited UDP drops in IPv4 and IPv6. The OFF state was observed by The tester but was not caught by ADB before the next ON tap.
- While viewing the tile, Android briefly displayed `Checking kernel...` a second time. The tile has no timer; repeated `onStartListening` callbacks are possible. If this becomes disruptive, improve tile lifecycle presentation without claiming stale verification.
- An alpha10 long press opened Android App Info. Alpha11 adds the documented `ACTION_QS_TILE_PREFERENCES` activity intent filter targeting `MainActivity`; ADB resolved the exact implicit intent to the dashboard after installing alpha11 on the Moto. A physical long-press test is still needed.
- A fresh launch previously displayed unchecked switches during the approximately two-second root read. Alpha11 shows a neutral `Checking kernel protection` panel until the first verified snapshot. The primary firewall switch previously dimmed while a Magisk boot toggle action was running because all switches used `enabled = !busy`; alpha11 keeps that switch's visual state steady and ignores any new taps while the root action is busy. Both fixes need human UI confirmation.
- **85 Python tests passed** including dedicated loading/busy-state and tile intent contract regressions, and `assembleDebug` plus `lintDebug` succeeded. Two preexisting Kotlin system-bar deprecations and the AGP 8.7/compileSdk 36 warning remain. Installed alpha11 as an in-place debug upgrade; the firewall stayed ACTIVE and the Magisk boot hook ENABLED. No PocketUFW kernel-rule or boot-engine changes in this alpha.

## Alpha12 Advanced UDP policy (November 2, 2026)

- **Status tab only:** An expandable `About / edit VPN UDP exceptions` explanation includes live IPv4/IPv6 listener ports, committed mode and saved values when present, then gates editing behind `Warning: advanced users only`. `Experimental` is the default, and applies to current live rules without persistence. `Committed` requires a separate `Are you sure?` dialog and stores one UDP port per family for future firewall enables and, when Magisk restoration is enabled, reboot. Blanks mean `none`. An explicit `Reset to automatic VPN exceptions` action resets both saved Committed settings and temporary Experimental changes after verified listener refresh.
- `udp-config` validates numeric 1–65535 decimal ports or `none`, rejects symlink paths and malformed files, and writes atomically at `Context.createDeviceProtectedStorageContext().filesDir/udp-committed.conf` using root access. App private storage is removed by Android upon uninstall; no orphaned long-term root preferences. A boot-enabled Magisk snapshot includes the helper and reads committed ports from device-protected app data, before unlock, through a strict parser. No shell sourcing of saved data. The normal boot hook remains one-shot.
- `pocketufw get-ports` verifies live firewall hooks and child-rule grammar before reporting actual ports. `set-ports --udp4 PORT|none --udp6 PORT|none` uses existing transactional replacement/rollback, never rewriting the parent inbound rules or Android-owned policies. The Android bridge now supports `set-ports IPv4 IPv6 experimental|committed` and `use-auto`, with one `su -c` session per user action, fail-closed validation, and rollback attempts for failed writes or boot snapshot rearming. A committed choice overrides automatic discovery on future enables. Manual `Refresh VPN` refuses to override a committed choice.
- Safety limits: no TCP or arbitrary rules editor; unknown/degraded rules refuse editing; manually committed Tailscale UDP ports can rotate and break direct connectivity. The advanced UI warns twice before a committed save. `Experimental` changes are temporary until the next rule rebuild or verified refresh.
- Full offline tests: **109 Python tests** passed after the final packaging test, including live ruleset mocking, boot-mode persistence and corruption handling. `:app:assembleDebug` and `:app:lintDebug` were successful for the initial alpha12 candidate, subject to the same existing AGP compileSdk and Kotlin system bar warnings. The final APK contains all seven identical source scripts and was installed in place on the Moto. The new device-protected app directory and read-only bridge inspection passed; live committed-mode reboot still needs separate human validation.

## Alpha13 terminology and recovery polish (November 2, 2026)

- Experimental text explains **exactly** when a live-only edit is replaced: turning the firewall off/on or rebooting rebuilds rules, and Refresh VPN may replace it when automatic detection is active. Closing PocketUFW or reconnecting Tailscale does **not** reset it.
- Committed text explains the saved lifetime: until edited, reset to automatic, or app data removal, and that restoration on reboot requires Magisk boot restoration.
- `Reset to automatic VPN exceptions` is now always offered while live protection is verified, including immediately after an Experimental change with no committed file. It opens a confirmation stating it replaces the current ports with **verified Tailscale listener ports** (or none when no listeners are detected), and that a failed detection leaves existing settings unchanged. The existing single-root-action `use-auto` path is reused; no new persistent service, firewall-engine policy or Android permissions.
- Focused regression covers Experimental→automatic reset; prior engine tests cover transactional Tailscale refresh and Committed→automatic clearing. All 110 tests passed. The alpha13 APK built and lint passed, and all seven bundled scripts matched source. It was installed in place on the Moto, with read-only verification that the firewall and Tailscale exceptions remained unchanged. The revised UI wording and reset button still need human visual confirmation.


## Alpha14: scope-copy clarity and Pixel 9a beta (November 2-3, 2026)

- The Status → incoming VPN UDP exceptions section now explicitly distinguishes its Experimental/Committed **port exceptions** from global Android firewall policy and outgoing traffic. An allowed UDP port admits inbound traffic to that port on supported physical interfaces; it is not limited to authenticated Tailscale packets.
- `versionCode 14` / `0.1.0-alpha14`; 114 Python tests, debug assemble and lint passed. No backend script, permission, or long-running service change.
- First Pixel 9a/Android 17 USB ADB beta passed verified enable, clean disable, re-enable, real dual-stack LAN DROP increments, boot restoration **without app launch**, simultaneous kernel WireGuard plus Tailscale, and one Wi-Fi → cellular → Wi-Fi handoff. Tailscale ports needed manual **Refresh VPN** after its later post-boot start. See [hardware validation](../docs/hardware-validation.md) for precise evidence and limitations.
- Do not generalize to carrier voice/SMS/IMS safety, all Android devices, long-term standby or verified global inbound coverage. The app remains an experimental debug build.
