# PocketUFW current handoff (2026-11-05, Beta 5 pre-release)

**Canonical project:** `~/toolbox/projects/PocketUFW`
**Active branch:** `fix/integration-audit` (local head `16dc742` when this handoff was prepared; check Git for later commits).
**Published release:** Beta 4 on GitHub `main`. **Beta 5 is not published or merged to `main`.**

## Current build and validation

- Beta 5 (`0.1.0-beta5`, versionCode `26`) contains the audited integration, confirmation before turning the firewall off, and one UDP customization entry point under Settings. Commit `16dc742` is local and not pushed yet.
- 407 Python tests (1 skipped), 174 Android JVM tests, debug/unsigned release builds, and lint passed. 15 isolated **real Linux kernel** packet-filter tests passed. Those do not substitute for Android uninstall/reboot validation.
- The signed Beta 5 candidate was created with the original PocketUFW release keystore. Its certificate matches published Beta 4 (`SHA-256: 29cac70ee30ed8ab26676aeb60809bdf668f3ad3428eab556316970ce1f99ad2`). Candidate is in `android/app/build/outputs/apk/release/PocketUFW-0.1.0-beta5.apk`, a generated/untracked build artifact.
- Beta 5 was freshly installed on Jay's rooted **Pixel 9a / Android 17**, after an earlier uninstall; app launched and reported existing active rules. The Moto audit covered the preceding audited code, not the new uninstall problem. No Beta 5 release has been uploaded or tagged.

## Release blocker: uninstall leaves an active firewall

**Observed on Pixel 9a:** After the PocketUFW app had been uninstalled, root-owned `/data/adb/service.d/pocketufw.sh`, `/data/adb/pocketufw/boot.enabled`, and `/data/adb/pocketufw/pocketufw` still existed, and both IPv4 and IPv6 `POCKETUFW_IN` chains with physical-interface INPUT hooks remained installed in the running kernel. Reinstalling signed Beta 5 found the firewall active and retained its counters. This is a real usability/security ownership problem: without the app, there is no normal UI to turn it off.

**Existing behavior:** `boot-service` checks on **next boot** whether the app is gone and its device-protected data absent, and then removes *its own boot hook and root-owned copies*, but this does not remove kernel rules during the same running session. An ordinary Android uninstall does not reliably call app cleanup code. Do not claim that a broadcast receiver inside the uninstalled app will run, or that removing the boot hook alone immediately removes live rules.

**Requested next work:** Ask Claude to independently investigate Android uninstall semantics and propose the least invasive, reliable lifecycle solution, then implement and test after design review. Candidate: explicit in-app **Remove PocketUFW** flow that shows what will happen, removes only verified PocketUFW-owned rules and boot files, confirms the resulting kernel state, and only then opens Android's uninstall UI. Keep standard uninstall and next-boot outcomes honest, including cleanup failures, partial rules, interrupted operations and uninstall without use of the in-app flow. No persistent watcher unless clearly justified. Avoid changing unrelated Android/OEM, Tailscale, WireGuard or VPN rules.

**Testing gate:** Use isolated kernel/bridge/UI tests and a disposable rooted test device for uninstall/reboot scenarios before considering a release. Do **not** uninstall, reboot, reset, or alter Frankenpixel's live firewall/VPN/root state without explicit approval. Have an independent audit of this new root/uninstall boundary. Do not publish Beta 5 until resolved or the remaining limitation is explicitly accepted and clearly documented.

---

## Historical handoff (superseded where it conflicts with the current status above)

# PocketUFW integration handoff (2026-11-05)

**Branch:** integration/pocketufw-next
**Baseline:** GitHub main 55283ab (published Beta 4 source).
**Status:** all three development branches merged *locally*, not pushed, not released. An independent audit then found defects this document's "validation green" didn't catch. Fixes are on `fix/integration-audit`, and that debug build has run on the Moto test phone. See `docs/audit-fixes.md`.

**Out of date below:** the statements that the bridge, engine, tile and boot scripts match `main`, and the test counts. Commits `bf0df24` and `2647d6d` changed `pocketufw` and `android-bridge` after this was written, and `fix/integration-audit` changes the rest.

## Integration history

1. Codex Tide redesign, design/codex-ui at 3998d5b, merged into the integration branch in 0a3ed73.
2. Claude audit fixes, fix/claude-audit at 74db0c5 (source fixes 301c393), merged into Tide in 1e77d10. The integration resolves shared Compose files using Tide's components and ports Claude's behavioral rules into them.
3. Frontier's Insights diagnostics, feature/drop-insights at 3a2fe65, merged in db655b5. **Development-only** CLI tooling, an offline NFLOG parser, and mocked tests; no Android Insights screen/capture service has been shipped or enabled.

All three original working trees and GitHub main remain unchanged.

## Behavior kept from Claude's audit

- Result/progress messages stay in a fixed Scaffold snackbar slot outside the scrolling content. Counters cannot accidentally receive a repeat tap from Refresh VPN's result shifting the UI.
- Reset counters already requires a confirmation in Tide; Remove partial rules now also asks first and explicitly mentions disarming the Magisk boot hook.
- A failed counter read withdraws the verified claim while retaining the last measured numbers. Recheck is required before destructive actions.
- On window focus return, the UI first reads the lightweight tile-status stamp and re-inspects the firewall only if the stamp changed. There is no polling or unconditional root request on shade-open.
- Unknown boot-restoration states show specific text instead of an off-looking switch.
- Automatic VPN exception labels do not claim live port verification. Refresh VPN is disabled in Committed/DEGRADED/UNKNOWN configuration modes and explains why.
- Counters remain per-family, missing values are never represented as zero, and historical timestamps include the date.
- Kernel rules remain in the actual supplied kernel order; unknown rules remain visible, and the diagnostic NFLOG target isn't mislabeled as DROP.
- Kotlin screen updates use the main dispatcher explicitly, preserving the original audit's race fix.

**Deliberately unchanged:** the Quick Settings tile and its behavior after reboot, plus all seven firewall/boot/bridge scripts, tile-status cache, Android manifest, signing and netfilter rules. The earlier unknown-tile policy trade-off was not reopened.

## Verification on the merged source

- **181 Python repository tests run; one skipped; none failed.**
- **11 Tide-adapted JVM Compose tests pass** under Robolectric API 34, plus 12 Python static audit contracts within the 181 tests. The original Claude 78 JVM tests target the retired pre-Tide UI and remain available in commit 301c393. They have not been falsely counted as tests of Tide.
- **Debug and unsigned release APKs build successfully**, and instrumentation test APK compiles.
- **Android lint passes**, previously 0 errors and 3 warnings.
- **All seven scripts embedded in the debug APK exactly match the repository sources by SHA-256.**
- No protected engine, Quick Settings, tile-status, boot, or bridge paths differ from main.
- No emulator is currently connected/available on Arch, so **the merged build's Android instrumentation tests have not been executed**. Codex ran the pre-merge Tide instrumentation suite independently (reported 11 passes).

There is no signed release APK, upload, main merge, or Frankenpixel install.

## Important remaining gates

1. **Android integration and UX validation:** run the combined build's Compose instrumentation tests on an emulator or spare rooted device, including reset confirmation, focus/shade transitions, stale-state display, exceptions and enlarged text. Follow Claude's device test checklist in docs/audit-fixes.md. Avoid using Frankenpixel as the first test target.
2. **Insights is NOT production-ready:** The developer-only capture runner temporarily adds NFLOG rules, which the strict eight-rule verifier currently sees as DEGRADED. It has offline rollback tests only. Before any production UI or live capture, coordinate diagnostic state and serialization, safe crash/reboot cleanup, native collector availability, and verified packet-counter preservation. See docs/insights-capture.md.
3. **Root and tile validation:** a real Android device must check root prompts and Quick Settings focus without repeated Magisk toasts. Never change the existing tile's post-boot behavior merely to cosmetically differentiate UNKNOWN from OFF.
4. **Security/release gate:** review signed APK lineage, leave all existing firewall policies unchanged, verify no new root or background capabilities, and manually test kernel rule invariants before publishing a version greater than Beta 4.

## Re-run commands (Arch)

    cd ~/toolbox/projects/PocketUFW
    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests

    cd android
    ANDROID_HOME=$HOME/toolbox/projects/android/Sdk \
    ANDROID_SDK_ROOT=$HOME/toolbox/projects/android/Sdk \
      ./gradlew --offline :app:testDebugUnitTest :app:assembleDebug \
      :app:assembleRelease :app:assembleDebugAndroidTest :app:lintDebug

**DO NOT** install the newly built debug APK over Frankenpixel's signed Beta 4. It is not the signed release candidate.
