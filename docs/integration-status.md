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
