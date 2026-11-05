# Tide implementation

Implemented in `design/codex-ui`, based on Beta 4 (`55283ab`). Not merged.

## Behavior and structure

- Firewall / Activity / Settings navigation, light and dark appearances, bundled Fraunces / DM Sans / DM Mono, and the existing terminal penguin.
- The five protection states have distinct words and symbols. Checking never shows an off switch; busy operations retain the verified state and ignore additional power/boot taps.
- Counters retain unavailable values and failed-refresh feedback. IPv4/IPv6 drops, bytes, accepted replies, last read, and last manual reset are accessible. Large text and long counts use stacked layouts.
- Readable and selectable raw rules iterate the supplied lists directly. Rule descriptions never determine ordering. Unrecognized rules remain visible. The Beta 4 fixture shows ICMP control traffic before INVALID; a deliberately shuffled test proves the renderer follows its input instead of a built-in policy sequence.
- Reset counters opens a confirmation. Cancel and dismiss make no call. Confirm invokes the existing callback once. An unverified state closes a pending confirmation, and a busy state disables confirmation.
- The existing UDP warning, Experimental default, Committed confirmation, automatic-reset confirmation, validation, and saved/live messages remain intact. The editor is accessible from Settings and Kernel rules.
- Magisk startup settings, VPN refresh, Quick Settings guidance, root/degraded reporting, and experimental-build information remain available.
- Future Insights belongs beside Counters and Kernel rules in Activity. No placeholder, historical metrics, or logging has been introduced.

`MainActivity` retains the original `perform`, `recheck`, and dedicated counter-refresh functions verbatim. It supplies immutable presentation inputs and callbacks to `TideScreen`; no backend architecture was replaced. The firewall engine, client, bridge, boot scripts, tile service/cache, main manifest, launcher resources, and icon pack match the baseline.

The only intentional interaction change is the user-requested counter-reset confirmation. No periodic reads, network services, analytics, or font downloads are added to the app.

## Preview captures

[Overview](implementation/overview.png) · [Reset confirmation](implementation/reset-confirmation.png) · [Raw rules](implementation/raw-rules.png) · [Settings](implementation/settings.png) · [Dark, 160% text](implementation/dark-large-text.png)

These PNGs are rendered by the real Compose screens on an isolated Android 15 emulator. Measurements and rules are explicitly supplied test fixtures, not measurements from a protected device. The fixture code is in `src/androidTest`; it is not included in the application APK. Screenshots do not use a browser mockup. Normal captures use Compose's root capture; the confirmation capture includes the Android dialog window and system bars.

## Validation

- `:app:assembleDebug`, `:app:assembleDebugAndroidTest`, and `:app:lintDebug` pass.
- 11 Android Compose tests pass, including reset confirmation/cancel/state invalidation, busy/loading controls, input-order preservation in readable and raw views, unknown rule visibility, family selection, and enlarged-text navigation.
- Repository Python suite: 138 tests, passing with 1 existing skip. Two static layout-specific loading/busy tests were migrated to the behavioral Compose test; the dedicated read-only counter-refresh contract remains in Python.
- Two enlarged-text interaction checks also pass at 320 dp width and 160% text; narrow-screen captures are included.
- Visually reviewed the native firewall, counters, rules, exception details, reset dialog, all five states, and dark/enlarged-text screens.
- Existing AGP/compile-SDK and dependency-age warnings remain. No unrelated dependency upgrades or engine debugging were performed.

These are UI and integration checks, not a rooted-device firewall audit or a full manual TalkBack certification.

## Reproduce

From `android/`, with an Android SDK configured:

```sh
./gradlew :app:assembleDebug :app:assembleDebugAndroidTest :app:lintDebug
ANDROID_SERIAL=<test-emulator> ./gradlew :app:connectedDebugAndroidTest
```

To retain PNGs, install the debug and androidTest APKs on a disposable emulator, run `am instrument -w io.github.pocketufw.test/androidx.test.runner.AndroidJUnitRunner`, then pull `/sdcard/Android/data/io.github.pocketufw/files/tide-previews/` before uninstalling. Gradle's connected-test runner may clean up the app and its external files.

The debug APK is generated at `android/app/build/outputs/apk/debug/app-debug.apk`. Existing release artifacts are untouched. No hardware install, publishing, merge, or push was performed.
