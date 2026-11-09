# Round-two UI follow-up

Worktree: `fix/tide-operation-progress`. Original evidence at
`android/build/ui-acceptance/round2/` in the main checkout is read-only.

## Unexpected activation: findings and limits

The confirmed lifecycle defect is the default `standard` launch mode. Explicit
MAIN/component and QS_TILE_PREFERENCES starts can create independent MainActivity
compositions, each with its own verified snapshot and busy guard. The process-wide
root-session mutex serializes commands; it cannot reject stale user intent from
another screen. A retained callback from a paused screen could start a mutation.
The new lifecycle regression reproduces that last defect before the fix.

Statistics itself only toggles local expansion state. The before-tap screenshot
and XML show separate hit areas: the activation text is at y=899–937, Statistics
at y=1297–1335 (1080×2424). No overlap explains the observed activation. The
logcat excerpt records window creation/destruction but contains no MotionEvent,
input target or focused-window trace. There is no recorded tap coordinate.
**The evidence does not establish that a touch passed through to the lower
Activity, nor does a host test reproduce that Android input-routing failure.**
Keep the activation issue pending the focused hardware retest below.

Both entry points now use `singleTask`, including when the task is backgrounded.
`onNewIntent` updates the intent without recreating the composition, navigation,
status or operation guard. `singleTop` alone would only cover an Activity already
at the top of the selected task. This follows Android's documented
[task and launch-mode behavior](https://developer.android.com/guide/components/activities/tasks-and-back-stack).
Mutation callbacks require a RESUMED lifecycle at dispatch; already-authorized
work still completes while backgrounded, retaining busy/progress state. No
cooldown, automatic enable, new root call, input interception or polling was added.
Existing Compose Back handling and the platform root-Activity Back behavior remain.

Host tests cover manifest resolution for both actions, repeated new-intent
lifecycle delivery, coordinate taps on Statistics while Off (including after
shutdown), rejection of a paused callback, busy-state retention and navigation.
Before the fix, the launch-mode, current-intent and paused-callback checks failed.
Robolectric does not simulate Android's ActivityTaskManager routing. The additional
`MainActivityEntryPointTest` instruments that routing on Android, counts created
Activities, launches from foreground and background, and taps Statistics using
pointer events. It injects a fake gateway before onCreate: no real root calls.
It is compile-checked locally, **not executed on a device/emulator**.

## Required supervised hardware retest (not run here)

Use a separately approved test build of this branch, the existing timing shim and
rollback procedure. Keep the original evidence; capture into a new directory.

1. Force-stop once to discard the old build's stack. Launch from the launcher.
   Verify protection Off with absent PocketUFW rules, and save IPv4/IPv6 tables.
   Do not force-stop between the remaining launch/tap checks.
2. While the app is open, run each launch repeatedly (at least three rounds):

   ```sh
   adb shell am start -W -n io.github.pocketufw/.MainActivity
   adb shell am start -W -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -n io.github.pocketufw/.MainActivity
   adb shell am start -W -a android.service.quicksettings.action.QS_TILE_PREFERENCES -n io.github.pocketufw/.MainActivity
   adb shell dumpsys activity activities
   ```

   Require exactly one live MainActivity history entry, not Hist #0 and #1 copies.
   Also actually long-press the QS tile, then repeat from Home and Recents. Do not
   short-tap the tile: that deliberately toggles protection.
3. On Firewall, scroll the Statistics pill into view. Save a screenshot, current
   uiautomator XML, activity/window dumps and timing-log offset before each tap:

   ```sh
   adb shell uiautomator dump /sdcard/pufw-retest.xml
   adb pull /sdcard/pufw-retest.xml
   adb shell dumpsys window windows
   ```

   Read the **current** pill bounds from the XML, calculate their center `(x,y)`,
   record that coordinate, and issue exactly one `adb shell input tap x y`.
   Require the pill to expand/collapse, no enable/toggle/reset or other mutation
   in the bridge timing log, and byte-identical filter rules in both families.
   Repeat collapsed→expanded and expanded→collapsed after each entry point.
   Leave Off for 90 seconds to exclude delayed queued activation.
4. Under the existing rollback protection, intentionally turn on, then turn off
   and wait for verified Off. Repeat steps 2–3 immediately after shutdown and
   again after 60 seconds. This covers both the owner and delayed ADB cases.
5. Start an intentional Recheck, and separately an intentional activation. While
   each is visibly busy, relaunch via MAIN and tile long-press. Require one
   Activity, the same spinner/label, no extra mutation and no second initial
   inspection just from relaunching. After completion/shutdown repeat Statistics.
6. Open Settings/UDP exceptions, relaunch and use Back: internal navigation should
   return normally; Back from Firewall must not reveal another PocketUFW screen.
   Home/Recents should restore the same screen. Check TalkBack activation of the
   pill as well as the single coordinate tap.

If activation recurs, capture the exact x/y, window focus/input-target diagnostics,
activity stack and monotonic bridge timestamps together before another interaction.
Do not label the input mechanism resolved solely because singleTask is configured.
