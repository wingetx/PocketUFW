# UI audit fixes

Branch `fix/claude-audit`, from `main` at `55283ab`. Not merged and not released.

These are targeted corrections to what the existing UI claims and does. They make no visual redesign. Nothing in `pocketufw`, `android-bridge`, `bootctl`, `boot-service`, `rules-report`, `udp-config`, `vpn-probe`, the manifest, signing, or the app's release dependencies changed.

**None of this has run on a phone.** Evidence comes from JVM Compose tests: the real `PocketScreen`, real layout and text measurement, and real tap dispatch, driven by a fake firewall through Robolectric (SDK 34, native graphics).

## How to run the tests

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
cd android && ANDROID_HOME=/path/to/Sdk ./gradlew :app:testDebugUnitTest
```

Commit `8c4fae0` keeps the reset bug reproducing as a passing assertion, so it can be checked out and seen.

## Confirmed bugs, now fixed

Each of these failed a test on the unmodified UI, except where noted.

| Bug | Evidence on the old UI | Fix |
| --- | --- | --- |
| A repeat tap on **Refresh VPN** could land on **Reset counters**, which reset immediately | 20 of 24 width, text size, message and scroll combinations fired `resetCounters`. Content moved 72 to 159dp. The result was off-screen in 21 of 24 | Results moved to a fixed banner outside the scrolling column, so showing or dismissing one moves nothing. Reset now asks first |
| **Reset counters** had no confirmation | Test | Dialog stating what changes, what doesn't, and the counts being lost |
| **Remove partial rules** had no confirmation, and didn't say it also disarms the boot hook | Test | Dialog stating both |
| App kept showing **Firewall active / RULES VERIFIED** after the tile changed the firewall | Test: state stayed ACTIVE after the tile cache changed | On regaining window focus, recheck only if the tile cache's stamp moved. This also covers the shade, which never pauses the activity. An unchanged return requests no root |
| A failed counter read left **RULES VERIFIED** on screen | Test | The verified claim is withdrawn on both tabs, the switch is hidden, and the last counts are kept, until a recheck |
| DEGRADED and ROOT_REQUIRED drew an **off-looking firewall switch** while rules may still be in the kernel | Test | No switch unless on or off is known. Text now says unknown doesn't mean off |
| Four boot states drew an **off-looking boot switch** and shared one sentence | Test, one per state | No switch. Each state has its own text |
| **"Automatic · verified Tailscale listeners"** stayed on screen after an Experimental edit | Test, plus `android-bridge:215`: Experimental leaves the saved mode unchanged | "Saved mode: Automatic", with a note on where live ports can come from and that they can go stale |
| Rule table called any exception **"Verified VPN UDP port"**, including typed ones | Test | "VPN UDP exception, port N" |
| **Refresh VPN** stayed enabled in modes where the bridge always refuses it | Test, plus `android-bridge:192-197` | Disabled, with the reason shown, saving a pointless root request |
| **Byte counts** were parsed but never shown, and replies were summed across families | Test | Per family: dropped packets, dropped bytes, established replies. Missing bytes say "unavailable", never zero |
| Reset and reading times had **no date** | Test | Date shown unless the reading is from today |
| Summary said **"incoming packets blocked"**, adding two rules | Test, plus `pocketufw:243` | "packets matched DROP rules", with a note saying which rules and that rebuild times aren't recorded |
| Home printed **hooks as a fixed string** | Test using a different hook in the report | Read from the kernel report. A missing report is stated |
| **Policy sentence and "Not verified"** shown as fact when verified off, and **"Not granted"** shown when root was never confirmed granted or refused | Test | "Not installed", "Not confirmed", and a conditional sentence |
| A "Counters refreshed" note **outlived later operations** | Test | Each new operation clears the note and any earlier result |
| Refresh VPN's **progress appeared on the other button** | Test | Its own "Refreshing VPN…" label |
| **Accessibility:** tabs had no tab role or selection, the expand row had no state, results and status weren't announced, `ALLOW` wrapped at 200% text | Test, one per item | Fixed. The column now scales from its own 12sp text, because Android 14+ scales large sp values less than small ones |

Fixing these also added a blank reserved line for the refresh note, so its arrival doesn't move Reset, and section headings.

## Counter anomaly: cause not established

The confirmed tap path is one candidate. Nothing here shows it caused the anomaly you observed. To test it, check whether `last_counter_reset_at` in the `pocketufw` preferences moved when the anomaly happened. If it did not move, a completed tap on Reset is ruled out.

These can also zero counters, and the app records none of them: firewall off and on, two tile taps, reboot restore, a partly failed reset, a root shell, or any root process running `iptables -Z`.

## Test results

| Check | Result |
| --- | --- |
| Tests on the old UI | 37 of 44 regression tests failed. The other 7 guard behaviour that was already right |
| JVM UI tests | 78 pass: 54 behaviour tests, plus the 24-case reset matrix |
| Python tests | 149 ran, 1 skipped, none failed (140 existing, 9 new) |
| Repeat runs | 35 consecutive full JVM runs, no failures |
| Mutation testing | 20 fixes deliberately broken, one at a time, and all 20 caught, each by a test aimed at that fix. Run on the final source, which matched its recorded hashes afterwards |
| Build | `assembleDebug`, `assembleRelease` and `lintDebug` pass, with 0 lint errors |
| Release dependencies | Identical to the baseline. The release APK contains no test tooling |
| Engine in the APK | All seven scripts in the release APK match the repository byte for byte |

### A flaky test that was investigated, not retried

Two tests failed intermittently, about 1 run in 6. Logging showed `adopt` running on `DefaultDispatcher-worker-2`. Compose's test dispatcher resumes after `withContext(IO)` on the worker thread, so state was written during composition on the main thread, and an update could be lost. On a device, Compose's effect dispatcher runs on the main thread, so this race shouldn't occur there. `PocketScreen` now states that with `Dispatchers.Main.immediate`, which should change nothing on a device and removes the race from tests.

That guarantee has no mutation test of its own, because removing it only fails intermittently.

### Limits of this evidence

- Nothing ran on a phone, or on any API level other than 34.
- Fonts and insets under Robolectric only approximate a device, so exact shift sizes may differ.
- The firewall is faked, so these tests prove what the UI does with a result. They don't exercise root, Magisk prompts or the tile's system UI.
- Only three changed screens were checked by eye. Automated capture was unreliable under Robolectric.

## Still unresolved

**Suspected, not verified**

- The keyboard may cover the UDP port fields. There's no IME inset handling, and target SDK 35 enforces edge-to-edge.
- Rotation appears to lose the selected tab, expanded panel and result, and to run a new root inspection.

**Known and left alone**

- A partly failed reset can zero IPv4 but not IPv6. The bridge says "Could not reset all counters", but neither it nor the UI says which. Fixing it means changing the engine.
- The stale-state check only sees changes that update the tile cache. A root shell or another tool won't trigger it, so the screen shows when it last checked. There is deliberately no monitoring.
- Multi-line errors and changed status text can still reflow the page. The Reset dialog is the backstop.
- A double tap could in theory pass through the Reset dialog if its button lines up with Reset. The first tap has to be on Reset already, so I didn't add a delay.

**Needs a decision from you**

- The tile shows unknown as `STATE_INACTIVE`, and below API 29 there's no subtitle to tell it from off. `STATE_UNAVAILABLE` would be more honest, but makes the tile inert after every reboot until the app is opened.

**Left for the redesign, as design opinions**

Taglines, mint and amber use, the always-amber beta card, corner radii, the mascot and tile art, tab naming, 10sp raw rules. Moving strings to resources was also left out, because it would conflict heavily with the redesign.

## Test on Frankenpixel

Supervised, with a recovery path ready:

1. With Firewall activity expanded, tap Refresh VPN repeatedly. Counters must not reset, and the result must clear the gesture bar.
2. Reset counters: try Keep counts, then Reset. Check the date shown and `last_counter_reset_at`.
3. Open the shade over the app and toggle the tile. The status must update, with one root toast.
4. Leave the app and come back with no change. There must be **no** root toast. This protects the earlier fix for repeated shade-open toasts.
5. Deny root, let a prompt time out, and revoke root. The screen must show no switch, and the text must not imply the firewall is off.
6. Run an Experimental edit, then check the labels, and whether the keyboard covers the fields.
7. TalkBack: tabs, expand state, announcements.
8. 200% text and largest display size.
9. Rotate, including during an operation.

DEGRADED needs real partial rules, so prefer a spare device for that.

## UI contracts for Tide

The tests are the specification, and most find controls by their text. Port them rather than merging text, because Tide rewrote these files. Status below is from reading Tide commit `3998d5b`. I did not run it.

| Contract | Tide today |
| --- | --- |
| Results and progress never insert into scrolling content above a control | **Not met:** `TideNotice` and the "Working…" row sit at the top of the scrolling column |
| Reset counters and Remove partial rules run only after a confirmation | Reset met. **Remove partial not met:** it runs on tap |
| No on/off position unless verified. Boot switch only for ENABLED and DISABLED | Firewall button looks fine. **Boot switch not met** |
| "Verified" is withdrawn when a later read fails or the tile changes state | **Not met** |
| Regaining focus requests root only if the tile stamp moved. Never poll, never request root on shade-open | **Not implemented** |
| Never call ports verified. Saved mode and live ports stay separate | **Not met:** both old labels remain |
| Refresh VPN disabled, with the reason, for COMMITTED and DEGRADED saved modes | **Not met** |
| Counters per family, replies in packets only, null is never zero, Dropped is described as two rules, nothing says "since" | Per-family mostly met. Check the rest |
| Dates on anything not from today | **Not met:** `readTime` is time-only, and the reset line too |
| Refresh counters stays read-only, runs no full inspection, and keeps the last counts on failure | Check when merging |
| Hooks come from the report | Fixed string appears gone |
| Tab role and selection, expand state, announced results and status, rule text fits at 200% | Partly met |
| UDP gates and their wording | Keep |
| Screen state written on the main thread, and UI reachable through `FirewallGateway` | Needed to run the tests |

## Insights integration concerns

`feature/drop-insights` currently touches none of these files. These matter when it reaches the app:

- **Capture looks like DEGRADED.** During a capture the app would show "Needs attention", hide the switch, and refuse counter reads and tile toggles. A counter read during capture now also withdraws the verified claim. That's accurate today, but alarming for a diagnostic someone started. It should have its own state.
- **Remove partial rules would be offered during capture.** It flushes PocketUFW's chains and disarms the boot hook. It should be hidden while a capture lock exists.
- **Same action for stale probes.** After SIGKILL or power loss, this button is the only in-app recovery, and it's a much bigger action than removing probes.
- **The rule table would mislabel a probe.** `describeRule` matches `--ctstate INVALID` before checking the target, so the INVALID NFLOG probe would read as "DROP Invalid packets". The report is emitted while DEGRADED, so this would be visible.
- **Tile state can stick.** Any inspection during capture publishes DEGRADED to the tile until the next inspection.
- **Counter preservation is still untested live.** The capture doc lists it as untested. Until it is, treat captures as another possible source of counter changes when investigating the anomaly.

## Tide integration note (2026-11-05)

This document records the **original Claude audit branch** and its 78 passing
Robolectric tests on the old dashboard. The subsequent integration branch
`integration/pocketufw-next` retains the Tide layout and ports the audit's
behavioral contracts into Tide's separate Compose components.

The old dashboard-only JVM tests cannot meaningfully run against the new
navigation or replaced controls. They remain available in Claude's original
commit `301c393` and were replaced in the integration snapshot by
`TideAuditRegressionTest.kt`, with new Python checks in
`tests/test_audit_fix_contract.py` and an updated loading contract. A debug and
release build, full JVM unit tests and lint pass offline as of this integration.
**This is not a claim that all 78 old tests also pass on Tide.**

The Quick Settings tile, packet-filtering engine, boot scripts, signing,
release behavior and Android bridge remain unchanged. The `STATE_UNAVAILABLE`
tile trade-off is deliberately out of scope. User testing of focus changes,
root prompts, large text and live VPN recovery is still required.
