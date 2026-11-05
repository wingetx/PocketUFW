# PocketUFW — independent UI directions

Tide was approved for implementation, with two corrections: render the actual reported kernel rule order and confirm counter resets. The original Phase 1 concepts below are retained as design history. Their illustrative rule sequence and immediate-reset interaction are superseded by the Compose implementation.

See [implementation notes](IMPLEMENTATION.md) and [real Compose previews](implementation/overview.png).

Worktree: `/home/winget/toolbox/projects/PocketUFW-codex`

Branch: `design/codex-ui`

Baseline: `main`, `55283ab`, Android `0.1.0-beta4`

## Tide — recommended

Warm paper, cobalt ink, an expressive serif state label, and the original terminal penguin. A single horizontal boundary gives the home screen a recognizable composition. Open rows and careful type hierarchy carry the rest of the interface.

The first screen answers whether the firewall is active, explains the policy, and exposes one explicit power action. A dropped-packet total leads into detail. Persistent Firewall / Activity / Settings navigation keeps configuration separate from routine checks.

Fraunces is the display face; DM Sans handles interface text; DM Mono handles technical values. A blue-black night palette preserves the same hierarchy. The original penguin uses a small pale medallion in the dark appearance.

## Relay

Charcoal, warm apricot, geometric lettering, and a prominent power control give this direction the character of a compact physical instrument. The penguin becomes a small maker's mark in the app bar. Squared edges and one asymmetric control panel make the silhouette distinct.

The main screen brings counters and connection controls closer to the power switch. Two bottom destinations, Firewall / Inspect, support quick checks; setup lives in the app bar. Counters are grouped by address family, with dropped packets, bytes, and accepted replies together. Space Grotesk and DM Mono support the more technical character.

## Why Tide

Tide gives the verified state the clearest visual priority, makes the mascot feel native to the composition, and needs less interface chrome. Its typography is distinctive without making technical content hard to scan. Relay is the stronger alternative for a denser, instrument-like personality.

## Feature placement

| Capability | Tide | Relay |
| --- | --- | --- |
| Verified status and enable/disable | Firewall headline and labeled action | Firewall control panel |
| Root and degraded states | Same headline region; state-specific explanation and actions | Same control panel; state-specific explanation and actions |
| IPv4/IPv6 drops, bytes, accepted replies | Activity → Counters | Inspect → Counters |
| Refresh / Reset counters | Counters; separate, explicitly labeled actions | Counters; separate, explicitly labeled actions |
| Readable and raw rules | Activity → Kernel rules; family selector; Raw | Inspect → Kernel rules; family selector; Raw |
| Tailscale and manual UDP exceptions | Settings and Kernel rules | Firewall, Setup, and Kernel rules |
| Experimental / Committed | Exception editor with existing warning and commit confirmation | Same behavior, Relay styling |
| Reset to automatic / Refresh VPN | Exception details; Refresh also in Settings | Exception details; Refresh also in Setup |
| Magisk restoration | Home summary → Settings | Home summary → Setup |
| Quick Settings integration | Settings → Quick Settings tile | Setup → Quick Settings tile |
| Future Insights | Third Activity view when implemented | Third Inspect view when implemented |

No Insights placeholder is shipped in the current concepts. Its future screen must consume actual dropped-packet metadata, not imply a history already exists.

## State and accessibility contract

| Engine state | Presentation | Control |
| --- | --- | --- |
| ACTIVE | Explicit verified state, colored label and check symbol | Turn firewall off |
| INACTIVE | Off, neutral label, explanation that Android's rules remain | Turn firewall on |
| CHECKING | Checking, neutral progress symbol; no assertion that protection is off | Power action disabled while checking |
| DEGRADED | Needs attention, warning symbol, protection not verified | Recheck; inspect; existing removal of partial rules |
| ROOT_REQUIRED | Root required, key symbol, root-manager guidance | Check root access |

Labels and symbols carry state independently of color. Content scrolls while main navigation remains available. Larger text reflows rows; the decorative home mascot yields space. Numeric columns use tabular figures. Raw rules remain selectable and can wrap in the review prototype; Compose implementation must retain access to the unmodified report.

Implementation must preserve the existing callback guards, operation messages, counter-refresh failures and retained prior readings, null/unavailable values, saved-versus-live exception distinctions, and all Magisk unavailable/conflict/degraded states. Never turn an unknown value into zero or show the firewall as off while it is checking. No background polling is proposed.

## Review files and limits

- `pocketufw-directions.html`: interactive conversation preview, with two named designs. The phone navigation works. Design controls expose all five firewall states and text scaling from 100% to 160%.
- `tide-overview.png`, `relay-overview.png`: three-screen boards at 390 × 844 logical pixels per phone.
- `state-overview.png`: all five protection states in both directions.
- `implementation/` contains actual Compose captures, including settings, raw rules, dark appearance, enlarged text, and the reset confirmation.

All displayed counters, ports, times, and rule text are illustrative fixtures. These are design mockups, not screenshots of a built APK. Local prototype interactions do not execute root commands. The prototype is not a complete firewall simulator.

The existing `pocket_penguin.webp` is reused; launcher assets and the shield Quick Settings tile are untouched. Fonts load from Google Fonts in the review preview; an approved Android implementation would bundle its chosen licensed fonts and make no font network requests.

## Verification

Rendered and visually inspected with Chromium. Checked 108 combinations of direction, screen, width (320 / 390 / 430), and text scale (100% / 130% / 160%): no horizontal body overflow after refinement. Also checked all five home states at 160%, dark appearance, local navigation, enable/disable, reset, raw IPv6 rules, and the Experimental/Committed confirmation flow. No runtime errors in these checks.

The checks above apply to the original concepts. Build and emulator validation for the approved implementation are recorded separately in `IMPLEMENTATION.md`. No engine, backend, boot-hook, launcher, tile, release, or original-worktree files were edited.
