# PocketUFW v1: one-switch release scope 🐧

**Decision (November 2, 2026):** prioritize the reliable default firewall. General
custom rules, user-supplied iptables commands, and the advanced A/B rule engine
are **out of scope for v1**. This is intentional, not unfinished release work.

## The product

- **One primary switch:** enable or disable the owned, verified inbound firewall.
- **Incoming:** deny unsolicited packets on supported physical interfaces,
  after established-reply and essential Android networking allowances.
- **Outgoing:** leave Android's outbound rules and policies untouched.
- **Honest status:** check both IP families, INPUT hooks, owned chain order,
  Tailscale UDP exception child, and measured packet counters before claiming
  ACTIVE. Counters are rule matches, not proof of attacks or universal coverage.
- **Reliable operation:** controlled enable/disable, clean rule removal, safe
  failure handling, optional one-shot Magisk boot restoration, and no permanent
  background service or VPN slot.
- **VPN compatibility:** automatic verified Tailscale UDP listener exceptions.
  The existing alpha13 *manual VPN UDP exception* editor may remain under
  Status as a recovery/compatibility control. It is **not** a general incoming
  port firewall editor and is not required for the normal one-switch workflow.
- **No clutter:** no app-level allow/block lists, per-app traffic interception,
  root-script editor, arbitrary user-specified iptables rules, accounts,
  analytics, always-on notification, or continuous logging by default.

## Explicitly postponed, not release blockers

- A future **Allow incoming port** option (TCP or UDP, potentially restricted
  to Wi-Fi and a source address), only if actual users need it. The default
  unsolicited incoming policy is already DENY; a separate Deny port editor
  offers little value without a pre-existing allowance.
- The advanced custom-rule parser, A/B chains, journaled policy swapping,
  editor preview, and experimental counters explored on the `main` branch.
  They remain recoverable in Git at commit `e902533` and can be evaluated
  independently later. **Do not merge them into v1 just to use sunk effort.**
- Full UFW parity, arbitrary iptables, routing/tethering firewall control,
  per-app rules, and persistent packet history.

## What v1 still needs before a daily phone

1. Recheck alpha13's on-device safety: exact pre/post rules, one-switch
   ON/OFF/ON, counters, Tailscale connectivity, and safe rollback if a step
   fails. Hardware checks must remain supervised and preserve Android-owned
   rules. No unexplained residual files, chains, or Magisk hooks.
2. Confirm optional Magisk boot restore, especially **committed manual UDP
   settings** after a real reboot; automatic VPN listener rotation is still
   a known limitation. Never silently claim listeners are current after a
   change. Test no resident process is necessary.
3. Check critical ordinary use: VPN reconnect, LAN access/printing, cameras
   and connectivity across available network types. Moto has no cellular
   service, so it **cannot** certify cellular or IMS behavior.
4. Perform a separate controlled **Pixel 9a / Android 17** trial only after
   the test-device results are convincing, with boot restoration initially
   disabled and a rehearsed recovery plan. VPN+Tailscale interaction and
   camera access matter more than optional knobs.
5. Revisit external release / F-Droid packaging only after independent
   multi-device safety evidence. The repo is a prototype, not a promise of
   complete inbound coverage on every Android device.

## Branch and preservation policy

- The public `main` branch is the **minimal one-switch firewall**, initially
  published as a fresh snapshot to avoid exposing private device details
  or original developer email addresses from pre-publication Git history.
- Previous experimental custom-rule engineering and the original development
  history remain preserved **locally**, outside this public release branch.
  General-purpose customization is not part of the v1 release requirements.
- Keep phone changes out of scope until explicit authorization for each
  consequential hardware test. Read-only inspections can establish the
  current status without changing device policy.

**Release principle:** The kernel may be complicated. The app shouldn't be.
