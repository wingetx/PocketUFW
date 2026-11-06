# PocketUFW 🐧

## Your phone runs Linux. Give it a Linux firewall.

**Real, stateful, kernel-level inbound packet filtering for rooted Android. Not another app-blocking switchboard.**

Most Android firewall apps start with an app list. PocketUFW starts with the network itself. It uses Android's existing Linux `iptables` and `ip6tables` firewall to enforce a straightforward policy on supported physical interfaces:

- **Outgoing traffic:** leave it alone.
- **Replies to connections your phone initiated:** let them in.
- **Unsolicited incoming packets:** drop them by default, with allowances for essential network protocols and explicitly permitted VPN listeners.

**It's an actual packet-filtering firewall, not an app-by-app internet permission manager.** No sprawling allowlists, no occupying Android's VPN slot, and no continuous traffic-capture service. Once installed, the kernel enforces the rules even when PocketUFW's interface is closed.

Think UFW's *deny incoming, allow outgoing* philosophy, adapted for rooted Android. PocketUFW is independent software, not UFW and not affiliated with Canonical.

**What you get:** one protection switch, readable rules, live kernel packet counters, optional one-shot Magisk boot restoration, and manual verified Tailscale listener refresh. No accounts, advertising, analytics, or continuously running background app.

> **Beta, not a security guarantee.** Version `0.1.0-beta5` is intended for testing, not unattended or production security use. Root and compatible `iptables`/`ip6tables` are required; Shizuku-only operation is not supported. Coverage is limited to supported physical interfaces, and earlier Android/OEM `INPUT` rules can bypass PocketUFW. It does not directly filter traffic inside VPN tunnels or forwarded/tethered traffic. See the [v1 scope](docs/v1-scope.md) and [hardware validation](docs/hardware-validation.md) for details.

**Permanent Android app identity:** Starting with `0.1.0-beta2`,
the app ID is `io.github.pocketufw`. The earlier beta1 used the
temporary `io.github.pocketufw.alpha` ID. This one-time change
requires uninstalling the old app before using the renamed version.

**Beta3:** A manual **Reset counters** action zeroes only owned IPv4/IPv6
packet counters, without restarting protection; a reduced-glow shield-penguin
launcher image and a shield-only Quick Settings tile complete the beta polish.

**Beta4:** The **Refresh counters** control now reads kernel counters through
a dedicated read-only operation, shows explicit progress/results, and displays
Last checked down to the second. Refresh never resets counters or changes rules.

## Design philosophy

**Debian calm, in your pocket.** PocketUFW aims to be simple, dependable, and easy to trust. The firewall engine can be sophisticated; the experience should not be.

- **Sensible defaults:** allow outgoing traffic and block unsolicited incoming traffic, with essential network protocols preserved.
- **One primary switch:** the user's main decision is protection on or off. General-purpose custom rules are not part of v1; a small VPN UDP exception control exists only for connection compatibility.
- **Verified protection:** never display a reassuring "protected" indicator or state unless the app has verified that the relevant rules are installed and effective.
- **Set it and forget it:** handle restarts, VPN port changes, and recovery with minimal interaction. Magisk boot restoration is implemented on the Moto; continuous VPN tracking and broader recovery are **not yet implemented**.
- **No unnecessary baggage:** no accounts, ads, analytics, or app-by-app permission maze.
- **Plain-language failures:** tell users what is working, what is not, and whether intervention is necessary.

**Quiet when everything works. Unmistakable when something doesn't.**

### Visual identity (selected direction)

**Terminal penguin**, not a shield. A small friendly, geometric penguin holding a dark terminal with a muted-green `>_` prompt. Flat charcoal, off-white, and restrained green. Minimal shapes, legible at Android launcher icon sizes, no elaborate mascots or security clichés.

- Wordmark: `Pocket` in charcoal, `UFW` in muted green.
- Separate the icon from the wordmark so the launcher icon works without text.
- Use the same restrained palette and typography for the one-switch app interface.
- Neon artwork is the app launcher and Home image; a separate monochrome penguin is used for Quick Settings.

## Firewall policy

- Incoming from a physical interface: **deny by default** after essential network allowances.
- Established inbound replies: **allow**.
- Outbound: **left unchanged** (other apps/system policy may still restrict it).
- Tailscale virtual interfaces and WireGuard tunnels: **not filtered directly**, though their *underlying* UDP listeners may require explicit allowances.
- Android's preexisting INPUT/OUTPUT/FORWARD rules and their default policies: **never flushed or modified**.
- PocketUFW owns two filter chains per address family: `POCKETUFW_IN` for inbound policy and `POCKETUFW_TS` for verified Tailscale UDP exceptions, with tagged hooks into `INPUT`.
- The standalone CLI does not persist rules after reboot. The Android alpha offers **optional Magisk boot restoration**, tested on the Moto; no continuous background monitoring.

## Why this exists

On Android, "firewall" often means choosing which apps get Wi-Fi or mobile data. That can be useful, but **controlling an app's internet access is not the same job as denying unsolicited inbound connections**.

PocketUFW takes the familiar Linux host-firewall approach: use connection tracking to recognize replies to traffic the phone initiated, allow essential network traffic, and deny other incoming packets on supported physical interfaces. Its rules live in the kernel's existing netfilter/iptables machinery. They don't depend on a packet-capture VPN, a constantly running Android service, or an app-by-app blocklist.

Other Android tools can use genuine kernel firewall rules too. **PocketUFW's difference is its policy: connection state and direction, not app permissions.** It complements Android's existing security model rather than replacing it.

**Default-deny incoming. Keep outgoing working. Verify the rules.**

### Important limitations in 0.1.0-beta1

1. **Do not enable alongside AFWall+'s active rules**. PocketUFW checks for its output hook and refuses to enable. Android or other firewall tools may still own unknown chains.
2. **No continuous Tailscale port tracking.** `--auto-tailscale` verifies current Android app-owned sockets when enabling rules. Use `refresh` after a port change to update only the exception chain. A future monitor will handle this automatically. A blocked direct UDP listener can push Tailscale onto encrypted relays.
3. Assumes physical interfaces named `wlan*`, `rmnet*`, or `v4-rmnet*`. Network interfaces differ across phones. Devices with `eth*`, `ccmni*`, or other names **will not be covered**.
4. Does not filter **tethered/FORWARD traffic** or traffic arriving through the *inner* `tun*` VPN interfaces.
5. `INPUT` hooks are appended **after system/OEM rules**. This preserves Android behavior but means an earlier terminal ACCEPT can bypass PocketUFW. It is not a universal host firewall guarantee.
6. Current profile uses broad allowances for IPv6 ICMP, ESP, DHCP and mDNS to favor compatibility; they will be tightened after multi-device tests.
7. No automatic watchdog or general rule-repair service. The Android app can install an opt-in one-shot Magisk boot hook; interrupted operations or later rule resets may still require manual intervention. Root access must remain available.
8. **Hardware tested, not production-ready.** IPv4/IPv6 ingress blocking, removal, Proton VPN coexistence, and Magisk reboot restoration were validated on a rooted Moto G 5G (2024). Other kernels, carriers, root managers, and unattended operation still require testing. See [hardware validation](docs/hardware-validation.md).
9. DNS filtering (such as Quad9) and VPN encryption are separate from PocketUFW's inbound firewall policy.

## Android app (beta)

The Kotlin/Jetpack Compose app lives in [`android/`](android/). It has a terminal-penguin launcher icon, one protection switch, root/VPN status, verified rule checks, and manual VPN refresh. Alpha5 combines each control action and its status/counter verification into **one root request**. Opt-in Magisk boot restoration is available without running a background app. **Use on test devices only.**

Build and installation instructions are in [the Android README](android/README.md). The debug APK is written locally under `android/app/build/outputs/apk/debug/`, not committed into Git.

### Background operation and recovery roadmap

- **Already works:** the Linux kernel filters inbound packets independently of whether the Android UI is visible, force-stopped, or closed. The optional Magisk late-start hook restores the policy after a reboot. No Android foreground service is needed.
- **Optional active Quick Settings tile:** opening the shade does not request
  root; it displays the last verified state with a check timestamp. A tap
  performs a fresh kernel-verified toggle, requiring an unlock when locked.
  The tile does not poll root or run a background service. Magisk may show a
  toast after an explicit operation. On Pixel 9a, the owner confirmed the
  active-tile change stopped repeated shade-open Magisk toasts.
- **Not yet solved:** later Android/OEM firewall rewrites, interrupted rule installation, unexpected interface changes, and Tailscale listener-port rotations. The existing boot hook runs only once.
- **Next design target:** an opt-in, low-overhead root-side health/recovery mechanism with explicit ownership checks, bounded retries, and honest failure reporting. It must refuse to overwrite unknown or conflicting chains, preserve boot and VPN functionality, and be removable through the off switch. Avoid repeatedly invoking `su` or keeping a foreground Android service alive.
- **Optional visibility:** packet totals can be shown on demand or in an opt-in notification. Counts are DROP-rule matches, never automatic claims of attacks or blocked trackers. No notification permission, constant polling, or packet-history collection should be required for ordinary protection.

## Preview without changing anything

```sh
sh pocketufw doctor
sh pocketufw plan --tailscale-udp4 46867 --tailscale-udp6 43504
# Root-only, read-only runtime port discovery:
sh pocketufw plan --auto-tailscale
```

The ports above are **examples from one Pixel's observed session**, not universal or permanent defaults. Tailscale may choose different values.

## Command-line operation (root required; use only on authorized devices)

```sh
# From a tested root shell, only after disabling conflicting AFWall rules:
sh pocketufw enable --tailscale-udp4 PORT4 --tailscale-udp6 PORT6
# Or, if the bundled vpn-probe finds verified Tailscale sockets:
sh pocketufw enable --auto-tailscale
sh pocketufw status
# Read-only kernel DROP counters and an administrator-style report:
sh pocketufw activity
sh pocketufw verbose
# Refresh verified Tailscale UDP ports without rebuilding the firewall:
sh pocketufw refresh
sh pocketufw disable
```

## Verifying what it owns

PocketUFW has two read-only evidence commands. `activity` returns structured IPv4/IPv6 DROP and accepted established-reply counters; `verbose` presents a human-readable, UFW-style summary. The Android alpha displays those same kernel counters in an expandable **Firewall activity** section. These counters reset when the firewall is disabled or rules are reinstalled. Nonzero DROP counts prove that packets matched PocketUFW's own rules, **not** that all possible incoming paths are protected. The Android Alpha12 **Status** tab also reads and displays the actual IPv4/IPv6 INPUT hooks, inbound chains, and verified VPN listener exceptions, with a raw-rule view. It uses the existing root check rather than requesting privileges again when switching tabs.


```sh
iptables -w -S POCKETUFW_IN
ip6tables -w -S POCKETUFW_IN
iptables -w -S POCKETUFW_TS
ip6tables -w -S POCKETUFW_TS
iptables -w -S INPUT | grep PocketUFW
ip6tables -w -S INPUT | grep PocketUFW
```

No `iptables -F`, `iptables -P INPUT DROP`, or global `iptables-restore` is used. Clean removal is a design requirement, not an optional feature.

## What v1 actually ships

**Deny unsolicited incoming on supported physical interfaces; leave outgoing
rules alone.** One toggle, accurate DROP counters, optional verified VPN
listener exceptions, and a one-shot boot restore. No general custom-rule
editor, arbitrary root scripts, per-app traffic blocking, VPN slot, or
always-running daemon. Beta1 is a tested prototype, not a production security release. See [the minimal v1 checklist](docs/v1-scope.md).

## Security & release checklist

- [ ] More tests for failed `iptables` operations and partial cleanup
- [x] Verified Tailscale UDP discovery and manual dual-stack live refresh (mock-tested; removal hardware-tested)
- [x] One privileged session per dashboard inspection or action, with real status and counter verification (Moto-tested)
- [x] Opt-in Magisk boot restoration on the Moto (other devices still unverified)
- [ ] Automatic monitoring of Tailscale restarts and listening-port changes
- [x] Read-only `verify` command checks both families' chains, default DROP rule, and physical interface hooks
- [ ] Non-destructive firewall recovery/watchdog
- [ ] Verify Android 17 kernel/root tool support and Android 14–16 compatibility
- [ ] Wi-Fi/cellular handover, DHCP renewal, IPv6 RA/NDP, hotspot and IMS calls
- [ ] Avoid public release claims until independently tested on multiple devices
- [ ] Document safe interaction with AFWall+ and other managers

## Sources and acknowledgements

Inspired by UFW's **policy design**, with independently authored shell commands:

- [UFW `before.rules`](https://sources.debian.org/src/ufw/0.36.2-10/conf/before.rules)
- [UFW `before6.rules`](https://sources.debian.org/src/ufw/0.36.2-10/conf/before6.rules)
- [Tailscale UDP firewall guidance](https://tailscale.com/docs/reference/faq/firewall-ports)

See `LICENSE` for PocketUFW's own source. No UFW source code is copied into this prototype.

### Alpha11 UI clarity

The optional Quick Settings tile's **long press** resolves to PocketUFW's main dashboard through Android's `ACTION_QS_TILE_PREFERENCES` activity intent filter (instead of the default App Info). A short tap acts on the state the tile showed, after checking the live kernel state, and only verifies when that state is unknown. Initial app launch displays a neutral, explicit kernel-checking panel until the first live root inspection completes, rather than showing false OFF switches. Changing Magisk boot restoration no longer temporarily dims the unrelated firewall switch. Pending the tester's visual confirmation on the Moto.

### Alpha12: optional advanced UDP exception editor

The Status tab's **About / edit VPN UDP exceptions** expands a plain-language explanation and an advanced, explicitly warned editor. Only one incoming UDP port per IPv4/IPv6 family is supported, with blank meaning no exception. **Experimental** applies only to the current live firewall rules; **Committed** persists across app launches and firewall restarts, and is restored by the opt-in one-shot Magisk boot hook on reboot. A second confirmation is required before committing. **Reset to automatic VPN exceptions** restores verified Tailscale listeners and clears a committed choice, or undoes an experimental edit, after a successful refresh. Normal Refresh VPN refuses to silently replace committed ports. Manual ports can become stale if Tailscale rotates its listeners, potentially falling back to DERP.

Committed settings are a root-validated, strictly formatted file in Android's app-owned **device-protected private storage**, not a permanent global Android setting. Uninstalling the app removes its data; the Magisk service self-disarms at next boot if the app is absent. No new Android foreground service, extra network permission, or background polling is required. Test builds are still experimental; compatibility and hardware reboot behavior of alpha12's new committed mode need validation on the Moto.

### Alpha13: precise lifetimes and reset control

The advanced UDP editor now explicitly states that **Experimental** edits survive app closure and Tailscale reconnect, but are lost when firewall rules are rebuilt (turning protection off/on or rebooting); Refresh VPN can overwrite them in Automatic mode. **Committed** stays saved until changed, reset to automatic detection, or app data is removed; it is restored on future firewall enables, and after reboot only with Magisk boot restoration enabled. The **Reset to automatic VPN exceptions** action is offered for both Experimental and Committed states, with a confirmation describing verified Tailscale listener discovery, including the possibility that no listener is currently detected. The engine's existing safe refresh/reset path is reused. No extra services, permissions, or firewall-engine modifications were required for alpha13.
