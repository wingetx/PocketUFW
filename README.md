# PocketUFW 🐧

<img src="assets/branding/pocketufw-neon-penguin.png" alt="PocketUFW's armored penguin mascot" width="145" align="right">

### Your phone runs Linux. Give it a Linux firewall.

**A small, open-source inbound firewall for rooted Android.** PocketUFW uses the phone's Linux kernel firewall rather than occupying Android's VPN slot. The Tide interface makes protection, VPN compatibility, and real kernel counters visible without an always-running app or an account.

**The policy is simple:** allow outbound traffic, allow replies to connections the phone started, and deny other inbound traffic on the interfaces PocketUFW covers. Essential networking and verified VPN-listener exceptions are handled separately.

> [!WARNING]
> **Experimental beta, not a security guarantee.** PocketUFW requires root and a compatible `iptables`/`ip6tables` backend. Coverage varies by device, kernel, interface naming, and Android/OEM rules. It is not a replacement for Android's security model.

**Latest signed beta:** [PocketUFW 0.1.0-beta5](https://github.com/wingetx/PocketUFW/releases/tag/v0.1.0-beta5) is published as an **experimental prerelease**, with Tide, optional tunnel filtering, and audited engine fixes. [Download the APK](https://github.com/wingetx/PocketUFW/releases/download/v0.1.0-beta5/PocketUFW-0.1.0-beta5.apk) and [verify its SHA-256](https://github.com/wingetx/PocketUFW/releases/download/v0.1.0-beta5/SHA256SUMS.txt). Its source is tagged `v0.1.0-beta5` at commit `508cb29`; later documentation edits do not change that release.

**Local release candidate:** `0.1.0-beta6` (versionCode 27) adds Insights v1 and the Tide cleanup described in the [Beta 6 notes](docs/releases/0.1.0-beta6.md). It is unsigned and awaiting independent review; the published release above remains Beta 5.

## What it does

| Feature | Behavior |
| --- | --- |
| **Physical inbound firewall** | Drops unsolicited IPv4 and IPv6 input on supported Wi-Fi, cellular, and CLAT interfaces |
| **Optional tunnel protection** | Independently filters incoming traffic on Android `tun*` interfaces and detected kernel WireGuard interfaces |
| **Outgoing connections** | Leaves Android's outbound firewall rules unchanged |
| **Activity** | Shows real packets and bytes matched by PocketUFW's DROP and established/related rules, separated by physical/tunnel and IPv4/IPv6 |
| **Insights** | Samples DROP matches on demand for up to 10 seconds / 256 records; shows sources, protocols, physical/tunnel classification and possible traffic purposes |
| **Live rule inspection** | Shows the verified rule chains, exceptions, incomplete coverage, and raw kernel rules |
| **Quick Settings tile** | Deliberate toggle with a fresh state check; long-press opens PocketUFW |
| **Boot restoration** | Optional one-shot **Magisk** restore for physical filtering only |
| **Network compatibility** | Does not use `VpnService`, leaving the VPN slot available for apps such as Tailscale or Proton VPN |

Tide includes a single primary firewall switch, an **Activity** page for all counters, an **Insights** sampling page, a labeled **Recheck** action, progress indicators, and separate controls for advanced tunnel and VPN settings. Resetting counters clears PocketUFW-owned measurements without rebuilding the firewall or changing Android/OEM rules.

PocketUFW has **no accounts, ads, analytics, or application telemetry**. It does not continuously capture packets, retain traffic history, or run a persistent Android foreground service.

## How the filtering works

### 1. Physical protection

PocketUFW creates its own `POCKETUFW_IN` and `POCKETUFW_TS` chains in the IPv4 and IPv6 filter tables. Its four supported interface patterns are:

```text
wlan+    rmnet+    v4-rmnet+    v4-wlan+
```

The last two cover cellular and Wi-Fi 464XLAT interface names. The firewall admits established/related replies and necessary control traffic (including DHCP, ICMP, mDNS, and ESP), optionally allows verified Tailscale UDP listeners, and drops other inbound matches.

It **does not flush, replace, or change the default policies of** Android/OEM `INPUT`, `OUTPUT`, or `FORWARD` chains. Its hooks are appended after existing Android rules, so an earlier `ACCEPT` may bypass them. Interfaces with different vendor names may also be outside coverage.

A verified ruleset is **not** proof that every incoming path is filtered. If the detailed rule report or interface inventory is missing, the app reports **coverage unknown**; known bypasses and uncovered interfaces are reported as partial coverage.

### 2. Optional tunnel protection

VPNs can deliver decrypted packets to virtual interfaces that the physical firewall does not cover. The optional tunnel filter adds its own `POCKETUFW_VPN` chain and separate counters. It is **off by default** and is **not restored after a reboot**, even when physical boot restoration is enabled.

| Mode | What it means |
| --- | --- |
| **PINNED** | Initially verifies Tailscale's ownership and the phone's IPv4 and IPv6 node addresses, then allows tailnet-source traffic addressed to those exact saved destinations while filtering other unsolicited tunnel input |
| **DENY-ONLY** | No tailnet exception. Drops unsolicited incoming tunnel packets, including new peer-initiated Tailscale traffic, while allowing established/related replies |

PINNED retains its authorized destinations across ordinary Tailscale reconnects. If the phone's addresses change, the UI reports **REAUTHORIZE**; it never silently broadens the allowance. A DEGRADED tunnel filter has a **tunnel-only recovery** action that leaves physical protection intact.

**Important trust boundary:** PINNED authenticates addresses during initial setup, **not the source of every subsequent packet**. Another qualifying tunnel could inject a packet claiming a tailnet source and aimed at a pinned local destination. The app documents this limitation, but PINNED is **not equivalent to cryptographically authenticated Tailscale-only ingress**. Earlier Android/OEM accepts can still bypass both modes. See [tunnel policy and threat model](docs/tunnel-filtering.md).

### 3. Tailscale UDP exceptions

Physical firewall allowances can preserve verified Tailscale UDP listeners. Listener ports can change after Tailscale restarts; without a continuous watcher, existing exceptions may become stale until a manual refresh. A failed refresh may retire ports proven unused, but it will not guess new ones or silently change committed manual settings.

This is a compatibility feature, **not** a general-purpose open-port editor.

## Understanding Activity and Insights

- **Dropped** means a packet matched one of PocketUFW's actual kernel DROP rules, not necessarily that an attacker was stopped.
- **Established/related** counts recognized return traffic that reached PocketUFW's chains. It isn't a count of *all* packets arriving on the phone.
- **Tunnel** and **physical** counters are separate. Values may change between two successive reads.
- **Reset** zeroes the counters owned by PocketUFW, not other Android or VPN counters. New packets can increment them immediately.

**Seeing zero drops is normal.** Home routers, carriers, Android, and VPNs may stop unsolicited traffic before PocketUFW ever sees it. Deliberate IPv4/IPv6 Wi-Fi and cellular probes have verified that supported rules drop matching traffic on a test phone, but a quiet counter is not proof of either failure or total protection.

Insights describes only a short, local sample of actual DROP matches. It does not explain historical totals or identify applications or malicious intent. **Android/OEM rule changes can cause Insights to withhold an otherwise useful sample**; strict verification remains enabled. Cleanup and independent protection verification still run after a refused collection. Qualified sampling is not implemented. See [Insights behavior and limits](docs/insights-v1.md).

PocketUFW does **not** currently provide per-app outbound blocking, domain/ad blocking, live DNS interception, or a PCAP-style traffic log. These are possible future directions, **not features in this beta**.

## Requirements and compatibility

- Root access with functioning `su`. Magisk is hardware tested; KernelSU and APatch compatibility is not yet established.
- A compatible IPv4/IPv6 legacy `iptables` implementation with the needed conntrack matches. Pure `nftables`/other backend variants are not established.
- Android API 26 or later for the app; successful operation still depends on the phone's actual kernel and interfaces.
- **Do not activate alongside AFWall+'s existing custom inbound setup.** PocketUFW has a basic conflict check, not universal detection of other firewall managers.

**Hardware evidence:** The physical firewall, controlled packet drops, boot behavior, VPN coexistence, and multiple UI flows have been tested on a Pixel 9a (Android 17) and a Moto G 5G (2024). Selected tunnel and cellular tests ran on the Pixel 9a. Wi-Fi 464XLAT hook matching has passed isolated real-Linux-kernel testing, **not** an end-to-end Android IPv6-only/NAT64 Wi-Fi trial. These are targeted experiments, not certification of every Android device.

See [hardware validation](docs/hardware-validation.md), [compatibility notes](docs/compatibility.md), and [latest audit follow-up](docs/medium-audit-followup.md).

## Install and first use

1. Download a **signed** APK from [GitHub Releases](https://github.com/wingetx/PocketUFW/releases), checking the release tag and notes for the features actually included. Development/debug builds are not interchangeable with release-signed APKs.
2. Install it on a rooted, compatible phone. Open PocketUFW and grant root in your root manager if prompted.
3. Tap **Recheck**. Confirm the app can read the live kernel state before enabling protection.
4. Tap **Turn firewall on**. Inspect the result and the reported coverage. Tunnel protection is an independent, optional choice under **Settings**.
5. If desired, enable **Restore after reboot**. This restores **physical** filtering using Magisk's one-shot boot hook, not the optional tunnel filter.

For initial testing, keep a trusted recovery route (such as USB ADB), especially when your phone depends on cellular, Wi-Fi calling, local services, or VPN connectivity. Installing or opening PocketUFW does not itself install firewall rules.

### Updating older betas

**The current four-hook engine does not silently migrate a three-hook installation.** An older active installation may show **DEGRADED** after upgrading because its installed rules do not match the new verifier.

On the upgraded app, use **Remove partial PocketUFW rules** if offered and verified, then turn the firewall back on to install the four-hook policy. Recheck your **Restore after reboot** setting and ensure its root-owned engine snapshot has been refreshed. Until that happens, an older Magisk hook may restore the old three-hook rules at the next boot.

The original Beta 1 used the different package ID `io.github.pocketufw.alpha`; Beta 2 onward uses `io.github.pocketufw`. Android treats those as distinct apps. Remove the old app's owned firewall rules and boot hook before uninstalling that old package.

See [the audited upgrade notes](docs/medium-audit-followup.md). **Never assume APK installation alone replaces already-running kernel rules.**

### Uninstalling safely

Prefer **Settings → Remove PocketUFW**. It removes verified PocketUFW-owned rules and Magisk boot files, checks that cleanup completed, and only then opens Android's uninstall screen.

An ordinary uninstall cannot remove already-installed kernel rules immediately. They can remain until the next reboot; a properly disarmed/self-cleaning boot hook then removes its own files rather than restoring rules. **Avoid `pm uninstall -k`:** keeping app data can cause an existing boot hook to keep restoring the firewall.

<details>
<summary>Advanced recovery: manual removal of PocketUFW's kernel rules (root)</summary>

Use the in-app removal flow whenever possible. The following is an emergency fallback for a known PocketUFW ruleset, **not a general iptables reset**. It removes PocketUFW's owned kernel chains/hooks; it **does not disarm its Magisk boot hook**, which must be cleaned up separately to prevent restoration on reboot.

To clear the rules without restarting, run the following from a trusted root shell after confirming the rules really belong to PocketUFW:

```sh
for t in iptables ip6tables; do
  # Only if the optional tunnel filter was on. Without it, the tunnel lines just report no such chain.
  for i in $($t -w -S INPUT | sed -n 's/^-A INPUT -i \([^ ]*\) -m comment --comment PocketUFW-VPN .*/\1/p'); do
    $t -w -D INPUT -i "$i" -m comment --comment PocketUFW-VPN -j POCKETUFW_VPN
  done
  $t -w -F POCKETUFW_VPN; $t -w -X POCKETUFW_VPN
  for i in wlan+ rmnet+ v4-rmnet+ v4-wlan+; do
    $t -w -D INPUT -i "$i" -m comment --comment PocketUFW -j POCKETUFW_IN
  done
  $t -w -F POCKETUFW_IN; $t -w -X POCKETUFW_IN
  $t -w -F POCKETUFW_TS; $t -w -X POCKETUFW_TS
done
```

Recheck both filter tables and the Magisk service hook before trusting the resulting state.

</details>

## Build from source

PocketUFW is written in Kotlin/Jetpack Compose with a small root-side shell engine and a native C++ Insights helper. A local debug APK requires Java 17 and an Android SDK with API 36, NDK 27.2.12479018 and CMake 3.22.1:

```sh
cd android
./gradlew :app:assembleDebug
```

Output: `android/app/build/outputs/apk/debug/app-debug.apk`.

This is **debug-signed**, not an official release-signed update. Root permission must be granted by the phone owner. Use [the Android build guide](android/README.md) for SDK setup and [the v1 scope](docs/v1-scope.md) for the intentionally limited product boundaries.

For developers with a tested root shell, the engine also provides read-only commands such as `doctor`, `plan`, `verify`, `activity`, `verbose` and `tunnel-status`. Rule-changing commands are not required for ordinary app use. All tests involving firewall changes should have a known rollback/recovery path.

## Project principles

**Make the kernel do the enforcement. Make the UI tell the truth.**

- **Own only our rules:** never indiscriminately flush Android/OEM policies.
- **Distinguish verification from coverage:** ACTIVE, DEGRADED, unknown coverage, stale authorization, and unsupported interfaces are different conditions.
- **Be quiet by default:** no telemetry, background packet capture, or constant root polling.
- **Stay reversible:** explicit on/off, narrowly owned cleanup, verified removal, and optional boot restoration.
- **Prioritize usable security:** the main interface stays simple even when the engine isn't.

PocketUFW is MIT-licensed; see [LICENSE](LICENSE). The firewall policy is inspired by [UFW](https://launchpad.net/ufw), but the project is independent, does not use UFW's source code, and is not affiliated with Canonical. Thanks to the upstream Linux, Android, Tailscale, and open-source projects whose documentation made the investigation possible.

**FOSS be fossin'. 🦩**
