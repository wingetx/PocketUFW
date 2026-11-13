# PocketUFW compatibility priorities

PocketUFW should **probe capabilities**, not require a particular root-manager brand. These are engineering targets, not compatibility promises.

## Root methods

| Root provider | Plan | Verification state |
| --- | --- | --- |
| Magisk | Real UID 0 plus supported kernel/netfilter features | Rooted Pixel 9a and Moto G 5G reconnaissance; Moto rule engine live-tested |
| KernelSU | Same UID 0 and netfilter checks; no Magisk-specific API dependency | Not yet hardware tested |
| APatch | Same UID 0 and netfilter checks; no Magisk-specific API dependency | Not yet hardware tested |
| Shizuku (ADB shell UID 2000) | Optional diagnostics; **not** a replacement for kernel firewall root | Not part of current firewall backend |

Do not infer firewall capabilities from an installed APK or an `su` binary. Verify the effective UID, usable IPv4/IPv6 kernel extensions, and selected iptables backend. A root manager's name is only diagnostic information.

## Common network stacks

| Stack | Strategy | Current state |
| --- | --- | --- |
| Tailscale Android | Verify app-owned UDP sockets for both families and refresh on changes | `vpn-probe` validates current Android UDP listeners at activation, and `pocketufw refresh` updates only owned exception chains. No continuous watcher yet. Inner traffic: see [tunnel filtering](tunnel-filtering.md) |
| WireGuard kernel interfaces and manual Proton configuration | Preserve existing kernel and Android WireGuard rules; do not flush or steal UDP ports | Coexistence with PocketUFW and Tailscale tested on a Pixel 9a. The optional [tunnel filter](tunnel-filtering.md) finds these by kernel type, not name. Replies through it passed on the phone, and blocking inside it is lab tested only |
| WireGuard via Android VPN app | Respect `VpnService`; avoid assuming kernel interface names | **Proton VPN active on Moto Android 15**: IPv4/IPv6 HTTPS and PocketUFW enable/disable/refresh smoke tests passed. On a Pixel 9a, the optional tunnel filter also worked with Proton, including a reconnect |
| OpenVPN / userspace `tun*` VPN | Don't filter virtual interface by default; examine physical underlying traffic and possible direct UDP listeners | Planned. The optional [tunnel filter](tunnel-filtering.md) denies inbound on any `tun*`: tested in the lab and on a Pixel 9a with a temporary tun, not on an OpenVPN tunnel |
| Commercial VPN providers | Treat provider names as presentation metadata; actual interface/socket behavior determines rules | Planned |
| AFWall+ | Refuse competing activation until AFWall+ is disabled and its owned hooks are cleared | Existing preflight checks one AFWall+ hook; broader detection planned |
| NetGuard / other Android `VpnService` firewalls | Never take Android's VPN slot; document feature overlaps and limitations | PocketUFW does not use `VpnService` |

## Hardware and kernel variability

- Initially verified on Motorola Android 15 (kernel 5.4) with **legacy** `iptables` and `ip6tables`; Pixel 9a Android 17 inspected separately.
- Android's native firewall stack may use iptables, eBPF, or vendor chains. We must not flush, reorder, or bypass system-owned rules.
- Current physical-interface patterns cover `wlan+`, `rmnet+`, `v4-rmnet+`, and `v4-wlan+` (Wi-Fi 464XLAT). Many other vendors may use `ccmni*`, `wwan*`, `eth*`, or other identifiers. Unknown interfaces must be called out explicitly rather than silently claimed protected.
- An older three-hook installation is DEGRADED under this verifier until explicitly removed and enabled again with the fourth hook. Inspection does not silently reinstall rules. Cleanup handles both old and new owned hook signatures and preserves other owners' rules.
- `iptables-nft` and pure `nftables` require explicit backend testing; using an incompatible firewall backend may produce misleading success messages.
- No phone requires rooting just for PocketUFW. The app should clearly say when the full kernel firewall is unavailable.

## Safe VPN port discovery

The read-only `vpn-probe` helper asks `ss` for bound UDP sockets separately for IPv4 and IPv6, then validates the process PID against `/proc/PID/cmdline` using the full Android Tailscale package name, and requires the process UID to own Tailscale's package data directory. Process names alone prove nothing, because any app can set them with `android:process`. A failed probe only withholds the exception; it never stops the firewall.

It prints only verified port numbers. An ambiguous or unverifiable listener is an **error**, never a guessed exception. A missing Tailscale process is not an error; both ports are empty.

**Implemented experimentally:** manual `refresh` of verified IPv4/IPv6 exceptions, with rollback after detected update errors. **Not implemented yet:** automatic port monitoring, persistent recovery, secure per-user allow/deny rules, or a production watchdog. Avoid calling any version production-ready until these are tested.

## Before wider release

PocketUFW does not automatically repair firewall rules or monitor VPN changes in
the background. Use **Recheck** for a current inspection and the app's explicit
refresh or recovery controls when needed. Installed rules keep working while the
app is closed, but a previous inspection does not prove that later VPN addresses,
listeners, or rules are unchanged. See [tunnel filtering](tunnel-filtering.md) for
the detailed authorization and refresh limitations.

1. Validate root and firewall backends on Magisk, KernelSU, and APatch devices.
2. Expand verified VPN socket handling and automatically monitor Tailscale port changes without requiring manual `refresh`.
3. Recovery that works after process death, reboot, route changes, and partial iptables failure.
4. IPv4/IPv6, TCP/UDP, Android IMS/DHCP/ICMPv6, hotspot and cellular handoff tests on actual supported devices.
5. Independent audit and documentation of upstream root/iptables restrictions.

Helpful upstream documentation: [Tailscale firewall ports](https://tailscale.com/docs/reference/faq/firewall-ports), [KernelSU](https://kernelsu.org/guide/what-is-kernelsu.html), [APatch](https://apatch.dev/what-is-apatch.html).
