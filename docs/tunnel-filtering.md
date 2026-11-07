# Optional inbound filtering on VPN tunnels

**Status: development branch. Tested on real netfilter, tun and kernel WireGuard in isolated namespaces. Not yet activated on any phone.** Off by default, with no switch in the app.

PocketUFW's physical policy never sees traffic inside a tunnel. This optional filter covers that gap and changes nothing about the physical policy: `POCKETUFW_IN`, `POCKETUFW_TS` and their three hooks stay byte for byte the same, and the tunnel rules are separate chains with separate counters.

## How inbound packets reach Android

*Public edition: addresses and interface names from the test phone are generalized.*

### Measured on a Pixel 9a, Android 17, read-only

| Fact | What was seen |
| --- | --- |
| A tun's number says nothing | Tailscale was on `tun1`. Proton was on `tun0` on another phone. |
| A kernel WireGuard's name says nothing | Named after its server, with no "wg" in it. |
| The kernel reports the kind | WireGuard: `DEVTYPE=wireguard` in `/sys/class/net/NAME/uevent`. tun: a `tun_flags` file, `0x1001` (IFF_TUN, IFF_NO_PI). |
| sysfs doesn't name a tun's owner | `owner` and `group` are both `-1`. |
| fdinfo does | Tailscale's process, under its own app ID, holds `/dev/tun`, and `/proc/PID/fdinfo/FD` says `iff: tun1`. |
| Android's record agrees | `dumpsys connectivity` lists the package and `InterfaceName` for an Android VPN. |
| The proof holds where the app's root runs | Inside an app's mount namespace, where other apps' data is hidden, the probe gave the same answers. |
| Kernel WireGuard isn't in that record | Only the app VPN was listed. |
| Encrypted and inner traffic are separate | WireGuard's kernel UDP socket has an earlier `INPUT` rule keyed on its port, with no interface. Nothing in `INPUT` matches the inner interface. |
| Android doesn't filter inner traffic first | `oem_in` and `fw_INPUT` are empty, and `bw_INPUT` has no verdict for tunnel traffic. |
| Reverse-path filtering is off | `rp_filter` is 0 on every interface checked, so a packet is accepted for any local address on any interface. |
| Conntrack is live, with long timeouts | TCP established 5 days, UDP 30 s, UDP stream 120 s. |

### Measured earlier on the same phone

5 of 5 packets sent through Tailscale's tun from a tailnet peer reached the phone with no drop counted. See [hardware validation](hardware-validation.md).

### Measured in the lab, real kernel in namespaces

- A packet a process writes to a tun arrives as received on that interface, and `-i` matches it.
- A kernel WireGuard's decrypted packet arrives on the WireGuard interface, and `-i` matches it. Its encrypted UDP arrives on the physical interface.
- A forged packet written to a second tun is delivered if addressed to any local address, with `rp_filter` off.

### Documented, not measured for this provider

- Android: each write to a VPN's descriptor "injects an incoming packet just like it was received from the interface" ([VpnService](https://developer.android.com/reference/android/net/VpnService)). Proton on Android uses a tun, seen on two phones. Nobody has sent packets into its tunnel, so its behavior rests on this.
- Proton's port forwarding is documented for Windows, macOS and Linux only ([Proton](https://protonvpn.com/support/port-forwarding/)). Unsolicited traffic inside its tunnel may be rare on Android.
- The Tailscale SSH server doesn't run on Android ([Tailscale](https://tailscale.com/kb/1193/tailscale-ssh)).

### Not established

Proton's Android tunnel backend.

## What gets filtered

```
INPUT ... -i tun+   -m comment --comment PocketUFW-VPN -j POCKETUFW_VPN
INPUT ... -i NAME   -m comment --comment PocketUFW-VPN -j POCKETUFW_VPN   (each kernel WireGuard)

POCKETUFW_VPN   -s TAILNET -d TAILNET -i tun+ ACCEPT · ESTABLISHED,RELATED ACCEPT · INVALID DROP · DROP
```

`TAILNET` is `100.64.0.0/10` for IPv4 and `fd7a:115c:a1e0::/48` for IPv6, the ranges [Tailscale's source](https://github.com/tailscale/tailscale/blob/main/net/tsaddr/tsaddr.go) assigns from.

`tun+` matches whichever app holds a tun and whatever number it was given, so a new VPN is filtered as soon as it appears, with nothing watching for it. A kernel WireGuard is hooked by name because it has no common prefix, but only once the kernel reports that kind. One that comes up later is named as not filtered until `tunnel-refresh`.

Other tunnels, such as carrier `ipsec`, aren't touched and stay listed as not filtered. Outside the tailnet there's no ICMP allowance, unlike the physical chain: errors for existing connections pass as `RELATED`, and pings to a VPN's address are dropped.

## The tailnet is trusted by default

Traffic between tailnet devices passes without any per-port rule: Syncthing, Taildrop, existing SSH sessions and new ones, on any port, in both families. The rule comes first, so conntrack's view of a flow can't affect it.

**Why addresses and not the interface.** A VPN that re-establishes can come back on a different tun number, so an exemption naming `tun1` would cut the tailnet off until something noticed. Avoiding that needs a process watching for changes, and the kernel offers nothing else to match on:

- No netfilter match identifies who holds a tun. sysfs reports its owner as `-1`, and `-m owner` doesn't work on inbound traffic.
- `addrtype --limit-iface-in` would tie a destination to the interface that holds it. The test phone's kernel doesn't have `addrtype`.
- Android marks each network's packets, but with a rule that names the interface, set up as the network comes up. Matching that mark would still need something to follow it.

A node's tailnet addresses don't depend on any of that, so they're what the rule matches. They change only if the node is re-registered or signs in to another tailnet, and the rule covers the whole range, so that's fine too. It needs no proof at install and no refresh afterwards, and works the same whether Tailscale was up when the filter went on.

**Traffic the rule doesn't cover stays filtered, even on Tailscale's own tun:** a source outside the tailnet, or a tailnet source aimed at any other local address, such as the phone's Wi-Fi address. A kernel WireGuard shares the chain but can't use the rule, because of `-i tun+`. A subnet router with SNAT turned off delivers its LAN's addresses as the source, so those packets are dropped unless they're replies.

## What ownership does now

`vpn-probe tunnels` prints one line per tunnel. An app's tun is `proof=verified` only when both sources agree:

1. Android's VPN record names the package for that interface.
2. A process running under that package's app ID, from `packages.list`, holds `/dev/tun`, and fdinfo names exactly that interface.

An app can choose its process name but not its app ID, and it can't open `/dev/tun` itself. The scan covers just the claimed app's processes: walking every descriptor on the phone hadn't finished after two minutes, while the whole probe takes about 1.4 s.

The kernel can't enforce any of this, so the proof audits the rule and doesn't decide connectivity. `tunnel-on`, `tunnel-refresh` and `tunnel-status` say who holds tailnet addresses right now:

| Line | Meaning |
| --- | --- |
| `tailnet=VERIFIED iface=tun1` | Tailscale, proven by Android and the kernel. |
| `tailnet=UNVERIFIED iface=tun9 owner=... proof=...` | A tun holds a tailnet address and isn't proven Tailscale's, so the rule reaches it too. That's coverage gap 2 below. A slow `dumpsys` can also cause this for Tailscale itself. |
| `tailnet=DOWN` | No tun holds one. |

## Coverage gaps

Trusting the tailnet with no watcher costs these. The first two are pinned by a test that passes packets on purpose.

1. **A second tun alongside Tailscale can claim tailnet addresses.** Its packets pass if they use a tailnet source and a local tailnet destination, because the kernel can't tell the two tuns apart. Android allows one VPN per user, so this needs a second user or work profile, or a root-run tunnel. A kernel WireGuard can't do it.
2. **Another VPN whose own address is in `100.64.0.0/10`** gets the rule for traffic from that range. Everything else on that VPN is still filtered, and `tunnel-status` reports it as `UNVERIFIED`. The Proton WireGuard configuration seen on the test phone uses `10.2.0.2`.
3. **Trust is for the whole tailnet.** A compromised tailnet device can reach anything listening on the phone's tailnet address. Tailscale's ACLs are what limit that.

## A reverse SSH tunnel

If the phone runs `ssh -R` to another host, with `sshd` bound to loopback, then the tunnel is a connection the phone started, and connections it forwards reach `sshd` on `lo`, which is never hooked. It works whatever the filter does. The lab reproduces this: a session started before the filter keeps working, and a reconnect during it works. A direct connection to port 8022 is refused, because nothing listens on the tailnet address.

## Lifecycle

| Action | Tunnel rules |
| --- | --- |
| `enable` | Never installed. Refused if any remain. |
| `tunnel-on` | Requires a verified firewall. Installs chains first and hooks last. Rolls back on any failure or failed read-back, and reports who holds tailnet addresses. |
| `verify` | Off is fine. If on, the exact rules in both families, or `DEGRADED`, which also blocks refreshes and counter resets. |
| `activity`, `verbose` | `tunnel_filter`, `tunnel_hooks`, and separate `ipv4_tunnel_*` and `ipv6_tunnel_*` counters, including `ipv4_tunnel_tailnet`. Physical counters mean what they always meant. |
| `reset-counters` | Includes the tunnel chains when present. |
| `disable`, Off, Remove PocketUFW | Removed with everything else. `residue` reads the whole table back. |
| `tunnel-off` | Removes only tunnel rules. |
| Restart | Gone, and never restored. Boot restoration only runs `enable`. |
| Ordinary uninstall | Stays until the next restart, like the rest. The README's manual commands cover it. |

In the app: the Status screen lists the extra hooks and rules, and a hooked tunnel leaves the "Not filtered" list. There's no switch, no tunnel counter display and no wording change yet.

## Rollback for hardware tests

`tools/tunnel-rollback` is a dead-man switch, not packaged in the app, because the shipped scripts promise nothing stays running.

```sh
sh tunnel-rollback on 120 "$ENGINE"        # arm, then tunnel-on. Unconfirmed, tunnel-off runs at 120 s.
sh tunnel-rollback physical 120 "$ENGINE"  # arm, then enable. Unconfirmed, disable runs at 120 s.
sh tunnel-rollback confirm                 # keep the rules; run this over the path being tested
sh tunnel-rollback status   # ARMED, UNCLEAN, CONFIRMED, FIRED, FAILED, CANCELLED, LOST or NONE
```

The timer starts in its own session before any rule exists, and no rule is installed until it answers, so losing the shell can't stop it. Tunnel mode removes only tunnel rules. It uses the wall clock, so a phone in deep sleep fires when it next wakes. A restart is a second way out.

**Whether rules are gone is read from the kernel, never taken from the engine's exit status,** and a table that can't be read isn't clean:

- A failed install stands the timer down, `CANCELLED`, only if both tables read back clean.
- If rules remain, it tries the removal once more and reports `UNCLEAN`. The timer stays armed and retries straight away, and `confirm` is refused.
- `FIRED` means the tables read back clean. If that never happens within five tries, the state is `FAILED`, and the rules need removing by hand.
- It refuses to arm while the rules it would remove already exist, so a rollback only ever removes what it installed.

## Hardware test plan

Run from this branch's scripts, pushed to a temporary folder over adb. No app build is needed. Keep USB attached throughout.

1. **Physical firewall, no VPN.** With every VPN off, `tunnel-rollback physical`. Send a known number of unsolicited UDP datagrams and TCP SYNs to an unbound port in both families from a LAN host. Each DROP counter must rise by exactly that number, in packets and in bytes, with no change while nothing is being sent, and the same probes must get answers once the firewall is off.
2. **Prove the rollback fires.** Leave it unconfirmed: `FIRED`, and the tables match the baseline.
3. **Filter on, tailnet up.** Tailscale up, `enable`, then `tunnel-rollback on`. `tunnel-status` shows `tailnet=VERIFIED`.
4. **Tailnet.** From a tailnet peer: ping, a TCP connection to a listener, Taildrop, and the SSH bridge. `ipv4_tunnel_tailnet` rises and tunnel drops don't.
5. **Reconnect.** Toggle Tailscale with no refresh. It may get a new tun number. Repeat step 4.
6. **Physical filter underneath.** LAN probes from step 1 still drop exactly, with the tunnel filter on.
7. **Kernel WireGuard.** `tunnel-status` reports its kind. Public traffic still works. Sending inner packets needs control of the far end, so unless that changes this is covered by the lab only.
8. **Proton.** Switch to it. Check its owner, its proof and browsing. No unsolicited traffic can be sent into its tunnel from here.
9. **Removal.** `disable` with the filter on: `residue` is clean and the tables match the baseline.

**If anything goes wrong:** wait for the timer, or over USB run `su -c "sh $ENGINE disable"`, or restart.
