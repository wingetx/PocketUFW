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
- A forged packet written to a second tun is delivered if addressed to any local address. The interface is the only thing that tells the tunnels apart.

### Documented, not measured for this provider

- Android: each write to a VPN's descriptor "injects an incoming packet just like it was received from the interface" ([VpnService](https://developer.android.com/reference/android/net/VpnService)). Proton on Android uses a tun, seen on two phones. Nobody has sent packets into its tunnel, so its behavior rests on this.
- Proton's port forwarding is documented for Windows, macOS and Linux only ([Proton](https://protonvpn.com/support/port-forwarding/)). Unsolicited traffic inside its tunnel may be rare on Android.
- The Tailscale SSH server doesn't run on Android ([Tailscale](https://tailscale.com/kb/1193/tailscale-ssh)).

### Not established

Proton's Android tunnel backend. Which Tailscale features run inside its own process and so never reach the tun: a phone with Tailscale up had no Tailscale TCP listener in the kernel, which suggests they don't, but Taildrop and similar weren't tested. The IPv6 prefix `fd7a:115c:a1e0::/48` comes from addresses seen on real devices, and the Tailscale page checked doesn't state it.

## What gets filtered

```
INPUT ... -i tun+   -m comment --comment PocketUFW-VPN -j POCKETUFW_VPN
INPUT ... -i NAME   -m comment --comment PocketUFW-VPN -j POCKETUFW_VPN   (each kernel WireGuard)

POCKETUFW_VPN    ESTABLISHED,RELATED ACCEPT · INVALID DROP · POCKETUFW_TRUST · DROP
POCKETUFW_TRUST  -s PEER -d OWN_TAILNET_ADDRESS -i PROVEN_TUN -p tcp|udp --dport PORT ACCEPT
```

**Denying needs no proof, and allowing needs a lot.** `tun+` matches whichever app holds a tun and whatever number it was given, so a new VPN is denied as soon as it appears. An interface isn't called anyone's on the strength of its name anywhere in this design.

A kernel WireGuard is hooked by name because it has no common prefix, but only once the kernel reports that kind. One that comes up later is named as not filtered until `tunnel-refresh`.

Other tunnels, such as carrier `ipsec`, aren't touched and stay listed as not filtered. Unlike the physical chain, this one has no ICMP allowance: errors for existing connections pass as `RELATED`, and pings to the phone's tunnel addresses are dropped.

## Identifying who owns a tunnel

`vpn-probe tunnels` prints one line per tunnel. An app's tun is `proof=verified` only when both sources agree:

1. Android's VPN record names the package for that interface.
2. A process running under that package's app ID, from `packages.list`, holds `/dev/tun`, and fdinfo names exactly that interface.

An app can choose its process name but not its app ID, and it can't open `/dev/tun` itself. Any disagreement gives `android-only` or `none`, and that only withholds allowances. The scan covers just the claimed app's processes: walking every descriptor on the phone hadn't finished after two minutes, while the whole probe takes about 1.4 s.

## Allowances

```sh
pocketufw tunnel-on --trust tcp:100.64.0.2:22000
```

An allowance is refused unless exactly one tunnel is `verified` as `com.tailscale.ipn`. It takes one Tailscale address and one port, with no ranges or wildcards. The rule binds the peer, Tailscale's own address, the proven interface, the protocol and the port.

**What each binding stops:**

- `-i`: a forged packet arriving through another tunnel. Without it, a VPN server could claim to be a trusted peer, because `rp_filter` is off.
- `-d`: the interface name being reused. If Tailscale goes away and another VPN gets its old name, the rule still names that interface, but Tailscale's address is no longer local, so it can't fire.
- `-s` relies on WireGuard's design, where a peer's packets are accepted only from addresses assigned to that peer. That wasn't tested for Tailscale here.

**When Tailscale re-establishes its VPN,** it can get a new number. The filter keeps holding through `tun+`, and existing connections continue, because conntrack isn't tied to an interface. New connections matching an allowance are dropped until `tunnel-refresh` rebinds it, which `tunnel-status` reports as `binding=STALE`. This fails closed, and there's no watcher to do it automatically.

**A remaining gap:** while an allowance is stale and Tailscale is still up, a second VPN running at the same time could hold the old interface name, and then a forged packet from it would match. Android allows one VPN per user, so this needs a second user or work profile, or a root-run tunnel. `tunnel-status` shows `binding=STALE` during that time, and `tunnel-refresh` closes it.

## A reverse SSH tunnel needs no allowance

If the phone runs `ssh -R` to another host, with `sshd` bound to loopback, then:

- The tunnel is a connection the phone started, so everything coming back is `ESTABLISHED`.
- Connections it forwards reach `sshd` on `lo`, which is never hooked.
- Nothing listens on the tailnet address, so an inbound allowance gets a refused connection.

The lab reproduces this exactly: a session started before the filter keeps working, a reconnect during it works, a direct connection is dropped, and adding an allowance only changes that to refused. Keep the allowance list empty unless something really listens on the tailnet address.

## Lifecycle

| Action | Tunnel rules |
| --- | --- |
| `enable` | Never installed. Refused if any remain. |
| `tunnel-on` | Requires a verified firewall. Installs chains first and hooks last. Rolls back on any failure or failed read-back. |
| `verify` | Off is fine. If on, the exact rules in both families, or `DEGRADED`, which also blocks refreshes and counter resets. |
| `activity`, `verbose` | `tunnel_filter`, `tunnel_hooks`, and separate `ipv4_tunnel_*` and `ipv6_tunnel_*` counters. Physical counters mean what they always meant. |
| `reset-counters` | Includes the tunnel chains when present. |
| `disable`, Off, Remove PocketUFW | Removed with everything else. `residue` reads the whole table back. |
| `tunnel-off` | Removes only tunnel rules. |
| Restart | Gone, and never restored. Boot restoration only runs `enable`. |
| Ordinary uninstall | Stays until the next restart, like the rest. The README's manual commands cover it. |

In the app: the Status screen lists the extra hooks and rules, and a hooked tunnel leaves the "Not filtered" list. There's no switch, no tunnel counter display and no wording change yet.

## Rollback for hardware tests

`tools/tunnel-rollback` is a dead-man switch, not packaged in the app, because the shipped scripts promise nothing stays running.

```sh
sh tunnel-rollback on 120 "$ENGINE"   # arm, then install. Unconfirmed, tunnel-off runs at 120 s.
sh tunnel-rollback confirm            # keep the rules; run this over the path being tested
sh tunnel-rollback status             # ARMED, CONFIRMED, FIRED, FAILED, CANCELLED, LOST or NONE
```

The timer starts in its own session before any rule exists, and no rule is installed until it answers, so losing the shell can't stop it. It removes only tunnel rules. It uses the wall clock, so a phone in deep sleep fires when it next wakes. A restart is a second way out.

## Hardware test plan

Not run yet. Needs an installed build containing this code. Keep USB attached throughout.

1. **Baseline.** Tailscale up, firewall `ACTIVE`, bridge up. Save `iptables -S` and `ip6tables -S` for both families. Confirm `tunnel-status` shows `proof=verified`.
2. **Prove the rollback first.** `tunnel-rollback on 30`, change nothing else, and confirm it fires: `status` says `FIRED`, the firewall is still `ACTIVE`, and the tables match the baseline.
3. **Filter with a rollback armed.** `tunnel-rollback on 300`. Check `verify` and `activity`.
4. **Bridge.** Over the existing session, run a command. Close and reconnect it. Run `confirm` over the bridge, which proves the path works.
5. **Inbound.** From a tailnet peer, send unsolicited UDP and TCP to a closed port, in both families. Expect no ICMP refusal, and tunnel counters rising by exactly that amount, with physical counters unchanged. Watch the `INVALID` rule with `iptables -L POCKETUFW_VPN -n -v -x`: drops there on an established flow would mean connections are being hurt.
6. **Normal use.** Browsing, DNS, MagicDNS, Taildrop, Syncthing, and anything else that reaches the phone over the tailnet.
7. **Reconnect.** Toggle Tailscale, and note the new tun number. Existing sessions, the bridge's reconnect, and `tunnel-refresh` if allowances are in use.
8. **Kernel WireGuard.** `tunnel-status` reports its kind. Public traffic still works. Sending inner packets needs control of the far end, which isn't available, so unless that changes this is covered by the lab only.
9. **Proton.** Switch to it. Check its owner, its proof and browsing.
10. **Removal.** Remove PocketUFW with the filter on: read-back clean, and the tables match the baseline. Then a restart with boot restoration armed: the firewall returns and the tunnel filter doesn't.

**If anything goes wrong:** wait for the timer, or over USB run `su -c "sh $ENGINE tunnel-off"`, or restart.
