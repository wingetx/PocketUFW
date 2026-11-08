# Optional inbound filtering on VPN tunnels

**Status: development branch, optional and off by default.** Enabling remains CLI-only; Android exposes status and tunnel-only recovery. The review follow-up to `ebe9019` is local and awaits another independent review. The phone measurements below are historical results from the earlier whole-range policy, not hardware validation of these changes. No watcher or tunnel boot restoration is added.

PocketUFW's physical policy never sees traffic inside a tunnel. This optional filter covers that gap and changes nothing about the physical policy: `POCKETUFW_IN`, `POCKETUFW_TS` and their three hooks stay byte for byte the same, and the tunnel rules are separate chains with separate counters.

## How inbound packets reach Android

*Public edition: addresses and interface names from the test phone are generalized.*

### Measured on a Pixel 9a, Android 17, read-only

| Fact | What was seen |
| --- | --- |
| A tun's number says nothing | Tailscale was on `tun1`. Proton was on `tun0` on another phone. |
| A tun comes back as a new interface | After toggling and force-stopping Tailscale it was `tun1` each time, with a new interface index and a new Android network mark. A changed number hasn't been seen on this phone, and the rule doesn't depend on either. |
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

Proton's Android tunnel backend. Whether a Taildrop transfer ever touches the firewall: its peer API answered on port 1 with no matching kernel listener, so it appears to end inside Tailscale's own process.

## What gets filtered

```
INPUT ... -i tun+   -m comment --comment PocketUFW-VPN -j POCKETUFW_VPN
INPUT ... -i NAME   -m comment --comment PocketUFW-VPN -j POCKETUFW_VPN   (each kernel WireGuard)

POCKETUFW_VPN   -s TAILNET -d NODE_HOST -i tun+ ACCEPT · ESTABLISHED,RELATED ACCEPT · INVALID DROP · DROP
```

`TAILNET` is `100.64.0.0/10` for IPv4 and `fd7a:115c:a1e0::/48` for IPv6, the ranges [Tailscale's source](https://github.com/tailscale/tailscale/blob/main/net/tsaddr/tsaddr.go) assigns from.

`NODE_HOST` is the phone's initially authorized IPv4 `/32` or IPv6 `/128`, never the whole destination range.

`tun+` matches whichever app holds a tun and whatever number it was given, so a new VPN is filtered as soon as it appears, with nothing watching for it. A kernel WireGuard is hooked by name because it has no common prefix, but only once the kernel reports that kind. One that comes up later is named as not filtered until `tunnel-refresh`.

Other tunnels, such as carrier `ipsec`, aren't touched and stay listed as not filtered. Outside the tailnet there's no ICMP allowance, unlike the physical chain: errors for existing connections pass as `RELATED`, and pings to a VPN's address are dropped.

## Explicit deny-only mode

For Proton-only or WireGuard-only use, run `pocketufw tunnel-on --deny-only`
(or `tunnel-plan --deny-only` to inspect first). A verified physical firewall is
still required. This mode installs only established/related acceptance, invalid
drops and the final drop; it has **no tailnet exemption** and requires no Tailscale
authorization. Kernel WireGuard interfaces named `tun*` are supported through the
wildcard hook. Other kernel WireGuard names require discovery/refresh as before.

This choice filters unsolicited tailnet peer connections if Tailscale starts later.
Existing established flows may still pass. Neither a Tailscale connection nor
`tunnel-refresh` changes the mode. To opt into pinned trust, explicitly run
`tunnel-off`, then `tunnel-on` while ownership can be verified. Failed default
authorization never falls back to deny-only. Both modes remain session-only.

## Explicit authorization of node destinations

Without `--deny-only`, `tunnel-plan` and `tunnel-on` require one currently verified Tailscale tun and one
node address in each family. Android's package/interface record must agree with
an open tun descriptor held by a process with Tailscale's app ID. The probe checks
interface identity and ownership around the address read and refuses incomplete
Android output, missing addresses and ambiguous ownership. It never substitutes
routes, another VPN's address, previous output or a whole destination range.

`tunnel-on` is the explicit authorization. The live rules retain the two pins;
there is no separate address cache. Tailscale can disconnect, reconnect, change
its tun number or become temporarily unverifiable without changing those rules.
`tunnel-refresh` updates ordinary WireGuard hooks only, never the pins. A new node
address requires explicit `tunnel-off` followed by `tunnel-on` while Tailscale is
verified. Off and reboot discard the authorization. Enabling while Tailscale is
down is refused before any tunnel rule changes, even if it was authorized earlier.

Traffic from the tailnet source ranges to either pin passes on `tun*`, on any port,
before conntrack checks. Ordinary Tailscale reconnections therefore need no watcher.
A different local address in CGNAT or the IPv6 tailnet range is no longer trusted.
Traffic outside the source ranges still needs an established/related connection;
this includes subnet-router traffic with SNAT disabled.

This authenticates the initial address selection, not subsequent packets. Static
iptables rules cannot identify the app holding a tun. Matching the current name
would break reconnections when Android renumbers it. `-m owner` is not an INPUT
match, and interface/address association would not authenticate the packet source.

**A few drops at startup are normal.** Each time Tailscale's tun came up on the test phone, `ipv6_tunnel_blocked` rose by about 6 within a second, then stayed still. In the run that was captured, their byte counts fit the phone's own multicast listener reports exactly, and no peer sent anything like them. A later run showed the same 6 packets and 536 bytes, and Proton showed the matching 4 packets and 364 bytes after a reconnect. Separately, IPv4 packets of about 1.3 KB each were dropped for a while after a reconnect, and similar ones after a network change, with none in 62 s of normal browsing on Proton. That fits servers resending for abandoned connections, but they weren't captured. That phone holds a multicast routing socket (`mc_forwarding=1`), which is the likely reason its own reports loop back through `INPUT`. This wasn't reproduced in the lab, where the test tun sent no reports at all, so the mechanism is unproven. Tailnet traffic was unaffected.

## What ownership does now

`vpn-probe tunnels` prints one line per tunnel. An app's tun is `proof=verified` only when both sources agree:

1. Android's VPN record names the package for that interface.
2. A process running under that package's app ID, from `packages.list`, holds `/dev/tun`, and fdinfo names exactly that interface.

An app can choose its process name but not its app ID, and it can't open `/dev/tun` itself. The scan covers just the claimed app's processes: walking every descriptor on the phone hadn't finished after two minutes, while the whole probe takes about 1.4 s.

Initial authorization uses that ownership proof. Later observations describe
current ownership without revoking or expanding the pins. Status separates them:

| Field | Meaning |
| --- | --- |
| `tailnet_trust=DENY_ONLY`, `tailnet_current=DENY_ONLY` | No tailnet exemption; starting Tailscale does not change policy. |
| `tailnet_trust=PINNED_DESTINATIONS` | The installed exception grammar contains one exact node destination per family. |
| `tailnet_observed4`, `tailnet_observed6` | Currently verified addresses; never implicitly installed. |
| `tailnet_pin4`, `tailnet_pin6` | The destinations actually retained in the live rules. |
| `tailnet_ingress=ADDRESS_ONLY` | Packets are not authenticated by source or interface ownership. |
| `tailnet=VERIFIED iface=...` | This interface currently holds a tailnet address and has verified Tailscale ownership; it does not authenticate other ingress paths. |
| `tailnet=UNVERIFIED ...` | Another or unproven interface holds an address in a tailnet range; that alone does not grant it an exception. |
| `tailnet=DOWN` | No observed `tun*` holds a tailnet address. Pins can still be installed. |
| `tailnet_current=MATCH` | Current verified node addresses match the installed pins. |
| `tailnet_current=REAUTHORIZE` | Verified node addresses differ; refresh will not change trust. |
| `tailnet_current=UNVERIFIED` | Current authorization could not be verified; installed pins stay unchanged. |
| `tailnet_wireguard=CONFLICT` | A kernel WireGuard currently has a `tun*` name. Live rules remain installed and may trust its packets; overall verification is DEGRADED. |
| `tailnet_wireguard=NONE_OBSERVED` / `UNKNOWN` | No current conflict was observed, or interface kinds could not be read. Neither predicts future devices. |

## Remaining trust limitations and WireGuard

1. **Injection to a pinned local destination remains possible.** A different `tun*`
   can inject a tailnet source addressed to a pin, even without holding that address
   itself. A second Android VPN can exist in another user/work profile, or a tunnel
   can be root-managed. Pins reduce accidental CGNAT trust; they do not authenticate
   the sender. Real namespace tests deliberately retain this passing-packet proof.
2. **Kernel WireGuard named `tun*` shares the wildcard.** In pinned mode, initial authorization and
   installation refuse an observed conflict, even if Android claims it is Tailscale.
   `verify`, `activity` and the app report DEGRADED if one appears or is renamed later.
   This is detection on explicit inspection, not automatic blocking or cleanup. Its
   decrypted packets can still use a pin if WireGuard permits that source. Rename
   the conflicting WireGuard or turn the optional filter off, then recheck. A static
   name exclusion could later block Tailscale when it reuses that name, so none is
   installed. There is no persistent watcher or claim of protection between reads.
3. **Source trust still covers the tailnet ranges.** Legitimate tailnet peers can
   reach listeners at the pinned addresses subject to Tailscale's access rules.
   Pinning is not per-peer or per-service authorization.
4. **Earlier Android/OEM ACCEPT rules can bypass appended hooks.** They remain
   untouched and the bounded rules report identifies direct ACCEPTs before relevant
   hooks. Foreign chains are not recursively audited.

Old whole-range rules are DEGRADED under this version. They are neither called
pinned nor silently migrated: remove them with `tunnel-off`, then authorize anew.
No read command revokes existing rules. Root controls the firewall and can alter
pins or bypass this policy; verification is not an attestation against root.

## A reverse SSH tunnel

If the phone runs `ssh -R` to another host, with `sshd` bound to loopback, then the tunnel is a connection the phone started, and connections it forwards reach `sshd` on `lo`, which is never hooked. It works whatever the filter does. The lab reproduces this: a session started before the filter keeps working, and a reconnect during it works. A direct connection to port 8022 is refused, because nothing listens on the tailnet address.

## Lifecycle

| Action | Tunnel rules |
| --- | --- |
| `enable` | Never installed. Refused if any remain. |
| `tunnel-on` | Requires a verified firewall and current dual-family Tailscale address authorization, with no observed `tun*` WireGuard conflict. Installs chains first and hooks last. Rolls back on any failure or failed read-back, and reports who holds tailnet addresses. |
| `tunnel-on --deny-only` | Explicitly installs no tailnet exemption; no Tailscale proof required. Later Tailscale connections remain subject to the deny policy. |
| `verify` | Off is fine. If on, the exact rules in both families, or `DEGRADED`, which also blocks refreshes and counter resets. |
| `activity`, `verbose` | `tunnel_filter`, `tunnel_hooks`, and separate `ipv4_tunnel_*` and `ipv6_tunnel_*` counters, including `ipv4_tunnel_tailnet`. Physical counters mean what they always meant. |
| `reset-counters` | Includes the tunnel chains when present. |
| `disable`, Off, Remove PocketUFW | Removed with everything else. `residue` reads the whole table back. |
| `tunnel-off` | Removes only tunnel rules. |
| Restart | Gone, and never restored. Boot restoration only runs `enable`. |
| Ordinary uninstall | Stays until the next restart, like the rest. The README's manual commands cover it. |

In the app: the Status screen lists the extra hooks and rules. A tunnel leaves the "Not filtered" list only after the complete policy and hooks verify in both families. The app names the session-only tunnel state and address-trust limitation; boot settings explicitly restore physical filtering only. There is still no tunnel enable switch or tunnel counter display. The Firewall
screen shows the installed pins and a separate connectivity observation:
`MATCH` means current verified addresses match (not a reachability test),
`REAUTHORIZE` shows verified replacement addresses while protection may remain
ACTIVE, and `UNVERIFIED` means the current ownership/address proof was unavailable.
No observation changes trust. A DEGRADED tunnel offers **Remove tunnel rules only**
with confirmation. This invokes `tunnel-off`, keeps physical rules and boot opt-in,
and verifies the result. If physical rules are also broken, recovery still reports
failure/DEGRADED and the existing partial-rule recovery remains available afterward.

## Rollback for hardware tests

`tools/tunnel-rollback` is a dead-man switch, not packaged in the app, because the shipped scripts promise nothing stays running.

```sh
sh tunnel-rollback on 120 "$ENGINE"        # arm, then pinned tunnel-on; Tailscale proof required
sh tunnel-rollback on 120 "$ENGINE" --deny-only  # no tailnet exemption; explicit Proton/WG-only choice
sh tunnel-rollback physical 120 "$ENGINE"  # arm, then enable. Unconfirmed, disable runs at 120 s.
sh tunnel-rollback confirm                 # keep the rules; run this over the path being tested
sh tunnel-rollback status   # ARMED, UNCLEAN, CONFIRMED, FIRED, FAILED, CANCELLED, LOST or NONE
```

The timer starts in its own session before any rule exists, and no rule is installed until it answers, so losing the shell can't stop it. Tunnel mode removes only tunnel rules. It uses the wall clock, rounded up by at most one second, so a phone in deep sleep resumes the deadline check when it wakes. The timer must also wait for an in-flight installer to finish before it can report FIRED. A stalled installer can therefore delay cleanup; ARMED with a negative remaining time is not a successful rollback. The installer refuses success after expiry and requests cleanup. A restart is a second way out.

**Whether rules are gone is read from the kernel, never taken from the engine's exit status,** and a table that can't be read isn't clean:

- A failed install stands the timer down, `CANCELLED`, only if both tables read back clean.
- If rules remain, it tries the removal once more and reports `UNCLEAN`. The timer stays armed and retries straight away, and `confirm` is refused.
- `FIRED` means the tables read back clean. If that never happens within five tries, the state is `FAILED`, and the rules need removing by hand.
- It refuses to arm while the rules it would remove already exist, so a rollback only ever removes what it installed.

## Hardware results

Run on a Pixel 9a from this branch's scripts, pushed over adb and deleted afterwards. Details are in [hardware validation](hardware-validation.md).

| Step | Result |
| --- | --- |
| Physical firewall, no VPN | Every probe counted exactly, in packets and bytes, in the right family. |
| Rollback fires unconfirmed | Yes, on time, with the tables back at baseline. |
| Partial install, failed cleanup | `UNCLEAN`, `confirm` refused, and removed once cleanup worked. |
| Filter on before Tailscale starts | Tailnet works with no refresh. |
| Tailscale toggled, and force-stopped | Ping, TCP and rules unaffected, with no refresh. |
| `scp` pulling from a tailnet host | Delivered with a matching hash, after a force stop. |
| Existing TCP connection as the filter goes on | Kept working. |
| Tailscale and kernel WireGuard together | Both hooked. Browser traffic and forced fetches on both families went through WireGuard, with replies passing as established. |
| Reverse SSH bridge | A connection through it kept working as the filters went on, a new one connected, and it was back about 15 s after a Tailscale toggle. Checked as far as SSH key exchange, not a full login. |
| Real Syncthing sync | Both directions, twice, with matching hashes and no conflict copies, and reconnected about 15 s after a toggle. One connection was dialed to the phone from outside, through the filter. |
| Proton's Android VPN | Owner verified. DNS, IPv4 and IPv6 worked, LAN probes dropped, and its reconnect needed no refresh. Browsing had 0 tunnel drops until a reconnect. |
| Real packets written into a temporary tun | Dropped exactly, 20 of 20 in each case, unless tailnet-addressed. A control with the firewall off reached the kernel. |
| Wi-Fi to cellular and back | Rules byte-identical, everything reconnected within about 16 s, and unsolicited IPv6 to the carrier address was dropped. A test call worked. |
| `disable` with the filter on | `residue` clean, tables at baseline. |

**Not run on a phone:**

- **A real unsolicited packet dropped on a real VPN's own tunnel.** Nothing else can send one into these tunnels from outside. Enforcement was shown on this kernel with a temporary tun, the same `tun+` rule, not on Proton's or Tailscale's own device. A zero on the tunnel counter proves nothing either way.
- Kernel WireGuard's inner traffic being dropped, which needs control of the far end, and WireGuard restarting while the filter is on.
- Unsolicited IPv4 on cellular, which a LAN host can't address, Wi-Fi calling, and IMS registration itself.
- A completed Taildrop and a full SSH login through the bridge.

**If anything goes wrong:** wait for the timer, or over USB run `su -c "sh $ENGINE disable"`, or restart.


## Independent audit remediation — local, November 7, 2026

These lifecycle changes were not deployed to a phone. This audit-fix series initially
left the tailnet policy unchanged; the subsequent pinned policy is described above. Previous hardware results above apply
to the earlier revision; they are not claims of hardware validation of these fixes.

- `activity` and `verbose` now verify the same complete dual-family policy as
  `verify`. Missing tunnel hooks cannot produce ACTIVE counters or hide a tunnel
  from the app's uncovered-interface list.
- A failed `tunnel-refresh` rolls back its own additions and deletions. Deleted
  hooks return to their prior positions, preserving foreign INPUT rules. Rollback
  failures remain visible as degraded protection. SIGKILL cannot run cleanup;
  subsequent verification detects a partial install rather than promising repair.
- `tunnel-status` reports `tunnel_uncovered` for newly discovered WireGuard names
  lacking either family's hook. ON means the installed rules verify, not that
  every present or future interface is covered. New names still need refresh.
- Earlier direct ACCEPT rules are compared with each relevant hook, including
  rules between the wildcard and a later WireGuard hook. The rules are reported,
  not rewritten. An earlier WireGuard transport-port ACCEPT still admits inner
  UDP targeting that port. Verdicts inside foreign chains remain outside this
  bounded report; no universal coverage claim is made.
- A shared cross-process lifecycle lock covers boot enable/disable/purge, the boot
  restore decision, bridge operations through final readback, and CLI mutations.
  Nested scripts inherit its descriptor. The engine snapshot lock remains
  separate; lock order is lifecycle then snapshot. Mutation requires usable
  `flock`; read-only engine inspection remains available. Runtime lock files stay
  private in `/dev` until reboot and are never unlinked while other operations
  might use them.
- Boot cleanup disarms the marker first and retains the hook for a later retry
  if owned data cannot be removed. Boot installation refuses an unrecognized
  staging file or directory instead of overwriting it.
- The development rollback tool serializes installation, confirmation and
  removal with an inherited lock. A clean table while an installer is pending
  is not FIRED. Confirmation after expiry is refused. The tool still requires
  a responsive engine and kernel; a reboot remains the independent recovery path.

Local validation: the original ten audit regressions failed before the fixes.
The full Python suite completed 570 tests with one unrelated icon-art check
skipped because Pillow is unavailable. The final focused security suite passed
all 16 tests, including additional stale-port and interruption cases. Android's
offline `:app:testDebugUnitTest` passed all 203 tests. Host packet tests used
isolated network namespaces; no phone tests, signing or deployment were performed.

### Stale UDP exceptions

Successful explicit refresh replaces old exceptions as before. If discovery of
new listeners fails, a separate, read-only scan may retire an existing allowance
only when no Tailscale-owned socket remains at its port. It checks listening and
connected sockets in both families, conservatively preserving possible dual-stack
listeners. Unreadable package/socket ownership means unknown and preserves the
allowance. A failed refresh opens no new ports, remains a failed operation, and
tells the app when it removed proven-stale allowances. Committed policy is not
automatically reconciled by the app.

This is a snapshot, not enforcement of socket ownership per packet. A port can
still become stale after any check and remain allowed until an explicit operation
or rule removal. There is no background monitor or automatic repair. A reachable
unrelated listener reusing that port is the meaningful exposure; an unbound port
is not an exposed application service.

### Pinned-policy implementation reviewed at `ebe9019`

The proposed destination pinning is now implemented, with explicit initial
ownership verification and no automatic broadening. Its rules and limitations
are described above. It adds no stored authorization, watcher, boot opt-in, UI
switch or provider integration. Enabling remains CLI-only and off by default; status and recovery are now exposed in Android.

Validation includes authorization failures, changing interface identity, partial
Android output, address changes requiring reauthorization, disconnect/renumber
continuity, old-range rejection, and a later `tun*` WireGuard conflict. Existing
lifecycle and rollback tests now authorize a node before installing the optional
policy. Hardware validation of this revision remains outstanding by design.

Local results: the full Python suite completed 588 tests with one unrelated
Pillow-dependent icon check skipped. All 28 final authorization/ownership tests
passed, including the additional final-read regression, and all 204 Android unit
tests passed offline. Real TUN and WireGuard packet tests ran in isolated host
namespaces. No phone deployment, signing, push or merge was performed.

### Independent review follow-up — local, November 7, 2026

- Added the explicit deny-only mode and Android status/recovery described above.
- The one-shot boot hook retries silent lifecycle-lock contention for up to 1,200
  sleeps of 0.1 s (about 120 seconds, plus command overhead), instead of the
  interactive 15-second window. Removing the armed marker cancels the wait; it
  rechecks the marker inside the acquired lock. Permanent contention still exits
  75 without restoration; the app's existing off-but-armed notice remains relevant.
  There is no deferred job or persistent retry service.
- Tunnel status combines inventory and authorization, with at most two Android
  ownership scans and an eight-second hard deadline for the read-only probe
  process group. Incomplete or timed-out proof is UNVERIFIED, never new authorization.
  Nested Android `dumpsys` deadlines also have a one-second kill grace, so a
  child ignoring SIGTERM is killed. Inner scans keep the outer process group, so
  a second scan cannot escape the overall deadline. This bounds the probe, not
  every iptables/OS command in a dashboard operation.
- mksh execution exposed EXIT cleanup returning success after SIGTERM. Install
  and refresh cleanup now explicitly exit nonzero. SIGKILL/power loss cannot run
  a trap; readback, tunnel-only recovery and reboot remain necessary then.

Targeted checks run with an AOSP-source mksh R59 host build, revision
`1548076841f243748a3f56da23b38794d437bc12`, built from
[Android's mksh source](https://android.googlesource.com/platform/external/mksh/)
using `CPPFLAGS='-DMKSH_ASSUME_UTF8 -DMKSH_DONT_EMIT_IDSTRING' sh Build.sh -r` in
`src/`. This is a Linux/glibc build, **not** Android/Bionic/toybox validation.
Supply that binary explicitly; the tests skip if no mksh is available:

```sh
POCKETUFW_TEST_MKSH=/path/to/mksh PYTHONDONTWRITEBYTECODE=1 \
  python -m unittest discover -s tests -p test_android_shell.py
```

The checks exercise parsing, inherited lifecycle/snapshot/rollback descriptors,
SIGTERM during installation and refresh, a killed rollback caller, slow, hung and
SIGTERM-ignoring VPN observations, and bounded boot contention/cancellation. Disposable namespace
packet checks cover deny-only traffic, including WireGuard named `tun*`. No phone
was accessed, no APK was signed or deployed, and nothing was pushed or merged.

**Residual trust remains:** in pinned mode, another tunnel can inject a packet
claiming a tailnet source and addressed to a still-local pinned destination. The
rule does not authenticate its source or current ingress owner. A later kernel
WireGuard renamed `tun*` can exploit the same match; detecting DEGRADED on the next
inspection does not remove that exemption. Deny-only closes this exemption at the
cost of unsolicited tailnet connectivity. Earlier Android/OEM ACCEPTs still bypass
either policy. These limits are not resolved by the new status or recovery UI.

Validation for this follow-up: a complete Python run, split by isolated test
module, completed 613 tests with no failures and one unrelated Pillow-dependent
icon check skipped. After the final timeout tightening and added second-scan
regression, all 64 affected tests passed, including 14 AOSP mksh execution checks.
The broad run included 38 real-kernel physical/tunnel namespace tests. All 211
Android JVM tests passed offline. These are local host results, not device proof.
