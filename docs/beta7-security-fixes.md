# Beta 7 security audit remediation

Branch `feature/beta7-security-fixes`, based on `65c061c`. These changes fix the four
Low findings and the README correction from the final read-only audit of `65c061c`.
They change no firewall rule, chain, hook, PINNED or DENY-ONLY policy, and add no
service. Every new regression was run against the code before its fix and failed there.

## L1: reachable unhooked interfaces are reported

`android-bridge` used to ignore IPv6 addresses that were not global. That hid an UP
interface whose only address was link-local, even though anyone on its link can reach
it. A real-kernel test also showed a broader case. With `rp_filter` off, as on Android,
an UP interface with a carrier and no address at all delivers packets sent to the
phone's other addresses.

An unhooked interface is now listed as not filtered when it is administratively UP and
has any address other than host scope, or a carrier. Only two kinds are left out:
loopback, and the kernel's dummy driver, which has no receive path. Dummy is read from
the kernel's own kind in `ip -d -o link`, the word after a lone backslash in oneline
details. It is never inferred from a name. If the kind can't be read, the interface is
listed.

The real-kernel test `test_reachable_interfaces_are_listed_whatever_their_addresses`
uses isolated namespaces and real packets, and checks these cases:

| Interface | Listed | Unsolicited packets delivered |
| --- | --- | --- |
| `aware_data0`, link-local only | yes | 5/5 |
| `bare0`, no address, IPv6 off | yes | 5/5 |
| `dummy1`, a veth with a dummy-like name | yes | 5/5 |
| `aware_nmi0`, down | no | none possible |
| `nan1`, up with no carrier | no | none possible |
| `dummy0` and `pufwd0`, kernel dummies | no | none possible |
| Hooked `wlan0`, for comparison | no | 0 |

Host tests also cover a missing kind, and the word "dummy" appearing as an altname or
later word. The existing fixture's `p2p0`, with only a link-local address, is now listed.

## L2: late root output is no longer lost

`collectRootOutput` (Kotlin) and the Insights helper's `command()` (C++) could stop at
an empty read that happened before the child exited. Each now returns only after an
empty read that began after the exit was seen. A descendant still holding the pipe adds
no wait. Deadlines, the 64 KiB and 256 KiB limits, overflow rejection and interruption
handling are unchanged.

Two deterministic tests place the last output exactly between the empty read and the
exit check:
- `RootOutputTest` uses a fake `Process`.
- `tests/insights_command_test.cpp` wraps `waitpid` around the real `insights.cpp`. It
  runs under ASan and UBSan.

## L3: the tile cache needs the same boot

A cached state now records a boot identity: `Settings.Global.BOOT_COUNT` and
`/proc/sys/kernel/random/boot_id`, whichever the app can read. A state is read back
only if every part it recorded is readable now and unchanged. If neither part could be
read, nothing is trusted. Caches from earlier versions, which have no identity, read as
not verified. The wall-clock-minus-uptime epoch stays only as an extra rejection rule.

Tests cover:
- a rapid reboot with no clock movement, followed by a failed restore: the tile shows
  "Not verified this boot", and a tap only checks;
- an identity that was recorded but can no longer be read;
- either part being available alone;
- caches written by earlier versions.

## L4: the tile forgets before rules can change

Every root action that can change firewall rules clears the tile's verified state
before the root command starts. The exceptions are counter resets and boot-file
switches. That covers app death mid-operation: the tile reads as not verified, never
as the state from before the change. Clearing also makes any older read superseded.
The operation's own read start is taken afterwards, so its result still publishes.

Tests cover:
- the cache as it stands while root runs, for each of the eleven rule-changing actions;
- a simulated process death (an `Error` escaping before the result is published) during
  Off, Remove and a tile toggle;
- an older read trying to republish.

## README

The uninstall section now says what `boot-service` does. If Android hasn't finished
booting within about 180 seconds, the hook can't ask the package manager. It then
restores the firewall as usual and checks again on the next boot. This is the existing,
tested behaviour (`test_wait_limit_installs_the_firewall_and_skips_only_the_uninstall_check`).

## Needs a device

All of these checks are read-only.

- **`ip -d -o link` output:** on Frankenpixel it must print `\    dummy` for `dummy0`, or
  `dummy0` will be listed as not filtered. Also confirm that no other interface becomes
  newly listed, for example an UP `p2p0`.
- **Boot identity readable by the app:** `Settings.Global.BOOT_COUNT` is public API with
  no permission, but `boot_id` may be refused by SELinux for apps. Either one is enough.
  If `BOOT_COUNT` were updated only after an app could first read it, the kernel
  `boot_id` would still catch the reboot. That holds only when the app can read `boot_id`.
- **Root survives app death:** whether Magisk 31.1's root child outlives the app process
  (the case L4 protects against).
