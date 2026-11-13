# Optional Termux companion

`pufw` is a small, on-demand, read-only companion for a rooted phone with
PocketUFW installed. It reads the installed app's engine; it does not enable,
disable, repair, reset, or reauthorize anything. It is separate from the
experimental `pufw-inspect` packet-sampling tool and does not capture packets.

## Optional installation

Nothing installs automatically. In Termux, start in a reviewed PocketUFW source
checkout or extracted source archive **that contains `tools/pufw`**, then run:

```sh
install -m 700 tools/pufw "$PREFIX/bin/pufw"
```

This copies only the helper into Termux's command directory. No shell startup
files, aliases, environment settings, services, or firewall configuration are
changed. It uses Android's shell plus `awk`, `timeout`, and `su`; no Python,
`jq`, Termux:API, or packet-capture package is required. If a required command is
missing, the helper stops and names it before requesting root.

Open the installed PocketUFW app and tap **Recheck** once to prepare its private
engine files. Then run `pufw` in Termux and approve Termux's root request in
Magisk. The helper itself never stages or updates engine files. A denied root
request, missing engine, or unsupported/incomplete response produces an error,
not an assertion that the firewall is off.

To update the helper, repeat the copy from the source version you intend to use.
To remove it, run `rm "$PREFIX/bin/pufw"` in Termux. Neither action changes rules
or the app. No APK installation is part of this procedure.

## Four views

| Command | What it reads |
| --- | --- |
| `pufw` | One native `pocketufw inspect`: verified physical/ruleset state, tunnel mode, current PINNED address evidence, and counters |
| `pufw tunnel` | One native `pocketufw tunnel-status`: tunnel ruleset verification, saved pins, and current address authorization |
| `pufw stats` | One native `pocketufw activity`: separate physical/tunnel statistics, with IPv4, IPv6, and combined counts for DROP packets, dropped bytes, and established/related return packets |
| `pufw raw` | The native `pocketufw inspect` key/value output, without summary formatting |

Each invocation uses one `su` session and one engine command. `inspect` and
`activity` already use the same rule verifier as `pocketufw verify`, so the
helper does not run another redundant `verify` pass. `inspect` also obtains
address evidence in its existing bounded probe. The helper allows at most
30 seconds for root access and the native inspection; timeout means **unknown**,
never inactive.
No background polling or automatic retries are scheduled.

`pufw` remains the quick overview. `pufw stats` is the detailed numbers view:
**PHYSICAL** and **TUNNEL** sections each show IPv4, IPv6, and total drops,
dropped bytes, and returns. Drops and returns are packet counts. Totals combine
IPv4 and IPv6 within that section; physical and tunnel counters are kept separate.
Counts are kernel rule matches since installation or a counter reset, not rates
or unique connections. The rows fit a narrow terminal; very large numbers move
onto their own indented line without rounding or truncation.

`ACTIVE` describes installed rules and hooks verified during that inspection,
not universal traffic coverage. Physical rules may remain verified when tunnel
or overall protection is degraded; the default view preserves that distinction.
An inactive firewall has unavailable counters, not fabricated zeros. An absent
tunnel is reported as not installed. Missing or malformed measurements remain
unavailable. Because `activity` has no completion marker, `pufw stats` withholds
all numbers and reports **UNKNOWN** if any required counter is missing or invalid.
Return traffic means matches of established/related rules, not all
device traffic or unique connections. DROP bytes are available in `pufw stats`;
the native engine does not expose established/related byte totals here.

`activity` does **not** recheck current Tailscale addresses. Thus `pufw stats`
can show a saved PINNED mode without claiming current address verification.
`MATCH` requires a completed, successful inspection, both saved and observed
addresses, matching values, and the native WireGuard conflict check. `REAUTHORIZE`
means addresses changed while installed rules remain in place; review PINNED in
the app's Settings. Missing, contradictory, or incomplete evidence stays
`UNVERIFIED`. Address verification is not a reachability test or authentication
of individual packets: another `tun*` interface can inject tailnet-source
packets aimed at a pinned local destination.

Earlier Android ACCEPT rules and unsupported interfaces remain coverage
boundaries. Use the app's **Coverage details** or **Activity → Kernel rules**
for that evidence. The existing Wi-Fi calling compatibility warning still applies.

Exit status: `0` for a complete normal read (including intentionally inactive
protection), `1` for failed/incomplete inspection or a reported condition needing
attention, and `2` for invalid arguments. Raw output is diagnostic evidence;
check its exit status and any error text before relying on partial output.

## Engine location

The default is the installed app's engine for Android user 0:

```text
/data/user/0/io.github.pocketufw/files/engine/pocketufw
```

For another Android user or a reviewed standalone engine, choose its path for
one invocation without changing Termux's configuration:

```sh
PUFW_ENGINE=/absolute/path/to/pocketufw pufw
```

Paths must be absolute and contain only letters, digits, `/`, `.`, `_`, or `-`.
Keep the matching `vpn-probe` beside a standalone engine. The helper does not
search for or fall back to an old Magisk boot snapshot. It does not modify
engine files, boot preferences, counters, firewall rules, or network state.
Native inspections may create/use the engine's existing synchronization lock;
this is not a service or a firewall/network change.

Initial `pufw`, `pufw tunnel`, and `pufw stats` checks were reported successful
on Frankenpixel (Pixel 9a, Android 17, Magisk 31.1). The redesigned statistics
display is validated on the host with fake root/native responses and an isolated
mock kernel; this layout has not yet been rechecked on the phone.
