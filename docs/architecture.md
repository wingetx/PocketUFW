# PocketUFW Android app architecture (design sketch)

**One application, one UI, capability-based backends.** No separate companion APK.

At startup, determine privileges rather than guessing from installed package names:

1. Request root capability only with the user's consent. Confirm a real uid 0 shell and the required iptables capabilities (not merely the presence of `su`).
2. If root is unavailable, detect whether the Shizuku service is running. If it is, request authorization, call the Shizuku API, and check whether its server identity is root (uid 0) or ADB shell (uid 2000). Probe **each required operation**, because rights vary by Android build.
3. If neither path provides root-level firewall privileges, show `Kernel firewall unavailable`. Offer only supported inspection or future opt-in alternatives; never claim incoming traffic is blocked.
4. If both are available, prefer the root backend for the stateful firewall. Shizuku may optionally power diagnostics without switching firewall backends.

| Backend | Possible behavior | Honest status |
| --- | --- | --- |
| Rooted Android | PocketUFW-owned IPv4/IPv6 INPUT chains via iptables; stateful policy | Full firewall (after explicit activation and validation) |
| Shizuku with root UID | Same capabilities as proven by runtime checks, not by label alone | Full if checks pass |
| Shizuku with ADB shell UID | Limited device inspection / Android framework controls where permitted; no blanket `iptables` claims | Inspection-only unless a tested enforcement path exists |
| Neither | Help, documentation, demo plan | Not protected by PocketUFW |

Avoid requiring VPNService for the default feature set because an Android VPN-based firewall can displace Tailscale. This constraint should be visible in the UI.

Architecture should separate Android UI, privilege capability probe, rule generator, iptables backend, and diagnostics. The initial shell CLI is the independent prototype for the root backend, not itself an Android app yet.

Sources: Shizuku official API, https://github.com/RikkaApps/Shizuku-API and https://shizuku.rikka.app/introduction/
