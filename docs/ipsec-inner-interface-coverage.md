# Coverage finding: decrypted IPsec interface outside existing hooks

Tracking ID: **COV-IPSEC-001**. Open; existing coverage limitation, separate from
Insights capture validity. No engine or VPN configuration change is proposed here.

Saved Frankenpixel evidence on 2026-11-10 identified restricted cellular IMS
moving from rmnet17 to ipsec1035 with the same assigned IPv6 address. Android's
connectivity diagnostics supplied the carrier attribution; `ipsec*` naming alone
would not justify it.

PocketUFW's saved physical INPUT hooks match wlan+, rmnet+, v4-rmnet+ and
v4-wlan+. Its enabled tunnel hooks match tun+ and the exact configured kernel
WireGuard interface US-DEN-315. The old rmnet17 matches rmnet+; ipsec1035 matches
none of those hooks. There is no other saved jump into PocketUFW for that inner
interface. Thus packets presented to INPUT with logical ingress ipsec1035 are
outside PocketUFW's installed interface-hook coverage. The limitation exists
in the hook design; its observed exposure began when IMS moved off rmnet17. The
device's usual IMS interface is not established by these snapshots.

This does not show that all carrier traffic is unprotected, that an exploit
exists, or that encrypted outer packets bypass physical hooks. The saved physical
chain explicitly ACCEPTs ESP in both families: reaching a
physical hook does not mean PocketUFW inspects decrypted inner traffic. On the
inner IPv6 path, scoped OEM IMS port DROPs remain (one was subsequently removed),
and the unchanged global WireGuard UDP-port DROP also precedes them. That DROP
is IPv6-only: the IPv4 counterpart is an unscoped UDP 35493 ACCEPT, and IPv4
oem_in is empty in the saved snapshots. These IPv4 statements are conditional
on any IPv4 traffic using the inner interface; they do not establish an IPv4
address on ipsec1035. Android/OEM,
XFRM and carrier policy may still filter traffic. No direct unsolicited inbound
IPsec test was performed. Keep ACTIVE's scope explicit: it verifies configured
PocketUFW coverage, not every present or future Android interface.

XFRM policy can consume packet marks and interface identifiers outside these
PocketUFW hooks; no claim of unchanged carrier/IPsec policy follows from unchanged
PocketUFW rules. This is distinct from proving that an observed Insights probe
was adjacent to an unchanged DROP.

Follow-up: when diagnostics independently verify IMS attribution, say
“Carrier IMS interface; outside PocketUFW interface coverage.” A system-managed
label must not replace that warning or imply a safety exemption. Investigate any
expansion of interface coverage as a
separate engine change, with IMS/calling tests and explicit user approval. Do not
silently hook every ipsec* interface, change VPN configuration or treat carrier
identity as a firewall-safety exemption. This record does not authorize testing
or changes on the daily driver.
