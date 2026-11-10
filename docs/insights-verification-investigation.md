# Insights: ingress guards, marks and counter replacement

**Historical design/investigation:** qualified sampling remains unimplemented.
The later Beta 6 refusal-path fix now independently verifies ACTIVE after
successful cleanup even when comparison withholds a sample. Any references below
to a skipped final verification describe the earlier implementation. See
[current behavior](insights-v1.md#native-boundary).

Status: **investigation complete; no production acceptance exception established**.
This follows [the revision-2 design](insights-verification-design.md). Keep the
current strict verifier and audited implementation unchanged. This investigation
used saved capture evidence, pinned upstream source and a disposable namespace
attempt. Neither phone was accessed. Claude reviewed the complete evidence, agreed to
retain strict acceptance, and proposed the narrower argument below. His verdict
was proof incomplete / implementation not approved. This report incorporates
the review with the qualifications explicitly identified below.

## Evidence and confidence

The complete saved IPv4/IPv6 `immediate-rules` and `after-rules` dumps supply the
previously missing chains. The IPv4 tables are nat/mangle/raw/filter; IPv6 has
mangle/raw/filter. These are endpoint observations, not a history of every rule
replacement. Android diagnostics separately attributed the transition from
rmnet17 to ipsec1035 to the same restricted carrier IMS network.

The private evidence bundle is `proof-investigation/20261110T230706Z` under the
existing Frankenpixel acceptance archive. It retains snapshot hashes, a complete
chain index, fetched source and hashes, the failed namespace attempt and review
inputs. No packet payloads were collected. Private handset addresses stay in
that archive; the address below is represented as IMS_ADDRESS.

Upstream references are pinned, but **have not been matched to the handset's
installed vendor kernel, netd or BPF objects**. They establish implementation
mechanisms and conditional reasoning, not a fresh live-device measurement.

## What the missing chains establish

Both families have these paths before PocketUFW's hooks:

| Path or rule | Observed behavior | Consequence |
| --- | --- | --- |
| `INPUT -> oem_in` | IPv4 empty at both endpoints; IPv6 empty then eight exact IMS_ADDRESS/128 TCP/UDP port DROPs | No hidden ACCEPT exposed within this chain. A later snapshot removes one of those DROPs; its precise vendor port-lifecycle cause remains unproven. |
| `INPUT -> bw_INPUT -> bw_global_alert` | quota2 accounting match with no verdict target | No explicit ACCEPT/DROP from this row; quota state and notification side effects are not global noninterference proof. |
| `bw_INPUT -> bw_costly_rmnet16` | Exact `-i rmnet16`, then penalty/allowlist BPF and quota REJECT | This filter BPF path is not reached by first-pass packets on rmnet17, ipsec1035, wlan0, tun1 or US-DEN-315. |
| `bw_INPUT -> bw_costly_v4-rmnet16` | Exact `-i v4-rmnet16`, same subchains | Same exclusion. These are exact guards, not a blanket cellular exemption. |
| `bw_INPUT` remainder | ESP RETURN; mark bit 0x100000 RETURN; set bit 0x100000 | The changed route mark preserves this bit. RETURN resumes INPUT; it is not an ACCEPT. |
| `INPUT -> fw_INPUT` | Empty in both families | No additional decision in this chain. |
| Earlier WireGuard UDP exception | Existing IPv4 ACCEPT / IPv6 DROP, structurally unchanged | Preserve it and its position exactly; do not classify it as carrier drift. |

The offline chain walker deliberately over-approximates calls rather than
interpreting arbitrary rule semantics. It enumerated every filter INPUT BPF path
in these snapshots; all carried one of the two exact guards above. It is evidence
indexing, not production verification code.

## Mark arithmetic passes locally; state isolation does not yet follow

For `MARK --set-xmark V/M`, the kernel computes `(old & ~M) ^ V`; the general
write footprint is `M | V`, not just M. Here V=0x000f0065 and M=0x7fefffff, with
no V bits outside M. The changed row only substitutes its exact ingress name.
The bandwidth bit 0x00100000 and wakeup bit 0x80000000 are both outside the
write footprint. These outside-mask bits are invariant under both adding and removing the
interface-scoped write; old-ingress packets retain their prior bits inside M
after removal. This supports the narrow, same-traversal argument. See the
[pinned MARK implementation](https://android.googlesource.com/kernel/common/+/153de33f91d69c9aa60925e5e2d0949a4318591f/net/netfilter/xt_mark.c).

The mangle INPUT call order is:

```
connmark_mangle_INPUT -> wakeupctrl_mangle_INPUT -> routectrl_mangle_INPUT
```

Both INPUT and OUTPUT connmark chains contain:

```
-m connmark --mark 0/0xfffff
-j CONNMARK --save-mark --nfmask 0xfffff --ctmask 0xfffff
```

Those masks overlap the changed route-mark footprint by 0xfffff. INPUT saves
before the route MARK, so that MARK cannot retroactively change the earlier save
on a single forward traversal. There is no `--restore-mark` in any of the saved
loaded tables. Neither observation proves that affected marks can never cross a
socket/reply/reinjection boundary or reach another connmark consumer.

In particular, the upstream kernel supports reflecting incoming marks to kernel
replies and inheriting SYN marks onto accepted sockets through `fwmark_reflect`
and `tcp_fwmark_accept`. A later OUTPUT save is therefore a concrete state-flow
possibility, conditional on configuration and packet path. It is **not evidence
that this happened on Frankenpixel**, nor a demonstrated bypass of PocketUFW.
The saved tables do not establish those settings, every external consumer or
XFRM/reinjection behavior. They do, however, permit a complete inventory of
connmark readers inside the loaded tables: the low 20 bits are read only by the
two save guards themselves. The other reader, st_clear_detect, tests disjoint
bits 0x01000000 and 0x02000000 and has no reachable caller from a built-in chain
(st_OUTPUT is empty). There is no verdict consumer of the transferred low bits
in this ruleset. That is a stronger local fact than merely observing no restore. See the
[pinned kernel settings](https://android.googlesource.com/kernel/common/+/153de33f91d69c9aa60925e5e2d0949a4318591f/Documentation/networking/ip-sysctl.rst)
and [CONNMARK code](https://android.googlesource.com/kernel/common/+/153de33f91d69c9aa60925e5e2d0949a4318591f/net/netfilter/xt_connmark.c).

**Claude's previous proposal, as written, refuses this device:** it explicitly
rejects overlapping CONNMARK state transfers. His new audit withdraws that
blanket veto and instead asks whether transferred state can affect a rule that
skips PocketUFW, or a decision inside PocketUFW. This is a revised proof, not an
ordering-only exception. No newly demonstrated bypass follows from the overlapping
save. Broad claims of global noninterference still do not follow.

## BPF: distinguish direct guards from installed-program proof

The guarded filter BPF is only part of the picture. Both families also have:

- raw PREROUTING: a mark-based DROP, then IPsec-interface/policy RETURNs, then
  the ingress xt_bpf match. This runs before the changed mangle INPUT MARK on a
  first traversal. The broad ingress program is not protected by rmnet16 guards.
- mangle POSTROUTING: IPsec-interface/policy RETURNs, clearing bandwidth bit
  0x100000, then the egress xt_bpf match.

A match without an explicit target still executes its BPF program. Its boolean
match result does not itself select an ACCEPT or bypass: matching and nonmatching
paths both continue. Do not equate that with having no side effects. The
[pinned xt_bpf implementation](https://android.googlesource.com/kernel/common/+/153de33f91d69c9aa60925e5e2d0949a4318591f/net/netfilter/xt_bpf.c)
resolves a pinned program object and runs it; a path string is not an integrity
measurement of its instructions or maps.

In the [pinned AOSP netd BPF source](https://android.googlesource.com/platform/packages/modules/Connectivity/+/2519a78731526d2eb20ae8812acdcab6ef7a09b6/bpf/progs/netd.c),
the corresponding ingress/egress xtbpf functions update interface statistics;
allowlist/denylist functions look up UID policy. These functions do not use the
route mark as a verdict input. This is positive conditional evidence, not a
reason to ignore arbitrary BPF or its shared maps. Their runtime identity and
external consumers have not been tied to this handset. A global noninterference
claim would require more evidence; the revised observed-DROP contract below does
not require global noninterference or attestation of every map. Within the saved
filter INPUT graph, map-consuming BPF verdicts are guarded and restrictive. Do
not generalize that inventory to all Android consumers.

The [pinned socket-filter verifier](https://android.googlesource.com/kernel/common/+/153de33f91d69c9aa60925e5e2d0949a4318591f/net/core/filter.c)
also narrows the assumption: this xt_bpf path loads BPF_PROG_TYPE_SOCKET_FILTER;
direct context writes are limited to cb, and the revision-1 xt_bpf runner saves
and restores cb. Packet-writing tc helpers are not the socket-filter helper
set. This supports the known-backend argument; an unknown backend, revision or
extension must not inherit it.

## Revised proof direction: inventory decisions that can skip protection

Claude now separates the actual qualified-result claim from global stability:
records hit this session's probes immediately before unchanged PocketUFW DROPs;
cleanup and ACTIVE are freshly checked for an accepted result; what reached
PocketUFW may have changed
and this is disclosed. A qualified result would not claim all Android policy or
carrier coverage remained unchanged.

For this contract, inventory every reachable pre-hook decision that can accept
or redirect traffic around PocketUFW, and every owned decision that consumes
changed state. On the saved filter INPUT paths, the only early ACCEPT is the
unchanged IPv4 WireGuard UDP-port exception, which reads protocol and port, not
marks. Its IPv6 counterpart DROPs. Other paths continue, DROP/REJECT, or RETURN
from an ordinary called user chain and resume INPUT. No `-g` occurs. The owned
chains do not read mark or connmark. A restrictive upstream decision may change
the sample population without falsifying a record's downstream DROP provenance.

This is a promising static argument for the snapshot pair, not a production gate
or proof of the whole ten-second history. It retains these obligations:

- Preserve strict owned hooks, callers, policies, pins and ordered rules; exact
  probe tags, uniqueness, ownership and DROP adjacency; post-cleanup verification;
  all-table completion checks; the complete DROP-only OEM grammar, exact mangle
  substitutions and complete residual equality in both families.
- Classify known extension/target semantics and jump-stack behavior. Refuse
  changed-state-dependent ACCEPTs, top-level INPUT RETURN, goto, NFQUEUE, TEE, CT,
  unknown targets/matches/revisions, and unresolved alterations to inputs of a
  bypass-capable or owned rule. Do not allow a match to mutate a packet merely
  because its rule lacks a target. Add mutation tests for these cases.
- Match the supported userspace/kernel backend semantics. State the boundary
  around other nftables, tc/cgroup BPF, routing and XFRM enforcement; inspect
  whether parallel backends affect this deployment rather than silently treating
  an iptables dump as a global firewall inventory.
- Endpoint comparison cannot prove the absence of a transient change reverted
  between reads. This limitation exists in V1 and must remain explicit. Unknown
  intermediate policy is not retroactively established by the static argument.
- Keep external acceptance-tool checks for every original owned packet/byte
  counter non-decreasing. Optional native provenance counters are a separate
  design choice, not permission to weaken that user requirement.

The old per-record destination/ingress exclusion is not intrinsically required
for this revised DROP-provenance claim. Such metadata may still improve display
and coverage explanations. V1 lacks it, but that absence alone need not block the
revised future design. No historical record report exists to qualify or display.

Two full-mask mark readers deserve explicit scope treatment. The raw PREROUTING
0xdeadc1a7 DROP precedes the changed INPUT MARK on first traversal. A *written*
route mark cannot equal that value or OUTPUT's exact 0x20000 ACCEPT value. However,
the interface substitution both adds and removes a write: removing it can expose
a pre-existing mark. **Codex qualification of the audit:** arithmetic about the
written value alone does not prove every before/after mark outcome invariant.
The raw decision is restrictive, and the OUTPUT ACCEPT is outside the inbound
claim; neither supplies a changed-state-dependent pre-hook INPUT ACCEPT in these
snapshots. XFRM can consume marks separately; track it with carrier coverage,
not as proof that all Android decisions are unchanged.

## Counter replacement: confirmed mechanism, untested device timing

The [pinned Android libiptc commit path](https://android.googlesource.com/platform/external/iptables/+/672d4a9452846646a3017d255fae319e12d92295/libiptc/libiptc.c)
does two separate operations: SO_SET_REPLACE, then SO_SET_ADD_COUNTERS.
The [IPv4 kernel path](https://android.googlesource.com/kernel/common/+/153de33f91d69c9aa60925e5e2d0949a4318591f/net/ipv4/netfilter/ip_tables.c)
and [IPv6 path](https://android.googlesource.com/kernel/common/+/153de33f91d69c9aa60925e5e2d0949a4318591f/net/ipv6/netfilter/ip6_tables.c)
clear new entry counters, install the replacement, return old totals, and later
add mapped totals. The kernel waits for old-table traversals before collecting
old totals. Traffic continues through the replacement table during the gap.
An unlocked reader can therefore observe incomplete totals even when a writer
intends to preserve every retained rule's counters. A writer failure between
the calls can leave an incomplete restoration; this must never be assumed benign.

This confirms Claude's mechanism at source level. It does **not** attribute any
observed phone decrease to that mechanism. The stored accepted-checkpoint owned
counter comparisons remain non-decreasing; unrelated Android bandwidth counters
have their separately documented lifecycle uncertainty.

A private LD_PRELOAD pause harness was compiled and attempted inside a new user
and network namespace. It would pause only an isolated legacy table commit
between the two calls, inspect totals and verify restoration. The attempt stopped
before its first rule was created: Arch's legacy filter table/module was absent
and module loading was denied. The legacy tool attempted modprobe, which failed with EPERM. No module was
enabled, no host rule was changed,
and no phone experiment was attempted. This is **BLOCKED, not a passing runtime
test**. Future attempts must disable the tool's automatic module-loading path
explicitly (for example with a validated modprobe override). Even a successful
host run would not test the vendor kernel. The temporary namespace exited; the
harness remains private evidence.

The source's [iptables-save path](https://android.googlesource.com/platform/external/iptables/+/672d4a9452846646a3017d255fae319e12d92295/iptables/iptables-save.c)
does not acquire the xtables writer lock. The
[restore path](https://android.googlesource.com/platform/external/iptables/+/672d4a9452846646a3017d255fae319e12d92295/iptables/iptables-restore.c)
holds it across each commit. Follow-up source checks confirmed standalone
[IPv4](https://android.googlesource.com/platform/external/iptables/+/672d4a9452846646a3017d255fae319e12d92295/iptables/iptables.c)
and [IPv6](https://android.googlesource.com/platform/external/iptables/+/672d4a9452846646a3017d255fae319e12d92295/iptables/ip6tables.c)
commands acquire that lock before table initialization, including -S. V1 has no
native counter reads; introducing unlocked `save -c` counter checks would expose
this accounting race in the supported source model, pending installed-binary
confirmation. The private ip6tables-userspace.c file maps to that linked
iptables/ip6tables.c path, as recorded with SHA-256 in upstream-ip6tables-source.json.
Existing external save-based acceptance snapshots may already encounter it.
The current helper supplies -w 2. Lock contention, timeout or nonzero exit must
remain a command/read failure, never be parsed as a rule difference. Any new
inspection failure after insertion must enter the cleanup-protected path; after
verified cleanup, the proposed separate ACTIVE check must still run on a
withheld-result path. These are implementation/test obligations, not new behavior. A future bounded read under the actual shared lock might
exclude cooperating writers' partial commits, but needs platform/inode/backend
validation, error-path audit and runtime tests. Do not hold Android's writer lock
for the 10-second capture, assume all writers cooperate, or declare cross-family
and cross-table snapshots transactional.

The following is optional additional native provenance checking, not a prerequisite
for V1 parity and not a replacement for strict external owned-counter checks.
For each exact session/family/probe, received-record count <= final absolute probe
count remains a **conditional one-sided sanity bound**: rule counters increment
before NFLOG emits, and the final read must be after collector close but before
probe deletion, with complete counter restoration and unique provenance verified.
It includes setup-queued records. It is not a losslessness or continuity proof.
Post-close hits inflate the bound, and copied tags or counter-aware root tampering
are outside its guarantee. Non-decreasing counters alone cannot prove no recreation.

Do not use probe/DROP delta equality as a gate: per-entry/per-CPU reads are not a
single packet boundary. No sequence gap also does not prove no loss; the
[NFLOG implementation](https://android.googlesource.com/kernel/common/+/153de33f91d69c9aa60925e5e2d0949a4318591f/net/netfilter/nfnetlink_log.c)
can fail allocation before assigning a sequence. Any observed owned-counter
decrease still withholds. Never reset, rebase, mask it or retry until it disappears
and then present that as uninterrupted proof. Explain unresolved accounting as
indeterminate, without alleging tampering from a counter observation alone.

## Disposition and safe fallback

1. Keep strict current acceptance. No qualified sample, parser migration, counter
   tolerance, per-family shortcut or automatic retry is authorized by these findings.
2. Preserve exact probe ownership/adjacency/removal, all PocketUFW hooks/rules/pins,
   strict external owned-counter checks, and full residual structural comparison. Continue
   checking both families and classifying every difference.
3. Separate validity, cleanup and protection in the future response. Withholding
   must not imply a collector failure or leftover probes when those claims are
   independently disproven. This is a UI/protocol design recommendation only.
4. V1-compatible candidate wording for this exact verified-cleanup failure:
   **“Insights probes were removed. Other firewall filter rules changed during
   the sample, so results were withheld.”** V1 cannot attribute the writer to
   Android, compare all tables, or append an ACTIVE claim here: its equality
   failure throws before verify() runs. The historical checkpoint's ACTIVE
   proof came from independent tooling. A future fresh, separately identified
   engine check may add “PocketUFW protection: ACTIVE.” If cleanup or protection
   is unknown, state that uncertainty. Prominent recovery still requires verified
   probe residue. Broader Android/IMS wording requires separate attribution and
   evidence; never display the withheld packet list.
5. Track [IPsec inner-interface coverage](ipsec-inner-interface-coverage.md)
   separately. It is not repaired by accepting an Insights sample.

Further acceptance relaxation needs a separately reviewed specification and
implementation of the bypass-decision inventory and strict grammar, backend
validation, and disposable-kernel/Moto tests. Any added counter-read feature
needs its own accounting and lock protocol. The new counter bound is optional;
original owned-counter requirements remain mandatory in acceptance testing. A
successful app capture on Frankenpixel remains outstanding; it must not be credited retrospectively.

## Audit disposition

Claude's tools-disabled review accepted the local chain observations and source
counter mechanism, withdrew his earlier blanket CONNMARK veto, and requested
the narrower bypass-decision inventory. Accepted corrections: V1-truthful
withholding text, optional native count bound, explicit external-counter scope,
complete connmark readers, ESP coverage, target-less BPF semantics and -S locking.

Codex retained two qualifications to that review: a removed mark writer can
expose an old value even when the written value cannot match a downstream reader;
and the IPv6 WireGuard-port DROP is also present before the OEM inner-interface
DROPs, so the latter are not the only observed filter restriction. No claim of
global BPF/XFRM noninterference or continuous endpoint-only observation is made.
The original review and this disposition are preserved together. No implementation
is approved or changed by this report.

Claude's finalization review accepted both Codex qualifications and permitted
finalizing this report after minor wording corrections, now applied: mark-mask
invariance on insertion and removal, explicit IPv4/IPv6 coverage, lock-failure
handling, and the userspace-source filename mapping. His final verdict remains
**static argument only; implementation not approved**. No further report audit
was requested; runtime/backend validation and future implementation are separate.
