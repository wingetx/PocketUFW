# Insights verification during Android rule changes

**Historical design/investigation:** qualified sampling remains unimplemented.
The later Beta 6 refusal-path fix now independently verifies ACTIVE after
successful cleanup even when comparison withholds a sample. Any references below
to a skipped final verification describe the earlier implementation. See
[current behavior](insights-v1.md#native-boundary).

Status: **design only, revision 2 after Claude requested changes**. Qualified
acceptance is not approved for implementation. The installed APK and all audited
source remain unchanged. No device operations belong to this design review.

## Proposed distinction

Separate three claims: the records matched PocketUFW DROP probes; PocketUFW's
protection and cleanup verified; and the surrounding network policy remained
unchanged or changed within a specifically understood boundary. The first two
do not establish the third.

Retain full comparison by default. A future qualified result would preserve
strict owned-state and probe checks while disclosing a bounded change in what
traffic could reach PocketUFW. Unknown or security-relevant changes still
withhold the whole sample. Neither an OEM chain name nor verified carrier
ownership alone makes a change safe.

The first implementation, if separately authorized, could classify and explain
withholding without relaxing acceptance. That does not complete Frankenpixel's
successful-capture milestone. Do not assume its carrier churn will be infrequent.

## Current behavior and evidence

`insights.cpp:tables()` reads the complete IPv4 and IPv6 **filter tables** with
`-S`, not every firewall table. `verifyProbes()` requires full stripped equality
and exact DROP adjacency after setup. Capture requires full filter equality after
exact cleanup. Group-17 conflicts are scanned across loaded tables before setup.
The helper's native snapshots have no counters; strict counter monotonicity was
verified by external acceptance tooling.

In the saved Frankenpixel run, six UDP packets incremented the physical logging
probe and original DROP by six. Three Tailscale pings per family received replies,
with matching pinned ACCEPT increases and zero tunnel probe matches. All eight
probes were removed, group 17 released, and ACTIVE/PINNED/MATCH preserved.
Android connectivity diagnostics identified the same restricted IMS network
moving from rmnet17 to ipsec1035; rule snapshots recorded eight exact-address
IPv6 OEM DROP additions during collection. Those filter changes
caused the helper to withhold; accompanying mangle changes were detected by the
external checks. One scoped TCP DROP disappeared during follow-up. Its exact
vendor port-lifecycle cause is not proven.

No record report was emitted, so displayed source/protocol/category attribution
was not verified. Do not reconstruct or retrospectively accept that sample.

## Invariants that remain strict

- Preserve locks, bounded commands, exact ownership validation and deletion,
  signal handling, deadlines, no payload persistence and all audited fixes.
- Preserve ordered POCKETUFW_IN, POCKETUFW_TS and POCKETUFW_VPN contents, UDP
  exceptions, pins and declarations. Preserve every hook/reference, its family,
  matches, multiplicity and position relative to surrounding INPUT rules. An
  extra jump/goto from another chain/table is a failure, not unrelated drift.
- Preserve INPUT policies and caller structure. Any unexplained earlier ACCEPT,
  RETURN, jump/goto or policy change refuses qualification.
- Compare original owned packet/byte counters without resetting them. Reject
  missing or ambiguous owned rows and observed decreases. Android/OEM accounting
  counters are recorded separately and need not be monotonic.
- Keep setup comparison strict. Churn during insertion aborts before collection;
  no new exception in verifyProbes(). Check complete signatures, family/session
  uniqueness and DROP adjacency again before cleanup and owned state afterward.
- Check loaded tables for foreign group-17 rules and reserved-tag misuse again
  at completion. Exact existing cleanup never deletes another owner's rule.
- Require engine ACTIVE before and after. Preserve tunnel mode/hooks/pins;
  Frankenpixel acceptance additionally requires current PINNED/MATCH and all
  three interfaces. Do not accidentally remove support for ordinary OFF or
  DENY_ONLY capture modes when adding that device-specific acceptance check.

NFLOG returns XT_CONTINUE, so the following unchanged DROP and its match/order
matter to attribution. An earlier verdict in a called chain can prevent reaching
PocketUFW. See the [Android kernel NFLOG target](https://android.googlesource.com/kernel/common/+/refs/heads/android-mainline/net/netfilter/xt_NFLOG.c)
and [Netfilter traversal documentation](https://www.netfilter.org/documentation/HOWTO/packet-filtering-HOWTO-7.html).

## One structural snapshot format

A proposed V2 uses bounded iptables-save -c / ip6tables-save -c dumps of loaded
tables for both structure and counters. Do not enumerate absent tables with
`-t NAME`, which may load them. All-loaded-table comparison must apply to normal
and qualified results alike; mangle-only drift must not silently earn an
unchanged result. Unsupported, oversized or truncated evidence fails closed.
Migrating from -S to -save changes parsing of quoting, declarations, table
boundaries and counter prefixes in owned(), strip(), verifyProbes() and cleanup().
That representation change needs explicit fixtures and its own implementation
audit; it is not merely a command-format substitution.
Retain only the audited numeric quota2 remaining-byte normalization. Do not mask
other fields, rule names, targets or policy changes.

Saved full snapshots on this device measured 10,329 bytes / 179 lines for IPv4
and 9,811 bytes / 166 lines for IPv6. This fits existing limits; it does not prove
those limits fit every Android device. Measure before changing bounds.

A per-family dump is not a transactional packet boundary across tables or
successive counters. Owned-counter monotonicity does not prove a rule was never
recreated. Do not call an asynchronous dump atomic with respect to packet flow.

## Candidate narrow exception

This is the proposed scope for further review, not an approved implementation.
No general firewall interpreter or ignore-all-OEM rule is proposed.

1. **Use kernel facts.** Bounded binary RTM_GETADDR/RTM_GETLINK dumps establish
   local address bytes and link identities at both endpoints. Each affected
   destination must be local at both checks; resolve the old interface initially
   and the new interface finally. Reject ambiguous, interrupted or incomplete
   dumps. Android connectivity diagnostics may support the UI's carrier label,
   but their text, embedded names and versioned grammar do not authorize native
   acceptance. Without separate attribution, call it system network rule drift.
2. **Require a complete DROP-only chain.** Every oem_in row, before and after,
   must use the exact supported form:
   `-A oem_in -d LOCAL_IPV6/128 -p tcp|udp -m tcp|udp --dport PORT -j DROP`.
   Protocols agree; port is canonical decimal 1..65535; no inversion, ranges,
   extra matches, duplicate options, ambiguous duplicate rows, other masks,
   callers or declarations. Limit additions plus removals combined to 32.
   An unchanged ACCEPT later in this chain would become reachable when an
   earlier DROP is removed: that must refuse. IPv4 exceptions are not inferred.
3. **Match accompanying mangle substitutions row by row.** Exactly one supported
   routectrl INPUT MARK row and one wakeupctrl INPUT NFLOG row per family may
   change at their existing positions. Only MARK's -i changes. In the NFLOG row,
   -i and the interface suffix in HANDLE:INTERFACE change together; the handle
   stays fixed. Mark/mask, group 3, limit, threshold and every other token stay
   fixed. No global token replacement, prefix matching or group-17 exception.
4. **Reject unresolved dependencies.** Follow the transitive INPUT path before
   the hooks. Potentially coupled mark, connmark, IPsec-policy or opaque program
   decisions refuse qualification unless a separately audited proof handles
   them. Unchanged rule text is not proof of unchanged semantics when a match's
   input changes. Other tables, including NAT/raw, remain exact.
5. **Require complete residual equality.** Account for only the explicit allowed
   differences. All remaining declarations, policies, rules, positions and
   references must match; a benign change cannot conceal a dangerous change in
   the same chain. Preserve order initially even where DROP-only reordering
   might eventually be proven equivalent.
6. **Conservatively constrain the displayed records.** Retain destination and
   logical ingress ifindex internally, using existing IP-header copy lengths
   and a strictly parsed NFLOG ingress attribute. Addresses compare as bytes.
   Each record must be outside the union of affected destinations and interfaces,
   with ingress in a positively resolved, endpoint-stable name/index set. These
   fields need not leave native memory. This is a display constraint, not the
   primary proof that a record hit DROP or that unseen traffic was unaffected.
7. **No selective salvage.** Any overlapping/unresolved record, an empty sample,
   unreadable/unrelated records or detected loss refuses the whole qualified
   result. Do not drop inconvenient records and display the rest. A fragment
   with a valid base-header destination is not automatically unreadable merely
   because ports are unavailable. Define and test each predicate explicitly.
   No detected sequence gap is not proof of zero loss: losses before message
   construction may never receive sequence numbers.

The initial dependency gate would **still refuse the actual saved scenario**:
its bw_INPUT has a mark match and reachable bandwidth subchains contain opaque
BPF matches. The observed route MARK mask preserves the bandwidth mark bit
(`0x7fefffff & 0x100000 == 0`), but that observation is not a complete dependency
proof. Resolve the actual path before claiming this proposal fixes Frankenpixel.
Per-family qualification is an alternative to investigate, not an approved
substitute or permission to ignore a dangerous change in the other family.

## Counter and provenance questions still open

Claude proposed equal probe/DROP deltas and accepted-record counts no greater
than post-setup probe deltas. Do not implement those equations as written:

- The socket is bound before insertion; packets can queue during setup. A delta
  starting after verifyProbes excludes legitimate queued observations.
- A newly inserted probe starts at zero. Its final absolute packet count,
  observed after collection closes, is a candidate upper bound for accepted
  records bearing that exact family/session/scope/reason tag. Validate this
  accounting model and all error paths before using it as a gate.
- Packets in flight can increment probe and DROP counters across snapshot reads.
  Delta equality needs a demonstrated accounting protocol, not an invented
  tolerance. Otherwise keep it diagnostic; do not introduce another routine
  false refusal while claiming a proof of continuity.
- A terminal all-table scan catches persistent copied-tag/group conflicts.
  Counter checks may detect additional inconsistencies, but do not establish
  authenticity against counter-aware root tampering or invisible ABA changes.
- Reject malformed sequence/ingress attribute lengths and duplicates. Verify the
  supported-kernel sequence initialization convention before adding a leading-
  loss rule. Audit recommendations do not substitute for ABI verification.

## Result, cleanup and UI contract

| Evidence | Proposed result |
| --- | --- |
| All loaded tables exact; owned/probe checks pass | Normal bounded sample |
| Every narrow exception and dependency check passes | Qualified sample with visible network-change notice |
| Owned changes, unexplained changes, overlap or incomplete proof | Withhold after exact cleanup; identify the failed check |
| Malformed reserved rule or foreign diagnostic session | Existing refusal/manual-review behavior; no broad deletion |
| Probes gone but validity fails | Sample withheld; no recovery suggestion for nonexistent residue |
| Cleanup unverified | No result; existing residue/recovery handling |

Every new pre-cleanup read/validation failure must enter the cleanup-protected
error path. Close collection first; delete only validated session probes. After
cleanup returns set touched=false, then classify and independently verify ACTIVE
even if the sample is refused. Classifier failure must not skip verification,
mislabel cleanup or trigger automatic recovery/retry. Recovery keeps its current
separate contract.

A versioned capture response (proposed PUFW_INSIGHTS_V2) must distinguish exact
and qualified comparisons. The Android parser rejects missing, duplicate,
unknown or inconsistent fields. Suggested qualified wording: “System networking
rules changed during this sample. These records came from unchanged PocketUFW
DROP rules. What reached PocketUFW may have changed.” Add a carrier label only
when separately supported. Keep “All Insights probes removed; PocketUFW filter
rules and ACTIVE status verified.” Never claim all original Android rules were
unchanged. Existing generic V1 wording should also be reviewed for precise scope.

## Tests and implementation gates

- Replay sanitized saved snapshots; V1 still refuses. Synthetic packet metadata
  can exercise a future predicate but cannot retrospectively validate this run.
- Mutate every grammar field, hook, caller, policy, counter and session marker.
  Include a removed DROP exposing an unchanged ACCEPT, transitive mark/policy
  coupling, opaque BPF, same-chain mixed changes and cross-table copied tags.
- Test exact -i plus NFLOG suffix substitution, similar interface names,
  duplicated supported rows, changed handles, masks, targets and group numbers.
- Include setup-queued packets, saturated traffic during counter reads, malformed
  sequence/ingress attributes, source-only records, address overlap, interface
  disappearance/reuse, empty/loss-limited samples and byte-counter decreases.
- Exercise every new read/parse failure before and after cleanup; exact cleanup
  and independent verification remain mandatory. Existing cancellation,
  malformed-residue and crash-recovery tests remain intact.
- Confirm loaded-table enumeration does not load modules, bounds fail closed,
  protocol enums remain strict and qualified UI never claims global stability.
- Review implementation independently, test disposable namespaces and Moto, then
  obtain separate authorization before any Frankenpixel update or new capture.

## Audit disposition and threat boundary

Claude's first verdict was REQUEST CHANGES. Adopted: whole-chain DROP-only
constraint, kernel evidence instead of a carrier-identity permission, exact
row-scoped substitutions, a consistent snapshot format, strict setup comparison,
completion provenance checks, and cleanup/error separation. Corrected two audit
assumptions: post-setup deltas omit queued records, and the NFLOG substitution
changes two linked values. Snapshot atomicity needs additional validation.

Remaining blockers are the actual mark/BPF dependency proof and sound bounded
counter/provenance accounting. No qualified acceptance implementation is approved.
The review package retains the original proposal and full Claude audit so this
revised draft is not misrepresented as already approved by that audit.

Claude's follow-up accepted revision 2 as an investigation plan and review
handoff, **not** approval to implement qualification. It withdrew the post-setup
delta equation, probe/DROP delta equality, one-token substitution, claim that the
proposed mark gate admitted this case, and unsupported assumption of rare churn.

Next bounded investigation: propagate exact ingress guards through unchanged
call paths and compare mark read/write footprints, rejecting unresolved state
transfer or opaque decisions. For generic --set-xmark V/M the write footprint
is M | V, not necessarily M; the observed value has no bits outside its mask.
The saved snapshots also contain CONNMARK save rules in INPUT and OUTPUT touching
overlapping bits. Their ordering and cross-packet implications remain unresolved;
mask arithmetic alone does not approve this case. Do not replace this work with
a per-family bypass or a broad Android exemption.

The follow-up raised a hypothesis that a legacy table replacement may transiently
expose lowered counters before saved totals are restored. This was not established
on either phone. Investigate with source and isolated fixtures before any separately
authorized Moto work. An observed owned-counter decrease still withholds; label
unresolved accounting as indeterminate, never silently rebase or reset counters.

Endpoint checks cannot detect every transient change restored between reads,
and non-decreasing counters cannot prove no recreation occurred. Locks constrain
cooperating PocketUFW writers, not netd or other root programs. Installed iptables
snapshots do not audit all nftables/eBPF/routing/XFRM/offload behavior. Keep these
limits explicit; the product explains observed DROP matches, not global network
immutability. When proof is incomplete, preserve protection and withhold.
