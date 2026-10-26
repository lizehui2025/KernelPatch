# selinux_hide: the time structure of a query

This note records what is still observable on the **time** side when selinux_hide
answers a selinuxfs query, and what has been closed. Content policy (whether the
answer depends on the payload) is not discussed here; it follows from the order of
decisions in `kp_context_to_sid_clean*`, which the code comments cover.

## 1. Three layers

A caller can observe the feature at three depths:

| Layer | What is observed | State |
| --- | --- | --- |
| L1 content | For the same request, does the answer depend on the payload | `context` and `attr/current` are closed; `access` cannot be closed (its answer *is* a function of the payload) |
| L2 cost | For the same *valid* request, does the time vary | Still present, see section 3 |
| L3 structure | SID numbering, sidtab size, policy snapshot | Bounded: `seqno` is pinned to a constant, and only contexts the snapshot accepts are registered in the live policy |

L1 is closed by ordering: `context` performs its permission check
(`check_context`) first and only touches the payload afterwards; `attr/current`
does the same through `kp_avc_check(SETCURRENT)` before any parsing. A denied
probe therefore takes one early-exit path on stock and on this feature alike,
whatever the payload looks like.

`access` is different: its answer (the six numbers of `av_decision`) is a function
of the payload, so a valid request is inherently more expensive than a failing one.
There is nothing to make *equal* on that layer, only constants to shrink.

## 2. Where a query goes

`context` (uid >= 10000, snapshot route):

1. `current_uid()`, log-level test (one comparison while the log is off)
2. `kp_avc_check(SECURITY__CHECK_CONTEXT)`: `security_cred_getsecid()` + `avc_has_perm()`
3. snapshot parse: payload copied into a writable buffer (now preferably the stack)
   -> `string_to_context_struct()` (in-place tokenising plus policy hash lookup)
   -> `sidtab_context_to_sid()`
4. live registration: `security_context_to_sid()`, which duplicates the string with
   `kstrdup` and tokenises it a second time
5. `sid_to_context()`: sidtab lookup plus `sid2str` (allocated and cached on first
   use, cached afterwards)
6. `memcpy` of the canonical string back into the kernel buffer

`access` does steps 3 and 4 twice (ssid and tsid) and adds `compute_av` plus
hex/decimal formatting.

The failing path (a context the snapshot does not know) returns after step 3 and
never runs steps 4 and 5. That difference is the source of L2, and it is not the
same thing as the stock "success versus early exit" ratio.

## 3. Measurements (hide on, big core pinned, paired A/B)

| Metric | Value |
| --- | --- |
| `context` A block median delta (measured in the app) | p10 / med / p90 = 2188 / 2240 / 2290 ns |
| Same-magnitude A−B (stock) | about +990 ns |
| Same-magnitude A−B (hooked) | about +1875 ns |
| Marginal cost, `context` | about +0.9 us (1.8 -> 2.7 us) |
| Marginal cost, `access` | about +2.0 us (10.1 -> 12.1 us) |
| Marginal cost, `attr/current` accept | about +0.35 us (6.98 -> 7.58 us, ~8%) |
| App-side A/B ratio (on screen) | `context` 2.67x, `access` 4.30x |
| Cross-session variance | same build, two runs, `context` A median 4115 -> 1771 ns (2.3x) |

How to read it:

- within one run the verdict is stable (about 18 sigma), so added noise does not hide it;
- cross-session variance is larger than the difference this feature introduces, so a
  comparison across devices concludes nothing;
- to decide anything, an attacker needs an OFF baseline on the *same* device and
  kernel, i.e. the ability to reflash boot or to toggle this feature, at which point
  hiding is moot. That is the practical boundary of this layer.

## 4. Residual channels

| Id | Channel | State | Note |
| --- | --- | --- | --- |
| R1 | `context` success costs more than failure | present | snapshot parse + live registration + sid2str + copy; stock also pays for success, this pays more |
| R2 | `access` does the policy work twice | present | one snapshot plus one live conversion per context, where stock does one live conversion |
| R3 | `attr/current` accept is ~8% slower | present | comes from the snapshot parse; does not happen when the permission is denied |
| R4 | `sid2str` cold/warm | present | allocated and cached on first use; repeated queries from one pid show a step |
| R5 | the query log | operational | at `on`/`verbose`, `logkfi` costs far more than the query itself; switch it off before timing |
| R6 | sidtab size | bounded | only snapshot-accepted contexts are registered; rejected ones (`u:r:su:s0` and friends) are not |
| R7 | `seqno` | pinned | `KP_AVD_CLEAN_SEQNO` |

There are only two ways to make the *cost* match, and both have a price:

1. make the failing path pay the same amount, which changes stock's early exit and
   creates a new observable difference of its own;
2. drop live registration or `sid2str` from the successful path, which breaks the
   invariant that a SID handed out here resolves in the live policy (KernelSU
   a810677b exists for exactly that).

So the goal can only be to shrink the constants, not to reach zero.

## 5. Per-stage timing

With the query log at `verbose` (control state 2) both hooks print one nanosecond
breakdown per app query; at `off`/`on` the whole block is a single comparison
against `KP_QLOG_VERBOSE`.

```
stage context uid=10443 size=33 log=0 avc=... snap=... live=... sid2str=... copy=... total=...
stage access  uid=10443 size=57 log=0 avc=... parse=... scon(snap=... live=...)
              tcon(snap=... live=...) conv=... avd=... fmt=... total=...
```

- `snap`: snapshot parse (in-place tokenising plus sidtab lookup)
- `live`: the `security_context_to_sid()` that registers the context in the live policy
- `sid2str`: reverse lookup of the canonical string (including the first allocation)
- `conv`: both context conversions together (`access`)
- `avd`: `compute_av` and field filling
- `fmt`: formatting and reply

`g_stage_*` are written only at that level and never take part in a decision. A
payload large enough to take the allocating route reports `-1` for the two context
stages, meaning "not attributed this time".

Reproduce:

```sh
# 1. set the log to verbose (control state 2)
# 2. run attrprobe / sfsprobe so an app uid issues context and access queries
# 3. read the numbers
su -c "dmesg | grep 'stage '" | tail -40
# 4. restore control state 0
```

Note that `verbose` itself is charged to `total` and inflates the absolute latency
the caller sees, so turn it off around any timing run; only stage values compared
against each other are meaningful, not `total` against stock.

## 6. Acceptance

A change is accepted the same way every time: on one device, with the same paired
app-side probe, compare

- the `context` A block median (hide on, before vs after),
- the `access` A block median (same),
- and the A−B difference.

A change counts as cost alignment only when the absolute A cost drops and the A−B
verdict (distinguishable or not) is unchanged; flattening the difference while
introducing a different fingerprint (a cold/warm step from a cache, say) does not.
