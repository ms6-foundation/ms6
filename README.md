# ms6

A batched, updatable commitment scheme with selective opening.

Commit once to a list of values. Later, prove that specific positions hold
specific values — without revealing anything else in the list, and without the
verifier ever seeing the underlying data. Add, replace or delete items
afterwards without recommitting from scratch.

> **Status: research prototype.** Its one structural exposure — two fixed
> columns per row, always readable via a modular root extraction — is
> neutralized at the data level (they never carry real digit content) and
> is now formally defined and proven for that specific exposure. Binding
> still lacks a full reduction to a named hardness assumption, and whether
> repeated openings against the same batch could leak more than a single
> opening does is an open question. Read [Security](#security) before
> relying on it.

## Layout

```
ms6/                       prover
  core.py                    ms6() commit, ps6() open, Commitment,
                              QueryGovernor (deployment-level query policy)
  utils6.py                  arithmetic toolkit, incl. domain_hash (SHAKE128)
vs6/                       verifier — imports nothing from ms6/
  core.py                    vs6() verify
  utils6.py                  the subset of the toolkit a verifier needs
tests/                     98 checks; exits non-zero on failure
  run_all.py                 runs every module, one combined report
  harness.py                 shared fixtures + the pass/fail reporter
  test_roundtrip.py          commit -> open -> verify, and tamper rejection
  test_updatability.py       append / replace / delete
  test_modulus.py            default modulus's shape; not baked in
  test_sealtree.py           the cached fold tree
  test_params.py             the parameter contract and its enforcement
  test_parity.py             prover/verifier duplicated-copy parity
  test_sizing.py             x-sizing determinism, parallel construction
  test_completeness.py       sweep over the workers>1 batch-routing path
  test_adversarial.py        tamper / forge / equivocation attempts
  test_leak.py               root-extraction leak: decoy content either way
  test_query_governance.py   QueryGovernor: refusal, cap, per-batch scoping
  bench.py                   update cost (informational, never fails)
examples/
  payroll_audit_demo.py      HR proves salaries to an auditor
  sanctions_screening_scale_demo.py   120k-record registry, bank checks 2
ms6_vibe.md                development log — why each decision is what it is
```

Python 3.9+, no third-party packages required. `gmpy2` is used automatically
if present and materially speeds up the big-integer arithmetic; without it
there is a pure-Python fallback.

## Quickstart

```python
from ms6 import ms6, ps6, Commitment
from vs6 import vs6

vals = [...]                                    # the data being committed
d, q = 3, 10                                    # degree, exponent

# 1. COMMIT — publish c, keep the rest private
c, h_list, x_list, s_list, hm_list, perm_list, h1_salt_list, params = ms6(vals, d, q)

# 2. OPEN — prove positions 0 and 17, revealing nothing else
ps_list = ps6({0, 17}, h_list, hm_list, s_list, params, d)

# 3. VERIFY — the verifier needs only c, the claims, the proof, and d
claims = {0: vals[0], 17: vals[17]}
vs6(c, claims, ps_list, x_list, perm_list, h1_salt_list, params, d, expect=agreed_params)
```

`d` (the row-seal degree) is not part of `params` — it's a separate, required
argument the prover and verifier already agree on out of band, the same way
they agree on `d` before ever calling `ms6()` (see [`params`](#params)).

`vs6` returns `True`, raises `AssertionError` if the proof is invalid, or
`ParamMismatch` if it was produced under parameters you did not agree to.

### Updating a commitment

```python
reg = Commitment(vals, d, q)
i = reg.append(new_value)      # add
reg.replace(i, other_value)    # swap in place
reg.delete(i)                  # tombstone the slot

c, h_list, x_list, s_list, hm_list, perm_list, h1_salt_list, params = reg.opening()
```

An update touches one batch and refreshes a cached fold tree rather than
recommitting — measured **~40× faster** than a full recommit at 120k records
(`examples/sanctions_screening_scale_demo.py`).

Two consequences worth knowing:

- **`c` changes on every update**, so every verifier needs the new one, and any
  proof already issued from the touched batch must be reissued. Proofs do not
  survive updates.
- **`delete()` tombstones rather than removes.** The slot stays so no later
  index shifts; the item's contribution is genuinely gone from the commitment.
  Deleted indices are never reused.

## `params`

`ms6()` returns the public parameter set as a dict — `q`, `chunk_size`,
`batch_size`, `mod`, `seal_batch_size`, `rand_edge_size` — and `ps6`/`vs6` read
from it rather than taking those values loose. The three sides silently
disagreeing on any one of them is the bug class this removes; it has bitten
this codebase more than once.

`d` (the row-seal degree) is deliberately **not** in `params`. It's passed to
`ps6`/`vs6` as its own required argument instead, sourced the same place the
committer got it (e.g. `Commitment.d`) — so a party who only ever holds `c`,
with no opening, never sees it in the params blob. This doesn't hide `d` from
anyone who *does* see a real proof — the disclosed proof's own shape reveals
it regardless — it only narrows who learns it from `params` alone.

`params` carries no secrets, but it arrives from the prover and is **not
self-authenticating**. A verifier with its own agreed parameters should pin
them:

```python
vs6(..., params, d, expect={"mod": MY_MOD})
```

A subset is fine; unknown keys raise, so a typo cannot silently disable the
check it was meant to add. `d` can't appear in `expect` since it isn't a
`params` key — wrong `d` isn't a `ParamMismatch`, it just fails to verify
(`AssertionError` or `IndexError`, never a silent `True`).

## Why two packages

`vs6` imports nothing from `ms6`. A party that only verifies can install and
audit `vs6/` alone, never loading code that generates a secret salt or holds
opening data. The package split enforces that structurally — the self-test
verifies it by blocking `ms6` at the import hook and importing `vs6`.

The cost is that several functions are deliberately duplicated across the two
(`_seal_batch`, `chunk_of`, `_get_batch_ids`, most of `Utils`). Nothing in the
language keeps the copies in step, so the self-test compares their outputs
bit-for-bit. That check has already caught drift in code no proof path
exercises.

## Row-seal: the two-stage degree fold

Each row's seal is not a single combinatorial pass any more. `ms6.core._seal_grid`
folds `H' = H * S^d` in two stages: `eval_level_mod(d, H1, mod, coef=True)`
bucket-sums it into an intermediate vector, then a second, ordinary degree-`d`
fold (`vsum_level_fold_mod`) collapses that vector to the row's final scalar.
The disclosure/reconstruction split needed to prove this without revealing the
unclaimed (oset) side is asymmetric: the prover's disclosure stays a raw,
unsummed `coef=False` sweep (unchanged from before), and the verifier pairs its
own `coef=True` reconstruction of the claimed side against it — the resulting
inner vector is fully public once combined, so the second fold needs no further
secret-splitting.

This does **not** close either of the two documented leak paths below — the
disclosure shape (and therefore what a given proof reveals) is identical to the
single-stage construction it replaced, since it's the same `eval_row_grouped`
sweep either way. What it changes is the effective degree an attacker has to
invert for degree-based guessing attacks (e.g. the ratio-cancellation attack
under `QueryGovernor` below needs a `d²`-order root instead of a `d`-order one)
— harder, not eliminated.

Run flat, a single-group fold pays a full `eval_level_mod(d, chunk_size, mod,
coef=True)` combinatorial pass — impractical at the shipped default
(`chunk_size=100`; roughly 300ms/row at `d=3`, low seconds at `d=4`). The
swappable multi-level partition (`ut.partition_menu`/`build_partition`, drawn
independently per row from `gen`, same mechanism the original single-stage
fold already used) composes with the two-stage target too: each group's own
bucket vector is computed at every degree `0..d` and combined via a
**binomial-weighted** Cauchy product (`convolve_bucket_vecs_mod` — the extra
`C(k,i)` weight distinguishes it from `convolve_h_vectors_mod`'s plain Cauchy
product for the single-stage target), verified bit-exact against the flat
computation across row-major, transposed, and nested recipes. At
`chunk_size=100`, `d=3`, splitting into groups of 10 cuts the per-row fold from
~330ms to ~17ms; the group-size/degree tradeoff is a straight combinatorial
blow-up vs. leak-surface/disclosure-size one, same shape as the original
single-stage grouping decision.

## Query governance (optional)

`S`, the per-cell blinding grid, is fixed for the life of a commitment —
folded into `c` itself at commit time, not re-derived per opening. Two
openings of the same batch whose claim sets differ by only a couple of
items can cancel `S` out of the ratio between them and recover the
differing items' actual data (see [Security](#security)). `ps6()` itself
is unchanged and has no opinion on this; `QueryGovernor` is an optional
policy layer in front of it:

```python
from ms6 import QueryGovernor, ps6_governed

gov = QueryGovernor(batch_size=1000)   # match the commitment's own batch_size
ps_list = ps6_governed(gov, {0, 17}, h_list, hm_list, s_list, params, d)

# a later request too close to one already served against the same batch
# raises QueryPolicyViolation instead of being silently served
ps6_governed(gov, {0}, h_list, hm_list, s_list, params, d)  # QueryPolicyViolation
```

`min_new_items` (default `3`) sets how different a new claim set must be
from every one already served against the same batch. It defaults to 3,
not 2, because two ordinary, unrelated single-item claims against the
same batch (symmetric difference 2) are a full, clean break under the
shipped defaults — each proof's per-column values are individually
root-extractable, and comparing two such proofs cancels `S` and recovers
both claimed items' actual digits outright; `min_new_items=2` alone does
not stop it. `max_openings_per_batch` (default `None`, uncapped) caps how
many distinct claim sets a batch will ever serve before an operator
should reseal that batch under a fresh salt. This is a policy control,
not a proof — see [Security](#security) for what it does and does not
close.

## Security

Honest limitations, since this is a prototype:

- **A structural exposure, neutralized at the data level rather than behind a
  hardness assumption.** The combinatorial bucketing underneath both
  reconstruction paths (`mul_combinations_mod`/`mul_group_hvec` for the
  original target, `mul_combinations_bucket_vec`/`mul_group_bucket_vec` for
  the two-stage one — see [Row-seal](#row-seal-the-two-stage-degree-fold))
  gives EVERY column — not just the two combinatorial-extreme ones — a raw,
  invertible pure-power term sitting at a publicly-computable position in its
  own bucket: reading one back costs one modular root extraction, regardless
  of `mod`. Rather than raise that cost, the construction ensures the read
  yields nothing over the columns nearest each edge: those are reserved for
  digits derived deterministically from the item's own hash under a
  domain-separating tag, disjoint from where real digit content is ever
  written. A successful extraction there is therefore always possible and
  always decoy — verified numerically (`tests/test_leak.py`), not just
  argued structurally. The remaining (real-data) columns are root-extractable
  the same way, but a single such extraction alone reveals nothing on its
  own — `S(r,j)` still blinds it; see the next point and `QueryGovernor`
  above for what turns that extraction into actual exposure. The two-stage
  fold does not change any of this — the prover's disclosure is byte-for-byte
  the same sweep either way, so this leak's surface is identical regardless
  of which target the verifier reconstructs from it.
- **The modulus's job is fingerprinting, not hiding — sized accordingly.**
  `DEFAULT_MOD` is a 256-bit nothing-up-my-sleeve prime (derived
  transparently from pi's digits — see its comment in `utils6.py`), not the
  RSA-2048 composite this project used to ship. Root-extraction hardness
  turned out not to be achievable through modulus choice under this
  construction at any size — mod a prime the group order is always public,
  so a `d`-th root is one `pow()` away regardless of bit length — so the
  decoy neutralization above is what actually has to hold, and does,
  independent of the modulus (`tests/test_leak.py`). The old composite is
  still available as `LEGACY_MOD_2048` for anyone who wants that redundant
  unknown-order layer anyway, at a measured ~2-3× arithmetic cost for the
  exponentiation-dominated operations throughout `ps6`/`vs6`. `mod` is not
  baked into the protocol either way: `ms6()`
  records the one it used in `params`, and `ps6`/`vs6` read it from there,
  so a commitment under any other modulus (prime or composite) still
  verifies from its own `params`.
- **Item digests, and the batch-combining fold, both go through a standard
  cryptographic hash.** `H1`/`H2` (the per-item digest) and the seal-tree/
  batch fold that combines per-batch scalars into the final commitment both
  go through SHAKE128 (`Utils.domain_hash`), not a bespoke transform —
  collision and preimage resistance rest on SHAKE128's own published
  security claims. A separate digit-substitution `hash()` still exists, but
  only for one remaining internal purpose (sizing the secret salt's range)
  — it is not used for item hashing or the batch-combining fold anymore.
- **`H1` is salted per batch**, closing an offline dictionary-attack gap:
  without a salt, anyone can hash a candidate value and compare it against a
  quantity extracted from a proof, with zero interaction — practical over a
  low-entropy item space (the stated use case: SSNs, names, DOBs). The salt
  is secret until any item in that batch is opened, same threat model as the
  blinding grid and column permutation.
- **The neutralized (edge) columns carry no information, unconditionally.**
  Their `H`-side content is a fixed public constant regardless of which
  items are claimed, so the ratio between any two proofs' edge-column
  values against the same commitment is always exactly 1 — not a bounded
  leak, no information at all (`tests/test_leak.py`). This says nothing
  about the non-edge columns.
- **One thing stays genuinely open; the other is demonstrated, not just
  suspected.** Binding has no reduction to a named hardness assumption — it
  rests on an empirical fingerprinting argument plus the domain hash's
  assumed collision resistance, not a proof; that part remains open.
  Multi-query correlation over the non-edge columns is no longer just a
  theoretical concern: two ordinary, unrelated single-item openings against
  the same batch (symmetric difference 2, no crafted similarity needed) fully
  recover both claimed items' actual digits at every real column, by root-
  extracting each proof's per-column values and canceling `S(r,j)` via their
  ratio. `QueryGovernor`'s default (`min_new_items=3`, above) blocks exactly
  this shape; larger, still-permitted differences between claim sets leak a
  messier but not obviously safe aggregate. This is a policy control, not a
  proof of resistance to a more general multi-query adversary.

`ms6_vibe.md` records what each mechanism defends against and what it does
not, including several attempts that were tried and reverted.

## Tests

```
python3 -m tests                 # everything, one combined report
python3 -m tests.test_parity     # one group on its own
```

78 checks covering the round trip, updatability (append/replace/delete), the
cached fold tree, the parameter contract and its enforcement, modulus sizing
and modulus-independence, prover/verifier copy parity, a sweep over the
parallel batch-routing path, an adversarial suite (tampered values,
wrong-index substitution, fabricated values, cross-batch swaps, iset/proof
mismatch, and hm equivocation at both claimed and unclaimed positions), the
root-extraction leak (confirming what's recovered is decoy under the shipped
default prime, a fresh unrelated prime, and the legacy composite alike, not
just that extraction fails), and `QueryGovernor`'s refusal/cap/per-batch-
scoping behavior. Exits non-zero on failure with the failing checks named,
so it works as a CI gate.

The parity module is the one worth keeping: it compares the duplicated prover
and verifier copies output-for-output, and is the only check that catches
drift in code no proof path happens to exercise.

## License

MIT — see [LICENSE](LICENSE).
