# ms6

A batched, updatable commitment scheme with selective opening.

Commit once to a list of values. Later, prove that specific positions hold
specific values — without revealing anything else in the list, and without the
verifier ever seeing the underlying data. Add, replace or delete items
afterwards without recommitting from scratch.

> **Status: research prototype.** It has a documented information leak and no
> formal security proof. Read [Security](#security) before relying on it.

## Layout

```
ms6/                       prover
  core.py                    ms6() commit, ps6() open, Commitment
  utils6.py                  arithmetic toolkit
vs6/                       verifier — imports nothing from ms6/
  core.py                    vs6() verify
  utils6.py                  the subset of the toolkit a verifier needs
tests/                     49 checks; exits non-zero on failure
  run_all.py                 runs every module, one combined report
  harness.py                 shared fixtures + the pass/fail reporter
  test_roundtrip.py          commit -> open -> verify, and tamper rejection
  test_updatability.py       append / replace / delete
  test_sealtree.py           the cached fold tree
  test_params.py             the parameter contract and its enforcement
  test_parity.py             prover/verifier duplicated-copy parity
  test_modulus.py            modulus sizing + legacy backward compatibility
  test_sizing.py             x-sizing determinism, parallel construction
  test_completeness.py       sweep over the workers>1 batch-routing path
  test_adversarial.py        tamper / forge / equivocation attempts
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
c, h_list, x_list, s_list, hm_list, perm_list, params = ms6(vals, d, q)

# 2. OPEN — prove positions 0 and 17, revealing nothing else
ps_list = ps6({0, 17}, h_list, hm_list, s_list, params)

# 3. VERIFY — the verifier needs only c, the claims, and the proof
claims = {0: vals[0], 17: vals[17]}
vs6(c, claims, ps_list, x_list, perm_list, params, expect=agreed_params)
```

`vs6` returns `True`, raises `AssertionError` if the proof is invalid, or
`ParamMismatch` if it was produced under parameters you did not agree to.

### Updating a commitment

```python
reg = Commitment(vals, d, q)
i = reg.append(new_value)      # add
reg.replace(i, other_value)    # swap in place
reg.delete(i)                  # tombstone the slot

c, h_list, x_list, s_list, hm_list, perm_list, params = reg.opening()
```

An update touches one batch and refreshes a cached fold tree rather than
recommitting — measured **~110× faster** than a full recommit at 120k records.

Two consequences worth knowing:

- **`c` changes on every update**, so every verifier needs the new one, and any
  proof already issued from the touched batch must be reissued. Proofs do not
  survive updates.
- **`delete()` tombstones rather than removes.** The slot stays so no later
  index shifts; the item's contribution is genuinely gone from the commitment.
  Deleted indices are never reused.

## `params`

`ms6()` returns the public parameter set as a dict — `d`, `q`, `chunk_size`,
`batch_size`, `mod`, `seal_batch_size` — and `ps6`/`vs6` read from it rather
than taking those values loose. The three sides silently disagreeing on any one
of them is the bug class this removes; it has bitten this codebase more than
once.

`params` carries no secrets, but it arrives from the prover and is **not
self-authenticating**. A verifier with its own agreed parameters should pin
them:

```python
vs6(..., params, expect={"mod": MY_MOD, "d": 3})
```

A subset is fine; unknown keys raise, so a typo cannot silently disable the
check it was meant to add.

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

## Security

Honest limitations, since this is a prototype:

- **Known information leak.** `mul_combinations_mod`'s combinatorial bucketing
  has singleton buckets at the extremes, invertible by modular root extraction,
  recovering a handful of real columns per row. Documented in the source, not
  fixed. Closing it needs a modulus of *unknown order* (RSA modulus or class
  group): root extraction is efficient mod a prime at any size, so no parameter
  choice fixes it.
- **The `h == c` check is probabilistic**, not exact — distinct values collide
  with probability ~1/`mod`. `DEFAULT_MOD` is 256-bit, giving ~2⁻²⁵⁶ against
  honest error and ~2¹²⁸ birthday work for an adversary. `LEGACY_MOD_2048` is
  retained so commitments made under the previous modulus still verify.
- **No formal proof** of binding or hiding. The blinding, column permutation
  and row-sealing each close a specific attack found during development; that
  is not a security argument.
- **`hash()` is a custom digit-substitution function**, not a standard
  cryptographic hash.

`ms6_vibe.md` records what each mechanism defends against and what it does not,
including several attempts that were tried and reverted.

## Tests

```
python3 -m tests                 # everything, one combined report
python3 -m tests.test_parity     # one group on its own
```

49 checks covering the round trip, updatability (append/replace/delete), the
cached fold tree, the parameter contract and its enforcement, modulus sizing
and backward compatibility, prover/verifier copy parity, a sweep over the
parallel batch-routing path, and an adversarial suite (tampered values,
wrong-index substitution, fabricated values, cross-batch swaps, iset/proof
mismatch, and hm equivocation at both claimed and unclaimed positions). Exits non-zero on
failure with the failing checks named, so it works as a CI gate.

The parity module is the one worth keeping: it compares the duplicated prover
and verifier copies output-for-output, and is the only check that catches
drift in code no proof path happens to exercise.

## License

MIT — see [LICENSE](LICENSE).
