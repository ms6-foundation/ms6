# ms6 — session log

A running log of changes to the ms6/ps6/vs6 commitment scheme, kept so the
reasoning behind a change (and behind backing one out) survives the change
itself. Newest entries at the bottom.

**This file merges two session logs covering the same lineage of code from
two different vantage points:**

- **Parts A–B** (entries 1–21) — the original development log, uploaded from
  the project folder. Covers `ds15/` (single-file prototype) and `ds16/`
  (verifier split into its own package) on a local macOS machine. This is
  where the S-side modulus-ring sealing and the `Commitment`/updatability
  design were built.
- **Part C** (entries 22–28) — a downstream integration session, run in a
  Linux sandbox (Cowork), that received Parts A–B's output as file uploads,
  fixed two platform/parallelism bugs, worked through a leak-diagnosis/revert
  cycle of its own, and wired the finished `Commitment` feature into two
  example applications. This is where the project currently stands.

**Session date:** 2026-08-08 (IST for Parts A–B). All Part A/B entries were
done in one session, so per-entry wall-clock times weren't recorded as they
happened — every timing in Parts A–B was measured on the machine described
under *Environment*, during that session. Part C's environment and timings
are noted separately at its start.

### Environment (Parts A–B)

| | |
|---|---|
| Python | 3.14.6 |
| Platform | Darwin 25.5.0 arm64 |
| CPUs | 10 |
| gmpy2 | **absent** — pure-Python integer fallback |

`gmpy2` being absent matters for every number in this log: `utils6.py` falls back
to CPython big-ints, so all modular arithmetic (and therefore every ms/µs figure
here) is slower than it would be with GMP's FFT-based routines. The *ratios* —
speedups, relative costs — should hold either way; the absolute times would not.

Covers two trees:

- **Part A — `ds15/`** (`ms6.py`, `pow_utils.py`) — single-file prototype
- **Part B — `ds16/`** (`ms6.py`, `utils6.py`, `vs6.py`, `verifier_utils6.py`) —
  verifier split into its own zero-prover-dependency package

Recurring theme worth stating once: several pieces of this codebase are
**deliberately duplicated** — `_seal_batch`, `chunk_of`/`chunks`,
`_get_batch_ids`, and most of `utils6.Utils` — so the verifier package has no
import dependency on prover code. Nothing enforces that the copies stay in
lockstep, so almost every entry below that touches one copy touches the other.

---

# Part A — `ds15/`

## 1. Constants, a separate vs6 modulus, Poseidon, and reverse index lookup

**Request**

> Please set all default values as constant, and use separate mod value in vs6.
> please pass poseidon hash values in the vs6 and reverse lookup the indices in
> the ps6. Please cleanup comments and add comments that are relevant to the
> current implementation.

### Findings before implementing

Three things surfaced that changed what "correct" meant, so they were raised
before writing code:

1. **`ut.hash_poseidon()` was dead code.** It referenced `DEFAULT_MOD` and
   `hashlib`, neither defined nor imported in `pow_utils.py` — `NameError` on
   any call.
2. **Switching only vs6's hash would break honest verification.** vs6 verifies
   against digit counts ms6 built with `ut.hash`; a different hash on one side
   only means honest proofs fail, not just dishonest ones.
3. **A real bug in `ps6`** (`ms6.py:355`): `end = start + len(hm_b)` reused
   `hm_b` left over from the boundaries-building loop — always the *last*
   batch's `hm` — instead of `hm_list[b]`. Wrong whenever batches aren't
   uniformly sized.

Three clarifying questions were asked. Answers: *replace vs6's core mod* /
*additional check, layered on* / *value → index lookup*.

### What changed

- Defaults extracted to constants; `VS6_MOD` as vs6's own named modulus.
- `pow_utils.py`: added `import hashlib` and a `DEFAULT_MOD` prime so
  `hash_poseidon` actually runs.
- **Poseidon layer, additive:** `ms6` computes a per-item Poseidon hash, folds
  each batch's into `ph_h`, and folds those into a second top-level commitment
  `c2`. vs6 re-folds `ph_h_list` and checks it against `c2` — independent of,
  and not weakening, the primary `h == c` check.
- **`ps6` reverse lookup:** takes claimed *values* instead of caller-supplied
  indices, hashes each with Poseidon, and looks up its true global index. A
  value that was never committed now raises instead of silently proving the
  wrong item.
- Fixed the boundary bug; deduped `batch_ids`.
- Trimmed long historical comments referencing files that don't exist in the
  repo (`forge_ps.py`, `tamper_row_truncation.py`, `seals6.py`, `utils6.py`).

### Verified

Commit → open → verify; bogus claim rejected by the reverse lookup; tampered
`c2` rejected; the original 10,000-item `__main__`.

---

## 2. Revert Poseidon (too slow)

**Request**

> poseidon hashing making the program run very slow, please revert the code clean
> the poseidon implementation.

Poseidon ran ~65 permutation rounds of 2048-bit modexp **per item**.

### What changed

`ms6.py` reverted to the non-Poseidon design — original `ms6`/`ps6`/`vs6`
signatures, no `c2`/`ph_list`/reverse lookup. **Kept** the independently-good
parts: constants, `VS6_MOD`, the `ps6` boundary-bug fix, trimmed comments.

Full run: **~0.9 s** (from painfully slow).

### Flagged, not changed

`vs6`'s `__main__` passed `iset`/`vals` as **sets** and paired them with
`zip()`. Two independently-ordered sets have no guaranteed matching iteration
order, so the pairing only lined up by luck. Pre-existing; raised rather than
silently fixed.

---

## 3. Fix the vs6 pairing; delete Poseidon from `pow_utils.py`

**Request**

> please fix the pairs in vs6 and delete the hash_poseidon/_poseidon_params from
> the pow_util.py

### What changed

- Removed `hash_poseidon`, `_poseidon_params`, `_poseidon_permute`,
  `DEFAULT_MOD`, and the `hashlib` import from `pow_utils.py`.
- **`vs6(c, iset, vals, …)` → `vs6(c, claims, …)`** where `claims` is a
  `dict[index, value]`. A dict's keys and values are inherently paired, so the
  index↔value correspondence cannot silently desync the way two sets could.

### Verified

Honest claim accepted in any key ordering; a claim where the value doesn't match
its index rejected.

---

# Part B — `ds16/`

## 4. Recursive `_seal_batch`

**Request**

> For large data set the ms6 batch will produce result larges than the
> batch_size. Can you set recursive batch operation in the `_seal_batch` for a
> seal_batch_size of 1000? This operation should be recursive if the result of
> the `_seal_batch` is over the seal_batch_size.

### What changed

New `DEFAULT_SEAL_BATCH_SIZE = 1000`. Above the threshold, `_seal_batch` splits
into `seal_batch_size` groups, seals each recursively, then recurses on the list
of group-seals — repeating until one pass covers everything. Below it, byte-for-byte
the original flat fold.

Applied to **both** `ms6.py` and `vs6.py` with the same default — `vs6` must
reproduce `ms6`'s fold exactly or `h == c` never holds.

### Verified

Below-threshold no-op; both copies agree bit-for-bit under multi-level
recursion; full commit→open→verify with **1050 batches** (over the threshold).

---

## 5. Remove `q` from `vsum_level`

**Request** — *please remove q from vsum_level*

`q` defaulted to 1 at every reachable call site and `pow(v, 1) == v`, so results
were unchanged. The only call passing `q` was in `vs6._seal_batch`'s
`mod is None` branch — already dead (`vs6()` always passes `mod`) and already
divergent from `ms6.py`'s copy, so the branch was removed, restoring lockstep.

---

## 6. Remove `q` from `vsum_level_mod` and `vsum_level_fold_mod`

**Request** — *Please remove q from vsum_level_mod and vsum_level_fold_mod*

### The complication

Unlike entry 5, `q` here was **load-bearing**. Removing it from the commit side
alone broke honest verification for any `q ≠ 1` — confirmed by bisecting:
`q=1` passed, `q=10` failed.

The row-seal is one equation computed two ways: `vsum_level_mod` on the commit
side, `mul_combinations_mod` on the verify side. So `q` had to come out of
`mul_combinations_mod` too — one function beyond the literal request, but the
change is incoherent without it. Verified the core identity afterwards:

```
vsum_level_mod(d, mod, combined) == mul_combinations_mod(d, eval_level_mod(d, combined, mod), [1]*L, mod)
```

Also dropped the now-ignored `q` from `seal_row_mod`'s args tuple.

### Flagged, not changed

`ms6.py` and `vs6.py`'s `_seal_batch` had **diverged** in parallel edits —
`ms6` used `e = d` as `cell_product_mod`'s exponent, `vs6` used `q`. That, not
the `q` removal, was what then failed. Raised with both options rather than
picking one.

---

## 7. Replace `e` with `q`

**Request** — *can you also replace e with q in ms6.py and vs6.py?*

Settled entry 6's open question in favour of `q`. Five sites, all previously
`e = d`, which had to move together — they're the same exponent seen from the
commit, open, and verify sides:

| file | function | site |
|---|---|---|
| `ms6.py` | `_ms6_batch` | `cell_product_mod(…, q, mod)` (H side) |
| `ms6.py` | `_seal_batch` | `cell_product_mod(…, q, mod)` |
| `ms6.py` | `_ps6_batch` | `cell_pow_product_mod(…, q, mod)` (oset) |
| `vs6.py` | `_seal_batch` | both branches |
| `vs6.py` | `_vs6_batch` | `interlace_mod(…, q, mod, perm=perm)` (M side) |

Also fixed `vs6`'s dead branch still calling `vsum_level(d, values=H1, q=q)`,
which would have raised `TypeError` after entry 5.

### Verified

`q` = 1/2/3/10 all verify; **verifying with a different `q` than committed is
rejected** — so `q` is genuinely load-bearing now, not inert.

---

## 8. Simplify the `pairs` construction

**Request**

> please remove mod operation from keys/values pairs, and replace it with simple
> pairs for example, `pairs = [(k, v) for k, v in zip(keys, values) if v]`

Four lines — `vsum_level_mod` and `h_vector_mod`, in both `utils6.py` and
`verifier_utils6.py`. Values now go in unreduced, which is equivalent since every
downstream use already reduces.

**Noted:** not a pure no-op. `if v % mod` dropped values that were nonzero but
≡ 0 mod `mod`; `if v` keeps them, and `C = max(k …)` derives from the survivors.
Negligible for a 2048-bit prime, and both sides run identical code.

---

## 9. Clean up `h_vector_mod` / `fold_h_vector_mod` signatures

**Request** — *please cleaup h_vector_mod and fold_h_vector_mod signatures*

Dropped the now-unused `q` from both signatures in both files, plus the two
`q=q` pass-throughs and a stale docstring reference. Verified the identity these
functions exist to satisfy still holds across randomized trials:

```
vsum_level_fold_mod(N, mod, row, global_keys=True) == vsum_level_mod(N, mod, values=row)
```

That completed the `q` removal across the whole seal chain.

---

## 10. Question — appropriate bit size for the modulus

**Request** — *what is an appropriate bit prime for `v % mod`?*

Answer depended entirely on which job the modulus does:

| job | appropriate size |
|---|---|
| fingerprinting (what it actually does) | **256-bit** — 2⁻²⁵⁶ honest, 2¹²⁸ birthday |
| discrete-log hiding | 3072-bit **safe** prime for 128-bit |
| root-extraction hardness | **not achievable with a prime at any size** |

Demonstrated the third point against the actual 2048-bit modulus: recovering `x`
from `x³ mod p` took **39 ms**. Root extraction is free mod a prime because the
group order is known; hardness needs a modulus of *unknown* order (RSA / class
group). Going 2048 → 4096 buys nothing there.

Also found `DEFAULT_MOD` is **not a safe prime** — `(p−1)/2` is composite — and
that `gcd(q, p−1) ≠ 1` for even `q`, so `x → x^q` isn't a bijection at the
default `q = 10`.

---

## 11. Fix `seal_mod`

**Request** — *please fix the seal_mod*

Three defects:

1. **Units bug.** `_seal_mod(len(str(hmax)))` fed a *decimal digit count* into
   `generate_prime(bits=…)` — an **81-bit** prime where `hmax` needed 266.
   Now `hmax.bit_length() + 1`.
   The `+1` is load-bearing: `generate_prime(n)` returns a value in
   `[2ⁿ⁻¹, 2ⁿ)`, so asking for `hmax.bit_length()` alone can still land *below*
   `hmax`. Caught when the docstring's own claim tested False.
2. **No floor.** Added `DEFAULT_SEAL_MOD_BITS = 256`; the sealed value becomes
   the secret salt, so it shouldn't be reduced into a small range.
3. **Wasted work.** The prime was generated unconditionally but only used in the
   `s is not None` branch. Moved inside it — the default path now commits in ~2 ms.

---

## 12. A separate modulus for `S`

**Request**

> can you use different mod value to achieve Discrete-log hiding for the
> cell_product_mod operation for constructing the s_list?

### What changed

`s_mod` threaded through `_ms6_batch`/`ms6`, defaulting to `DEFAULT_S_MOD`.
`ps6`/`vs6` needed **no** changes: `S`'s value travels in `s_list`, and both
sides feed that same integer to `pow(S[j], d, mod)` on the H side, so only `mod`
governs the check identity.

### Flagged — it does not achieve DL hiding

The documented leak recovers the group element `S[j]` **itself**. Possessing it
is all an attacker needs to unblind; whether its discrete log is hard is
irrelevant, as is the ring it was built in. Documented at the constant so the
name doesn't imply a property it lacks.

### Two measurements that mattered more

- **`s_mod` often does nothing.** At batch=20 `S` never reaches 50 bits, so the
  reduction never bites regardless of modulus.
- **`S` was weak for an unrelated reason:** at chunk_size=40/batch_size=1000,
  **46% of `S` entries were ≤ 8 bits** (74 of 160) — cells where `accS` counts
  were all-zero, leaving `S = S0[i][j] ∈ 1..9`. Median 530 bits: the grid was
  bimodal, half doing real work and half doing nothing.

---

## 13. Full-width blinding for every cell

**Request** — *get the cells seeded from the salt so every column gets full-width blinding*

`_s0_grid()` replaces one-decimal-digit-per-cell `S0`:

```python
digest = hashlib.shake_256(f"{s}:{batch_index}:{i}:{j}".encode()).digest(nbytes)
row.append(int.from_bytes(digest, 'big') % s_mod or 1)
```

| | before | after |
|---|---|---|
| cells ≤ 8 bits | 74 (46.2%) | **0** |
| min / median bits | 1 / 530 | **2041 / 2047** |

Design points:

- **SHAKE-256, not `Random(seed)`** — the leak recovers some `S[i][j]`, and a
  Mersenne Twister's state is recoverable from its output, which would expose
  `s` and every other cell.
- **`batch_index` mixed in**, so batches sharing a salt don't get identical grids.
- **`or 1`** — a zero cell would annihilate its column, not blind it.
- **Scope:** this *expands* entropy, it doesn't create it — the grid carries only
  as much unpredictability as `s` (~266 bits).

Verified `x` (which sizes `accH`/`accS`/`hm`) is derived identically to before.

---

## 14. `q` as the exponent in `S`'s `cell_product_mod`

**Request**

> the goal is to seal to the single combination values that get leaked using
> different modulus that verifier does not know. Can you pass q to the
> cell_product_mod for the S values construction?

Changed `S`'s exponent from `1` to `q`.

**Confirmed the goal was already structurally met:** `vs6.py` contains no
reference to `s_mod` or `s_list`, and `vs6`'s signature takes neither.
Demonstrated end-to-end with a fresh secret 1024-bit prime the verifier was
never told — verification succeeded, tampering still rejected.

Caveat recorded: the leak recovers `S[j]` in the `mod` ring without touching
`s_mod`, so secrecy of `s_mod` protects the step *behind* `S[j]` (unwinding it to
counts or salt), not `S[j]` itself.

---

## 15. Fresh secret `s_mod` per commit

**Request** — *yes, generate fresh screcret per commit, please*

`s_mod=None` is now the default and generates a fresh prime per commit.

**Size chosen from measurement**, not defaulted to 2048:

| bits | `generate_prime` cost |
|---|---|
| 256 | 0.01–0.02 s |
| **512 (chosen)** | **0.07–0.14 s** |
| 1024 | 0.55–0.61 s |
| 2048 | **3.98–18.06 s** |

**Deliberately not returned** — `s_mod` appears only in `_s0_grid` and the `S`
construction; `_ps6_batch` uses the H-side `mod`. So it's consumed at commit time
and never referenced again: no key to store, hand off, or leak.

Verified generated **once per commit, not per batch** (instrumented counter: 1
call across a 5-batch commit).

---

## 16. Design question — updatability

**Request** — *Can you please suggest how to implement the updatability of the commitment?*

Key insight: the pipeline is **count-based**, and only the counts depend on which
items are in the set —

```
items → accH/accS digit counts → cell_product_mod → row-seal → pack → tree fold → c
```

Four traps, each verified rather than asserted:

1. **Batches must stay uniformly `batch_size`.** `ps6`/`vs6` locate a batch with
   `index // batch_size` but derive local offsets from `len(hm_b)`. With lengths
   `[500, 1500, 1000]`, global index 600 maps to batch 1 but `600//1000 = 0`.
   ⇒ deletions must be tombstoned, appends must open new batches.
2. **Tombstones need `oset` support** (`oset = iset ^ set(range(len(hm)))`).
3. **Don't re-randomise the salt on update** — that changes `perm`, `S0`, `x`.
4. **Updates invalidate outstanding proofs** — `S` changes for the touched batch
   and `c` changes globally.

Staged: 1 append → 2 replace → 3 delete → 4 cache.

---

## 17. Stages 1 + 2 — append and replace

**Request** — *Yes, please implement the stage 1+2.*

Added a `Commitment` class **alongside** `ms6`/`ps6`/`vs6` — `opening()` returns
exactly `ms6()`'s tuple, so no existing call site changed.

Factored `_item_rows`, `_apply_rows`, `_seal_grid` out of `_ms6_batch` so the
commit and update paths are literally the same code. `_ms6_batch` now also
returns the counts and batch salt it used to discard.

**The load-bearing test:** an incrementally-updated commitment is
**bit-identical** to one built from scratch over the same final data (enabled by
a new `batch_salt` pin). Both stages pass.

Also verified: proofs work after updates, a **superseded value no longer proves**,
batch sizes stay uniform-except-last across boundary appends.

**Bug found and fixed (my own regression):** `_ms6_batch`'s `workers>1` branch
still passed a 4-tuple to `seal_row_mod` after entry 6 reduced it to 3 — a live
`ValueError`, hidden because `ms6` with `workers>1` parallelises *across* batches
and passes `workers=1` down.

Cost at 400 items / 8 batches: replace 59 ms vs full recommit 550 ms (**9.4×**).

---

## 18. Stage 4 — cache the seal tree

**Request** — *Please implement the stage 4 to cache the seal tree.*

`_SealTree` caches the fold. Two properties make it work:

1. The fold is a `seal_batch_size`-ary tree with **positional** grouping, so leaf
   `i` only feeds node `i // sbs`.
2. Every node is a **pure function of its own digit counts**, so a node refreshes
   by subtracting the old child's rows and adding the new one's — not by
   re-hashing its ≤1000 children.

Point 2 is why it pays off even *below* the threshold, where the tree is a single
root node.

Split `_seal_batch`'s flat fold into `_seal_chunker` / `_seal_rows` /
`_seal_from_counts`, shared with the tree. Output verified identical to
`vs6.py`'s independent copy at n = 1, 5, 50, 999, 1000, 1001, 2500.

| batches | replace | append | full recommit | speedup |
|---|---|---|---|---|
| 9 | 3.9 ms | 2.4 ms | 42 ms | 10.8× |
| 61 | 5.7 ms | 4.0 ms | 248 ms | 43.7× |
| 201 | 8.0 ms | 7.4 ms | 867 ms | **108×** |

Verified `root == _seal_batch(...)` across fan-outs 2/3/4 (trees to 6 levels),
every build size 1–29, every update position, every append boundary; plus the
`x`-change rebuild path, forced explicitly with pinned salts since it doesn't
arise in random runs.

---

## 19. Updatability verification under `__main__`

**Request** — *Can you please add the updatibility verificaiton for all three stages under the `__main__`?*

Nine PASS/FAIL checks, exiting 1 with a failure count so it works as a smoke test:

```
  [PASS] stage 1 append : incremental c == from-scratch c
  [PASS] stage 1 append : proof verifies for an appended item
  [PASS] stage 1 append : batches stay uniform except the last
  [PASS] stage 2 replace: incremental c == from-scratch c
  [PASS] stage 2 replace: proof verifies with the new value
  [PASS] stage 2 replace: superseded value no longer proves
  [PASS] stage 4 cache  : cached c == uncached _seal_batch
  [PASS] stage 4 cache  : root tracks _seal_batch over appends/updates
  [PASS] stage 4 cache  : rebuilds when a new batch changes x
```

Meta-tested that the checks actually discriminate — sabotaging `_apply_rows` or
corrupting a cached root is caught. Stage 3 (delete) gets an explicit `[note]`
line rather than being silently absent.

---

## 20. Seal `S` with `vsum_level_mod` instead of `pow`

**Request**

> Please replace the `pow(sv, d, mod)` with
> `ut.vsum_level_mod(d,mod,values=list(map(int,str(sv))))` and also apply this fix
> in the ps6 operation.

Both sites routed through one shared helper:

```python
def _blind(sv, d, mod):
    return ut.vsum_level_mod(d, mod, values=list(map(int, str(sv))))
```

- commit — `_seal_grid`: `H = [[(hv * _blind(sv, d, mod)) % mod …]]`
- open — `_ps6_batch`: `result.append([(row[j] * _blind(Srow[j], d, mod)) % mod …])`

A helper rather than the expression inline because these must compute the
identical function on the identical `S` — the check identity
`row[j] * M[j] == H[j]` only holds because the blinding cancels between sides.
Exactly the class of paired expression that has drifted here before.

Safe for correctness regardless of *what* `f` is, as long as both sides match:

```
H_full = cell_product(cnt_full, q)·f(S)
row    = cell_product(cnt_oset, q)·f(S)
M      = cell_product(cnt_iset, q)
row·M == H_full                       for any f
```

### Cost — the problem

**~145× more per call: 1.2 µs → 175 µs.** `S` is 512 bits ⇒ ~154 decimal digits,
so `vsum_level_mod` runs a degree-`d` DP over all of them instead of `pow`'s two
modular squarings — on `x·chunk_size` cells, on **both** sides.

| | before | after |
|---|---|---|
| replace (30 batches) | 1.6 ms | 8.4 ms |
| full recommit | 90 ms | 509 ms |

---

## 21. Revert entry 20

**Request**

> Please revert the changes. As I need to find better way to seal the values with
> `vsum_level_mod` rather than using pow's modular squaring.

Both sites back to `pow(sv, d, mod)`; `_blind` removed. Timings restored:
replace **1.6 ms**, full recommit **92 ms**.

**One piece deliberately kept:** a nearby comment read
`cell_product_mod(..., 1, ...)`, stale since entry 14 changed that exponent to
`q`. The correction had been made in the same commit as `_blind`, so only the
`pow` → `_blind` half was reverted.

### Carried forward — why the digit-fold was expensive

- At `DEFAULT_S_MOD_BITS = 512`, each `S` value is ~154 decimal digits.
- `vsum_level_mod` therefore ran a degree-`d` DP over 154 values **per cell**.
- It runs on `x·chunk_size` cells, on **both** the commit and open sides.

So a future attempt wants either:

1. a much smaller digit count — a smaller `s_mod`; or
2. a fold over something already short — chunked `S`, or the **row** rather than
   the **cell**.

Option 2 looks more promising: it changes the number of folds from
`x·chunk_size` to `x`, without weakening `S` itself.

---

# Verification run (end of Part B)

Last full run of `python3 ms6.py` on the `ds16/` tree, which exercises the
commit → open → verify demo and then the updatability checks from entry 19.

**Started:** 2026-08-08 15:45:59 IST
**Finished:** 2026-08-08 15:46:01 IST (~2 s wall clock)
**Exit code:** 0

```
opening...
verifying...

updatability
  [PASS] stage 1 append : incremental c == from-scratch c
  [PASS] stage 1 append : proof verifies for an appended item
  [PASS] stage 1 append : batches stay uniform except the last
  [PASS] stage 2 replace: incremental c == from-scratch c
  [PASS] stage 2 replace: proof verifies with the new value
  [PASS] stage 2 replace: superseded value no longer proves
  [PASS] stage 4 cache  : cached c == uncached _seal_batch
  [PASS] stage 4 cache  : root tracks _seal_batch over appends/updates
  [PASS] stage 4 cache  : rebuilds when a new batch changes x
  [info] 30 batches: replace 1.6 ms vs full recommit 91.3 ms (56x)
  [note] stage 3 delete: not implemented (needs tombstones)

all updatability checks passed
```

Note the `[info]` line is measured fresh on each run and moves around a little
between runs (56×–60× observed); the salt, and therefore `x`, is redrawn every
time.

---

# Part C — integration session (`ps4work/`, Cowork sandbox)

### Environment

| | |
|---|---|
| Platform | Linux sandbox (Cowork), independent from the Darwin machine used in Parts A–B |
| Working tree | `ps4work/` — `ms6.py`, `vs6.py`, `utils6.py`, `verifier_utils6.py`, plus two example applications: `zk_payroll_demo.py`, `zk_sanctions_screening_scale_demo.py` |

This part picks up the same `ms6`/`ps6`/`vs6` protocol as a set of file
uploads at various points — some already carrying Part B's S-side sealing
work (entries 12–14) or its `Commitment`/updatability design (entries 16–19)
— and covers platform fixes, an independent leak-diagnosis/revert cycle, a
second (distinct) `workers>1` bug, and finally wiring the finished
`Commitment` feature into two runnable example applications.

---

## 22. macOS "failed to SpawnProcess" fix

**Request** — *"The program failed to SpawnProcess on apple silicon."*

### Findings

Both example applications had multiprocessing-launching code sitting at
module top level, unguarded. macOS/Windows use the "spawn" start method,
which re-imports the entry script fresh in **every** worker process; without
`if __name__ == "__main__":`, top-level code that itself launches a process
pool re-runs inside each new worker, recursively spawning more pools.

### What changed

Wrapped all executable code in `zk_payroll_demo.py` and
`zk_sanctions_screening_scale_demo.py` in `def main(): ... / if __name__ ==
"__main__": main()`.

### Verified

Forced `multiprocessing.set_start_method('spawn', force=True)` in the (Linux)
sandbox and confirmed both demos still run clean end to end.

---

## 23. Pinpointing the root-extraction leak

**Request**

> Please pin point exact logic that causes the leak so I can work on fixes. Is
> the pow(p * v, q, mod) operation in the mul_combinations_mod causes the leak?
> Does the leak forge false commitment or false proof or does it reveal the
> value at some columns?

### Findings

`eval_level_mod`'s `idx = sum(p * c for p, c in runs)` bucketing (combinatorial
enumeration over `combinations_with_replacement`) creates singleton buckets at
logical columns `{0, 1, chunk_size-2, chunk_size-1}` per row — the only
combination mapping to that `idx`, so `ps[idx]` there is a raw, unblinded
value. Since the exponent and modulus are public, an eavesdropper can root-
extract it directly from `ps_list`, without ever running `vs6`.

**Two-query differencing attack**, confirmed by direct reproduction: query the
same commitment twice with claim sets differing by exactly one item
(`{i1}` then `{i1, i0}`), take the ratio of the two singleton `ps[idx=0]`
values — the shared blinding factor `S[j]` and the shared unclaimed-item
product cancel exactly, isolating one digit's contribution. A 9-way brute
force (digits are always 1–9) recovers it exactly.

### Answering the three-part question directly

- The leak is in `mul_combinations_mod`/`eval_level_mod`'s **structural
  bucketing**, not specifically the `pow(p*v, q, mod)` operation — that
  operation is just where the singleton value ends up exposed.
- It does **not** forge false commitments or proofs — `h == c` soundness was
  re-verified against the full 14-check adversarial suite at every stage of
  this investigation and held throughout.
- It **reveals unclaimed-item digit values at specific (leaky) columns** to a
  legitimate proof recipient — a hiding/confidentiality leak, not a binding
  break.

---

## 24. Leak-fix attempt, then revert

**Request** — *"kindly check if the leak is resolved now after adding the
fixes in the ms6.py"* → then *"Lets revert the fixes for the leak but keep the
recursive batch operation in the `_seal_batch` method in both the ms6.py and
vs6.py"*

### What happened

Tested an uploaded leak-fix candidate. First pass failed completeness
(`assert h == c`) — traced to testing against a stale, previously-cached
`vs6.py` rather than the correctly paired verifier from the same upload.
Prover/verifier files must be pulled and tested as a matched set, never mixed
across upload generations.

Once correctly paired, completeness passed, but the fix **regressed a
previously-passing adversarial check**: "hm[iset] tampered, claim TRUE val →
should still verify (no-op)" flipped from PASS to FAIL, because the redesigned
`_ps6_batch` started reading `hm[iset]`, which it had never touched before.

### What changed

Reverted `ms6.py`/`vs6.py` to the prior logic, per instruction — keeping only
the hierarchical/recursive `_seal_batch` fold (this doc's entry 4) in both
files.

---

## 25. Sealing the single combination values in a different modulus ring

**Request**

> To fix the root extraction leak is not the goal but the goal is to seal the
> single combination values that get leaked using different modulus ring that
> the verifier does not know. The code fixes are added to the ms6.py and
> vs6.py.

This corresponds to receiving Part B's S-side modulus-ring work (entries
12–14: a separate `s_mod` for `S`'s `cell_product_mod`, full-width SHAKE-256
blinding, `q` as `S`'s exponent) as an upload and integrating it.

Confirmed via `diff` that `vs6.py` contains no reference to `s_mod` or
`s_list` at all — the design goal (verifier never learns the ring `S` was
built in) was already structurally met by the uploaded code. Demonstrated
end-to-end with a fresh secret modulus the verifier was never told:
verification succeeded, tampering was still rejected.

**Caveat carried forward from entry 14:** the leak recovers `S[j]` itself
inside the public `mod` ring, without ever touching `s_mod` — so this protects
the step *behind* `S[j]` (unwinding it to counts or the salt), not `S[j]` as a
leaked value. Closing the leak at the source needs a modulus of unknown order
on the H side (see entry 27), not a secret ring on the S side.

---

## 26. `workers>1` bug in `vs6.py`'s `ProcessPoolExecutor` branch

**Request** — *"Please fix the workers>1 bug."*

### Findings

`_vs6_batch`'s parallel branch called:

```python
ex.map(ut.mul_combinations_mod, [d]*len(ps), [q]*len(ps), ps, M, [mod]*len(ps))
```

— 5 argument lists, against a function whose signature had already been
reduced to 4 params (`N, ps, vals, mod`) in the same upload that dropped `q`
from `mul_combinations_mod` (paired with this doc's entry 6). Only the
sequential branch (`H = [ut.mul_combinations_mod(d, ps[i], M[i], mod) for i in
range(len(ps))]`) had been updated to match — the parallel branch was never
touched. This is the same *class* of bug as entry 17's, in a different file:
a shared function's signature changed, and only one of its two call sites
(sequential vs. `ex.map`) was updated.

### What changed

Removed `[q] * len(ps),` from the `ex.map` call — one line.

### Verified

Reproduced the exact previously-broken case (single batch, `workers=4`) now
returning `ok=True`; the 25-config completeness sweep went from 15/25 to
25/25; the 14-check adversarial suite passed 14/14 at `workers=4`.

---

## 27. Researched: unknown-order modulus on the H side

**Request** — *"Please look for feasible solution for an unknown-order modulus
on the H side."*

Not implemented — a research/analysis pass, offered as a follow-up. Closing
the leak from entry 23 **at the source** (rather than just hardening what it
exposes) needs a modulus of *unknown order* — an RSA modulus or a class
group — not a bigger prime (this doc's entry 10 already showed a bigger prime
buys nothing here). Two options surfaced:

1. **An unfactored RSA-2048 challenge modulus** — swap `DEFAULT_MOD`; audited
   every honest-path arithmetic operation across `utils6.py`/
   `verifier_utils6.py` for hidden modular-inverse dependencies and found
   none, making this a config-level change rather than a rewrite.
2. **Class groups of imaginary quadratic discriminants** — no trusted setup
   needed at all, but ~6656-bit discriminants for 128-bit security, and
   NUCOMP/NUDUPL arithmetic not available in `gmpy2`.

**Flagged as actively risky if done wrong:** confirmed via research that if
the party generating an RSA-style modulus retains its factorization, they can
compute d-th roots for *any* value and forge membership/opening witnesses —
this construction is structurally an accumulator-style d-th-power witness
scheme, so a **prover-generated** secret modulus would let the prover forge
proofs outright, not just fail to fix a leak. Option 1 only works with a
modulus nobody — including the prover — has factored.

Offered to prototype option 1 (swap `DEFAULT_MOD`, re-verify completeness/
soundness, re-run the leak-extraction attack to confirm it no longer
recovers anything); **not yet taken up.**

---

## 28. Installing `Commitment`/updatability; wiring it into the example applications

**Request**

> I have upload 4 files to the project folder for implementing the commitment
> updatability so please update examples with the updatability test.

This installed the `ms6.py` described in this doc's entries 16–19
(`Commitment` class, `_SealTree`, append/replace, stages 1/2/4) into
`ps4work/`. Diffed the other 3 uploaded files (`utils6.py`,
`verifier_utils6.py`, `vs6.py`) against the working copies already in
place — byte-identical, confirming the feature is self-contained in
`ms6.py` and needed no verifier-side changes.

### Verified before touching anything downstream

- `ms6.py`'s own `__main__` (entry 19's 9-check updatability suite) passed
  as-is: 9/9.
- The existing regression suite — the 25-config completeness sweep and the
  14-check adversarial suite — both still passed at 25/25 and 14/14,
  confirming the base ms6/ps6/vs6 protocol was unaffected by the
  substantially rewritten file.

### What changed, beyond the file itself

Added an "updatability" section to each example application, using
`Commitment` in that application's own narrative rather than the generic
synthetic data `ms6.py`'s own test uses:

- **`zk_payroll_demo.py`** — HR onboards a new hire (`.append()`) and
  corrects an existing salary (`.replace()`), both ~1.3 ms with no other
  employee rehashed. The auditor confirms the new/corrected values verify
  through the unmodified `ps6`/`vs6` path, and that the superseded salary is
  rejected.
- **`zk_sanctions_screening_scale_demo.py`** — demonstrated on a separate
  5,000-record `Commitment` rather than editing the full 120,000-record
  registry in place, because `Commitment`'s own construction commits its
  batches **sequentially** (unlike `ms6()`'s `ProcessPoolExecutor`-parallel
  batch commit across many workers) — building one at full `N_RECORDS` would
  cost materially more wall-clock time without demonstrating anything the
  smaller slice doesn't, since an edit's cost is set by one batch's size, not
  by how many other batches exist. Append/replace cost 10.32 ms / 19.15 ms
  against a 1.149 s full recommit of the real 120,000-record registry.

### Verified

Both example applications run clean end-to-end (exit 0), with every check in
both files — correctness, soundness/tamper-rejection, and updatability —
passing.

---

# Current state (end of Part C)

`ps4work/` now holds the full protocol plus two runnable, narrated example
applications:

- **`ms6.py` / `vs6.py` / `utils6.py` / `verifier_utils6.py`** — commit/open/
  verify (`ms6`/`ps6`/`vs6`), the S-side modulus-ring sealing (entries 12–14),
  the recursive `_seal_batch` fold (entry 4), and the `Commitment` class with
  `.append()`/`.replace()` backed by a cached `_SealTree` (entries 16–19,
  28). Both platform-parallelism bugs found in this lineage (entries 17 and
  26) are fixed. Spawn-safety (entry 22) is in place for both example
  applications.
- **`zk_payroll_demo.py`** — commit/prove/verify over a 60-employee payroll,
  plus a live-edit (`Commitment`) section: onboard a new hire, correct a
  salary, confirm the superseded value is rejected.
- **`zk_sanctions_screening_scale_demo.py`** — commit/prove/verify at scale
  (120,000 records, 120 batches), 10 simulated bank requests benchmarked,
  3 soundness/tamper checks, plus a live-edit section on a 5,000-record
  `Commitment` comparing edit cost against a full recommit.

Everything above is empirically verified in this session: 25/25 completeness
configs, 14/14 adversarial checks, 9/9 updatability checks, and both example
applications running clean end-to-end.

---

# Part D — params dict, stage 3 (delete), modulus resize, and the ePrint paper

### Environment

Same Linux sandbox (Cowork) as Part C, continued in a later session.

---

## 29. Params dict API, delete via tombstones (stage 3), `DEFAULT_MOD` resize

**Request**

> The four updated files are now added to the project and added the
> implementation of the following open items: Return the parameters list
> from ms6, Commitment updatability delete via tombstones, DEFAULT_MOD
> sizing.

Received 4 uploaded files (`ms6.py`, `utils6.py`, `vs6.py`, and a
`verifier_utils.py` — misnamed, see below) implementing three of Part C's
open items at once.

### What changed

- **Params dict.** `ms6()`/`Commitment.opening()` now return a 7-tuple
  ending in `params` — `PARAM_KEYS = ("d","q","chunk_size","batch_size",
  "mod","seal_batch_size")`, built by `make_params()`. `ps6()`/`vs6()` take
  `params` instead of individual kwargs, with an `expect=` mechanism to pin
  and validate against out-of-band-agreed parameters (`ParamMismatch` on
  disagreement). Removes an entire class of silent commit/verify
  parameter-mismatch bugs — a proof and its verification can no longer
  disagree on `mod` or `d` without an explicit, loud rejection.
- **Stage 3 (delete), closing entry 16's design.** `Commitment.delete(index)`
  tombstones the slot — blanks `hm_list[b][local]`, blanks `vals[index]`,
  subtracts the item's digit contribution via the existing count-editing
  path, and adds `index` to a new `self.dead` set. Never spliced out (would
  shift every later index, breaking `index // batch_size`) and never reused
  by `append()`. `ps6`/`_ps6_batch` check `claimed_dead` and exclude dead
  slots from `oset`.
- **`DEFAULT_MOD` resized 2048 → 256 bits.** Closes entry 10's own finding:
  the modulus does a fingerprinting job (Schwartz–Zippel), not a
  discrete-log-hiding or root-extraction-hardness one, and 256 bits is the
  right size for that job at any size prime. `LEGACY_MOD_2048` keeps the old
  value available — a commitment built under it still verifies, since `mod`
  now travels in `params` rather than being read from the module default.

### Bugs caught while installing (diffed against the working copy first)

- **Reintroduced `vs6.py` `workers>1` bug** — the exact bug fixed in entry
  26, back again in this upload's `_vs6_batch`, apparently branched from
  before that fix landed. Fixed again, with an explanatory comment added
  in the code this time.
- **File misnamed on upload** — the fourth file was `verifier_utils.py`,
  missing the `6`, but both `vs6.py` and `ms6.py`'s own copy-parity tests
  import `verifier_utils6`. Diffed its contents against the existing
  `verifier_utils6.py`: the only difference was the same `DEFAULT_MOD`
  change present in `utils6.py`. Installed under the working name rather
  than introducing a second import path, and flagged the discrepancy
  rather than silently absorbing it.

### Verified

`ms6.py`'s own expanded `__main__` suite passed as installed. Both example
applications updated to the new params-dict API and to demonstrate
`delete()` (a departed employee, a cleared watchlist customer), and both
re-run clean end-to-end.

---

## 30. IACR ePrint-format spec paper

**Request** — *please draft a formal spec doc in the format acceptable by
IACR ePrint preprint.*

Followed a request for publication recommendations (discussed but not
requested as a written deliverable). Wrote `ms6_eprint.tex` — LaTeX article
class, no `algorithm`/`algorithmic` packages available in the sandbox's TeX
Live install, so pseudocode is `description`/`enumerate` + display math
instead. Contents: the full construction, Theorem 1 (completeness, proved),
a heuristic (not formally reduced) binding argument, the two-query
differencing attack as Attack 6.4/Theorem 6.5 with a full proof, a
mitigations-don't-work subsection explaining why sealing `S` (entries
12–14/25) doesn't close the leak, and 7 open problems — including the
unknown-order-modulus direction from entry 27.

One duplicate-`\label{}` collision (the "Opening" subsection and the "Open
problems" section both used `sec:open`) caught and fixed via two more
compile passes. Compiles clean: 0 warnings, 0 errors, 16 pages.

**Known stale spot, flagged and not yet updated:** still cites the old
2048-bit `DEFAULT_MOD` in its parameter table and a remark, since entry 29's
resize landed after the paper was drafted.

---

# Part E — data-driven `x`, an append/replace width guard, and parallel `Commitment` construction

### Request

> Now resolve the `Commitment`'s sequential batch construction, and the
> `x_list` run-to-run variation.

Both were Part C's own open items (below). Closing the second turned out to
be more than cosmetic — see entry 31.

---

## 31. Size `x` from actual item hash widths, not the salt

### The problem, restated precisely

`_ms6_batch` sized a batch's row count `x` from `len(str(s))` — the random
per-batch salt's own decimal digit length — not from anything about the
items actually being committed. Two consequences:

1. **Cosmetic:** the same `vals`, committed twice, could get a different
   `x_list` each time, purely because `s` is redrawn randomly per commit.
   Documented in Part C's open items as "easy to mistake for a bug."
2. **Not cosmetic:** `hash()`'s output length is not monotonic in input
   magnitude (confirmed by direct measurement — see below), so a batch could
   legitimately contain an item whose true hash needs *more* rows than that
   batch's particular salt draw happened to imply. `chunk_of` pads a
   *short* digest up to `x` but does not grow `x` for a *long* one, and
   `Acc.add`/`_apply_rows` only ever consult the first `x` rows — so an
   over-wide item's low-order (least-significant) hash digits would be
   silently dropped from the accumulator. A real loss of committed data,
   not just a display quirk.

### What changed

Split the old `_item_rows` into `_hash_item(val, s_exp)` (returns the raw
`h1s`/`h2s` digest strings) and a slimmed `_item_rows` that chunks/permutes
them — a pure, behavior-preserving refactor first, so nothing downstream
broke before the real change landed.

`_ms6_batch` now hashes every item up front, sizes `rows` from the widest
digest actually seen (`rows = max(1, ceil(widest / chunk_size))`), *then*
builds `S0`/`x`/`accH`/`accS`/`chunk_of` from that data-driven size, then
runs the accumulation loop reusing the already-computed hashes rather than
re-hashing. `x` is now a deterministic function of `vals` alone.

### Verified

Added two regression checks to `ms6.py`'s own `__main__`: committing the
same `vals` twice produces identical `x_list` both times (independent of
the random salt draw each commit still makes), confirmed PASS.

---

## 32. Guard `append()`/`replace()` against over-wide items

Entry 31's fix only covers a *new* batch, sized once from its own items at
construction time. `append()`/`replace()` edit an *existing* batch's counts
directly (`_apply_rows`), so the identical silent-truncation risk described
in entry 31 was still open on the incremental-update path.

### What changed

Added `Commitment._check_fits(b, val, hm1, hm2)`, called right after
hashing and before any count mutation in both `append()` and `replace()`:
if the incoming value's hash needs more rows than the batch's current `x`,
raise `ValueError` naming the batch and pointing at the fix (delete the old
slot and `append()` instead, which opens a correctly-sized new batch, or
rebuild the `Commitment` from scratch) rather than silently truncating.

### Caught its own regression test

The guard immediately tripped on 3 places in `ms6.py`'s own `__main__`
updatability suite, which replaced small-magnitude items with much larger
ones (`mk(555)`/`mk(666)`/`mk(777)`/`mk(999)`/`mk(4242)`) that legitimately
needed more rows than their target batch had — exactly the scenario the
guard exists to catch, not a false positive. Fixed the test data to use
same-magnitude-class replacements where the test's intent was "verify a
normal replace still works," and added a dedicated new check exercising
the guard's *rejection* path deliberately (`mk(777)` against a
small-magnitude batch, expecting `ValueError`).

### Verified

`ms6.py`'s own suite: 32/32 checks pass, including the new guard-rejection
check. The pre-existing 25-config completeness sweep and 14-check
adversarial suite (both exercise `ms6()`/`ps6()`/`vs6()` directly, not
`Commitment`) were unaffected, as expected — this fix is entirely inside
`Commitment`'s incremental-update path.

---

## 33. Parallelize `Commitment`'s initial multi-batch construction

Closes Part C's other open item: `Commitment.__init__` looped sequentially
over `_new_batch` regardless of `workers`, unlike `ms6()`'s own
across-batch `ProcessPoolExecutor` parallelism.

### What changed

Added `Commitment._new_batches_parallel(batch_groups)`, mirroring `ms6()`'s
pattern: every batch's salt is resolved **sequentially, up front** (not
inside worker calls) so the salt sequence — and therefore the resulting
commitment — doesn't depend on how the pool happens to schedule work; only
then are the batches dispatched to a `ProcessPoolExecutor`, each call using
`workers=1` (worker processes are daemonic and can't spawn their own
child pool, the same constraint `ms6()` already documents). `__init__` now
calls this path when `workers > 1` and there's more than one batch to
build, falling back to the existing sequential loop otherwise.
`append()`'s "open one new batch" path is untouched — nothing to
parallelize across a single batch.

### Verified

Added a regression check building the same data as two separate
`Commitment`s — one pinned to `workers=1`, one to `workers=4`, both with
pinned salts for reproducibility — and asserting `opening()` returns
bit-identical tuples. PASS.

---

## Full regression pass (Part E)

Run after entries 31–33 landed:

- `ms6.py`'s own `__main__`: **32/32 PASS** (28 pre-existing + 4 new: `x_list`
  determinism, the `_check_fits` rejection check, and the parallel-vs-
  sequential `Commitment` equivalence check folded into that count).
- `_scratch_batch_adversarial.py`: **14/14 PASS**.
- `_scratch_completeness_parallel.py`: **25/25 PASS**.
- `zk_payroll_demo.py`: clean end-to-end, all updatability checks (append/
  replace/delete) still ACCEPTED/REJECTED as expected.
- `zk_sanctions_screening_scale_demo.py`: clean end-to-end at the full
  120,000-record / 120-batch scale; commit **1.09 s**, replace **9.86 ms**
  (~110×), all soundness and updatability checks correct.

---

# Current state (end of Part E)

`ps4work/` now holds:

- **`ms6.py` / `vs6.py` / `utils6.py` / `verifier_utils6.py`** — everything
  from Part C, plus: the params-dict API (`make_params`/`unpack_params`/
  `ParamMismatch`/`expect=`), full three-stage `Commitment` updatability
  (append/replace/delete-via-tombstone) backed by the cached `_SealTree`,
  a 256-bit `DEFAULT_MOD` (with `LEGACY_MOD_2048` for backward
  compatibility), data-driven `x`-sizing (deterministic across commits of
  the same data, and no longer able to silently truncate an over-wide
  item), a width guard on `append()`/`replace()`, and batch-level-parallel
  initial construction for `Commitment` matching `ms6()`'s own.
- **`ms6_eprint.tex` / `ms6_eprint.pdf`** — the formal spec paper (entry 30),
  compiling clean at 16 pages. `DEFAULT_MOD` references now read 256-bit
  throughout (entry 34); the efficiency table's absolute timings are
  flagged in-text as measured under the prior 2048-bit modulus and not
  re-run at the smaller size. Byline is now Ayaz Mumtaz, no affiliation,
  no repository link.
- **`zk_payroll_demo.py`** / **`zk_sanctions_screening_scale_demo.py`** — both
  demonstrate the full commit/prove/verify flow plus all three updatability
  stages, narrated in-domain (HR payroll audit; sanctions-screening
  registry).

## 34. `vsum_level_fold_mod` swap + `ms6_eprint` byline/`DEFAULT_MOD` sync

**Request** — replace `ms6.py`'s remaining direct `vsum_level_mod` calls with
`vsum_level_fold_mod`; set the `ms6_eprint` byline to Ayaz Mumtaz (with
contact address) and no affiliation or repository link; close out any
already-resolved Open Items.

### What changed

- `ms6.py`'s two remaining direct `vsum_level_mod` call sites
  (`_seal_grid`'s sequential fallback and `_seal_from_counts`) now call
  `vsum_level_fold_mod(d, mod, H1, global_keys=True)` instead — the same
  swap `seal_row_mod` (the `ProcessPoolExecutor` path) already made.
  Bit-identical by construction (`vsum_level_fold_mod` is a thin wrapper
  documented as reproducing `vsum_level_mod`'s output exactly). The
  cross-file `vsum_level_mod`/`vsum_level_fold_mod` parity checks in
  `ms6.py`'s own `__main__` (comparing `utils6` against
  `verifier_utils6`) are untouched — they test something else entirely
  (the two files staying in sync), not this call-site choice.
- `ms6_eprint.tex`'s `\author` block now reads `Ayaz Mumtaz` with the
  contact address, no affiliation line, no repository placeholder.
- Closed the `DEFAULT_MOD` sync-pass item: the parameter table now reads
  256-bit; the efficiency section's "Default parameters" line is relabeled
  as the parameters *at the time of that measurement* (2048-bit, prior to
  the entry-29 resize) with an explicit note that the table hasn't been
  re-run at the current 256-bit default; and the root-extraction timing
  demo was re-measured against the actual current `DEFAULT_MOD` (256-bit):
  **0.1 ms** average over 200 trials, down from the previously-recorded
  39 ms at 2048-bit — reinforcing rather than weakening the paper's point,
  since a smaller modulus makes root extraction cheaper, not harder.

### Verified

- `ms6.py`'s own `__main__` suite: all checks PASS after the call-site
  swap (updatability, params, copy-parity, x-sizing, parallelism), no
  regressions.
- `ms6_eprint.tex` recompiles clean (pdflatex, 2 passes, 0 errors, 16
  pages).
- Root-extraction re-measurement done against the live `utils6.DEFAULT_MOD`
  (confirmed 256-bit, prime) in this session, not copied from memory.

---

## 35. Repository link, deletion section, and closing Open Problem 11.5 (Deletion)

**Request** — add the repository URL to `ms6_eprint`'s byline; write up
tombstone-based deletion as a real section (it's already implemented and
tested, entries in Part D/E's stage-3-delete suite), and remove the
now-stale "Open Problem (Deletion)" that asked for exactly that.

### What changed

- `ms6_eprint.tex`'s `\author` block gained a third line,
  `https://github.com/ms6-foundation/ms6`.
- Added `\subsection{Deletion}` (\S8.3) to the Updatability section,
  describing `Commitment.delete()`'s actual tombstoning mechanism (blank
  the slot, subtract its rows from the batch counts, never shift a later
  index) and why it's address-preserving rather than compacting. Added
  Proposition 8.2 (Deletion is exact, not compaction) with a proof sketch
  reusing the same additive-counts argument as Theorem 8.1, formalizing
  the `Commitment.delete()` docstring's own claim: `replace(i, X)` then
  `delete(i)` lands on the same commitment as `delete(i)` alone, but a
  tombstoned commitment is *not* bit-identical to a from-scratch commit
  over the survivors (batches don't compact). Listed the same empirical
  checks the stage-3-delete suite already covers (pre-delete proof
  rejected, survivors unaffected, replace-then-delete == delete, emptied
  batch still verifies, append lands past tombstones, double-delete/
  revive/range guarded).
- Removed the "Deletion" Open Problem (was 11.5, asking for exactly the
  section just added); remaining open problems renumbered automatically
  (11.1–11.7, was 11.1–11.8). Updated the Contributions paragraph and the
  Motivation subsection to mention deletion alongside append/replace.

### Verified

- Checked no other cross-reference in the document pointed at the removed
  `op:delete` label (none did — the one nearby "Open Problem 11.5" text
  reference is to cross-implementation equivalence, a different, unmoved
  label, unaffected by the removal).
- Recompiled clean: pdflatex, 2 passes, 0 errors, 0 undefined references,
  17 pages (was 16).

---

## 36. `DEFAULT_MOD` -> unknown-order composite (the RSA-2048 challenge number)

**Request** — "Please change the DEFAULT_MOD to unknown order prime in the
ms6 project." Takes up the follow-up offered but not taken in entry 27:
close the differencing-attack leak's root-extraction step at the source by
moving `DEFAULT_MOD` off a public prime (known order) onto a composite of
unknown order.

### What changed

- Asked the user two questions first: modulus size (chose 2048-bit, i.e.
  ~1024-bit factors, matching the old `LEGACY_MOD_2048`'s security level)
  and how to handle the secret factorization (chose: generate and discard,
  never write p/q to a file).
- First pass: generated a fresh 2048-bit `n = p*q` in-sandbox (1024-bit
  p, q, Miller-Rabin confirmed both ways, `n` confirmed composite),
  printed only `n`, never wrote `p`/`q` anywhere. Wired it into
  `utils6.DEFAULT_MOD` and `verifier_utils6.DEFAULT_MOD`.
- Before shipping that, re-read entry 27 (this doc) and caught that it had
  already flagged this exact approach as risky: whoever generates a fresh
  RSA-style modulus necessarily sees p and q during generation and could
  use that to forge witnesses outright, not just fail to fix the leak --
  a self-generated modulus is a self-issued trapdoor, and entry 27
  explicitly recommended an unfactored public challenge number instead.
- Replaced the self-generated `n` with the actual RSA-2048 Factoring
  Challenge modulus (RSA Laboratories, 1991 RSA Factoring Challenge; 617
  decimal digits, 2048 bits, unfactored since publication, and never
  demonstrably held by anyone including this project). Digits
  cross-checked against two independent sources before use; confirmed
  programmatically to be exactly 617 decimal digits, 2048 bits, and to
  fail Miller-Rabin (genuinely composite).
- Renamed the displaced 256-bit prime constant to `LEGACY_MOD_256_PRIME`
  (was `DEFAULT_MOD`) in both `utils6.py` and `verifier_utils6.py`, kept
  `LEGACY_MOD_2048` (the older public prime) as-is -- both retained only
  for verifying commitments made under prior defaults.
- Updated `ms6.py`'s modulus self-test: was asserting `DEFAULT_MOD.
  bit_length() == 256`; now asserts 2048 bits, composite (fails
  `is_prime`), and numerically identical between the `utils6`/
  `verifier_utils6` copies. Added a matching legacy-256-bit-prime
  still-verifies check alongside the existing legacy-2048-bit-prime one.

### Verified

- Audited `ms6.py`/`utils6.py`/`vs6.py`/`verifier_utils6.py` for any
  modular-inverse dependency on `DEFAULT_MOD` in the legitimate
  commit/prove/verify path (grepped for `inverse`/`modinv`/`pow(...,-1`) --
  none found; every honest-path operation is add/multiply mod n, so
  primality was never required for correctness.
- Full `ms6.py` `__main__` suite: all checks pass, including the two
  updated modulus checks and both legacy-modulus-still-verifies checks.
- `zk_payroll_demo.py` and `zk_sanctions_screening_scale_demo.py`: full
  end-to-end runs, all accept/reject outcomes correct, updatability
  (append/replace/delete) unaffected.
- Performance at 120,000 records reverted to roughly the old 2048-bit
  prime's cost, as expected (modexp cost tracks bit length, not
  primality): commit 1.24s, prove 0.76s avg, verify 0.09s avg -- versus
  0.99s / 64ms / 34ms at the (now legacy) 256-bit prime.
- Not done this turn: `ms6_eprint.tex` still describes the DEFAULT_MOD as
  the 256-bit prime throughout (Parameters table, Efficiency section,
  Remark on mod-not-hidden, the Open Problem this change addresses) --
  the paper's narrative is now stale relative to the code and needs its
  own pass if the user wants it reconciled.

---

## 37. Reconcile `ms6_eprint.tex` with the entry-36 `DEFAULT_MOD` change

**Request** — "Update the open items list in the paper and also update
the Efficiency section." Brings the paper's narrative back in step with
entry 36's code change.

### What changed

- Parameters table (\S3): `p`/`DEFAULT_MOD` row rewritten to describe the
  current RSA-2048 Factoring Challenge composite, noting the two prior
  defaults (256-bit prime, 2048-bit prime) as history.
- Remark on mod-not-hidden: reframed from "`p` is a public prime" (no
  longer true) to explaining why *any* prime lacks root-extraction
  hardness regardless of size, with a closing sentence pointing at the
  now-implemented fix.
- \S"Toward a fix": the closing "We have not implemented either
  option" replaced with a paragraph describing what was implemented (the
  RSA-2048 challenge modulus, chosen specifically to avoid the section's
  own "obvious wrong fix" trapdoor risk), what was verified (full
  regression suite, unchanged), and what was not (re-running the
  differencing attack itself against the new modulus, since that
  scratch script isn't part of the current file set) -- narrowing rather
  than closing the open problem.
- Related Work: one clause fix ("and currently missing" -> "and now
  uses"), since it directly contradicted the paragraph above.
- Open Problems (\S"Open problems"): `op:leak2` retitled "Verify the leak
  is closed" (was "Close the leak") and reworded from "implement and
  verify" to describing the implementation as done and narrowing the
  problem to the numerical re-verification step.
- Efficiency section: rewrote the intro paragraph, the main table (now
  "current 2048-bit unknown-order composite" vs "previous 256-bit prime,
  legacy" instead of "256-bit vs 2048-bit-prime legacy"), and the closing
  root-extraction-context paragraph. New numbers from a fresh
  `_bench_compare.py`-style run (same methodology, both moduli in one
  process, 120,000-record registry): commit 1.25s vs 1.04s, prove 768ms
  vs 64ms avg, verify 90ms vs 35ms avg, build 0.17s vs 0.13s, append
  11.3ms vs 9.8ms, replace 19.7ms vs 12.1ms (current vs previous). Ratios
  are the near-mirror image of entry 34's 2048-to-256-bit speedup, as
  expected -- modexp cost tracks bit length, not primality.
- Table width fix: the new table's r-columns had long headers ("Current
  (2048-bit, unknown order)" etc.) and overflowed the page the same way
  the original table did before its own column-width fix; shortened the
  headers and gave all four columns fixed `p{}` widths.

### Verified

- Digits of the RSA-2048 challenge number cross-checked against two
  independent sources (Wikipedia's "RSA numbers" article, a general web
  search) before use in entry 36; not re-verified here, only cited.
- Recompiled clean: pdflatex, 2 passes, 0 errors, 0 undefined references,
  18 pages (was 17). Remaining overfull-hbox warnings (4, at lines
  62-63/352-358/1067-1072/1095-1107) are pre-existing and unrelated to
  this turn's edits -- confirmed by diffing against the pre-edit warning
  list, same count, same locations modulo line-number drift.

### Still open

- The numerical re-verification itself (Open Problem `op:leak2` as
  narrowed): re-running the differencing attack's extraction against the
  new modulus to confirm it no longer recovers digits. The attack
  reproduction from entry 23 is not part of the current `ps4work/` file
  set.

---

# Open items

- **The root-extraction leak itself (entry 23) is now closed at the
  source, pending numerical re-verification (entries 27, 36, 37).**
  Entries 12–14/25 seal the *value* that leaks (`S[j]`) behind a modulus
  ring the verifier doesn't know; entry 36 additionally moved the H-side
  ring itself off a public prime (known order) onto the RSA-2048
  Factoring Challenge composite (unknown order), closing the
  root-extraction step the entry-23 differencing attack depends on.
  Structurally this should defeat the attack (root extraction needs a
  known group order, which this modulus does not have), but the
  entry-23 attack script has not been re-run against the new modulus to
  confirm numerically -- that re-run is the last open step, tracked as
  `ms6_eprint.tex`'s Open Problem "Verify the leak is closed."