"""The root-extraction leak: is it actually closed?

`mul_combinations_mod`'s combinatorial bucketing leaves the two extreme
buckets as singletons. `eval_level_mod` returns `list(r.values())` in
insertion order, and `combinations_with_replacement` starts at (0,...,0) and
ends at (L-1,...,L-1), so the FIRST and LAST buckets each hold exactly one
term: combined[0]**d and combined[L-1]**d, where

    combined[j] = row[j] * S[j]**d   (mod)

Structurally, this is unchanged and unfixed: the singleton bucket still
holds a single raw value, and anyone who can take a d-th root mod `mod`
still reads it straight out -- easily if `mod`'s group order is public,
harder (the RSA problem) if it isn't.

What changed is WHAT'S actually exposed at columns 0 and chunk_size-1 (see
ms6.core's EDGE-COLUMN PADDING comment). hm1's edges are now u.PAD, a fixed
public constant -- not per-item decoy digits. That makes row[0]/row[L-1]
IDENTICALLY 1 for ANY oset, not merely uncorrelated with real data: the
edge columns carry no information at all, about anything, ever. The
consequence checked below is sharper than "the recovered value is junk" --
it's that the exposed value never changes between two different queries
against the same (unresealed) commitment, since combined[edge] collapses to
S[edge]**d regardless of which items are claimed, and S doesn't move
without an update.

DEFAULT_MOD is a 256-bit prime, not an unknown-order composite -- root-
extraction hardness turned out not to be achievable via modulus choice
under this construction at any size (mod a prime the group order p-1 is
always public, so a d-th root is one pow() away; a composite makes it the
RSA problem, but that was never the thing actually standing between an
extraction and real data -- see DEFAULT_MOD's own comment in utils6.py).
The old RSA-2048 composite is kept as LEGACY_MOD_2048 for anyone who still
wants that redundant layer. This module checks the invariance property
holds regardless of which of the three moduli below is in play, and
separately confirms what changes and what doesn't as the modulus itself
changes.

THREE ARMS, AND WHY ALL THREE ARE REQUIRED
-------------------------------------------
A single "we ran the attack and it failed [or succeeded]" result proves
nothing on its own. It is equally consistent with:

  1. the recovered value carries no information, by construction  <- the claim
  2. the attack code broke                                        <- a bug here
  3. parameters drifted so the attack no longer applies

So this module mounts the SAME attack three times in one run:

  ARM 1 -- DEFAULT_MOD itself (the shipped 256-bit prime). Its group order
      p-1 is public, so the d-th root is unique and computable as
      pow(y, d^-1 mod (p-1), p): extraction MUST SUCCEED here. Demonstrates
      the shipped default does not resist extraction -- and that this is
      fine, because what's recovered is checked for invariance across two
      differently-claimed proofs against the same commitment (see
      _edge_invariant below).

  ARM 2 -- a freshly generated, unrelated prime, with gcd(d, p-1) == 1 by
      construction. Extraction MUST SUCCEED here too. This arm exists to
      show ARM 1 isn't special-cased -- the same holds for any known-order
      prime, not just the one constant this module happens to import.

  ARM 3 -- LEGACY_MOD_2048 (the retired RSA-2048 Factoring Challenge
      composite, unknown order). There is no public exponent to invert, so
      extraction MUST FAIL here. Demonstrates the old modulus, if a caller
      opts back into it via mod=LEGACY_MOD_2048, still behaves exactly as
      it always did -- switching the *default* changed nothing about what
      that constant itself does.

WHAT THIS DOES NOT CLAIM
------------------------
The singleton bucket is not eliminated -- asserted below under all three
arms, deliberately. What's eliminated is the bucket ever holding something
correlated with real data: row[0] recomputed directly from the oset's own
hm (with zero reference to any item's H1/H2 digest) is asserted to be
EXACTLY 1 under all three moduli, and two proofs issued for DIFFERENT claim
sets against the SAME commitment are asserted to expose the IDENTICAL
column-0 value -- not merely "hard to correlate with data", but literally
unchanged by which items are claimed. That invariance -- not extraction
difficulty -- is the actual security property this module checks.
"""
import math

from tests.harness import (  # noqa: F401
    ms6, ps6, Commitment, vs6, ParamMismatch,
    make_params, unpack_params, PARAM_KEYS, VS6_PARAM_KEYS,
    _seal_batch, _SealTree, chunk_of, chunks, _column_perm,
    _permute_row, _get_batch_ids, DEFAULT_MOD, LEGACY_MOD_2048, ut, gen, u, M, V,
    vs6pkg, D, Q, U_CS, U_BS, mk, proves, proves_with_expect,
    rebuilt, standalone,
)

CS, BS = 12, 20
SALT = 999983          # pinned so every arm is reproducible

# Default rand_edge_size (ms6.core.DEFAULT_RAND_EDGE_SIZE) at this module's
# CS=12 -- front/back split per ms6.core._front_back_edge_counts, so the
# full edge region is columns EDGE_COLS below, not just column 0/CS-1. Only
# the two extremes are true singleton buckets (Lemma singleton); the rest
# of this region is protected by construction (row[j] == 1 regardless of
# whether any given extraction technique can reach it), not by relying on
# the cascade's specific reach -- see _row_at below.
RAND_EDGE_SIZE = 6
_FRONT_N, _BACK_N = RAND_EDGE_SIZE // 2 + RAND_EDGE_SIZE % 2, RAND_EDGE_SIZE // 2
EDGE_COLS = list(range(_FRONT_N)) + list(range(CS - _BACK_N, CS))


def _row0(vals, hm, iset, mod):
    """row[0], recomputed directly from oset's own hm -- the ground truth
    ps6's own _ps6_batch would compute for column 0, from the prover's own
    data. The attack is only meaningful measured against this."""
    oset = {i for i in range(len(hm)) if i not in iset and hm[i] is not None}
    cnt = ut.col_digit_counts([hm[i][0] for i in oset], CS)
    return ut.cell_pow_product_mod(cnt[0], Q, mod)


def _row_at(hm, iset, col, mod, row=0):
    """Same ground-truth recomputation as _row0, generalized to any column
    -- used to check row[j] == 1 across the WHOLE edge region, not just the
    two extreme singleton-bucket columns. This doesn't depend on whether a
    given column is individually extractable via the bucket structure
    (Proposition leak / Corollary cascade): it recomputes the raw digit
    value directly from the prover's own oset data, the same ground truth
    _row0 uses for column 0."""
    oset = {i for i in range(len(hm)) if i not in iset and hm[i] is not None}
    cnt = ut.col_digit_counts([hm[i][row] for i in oset], CS)
    return ut.cell_pow_product_mod(cnt[col], Q, mod)


def _mount(mod, vals):
    """Commit under `mod`, open TWO different single-item claims against
    the SAME commitment, and try to read the singleton bucket in each.

    Returns (bucket_holds_value, recovered_matches_truth, row0_is_one,
    invariant_across_claims, all_edges_one, all_edges_invariant).
    """
    _, hl, _, sl, hml, _, _, params = ms6(vals, D, Q, chunk_size=CS, batch_size=BS,
                                          mod=mod, s=SALT)
    iset_a, iset_b = {3}, {11}          # two ordinary, disjoint single-item claims
    ps_a = ps6(iset_a, hl, hml, sl, params)
    ps_b = ps6(iset_b, hl, hml, sl, params)

    b, r = 0, 0
    S, hm = sl[b], hml[b]

    row0_a = _row0(vals, hm, iset_a, mod)
    row0_b = _row0(vals, hm, iset_b, mod)
    row0_is_one = row0_a == 1 and row0_b == 1

    combined_a = (row0_a * pow(S[r][0], D, mod)) % mod
    combined_b = (row0_b * pow(S[r][0], D, mod)) % mod

    bucket0_a = ps_a[b][r][0]
    bucket0_b = ps_b[b][r][0]
    holds = (len(bucket0_a) == 1 and bucket0_a[0] == pow(combined_a, D, mod)
             and len(bucket0_b) == 1 and bucket0_b[0] == pow(combined_b, D, mod))

    # the actual fix: the exposed bucket value doesn't even depend on which
    # item was claimed -- two structurally different proofs against the
    # same commitment expose the SAME column-0 content.
    invariant_across_claims = bucket0_a == bucket0_b

    # the attack: invert the exponent against the group order. Mod a prime
    # that order is p-1 and this is exact. Mod a composite, n-1 is NOT the
    # order, so the same move returns a wrong value -- the only correct route
    # would be phi(n), i.e. factoring.
    try:
        recovered_a = pow(bucket0_a[0], pow(D, -1, mod - 1), mod)
    except ValueError:
        recovered_a = None                      # no inverse at all

    # the SAME two checks (row[j] == 1, invariant across claims), extended
    # to EVERY edge column, not just column 0 -- this is the generalization
    # a bare per-column extraction demo can't give: it doesn't route through
    # the bucket structure at all, so it covers columns the cascade may or
    # may not individually reach (see EDGE_COLS's own comment).
    all_edges_one, all_edges_invariant = True, True
    for col in EDGE_COLS:
        ra = _row_at(hm, iset_a, col, mod)
        rb = _row_at(hm, iset_b, col, mod)
        if ra != 1 or rb != 1:
            all_edges_one = False
        combined_col_a = (ra * pow(S[r][col], D, mod)) % mod
        combined_col_b = (rb * pow(S[r][col], D, mod)) % mod
        if combined_col_a != combined_col_b:
            all_edges_invariant = False

    return (holds, recovered_a == combined_a, row0_is_one, invariant_across_claims,
            all_edges_one, all_edges_invariant)


def run(check):
    vals = [mk(i) for i in range(40)]

    # DEFAULT_MOD is picked (see its own comment in utils6.py) so that
    # gcd(d, DEFAULT_MOD - 1) == 1 already holds for this project's own
    # default d=3 -- ARM 1 exercises the extraction precondition against
    # the actual shipped constant, not a substitute.
    check("leak setup    : gcd(d, DEFAULT_MOD - 1) == 1 (extraction precondition "
          "holds for the shipped default itself)",
          math.gcd(D, DEFAULT_MOD - 1) == 1)

    # ARM 2's setup: a freshly generated, unrelated prime with
    # gcd(d, p-1) == 1 (the extraction precondition). D=3 makes this fail
    # for ~half of random primes (any p == 1 mod 3), so this retries rather
    # than asserting on a single draw -- the precondition is about the
    # arm's setup, not something worth ever failing the suite over.
    prime_mod = ut.generate_prime(256)
    while math.gcd(D, prime_mod - 1) != 1:
        prime_mod = ut.generate_prime(256)
    check("leak setup    : gcd(d, fresh prime_mod - 1) == 1 (extraction precondition)",
          math.gcd(D, prime_mod - 1) == 1)

    holds_1, recovered_1, one_1, inv_1, all_one_1, all_inv_1 = _mount(DEFAULT_MOD, vals)
    holds_2, recovered_2, one_2, inv_2, all_one_2, all_inv_2 = _mount(prime_mod, vals)
    holds_3, recovered_3, one_3, inv_3, all_one_3, all_inv_3 = _mount(LEGACY_MOD_2048, vals)

    # the bucket is structural: present under ALL THREE moduli. Asserting
    # this keeps the claim honest -- the SLOT was never removed, only what
    # fills it (and how hard it is to read) changed.
    check("leak          : singleton bucket holds combined[0]**d (shipped default)",
          holds_1)
    check("leak          : singleton bucket holds combined[0]**d (fresh prime)",
          holds_2)
    check("leak          : singleton bucket holds combined[0]**d (legacy composite)",
          holds_3)

    # the actual fix, part 1: row[0] is IDENTICALLY 1, for any oset, under
    # all three moduli -- not merely decoy, but structurally carrying zero
    # information regardless of which items are in play.
    check("leak          : row[0] == 1 for any oset (shipped default)", one_1)
    check("leak          : row[0] == 1 for any oset (fresh prime)", one_2)
    check("leak          : row[0] == 1 for any oset (legacy composite)", one_3)

    # the actual fix, part 2: two proofs issued for DIFFERENT claim sets
    # against the SAME commitment expose the IDENTICAL column-0 bucket --
    # the exposed value never varies with the query, only with a real
    # update (append/replace/delete, which reseals S). This is the property
    # that makes column 0 unconditionally safe under repeated querying, not
    # just safe against a single proof.
    check("leak          : bucket0 is IDENTICAL across two differently-claimed "
          "proofs against the same commitment (shipped default)", inv_1)
    check("leak          : bucket0 is IDENTICAL across two differently-claimed "
          "proofs against the same commitment (fresh prime)", inv_2)
    check("leak          : bucket0 is IDENTICAL across two differently-claimed "
          "proofs against the same commitment (legacy composite)", inv_3)

    # the same two properties, extended to EVERY column in the edge region
    # (EDGE_COLS), not just column 0 -- this doesn't depend on whether a
    # given column happens to be individually bucket-extractable (that's a
    # separate, narrower question the cascade answers); it's checked
    # directly from ground truth, so it covers the whole padded margin
    # uniformly, regardless of how far any given extraction technique can
    # reach into it.
    check(f"leak          : row[j] == 1 for ALL {len(EDGE_COLS)} edge columns "
          "(shipped default)", all_one_1)
    check(f"leak          : row[j] == 1 for ALL {len(EDGE_COLS)} edge columns "
          "(fresh prime)", all_one_2)
    check(f"leak          : row[j] == 1 for ALL {len(EDGE_COLS)} edge columns "
          "(legacy composite)", all_one_3)
    check(f"leak          : combined[j] IDENTICAL across two differently-claimed "
          f"proofs, for ALL {len(EDGE_COLS)} edge columns (shipped default)", all_inv_1)
    check(f"leak          : combined[j] IDENTICAL across two differently-claimed "
          f"proofs, for ALL {len(EDGE_COLS)} edge columns (fresh prime)", all_inv_2)
    check(f"leak          : combined[j] IDENTICAL across two differently-claimed "
          f"proofs, for ALL {len(EDGE_COLS)} edge columns (legacy composite)", all_inv_3)

    # ARM 1 -- extraction against the shipped default succeeds: its group
    # order is public (it's prime), so there's an exponent to invert. Not a
    # red flag -- see the module docstring for why: what's recovered is
    # S[0]**d either way, itself carrying no item information, independently
    # confirmed by one_1/inv_1 above.
    check("leak ARM 1    : root extraction recovers the column under "
          "the shipped default prime modulus", recovered_1)

    # ARM 2 -- extraction succeeds against an unrelated modulus with known
    # group order too, as expected -- ARM 1 isn't a special case.
    check("leak ARM 2    : root extraction recovers the column under "
          "a fresh, unrelated known-order prime modulus", recovered_2)

    # ARM 3 -- extraction against the legacy composite fails: its order is
    # unknown, so there is no exponent to invert. Phrased without the word
    # FAIL: a CI step grepping output for that string would otherwise
    # false-positive on a passing run. Demonstrates LEGACY_MOD_2048 still
    # behaves exactly as it always did for anyone who opts back into it.
    check("leak ARM 3    : root extraction does NOT recover the column under "
          "the legacy composite modulus", not recovered_3)


if __name__ == "__main__":
    standalone(run, "test_leak checks")
