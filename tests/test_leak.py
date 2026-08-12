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
harder (the RSA problem) if it isn't. What changed is WHAT lives at
columns 0 and chunk_size-1: _ms6_batch (see ms6.core's EDGE-COLUMN DECOY
PADDING comment) now reserves rand_edge_size columns at each row's edges
for digits derived via _edge_digits -- deterministic, but independent of
the item's real H1/H2 digest -- rather than real per-item content.
combined[0]/combined[L-1] are therefore junk by construction, not merely
expensive to read; a successful root extraction hands back a value with
no relationship to any registry item's actual data.

DEFAULT_MOD is a 256-bit prime, not an unknown-order composite -- root-
extraction hardness turned out not to be achievable via modulus choice
under this construction at any size (mod a prime the group order p-1 is
always public, so a d-th root is one pow() away; a composite makes it the
RSA problem, but that was never the thing actually standing between an
extraction and real data -- see DEFAULT_MOD's own comment in utils6.py).
The old RSA-2048 composite is kept as LEGACY_MOD_2048 for anyone who still
wants that redundant layer. This module checks the decoy property holds
regardless of which of the three moduli below is in play, and separately
confirms what changes and what doesn't as the modulus itself changes.

THREE ARMS, AND WHY ALL THREE ARE REQUIRED
-------------------------------------------
A single "we ran the attack and it failed [or succeeded]" result proves
nothing on its own. It is equally consistent with:

  1. the recovered value is decoy junk, by construction     <- the claim
  2. the attack code broke                                  <- a bug here
  3. parameters drifted so the attack no longer applies

So this module mounts the SAME attack three times in one run:

  ARM 1 -- DEFAULT_MOD itself (the shipped 256-bit prime). Its group order
      p-1 is public, so the d-th root is unique and computable as
      pow(y, d^-1 mod (p-1), p): extraction MUST SUCCEED here. Demonstrates
      the shipped default does not resist extraction -- and that this is
      fine, because what's recovered is still checked against the pure-
      decoy reconstruction (see _decoy_only_col0) below.

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
worth reading: `_decoy_only_col0` recomputes column 0's aggregate purely
from _edge_digits, with zero reference to any item's real digest content
beyond feeding it (as the deterministic derivation requires) into that
formula, and asserts it matches the real pipeline's own row[0] exactly,
under all three moduli. That equality -- not extraction difficulty -- is
the actual security property this module checks.
"""
import math

from tests.harness import (  # noqa: F401
    ms6, ps6, Commitment, vs6, ParamMismatch,
    make_params, unpack_params, PARAM_KEYS, VS6_PARAM_KEYS,
    _seal_batch, _SealTree, chunk_of, chunks, _column_perm,
    _permute_row, _get_batch_ids, DEFAULT_MOD, LEGACY_MOD_2048, ut, gen, u, M, V,
    ms6pkg, vs6pkg, D, Q, U_CS, U_BS, mk, proves, proves_with_expect,
    rebuilt, standalone,
)

CS, BS = 12, 20
SALT = 999983          # pinned so every arm is reproducible


def _decoy_only_col0(vals, hm, oset, r, red, mod, h1_salt=""):
    """Column 0's aggregate, recomputed purely from _edge_digits -- no
    reference to any item's real H1 content beyond passing it (as the
    deterministic decoy formula requires) into that function. If this
    matches the real pipeline's row[0], column 0 carries no information
    about the registry beyond what _edge_digits already publicly derives
    from each item's own digest string.

    h1_salt must be the SAME batch's h1_salt the real pipeline used --
    otherwise the recomputed h1s (and thus the edge digits derived from it)
    won't match, even though nothing about the decoy property actually
    changed."""
    histogram = {}
    for i in oset:
        h1s = ms6pkg.core._hash_item(vals[i], ms6pkg.core.DEFAULT_S_EXP, h1_salt)[0]
        edge = ms6pkg.core._edge_digits(h1s, r, red, ms6pkg.core.H_EDGE_TAG)
        front_n, _ = ms6pkg.core._front_back_edge_counts(red)
        d0 = edge[0] if front_n > 0 else None
        if d0 is not None:
            histogram[d0] = histogram.get(d0, 0) + 1
    val = 1
    for dch, ct in histogram.items():
        val = (val * pow(u.DIGIT_PRIMES[int(dch)], Q * ct, mod)) % mod
    return val


def _mount(mod, vals):
    """Commit under `mod`, then try to read the singleton bucket.

    Returns (bucket_holds_value, recovered_matches_truth, truth_is_decoy).
    """
    c, hl, xl, sl, hml, pl, h1sl, params = ms6(vals, D, Q, chunk_size=CS, batch_size=BS,
                                               mod=mod, s=SALT)
    iset = {3}
    ps_list = ps6(iset, hl, hml, sl, params)

    b, r = 0, 0
    S, hm = sl[b], hml[b]

    # ground truth: recompute what _ps6_batch computed for this row, from the
    # prover's own data. The attack is only meaningful measured against this.
    oset = {i for i in range(len(hm)) if i not in iset and hm[i] is not None}
    cnt = ut.col_digit_counts([hm[i][r] for i in oset], CS)
    row = [ut.cell_pow_product_mod(cnt[j], Q, mod) for j in range(CS)]
    combined = [(row[j] * pow(S[r][j], D, mod)) % mod for j in range(CS)]

    bucket0 = ps_list[b][r][0]
    holds = len(bucket0) == 1 and bucket0[0] == pow(combined[0], D, mod)

    # is the exposed quantity junk? row[0] (the H-side half of combined[0])
    # must equal the PURE-decoy reconstruction, with no other channel for
    # real item data to have entered it.
    truth_is_decoy = row[0] == _decoy_only_col0(vals, hm, oset, r, params["rand_edge_size"], mod,
                                                h1_salt=h1sl[b])

    # the attack: invert the exponent against the group order. Mod a prime
    # that order is p-1 and this is exact. Mod a composite, n-1 is NOT the
    # order, so the same move returns a wrong value -- the only correct route
    # would be phi(n), i.e. factoring.
    try:
        recovered = pow(bucket0[0], pow(D, -1, mod - 1), mod)
    except ValueError:
        recovered = None                      # no inverse at all
    return holds, recovered == combined[0], truth_is_decoy


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

    holds_1, recovered_1, decoy_1 = _mount(DEFAULT_MOD, vals)
    holds_2, recovered_2, decoy_2 = _mount(prime_mod, vals)
    holds_3, recovered_3, decoy_3 = _mount(LEGACY_MOD_2048, vals)

    # the bucket is structural: present under ALL THREE moduli. Asserting
    # this keeps the claim honest -- the SLOT was never removed, only what
    # fills it (and how hard it is to read) changed.
    check("leak          : singleton bucket holds combined[0]**d (shipped default)",
          holds_1)
    check("leak          : singleton bucket holds combined[0]**d (fresh prime)",
          holds_2)
    check("leak          : singleton bucket holds combined[0]**d (legacy composite)",
          holds_3)

    # the actual fix: what's in that slot is provably decoy, independent of
    # the modulus -- checked under all three so a regression here isn't
    # masked by which modulus happens to be default.
    check("leak          : column 0 is provably decoy, not real item data (shipped default)",
          decoy_1)
    check("leak          : column 0 is provably decoy, not real item data (fresh prime)",
          decoy_2)
    check("leak          : column 0 is provably decoy, not real item data (legacy composite)",
          decoy_3)

    # ARM 1 -- extraction against the shipped default succeeds: its group
    # order is public (it's prime), so there's an exponent to invert. Not a
    # red flag -- see the module docstring for why: what's recovered is
    # decoy either way, independently confirmed by decoy_1 above.
    check("leak ARM 1    : root extraction recovers the (junk) column under "
          "the shipped default prime modulus", recovered_1)

    # ARM 2 -- extraction succeeds against an unrelated modulus with known
    # group order too, as expected -- ARM 1 isn't a special case.
    check("leak ARM 2    : root extraction recovers the (junk) column under "
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
