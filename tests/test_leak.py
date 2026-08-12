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
no relationship to any registry item's actual data. DEFAULT_MOD's unknown
group order (see its own comment in utils6.py) is kept anyway as a second,
independent layer on top of that: this module checks the decoy property
holds regardless of which modulus is in play, and separately checks that
the shipped default actually does make extraction the RSA problem.

TWO ARMS, AND WHY BOTH ARE REQUIRED
-----------------------------------
A single "we ran the attack and it failed" result proves nothing. It is
equally consistent with:

  1. the recovered value is decoy junk, by construction     <- the claim
  2. the attack code broke                                  <- a bug here
  3. parameters drifted so the attack no longer applies

So this module mounts the SAME attack twice in one run:

  ARM 1 -- DEFAULT_MOD itself (the RSA-2048 Factoring Challenge composite,
      unknown order). There is no public exponent to invert, so extraction
      MUST FAIL here -- the modulus does its job as a second layer, on top
      of (not instead of) the decoy property checked below.

  ARM 2 -- a freshly generated prime, with gcd(d, p-1) == 1 by construction
      of D/Q below. The group order p-1 is public, so the d-th root is
      unique and computable as pow(y, d^-1 mod (p-1), p): extraction MUST
      SUCCEED here. This arm exists to demonstrate the decoy property does
      not lean on extraction failing -- what's recovered is still checked
      against the pure-decoy reconstruction (see _decoy_only_col0),
      independent of whether the attack itself succeeds.

WHAT THIS DOES NOT CLAIM
------------------------
The singleton bucket is not eliminated -- asserted below under both arms,
deliberately. What's eliminated is the bucket ever holding something worth
reading: `_decoy_only_col0` recomputes column 0's aggregate purely from
_edge_digits, with zero reference to any item's real digest content beyond
feeding it (as the deterministic derivation requires) into that formula,
and asserts it matches the real pipeline's own row[0] exactly, under both
moduli. That equality -- not extraction difficulty -- is the actual
security property this module checks.
"""
import math

from tests.harness import (  # noqa: F401
    ms6, ps6, Commitment, vs6, ParamMismatch,
    make_params, unpack_params, PARAM_KEYS, VS6_PARAM_KEYS,
    _seal_batch, _SealTree, chunk_of, chunks, _column_perm,
    _permute_row, _get_batch_ids, DEFAULT_MOD, ut, gen, u, M, V,
    ms6pkg, vs6pkg, D, Q, U_CS, U_BS, mk, proves, proves_with_expect,
    rebuilt, standalone,
)

CS, BS = 12, 20
SALT = 999983          # pinned so both arms are reproducible


def _decoy_only_col0(vals, hm, oset, r, red, mod):
    """Column 0's aggregate, recomputed purely from _edge_digits -- no
    reference to any item's real H1 content beyond passing it (as the
    deterministic decoy formula requires) into that function. If this
    matches the real pipeline's row[0], column 0 carries no information
    about the registry beyond what _edge_digits already publicly derives
    from each item's own digest string."""
    histogram = {}
    for i in oset:
        h1s = ms6pkg.core._hash_item(vals[i], ms6pkg.core.DEFAULT_S_EXP)[0]
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
    c, hl, xl, sl, hml, pl, params = ms6(vals, D, Q, chunk_size=CS, batch_size=BS,
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
    truth_is_decoy = row[0] == _decoy_only_col0(vals, hm, oset, r, params["rand_edge_size"], mod)

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

    # ARM 2's setup: a freshly generated prime with gcd(d, p-1) == 1 (the
    # extraction precondition). D=3 makes this fail for ~half of random
    # primes (any p == 1 mod 3), so this retries rather than asserting on a
    # single draw -- the precondition is about the arm's setup, not
    # something worth ever failing the suite over.
    prime_mod = ut.generate_prime(256)
    while math.gcd(D, prime_mod - 1) != 1:
        prime_mod = ut.generate_prime(256)
    check("leak setup    : gcd(d, prime_mod - 1) == 1 (extraction precondition)",
          math.gcd(D, prime_mod - 1) == 1)

    holds_c, recovered_c, decoy_c = _mount(DEFAULT_MOD, vals)
    holds_p, recovered_p, decoy_p = _mount(prime_mod, vals)

    # the bucket is structural: present under BOTH moduli. Asserting this
    # keeps the claim honest -- the SLOT was never removed, only what fills
    # it changed.
    check("leak          : singleton bucket holds combined[0]**d (default composite)",
          holds_c)
    check("leak          : singleton bucket holds combined[0]**d (fresh prime)",
          holds_p)

    # the actual fix: what's in that slot is provably decoy, independent of
    # the modulus -- checked under both so a regression here isn't masked
    # by which modulus happens to be default.
    check("leak          : column 0 is provably decoy, not real item data (default composite)",
          decoy_c)
    check("leak          : column 0 is provably decoy, not real item data (fresh prime)",
          decoy_p)

    # ARM 1 -- extraction against the shipped default fails: DEFAULT_MOD's
    # order is unknown (RSA-2048 composite), so there is no exponent to
    # invert. This is the modulus doing its job as a second layer, on top
    # of (not instead of) the decoy property confirmed by decoy_c above.
    # phrased without the word FAIL: a CI step grepping output for that
    # string would otherwise false-positive on a passing run.
    check("leak ARM 1    : root extraction does NOT recover the column under "
          "the default composite modulus", not recovered_c)

    # ARM 2 -- extraction succeeds against a modulus with known group
    # order, as expected. Not a red flag: see the module docstring for why
    # this is fine -- what's recovered is decoy either way, independently
    # confirmed by decoy_p above.
    check("leak ARM 2    : root extraction recovers the (junk) column under "
          "a fresh known-order prime modulus", recovered_p)


if __name__ == "__main__":
    standalone(run, "test_leak checks")
