"""The root-extraction leak: is it actually closed by the modulus?

`mul_combinations_mod`'s combinatorial bucketing leaves the two extreme
buckets as singletons. `eval_level_mod` returns `list(r.values())` in
insertion order, and `combinations_with_replacement` starts at (0,...,0) and
ends at (L-1,...,L-1), so the FIRST and LAST buckets each hold exactly one
term: combined[0]**d and combined[L-1]**d, where

    combined[j] = row[j] * S[j]**d   (mod)

is a real per-column value of the prover's data. Anyone who can take a d-th
root mod `mod` reads it straight out.

TWO ARMS, AND WHY BOTH ARE REQUIRED
-----------------------------------
A single "we ran the attack and it failed" result proves nothing. It is
equally consistent with:

  1. the modulus closed the leak                     <- the claim
  2. the attack code broke                           <- a bug in this file
  3. parameters drifted so the attack no longer applies

So this module mounts the SAME attack twice in one run:

  ARM 1 (positive control) -- a prime modulus with gcd(d, p-1) == 1. The
      group order p-1 is public, so the d-th root is unique and computable
      as pow(y, d^-1 mod (p-1), p). This MUST SUCCEED. If it fails, the
      attack harness is broken and arm 2 proves nothing -- read a failure
      here as "this test is broken", NOT as "the system is secure".

  ARM 2 -- the shipped DEFAULT_MOD, the RSA-2048 composite. phi(n) is
      unknown, so there is no exponent to invert and extracting the root is
      the RSA problem. This MUST FAIL.

Only the difference between the two arms is evidence, because only the
modulus differs between them.

WHAT THIS DOES NOT CLAIM
------------------------
The leak is not eliminated. The singleton buckets still hold the values --
asserted below under both moduli, deliberately. What changed is the cost of
reading them: a modular exponentiation before, factoring a 2048-bit
composite now. That rests on RSA-2048's factors being unknown, which is a
trust assumption in RSA Security's word, not a proof.

The lasting value here is the reverse direction: if anyone ever puts a
known-order modulus back into DEFAULT_MOD, arm 2 starts succeeding and this
fails loudly, instead of the leak silently reopening.
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


def _mount(mod):
    """Commit under `mod`, then try to read a real column value out of the
    singleton bucket.

    Returns (bucket_holds_value, recovered_matches_truth).
    """
    vals = [mk(i) for i in range(40)]
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

    # the attack: invert the exponent against the group order. Mod a prime
    # that order is p-1 and this is exact. Mod a composite, n-1 is NOT the
    # order, so the same move returns a wrong value -- the only correct route
    # would be phi(n), i.e. factoring.
    try:
        recovered = pow(bucket0[0], pow(D, -1, mod - 1), mod)
    except ValueError:
        recovered = None                      # no inverse at all
    return holds, recovered == combined[0]


def run(check):
    # a prime where the d-th root is unique
    while True:
        prime_mod = ut.generate_prime(256)
        if math.gcd(D, prime_mod - 1) == 1:
            break

    holds_p, recovered_p = _mount(prime_mod)
    holds_n, recovered_n = _mount(DEFAULT_MOD)

    # the buckets are structural: present under BOTH moduli. Asserting this
    # keeps the claim honest -- the value was never removed, only made
    # expensive to read.
    check("leak          : singleton bucket holds combined[0]**d (prime modulus)",
          holds_p)
    check("leak          : singleton bucket holds combined[0]**d (RSA-2048)",
          holds_n)

    # ARM 1 -- positive control. A failure here means THIS FILE is broken,
    # not that the system is secure; arm 2 is uninterpretable without it.
    check("leak ARM 1    : root extraction RECOVERS the column under a prime "
          "(positive control -- a red here means this test is broken, not that "
          "the system is secure)", recovered_p)

    # ARM 2 -- the actual claim.
    # phrased without the word FAIL: a CI step grepping output for that
    # string would otherwise false-positive on a passing run
    check("leak ARM 2    : root extraction does NOT recover the column under "
          "the unknown-order default", not recovered_n)

    # and the two arms must genuinely differ, or the comparison is vacuous
    check("leak          : the two arms differ (only the modulus changed)",
          recovered_p and not recovered_n)


if __name__ == "__main__":
    standalone(run, "test_leak checks")
