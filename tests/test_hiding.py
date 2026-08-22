"""Single-proof hiding: does a disclosed proof depend on the oset's own values?

_ps6_batch computes, per row r and column j,

    combined[r][j] = row[j] * S[r][j]**d   (mod)

where row[j] = cell_pow_product_mod(cnt[j], q, mod) is a PUBLIC, deterministic
function of the oset's own digit counts at that column (see test_leak.py's own
module docstring for the identical formula, there called "combined"). The
entire disclosed proof (`eval_row_grouped`'s sweep, for every row) is a
deterministic function of nothing but this `combined` array plus public
(d, mod, partition) -- so hiding of the oset's content reduces entirely to
one question: does `combined`'s distribution depend on `row`, i.e. on which
items are actually in oset?

THE LEMMA
---------
Fix any nonzero row[j] (mod a prime `mod`) and any degree d with
gcd(d, mod-1) == 1 -- the same coprimality precondition ms6_vibe.md entry 78
enforces for binding. Two facts compose:

  1. x -> pow(x, d, mod) is a BIJECTION on Z_mod* (entry 78's own lemma).
  2. x -> row[j] * x (mod mod) is a BIJECTION on Z_mod* for ANY fixed nonzero
     row[j] (group translation).

So x -> row[j] * pow(x, d, mod) % mod is a bijection on Z_mod*, for EVERY
possible row[j]. If S[r][j] is drawn uniformly over Z_mod* (computationally,
via _s0_grid's SHAKE-256 expansion -- a PRG/random-oracle-style assumption on
SHAKE-256, the same caliber assumption binding already rests on for SHAKE128),
then combined[r][j] = row[j] * S[r][j]**d is ALSO uniform over Z_mod*,
IDENTICALLY so regardless of what row[j] was. Applied per column
(independent S draws per cell, per _s0_grid's own docstring) and per row, the
WHOLE combined array -- and therefore the whole disclosed proof, being a pure
function of it -- has a distribution that does not depend on oset's content
at all. That is single-proof hiding, stated precisely rather than left as
"S(r,j) still blinds it."

WHAT THIS DOES NOT CLOSE
------------------------
This is a per-proof argument: it holds S fixed and shows the disclosure
carries no information about oset given that ONE draw of S. It says nothing
about TWO proofs compared against the same commitment under the SAME S --
that is exactly where the ratio-cancellation attack (obs:ratio,
QueryGovernor's own reason for existing) lives, and this module does not
touch it. Nor does it cover claimed items' own values, which are meant to be
revealed, not hidden.

TWO CHECKS, MIRRORING test_leak.py's OWN DISCIPLINE
-----------------------------------------------------
A single "it looks random" run proves nothing (same reasoning test_leak.py's
own docstring gives for its three arms). So this module checks the lemma two
ways:

  1. EXACT, brute-forced bijection at small primes, for several (p, d, row[j])
     combinations -- proves the algebra, not just this construction's own
     numbers. A negative control (d NOT coprime to p-1) confirms the same
     check would actually catch a violation.
  2. The SAME map, at the shipped DEFAULT_MOD and D, using a REAL row[j]
     computed by the real pipeline's own col_digit_counts/cell_pow_product_mod
     from a real batch's real oset -- confirms invertibility holds for actual
     pipeline output, not just abstract algebra, at full 256-bit scale where
     brute-forcing every element isn't possible.

No statistical/distributional sampling check is included deliberately: an
exact bijection proof is strictly stronger evidence than a statistical
closeness test, and a sampling-based check would only add flakiness risk for
no added rigor.
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


def _is_bijection(row_const, d, p):
    """Brute-force: does x -> row_const * pow(x, d, p) % p hit every element
    of {1, .., p-1} exactly once as x ranges over the same set?"""
    seen = set()
    for x in range(1, p):
        y = (row_const * pow(x, d, p)) % p
        if y in seen or y == 0:
            return False
        seen.add(y)
    return seen == set(range(1, p))


def run(check):
    d, q, u_cs, u_bs = D, Q, U_CS, U_BS

    # --- 1. exact bijection lemma at small, brute-forceable primes --------
    small_primes = [101, 211, 1009]  # small enough to enumerate every element
    row_consts = [1, 2, 3, 17, 97]

    all_bijective = True
    for p in small_primes:
        # d values coprime to p-1, including D itself when it happens to fit.
        coprime_ds = [dd for dd in (1, 3, 5, 7, 9, 11) if math.gcd(dd, p - 1) == 1]
        for dd in coprime_ds:
            for c in row_consts:
                c_mod = c % p
                if c_mod == 0:
                    continue
                if not _is_bijection(c_mod, dd, p):
                    all_bijective = False
    check("hiding lemma  : x -> row_const * pow(x, d, p) % p is an exact "
          "bijection on Z_p* for every (p, d, row_const) tried, whenever "
          "gcd(d, p-1) == 1",
          all_bijective)

    # Negative control: d NOT coprime to p-1 must break injectivity -- proves
    # the check above isn't vacuously true for every d.
    p = small_primes[0]
    non_coprime_ds = [dd for dd in range(2, 20) if math.gcd(dd, p - 1) != 1]
    check("hiding lemma  : negative control -- d not coprime to p-1 breaks "
          "the bijection (confirms the positive check isn't vacuous)",
          len(non_coprime_ds) > 0
          and not _is_bijection(1, non_coprime_ds[0], p))

    # --- 2. the same map, at the shipped default, on REAL pipeline values -
    # Build a real batch, open several different claim sets against it so
    # row[j] (the oset's own combinatorial value) genuinely varies, and
    # confirm combined[r][j] = row[j] * S[r][j]**d is invertible back to the
    # real S[r][j] every time -- using the actual col_digit_counts/
    # cell_pow_product_mod the live pipeline uses, not a synthetic row_const.
    check("hiding lemma  : gcd(D, DEFAULT_MOD - 1) == 1 (precondition, "
          "already enforced and tested in test_modulus.py -- restated here "
          "as this module's own precondition)",
          math.gcd(d, DEFAULT_MOD - 1) == 1)

    # s_mod left at its default (DEFAULT_S_MOD == DEFAULT_MOD): the lemma
    # needs S drawn in the SAME ring the H-side pow(S, d, mod) operates in
    # -- true by default (Commitment.s_mod defaults to sharing DEFAULT_MOD,
    # see DEFAULT_S_MOD's own comment in ms6/core.py), but an explicit,
    # DIFFERENT s_mod (as e.g. test_modulus.py deliberately uses to probe
    # an unrelated ring) would reduce S into a different modulus before
    # pow(S, d, mod) treats it as a base mod `mod` -- outside this lemma's
    # scope, not a counterexample to it.
    base = [mk(i) for i in range(u_bs)]  # one full batch
    C = Commitment(base, d, q, chunk_size=u_cs, batch_size=u_bs)
    assert C.s_mod == DEFAULT_MOD, "test precondition: S's ring must match mod"
    _, _, x_list, s_list, hm_list, _, _, _ = C.opening()
    hm_b, S_b, rows = hm_list[0], s_list[0], len(s_list[0])
    d_inv = pow(d, -1, DEFAULT_MOD - 1)  # exists: gcd(d, mod-1) == 1

    claim_sets = [set(), {0}, {0, 1}, set(range(len(hm_b) - 1))]
    no_zero_row = True
    all_invertible = True
    checked_nonconstant_row = False
    first_row_val = None
    for iset_b in claim_sets:
        oset = [i for i in range(len(hm_b)) if i not in iset_b]
        for r in range(rows):
            row_strings = [hm_b[i][r] for i in oset]
            cnt = ut.col_digit_counts(row_strings, u_cs)
            for j in range(u_cs):
                row_j = ut.cell_pow_product_mod(cnt[j], q, DEFAULT_MOD)
                if row_j == 0:
                    no_zero_row = False
                    continue
                if first_row_val is None:
                    first_row_val = row_j
                elif row_j != first_row_val:
                    checked_nonconstant_row = True
                S_rj = S_b[r][j]
                combined = (row_j * pow(S_rj, d, DEFAULT_MOD)) % DEFAULT_MOD
                recovered = pow(
                    (combined * pow(row_j, -1, DEFAULT_MOD)) % DEFAULT_MOD,
                    d_inv, DEFAULT_MOD)
                if recovered != S_rj % DEFAULT_MOD:
                    all_invertible = False

    check("hiding lemma  : real row[j] values (varied across several claim "
          "sets) are never 0 mod DEFAULT_MOD",
          no_zero_row)
    check("hiding lemma  : combined[r][j] = row[j] * S[r][j]**d is "
          "invertible back to the real S[r][j], for real pipeline row[j] "
          "values at full DEFAULT_MOD scale, across varied claim sets/rows/"
          "columns",
          all_invertible)
    check("hiding lemma  : row[j] actually varied across the claim sets "
          "tried (confirms this check exercised more than one constant "
          "row[j], not a degenerate case)",
          checked_nonconstant_row)


if __name__ == "__main__":
    standalone(run, "test_hiding checks")
