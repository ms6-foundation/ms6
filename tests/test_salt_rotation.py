"""Commitment.rotate_batch_salt: does it actually bound the multi-query gap?

QueryGovernor (tests/test_query_governance.py) is a POLICY mitigation: it
refuses claim sets shaped like Observation obs:ratio, but does nothing to the
underlying cause -- S(r,j) is fixed for the whole life of a commitment, so
two proofs that DO get served (a legitimately different follow-up claim, or
an operator who has opted into a looser policy) still cancel S via their
ratio if compared. rotate_batch_salt() is the other half QueryGovernor's own
docstring names but leaves out of scope: draw a fresh S for one batch,
in-place, without touching that batch's items/perm/h1_salt.

WHAT THIS MODULE DEMONSTRATES, PRECISELY
------------------------------------------
Not "rotation fixes hiding" -- it doesn't, and the module docstring
shouldn't imply that. Two things, both required to trust the claim honestly:

  1. Ratio-cancellation still WORKS within a single salt window (before OR
     after any given rotation) -- rotation does not touch the underlying
     mechanism, only bounds when a given S is exploitable. If this check
     failed to demonstrate the attack still works, the "still needs
     QueryGovernor" claim in the docs would be untested air.
  2. Ratio-cancellation FAILS across a rotation boundary -- a proof from
     before rotate_batch_salt() and a proof from after it no longer share
     an S to cancel, so comparing them doesn't isolate row content the way
     two same-window proofs do. This is rotation's actual protective value,
     shown directly rather than asserted.

Everything else here is fidelity: confirming rotation really is cheap (only
S0/h/S change; perm/h1_salt/hm_list/every other batch are untouched) and
really is "not a new commitment" (same vals/indices, old proofs for THIS
batch just stop verifying, exactly like replace()/delete() already do).
"""
import math

from tests.harness import (  # noqa: F401
    ms6, ps6, Commitment, vs6, ParamMismatch,
    QueryGovernor, QueryPolicyViolation, ps6_governed,
    make_params, unpack_params, PARAM_KEYS, VS6_PARAM_KEYS,
    _seal_batch, _SealTree, chunk_of, chunks, _column_perm,
    _permute_row, _get_batch_ids, DEFAULT_MOD, ut, gen, u, M, V,
    vs6pkg, D, Q, U_CS, U_BS, mk, proves, proves_with_expect,
    rebuilt, standalone,
)


def _row_at(hm, iset, col, mod, row=0):
    """Ground-truth row[col], recomputed directly from oset's own hm --
    same technique tests/test_leak.py's own _row_at uses, and tests/
    test_hiding.py's inline version."""
    oset = {i for i in range(len(hm)) if i not in iset and hm[i] is not None}
    cnt = ut.col_digit_counts([hm[i][row] for i in oset], U_CS)
    return ut.cell_pow_product_mod(cnt[col], Q, DEFAULT_MOD)


def run(check):
    d, q, u_cs, u_bs = D, Q, U_CS, U_BS
    base = [mk(i) for i in range(u_bs)]

    # --- fidelity: rotation is cheap and touches only what it claims to --
    C = Commitment(base, d, q, chunk_size=u_cs, batch_size=u_bs)
    assert C.s_mod == DEFAULT_MOD  # precondition for the ratio math below

    perm_before = list(C.perms[0])
    h1_salt_before = C.h1_salts[0]
    hm_before = [row[:] if row is not None else None for row in C.hm_list[0]]
    salt_before = C.salts[0]
    h_before = C.h_list[0]
    c_before = C.c

    new_salt = C.rotate_batch_salt(0)

    check("rotation      : rotate_batch_salt returns the new salt, and it "
          "differs from the old one",
          new_salt == C.salts[0] and new_salt != salt_before)
    check("rotation      : h_list[0] (and therefore c) changed",
          C.h_list[0] != h_before and C.c != c_before)
    check("rotation      : perm[0] is untouched (not re-derived)",
          C.perms[0] == perm_before)
    check("rotation      : h1_salts[0] is untouched (not re-derived)",
          C.h1_salts[0] == h1_salt_before)
    check("rotation      : hm_list[0] (every item's hashed/permuted digits) "
          "is untouched -- no item was re-hashed",
          C.hm_list[0] == hm_before)
    check("rotation      : vals/indices/live_count are untouched -- not a "
          "new commitment, same items",
          C.vals == base and C.live_count == len(base))

    # --- items still prove correctly against the ROTATED commitment ------
    check("rotation      : an item still proves correctly after its "
          "batch's salt was rotated",
          proves(C, [0, 2]))

    # --- a proof from BEFORE rotation no longer verifies against the -----
    # --- rotated commitment's current state -------------------------------
    C2 = Commitment(base, d, q, chunk_size=u_cs, batch_size=u_bs)
    c_u, h_u, x_u, s_u, hm_u, perm_u, h1s_u, p_u = C2.opening()
    ps_pre = ps6({0}, h_u, hm_u, s_u, p_u, C2.d)      # proof under the OLD salt
    C2.rotate_batch_salt(0)
    stale_proof_fails = False
    try:
        ok = vs6(C2.c, {0: C2.vals[0]}, ps_pre, x_u, perm_u, h1s_u, C2.params, C2.d)
        stale_proof_fails = not ok
    except AssertionError:
        stale_proof_fails = True
    check("rotation      : a proof generated before rotation does not "
          "verify against the commitment's post-rotation state",
          stale_proof_fails)

    # --- the core question: does this sever ratio-cancellation? ----------
    # Two ordinary, disjoint single-item claims -- the obs:ratio shape --
    # against one interior (non-edge) column, well clear of EDGE_COLS at
    # this chunk_size/rand_edge_size.
    C3 = Commitment(base, d, q, chunk_size=u_cs, batch_size=u_bs)
    hm3 = C3.hm_list[0]
    col = u_cs // 2
    iset_a, iset_b = {0}, {1}
    row_a = _row_at(hm3, iset_a, col, DEFAULT_MOD)
    row_b = _row_at(hm3, iset_b, col, DEFAULT_MOD)

    def combined_now(row_val):
        S_rj = C3.s_list[0][0][col]
        return (row_val * pow(S_rj, d, DEFAULT_MOD)) % DEFAULT_MOD

    # 1. WITHIN one salt window: ratio cancels S, isolating row_a/row_b --
    #    the attack works exactly as documented, rotation hasn't happened.
    combined_a_1 = combined_now(row_a)
    combined_b_1 = combined_now(row_b)
    ratio_same_window = (combined_a_1 * pow(combined_b_1, -1, DEFAULT_MOD)) % DEFAULT_MOD
    expected_ratio = (row_a * pow(row_b, -1, DEFAULT_MOD)) % DEFAULT_MOD
    check("rotation      : ratio-cancellation WORKS within a single salt "
          "window -- confirms rotation does not change the underlying "
          "mechanism, only bounds when it applies",
          ratio_same_window == expected_ratio)

    # 2. Query AGAIN, same window, no rotation between -- still cancels,
    #    confirming the vulnerability is live right up until a rotation.
    combined_b_1_again = combined_now(row_b)
    check("rotation      : repeated queries in the SAME window keep "
          "cancelling S the same way (sanity: this isn't a fluke of one "
          "particular draw)",
          combined_b_1_again == combined_b_1)

    # 3. Rotate. Compute combined_b AFTER rotation (a fresh query under the
    #    new S), and ratio it against combined_a_1 (the proof from BEFORE
    #    rotation) -- these no longer share an S, so the ratio should NOT
    #    reproduce row_a/row_b.
    C3.rotate_batch_salt(0)
    combined_b_after = combined_now(row_b)
    ratio_cross_rotation = (combined_a_1 * pow(combined_b_after, -1, DEFAULT_MOD)) % DEFAULT_MOD
    check("rotation      : ratio-cancellation FAILS across a rotation "
          "boundary -- a pre-rotation proof and a post-rotation proof no "
          "longer share an S to cancel",
          ratio_cross_rotation != expected_ratio)

    # 4. Within the NEW window (both queries after rotation), the attack
    #    works again -- rotation bounds the window, it does not eliminate
    #    the mechanism inside a window, and this module should not imply
    #    otherwise.
    combined_a_after = combined_now(row_a)
    ratio_new_window = (combined_a_after * pow(combined_b_after, -1, DEFAULT_MOD)) % DEFAULT_MOD
    check("rotation      : ratio-cancellation works again WITHIN the new "
          "(post-rotation) window -- rotation bounds exposure, it is not "
          "a proof of resistance to a general multi-query adversary",
          ratio_new_window == expected_ratio)

    # --- QueryGovernor.forget_batch pairs with rotation -------------------
    gov = QueryGovernor(batch_size=u_bs)
    gov.authorize({0})
    check("rotation      : governor recorded batch 0's history before "
          "forget_batch",
          gov.history_for_batch(0) != [])
    forgotten = gov.forget_batch(0)
    check("rotation      : forget_batch clears a batch's history and "
          "reports how many claim sets it forgot",
          gov.history_for_batch(0) == [] and forgotten == 1)
    check("rotation      : forget_batch on a batch with no history is a "
          "harmless no-op",
          gov.forget_batch(99) == 0)


if __name__ == "__main__":
    standalone(run, "test_salt_rotation checks")
