"""Commitment stages 1-3: append, replace, delete-via-tombstone.

Stages 1-2 assert the property that actually pins the incremental path
down: an updated commitment is BIT-IDENTICAL to one built from scratch
over the same final data (only checkable with the salts pinned).

Stage 3 cannot have that property -- tombstoning keeps a slot a fresh
commit would compact -- so it asserts the equivalence that does hold:
delete() subtracts exactly what the slot held, i.e. replace(i, X) then
delete(i) lands where delete(i) alone does."""
from tests.harness import (  # noqa: F401
    ms6, ps6, Commitment, vs6, ParamMismatch,
    make_params, unpack_params, PARAM_KEYS, VS6_PARAM_KEYS,
    _seal_batch, _SealTree, chunk_of, chunks, _column_perm,
    _permute_row, _get_batch_ids, DEFAULT_MOD, ut, gen, u, M, V,
    ms6pkg, vs6pkg, D, Q, U_CS, U_BS, mk, proves, proves_with_expect,
    rebuilt, standalone,
)


def run(check):
    d, q, u_cs, u_bs = D, Q, U_CS, U_BS
    base = [mk(i) for i in range(12)]
    extra = [mk(i) for i in range(100, 107)]
    # -- stage 1: append -----------------------------------------------
    A = Commitment(base, d, q, chunk_size=u_cs, batch_size=u_bs,
                   s_mod=ut.generate_prime(256))
    for v in extra:
        A.append(v)
    check("stage 1 append : incremental c == from-scratch c",
          A.c == rebuilt(A, base + extra).c)
    check("stage 1 append : proof verifies for an appended item",
          proves(A, [0, len(A.vals) - 1]))
    check("stage 1 append : batches stay uniform except the last",
          all(len(h) == u_bs for h in A.hm_list[:-1]))

    # -- stage 2: replace ----------------------------------------------
    # Replacement values are drawn from mk()'s own small-i range (like the
    # items already occupying these slots), NOT the far-larger-magnitude
    # mk(555)/mk(666)/mk(777) family used elsewhere in this suite. Since x
    # is now sized from the actual item hashes a batch was built with (see
    # _ms6_batch's x-sizing comment), a replacement whose hash needs
    # materially more rows than its batch already has is exactly what
    # _check_fits is supposed to refuse -- see the dedicated check for
    # that right below, using mk(777) deliberately for that purpose.
    B = rebuilt(A, base + extra)
    final = list(base + extra)
    for idx, nv in ((0, mk(50)), (7, mk(60)), (18, mk(102))):
        B.replace(idx, nv)
        final[idx] = nv
    check("stage 2 replace: incremental c == from-scratch c",
          B.c == rebuilt(B, final).c)
    check("stage 2 replace: proof verifies with the new value",
          proves(B, [0, 7, 18]))

    c_b, h_b, x_b, s_b, hm_b, perm_b, p_b = B.opening()
    superseded = {7: base[7]}                      # the value replace() overwrote
    ps_b = ps6(superseded.keys(), h_b, hm_b, s_b, p_b)
    try:
        vs6(c_b, superseded, ps_b, x_b, perm_b, p_b)
        rejected = False
    except AssertionError:
        rejected = True
    check("stage 2 replace: superseded value no longer proves", rejected)

    # -- _check_fits guard: replace() must refuse a value whose hash needs
    # more rows than its batch's current x, rather than silently truncate
    # its low-order digits (see _check_fits's own docstring). Index 0 sits
    # in a batch sized from small mk(i) items. mk()'s whole family is capped
    # at 2**120 regardless of i, so no mk(i) reliably overflows another once
    # real_width (chunk_size - rand_edge_size) shrank the margin -- an
    # explicitly oversized value, independent of mk(), is used instead.
    try:
        B.replace(0, 10 ** 600 + 777)
        guard_rejected = False
    except ValueError:
        guard_rejected = True
    check("_check_fits: replace() refuses an over-wide value instead of truncating",
          guard_rejected)

    # -- stage 3: delete via tombstones ---------------------------------
    base3 = [mk(i) for i in range(20)]
    D0 = Commitment(base3, d, q, chunk_size=u_cs, batch_size=u_bs,
                    s_mod=ut.generate_prime(256))
    before_c = D0.c
    D0.delete(7)
    check("stage 3 delete : commitment changes", D0.c != before_c)
    check("stage 3 delete : survivors still prove", proves(D0, [0, 6, 8, 19]))
    check("stage 3 delete : slots kept, indices don't shift",
          len(D0.vals) == 20 and D0.live_count == 19 and D0.vals[8] == base3[8]
          and D0.vals[19] == base3[19])

    c_d, h_d, x_d, s_d, hm_d, perm_d, p_d = D0.opening()
    try:
        ps6({7}, h_d, hm_d, s_d, p_d)
        opened_dead = True
    except ValueError:
        opened_dead = False
    check("stage 3 delete : deleted slot cannot be opened", not opened_dead)

    # a proof issued before the delete must not verify against the new c
    D1 = Commitment(base3, d, q, chunk_size=u_cs, batch_size=u_bs,
                    s_mod=ut.generate_prime(256))
    c_pre, h_pre, x_pre, s_pre, hm_pre, perm_pre, p_pre = D1.opening()
    cl_pre = {6: D1.vals[6]}
    ps_pre = ps6(cl_pre.keys(), h_pre, [list(b) for b in hm_pre],
                 [list(r) for r in s_pre], p_pre)
    D1.delete(7)                      # same batch as index 6
    try:
        vs6(D1.c, cl_pre, ps_pre, D1.x_list, D1.perms, D1.params)
        stale_ok = True
    except AssertionError:
        stale_ok = False
    check("stage 3 delete : pre-delete proof rejected after delete", not stale_ok)

    # delete subtracts exactly what the slot held
    salts3 = D0.salts
    E1 = Commitment(base3, d, q, chunk_size=u_cs, batch_size=u_bs,
                    s_mod=D0.s_mod, s=D0.s, batch_salts=salts3)
    E1.delete(7)
    E2 = Commitment(base3, d, q, chunk_size=u_cs, batch_size=u_bs,
                    s_mod=D0.s_mod, s=D0.s, batch_salts=salts3)
    # mk(60), not mk(999): same small-magnitude class as base3's own items
    # (base3 = mk(0..19)) -- see _check_fits, which now refuses a
    # replacement whose hash needs more rows than its batch's x already has.
    E2.replace(7, mk(60)); E2.delete(7)
    check("stage 3 delete : replace-then-delete == delete", E1.c == E2.c)

    # an entirely emptied batch still folds, and append lands past the hole
    F = Commitment(base3, d, q, chunk_size=u_cs, batch_size=u_bs,
                   s_mod=ut.generate_prime(256))
    for _i in range(u_bs, 2 * u_bs):
        F.delete(_i)
    check("stage 3 delete : fully emptied batch still proves",
          all(e is None for e in F.hm_list[1]) and proves(F, [0, 2 * u_bs, 19]))
    _new = F.append(mk(777))
    check("stage 3 delete : append lands past tombstones, not in them",
          _new == 20 and proves(F, [_new, 0]))

    _guards = {}
    for _label, _fn in (("double delete", lambda: F.delete(u_bs)),
                        ("revive via replace", lambda: F.replace(u_bs, mk(1))),
                        ("out of range", lambda: F.delete(9999))):
        try:
            _fn()
            _guards[_label] = False          # should not have been allowed
        except (ValueError, IndexError):
            _guards[_label] = True
    _ungu = sorted(k for k, v in _guards.items() if not v)
    check("stage 3 delete : double-delete / revive / range guarded"
          + (f" -- UNGUARDED: {', '.join(_ungu)}" if _ungu else ""), not _ungu)


if __name__ == "__main__":
    standalone(run, "test_updatability checks")
