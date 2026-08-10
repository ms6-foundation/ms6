"""Self-test for the ms6/ps6/vs6 packages.

Run:  python3 examples/selftest.py     (exits non-zero if any check fails)

Three groups of checks:

  updatability  -- Commitment's append / replace / delete, each asserted
                   against the property that actually pins it down (see the
                   comments inline; delete deliberately gets a different one)
  params        -- the shared parameter dict, and its enforcement
  copy parity   -- the prover and verifier packages duplicate several
                   functions so the verifier can be installed alone. Nothing
                   enforces the copies agree; these compare their OUTPUTS on
                   identical inputs. This is the only check that catches a
                   drift in code no proof path happens to exercise.
"""
import multiprocessing
import random as _random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ms6 as _ms6pkg
import vs6 as _vs6pkg
from ms6 import core as M
from ms6 import utils6 as u
from vs6 import core as V
from vs6 import vs6, ParamMismatch, PARAM_KEYS as VS6_PARAM_KEYS

# the self-test reaches past the public API on purpose -- it is checking
# internals (the seal tree, the duplicated helpers), not just behaviour.
ms6, ps6, Commitment = M.ms6, M.ps6, M.Commitment
make_params, unpack_params, PARAM_KEYS = M.make_params, M.unpack_params, M.PARAM_KEYS
_seal_batch, _SealTree = M._seal_batch, M._SealTree
chunk_of, chunks, _column_perm = M.chunk_of, M.chunks, M._column_perm
_permute_row, _get_batch_ids = M._permute_row, M._get_batch_ids
DEFAULT_MOD, ut, gen = M.DEFAULT_MOD, M.ut, M.gen


def main():
    import multiprocessing
    import random as _random
    import time
    from vs6 import vs6, ParamMismatch, PARAM_KEYS as VS6_PARAM_KEYS

    chunk_size, d, q = 40, 3, 10
    WIDTH, DEPTH = 10, 4
    vals = [(1720941241 + (i**70) ^ (i**99)) % 2**200 for i in range(WIDTH ** DEPTH)]
    # ps6/vs6's per-row payload scales with len(oset), i.e. with len(vals)
    # here -- at small WIDTH**DEPTH like this default, row-parallel workers
    # is a clear win. At larger scales each row's payload reaches hundreds
    # of MB, and shipping that between worker processes via
    # ProcessPoolExecutor's pickling can cost more than it saves -- prefer
    # workers=1 there.
    workers = multiprocessing.cpu_count()
    c, h_list, x_list, s_list, hm_list, perm_list, params = ms6(vals, d, q, chunk_size=chunk_size)

    claims = {0: vals[0], 99: vals[99]}

    # params travels with the proof: ps6/vs6 read d/q/chunk_size/batch_size/
    # mod/seal_batch_size from it, so none of the three can be run under
    # parameters the others didn't use.
    # A verifier with its own notion of the correct parameters pins them
    # with expect=; params arrives from the prover and is not
    # self-authenticating on its own.
    agreed = {"d": d, "q": q, "chunk_size": chunk_size, "mod": DEFAULT_MOD}

    print("opening...")
    ps_list = ps6(claims.keys(), h_list, hm_list, s_list, params, workers=1)
    print("verifying...")
    vs6(c, claims, ps_list, x_list, perm_list, params, workers=1, expect=agreed)

    # ------------------------------------------------------------------
    # Updatability (Commitment)
    #
    #   stage 1  append  -- add an item without rehashing the rest
    #   stage 2  replace -- swap an item in place, same slot
    #   stage 3  delete  -- tombstone a slot, keeping every index stable
    #   stage 4  cache   -- _SealTree, so the root costs a path not a refold
    #
    # Stage 3 does NOT get the bit-identical from-scratch comparison stages
    # 1-2 use: tombstoning keeps the slot a fresh commit would compact, so
    # the two legitimately differ. The equivalence asserted instead is that
    # delete() subtracts exactly what the slot held -- replace(i, X) then
    # delete(i) lands where delete(i) alone does.
    #
    # The load-bearing property in stages 1-2 is that an incrementally
    # updated commitment is BIT-IDENTICAL to one built from scratch over
    # the same final data -- that is what proves the incremental path
    # hasn't drifted from the real one. It only holds with the salts
    # pinned (batch_salts=), since a fresh commit would otherwise draw new
    # ones.
    # ------------------------------------------------------------------
    print("\nupdatability")
    failures = []

    def check(label, ok):
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
        if not ok:
            failures.append(label)
        return ok

    u_cs, u_bs = 12, 5
    mk = lambda i: (1720941241 + (i ** 7) ^ (i ** 5)) % 2 ** 120
    base = [mk(i) for i in range(12)]
    extra = [mk(i) for i in range(100, 107)]

    def proves_with_expect(C, idxs, expect):
        c_u, h_u, x_u, s_u, hm_u, perm_u, p_u = C.opening()
        cl = {i: C.vals[i] for i in idxs}
        ps_u = ps6(cl.keys(), h_u, hm_u, s_u, p_u)
        return vs6(c_u, cl, ps_u, x_u, perm_u, p_u, expect=expect)

    def rebuilt(C, vals_now):
        """The same data committed from scratch, under C's own salts."""
        return Commitment(vals_now, d, q, chunk_size=u_cs, batch_size=u_bs,
                          s_mod=C.s_mod, s=C.s, batch_salts=C.salts)

    def proves(C, idxs):
        """A claim over an updated commitment, through the unmodified
        ps6/vs6 path -- Commitment.opening() returns ms6()'s own tuple,
        params included."""
        c_u, h_u, x_u, s_u, hm_u, perm_u, p_u = C.opening()
        cl = {i: C.vals[i] for i in idxs}
        ps_u = ps6(cl.keys(), h_u, hm_u, s_u, p_u)
        return vs6(c_u, cl, ps_u, x_u, perm_u, p_u)

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
    # in a batch sized from small mk(i) items; mk(777) is one of this
    # suite's deliberately much-larger-magnitude values (see stage 1/2
    # comments), so it should overflow that batch's x and be rejected.
    try:
        B.replace(0, mk(777))
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

    # -- modulus sizing / backward compatibility --------------------------
    # DEFAULT_MOD moved 2048 -> 256 bits (see utils6.DEFAULT_MOD's comment
    # for why the fingerprinting job doesn't need more, and why more buys no
    # root-extraction hardness). A commitment made under the old modulus must
    # still verify, because ms6() records the modulus it used in params and
    # ps6/vs6 read it from there rather than from the module default.
    legacy = Commitment(base, d, q, chunk_size=u_cs, batch_size=u_bs,
                        mod=u.LEGACY_MOD_2048, s_mod=ut.generate_prime(256))
    check("modulus       : legacy 2048-bit commitment still verifies",
          legacy.params["mod"] == u.LEGACY_MOD_2048 and proves(legacy, [0, 5, 11]))
    check("modulus       : default is 256-bit and identical in both copies",
          DEFAULT_MOD.bit_length() == 256 and DEFAULT_MOD == u.DEFAULT_MOD)

    # -- stage 4: cached seal tree --------------------------------------
    check("stage 4 cache  : cached c == uncached _seal_batch",
          B.c == _seal_batch(B.h_list, B.chunk_size, max(B.x_list), d, q, B.mod))

    # Small fan-outs so the tree is several levels deep without needing
    # thousands of leaves, and so every group boundary gets crossed.
    rng = _random.Random(11)
    tree_ok = True
    for sbs in (2, 3, 4):
        leaves = [rng.randrange(1, 2 ** 160)]
        T = _SealTree(leaves, 2, u_cs, d, q, DEFAULT_MOD, sbs=sbs)
        for _ in range(25):
            nv = rng.randrange(1, 2 ** 160)
            T.append_leaf(nv)
            leaves.append(nv)
            tree_ok &= T.root == _seal_batch(leaves, u_cs, 2, d, q, DEFAULT_MOD,
                                             seal_batch_size=sbs)
            i = rng.randrange(len(leaves))
            nv = rng.randrange(1, 2 ** 160)
            T.update_leaf(i, nv)
            leaves[i] = nv
            tree_ok &= T.root == _seal_batch(leaves, u_cs, 2, d, q, DEFAULT_MOD,
                                             seal_batch_size=sbs)
    check("stage 4 cache  : root tracks _seal_batch over appends/updates", tree_ok)

    # A taller batch invalidates every node (all counts are chunked to
    # max(x_list)), so the tree must notice and rebuild rather than patch.
    X = Commitment([mk(0), mk(1)], d, q, chunk_size=u_cs, batch_size=2,
                   s_mod=ut.generate_prime(256),
                   batch_salts=[10 ** 8 + 7, 10 ** 80 + 7, 10 ** 80 + 7])
    X.append(mk(2))
    check("stage 4 cache  : rebuilds when a new batch changes x",
          X._tree_x == max(X.x_list)
          and X.c == _seal_batch(X.h_list, X.chunk_size, max(X.x_list), d, q, X.mod))

    # -- params enforcement ---------------------------------------------
    p_ok = B.params
    check("params        : correct expect= accepted",
          proves_with_expect(B, [0], dict(p_ok)))

    def rejects(expect_or_params, use_as_expect=True):
        try:
            if use_as_expect:
                vs6(c_b, {0: B.vals[0]}, ps6({0}, h_b, hm_b, s_b, p_b), x_b, perm_b, p_b,
                    expect=expect_or_params)
            else:
                vs6(c_b, {0: B.vals[0]}, ps6({0}, h_b, hm_b, s_b, p_b), x_b, perm_b,
                    expect_or_params)
            return False
        except ParamMismatch:
            return True

    check("params        : wrong pinned d rejected", rejects({"d": p_ok["d"] + 1}))
    check("params        : wrong pinned mod rejected", rejects({"mod": p_ok["mod"] - 2}))
    check("params        : typo in expect key rejected", rejects({"chunck_size": 12}))
    check("params        : nonsense mod rejected",
          rejects({**p_ok, "mod": 1}, use_as_expect=False))
    check("params        : ms6/vs6 PARAM_KEYS agree", PARAM_KEYS == VS6_PARAM_KEYS)

    # -- duplicated-copy parity ------------------------------------------
    # vs6.py + verifier_utils6.py deliberately DUPLICATE a slice of ms6.py +
    # utils6.py rather than importing them, so a verifier-only deployment
    # pulls in no prover code. Nothing enforces that the copies stay in
    # step, and this session broke that twice (the _seal_batch exponent
    # drift; q removed from one side of the row-seal only).
    #
    # These compare OUTPUTS on identical inputs, not source text -- the
    # docstrings legitimately differ between copies, so a textual diff
    # would be a false-alarm generator.
    _V = V
    _vu = _vs6pkg.verifier_utils6
    _vut = _vu.Utils()
    prng = _random.Random(4242)
    ri = lambda b=160: prng.randrange(1, 1 << b)
    mod_ = DEFAULT_MOD

    def parity(group, cases):
        """cases: {name: (ours, theirs)} -- report which member drifted."""
        drifted = sorted(n for n, (a, b) in cases.items() if a != b)
        check(f"copy parity   : {group}" + (f" -- DRIFTED: {', '.join(drifted)}" if drifted else ""),
              not drifted)

    iden_ = f"{'':1>{12}}"
    svals = [str(ri(200)) for _ in range(15)]
    perm_ = _column_perm(12345, 12)
    prows = [''.join(prng.choice('123456789') for _ in range(12)) for _ in range(15)]
    idxs = [prng.randrange(0, 10000) for _ in range(50)]
    seal_cases = {}
    for n_, sbs_ in ((1, 1000), (5, 1000), (30, 4), (1001, 1000)):
        lv = [ri(200) for _ in range(n_)]
        seal_cases[f"_seal_batch(n={n_},sbs={sbs_})"] = (
            _seal_batch(lv, 12, 2, 3, 10, mod_, sbs_), _V._seal_batch(lv, 12, 2, 3, 10, mod_, sbs_))
    pp = make_params(3, 10, 12, 5, mod_, 7)
    parity("ms6.py <-> vs6.py", {
        "chunk_of": ([chunk_of(v, iden_, 3, 12) for v in svals],
                     [_V.chunk_of(v, iden_, 3, 12) for v in svals]),
        "_permute_row": ([_permute_row(r, perm_) for r in prows],
                         [_V._permute_row(r, perm_) for r in prows]),
        "_get_batch_ids": (_get_batch_ids(idxs, 1000), _V._get_batch_ids(idxs, 1000)),
        "PARAM_KEYS": (PARAM_KEYS, _V.PARAM_KEYS),
        "unpack_params": (unpack_params(pp), _V.unpack_params(pp)),
        **seal_cases,
    })

    ints = [ri(220) for _ in range(10)]
    cnts = [[prng.randrange(0, 30) for _ in range(10)] for _ in range(5)]
    vrows = [[ri(120) for _ in range(8)] for _ in range(4)]
    A_ = ut.h_vector_mod(3, mod_, values=vrows[0])
    B_ = ut.h_vector_mod(3, mod_, values=vrows[1])
    L_ = 6
    M_ = [prng.randrange(1, 10) for _ in range(L_)]
    ps_ = [[ri(100) for _ in range(40)] for _ in range(3 * (L_ - 1) + 1)]
    parity("utils6 <-> verifier_utils6", {
        "DEFAULT_MOD": (u.DEFAULT_MOD, _vu.DEFAULT_MOD),
        "hash": ([ut.hash(v, k) for v in ints for k in (1, 3, 10)],
                 [_vut.hash(v, k) for v in ints for k in (1, 3, 10)]),
        "backward_chunk": ([list(ut.backward_chunk(str(v), 12)) for v in ints],
                           [list(_vut.backward_chunk(str(v), 12)) for v in ints]),
        "cell_product": ([ut.cell_product(c, m) for c in cnts for m in (1, 3)],
                         [_vut.cell_product(c, m) for c in cnts for m in (1, 3)]),
        "cell_product_mod": ([ut.cell_product_mod(c, m, mod_) for c in cnts for m in (1, 3)],
                             [_vut.cell_product_mod(c, m, mod_) for c in cnts for m in (1, 3)]),
        "vsum_level": ([ut.vsum_level(N, values=r, b=b) for r in vrows for N in (1, 3) for b in (1, 4)],
                       [_vut.vsum_level(N, values=r, b=b) for r in vrows for N in (1, 3) for b in (1, 4)]),
        "vsum_level_fold_mod": ([ut.vsum_level_fold_mod(N, mod_, values=r) for r in vrows for N in (1, 3)],
                           [_vut.vsum_level_fold_mod(N, mod_, values=r) for r in vrows for N in (1, 3)]),
        "h_vector_mod": ([ut.h_vector_mod(3, mod_, values=r) for r in vrows],
                         [_vut.h_vector_mod(3, mod_, values=r) for r in vrows]),
        "fold_h_vector_mod": ([ut.fold_h_vector_mod(3, mod_, [r[:4], r[4:]], global_keys=True) for r in vrows],
                              [_vut.fold_h_vector_mod(3, mod_, [r[:4], r[4:]], global_keys=True) for r in vrows]),
        "vsum_level_fold_mod": ([ut.vsum_level_fold_mod(3, mod_, r, global_keys=True) for r in vrows],
                                [_vut.vsum_level_fold_mod(3, mod_, r, global_keys=True) for r in vrows]),
        "convolve_h_vectors_mod": (ut.convolve_h_vectors_mod(A_, B_, 3, mod_),
                                   _vut.convolve_h_vectors_mod(A_, B_, 3, mod_)),
        "mul_combinations_mod": (ut.mul_combinations_mod(3, ps_, M_, mod_),
                                 _vut.mul_combinations_mod(3, ps_, M_, mod_)),
    })

    _a1, _a2 = u.Acc(3, 12), _vu.Acc(3, 12)
    for _v in svals:
        _r = chunk_of(_v, iden_, 3, 12)
        _a1.add(_r); _a2.add(_r)
    _a1.flush(); _a2.flush()
    parity("Acc", {"Acc.cnt/rows": ((_a1.cnt, _a1.rows), (_a2.cnt, _a2.rows))})

    U = Commitment([mk(i) for i in range(600)], d, q, chunk_size=chunk_size, batch_size=20)
    # A same-magnitude-class replacement, not mk(4242): mk(i)'s hash width
    # grows with i (see _check_fits), so a value from a far larger i would
    # legitimately overflow index 300's batch -- this timing probe isn't
    # exercising that guard, just the replace-vs-recommit cost, so it needs
    # a value that actually fits.
    t0 = time.time(); U.replace(300, mk(300) ^ 0xABCDEF1234567); t_upd = time.time() - t0
    t0 = time.time()
    Commitment(U.vals, d, q, chunk_size=chunk_size, batch_size=20, s_mod=U.s_mod)
    t_full = time.time() - t0
    print(f"  [info] {len(U.h_list)} batches: replace {t_upd * 1000:.1f} ms "
          f"vs full recommit {t_full * 1000:.1f} ms ({t_full / t_upd:.0f}x)")

    # -- x-sizing: deterministic across salts, correct across parallelism --
    # x used to come from the per-batch salt's own decimal digit length, so
    # two commits of the SAME vals could get different x_list just because
    # they drew different random salts. It's now a function of the item
    # hashes alone (see _ms6_batch's x-sizing comment) -- these two checks
    # are the regression test for that: same vals -> same x_list regardless
    # of the (still-random) salt, and the new batch-level-parallel
    # Commitment.__init__ path (_new_batches_parallel, task #58) produces a
    # bit-identical result to the sequential one it replaces when workers>1.
    det_vals = [mk(i) for i in range(37)]     # not a multiple of any batch_size below
    _, _, x_list_1, *_ = ms6(det_vals, d, q, chunk_size=u_cs, batch_size=u_bs)
    _, _, x_list_2, *_ = ms6(det_vals, d, q, chunk_size=u_cs, batch_size=u_bs)
    check("x-sizing      : x_list deterministic across independent commits "
          "(salt no longer sizes x)", x_list_1 == x_list_2)

    par_vals = [mk(i) for i in range(23)]
    par_salts = [ut.generate_prime(64) for _ in range(-(-len(par_vals) // u_bs))]
    par_s, par_s_mod = gen.randrange(10 ** 30), ut.generate_prime(256)
    C_seq = Commitment(par_vals, d, q, chunk_size=u_cs, batch_size=u_bs, workers=1,
                       s=par_s, s_mod=par_s_mod, batch_salts=par_salts)
    C_par = Commitment(par_vals, d, q, chunk_size=u_cs, batch_size=u_bs, workers=4,
                       s=par_s, s_mod=par_s_mod, batch_salts=par_salts)
    check("parallelism   : sequential vs. parallel Commitment build (workers=1 vs 4) "
          "bit-identical", C_seq.opening() == C_par.opening())

    if failures:
        print(f"\n{len(failures)} updatability check(s) FAILED")
        raise SystemExit(1)
    print("\nall updatability checks passed")

if __name__ == "__main__":
    main()
