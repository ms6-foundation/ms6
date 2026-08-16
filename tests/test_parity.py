"""Parity between the deliberately duplicated prover and verifier copies.

vs6/ duplicates a slice of ms6/ so the verifier can be installed alone.
Nothing in the language keeps the copies in step, so these compare their
OUTPUTS on identical inputs (not source text -- docstrings legitimately
differ). This is the only check that catches drift in code no proof path
happens to exercise."""
import random as _random

from tests.harness import (  # noqa: F401
    ms6, ps6, Commitment, vs6, ParamMismatch,
    make_params, unpack_params, PARAM_KEYS, VS6_PARAM_KEYS,
    _seal_batch, _SealTree, chunk_of, chunks, _column_perm,
    _permute_row, _get_batch_ids, DEFAULT_MOD, ut, gen, u, M, V,
    vs6pkg, D, Q, U_CS, U_BS, mk, proves, proves_with_expect,
    rebuilt, standalone,
)


def run(check):
    # -- duplicated-copy parity ------------------------------------------
    # vs6/ deliberately DUPLICATES a slice of ms6/ (core.py and utils6.py)
    # utils6.py rather than importing them, so a verifier-only deployment
    # pulls in no prover code. Nothing enforces that the copies stay in
    # step, and this session broke that twice (the _seal_batch exponent
    # drift; q removed from one side of the row-seal only).
    #
    # These compare OUTPUTS on identical inputs, not source text -- the
    # docstrings legitimately differ between copies, so a textual diff
    # would be a false-alarm generator.
    _V = V
    _vu = vs6pkg.utils6
    _vut = _vu.Utils()
    prng = _random.Random(4242)
    ri = lambda b=160: prng.randrange(1, 1 << b)
    mod_ = DEFAULT_MOD

    def parity(group, cases):
        """cases: {name: (ours, theirs)} -- report which member drifted."""
        drifted = sorted(n for n, (a, b) in cases.items() if a != b)
        check(f"copy parity   : {group}" + (f" -- DRIFTED: {', '.join(drifted)}" if drifted else ""),
              not drifted)

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
        "chunk_of": ([chunk_of(v, 3, 12) for v in svals],
                     [_V.chunk_of(v, 3, 12) for v in svals]),
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
    parity("ms6.utils6 <-> vs6.utils6", {
        "DEFAULT_MOD": (u.DEFAULT_MOD, _vu.DEFAULT_MOD),
        "hash": ([ut.hash(v, k) for v in ints for k in (1, 3, 10)],
                 [_vut.hash(v, k) for v in ints for k in (1, 3, 10)]),
        "domain_hash": ([ut.domain_hash(f"tag:{v}".encode()) for v in ints],
                        [_vut.domain_hash(f"tag:{v}".encode()) for v in ints]),
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
        "vsum_level_fold_mod (global_keys=True)": ([ut.vsum_level_fold_mod(3, mod_, r, global_keys=True) for r in vrows],
                                [_vut.vsum_level_fold_mod(3, mod_, r, global_keys=True) for r in vrows]),
        "convolve_h_vectors_mod": (ut.convolve_h_vectors_mod(A_, B_, 3, mod_),
                                   _vut.convolve_h_vectors_mod(A_, B_, 3, mod_)),
        "mul_combinations_mod": (ut.mul_combinations_mod(3, ps_, M_, mod_),
                                 _vut.mul_combinations_mod(3, ps_, M_, mod_)),
    })

    _a1, _a2 = u.Acc(3, 12), _vu.Acc(3, 12)
    for _v in svals:
        _r = chunk_of(_v, 3, 12)
        _a1.add(_r); _a2.add(_r)
    _a1.flush(); _a2.flush()
    parity("Acc", {"Acc.cnt/rows": ((_a1.cnt, _a1.rows), (_a2.cnt, _a2.rows))})


if __name__ == "__main__":
    standalone(run, "test_parity checks")
