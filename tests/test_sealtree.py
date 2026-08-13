"""Stage 4: the cached _SealTree.

The cached root must equal an uncached _seal_batch fold at every step --
across builds, updates, appends at every group boundary, and the rebuild
triggered when a new batch changes x."""
import random as _random

from tests.harness import (  # noqa: F401
    ms6, ps6, Commitment, vs6, ParamMismatch,
    make_params, unpack_params, PARAM_KEYS, VS6_PARAM_KEYS,
    _seal_batch, _SealTree, chunk_of, chunks, _column_perm,
    _permute_row, _get_batch_ids, DEFAULT_MOD, ut, gen, u, M, V,
    ms6pkg, vs6pkg, D, Q, U_CS, U_BS, mk, proves, proves_with_expect,
    rebuilt, standalone,
)


def run(check):
    d, q, u_cs = D, Q, U_CS
    base = [mk(i) for i in range(12)]
    extra = [mk(i) for i in range(100, 107)]
    B = rebuilt(Commitment(base + extra, D, Q, chunk_size=U_CS,
                           batch_size=U_BS, s_mod=ut.generate_prime(256)),
                base + extra)
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


if __name__ == "__main__":
    standalone(run, "test_sealtree checks")
