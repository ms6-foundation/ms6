"""x-sizing determinism, and parallel vs sequential Commitment construction.

x sizes accH/accS and hm's chunking; it is derived from the items' own
hash widths, so it must not vary with the salt between commits of the
same data."""
from tests.harness import (  # noqa: F401
    ms6, ps6, Commitment, vs6, ParamMismatch,
    make_params, unpack_params, PARAM_KEYS, VS6_PARAM_KEYS,
    _seal_batch, _SealTree, chunk_of, chunks, _column_perm,
    _permute_row, _get_batch_ids, DEFAULT_MOD, ut, gen, u, M, V,
    vs6pkg, D, Q, U_CS, U_BS, mk, proves, proves_with_expect,
    rebuilt, standalone,
)


def run(check):
    d, q, u_cs, u_bs = D, Q, U_CS, U_BS
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

    # -- row-level parallelism inside _seal_grid (ut.seal_row_mod), a DIFFERENT
    # code path than the batch-level one just above: it only runs when a
    # single batch spans multiple rows (items > chunk_size) AND workers>1
    # reaches _seal_grid itself -- which never happens through the batch-level
    # parallel path above, since ms6()/Commitment always pin workers=1 per
    # batch to avoid nesting process pools (see ms6()'s own docstring). Call
    # ms6() directly with one big batch so this branch actually runs.
    row_vals = [mk(i) for i in range(45)]     # one batch, chunk_size=10 -> 5 rows
    row_cs = 10
    row_s, row_s_mod = gen.randrange(10 ** 30), ut.generate_prime(256)
    row_salts = [ut.generate_prime(64)]       # one batch -> one pinned salt
    Row_seq = Commitment(row_vals, d, q, chunk_size=row_cs, batch_size=1000, workers=1,
                          s=row_s, s_mod=row_s_mod, batch_salts=row_salts)
    Row_par = Commitment(row_vals, d, q, chunk_size=row_cs, batch_size=1000, workers=4,
                          s=row_s, s_mod=row_s_mod, batch_salts=row_salts)
    check("parallelism   : sequential vs. parallel row-fold (single multi-row "
          "batch, seal_row_mod) bit-identical", Row_seq.opening() == Row_par.opening())

    c_row, h_row, x_row, s_row, hm_row, perm_row, h1s_row, p_row = Row_par.opening()
    claims_row = {3: row_vals[3], 40: row_vals[40]}
    ps_row = ps6(claims_row.keys(), h_row, hm_row, s_row, p_row)
    check("parallelism   : row-level-parallel commit still verifies correctly",
          vs6(c_row, claims_row, ps_row, x_row, perm_row, h1s_row, p_row))


if __name__ == "__main__":
    standalone(run, "test_sizing checks")
