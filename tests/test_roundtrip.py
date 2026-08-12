"""End-to-end commit -> open -> verify, at a realistic size.

The smoke test: if this fails, nothing else in the suite is meaningful."""
import multiprocessing

from tests.harness import (  # noqa: F401
    ms6, ps6, Commitment, vs6, ParamMismatch,
    make_params, unpack_params, PARAM_KEYS, VS6_PARAM_KEYS,
    _seal_batch, _SealTree, chunk_of, chunks, _column_perm,
    _permute_row, _get_batch_ids, DEFAULT_MOD, ut, gen, u, M, V,
    ms6pkg, vs6pkg, D, Q, U_CS, U_BS, mk, proves, proves_with_expect,
    rebuilt, standalone,
)


def run(check):
    chunk_size, d, q = 40, 3, 10
    DEFAULT_MOD_ = DEFAULT_MOD


    WIDTH, DEPTH = 10, 4
    vals = [(1720941241 + (i**70) ^ (i**99)) % 2**200 for i in range(WIDTH ** DEPTH)]
    # ps6/vs6's per-row payload scales with len(oset), i.e. with len(vals)
    # here -- at small WIDTH**DEPTH like this default, row-parallel workers
    # is a clear win. At larger scales each row's payload reaches hundreds
    # of MB, and shipping that between worker processes via
    # ProcessPoolExecutor's pickling can cost more than it saves -- prefer
    # workers=1 there.
    workers = multiprocessing.cpu_count()
    c, h_list, x_list, s_list, hm_list, perm_list, h1_salt_list, params = ms6(vals, d, q, chunk_size=chunk_size)

    claims = {0: vals[0], 99: vals[99]}

    # params travels with the proof: ps6/vs6 read d/q/chunk_size/batch_size/
    # mod/seal_batch_size from it, so none of the three can be run under
    # parameters the others didn't use.
    # A verifier with its own notion of the correct parameters pins them
    # with expect=; params arrives from the prover and is not
    # self-authenticating on its own.
    agreed = {"d": d, "q": q, "chunk_size": chunk_size, "mod": DEFAULT_MOD}

    ps_list = ps6(claims.keys(), h_list, hm_list, s_list, params, workers=1)
    check("round trip    : commit -> open -> verify over %d items" % len(vals),
          vs6(c, claims, ps_list, x_list, perm_list, h1_salt_list, params, workers=1, expect=agreed))

    # a wrong value at a claimed index must be rejected, or "it verified" means
    # nothing
    tampered = dict(claims)
    tampered[0] = vals[1]
    try:
        vs6(c, tampered, ps_list, x_list, perm_list, h1_salt_list, params, workers=1, expect=agreed)
        rejected = False
    except AssertionError:
        rejected = True
    check("round trip    : tampered claim rejected", rejected)


if __name__ == "__main__":
    standalone(run, "test_roundtrip checks")
