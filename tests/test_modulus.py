"""DEFAULT_MOD sizing, and backward compatibility with LEGACY_MOD_2048.

ms6() records the modulus in params and ps6/vs6 read it from there, so
moving the default must not invalidate commitments made under the old
one."""
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
    check("modulus       : default is the 2048-bit RSA-2048 composite, "
          "identical in both copies",
          DEFAULT_MOD.bit_length() == 2048 and len(str(DEFAULT_MOD)) == 617
          and DEFAULT_MOD == u.DEFAULT_MOD)
    # the whole point of the change: a PRIME modulus would hand the leak an
    # efficient d-th root, so assert the default is genuinely composite and
    # has no cheaply-findable factor
    check("modulus       : default is composite (unknown order), no small factors",
          not ut.is_prime(DEFAULT_MOD, k=32)
          and all(DEFAULT_MOD % f for f in range(3, 50000, 2)))
    # commitments made under the superseded primes must still verify, since
    # params carries the modulus that was actually used
    legacy256 = Commitment(base, d, q, chunk_size=u_cs, batch_size=u_bs,
                           mod=u.LEGACY_MOD_256, s_mod=ut.generate_prime(256))
    check("modulus       : legacy 256-bit commitment still verifies",
          legacy256.params["mod"] == u.LEGACY_MOD_256 and proves(legacy256, [0, 5, 11]))


if __name__ == "__main__":
    standalone(run, "test_modulus checks")
