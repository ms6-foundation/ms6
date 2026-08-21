"""The accumulator modulus: what DEFAULT_MOD must be, and that it is not baked in.

DEFAULT_MOD is a 256-bit prime (nothing-up-my-sleeve, derived from pi --
see ms6.utils6's own comment), identical across ms6/vs6's copies. The modulus's job here is fingerprinting
(Schwartz-Zippel), not hiding: the documented leak in mul_combinations_mod
is independently closed at the data level (see ms6.core's EDGE-COLUMN
PADDING), so what a successful extraction recovers is a fixed public
constant, not real item data, regardless of the modulus. An unknown-order
modulus (the old RSA-2048 composite, kept as LEGACY_MOD_2048) was never
load-bearing for that leak -- root-extraction hardness is not achievable
via modulus choice under this construction at any size, mod a prime the
group order is public and a d-th root is one pow() away (see
tests/test_leak.py) -- so a 256-bit prime does the one job the modulus
actually has, at a fraction of the arithmetic cost. The property that
does still matter is that the modulus is not baked into the protocol:
ms6() records the one it used in the params dict, and ps6/vs6 read it
from there, so a commitment under any other modulus -- prime or
composite -- still verifies from its own params.
"""
from tests.harness import (  # noqa: F401
    ms6, ps6, Commitment, vs6, ParamMismatch,
    make_params, unpack_params, PARAM_KEYS, VS6_PARAM_KEYS,
    _seal_batch, _SealTree, chunk_of, chunks, _column_perm,
    _permute_row, _get_batch_ids, DEFAULT_MOD, LEGACY_MOD_2048, ut, gen, u, M, V,
    vs6pkg, D, Q, U_CS, U_BS, mk, proves, proves_with_expect,
    rebuilt, standalone,
)


def run(check):
    d, q, u_cs, u_bs = D, Q, U_CS, U_BS
    base = [mk(i) for i in range(12)]

    check("modulus       : default is a 256-bit prime, identical across "
          "ms6/vs6's copies",
          DEFAULT_MOD.bit_length() == 256 and ut.is_prime(DEFAULT_MOD, k=64)
          and DEFAULT_MOD == u.DEFAULT_MOD == V.DEFAULT_MOD)

    check("modulus       : LEGACY_MOD_2048 is still the old 2048-bit "
          "composite of unknown order, identical across ms6/vs6's copies, "
          "and is not the default",
          LEGACY_MOD_2048.bit_length() == 2048
          and not ut.is_prime(LEGACY_MOD_2048, k=64)
          and LEGACY_MOD_2048 == u.LEGACY_MOD_2048 == V.LEGACY_MOD_2048
          and LEGACY_MOD_2048 != DEFAULT_MOD)

    # The modulus travels in params, so a commitment under a DIFFERENT one
    # verifies without the library knowing anything about it -- prime or
    # composite, since neither is load-bearing for security here (see
    # DEFAULT_MOD's own comment in utils6.py). Driven with freshly
    # generated moduli rather than retired constants: testing a constant
    # against itself would only prove the constant exists.
    other_prime = ut.generate_prime(512)
    alt = Commitment(base, d, q, chunk_size=u_cs, batch_size=u_bs,
                     mod=other_prime, s_mod=ut.generate_prime(256))
    check("modulus       : commitment under an unrelated prime modulus verifies",
          alt.params["mod"] == other_prime and proves(alt, [0, 5, 11]))

    p_, q_ = ut.generate_prime(256), ut.generate_prime(256)
    other_composite = p_ * q_
    alt2 = Commitment(base, d, q, chunk_size=u_cs, batch_size=u_bs,
                      mod=other_composite, s_mod=ut.generate_prime(256))
    check("modulus       : commitment under an unrelated composite modulus verifies",
          alt2.params["mod"] == other_composite and proves(alt2, [0, 5, 11]))

    # and the two must not be interchangeable: a proof produced under one
    # modulus must not verify against a commitment made under another
    c_a, h_a, x_a, s_a, hm_a, perm_a, h1s_a, p_a = alt.opening()
    claims = {0: alt.vals[0]}
    ps_a = ps6(claims.keys(), h_a, hm_a, s_a, p_a, alt.d)
    swapped = dict(p_a, mod=other_composite)
    try:
        vs6(c_a, claims, ps_a, x_a, perm_a, h1s_a, swapped, alt.d)
        crossed = True
    except (AssertionError, ParamMismatch):
        crossed = False
    check("modulus       : proof does not verify under a substituted modulus",
          not crossed)


if __name__ == "__main__":
    standalone(run, "test_modulus checks")
