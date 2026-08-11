"""The accumulator modulus: what DEFAULT_MOD must be, and that it is not baked in.

DEFAULT_MOD is the RSA-2048 challenge composite. Two properties matter and
neither is self-evident from the value sitting in the source:

  * it must stay COMPOSITE. The documented leak in mul_combinations_mod
    reads singleton buckets by extracting a d-th root; mod a prime that is
    free at any size, because the group order is public. If a prime ever
    slipped back into this constant nothing else in the suite would notice.
  * the modulus must not be baked into the protocol. ms6() records the one
    it used in the params dict, and ps6/vs6 read it from there, so a
    commitment under any other modulus still verifies from its own params.
    That is what makes the default safe to change -- and why no constants
    are kept for the primes this replaced.
"""
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

    check("modulus       : default is the 2048-bit RSA-2048 composite, "
          "identical in both copies",
          DEFAULT_MOD.bit_length() == 2048 and len(str(DEFAULT_MOD)) == 617
          and DEFAULT_MOD == u.DEFAULT_MOD)

    # a prime here would hand the leak a free d-th root -- see the module
    # docstring. Small factors would be just as bad: they expose enough of
    # the order to invert against.
    check("modulus       : default is composite (unknown order), no small factors",
          not ut.is_prime(DEFAULT_MOD, k=32)
          and all(DEFAULT_MOD % f for f in range(3, 50000, 2)))

    # The modulus travels in params, so a commitment under a DIFFERENT one
    # verifies without the library knowing anything about it. Driven with a
    # freshly generated modulus rather than a retired constant: testing a
    # constant against itself would only prove the constant exists.
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
    c_a, h_a, x_a, s_a, hm_a, perm_a, p_a = alt.opening()
    claims = {0: alt.vals[0]}
    ps_a = ps6(claims.keys(), h_a, hm_a, s_a, p_a)
    swapped = dict(p_a, mod=other_composite)
    try:
        vs6(c_a, claims, ps_a, x_a, perm_a, swapped)
        crossed = True
    except (AssertionError, ParamMismatch):
        crossed = False
    check("modulus       : proof does not verify under a substituted modulus",
          not crossed)


if __name__ == "__main__":
    standalone(run, "test_modulus checks")
