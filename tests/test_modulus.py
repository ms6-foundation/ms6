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

Under a PRIME modulus specifically, pow(x, d, mod) is a bijection on
Z_mod* exactly when gcd(d, mod-1) == 1 -- elementary group theory, not an
assumption. ms6/ps6/vs6 now enforce this at entry (_validate_d in both
ms6/core.py and vs6/core.py) whenever mod is prime, which is what upgrades
the row-fold's binding argument from "no collision found in testing" to
"no collision exists" for the prime-modulus path. See README's Security
section and ms6_vibe.md entry 78.
"""
import math

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
    # gcd(d, p-1) == 1 is now an enforced precondition for a prime mod (see
    # module docstring), not just a property of the shipped default -- D=3
    # makes it fail for ~half of random primes (any p == 1 mod 3), so this
    # retries rather than risking a flaky ParamMismatch on an unrelated check.
    other_prime = ut.generate_prime(512)
    while math.gcd(d, other_prime - 1) != 1:
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

    # --- the gcd(d, mod-1) binding guard --------------------------------
    check("modulus       : gcd(d, DEFAULT_MOD - 1) == 1 -- the shipped "
          "default is a provable pow(x, d, mod) bijection, not just "
          "empirically uncollided",
          math.gcd(d, DEFAULT_MOD - 1) == 1)

    # Deliberately construct a prime that shares a factor with d, and
    # confirm commit-time (ms6, via Commitment) refuses it outright rather
    # than silently sealing a row-fold that is no longer injective.
    # ms6.core and vs6.core each define their OWN ParamMismatch (see
    # vs6/utils6.py's module docstring on package independence -- vs6/
    # core.py has zero import-time dependency on ms6/core.py, so it can't
    # just import ms6's exception type). `ParamMismatch` here (from
    # tests.harness) is specifically vs6's; ms6-side raises need M.ParamMismatch.
    bad_prime = ut.generate_prime(256)
    while math.gcd(d, bad_prime - 1) == 1:
        bad_prime = ut.generate_prime(256)
    try:
        Commitment(base, d, q, chunk_size=u_cs, batch_size=u_bs,
                   mod=bad_prime, s_mod=ut.generate_prime(256))
        guarded_commit = False
    except M.ParamMismatch:
        guarded_commit = True
    check("modulus       : commit-time (ms6, via Commitment) rejects d "
          "not coprime to (prime mod - 1) -- would otherwise reopen a "
          "genuine row-fold collision, not just make root-extraction "
          "ambiguous",
          guarded_commit)

    # Same bad pairing, reached directly through ps6()/vs6() with a
    # hand-substituted params dict (built from alt's own valid opening
    # under other_prime) rather than through Commitment -- confirms the
    # guard lives in _validate_d itself and fires from all three entry
    # points, not just Commitment's wrapper around ms6().
    bad_params = dict(p_a, mod=bad_prime)
    try:
        ps6(claims.keys(), h_a, hm_a, s_a, bad_params, d)
        guarded_ps6 = False
    except M.ParamMismatch:
        guarded_ps6 = True
    check("modulus       : ps6() itself rejects the bad (d, prime mod) "
          "pairing",
          guarded_ps6)

    try:
        vs6(c_a, claims, ps_a, x_a, perm_a, h1s_a, bad_params, d)
        guarded_vs6 = False
    except ParamMismatch:
        guarded_vs6 = True
    check("modulus       : vs6() itself rejects the bad (d, prime mod) "
          "pairing",
          guarded_vs6)

    # The guard is specific to PRIME moduli (gcd against mod-1 is only the
    # right question when the group order is public and equal to mod-1).
    # A composite modulus must accept the same d unconditionally -- its
    # binding case is the Strong-RSA-style argument instead, not this one.
    alt3 = Commitment(base, d, q, chunk_size=u_cs, batch_size=u_bs,
                      mod=other_composite, s_mod=ut.generate_prime(256))
    check("modulus       : composite modulus path is unaffected by the "
          "gcd guard (binding there rests on Strong-RSA-style hardness, "
          "not pow(x, d, mod) bijectivity)",
          alt3.params["mod"] == other_composite and proves(alt3, [0, 5, 11]))


if __name__ == "__main__":
    standalone(run, "test_modulus checks")
