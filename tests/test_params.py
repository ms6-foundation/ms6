"""The shared parameter dict and its enforcement.

params reaches the verifier FROM the prover: it carries no secrets but is
not self-authenticating, so structural validation always runs and expect=
pins it against out-of-band agreement."""
from tests.harness import (  # noqa: F401
    ms6, ps6, Commitment, vs6, ParamMismatch,
    make_params, unpack_params, PARAM_KEYS, VS6_PARAM_KEYS,
    _seal_batch, _SealTree, chunk_of, chunks, _column_perm,
    _permute_row, _get_batch_ids, DEFAULT_MOD, ut, gen, u, M, V,
    vs6pkg, D, Q, U_CS, U_BS, mk, proves, proves_with_expect,
    rebuilt, standalone,
)


def run(check):
    base = [mk(i) for i in range(12)]
    extra = [mk(i) for i in range(100, 107)]
    B = rebuilt(Commitment(base + extra, D, Q, chunk_size=U_CS,
                           batch_size=U_BS, s_mod=ut.generate_prime(256)),
                base + extra)
    c_b, h_b, x_b, s_b, hm_b, perm_b, h1s_b, p_b = B.opening()
    # -- params enforcement ---------------------------------------------
    p_ok = B.params
    check("params        : correct expect= accepted",
          proves_with_expect(B, [0], dict(p_ok)))

    def rejects(expect_or_params, use_as_expect=True):
        try:
            if use_as_expect:
                vs6(c_b, {0: B.vals[0]}, ps6({0}, h_b, hm_b, s_b, p_b, B.d), x_b, perm_b, h1s_b, p_b, B.d,
                    expect=expect_or_params)
            else:
                vs6(c_b, {0: B.vals[0]}, ps6({0}, h_b, hm_b, s_b, p_b, B.d), x_b, perm_b, h1s_b,
                    expect_or_params, B.d)
            return False
        except ParamMismatch:
            return True

    check("params        : d not present in params/expect (moved out, "
          "pre-shared only)",
          "d" not in p_ok and "d" not in PARAM_KEYS)

    def wrong_d_fails(wrong_d):
        """d is no longer pinnable via expect= (see PARAM_KEYS's own comment
        -- it isn't a params key at all any more), so a wrong d can't surface
        as a params-mismatch in the pinning sense. It still can't verify
        silently either: reconstruction itself breaks -- AssertionError
        (final h==c check) if wrong_d is low, typically IndexError (walking
        past the end of a sweep sized by the prover's true, lower degree) if
        wrong_d is high. Since the gcd(d, mod-1) binding guard (ms6_vibe.md
        entry 78), a wrong_d that happens to share a factor with (prime)
        mod-1 -- any even wrong_d, since mod-1 is always even for an odd
        prime -- is instead rejected immediately as ParamMismatch, before
        reconstruction even runs. All three count as correctly rejected
        here: the point is that a mismatched d never verifies, not which
        mechanism catches it first."""
        try:
            vs6(c_b, {0: B.vals[0]}, ps6({0}, h_b, hm_b, s_b, p_b, B.d), x_b, perm_b, h1s_b, p_b, wrong_d)
            return False
        except (AssertionError, IndexError, ParamMismatch):
            return True

    check("params        : wrong d (lower) fails verification",
          wrong_d_fails(B.d - 1) if B.d > 1 else True)
    check("params        : wrong d (higher) fails verification",
          wrong_d_fails(B.d + 1))
    check("params        : wrong pinned mod rejected", rejects({"mod": p_ok["mod"] - 2}))
    check("params        : typo in expect key rejected", rejects({"chunck_size": 12}))
    check("params        : nonsense mod rejected",
          rejects({**p_ok, "mod": 1}, use_as_expect=False))
    check("params        : ms6/vs6 PARAM_KEYS agree", PARAM_KEYS == VS6_PARAM_KEYS)


if __name__ == "__main__":
    standalone(run, "test_params checks")
