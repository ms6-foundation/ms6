"""Adversarial suite: batch-routing coverage plus tamper/forge attempts.

Exercises claims within one batch, spanning several with untouched batches in
between, in the uneven final batch, and a fully-claimed batch (empty oset) --
then tries to break it: tampered values, wrong-index substitution, fabricated
values, cross-batch swaps, an iset/proof mismatch, and hm equivocation at both
claimed (iset) and unclaimed (oset) positions.

Two things here are load-bearing rather than stylistic:

  * the __main__ guard and run() wrapper -- this spawns process pools at
    workers=4, and under spawn each child re-imports the module. At module
    level the whole suite re-ran inside every child (see test_completeness.py
    for the same fix).
  * results go through the shared `check`. The original helpers printed
    "FAIL (forged proof ACCEPTED!)" and then returned normally, so a genuine
    forgery would have been reported and still exited 0 -- coverage that reads
    as real but cannot gate CI.
"""
import random
import sys

sys.set_int_max_str_digits(2000000)

from tests.harness import ms6, ps6, vs6, chunk_of, M, standalone  # noqa: E402


def run(check):
    chunk_size, d, q = 10, 3, 10
    BATCH_SIZE = 20
    N = 97   # deliberately not a multiple of BATCH_SIZE -> uneven last batch
    vals = [(1720941241 + (i**70) ^ (i**99)) % 2**200 for i in range(N)]
    rnd = random.Random(42)
    WORKERS = 4  # exercise the batch-level AND row-level parallel paths

    def expect_pass(name, fn):
        try:
            fn()
            ok = True
        except Exception:
            ok = False
        return check(f"adversarial   : {name}", ok)

    def expect_reject(name, fn):
        try:
            fn()
            ok = False          # accepted a proof it should have refused
        except AssertionError:
            ok = True
        except Exception:
            ok = True           # refused via an error is still a refusal
        return check(f"adversarial   : {name} -- rejected", ok)

    c, h_list, x_list, s_list, hm_list, perm_list, h1_salt_list, params = ms6(vals, d, q, chunk_size=chunk_size, batch_size=BATCH_SIZE, workers=WORKERS)
    n_batches = len(h_list)
    print(f"n_batches={n_batches} (N={N}, batch_size={BATCH_SIZE}, workers={WORKERS})")

    def verify(claims, ps_list=None):
        if ps_list is None:
            ps_list = ps6(claims.keys(), h_list, hm_list, s_list, params, workers=WORKERS)
        vs6(c, claims, ps_list, x_list, perm_list, h1_salt_list, params, workers=WORKERS)

    # 1. single claim, single batch
    claims1 = {5: vals[5]}
    expect_pass("single claim (batch 0)", lambda: verify(claims1))

    # 2. two claims in the SAME batch
    claims2 = {2: vals[2], 7: vals[7]}
    expect_pass("two claims, same batch", lambda: verify(claims2))

    # 3. claims spanning multiple batches, with an untouched batch in between
    claims3 = {5: vals[5], 45: vals[45], 90: vals[90]}   # batches 0, 2, 4 (batch 1,3 untouched)
    expect_pass("claims spanning 3 batches, gaps between", lambda: verify(claims3))

    # 4. claim in the last (short/uneven) batch
    last_idx = N - 1
    claims4 = {last_idx: vals[last_idx]}
    expect_pass(f"claim in final uneven batch (idx {last_idx})", lambda: verify(claims4))

    # 5. claim EVERY item in one batch (fully-claimed batch, oset empty for it)
    batch0_idxs = list(range(0, BATCH_SIZE))
    claims5 = {i: vals[i] for i in batch0_idxs}
    expect_pass("fully-claimed batch (oset empty)", lambda: verify(claims5))

    # 6. claim spanning ALL batches at once
    claims_all_idxs = [0, 25, 45, 65, 90]
    claims6 = {i: vals[i] for i in claims_all_idxs}
    expect_pass("claims touching every batch", lambda: verify(claims6))

    # --- adversarial ---

    # 7. tampered claim (+1)
    claims7_true = {5: vals[5], 45: vals[45]}
    ps7 = ps6(claims7_true.keys(), h_list, hm_list, s_list, params, workers=WORKERS)
    claims7_bad = {5: vals[5] + 1, 45: vals[45]}
    expect_reject("tampered claim (+1)", lambda: verify(claims7_bad, ps7))

    # 8. wrong-index substitution (real value, wrong position)
    claims8_bad = {5: vals[6], 45: vals[45]}   # vals[6] used at position 5
    expect_reject("wrong-index substitution", lambda: verify(claims8_bad, ps7))

    # 9. fully fabricated value, no real data
    claims9_bad = {5: rnd.randrange(2**200), 45: vals[45]}
    expect_reject("fully fabricated value", lambda: verify(claims9_bad, ps7))

    # 10. cross-batch swap: claim batch-0 item's value at a batch-2 position
    claims10_bad = {5: vals[5], 45: vals[5]}   # vals[5]'s value claimed at position 45 too
    expect_reject("cross-batch value swap", lambda: verify(claims10_bad, ps7))

    # 11. proof for a DIFFERENT iset than what's actually claimed (iset/claims mismatch)
    ps11 = ps6([5], h_list, hm_list, s_list, params, workers=WORKERS)
    claims11 = {45: vals[45]}   # claiming idx 45 but proof only opened idx 5
    expect_reject("claims/proof iset mismatch", lambda: verify(claims11, ps11))

    # 12. equivocation, iset position: fabricate hm at a CLAIMED (iset) position.
    # _ps6_batch's oset excludes iset entirely, so this is expected to be a
    # no-op -- ps6 never reads hm[iset], so claiming the TRUE value should
    # still verify (mirrors the single-batch protocol's own documented
    # behavior: "hm[iset] tampered, but TRUE vals claimed -> still verifies").
    hm_list_fake = [list(hm_b) for hm_b in hm_list]
    fake_val = rnd.randrange(2**200)
    fake_h1s = M.ut.domain_hash(f"{M.H1_TAG}:{h1_salt_list[0]}:{fake_val}".encode())
    x0 = x_list[0]
    fake_hm_row = chunk_of(fake_h1s, x0, chunk_size)
    hm_list_fake[0][5] = fake_hm_row
    ps12 = ps6([5], h_list, hm_list_fake, s_list, params, workers=WORKERS)
    claims12 = {5: vals[5]}
    expect_pass("hm[iset] tampered (claimed pos), TRUE val claimed -> no-op, still verifies",
                lambda: verify(claims12, ps12))

    # 13. equivocation, real forgery attempt: same corrupted hm_list, but now
    # claim the FAKE value itself instead of the true one -- should be
    # rejected (the fake hm was never read by ps6, so `ps`/h don't reflect it;
    # claiming the fake value just makes a false claim against a valid proof).
    claims13 = {5: fake_val}
    expect_reject("hm[iset] tampered, claim the FAKE val itself", lambda: verify(claims13, ps12))

    # 14. equivocation, OSET position: fabricate hm at an UNCLAIMED (oset)
    # position within a batch. oset DOES read this entry, so the batch's own
    # `ps` now reflects fabricated data -- even a TRUE claim for a position
    # in that same batch should be rejected, since `ps` no longer matches
    # what ms6's commitment was built from.
    hm_list_fake2 = [list(hm_b) for hm_b in hm_list]
    fake_val2 = rnd.randrange(2**200)
    fake_h1s2 = M.ut.domain_hash(f"{M.H1_TAG}:{h1_salt_list[0]}:{fake_val2}".encode())
    fake_hm_row2 = chunk_of(fake_h1s2, x0, chunk_size)
    hm_list_fake2[0][12] = fake_hm_row2   # position 12: same batch (0) as claimed pos 5, itself unclaimed
    ps14 = ps6([5], h_list, hm_list_fake2, s_list, params, workers=WORKERS)
    claims14 = {5: vals[5]}
    expect_reject("hm[oset] tampered (unclaimed pos, same batch), claim true val elsewhere",
                  lambda: verify(claims14, ps14))

    # 15. INJECTIVITY of the digit encoding. This is what binds the grid, and
    # it is a property of the ENCODING, not of the modulus: an unknown-order
    # ring cannot restore injectivity that the encoding discarded before the
    # modulus was ever applied. Nothing else in the suite would catch a
    # regression here -- test_parity only checks the two copies agree, which a
    # colliding encoding satisfies just as well.
    #
    # The collisions below are the ones a digit-as-base product actually had.
    # Each pair is (multiset A, multiset B) with A != B; the encoding must
    # separate every pair.
    collisions = [
        ([6],       [2, 3]),        # 6 = 2*3
        ([4],       [2, 2]),        # 4 = 2^2
        ([9],       [3, 3]),        # 9 = 3^2
        ([8],       [2, 2, 2]),     # 8 = 2^3
        ([1, 1, 1, 6], [2, 3]),     # plus 1 contributing nothing
    ]

    def counts(digits):
        c = [0] * 11
        for dg in digits:
            c[dg] += 1
        return c

    sep = all(M.ut.cell_product(counts(a), 1) != M.ut.cell_product(counts(b), 1)
              for a, b in collisions)
    check("adversarial   : digit encoding separates all known collisions "
          "(binding depends on this, not on the modulus)", sep)

    # and injectivity in the large: no two distinct 4-digit multisets may
    # share a cell value
    seen, injective = {}, True
    for a in range(10):
        for b in range(a, 10):
            for c_ in range(b, 10):
                for e in range(c_, 10):
                    key = M.ut.cell_product(counts([a, b, c_, e]), 1)
                    if key in seen:
                        injective = False
                    seen[key] = (a, b, c_, e)
    check("adversarial   : no two distinct 4-digit multisets share a cell value",
          injective)


if __name__ == "__main__":
    standalone(run, "test_adversarial checks")
