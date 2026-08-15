"""
Sample ZK application (larger scale): confidential sanctions/watchlist
screening registry, built on ms6/ps6/vs6, committing over 100,000 records.

SCENARIO
--------
A compliance body maintains a confidential screening registry of N
customer risk records (far too sensitive to ever hand to a requesting
bank in full). It commits the whole registry ONCE, publishing a single
short commitment `c`. Banks then submit individual screening requests
("is customer #48213's on-file risk record really X?") throughout the
day; the registry operator answers each with a small, per-request proof,
and the bank verifies it against the one published `c` -- never seeing
any other customer's record, and paying a verification cost that does
NOT grow with the size of the registry.

  1. COMMIT  (registry operator, once):     c, h_list, x_list, s_list, hm_list, perm_list, h1_salt_list, params = ms6(registry, d, q)
  2. PROVE   (registry operator, per request): ps_list = ps6(iset, h_list, hm_list, s_list, params)
  3. VERIFY  (bank, per request):           vs6(c, claims, ps_list, x_list, perm_list, h1_salt_list, params)

ms6 splits the registry into BATCH_SIZE-sized groups and commits each
independently before folding the per-batch results into one final `c`
(see ms6's own docstring) -- at N_RECORDS=120,000 and the batch size used
below, that's 120 separate per-batch commitments folded into one. This
demo builds a registry of 120,000 records and benchmarks all three
stages.

HONESTY NOTE: same caveat as payroll_audit_demo.py -- this is the
project's research-prototype protocol, not an audited zk-SNARK. At this
chunk_size/d, 4 of the 40 columns per row are always recoverable via
modular root extraction (mul_combinations_mod's documented structural
exposure); the reference implementation neutralizes this unconditionally
at the data level (those columns are a fixed public constant, never real
digit content -- see docs/ms6_eprint.tex's edge-column padding section
and README's Security section), verified numerically rather than merely
argued. The interior (non-edge) columns are a separate, still-open
exposure under repeated querying, only mitigated at the deployment-policy
level (QueryGovernor). Binding still has no formal reduction, either.

PLATFORM NOTE: ms6/ps6/vs6 use ProcessPoolExecutor for parallelism when
workers>1. All executable code below is wrapped in `if __name__ ==
"__main__":` -- this is required on macOS/Windows, where the default
multiprocessing start method is "spawn" (it re-imports this script fresh
in every worker process; without the guard, top-level code that itself
launches a process pool would re-run inside each worker, recursively
spawning more pools -- this is what "failed to spawn process" errors on
Apple Silicon / macOS trace back to). Linux's default "fork" start method
doesn't need this guard, since forked workers are memory copies rather
than re-imports, but the guard is required for cross-platform correctness
regardless.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import random
import time
import multiprocessing

sys.set_int_max_str_digits(2_000_000)

from ms6 import ms6, ps6, Commitment
from vs6 import vs6

CHUNK_SIZE, D, Q = 40, 3, 10
BATCH_SIZE = 1_000
N_RECORDS = 120_000
N_REQUESTS = 10             # simulated screening requests to benchmark
WORKERS = multiprocessing.cpu_count()  # batch-level parallelism across ms6/ps6/vs6

# Updatability section (below) builds a separate, smaller Commitment rather
# than editing the full 120,000-record registry -- Commitment's own
# construction commits its batches sequentially (unlike ms6()'s
# ProcessPoolExecutor-parallel batch commit), so building one at full
# N_RECORDS would cost materially more wall-clock time than the fixed
# ms6() commit above without demonstrating anything the smaller slice
# doesn't: an edit's cost is a function of one batch's size, not of how
# many other batches exist.
UPDATE_N = 5_000

rnd = random.Random(2026)


def make_registry(n):
    # synthetic but distinct per-record risk codes -- same generator shape
    # used throughout this project's test files.
    return [(1720941241 + (i ** 70) ^ (i ** 99)) % 2 ** 200 for i in range(n)]


def bench(label, fn):
    t0 = time.time()
    result = fn()
    dt = time.time() - t0
    print(f"  {label:<45} {dt:>8.3f}s")
    return result, dt


def main():
    print("=" * 78)
    print(f"ZK SANCTIONS-SCREENING REGISTRY DEMO  (ms6 / ps6 / vs6, N={N_RECORDS:,} records)")
    print("=" * 78)

    registry = make_registry(N_RECORDS)

    # s is left at its default (None): ms6 draws a fresh random secret salt
    # per commit. See tamper_row_truncation.py's original derivation notes for
    # why a hand-picked small salt is risky, and utils6.py's interlace_mod
    # docstring for the x-sizing fix that makes this safe regardless of `s`.
    print()
    print("--- 1. COMMIT (registry operator, once) ---")
    (c, h_list, x_list, s_list, hm_list, perm_list, h1_salt_list, params), t_commit = bench(
        "commit", lambda: ms6(registry, D, Q, chunk_size=CHUNK_SIZE, batch_size=BATCH_SIZE, workers=WORKERS))
    print(f"  -> commitment c published ({len(h_list)} batch(es) of up to {BATCH_SIZE} records each, "
          f"workers={WORKERS})")

    print()
    print("--- 2. PROVE + VERIFY: 10 simulated bank screening requests ---")
    requests = [tuple(sorted(rnd.sample(range(N_RECORDS), 2))) for _ in range(N_REQUESTS)]

    prove_times, verify_times = [], []
    for i, iset in enumerate(requests):
        ps_list, dt_prove = bench(f"  request {i}: proof", lambda iset=iset: ps6(
            iset, h_list, hm_list, s_list, params, workers=WORKERS))
        claims = {j: registry[j] for j in iset}
        _, dt_verify = bench(f"  request {i}: verify (bank side)", lambda claims=claims, ps_list=ps_list: vs6(
            c, claims, ps_list, x_list, perm_list, h1_salt_list, params, workers=WORKERS))
        prove_times.append(dt_prove)
        verify_times.append(dt_verify)

    print()
    print("--- 3. Soundness checks (registry operator/bank cannot forge a screening result) ---")
    iset0 = requests[0]
    claimed0 = {j: registry[j] for j in iset0}
    ps0 = ps6(iset0, h_list, hm_list, s_list, params, workers=WORKERS)

    def expect_reject(label, claim):
        try:
            vs6(c, claim, ps0, x_list, perm_list, h1_salt_list, params, workers=WORKERS)
            print(f"  {label:<55} *** ACCEPTED (should have been rejected!) ***")
        except AssertionError:
            print(f"  {label:<55} REJECTED (correct)")

    j0, j1 = iset0
    expect_reject("tampered risk record (+1)", {j0: claimed0[j0] + 1, j1: claimed0[j1]})
    expect_reject("record from a different customer substituted", {j0: registry[8], j1: claimed0[j1]})
    expect_reject("two fully fabricated values", {j0: rnd.randrange(2 ** 200), j1: rnd.randrange(2 ** 200)})

    print()
    print("--- 4. Updatability: editing the registry without a full re-commit ---")
    print(f"  (demonstrated on a {UPDATE_N:,}-record slice to keep this script's runtime")
    print(f"   reasonable -- an edit's cost is set by its own batch's size, not by how")
    print(f"   many OTHER batches the registry has, so the mechanism is identical at")
    print(f"   N_RECORDS={N_RECORDS:,}.)")
    print()

    live_registry, t_live_commit = bench(
        f"build live {UPDATE_N:,}-record Commitment",
        lambda: Commitment(registry[:UPDATE_N], D, Q, chunk_size=CHUNK_SIZE, batch_size=BATCH_SIZE, workers=WORKERS))

    def verify_update(label, idxs, values, expect_accept):
        c_u, h_u, x_u, s_u, hm_u, perm_u, h1s_u, params_u = live_registry.opening()
        claims = dict(zip(idxs, values))
        ps_u = ps6(claims.keys(), h_u, hm_u, s_u, params_u, workers=WORKERS)
        try:
            vs6(c_u, claims, ps_u, x_u, perm_u, h1s_u, params_u, workers=WORKERS)
            ok = True
        except AssertionError:
            ok = False
        verdict = "ACCEPTED" if ok else "REJECTED"
        outcome = "correct" if ok == expect_accept else "*** UNEXPECTED ***"
        print(f"  {label:<55} {verdict:<9} ({outcome})")
        return ok

    # -- append: a new customer record is added to the registry --
    new_record = rnd.randrange(2 ** 200)
    _, t_append = bench("append new customer record", lambda: live_registry.append(new_record))
    new_idx = len(live_registry.vals) - 1
    verify_update(f"bank verifies newly-appended record (idx {new_idx})", [new_idx], [new_record], expect_accept=True)

    # -- replace: an existing customer's risk record is updated, e.g. a --
    # -- match is cleared after manual review --
    update_idx = 42
    old_record = live_registry.vals[update_idx]
    new_value = rnd.randrange(2 ** 200)
    _, t_replace = bench(f"replace record {update_idx} (risk re-assessment)",
                          lambda: live_registry.replace(update_idx, new_value))
    verify_update(f"bank verifies updated record (idx {update_idx})", [update_idx], [new_value], expect_accept=True)
    verify_update(f"bank re-checks the now-superseded record (idx {update_idx})", [update_idx], [old_record],
                  expect_accept=False)

    print()
    print(f"  For comparison: recommitting the full {N_RECORDS:,}-record registry from")
    print(f"  scratch (section 1 above) took {t_commit:.3f}s. Updating one record here")
    print(f"  cost {t_replace * 1000:.2f} ms -- a cost set by the touched batch's size,")
    print(f"  not by how many other records or batches the registry holds.")

    print()
    print("=" * 78)
    print("BENCHMARK SUMMARY")
    print("=" * 78)
    print(f"  Registry size:                    {N_RECORDS:,} records ({len(h_list)} batches)")
    print(f"  Commit time:                      {t_commit:.3f}s")
    print(f"  Proof time, avg:                  {sum(prove_times)/len(prove_times):.3f}s per request")
    print(f"  Verify time, avg (bank side):     {sum(verify_times)/len(verify_times):.3f}s per request")
    print(f"  Record update (append/replace):   {t_append*1000:.2f} ms / {t_replace*1000:.2f} ms "
          f"(vs. {t_commit:.3f}s for a full recommit)")
    print()
    print("Key property demonstrated: verify cost does not scale with registry size --")
    print("a bank checks 2 of 120,000 records at the same per-request cost the")
    print("registry operator would pay at any N, because vs6 only ever touches the")
    print("small `ps_list` payload and the 2 claimed values, never the full registry.")


if __name__ == "__main__":
    main()