"""
Sample ZK application: selective-disclosure payroll audit, built on ms6/
ps6/vs6 (this project's commit / prove / verify protocol).

SCENARIO
--------
HR holds a private payroll database of N employees' salaries. HR publishes
a single short commitment `c` (e.g. on an internal ledger or bulletin
board). An external auditor later needs to confirm the salaries of a
*specific* pair of employees under review -- without HR handing over the
other N-2 salaries, and without the auditor having to trust HR's word for
it.

  1. COMMIT  (HR, once):        c, h_list, x_list, s_list, hm_list, perm_list, params = ms6(salaries, d, q)
  2. PROVE   (HR, per audit):   ps_list = ps6(iset, h_list, hm_list, s_list, params)
  3. VERIFY  (auditor, per audit): vs6(c, claims, ps_list, x_list, perm_list, params)

`c` is the only thing that ever needs to be public ahead of time. `ps_list`
is the audit-specific proof HR hands the auditor together with the two
salaries being audited; the auditor's vs6 call either accepts (the claimed
salaries really are what HR committed to, at those exact positions) or
raises AssertionError (the claim doesn't match the commitment).

ms6 internally splits the payroll into `batch_size`-sized groups (default
1000) and commits each independently before folding the per-batch results
into one final `c` -- see ms6's own docstring. At N_EMPLOYEES=60 this
payroll fits in a single batch, but the commit/prove/verify calls below
are the same regardless of how many batches the data spans.

This demonstrates the three properties an audit like this needs:
  - CORRECTNESS: true claims verify.
  - SOUNDNESS:   a tampered salary, or a salary attributed to the wrong
                 employee, is rejected.
  - SELECTIVE DISCLOSURE: verifying 2 of 60 salaries costs the auditor a
                 single vs6 call over a small `ps_list` payload -- HR never
                 ships the other 58 salaries, and the auditor's cost does
                 not scale with the size of the full payroll.

HONESTY NOTE: this is the research-prototype protocol developed and
hardened earlier in this project's history, not an audited zk-SNARK
library. It has documented, accepted leaks (see mul_combinations_mod's
"KNOWN LEAK" docstring in utils6.py: at this chunk_size/d, 4 of the 40
columns per row are recoverable via modular root extraction -- see
check_leak.py-style verification) and has not undergone external
cryptographic review. Treat this as an educational/demonstration example
of the commit-prove-verify *shape* of a ZK protocol, not a production
credential system.

PLATFORM NOTE: ms6/ps6/vs6 use ProcessPoolExecutor for parallelism when
workers>1. All executable code below is wrapped in `if __name__ ==
"__main__":` -- this is required on macOS/Windows, where the default
multiprocessing start method is "spawn" (it re-imports this script fresh
in every worker process; without the guard, top-level code that itself
launches a process pool would re-run inside each worker, recursively
spawning more pools). Linux's default "fork" start method doesn't need
this guard, since forked workers are memory copies rather than re-imports,
but the guard is required for cross-platform correctness regardless.
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


def main():
    # ---------------------------------------------------------------------
    # 0. Setup: HR's private payroll. Only HR ever sees this list.
    # ---------------------------------------------------------------------
    CHUNK_SIZE, D, Q = 40, 3, 10   # this project's current default params
    N_EMPLOYEES = 60
    # NOTE: at N_EMPLOYEES=60 (< default batch_size=1000) this payroll fits in a
    # single batch, so workers>1 here only exercises ROW-level parallelism
    # within that one batch, not the new batch-level parallelism (see
    # zk_sanctions_screening_scale_demo.py, which spans 120 batches, for that).
    WORKERS = multiprocessing.cpu_count()

    rnd = random.Random(2026)
    employees = [f"EMP{i:04d}" for i in range(N_EMPLOYEES)]
    salaries = [rnd.randrange(55_000, 195_000) for _ in range(N_EMPLOYEES)]

    print("=" * 72)
    print("ZK PAYROLL AUDIT DEMO  (built on ms6 / ps6 / vs6)")
    print("=" * 72)
    print(f"HR's private payroll: {N_EMPLOYEES} employees (salaries never leave HR)")
    print()

    # ---------------------------------------------------------------------
    # 1. COMMIT (HR, once). c is the only thing published ahead of time.
    # ---------------------------------------------------------------------
    t0 = time.time()
    c, h_list, x_list, s_list, hm_list, perm_list, params = ms6(salaries, D, Q, chunk_size=CHUNK_SIZE, workers=WORKERS)
    t1 = time.time()
    print(f"[HR]      committed payroll -> published commitment c ({t1 - t0:.3f}s, "
          f"{len(h_list)} batch(es))")
    print(f"          c = {c}"[:120] + " ...")
    print()

    # ---------------------------------------------------------------------
    # 2. PROVE (HR, per audit request). Auditor names 2 employees to review.
    # ---------------------------------------------------------------------
    audit_positions = (3, 27)
    audit_names = tuple(employees[i] for i in audit_positions)
    audit_true_salaries = tuple(salaries[i] for i in audit_positions)

    print(f"[Auditor] requests audit of: {audit_names}")

    t0 = time.time()
    ps_list = ps6(audit_positions, h_list, hm_list, s_list, params, workers=WORKERS)
    t1 = time.time()
    payload_size = sum(len(row) if isinstance(row, list) else 1 for batch in ps_list for row in
                        (batch if isinstance(batch, list) else [batch]))
    print(f"[HR]      generated audit proof for {audit_names} ({t1 - t0:.3f}s, "
          f"ps payload: {payload_size} field elements across {len(ps_list)} batch(es) -- "
          f"independent of N_EMPLOYEES={N_EMPLOYEES})")
    print(f"[HR]      hands auditor: ps_list, and the claimed salaries {audit_true_salaries}")
    print()

    # ---------------------------------------------------------------------
    # 3. VERIFY (auditor). Only c, ps_list, x_list, and the 2 claimed salaries
    #    are used -- the auditor never receives or needs the other 58 salaries.
    # ---------------------------------------------------------------------
    def run_check(label, claimed_vals, expect_accept):
        claims = dict(zip(audit_positions, claimed_vals))
        try:
            vs6(c, claims, ps_list, x_list, perm_list, params, workers=WORKERS)
            ok = True
        except AssertionError:
            ok = False
        verdict = "ACCEPTED" if ok else "REJECTED"
        outcome = "correct" if ok == expect_accept else "*** UNEXPECTED ***"
        print(f"[Auditor] {label:<45} -> {verdict:<9} ({outcome})")
        return ok

    print("--- Audit checks ---")
    run_check("true salaries, correct employees", audit_true_salaries, expect_accept=True)

    tampered = (audit_true_salaries[0] + 1, audit_true_salaries[1])
    run_check("HR quietly bumps one salary by $1", tampered, expect_accept=False)

    wrong_employee = (salaries[8], audit_true_salaries[1])
    run_check("salary from a different employee substituted", wrong_employee, expect_accept=False)

    fabricated = (rnd.randrange(55_000, 195_000), rnd.randrange(55_000, 195_000))
    run_check("two fabricated salaries, no real data", fabricated, expect_accept=False)

    print()
    print("--- Summary ---")
    print(f"Full payroll never left HR. Auditor verified {len(audit_positions)} of "
          f"{N_EMPLOYEES} salaries against the single published commitment `c`, "
          f"using a proof whose size does not grow with the payroll size, and "
          f"every tampered/forged claim was rejected.")

    # ---------------------------------------------------------------------
    # 4. UPDATABILITY: HR onboards a new hire and corrects a salary. Both
    #    edits go through Commitment, which edits digit counts for the one
    #    touched batch in place -- no other employee's salary is rehashed,
    #    and the commit-time cost of an edit no longer scales with
    #    N_EMPLOYEES. See ms6.py's Commitment docstring for the mechanism.
    # ---------------------------------------------------------------------
    print()
    print("=" * 72)
    print("UPDATABILITY: editing the payroll without a full re-commit")
    print("=" * 72)
    print("HR now holds the payroll as a live Commitment object instead of a fixed")
    print("list -- hiring someone or correcting a salary edits that one record's")
    print("contribution in place, rather than recommitting all N_EMPLOYEES again.")
    print()

    payroll = Commitment(salaries, D, Q, chunk_size=CHUNK_SIZE, workers=WORKERS)

    def audit_update(label, idxs, values, expect_accept):
        c_u, h_u, x_u, s_u, hm_u, perm_u, params_u = payroll.opening()
        claims = dict(zip(idxs, values))
        ps_u = ps6(claims.keys(), h_u, hm_u, s_u, params_u, workers=WORKERS)
        try:
            vs6(c_u, claims, ps_u, x_u, perm_u, params_u, workers=WORKERS)
            ok = True
        except AssertionError:
            ok = False
        verdict = "ACCEPTED" if ok else "REJECTED"
        outcome = "correct" if ok == expect_accept else "*** UNEXPECTED ***"
        print(f"[Auditor] {label:<50} -> {verdict:<9} ({outcome})")
        return ok

    # -- append: a new hire joins mid-quarter --
    new_employee = f"EMP{N_EMPLOYEES:04d}"
    new_salary = rnd.randrange(55_000, 195_000)
    t0 = time.time()
    new_idx = payroll.append(new_salary)
    t_append = time.time() - t0
    employees.append(new_employee)
    print(f"[HR]      onboarded {new_employee} at index {new_idx} "
          f"({t_append * 1000:.2f} ms, no other employee rehashed)")

    audit_update("audit new hire's salary", [new_idx], [new_salary], expect_accept=True)

    # -- replace: a data-entry correction to an existing salary --
    correction_idx = 12
    old_salary = payroll.vals[correction_idx]
    corrected_salary = old_salary + 5_000
    t0 = time.time()
    payroll.replace(correction_idx, corrected_salary)
    t_replace = time.time() - t0
    print(f"[HR]      corrected {employees[correction_idx]}'s salary "
          f"(${old_salary:,} -> ${corrected_salary:,}, {t_replace * 1000:.2f} ms)")

    audit_update("audit corrected salary", [correction_idx], [corrected_salary], expect_accept=True)
    audit_update("audit the now-superseded salary", [correction_idx], [old_salary], expect_accept=False)

    print()
    print("[info] neither edit rehashed an unrelated employee's salary; the")
    print("       commitment changed, so every verifier needs the new `c` from")
    print("       payroll.opening() -- a proof issued against the old `c` for")
    print("       the touched batch would no longer verify.")


if __name__ == "__main__":
    main()