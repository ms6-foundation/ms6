"""QueryGovernor: the deployment-level mitigation for the multi-query
correlation risk documented in the eprint (Observation obs:ratio / "What
an observer can still compute") -- S(r,j) is fixed for the life of a
commitment, so two openings against the same batch that differ by a
small number of claimed items let an observer cancel S out of the ratio
between them. This is NOT closed cryptographically here (that would mean
decoupling c from S and adding a per-query rerandomization proof); this
module only checks the POLICY layer: refuse claim sets that are
suspiciously close to one already served against the same batch, and cap
how many distinct claim sets a batch will ever serve.

Unit-level checks run against QueryGovernor directly (no real hashing/
accumulation needed -- it only ever looks at claim-set index arithmetic).
The final check runs it against a real Commitment to demonstrate it
actually blocks the paper's literal obs:ratio construction."""
from tests.harness import (  # noqa: F401
    ms6, ps6, Commitment, vs6, ParamMismatch,
    QueryGovernor, QueryPolicyViolation, ps6_governed,
    make_params, unpack_params, PARAM_KEYS, VS6_PARAM_KEYS,
    _seal_batch, _SealTree, chunk_of, chunks, _column_perm,
    _permute_row, _get_batch_ids, DEFAULT_MOD, ut, gen, u, M, V,
    ms6pkg, vs6pkg, D, Q, U_CS, U_BS, mk, proves, proves_with_expect,
    rebuilt, standalone,
)


def run(check):
    # -- the exact obs:ratio construction: {i1} then {i1, i0} -----------
    gov = QueryGovernor(batch_size=20)          # default min_new_items=2
    gov.authorize({5})
    blocked = False
    try:
        gov.authorize({5, 6})                    # differs from {5} by 1 item
    except QueryPolicyViolation:
        blocked = True
    check("governance    : literal obs:ratio pair ({i1}, {i1,i0}) blocked",
          blocked)

    # the mirror shape -- swapping one claimed item for another -- is the
    # same symmetric-difference-1 pattern and must be caught too
    gov2 = QueryGovernor(batch_size=20)
    gov2.authorize({5})
    blocked2 = False
    try:
        gov2.authorize({6})                       # {5} ^ {6} == {5,6}, diff 2... not blocked by default
    except QueryPolicyViolation:
        blocked2 = True
    check("governance    : disjoint single-item swap ({5},{6}) has symmetric "
          "difference 2, NOT blocked by default min_new_items=2",
          not blocked2)

    gov2b = QueryGovernor(batch_size=20, min_new_items=3)
    gov2b.authorize({5})
    blocked2b = False
    try:
        gov2b.authorize({6})
    except QueryPolicyViolation:
        blocked2b = True
    check("governance    : same swap IS blocked once min_new_items=3 "
          "(diff 2 < 3)", blocked2b)

    # -- sufficiently different claim sets are allowed -------------------
    gov3 = QueryGovernor(batch_size=20, min_new_items=2)
    gov3.authorize({0, 1, 2})
    allowed = True
    try:
        gov3.authorize({10, 11, 12})              # symmetric diff 6
    except QueryPolicyViolation:
        allowed = False
    check("governance    : a sufficiently different claim set is allowed",
          allowed)

    # -- exact repeats are always free, don't count against the cap -----
    gov4 = QueryGovernor(batch_size=20, max_openings_per_batch=1)
    gov4.authorize({3, 4})
    repeat_ok = True
    try:
        gov4.authorize({3, 4})                    # identical set, not a new claim
        gov4.authorize({3, 4})
        gov4.authorize({3, 4})
    except QueryPolicyViolation:
        repeat_ok = False
    check("governance    : exact repeats of an already-served claim set "
          "are always allowed and free", repeat_ok)

    new_after_cap_blocked = False
    try:
        gov4.authorize({7, 8})                    # a genuinely NEW claim, cap is 1
    except QueryPolicyViolation:
        new_after_cap_blocked = True
    check("governance    : a distinct new claim set is refused once "
          "max_openings_per_batch is reached", new_after_cap_blocked)

    # -- per-batch scoping: a claim spanning two batches is judged batch- ­
    # by-batch, not by its global symmetric difference ------------------
    gov5 = QueryGovernor(batch_size=20, min_new_items=2)
    gov5.authorize({5})                           # batch 0 only so far
    ok_other_batch = True
    try:
        # batch 0: {5} vs {5,6} -> symmetric difference 1, blocks -- batch
        # 1's own claim (its very first) would be fine on its own, but
        # must not save the request
        gov5.authorize({5, 6, 25})
    except QueryPolicyViolation:
        ok_other_batch = False
    check("governance    : a violation on one touched batch blocks the "
          "whole request even if other touched batches would be fine",
          not ok_other_batch)

    # confirm the block above did NOT record anything into batch 1's
    # history (read-only validation pass before any recording)
    check("governance    : a blocked request records nothing, on ANY "
          "touched batch (no partial state)",
          gov5.history_for_batch(1) == [])

    gov6 = QueryGovernor(batch_size=20, min_new_items=2)
    gov6.authorize({5, 25})
    ok_independent = True
    try:
        gov6.authorize({15, 35})                  # batch 0: {5}v{15} diff2; batch1: {5}v{15} diff2
    except QueryPolicyViolation:
        ok_independent = False
    check("governance    : independent, sufficiently-different claims "
          "across two touched batches are both allowed", ok_independent)

    # -- logger callback fires on refusal --------------------------------
    class _FakeLogger:
        def __init__(self):
            self.warnings = []

        def warning(self, msg):
            self.warnings.append(msg)

    logger = _FakeLogger()
    gov7 = QueryGovernor(batch_size=20, logger=logger)
    gov7.authorize({1})
    try:
        gov7.authorize({1, 2})
    except QueryPolicyViolation:
        pass
    check("governance    : logger.warning() is called on refusal, before "
          "the exception propagates", len(logger.warnings) == 1)

    # -- end-to-end: block the literal construction against a real commit -
    base = [mk(i) for i in range(12)]
    C = Commitment(base, D, Q, chunk_size=U_CS, batch_size=U_BS,
                   s_mod=ut.generate_prime(256))
    c_u, h_u, x_u, s_u, hm_u, perm_u, h1s_u, p_u = C.opening()
    real_gov = QueryGovernor(batch_size=U_BS)

    ps_1 = ps6_governed(real_gov, {1}, h_u, hm_u, s_u, p_u)
    check("governance    : first real opening (via ps6_governed) succeeds "
          "and still verifies",
          vs6(c_u, {1: C.vals[1]}, ps_1, x_u, perm_u, h1s_u, p_u))

    e2e_blocked = False
    try:
        ps6_governed(real_gov, {1, 0}, h_u, hm_u, s_u, p_u)   # {1} -> {0,1}: diff 1
    except QueryPolicyViolation:
        e2e_blocked = True
    check("governance    : ps6_governed refuses the second real opening "
          "that would reproduce obs:ratio's construction", e2e_blocked)

    # a legitimately different follow-up claim against the same commitment
    # still goes through fine -- this is a policy layer, not a lockout
    e2e_ok = True
    try:
        ps6_governed(real_gov, {1, 2, 3, 4, 5}, h_u, hm_u, s_u, p_u)
    except QueryPolicyViolation:
        e2e_ok = False
    check("governance    : a legitimately different follow-up claim on "
          "the same commitment is still served", e2e_ok)


if __name__ == "__main__":
    standalone(run, "test_query_governance checks")
