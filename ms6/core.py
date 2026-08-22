from random import SystemRandom, Random
import hashlib
from . import utils6 as u


try:
    from gmpy2 import mpz as _mpz

    def _s(v):
        return _mpz(v).digits()
except ImportError:                   # pragma: no cover
    _mpz = None
    _s = str

gen = SystemRandom()
ut = u.Utils()

FLUSH = 4096                          # iterations buffered before C-speed counting

# --- default parameters, shared by ms6 (commit) / ps6 (open) / vs6 (verify) ---
# 100, not 40: wide enough that ut.sparse_expand (see _hash_item's own
# docstring) has real headroom to fill past DOMAIN_HASH_DIGITS (78) with
# genuine per-item content rather than mostly u.PAD, AND wide enough that
# partition_menu(100)'s recursive, multi-level recipes (see ms6.utils6.
# Utils.partition_menu) offer a materially richer set of leaf-grouping
# shapes -- 111 total recipes, up to 3 levels deep -- than partition_
# menu(40) did (13 single-level entries) for the swappable fold to pick
# from at query time -- see ms6_vibe.md for the benchmark comparing
# eval_level_mod's flat combinatorial cost at this width against the
# grouped fold's own cost.
DEFAULT_CHUNK_SIZE = 100
DEFAULT_BATCH_SIZE = 1000
DEFAULT_WORKERS = 1
DEFAULT_KEEP_HM = True

# _seal_batch folds a list of scalars into one via a single Acc pass; for a
# large dataset the list it's folding (e.g. ms6's h_list, one entry per
# batch_size-sized batch) can itself exceed a sane single-pass size. Capped
# via seal_batch_size, recursively -- see _seal_batch's own docstring.
DEFAULT_SEAL_BATCH_SIZE = 1000

# Floor on the per-commit prime _seal_mod generates to re-seal a
# caller-supplied salt. 256 bits keeps the sealed salt out of brute-force
# range (and gives a 2^-256 fingerprint-collision bound) even when hmax is
# small for a particular dataset.
DEFAULT_SEAL_MOD_BITS = 256

# Shared accumulator modulus for ms6/ps6/vs6's core arithmetic (cell products,
# vsum_level_fold_mod, mul_combinations_mod, eval_level_mod). All three must
# use the exact same value or verification of honest proofs fails.
DEFAULT_MOD = u.DEFAULT_MOD

# The former default -- see u.LEGACY_MOD_2048's own comment for why it is
# no longer DEFAULT_MOD. Exported for any caller who wants the old
# unknown-order composite explicitly.
LEGACY_MOD_2048 = u.LEGACY_MOD_2048

# Modulus for building S (the secret-salt blinding grid) in _ms6_batch.
# Reuses DEFAULT_MOD rather than a separate ring: S's *value* travels to
# ps6 in s_list and is used there as a base in the mod-DEFAULT_MOD ring
# (pow(S[j], d, mod)), so ps6/vs6 need no separate knowledge of this
# constant -- only ms6-side code (_s0_grid, _seal_grid) ever reduces mod
# s_mod directly. Nothing requires the two rings to match; sharing one
# keeps the parameter surface smaller at no cost, since both are sized
# for the same reason (cheap modular arithmetic -- see DEFAULT_MOD's own
# comment in utils6.py).
#
# S is never sent to the verifier: only ps6's already-aggregated buckets
# are, and vs6 never reads s_mod or S directly. What makes two commits of
# the same data unlinkable is S0, the per-cell blinding seed expanded
# fresh from each commit's own salt -- see _s0_grid's own docstring --
# not this modulus.
DEFAULT_S_MOD = DEFAULT_MOD

# Exponent used when folding accS's digit counts into S, the S-side
# counterpart of `q`. Kept separate because the two are not constrained the
# same way:
#
#   q     is load-bearing across parties. ms6's H, ps6's oset row and vs6's
#         interlaced M must all raise digits to the SAME exponent or the
#         check identity row[j]*M[j] == H[j] does not close. It lives in
#         params for exactly that reason.
#   s_q   is prover-only and free. S's *value* travels to ps6 in s_list, and
#         ms6/ps6 both use that integer as a base in pow(S[j], d, mod), so
#         how S was folded never enters anyone's arithmetic. Nothing
#         outside this file ever needs to know it -- it is deliberately NOT
#         in params.
#
# So this value is unconstrained; 7 simply keeps it distinct from the
# default q=10. It must stay STABLE for the lifetime of a commitment,
# though: Commitment.append/replace/delete reseal a batch through
# _seal_grid, and a changed s_q would rebuild S differently and invalidate
# the commitment. Commitment therefore captures it at construction rather
# than reading the constant afresh.
DEFAULT_S_Q = 7

DEFAULT_S_EXP = 3
DEFAULT_HMAX_PAD_SIZE = int(str(ut.hash(9, DEFAULT_S_MOD, DEFAULT_S_EXP)))

# EDGE-COLUMN PADDING -- closes the singleton-bucket leak (see
# mul_combinations_mod's KNOWN LEAK docstring) at the DATA level instead of
# the arithmetic level: eval_level_mod/mul_combinations_mod are untouched,
# and instead the real per-item digit data simply never reaches the
# logical columns those two functions always expose (0, 1, chunk_size-2,
# chunk_size-1 at d=3; the cascade reaches deeper at larger d).
#
# chunk_of only ever encodes chunk_size - rand_edge_size REAL columns now;
# the outer rand_edge_size columns (split front/back, see
# _front_back_edge_counts) are filled asymmetrically on the two sides that
# feed them, per _rows_from_hash:
#
#   hm1 (H/accH side) gets FIXED PAD, not per-item decoy digits. vs6's
#   interlace_mod must reproduce a claimed item's edge columns bit-for-bit
#   to check them against H -- a public constant is the simplest thing
#   that satisfies that, and it makes row[j] at every edge column
#   IDENTICALLY 1 for ANY oset, not merely a value uncorrelated with real
#   data. That in turn makes combined[j] = row[j]*S[j]^d collapse to
#   S[j]^d at every edge column regardless of which items are claimed --
#   so the ratio between ANY two proofs' edge-column values, against the
#   same unresealed commitment, is always exactly 1. Not a bounded leak,
#   no information at all (see tests/test_leak.py).
#
#   hm2 (S/accS side) gets digits derived from (h1_salt, slot_index,
#   row_index) -- deterministic, but NOT derived from the item's own
#   hash/value at all, unlike hm1's real columns (or this scheme's own
#   pre-existing decoy design before this comment was last revised). This
#   is deliberately NOT needed for the ratio-is-always-1 property above
#   (that comes from hm1 alone -- S cancels in the ratio regardless of its
#   own content or origin, since it's the same S in both proofs either
#   way); it exists so S(edge) never carries anything derived from item
#   CONTENT either, even in the single-proof case, while staying
#   recomputable by the prover from data it already has (h1_salt plus the
#   item's own slot position) -- no separate per-item storage needed.
#   (A genuinely random alternative was tried and reverted: it bought no
#   additional binding or hiding once hm1's fix was in place -- the
#   ratio-cancellation attack it would have hardened against was already
#   fully closed by hm1 alone -- and it cost Commitment's bit-identical
#   incremental-vs-from-scratch rebuild property for nothing in return.)
#
# rand_edge_size must comfortably exceed the singleton-bucket cascade
# depth for whatever `d` is in use (2*(d-1) columns from each edge, per
# mul_combinations_mod's docstring) -- 6 covers d up to 4 with margin at
# the library's own default chunk_size=40.
DEFAULT_RAND_EDGE_SIZE = 6

# Upper bound on how many leaves _finish_ps6's TARGETED fold splits one
# level deeper, per row, on top of the row's own (already independently
# random) base partition choice -- see _finish_ps6's own comment. 0 is
# always a possible draw (no targeting that row), so this is a ceiling,
# not a floor; kept small since the whole point is a handful of leaves
# paying the deeper disclosure, not the row uniformly.
DEFAULT_MAX_FOLD_TARGETS = 3

# Domain-separation tags for the item digest itself (H1/H2, see
# _hash_item): H1_TAG for H1 = domain_hash(H1_TAG:h1_salt:val) (the
# H/accH side, which vs6._vs6_batch must reproduce for claimed items --
# see its own H1_TAG copy) and H2_TAG for H2 = domain_hash(H2_TAG:H1) (the
# S/accS side, prover-only -- vs6 never reconstructs S, so this one has no
# cross-package agreement obligation). Tagging H2 off of H1 rather than off
# of `val` directly keeps H1 and H2 from being two evaluations of the same
# hash on related inputs with no separation between them; it also means H2
# inherits h1_salt's effect automatically without its own copy of it.
#
# h1_salt (see _h1_salt) is the per-batch secret that keeps H1 from being
# a pure public function of val alone -- closes the domain hash's
# zero-interaction guessing gap discussed in the eprint's confidentiality
# section. Unlike these two tags, it is NOT a fixed public constant.
H1_TAG = "ms6-h1"
H2_TAG = "ms6-h2"

# Domain-separation tag for hm2's edge derivation (see EDGE-COLUMN PADDING
# above) -- keeps its hash input space separate from H1_TAG/H2_TAG's, even
# though nothing currently collides them.
S_EDGE_TAG = "ms6-edge-s"

# Domain-separation tag for _seal_hash (the seal-tree/batch-combining
# fold's per-value hashing -- see _seal_hash/_seal_rows/_seal_batch). Keeps
# this hash input space separate from H1_TAG/H2_TAG/S_EDGE_TAG's.
SEAL_TAG = "ms6-seal"


def _front_back_edge_counts(rand_edge_size):
    """rand_edge_size split as (front, back): ceil(n/2) toward the
    beginning, floor(n/2) toward the end -- e.g. 5 -> (3, 2)."""
    return rand_edge_size // 2 + rand_edge_size % 2, rand_edge_size // 2


def _attach_edges_pad(row, rand_edge_size):
    """Widen one already-permuted, narrow (chunk_size - rand_edge_size)
    real row back to chunk_size by prepending/appending u.PAD -- the same
    convention chunk_of already uses for a short first chunk, contributing
    no prime to cell_product_mod. Must run AFTER permutation, not before:
    padding has to land at the true logical edges (index 0 /
    chunk_size-1) regardless of how _column_perm shuffled the real
    columns, since that's exactly where eval_level_mod/mul_combinations_
    mod's singleton buckets look. Used for hm1 -- see EDGE-COLUMN PADDING
    above for why a fixed constant, not per-item decoy digits, is what
    actually closes the leak here."""
    if rand_edge_size <= 0:
        return row
    front_n, back_n = _front_back_edge_counts(rand_edge_size)
    return u.PAD * front_n + row + u.PAD * back_n


def _edge_digits_s(h1_salt, slot_index, row_index, n):
    """n deterministic decimal-digit characters for hm2's edges, derived
    from the batch's own h1_salt and this item's SLOT POSITION -- not from
    the item's own value/hash at all (see EDGE-COLUMN PADDING above for
    why that matters and why genuine randomness was tried and reverted).
    row_index separates a multi-row item's rows from each other, same
    reasoning as hm1's own edge derivation used to have before it became a
    fixed constant."""
    if n <= 0:
        return ""
    nbytes = max(n, 8)
    digest = hashlib.shake_256(
        f"{S_EDGE_TAG}:{h1_salt}:{slot_index}:{row_index}".encode()).digest(nbytes)
    return str(int.from_bytes(digest, "big")).zfill(n * 4)[-n:]


def _attach_edges_s(row, h1_salt, slot_index, row_index, rand_edge_size):
    """Widen one already-permuted, narrow (chunk_size - rand_edge_size)
    real row back to chunk_size using hm2's deterministic, item-value-
    independent edge digits -- see _edge_digits_s. Used for hm2 only; hm1
    uses _attach_edges_pad instead (see EDGE-COLUMN PADDING above for why
    the two sides get different treatment)."""
    if rand_edge_size <= 0:
        return row
    front_n, _ = _front_back_edge_counts(rand_edge_size)
    edge = _edge_digits_s(h1_salt, slot_index, row_index, rand_edge_size)
    return edge[:front_n] + row + edge[front_n:]

# NOTE: vs6 (the verifier) now lives in its own module, vs6.py, paired with
# vs6/utils6.py -- a self-contained package with zero import
# dependency on this file or utils6.py, so a party that only ever verifies
# proofs never has to load prover-only code (SystemRandom-based salt
# generation, _column_perm's generation, col_digit_counts,
# cell_pow_product_mod, eval_level_mod, seal_row_mod). vs6.DEFAULT_MOD /
# vs6.VS6_MOD must stay numerically equal to this file's DEFAULT_MOD --
# see vs6/core.py's and vs6/utils6.py's own DEFAULT_MOD comments.



# The parameters ms6, ps6 and vs6 must all agree on, carried as one dict so
# they cannot be passed inconsistently. Every one of these is load-bearing:
# disagree on any of them and an honest proof fails to verify (or, worse,
# fails only for some inputs -- this session hit exactly that twice, once
# when ms6/vs6's _seal_batch drifted apart on the cell_product_mod exponent,
# and once when q was removed from one side of the row-seal but not the
# other).
#
# Deliberately NOT in here:
#   d                 the row-seal degree -- pre-shared out-of-band between
#                     committer and verifier instead, passed as its own
#                     explicit argument to ps6()/vs6() rather than riding
#                     along in this dict. `params` reaches the verifier
#                     FROM the prover (see this dict's own "not self-
#                     authenticating" framing below); d does not travel
#                     that path at all now, so a party who has only `c`
#                     (no opening) never sees it here, unlike every other
#                     entry in this dict, which an opening's own params
#                     blob discloses regardless. This does NOT hide d from
#                     anyone who observes an actual opening/proof -- the
#                     disclosed sweep's own length is d*(chunk_size-1)+1,
#                     so d is recoverable from the proof's shape alone
#                     given the (still public) chunk_size; moving it here
#                     only keeps it out of the bare params blob, see
#                     ms6_vibe.md for the analysis that ruled out anything
#                     stronger via renaming/relabeling alone.
#   s_mod, s          per-commit secrets -- this dict goes to the verifier
#   s_exp, pad_size,
#   keep_hm           prover-only, never consulted by ps6/vs6
#   workers           a local performance choice; each party picks its own
PARAM_KEYS = ("q", "chunk_size", "batch_size", "mod", "seal_batch_size", "rand_edge_size")


def _validate_d(d, mod=None):
    """d's own validation, standalone now that it no longer travels inside
    `params` (see PARAM_KEYS's own comment) -- ms6/ps6/vs6 call this at
    entry since they're where d is now supplied as an explicit, separate
    argument rather than read out of a dict that's already been through
    _validate_params.

    mod=<prime>: also enforces gcd(d, mod - 1) == 1. Under a prime
    modulus, x -> pow(x, d, mod) is a bijection on Z_mod* exactly when d
    is coprime to mod-1 (elementary group theory -- the inverse map is
    x -> pow(x, pow(d, -1, mod - 1), mod)). That bijectivity is what
    upgrades the row-fold's binding argument from "no collision found in
    testing" to "no collision exists": two distinct valid grids cannot
    map to the same committed value, full stop, independent of any
    hardness assumption. Violating gcd(d, mod-1)==1 does not just make
    root-extraction ambiguous -- it reopens exactly that collision. See
    README's Security section and ms6_vibe.md entry 78 for the full
    argument. Skipped when mod is composite (e.g. LEGACY_MOD_2048): an
    unknown-order ring's binding case is the standard Strong-RSA-style
    argument instead, which this check does not apply to."""
    if not isinstance(d, int) or d < 1:
        raise ParamMismatch(f"d must be a positive int, got {d!r}")
    if mod is not None and ut.is_prime(mod):
        from math import gcd
        if gcd(d, mod - 1) != 1:
            raise ParamMismatch(
                f"d={d} is not coprime to mod-1 under prime mod={_brief(mod)} -- "
                f"pow(x, d, mod) is not a bijection on Z_mod*, which reopens the "
                f"row-fold collision the degree-d step is meant to rule out (see "
                f"README's Security section). Pick a d with gcd(d, mod-1) == 1, "
                f"or use an unknown-order composite mod (e.g. LEGACY_MOD_2048) "
                f"instead.")


def make_params(q, chunk_size=DEFAULT_CHUNK_SIZE, batch_size=DEFAULT_BATCH_SIZE,
                mod=DEFAULT_MOD, seal_batch_size=DEFAULT_SEAL_BATCH_SIZE,
                rand_edge_size=DEFAULT_RAND_EDGE_SIZE):
    """The public parameter set, as returned by ms6() and consumed by
    ps6()/vs6() -- d is NOT in here, see PARAM_KEYS's own comment; ms6()
    still takes d as its own explicit argument and callers must track it
    separately to pass to ps6()/vs6()."""
    return {"q": q, "chunk_size": chunk_size, "batch_size": batch_size,
            "mod": mod, "seal_batch_size": seal_batch_size,
            "rand_edge_size": rand_edge_size}


def _brief(v):
    """Abbreviate a value for an error message -- `mod` is a large int and
    printing it twice makes a mismatch report unreadable."""
    if isinstance(v, int) and v.bit_length() > 64:
        return f"<{v.bit_length()}-bit int ...{str(v)[-6:]}>"
    return repr(v)


class ParamMismatch(ValueError):
    """params did not match what the caller pinned via expect=.

    Distinct from the AssertionError vs6 raises for a failed proof: that one
    means "this proof is invalid", this one means "this proof was produced
    under parameters I did not agree to" -- a configuration or substitution
    signal, which a caller usually wants to handle differently."""


def _validate_params(params, expect=None):
    """Structural sanity, always; exact pinning when `expect` is given.

    The structural half runs unconditionally because `params` reaches the
    verifier from the prover: it carries no secrets, but it is not
    self-authenticating either, so nonsense or hostile values (mod=1,
    chunk_size=0) should not get as far as the arithmetic. d is NOT
    validated here -- it is no longer part of `params` at all (see
    PARAM_KEYS's own comment); callers that accept d as a separate
    argument validate it via _validate_d instead.

    `expect` may be a subset -- pin only the keys you actually care about
    (typically mod/q) and leave the rest free. Unknown keys in `expect`
    raise rather than being silently ignored, so a typo can't quietly
    disable the check it was meant to add.
    """
    missing = [k for k in PARAM_KEYS if k not in params]
    if missing:
        raise KeyError(f"params missing required key(s): {', '.join(missing)}")

    for k in ("q", "chunk_size", "batch_size", "seal_batch_size"):
        v = params[k]
        if not isinstance(v, int) or v < 1:
            raise ParamMismatch(f"params[{k!r}] must be a positive int, got {v!r}")
    if not isinstance(params["mod"], int) or params["mod"] < 2:
        raise ParamMismatch(f"params['mod'] must be an int >= 2, got {params['mod']!r}")
    red = params["rand_edge_size"]
    if not isinstance(red, int) or red < 0:
        raise ParamMismatch(f"params['rand_edge_size'] must be a non-negative int, got {red!r}")
    if red >= params["chunk_size"]:
        raise ParamMismatch(
            f"params['rand_edge_size'] ({red}) must be smaller than chunk_size "
            f"({params['chunk_size']}) -- it can't consume the whole row")

    if expect:
        unknown = [k for k in expect if k not in PARAM_KEYS]
        if unknown:
            raise ParamMismatch(f"expect has unknown key(s): {', '.join(sorted(unknown))}")
        bad = {k: (expect[k], params[k]) for k in expect if params[k] != expect[k]}
        if bad:
            detail = "; ".join(f"{k}: expected {_brief(e)}, got {_brief(g)}"
                               for k, (e, g) in sorted(bad.items()))
            raise ParamMismatch(f"params do not match expect -- {detail}")


def unpack_params(params, expect=None):
    """params -> (q, chunk_size, batch_size, mod, seal_batch_size,
    rand_edge_size), validated first -- see _validate_params. d is NOT
    part of this tuple any more -- see PARAM_KEYS's own comment; callers
    that need d take it as their own separate argument."""
    _validate_params(params, expect)
    return tuple(params[k] for k in PARAM_KEYS)


def chunk_of(val, x, chunk_size):
    """Digit rows for one value. Short first chunks and missing rows are
    filled with u.PAD, which occupies its own count slot and contributes no
    prime -- padding is deterministic and public, so it must not affect the
    cell value. It cannot be a decimal digit: every digit indexes a prime
    and therefore carries information."""
    chunks = list(ut.backward_chunk(val, chunk_size))
    chunks[0] = f"{chunks[0]:{u.PAD}>{chunk_size}}"
    return [u.PAD * chunk_size] * (x - len(chunks)) + chunks


def chunks(x, chunk_size):
    def internal(val):
        return chunk_of(val, x, chunk_size)

    return internal


def _column_perm(seed, chunk_size):
    """Deterministic, secret-salt-derived permutation of the chunk_size
    column positions.

    mul_combinations_mod's combinatorial bucketing has two logical column
    indices (0 and chunk_size-1, plus their immediate cascade neighbours)
    that are ALWAYS singleton buckets -- directly invertible via modular
    root extraction -- for any chunk_size/d (see KNOWN LEAK in
    utils6.py). That's a structural property of combinations_with_
    replacement's indexing, not something a parameter choice fixes.

    What this DOES fix: which REAL digit column ends up at logical index
    0/chunk_size-1 is no longer fixed and public across every commitment
    this protocol ever makes. Applied consistently (same seed) to every
    row before accH/accS accumulate it (_ms6_batch) and before a claimed
    value's fresh hash is folded into M (interlace_mod, via
    _vs6_batch/vs6's perm_list) -- so ps6/vs6's math is unaffected
    (eval_level_mod/mul_combinations_mod still just see logical indices
    0..chunk_size-1), only the mapping from logical index to real column
    changes.

    SCOPE: the permutation is derived from the secret salt `s`, but is
    published (as part of ms6's own return value, alongside S) so vs6 can
    apply the same one -- like S itself, its value isn't secret once a
    commitment is public, only *unpredictable in advance*. This defeats
    an attacker correlating the same real column across many different
    commitments (or precomputing against a not-yet-published commitment);
    it does NOT hide which 4 columns leak from someone who already has
    one specific commitment's full public output, since perm is part of
    that output.
    """
    return Random(seed).sample(range(chunk_size), chunk_size)


def _permute_row(row, perm):
    return ''.join(row[p] for p in perm)


def _s0_grid(s, batch_index, rows, chunk_size, s_mod):
    """Per-cell blinding seeds, expanded from the secret salt so that every
    cell gets a full-width (s_mod-sized) value.

    Every cell gets a full-width value. A one-digit-per-cell seed would
    leave any cell whose accS counts came out all-zero -- padding rows, and
    any column no item's digest reached -- blinded by a single decimal
    digit, which at chunk_size=40/batch_size=1000 would be roughly half the
    grid carrying under 8 bits of blinding.

    SHAKE-256 rather than Random(seed): the cells are expanded from `s`, so
    an attacker who recovers one S[i][j] -- and utils6.mul_combinations_mod's
    documented leak does recover a handful per row -- must not be able to
    run the expansion backwards to `s` and derive every other cell. A
    Mersenne Twister stream would permit exactly that, its internal state
    being recoverable from its own output. batch_index is mixed in for the
    same reason _column_perm mixes it: without it, every batch under one
    commit's shared salt would get an identical grid.

    SCOPE: this expands entropy, it does not create it. Cells hold
    full-width *values*, but the grid as a whole carries only as much
    unpredictability as `s` itself (~266 bits at the default hmax sizing),
    however many cells it fills.
    """
    nbytes = (s_mod.bit_length() + 7) // 8
    grid = []
    for i in range(rows):
        row = []
        for j in range(chunk_size):
            digest = hashlib.shake_256(f"{s}:{batch_index}:{i}:{j}".encode()).digest(nbytes)
            # `or 1`: a zero cell would annihilate its column's H entry
            # outright (0 * anything == 0), not blind it.
            row.append(int.from_bytes(digest, 'big') % s_mod or 1)
        grid.append(row)
    return grid


def _h1_salt(s, batch_index):
    """Per-batch secret mixed into H1 (and, transitively, H2 -- see
    _hash_item) so the domain hash stops being a pure public function of
    an item's value alone.

    WHY: domain_hash(H1_TAG:val) with no salt lets anyone precompute H1
    for any candidate value entirely offline, with zero interaction --
    the domain hash's one-wayness (Open Problem op:hash in the eprint)
    only stops INVERTING an unknown digest, not VERIFYING a guessed value
    against one, which is the actual attack the two-query ratio trick
    (Observation obs:ratio) enables once combined with an unsalted hash:
    query the same commitment with two claim sets differing by one item,
    cancel S(r,j) out, and at an INTERIOR (non-edge) column the residual
    is the unclaimed item's own real digit there -- a known, checkable
    function of the item's H1 once a candidate value is guessed. (At an
    edge column the residual is a fixed public constant regardless of
    h1_salt or anything else -- see EDGE-COLUMN PADDING above -- so this
    salt's job is specifically about the interior columns, not the edge
    ones.) For a low-entropy item space (this construction's own stated
    use case, sanctions/watchlist screening -- SSNs, names, DOBs), that
    check is cheap enough to run over the whole plausible universe.

    Mixing a per-batch secret in raises the bar from "guess offline,
    zero interaction" to "obtain at least one opening from this batch
    first" -- exactly the same threat model _column_perm's own perm and
    _s0_grid's own S0 already accept: unpredictable before any opening,
    revealed as part of an opening (not the raw commitment `c`) same as
    perm already is, so guessing against a batch's STILL-unclaimed items
    is possible once that batch's h1_salt is public, but not before.
    This does not close that residual gap (see Observation obs:ratio /
    "What an observer can still compute" in the eprint); it closes the
    strictly worse zero-interaction case. A sibling risk -- S(r,j) itself
    being fixed across every opening of a commitment, letting two
    suitably-chosen openings cancel it out of their ratio -- is not
    addressed here either; QueryGovernor (below) is this codebase's
    deployment-level (policy, not cryptographic) mitigation for that one.

    SHAKE-256 (not Random(seed), not reusing perm's own Mersenne-Twister
    output): same reasoning as _s0_grid's own docstring -- a construction
    whose internal state is recoverable from its output must not be the
    thing standing between an observer and every other batch-wide secret.
    Deterministic given (s, batch_index), like perm/S0, NOT independently
    random per item like the truly-random hm2 proposal that was
    considered and aborted -- so it needs no new per-item storage:
    Commitment.replace()/delete() and the incremental-vs-from-scratch
    rebuild equivalence (pinned via batch_salts=) keep working unchanged,
    since this is recoverable from the same salt they already pin."""
    return hashlib.shake_256(f"ms6-h1-salt:{s}:{batch_index}".encode()).hexdigest(16)


def _hash_item(val, h1_salt="", chunk_size=DEFAULT_CHUNK_SIZE,
               rand_edge_size=DEFAULT_RAND_EDGE_SIZE, mod=DEFAULT_MOD):
    """One item's two independent hash-digit strings -- H1 (feeds accH, the
    primary commitment grid) and H2 (feeds accS, the blinding-side
    accumulator) -- both via Utils.domain_hash (SHAKE128), tagged apart by
    H1_TAG/H2_TAG.

    This is a real cryptographic hash, unlike utils6.Utils.hash() (still
    used elsewhere in this file -- the seal-tree fold, hmax sizing -- but
    NOT for the digest itself, see below): that function is a fixed,
    public digit-substitution transform with no collision-resistance
    argument behind it, which is exactly what the eprint's Open Problem on
    the domain hash used to flag as an unproven assumption. domain_hash
    closes that: H1/H2 collision resistance is now an ordinary SHAKE128
    assumption, not a bespoke one.

    domain_hash's output is fixed-width (DOMAIN_HASH_DIGITS decimal
    digits, zero-padded) regardless of val's own magnitude, unlike the old
    hash()'s input-magnitude-scaling output -- so every item's raw H1/H2
    are the same length before the widening step below runs too.

    SPARSE WIDENING: DOMAIN_HASH_DIGITS (78) is fixed regardless of
    chunk_size, so a chunk_size whose real_width (chunk_size -
    rand_edge_size) comfortably exceeds it -- chunk_size=100 at the
    default rand_edge_size=6, real_width=94 -- would otherwise leave every
    row mostly u.PAD (16 narrow-chunk pad columns here, on top of the 6
    fixed edge ones -- see chunk_of/_attach_edges_pad). ut.sparse_expand
    widens h1s/h2s out to _item_digest_rows(chunk_size, rand_edge_size) *
    real_width digits -- an exact multiple of real_width, so chunk_of's
    OWN existing padding logic downstream sees no shortfall left to pad at
    all -- by APPENDING utils6.Utils.hash()-derived filler after the real
    digest, never touching the real digest's own digits (see sparse_
    expand's own docstring for why that's what keeps this safe to build on
    `hash()` despite the same collision-resistance caveat this docstring's
    second paragraph raises against using it for the digest itself: two
    items still need an actual domain_hash collision to land in the same
    row, since the filler is never what makes two DIFFERENT digests
    distinguishable, only what fills space past them). A no-op whenever
    real_width alone already covers DOMAIN_HASH_DIGITS in one row's worth
    (chunk_size's usual range) or a row count already covers it without
    any excess (see sparse_expand's own no-op case) -- most existing
    chunk_size choices are unaffected.

    s_exp used to be accepted here too, unused in the body -- dropped
    (along with the matching dead parameter on _item_rows/_ms6_batch and
    every call site, including tests/test_leak.py's direct use of H1
    alone). s_exp itself remains meaningful elsewhere in this module
    (hmax sizing, on ms6()/Commitment directly) -- only the dead
    threading into H1/H2 is gone.

    h1_salt (see _h1_salt) is mixed into H1 so it is no longer a pure
    public function of val alone -- default "" reproduces the OLD
    unsalted behavior for any caller that hasn't been updated to pass
    one, rather than silently changing every existing digest. H2 is
    computed from H1 (not val directly), so it inherits the salt's effect
    automatically without needing its own copy."""
    h1s = ut.domain_hash(f"{H1_TAG}:{h1_salt}:{val}".encode())
    h2s = ut.domain_hash(f"{H2_TAG}:{h1s}".encode())
    target_len = _item_digest_rows(chunk_size, rand_edge_size) * (chunk_size - rand_edge_size)
    h1s = ut.sparse_expand(h1s, target_len, mod)
    h2s = ut.sparse_expand(h2s, target_len, mod)
    return h1s, h2s


def _rows_from_hash(h1s, h2s, chunk_of, perm, rand_edge_size, h1_salt, slot_index):
    """Permuted, edge-padded digit rows for H (hm1) and S (hm2), from an
    item's already-computed hash strings. chunk_of/perm must already be
    sized to the REAL width (chunk_size - rand_edge_size); edges are
    attached AFTER permutation, so they land at the true logical edges
    regardless of how the real columns were shuffled -- see EDGE-COLUMN
    PADDING above for why hm1's edges are fixed PAD and hm2's are derived
    from (h1_salt, slot_index, row_index) instead, not the same treatment.

    Shared by _item_rows (fresh hash) and _ms6_batch's own loop
    (pre-hashed, for the x-sizing reason documented there) so both derive
    an item's contribution identically -- the two must agree character-
    for-character or the counts they add and subtract won't cancel. That
    now includes hm2's edges too: slot_index must be the SAME slot the
    original commit used for this item, or the recomputed hm2 silently
    disagrees with what's already folded into that batch's counts."""
    real1 = [_permute_row(r, perm) for r in chunk_of(h1s)]
    real2 = [_permute_row(r, perm) for r in chunk_of(h2s)]
    hm1 = [_attach_edges_pad(row, rand_edge_size) for row in real1]
    hm2 = [_attach_edges_s(row, h1_salt, slot_index, i, rand_edge_size)
           for i, row in enumerate(real2)]
    return hm1, hm2


def _item_rows(val, chunk_of, perm, rand_edge_size=0, h1_salt="", slot_index=0,
               chunk_size=DEFAULT_CHUNK_SIZE, mod=DEFAULT_MOD):
    """One item's permuted, edge-padded digit rows for the H side (hm1)
    and the S side (hm2), against an ALREADY-SIZED, ALREADY-NARROWED
    (chunk_size - rand_edge_size) chunk_of/perm pair (x fixed). See
    _rows_from_hash for the shared logic; this just adds the fresh hash
    step. Factored out of _ms6_batch's own loop so the incremental update
    path (Commitment.append/replace/delete) derives an item's contribution
    the exact same way the original commit did -- the two must agree
    character-for-character or the counts they add and subtract won't
    cancel. h1_salt must be the SAME batch's h1_salt (see _h1_salt) the
    original commit used, and slot_index the SAME local index within the
    batch, or the recomputed hm1/hm2 silently disagree with what's already
    folded into that batch's counts.

    chunk_size/mod must be the SAME batch's own chunk_size/mod too (a
    Commitment's config, fixed for its whole life) -- _hash_item's sparse
    widening (see its own docstring) is a deterministic function of
    exactly these two plus rand_edge_size, so passing the batch's real
    values here reproduces the SAME widened h1s/h2s the original commit
    computed, not just the same-length ones."""
    h1s, h2s = _hash_item(val, h1_salt, chunk_size, rand_edge_size, mod)
    return _rows_from_hash(h1s, h2s, chunk_of, perm, rand_edge_size, h1_salt, slot_index)


def _apply_rows(cnt, rows, sign):
    """Add (sign=+1) or subtract (sign=-1) one item's digit rows from an
    Acc-shaped count grid, cnt[row][col][digit].

    Only the first len(cnt) rows are consulted, mirroring Acc.add's own
    convention: chunk_of pads short digests up to x rows but leaves longer
    ones long, and Acc only ever accumulates its first `rows` of them.
    Every row string is exactly chunk_size chars, so character position j
    lands in column j -- the same mapping Acc.flush's big[j::cols] slice
    produces."""
    for i, cnt_i in enumerate(cnt):
        for j, ch in enumerate(rows[i]):
            cnt_i[j][ord(ch) - 48] += sign


def _seal_grid(accH_cnt, accS_cnt, S0, chunk_size, d, q, mod, s_mod,
               workers=DEFAULT_WORKERS, s_q=DEFAULT_S_Q):
    """Counts + salt grid -> (h, S) for one batch.

    This is the whole tail of a batch commit, from digit counts onward, and
    it is a pure function of those counts -- which is exactly what makes
    the commitment updatable: an item can be added to or subtracted from
    accH/accS and this recomputes the batch's h without rehashing any other
    item. _ms6_batch and Commitment.append/replace both go through here so
    an incrementally-updated batch is bit-identical to a freshly committed
    one over the same items.

    The returned `h` is domain_hash(SEAL_TAG:...) of the batch's own final
    folded scalar, not that raw scalar itself -- the same standard of hash
    _seal_rows used to apply one level up, when h_list (this function's own
    output, batch by batch) later got folded into c via _seal_batch. Hashing
    it here instead means _seal_rows/_seal_batch/_SealTree no longer hash
    their own inputs (see _seal_rows), so every value that ever becomes a
    tree leaf is hashed exactly once, at the point it's produced -- vs6's
    _vs6_batch hashes its own per-batch reconstruction the same way, so a
    touched batch's h lines up with an untouched batch's (copied straight
    from h_list) either way."""
    H = [[ut.cell_product_mod(accH_cnt[i][j], q, mod) for j in range(chunk_size)]
         for i in range(len(accH_cnt))]
    S = [[(S0[i][j] * ut.cell_product_mod(accS_cnt[i][j], s_q, s_mod)) % s_mod for j in range(chunk_size)]
         for i in range(len(accS_cnt))]

    H = [[(hv * pow(sv, d, mod)) % mod for hv, sv in zip(H1, S1)] for H1, S1 in zip(H, S)]

    if workers and workers > 1 and len(H) > 1:
        from concurrent.futures import ProcessPoolExecutor
        with ProcessPoolExecutor(max_workers=workers) as ex:
            H = list(ex.map(ut.seal_row_mod, [(H1, d, mod) for H1 in H]))
    else:
        H = [[sum(hv) % mod for hv in ut.eval_level_mod(d, H1, mod, coef=True)] for H1 in H]
        H = [ut.vsum_level_fold_mod(d, mod, values=H1, global_keys=True) for H1 in H]

    h = ut.vsum_level(H, b=chunk_size)
    return _seal_hash(h), S


def _ms6_batch(vals, chunk_size, d, q, s, mod=DEFAULT_MOD, s_mod=DEFAULT_S_MOD,
               s_q=DEFAULT_S_Q, rand_edge_size=DEFAULT_RAND_EDGE_SIZE,
               keep_hm=DEFAULT_KEEP_HM, workers=DEFAULT_WORKERS, batch_index=0, batch_salt=None):
    """Commits a single batch: builds its own accH/accS/S0 from just the
    `vals` it's given, and returns that batch's own h.

    batch_salt pins the per-batch salt instead of drawing a fresh one from
    `s`. ms6() leaves it None (unchanged behaviour); Commitment passes the
    stored salt so a batch can be resealed later against the same S0/perm/x
    it was originally built with.

    No s_exp parameter here -- ms6()/Commitment's own s_exp only ever fed
    hmax sizing, never this function; _hash_item stopped taking one too
    once its own dead threading of it was removed."""
    s = gen.randrange(s) if batch_salt is None else batch_salt

    # batch_index is mixed into the permutation seed (not just `s` alone)
    # so batches within the SAME commit don't all leak the same 4 real
    # columns -- every batch here shares one `s` (ms6 passes the same s to
    # every _ms6_batch call), so without this, perm would be identical
    # across the whole commit. See _column_perm's docstring.
    real_width = chunk_size - rand_edge_size
    perm = _column_perm(s * 1_000_000_007 + batch_index, real_width)

    # Per-batch secret mixed into H1/H2 -- see _h1_salt's own docstring for
    # why (closes the domain hash's zero-interaction guessing gap). Same
    # batch_index-mixing reasoning as perm above: without it every batch
    # under one commit's shared `s` would reuse the same salt.
    h1_salt = _h1_salt(s, batch_index)

    # Every item is hashed once, up front, so x (this batch's row count)
    # can be sized from the ACTUAL digests in play, rather than guessed at.
    #
    # x used to come from len(str(s)) alone -- the SALT's own decimal digit
    # length. That was wrong two ways: (1) s is redrawn randomly per batch/
    # commit, so x (and therefore ms6()'s own returned x_list) varied
    # run-to-run for the exact same dataset -- confusing, and made two
    # commits of identical data structurally incomparable even though
    # nothing was actually wrong. (2) hash() output length is NOT monotonic
    # in input magnitude (nothing about a larger item guarantees a longer
    # hash), so a batch could legitimately contain an item whose true hash
    # needed MORE rows than that particular draw of `s` happened to imply.
    # chunk_of pads a SHORT digest up to x, but does not grow x to fit a
    # LONG one -- Acc.add's own truncate-to-shorter guard would then
    # silently drop that item's low-order (least-significant) chunks from
    # the accumulator: a real loss of committed data, not just a cosmetic
    # surprise.
    #
    # Sizing x from the widest digest actually hashed here closes both:
    # x is now a deterministic function of `vals` alone (same dataset ->
    # same x_list, regardless of which salt got drawn), and it is, by
    # construction, always wide enough for every item this batch commits.
    # The per-cell blinding *values* are still salt-derived (_s0_grid);
    # only the grid's row *count* stopped taking its size from the salt.
    hashed = [_hash_item(val, h1_salt, chunk_size, rand_edge_size, mod) for val in vals]
    widest = max((len(h) for pair in hashed for h in pair), default=1)
    # ceil(widest / real_width), NOT chunk_size: each row only carries
    # real_width real digits now (the rest is edge padding), so sizing
    # against the full chunk_size would under-count rows needed and
    # silently truncate a wide digest's low-order chunks.
    rows = max(1, -(-widest // real_width))

    S0 = _s0_grid(s, batch_index, rows, chunk_size, s_mod)
    x = len(S0)
    accH = u.Acc(x, chunk_size)
    accS = u.Acc(x, chunk_size)

    hm = []
    chunk_of = chunks(x, real_width)
    for t, (h1s, h2s) in enumerate(hashed):
        hm1, hm2 = _rows_from_hash(h1s, h2s, chunk_of, perm, rand_edge_size, h1_salt, t)
        if keep_hm:
            hm.append(hm1)
        accH.add(hm1)
        accS.add(hm2)
        if (t & (FLUSH - 1)) == FLUSH - 1:
            accH.flush()
            accS.flush()
    accH.flush()
    accS.flush()

    # q is the shared exponent applied to every hm digit (H side) and every
    # S digit (via cell_product_mod(..., q, ...) plus the *pow(sv, d, mod)
    # below); it must match ps6's/vs6's own q exactly.
    #
    # H/S: per-(row, column) products of every item's digit contribution,
    # both raised to q, and S additionally combined with the secret salt
    # grid S0 and later raised to d below. Computed via cell_product_mod
    # from accH/accS's digit counts (each digit contributing its own prime
    # from DIGIT_PRIMES) instead of one multiplication per item, reduced
    # mod throughout so intermediate values stay bounded regardless of
    # dataset size.
    #
    # H reduces mod `mod`; S reduces mod `s_mod`, its own independently
    # choosable ring (see DEFAULT_S_MOD). The two rings need not match, and
    # `s_mod` is never given to the verifier: S's value travels to ps6 via
    # s_list, and ms6/ps6 both feed that same integer to pow(S[j], d, mod)
    # on the H side, so only `mod` governs the check identity. vs6 works
    # entirely from ps_list/x_list/perm_list and never sees s_mod or S.
    #
    # H is blinded by the secret-salted S rather than left raw: without
    # that, vs6's final check reduces to a single linear modular equation
    # solvable by modular q-th-root extraction with no knowledge of real
    # data. S itself stays unhashed. The row-seal that follows folds each
    # row's chunk_size column values into one h_d value; it's independent
    # per row, so it parallelises across rows. All of that lives in
    # _seal_grid, shared with the incremental update path.
    h, S = _seal_grid(accH.cnt, accS.cnt, S0, chunk_size, d, q, mod, s_mod, workers, s_q)

    # mod is not returned: it's a fixed, public parameter (like chunk_size
    # or d), not a per-commit secret -- ps6/vs6 default to the same
    # DEFAULT_MOD/VS6_MOD. Pass mod= explicitly and consistently to every
    # call if a non-default modulus is ever used.
    #
    # hm is prover-only opening data (ps6 recomputes oset's aggregate
    # directly from it every call -- see _ps6_batch). Handing ps6 a
    # full-dataset aggregate instead would be unsound: row[j] = cell_product
    # (cnt_full - X, q) combined with vs6's M[j] = cell_product(X, q)
    # multiplies back to cell_product(cnt_full, q) for *any* X, as a plain
    # algebraic identity -- a dishonest prover could fabricate hm[iset] and
    # the check would still pass. hm's per-item entries carry no such
    # shortcut.
    #
    # perm is returned so vs6 can apply the same column permutation to a
    # claimed value's freshly-hashed rows (via interlace_mod) -- ps6 needs
    # no separate copy, since hm is already stored here in permuted form.
    # h1_salt travels the same way and for the same reason: vs6 needs it to
    # recompute a claimed item's H1 identically (see _h1_salt); ps6 needs
    # no separate copy of it either, for the same reason it needs no perm.
    # Commitment.append/replace/delete also reuse h1_salt (together with an
    # item's own slot index) to recompute hm2 on demand -- see
    # _item_rows/_attach_edges_s -- so no separate hm2 storage is needed
    # there either.
    #
    # accH/accS's counts and the batch salt are returned for Commitment's
    # sake: the counts are what an update edits in place (no rehashing of
    # untouched items), and the salt is what lets a later reseal rebuild
    # the same S0/perm/x/h1_salt. ms6() discards both.
    return h, x, S, hm, perm, h1_salt, accH.cnt, accS.cnt, s


def _seal_mod(bits):
    """Fresh prime modulus for re-sealing a caller-supplied salt (see ms6).

    `bits` is a BIT length -- generate_prime's own unit. This previously
    received len(str(hmax)), a DECIMAL DIGIT count, which undersized the
    modulus by ~3.3x (an 81-bit prime where hmax needed 266) and left the
    re-sealed salt's entropy capped well below brute-force range.

    Floored at DEFAULT_SEAL_MOD_BITS: the sealed value becomes the secret
    salt `s`, whose whole job is being unpredictable in advance, so it
    should never be reduced into a range smaller than that regardless of
    how small hmax happens to be for a given dataset.
    """
    return ut.generate_prime(max(bits, DEFAULT_SEAL_MOD_BITS))


def _seal_hash(val):
    """The one place SEAL_TAG's domain_hash actually gets applied: every
    value that ever becomes a leaf of a _seal_batch/_SealTree fold (a
    batch's own h from _seal_grid, vs6.core._vs6_batch's reconstruction of
    one, an intermediate group-seal one level of recursion down, or the
    secret-salt reseal's own s0/s) is hashed exactly once, right here, at
    the point it's produced -- not implicitly inside the fold itself (see
    _seal_rows). Must stay textually identical to vs6.core's own copy, so
    the two sides hash the same way."""
    return ut.domain_hash(f"{SEAL_TAG}:{val}".encode())


def _seal_batch(vals, chunk_size, x, d, q, mod=DEFAULT_MOD, seal_batch_size=DEFAULT_SEAL_BATCH_SIZE):
    """Folds a list of already-hashed (see _seal_hash) big-int-derived
    digests into a single scalar: chunk+accumulate each value, then
    row-seal + combine, exactly like _ms6_batch's own H does for one row --
    just one level up.

    When `vals` is larger than seal_batch_size, it's folded hierarchically
    instead of in one Acc pass: split into seal_batch_size-sized groups,
    seal each group (recursively, in case a group's own sub-groups are
    still oversized), then recurse on the resulting list of group-seals --
    repeating until a single pass at the top covers everything. Below the
    threshold this is exactly the original flat fold, so output for any
    `vals` that already fit in one pass is unchanged.

    Each intermediate group-seal is re-hashed (_seal_hash) before it joins
    the next level's `vals`, exactly like a fresh leaf would be -- only the
    very last, top-level fold (this function's own final return) stays a
    raw scalar, matching `c`/a batch's pre-_seal_grid-hash convention.
    """
    vals = list(vals)
    if len(vals) > seal_batch_size:
        vals = [
            _seal_hash(_seal_batch(vals[start:start + seal_batch_size], chunk_size, x, d, q, mod, seal_batch_size))
            for start in range(0, len(vals), seal_batch_size)
        ]
        return _seal_batch(vals, chunk_size, x, d, q, mod, seal_batch_size)

    accH = u.Acc(x, chunk_size)
    chunk_of = _seal_chunker(x, chunk_size)
    for t, val in enumerate(vals):
        accH.add(_seal_rows(val, chunk_of))
        if (t & (FLUSH - 1)) == FLUSH - 1:
            accH.flush()
    accH.flush()

    return _seal_from_counts(accH.cnt, chunk_size, d, q, mod)


def _seal_chunker(x, chunk_size):
    """chunk_of for the seal side (no column permutation -- _seal_batch
    folds h scalars, not item digests)."""
    return chunks(x, chunk_size)


def _seal_rows(val, chunk_of):
    """One folded value's digit rows, as _seal_batch accumulates them.
    Shared with _SealTree so a cached node can add or subtract exactly the
    rows the flat fold would have contributed.

    `val` must already be a Utils.domain_hash (SHAKE128) digest, tagged
    with SEAL_TAG -- the same real cryptographic hash _hash_item uses for
    H1/H2, rather than utils6.Utils.hash() (still used elsewhere in this
    file: hmax sizing, the secret-salt reseal's own hmax-derived bound).
    This fold is binding-relevant in exactly the same way the row-level
    H1/H2 check is (vs6.vs6 recomputes it and asserts the result equals c,
    see its own docstring), so it deserves the same standard of hash, not a
    weaker one smuggled in one level up -- _seal_rows itself no longer
    applies that hash, though: every value that reaches here is hashed
    once, at the point it's produced (_seal_grid for a batch's own h,
    vs6.core._vs6_batch for its reconstruction of one, or explicitly at the
    secret-salt reseal's own call site in ms6()) so a value is never
    re-hashed just because it passes through another fold.

    domain_hash's output is fixed-width (DOMAIN_HASH_DIGITS decimal
    digits) regardless of the original value's own magnitude, unlike
    ut.hash()'s input-magnitude-scaling output -- see SEAL_FOLD_ROWS below
    for what that means for callers sizing `x`."""
    return chunk_of(val)


# _seal_rows's output is now a FIXED DOMAIN_HASH_DIGITS-digit string
# (domain_hash, not the old input-magnitude-scaling ut.hash), so the
# number of rows any _seal_batch fold needs to hold one value without
# truncation no longer depends on that value's own size -- it's this,
# always. (_seal_batch's main fold, `x=max(x_list)`, is already >= this
# for any real chunk_size/rand_edge_size combination, since x_list
# itself is sized to hold a domain_hash-width H1/H2 digest per row over
# a narrower real_width = chunk_size - rand_edge_size <= chunk_size; the
# secret-salt reseal path is the one call site that used to size `x`
# from its own operand's decimal length -- see ms6()'s reseal call --
# and needs this instead now that that assumption no longer holds.)
def _seal_fold_rows(chunk_size):
    return -(-u.DOMAIN_HASH_DIGITS // chunk_size)


def _item_digest_rows(chunk_size, rand_edge_size):
    """Row count (x) an item's own H1/H2 digest needs at this chunk_size/
    rand_edge_size -- the SAME formula _ms6_batch's own x-sizing already
    reduces to (domain_hash is fixed-width, so 'measure the widest digest
    actually hashed' always measures DOMAIN_HASH_DIGITS today -- see
    _hash_item's docstring), pulled out as its own pure function of public
    params alone so _hash_item can compute a widening target BEFORE
    hashing runs, with no dependency on _ms6_batch's own post-hash
    measurement (see _hash_item's own sparse-expansion paragraph for why
    that matters: this must be side-effect-free and call-order-
    independent, or an append/replace years after the original commit
    could widen to a different x than the batch was actually built with).
    real_width, not chunk_size: each row only ever carries real_width
    real digits (the rest is _attach_edges_pad's fixed edge margin), same
    reasoning as _ms6_batch's own rows= line."""
    real_width = chunk_size - rand_edge_size
    return max(1, -(-u.DOMAIN_HASH_DIGITS // real_width))


def _seal_from_counts(cnt, chunk_size, d, q, mod):
    """Digit counts -> one sealed scalar: the tail of _seal_batch's flat
    fold. Pure function of the counts, which is what lets _SealTree refresh
    a node by editing its counts instead of re-folding its children."""
    H = [[ut.cell_product_mod(cnt[i][j], q, mod) for j in range(chunk_size)]
             for i in range(len(cnt))]

    H = [ut.vsum_level_fold_mod(d, mod, values=H1, global_keys=True) for H1 in H]
    return ut.vsum_level(H,b=chunk_size)


def ms6(vals, d, q, s=None, pad_size=DEFAULT_HMAX_PAD_SIZE, s_exp=DEFAULT_S_EXP, chunk_size=DEFAULT_CHUNK_SIZE, batch_size=DEFAULT_BATCH_SIZE,
        mod=DEFAULT_MOD, s_mod=None, s_q=DEFAULT_S_Q, keep_hm=DEFAULT_KEEP_HM,
        workers=DEFAULT_WORKERS, seal_batch_size=DEFAULT_SEAL_BATCH_SIZE,
        rand_edge_size=DEFAULT_RAND_EDGE_SIZE):
    """Splits vals into batch_size-sized groups and commits to each one
    independently via _ms6_batch, all under the same secret salt s. Every
    batch's h is already fully row-sealed before this function folds batches
    together via _seal_batch, the identical combine _ms6_batch uses for
    rows, one level up (over per-batch h scalars instead of per-row h_d
    values) -- required, not cosmetic, since a raw un-sealed per-batch value
    folded straight into the final combine would be forgeable.

    perm_list holds each batch's secret-salt-derived column permutation
    (see _column_perm) -- pass it to vs6 alongside x_list; ps6 doesn't
    need it separately, since hm_list is already stored in permuted form.
    h1_salt_list holds each batch's secret-salt-derived H1/H2 salt (see
    _h1_salt) -- same deal: pass it to vs6 alongside perm_list, ps6 needs
    no separate copy of it either.

    d is likewise not placed in the returned params dict (see PARAM_KEYS's
    own comment) -- callers must track the d they passed in here
    themselves and supply it explicitly to ps6()/vs6() later, the same way
    the caller of Commitment already gets it back via C.d. This keeps d
    out of the blob a party who only holds `c` (never an opening) would
    ever see; it does not hide d from anyone who does see an opening, since
    a disclosed proof's own shape reveals it regardless (see PARAM_KEYS's
    comment for the reasoning).

    s_mod=None (the default) builds every batch's S grid in DEFAULT_S_MOD,
    the same ring the H side uses. It is deliberately not returned and not
    placed in params: nothing downstream needs it. S's own
    values travel to ps6 in s_list, and both ms6 and ps6 feed those integers
    to pow(S[j], d, mod) in the H-side ring, so how S was derived never
    enters the check -- ps6 does not need s_mod, and vs6 is never told it.
    Pass an explicit s_mod to use a different ring (e.g. pinning one to
    reproduce a commit in a test).

    workers>1 parallelizes ACROSS batches when there's more than one --
    each batch's own commit is fully independent (same shared `s` as
    input, no shared mutable state), so this is a plain map. Each batch's
    own call then runs with workers=1 (no row-level parallelism inside
    it): nesting a second ProcessPoolExecutor inside a pool worker fails
    (worker processes are daemonic and can't spawn their own children),
    so the row-level parallelism _ms6_batch itself offers is only used
    when there's a single batch to begin with.
    """
    _validate_d(d, mod)
    hmax = pad_size+int(str(ut.hash(max(vals), s_mod, s_exp)))

    # S's ring: shared with the H side by default -- see DEFAULT_S_MOD.
    if s_mod is None:
        s_mod = DEFAULT_S_MOD

    if s is None:
        s = gen.randrange(hmax)
    else:
        # seal_mod is generated here, not above, so the s=None path doesn't
        # pay for a prime it never uses (generate_prime is the single most
        # expensive step in a small commit).
        # +1 bit: generate_prime(n) returns a value in [2**(n-1), 2**n), so
        # asking for hmax.bit_length() alone can land *below* hmax. One more
        # bit puts the prime at >= 2**hmax.bit_length() > hmax, always.
        seal_mod = _seal_mod(hmax.bit_length() + 1)
        s0 = gen.randrange(hmax)
        # x sized to domain_hash's actual (fixed) output width, not s0's/
        # s's own decimal length -- see _seal_fold_rows. _seal_rows no
        # longer hashes its own input (see its docstring), so s0 and s are
        # hashed explicitly here, the same standard of hash h_list's own
        # entries get from _seal_grid.
        s = _seal_batch([_seal_hash(s0), _seal_hash(s)],
                         chunk_size, _seal_fold_rows(chunk_size), d, q, mod=seal_mod)

    starts = list(range(0, len(vals), batch_size))

    if workers and workers > 1 and len(starts) > 1:
        from concurrent.futures import ProcessPoolExecutor
        with ProcessPoolExecutor(max_workers=workers) as ex:
            futures = [
                ex.submit(_ms6_batch, vals[start:start + batch_size], chunk_size, d, q, s,
                          mod=mod, s_mod=s_mod, s_q=s_q, rand_edge_size=rand_edge_size,
                          keep_hm=keep_hm, workers=1, batch_index=batch_index)
                for batch_index, start in enumerate(starts)
            ]
            batch_results = [f.result() for f in futures]
    else:
        batch_results = [
            _ms6_batch(vals[start:start + batch_size], chunk_size, d, q, s,
                       mod=mod, s_mod=s_mod, s_q=s_q, rand_edge_size=rand_edge_size,
                       keep_hm=keep_hm, workers=workers, batch_index=batch_index)
            for batch_index, start in enumerate(starts)
        ]

    h_list, x_list, s_list, hm_list, perm_list, h1_salt_list = [], [], [], [], [], []
    for h_b, x_b, s_b, hm_b, perm_b, h1_salt_b, _cntH, _cntS, _salt in batch_results:
        h_list.append(h_b)
        x_list.append(x_b)
        s_list.append(s_b)
        hm_list.append(hm_b)
        perm_list.append(perm_b)
        h1_salt_list.append(h1_salt_b)

    params = make_params(q, chunk_size, batch_size, mod, seal_batch_size, rand_edge_size)
    h = _seal_batch(h_list, chunk_size, max(x_list), d, q, mod, seal_batch_size)

    return h, h_list, x_list, s_list, hm_list, perm_list, h1_salt_list, params


class _SealTree:
    """Cached view of _seal_batch's fold, so a changed leaf costs a path to
    the root instead of a full re-fold.

    Two things make this work, both properties of _seal_batch itself:

    1. The fold is a seal_batch_size-ary tree. Groups are sliced
       positionally (vals[start:start + sbs]), so leaf i only ever feeds
       node i // sbs, and changing it touches exactly one node per level.
    2. Every node is a pure function of its own digit counts
       (_seal_from_counts). So a node is refreshed by subtracting the old
       child's rows and adding the new child's -- O(x*chunk_size) -- rather
       than re-hashing its <= sbs children.

    Point 2 is why this pays off even below the sbs threshold, where the
    tree is a single root node: a one-leaf change there costs a count edit
    instead of re-hashing every batch in the commitment.

    root() reproduces _seal_batch(leaves, ...) exactly; the equality is
    asserted in the tests rather than assumed.
    """

    def __init__(self, leaves, x, chunk_size, d, q, mod, sbs=DEFAULT_SEAL_BATCH_SIZE):
        self.x, self.chunk_size = x, chunk_size
        self.d, self.q, self.mod, self.sbs = d, q, mod, sbs
        self._chunk_of = _seal_chunker(x, chunk_size)
        self.build(leaves)

    def build(self, leaves):
        """Full rebuild. Used on construction and whenever the tree's shape
        changes (a new node or level appears, or x changes).

        leaves must already be hashed (_seal_hash) -- Commitment builds
        this over self.h_list, whose entries are _seal_grid's own hashed
        output. Every non-root level computed here gets _seal_hash applied
        before it's stored, so it also reads back as an already-hashed
        value the next time it's used as a group's own input (_counts_of,
        or a later _propagate) -- exactly mirroring _seal_batch's own
        recursive branch, which is what keeps root() equal to
        _seal_batch(leaves, ...)."""
        self.levels = [list(leaves)]
        self.counts = [None]                    # level 0 are raw leaves, no counts
        level = self.levels[0]
        while True:
            groups = ([level] if len(level) <= self.sbs
                      else [level[i:i + self.sbs] for i in range(0, len(level), self.sbs)])
            cnts = [self._counts_of(g) for g in groups]
            raw = [_seal_from_counts(c, self.chunk_size, self.d, self.q, self.mod) for c in cnts]
            is_root = len(raw) == 1
            level = raw if is_root else [_seal_hash(v) for v in raw]
            self.levels.append(level)
            self.counts.append(cnts)
            if is_root:
                break
        return self.root

    def _counts_of(self, vals):
        acc = u.Acc(self.x, self.chunk_size)
        for t, v in enumerate(vals):
            acc.add(_seal_rows(v, self._chunk_of))
            if (t & (FLUSH - 1)) == FLUSH - 1:
                acc.flush()
        acc.flush()
        return acc.cnt

    @property
    def root(self):
        return self.levels[-1][0]

    def _propagate(self, idx, old_v, new_v):
        """Walk one changed value up the tree, editing each ancestor's
        counts in place. old_v=None means the child is newly present.

        Same hash-unless-root rule as build(): every ancestor recomputed
        here gets _seal_hash applied before it's stored/fed further up,
        except the root itself -- k == len(self.levels)-1 identifies it
        (fixed for the duration of one call; only build() ever changes the
        tree's depth)."""
        for k in range(1, len(self.levels)):
            j = idx // self.sbs
            cnt = self.counts[k][j]
            if old_v is not None:
                _apply_rows(cnt, _seal_rows(old_v, self._chunk_of), -1)
            _apply_rows(cnt, _seal_rows(new_v, self._chunk_of), +1)
            old_v = self.levels[k][j]
            raw = _seal_from_counts(cnt, self.chunk_size, self.d, self.q, self.mod)
            new_v = raw if k == len(self.levels) - 1 else _seal_hash(raw)
            self.levels[k][j] = new_v
            idx = j
        return self.root

    def update_leaf(self, i, new_val):
        old = self.levels[0][i]
        if old == new_val:
            return self.root
        self.levels[0][i] = new_val
        return self._propagate(i, old, new_val)

    def append_leaf(self, val):
        """Incremental when the new leaf joins an existing level-1 node;
        a full rebuild when it starts a new node (once every sbs appends),
        since that changes the tree's shape."""
        i = len(self.levels[0])
        if len(self.levels) > 1 and i // self.sbs < len(self.levels[1]) and len(self.levels[1]) > 1:
            self.levels[0].append(val)
            return self._propagate(i, None, val)
        if len(self.levels) == 2 and i < self.sbs:
            # single root node still has room: extend it in place
            self.levels[0].append(val)
            return self._propagate(i, None, val)
        self.levels[0].append(val)
        return self.build(self.levels[0])


class Commitment:
    """An ms6 commitment that can be appended to and edited in place.

    Rationale: the commit pipeline is count-based --

        items -> accH/accS digit counts -> cell_product_mod -> row-seal
              -> positional pack -> _seal_batch tree -> c

    -- and only the counts depend on *which* items are in the set. So an
    update edits one batch's counts (O(x*chunk_size)), re-runs _seal_grid
    for that batch alone, and refolds the root. No other item is rehashed.

    opening() hands back exactly the tuple ms6() returns, so ps6/vs6 consume
    an updated commitment with no changes at all.

    WHAT AN UPDATE INVALIDATES: `c` changes, so every verifier needs the new
    one, and S changes for the touched batch, so any proof already issued
    from that batch must be re-issued via ps6. Proofs do not survive updates
    -- that is a strictly stronger property this construction doesn't offer.

    BATCH UNIFORMITY IS LOAD-BEARING: ps6/vs6 locate a batch with
    `index // batch_size` while ps6 also derives local offsets from actual
    len(hm_b). Those agree only while every batch except the last holds
    exactly batch_size items. So append fills the last partial batch or
    opens a new one, and replace keeps items in place -- neither ever
    splices, which would shift every later index. delete() tombstones for
    the same reason -- it blanks the slot rather than removing it.

    NOTE ON delete(): tombstoning means an updated commitment is no longer
    bit-identical to a from-scratch commit over the surviving values, since
    a fresh commit would compact the slots that delete() deliberately
    keeps. The equivalence that does hold, and is what the tests assert, is
    that delete() subtracts exactly what is in the slot: replace(i, X)
    followed by delete(i) lands on the same commitment as delete(i) alone.

    NOTE ON hm2's edges (see ms6.core's EDGE-COLUMN PADDING comment): they
    are derived from (h1_salt, slot_index, row_index) -- deterministic and
    recomputable, like hm1's edges, just not from the item's own hash the
    way hm1's real columns are. A genuinely random alternative was tried
    and reverted: it added no binding or hiding beyond what hm1's own fix
    already provides, and it broke bit-identical incremental-vs-from-
    scratch equivalence for no offsetting benefit -- see ms6.core's own
    comment for the fuller comparison.
    """

    def __init__(self, vals, d, q, s=None, pad_size=DEFAULT_HMAX_PAD_SIZE, s_exp=DEFAULT_S_EXP,
                 chunk_size=DEFAULT_CHUNK_SIZE, batch_size=DEFAULT_BATCH_SIZE, mod=DEFAULT_MOD,
                 s_mod=None, s_q=DEFAULT_S_Q, workers=DEFAULT_WORKERS,
                 batch_salts=None, seal_batch_size=DEFAULT_SEAL_BATCH_SIZE,
                 rand_edge_size=DEFAULT_RAND_EDGE_SIZE):
        """batch_salts pins each batch's salt instead of drawing fresh ones.
        Only for reproducing a commitment (the incremental-vs-from-scratch
        equivalence test relies on it); leave it None in normal use.
        Pinning it also pins h1_salt (see _h1_salt) for free, since h1_salt
        is derived from the batch salt rather than drawn independently --
        no separate pinning knob is needed for it."""
        vals = list(vals)
        if not vals:
            raise ValueError("Commitment needs at least one value")

        _validate_d(d, mod)
        self.d, self.q, self.s_exp = d, q, s_exp
        self.chunk_size, self.batch_size = chunk_size, batch_size
        self.mod, self.workers = mod, workers
        self.seal_batch_size = seal_batch_size
        # captured, not re-read from the constant: a changed
        # DEFAULT_RAND_EDGE_SIZE would otherwise change which columns are
        # edge-padded on the next reseal/update, corrupting this commitment.
        self.rand_edge_size = rand_edge_size
        # captured, not re-read from the constant: a changed DEFAULT_S_Q
        # would otherwise rebuild S differently on the next reseal and
        # invalidate this commitment.
        self.s_q = s_q

        hmax = pad_size + int(str(ut.hash(max(vals), s_mod, s_exp)))
        self.s_mod = DEFAULT_S_MOD if s_mod is None else s_mod
        if s is None:
            s = gen.randrange(hmax)
        self.s = s

        self.vals = []
        self.dead = set()
        self.salts, self.x_list, self.perms, self.h1_salts = [], [], [], []
        self.cntH, self.cntS, self.hm_list = [], [], []
        self.s_list, self.h_list = [], []

        self._tree = self._tree_x = None
        self._pinned_salts = list(batch_salts) if batch_salts else None
        batch_groups = [vals[start:start + batch_size] for start in range(0, len(vals), batch_size)]
        if self.workers and self.workers > 1 and len(batch_groups) > 1:
            self._new_batches_parallel(batch_groups)
        else:
            for group in batch_groups:
                self._new_batch(group)
        self._refresh_root()

    # --- construction -----------------------------------------------------

    def _next_salt(self, batch_index):
        if self._pinned_salts is not None and batch_index < len(self._pinned_salts):
            return self._pinned_salts[batch_index]
        return gen.randrange(self.s)

    def _new_batch(self, batch_vals):
        b = len(self.h_list)
        salt = self._next_salt(b)
        h, x, S, hm, perm, h1_salt, cntH, cntS, salt = _ms6_batch(
            batch_vals, self.chunk_size, self.d, self.q, self.s,
            mod=self.mod, s_mod=self.s_mod, rand_edge_size=self.rand_edge_size,
            keep_hm=True, workers=self.workers,
            batch_index=b, batch_salt=salt)
        self.vals.extend(batch_vals)
        self.salts.append(salt)
        self.x_list.append(x)
        self.perms.append(perm)
        self.h1_salts.append(h1_salt)
        self.cntH.append(cntH)
        self.cntS.append(cntS)
        self.hm_list.append(hm)
        self.s_list.append(S)
        self.h_list.append(h)
        return b

    def _new_batches_parallel(self, batch_groups):
        """Builds several NEW batches at once via ProcessPoolExecutor,
        mirroring ms6()'s own across-batch parallel-map (see its docstring)
        -- used for the initial multi-batch construction in __init__, where
        every batch is independent (same shared `s`, no mutable state yet
        to race on). append()'s "open one new batch" path stays on
        _new_batch unchanged: there's a single batch to build, nothing to
        parallelize across.

        Salts are resolved here, sequentially, BEFORE dispatch -- not
        inside the worker calls -- for two reasons. First, _next_salt reads
        the shared `gen` random generator (or the pinned-salt list) by
        batch index in order; drawing it inside worker processes would
        make the salt sequence depend on however the pool happens to
        schedule work, breaking reproducibility (the same vals + same
        pinned batch_salts should build the same Commitment regardless of
        workers=1 vs workers>N). Second, it keeps _ms6_batch itself
        oblivious to whether it's running sequentially or in a pool -- it
        always receives an already-decided batch_salt, exactly as
        _new_batch already gives it one.

        Each dispatched call runs with workers=1, same reasoning as ms6():
        worker processes are daemonic and can't spawn their own child
        pool, so a batch's internal row-level parallelism is only
        available when there's just one batch to build in the first
        place (_new_batch's plain workers=self.workers path)."""
        b0 = len(self.h_list)
        salts = [self._next_salt(b0 + i) for i in range(len(batch_groups))]

        from concurrent.futures import ProcessPoolExecutor
        with ProcessPoolExecutor(max_workers=self.workers) as ex:
            futures = [
                ex.submit(_ms6_batch, group, self.chunk_size, self.d, self.q, self.s,
                          mod=self.mod, s_mod=self.s_mod,
                          s_q=self.s_q, rand_edge_size=self.rand_edge_size, keep_hm=True, workers=1,
                          batch_index=b0 + i, batch_salt=salts[i])
                for i, group in enumerate(batch_groups)
            ]
            results = [f.result() for f in futures]

        for group, (h, x, S, hm, perm, h1_salt, cntH, cntS, salt) in zip(batch_groups, results):
            self.vals.extend(group)
            self.salts.append(salt)
            self.x_list.append(x)
            self.perms.append(perm)
            self.h1_salts.append(h1_salt)
            self.cntH.append(cntH)
            self.cntS.append(cntS)
            self.hm_list.append(hm)
            self.s_list.append(S)
            self.h_list.append(h)

    # --- accessors --------------------------------------------------------

    @property
    def params(self):
        """The public parameter dict for this commitment -- same contents
        ms6() returns, so ps6/vs6 are driven by it identically. Does NOT
        include d (see PARAM_KEYS's own comment) -- use self.d, passed
        explicitly to ps6()/vs6() alongside this dict."""
        return make_params(self.q, self.chunk_size, self.batch_size,
                           self.mod, self.seal_batch_size, self.rand_edge_size)

    def opening(self):
        """(c, h_list, x_list, s_list, hm_list, perm_list, h1_salt_list,
        params) -- same shape and meaning as ms6()'s return, so ps6/vs6
        take it unchanged."""
        return (self.c, self.h_list, self.x_list, self.s_list, self.hm_list,
                self.perms, self.h1_salts, self.params)

    def _chunk_of(self, b):
        real_width = self.chunk_size - self.rand_edge_size
        return chunks(self.x_list[b], real_width)

    def _s0(self, b):
        # recomputed from the stored salt rather than kept resident: it's
        # deterministic, and x*chunk_size full-width ints per batch is the
        # bulkiest thing here.
        return _s0_grid(self.salts[b], b, self.x_list[b], self.chunk_size, self.s_mod)

    # --- update primitives ------------------------------------------------

    def _check_fits(self, b, val, hm1, hm2):
        """Guards append()/replace() against the same silent-truncation risk
        _ms6_batch's own x-sizing fix (see its docstring) closed for the
        initial commit. That fix sizes a NEW batch's x from every item's
        hash width up front; it can't help an EXISTING batch, since x is
        already fixed by the time an update comes in.

        chunk_of pads a short digest up to x but does not grow x for a long
        one -- it returns the digest's own (longer) chunk list unchanged.
        _apply_rows then only reads the first len(cnt)==x of those rows,
        which (per its own docstring) are the MOST-significant end; the
        item's low-order chunks would be silently dropped from the count
        grid, and the update would proceed on a truncated contribution
        instead of failing loudly. Rather than allow that, refuse the
        update: the caller needs a batch wide enough for this item, e.g. by
        deleting+re-appending so a fresh (correctly-sized) batch is opened,
        or by rebuilding the commitment from scratch."""
        x = self.x_list[b]
        if len(hm1) > x or len(hm2) > x:
            raise ValueError(
                f"value {val!r} hashes wider than batch {b}'s current row "
                f"count (x={x}); this update would silently truncate its "
                f"low-order digits. Delete the old slot and append() the "
                f"value instead (opens a batch sized for it), or rebuild "
                f"the Commitment from scratch.")

    def _reseal(self, b):
        h, S = _seal_grid(self.cntH[b], self.cntS[b], self._s0(b), self.chunk_size,
                          self.d, self.q, self.mod, self.s_mod, self.workers,
                          self.s_q)
        self.h_list[b], self.s_list[b] = h, S

    def _rebuild_tree(self):
        self._tree_x = max(self.x_list)
        self._tree = _SealTree(self.h_list, self._tree_x, self.chunk_size,
                               self.d, self.q, self.mod, sbs=self.seal_batch_size)
        self.c = self._tree.root

    def _refresh_root(self, leaf=None, appended=False):
        """Maintains the cached seal tree (see _SealTree).

        `leaf=b` means batch b's h changed; `appended=True` means h_list
        just grew. Either way this falls back to a full rebuild when the
        tree's x (= max(x_list)) moves, since every node's counts are
        chunked to that width -- a new batch with a taller grid invalidates
        the whole tree, not just one path.
        """
        if self._tree is None or self._tree_x != max(self.x_list):
            return self._rebuild_tree()
        if appended:
            self.c = self._tree.append_leaf(self.h_list[-1])
        elif leaf is not None:
            self.c = self._tree.update_leaf(leaf, self.h_list[leaf])
        else:
            self._rebuild_tree()

    def append(self, val):
        """Stage 1. Adds `val` and returns its global index. Fills the last
        partial batch, or opens a new one when it's full -- never grows a
        batch past batch_size, which would break ps6/vs6's index math."""
        last = len(self.h_list) - 1
        if last < 0 or len(self.hm_list[last]) >= self.batch_size:
            self._new_batch([val])
            self._refresh_root(appended=True)
            return len(self.vals) - 1

        hm1, hm2 = _item_rows(val, self._chunk_of(last), self.perms[last],
                              self.rand_edge_size, self.h1_salts[last],
                              len(self.hm_list[last]), self.chunk_size, self.mod)
        self._check_fits(last, val, hm1, hm2)
        _apply_rows(self.cntH[last], hm1, +1)
        _apply_rows(self.cntS[last], hm2, +1)
        self.hm_list[last].append(hm1)
        self.vals.append(val)
        self._reseal(last)
        self._refresh_root(leaf=last)
        return len(self.vals) - 1

    def replace(self, index, new_val):
        """Stage 2. Swaps the value at `index` in place: subtracts the old
        item's digit contribution from the batch's counts, adds the new
        one's, and reseals that batch only. The slot is reused, so no index
        anywhere shifts."""
        if not 0 <= index < len(self.vals):
            raise IndexError(f"index {index} outside 0..{len(self.vals) - 1}")
        if index in self.dead:
            raise ValueError(f"index {index} is deleted; replace() cannot revive a slot")
        b = index // self.batch_size
        local = index - b * self.batch_size
        chunk_of, perm = self._chunk_of(b), self.perms[b]

        h1_salt = self.h1_salts[b]
        old_h1, old_h2 = _item_rows(self.vals[index], chunk_of, perm, self.rand_edge_size, h1_salt, local,
                                    self.chunk_size, self.mod)
        new_h1, new_h2 = _item_rows(new_val, chunk_of, perm, self.rand_edge_size, h1_salt, local,
                                    self.chunk_size, self.mod)
        self._check_fits(b, new_val, new_h1, new_h2)
        _apply_rows(self.cntH[b], old_h1, -1)
        _apply_rows(self.cntS[b], old_h2, -1)
        _apply_rows(self.cntH[b], new_h1, +1)
        _apply_rows(self.cntS[b], new_h2, +1)

        self.hm_list[b][local] = new_h1
        self.vals[index] = new_val
        self._reseal(b)
        self._refresh_root(leaf=b)
        return index

    def delete(self, index):
        """Stage 3. Removes the item at `index` by tombstoning its slot.

        The slot is blanked (hm entry -> None), NOT spliced out: ps6/vs6
        locate a batch with `index // batch_size`, so removing an entry
        would shift every later index and silently misroute every
        subsequent claim. The item's digit contribution is subtracted from
        the batch's counts, so it is genuinely gone from the commitment --
        only the empty slot remains.

        Deleted slots are not reused by append(); a global index, once
        issued, keeps its meaning for the life of the commitment.
        """
        if not 0 <= index < len(self.vals):
            raise IndexError(f"index {index} outside 0..{len(self.vals) - 1}")
        if index in self.dead:
            raise ValueError(f"index {index} is already deleted")
        b = index // self.batch_size
        local = index - b * self.batch_size

        old_h1, old_h2 = _item_rows(self.vals[index], self._chunk_of(b),
                                    self.perms[b], self.rand_edge_size,
                                    self.h1_salts[b], local,
                                    self.chunk_size, self.mod)
        _apply_rows(self.cntH[b], old_h1, -1)
        _apply_rows(self.cntS[b], old_h2, -1)

        self.hm_list[b][local] = None
        self.vals[index] = None
        self.dead.add(index)
        self._reseal(b)
        self._refresh_root(leaf=b)
        return index

    # --- salt rotation (multi-query mitigation) ----------------------------

    def rotate_batch_salt(self, b, new_salt=None):
        """Refreshes batch `b`'s blinding grid (S0/S) under a FRESH secret
        salt -- the operator-side mitigation QueryGovernor's own docstring
        names but deliberately leaves "out of scope for this class."

        WHY THIS HELPS obs:ratio (the multi-query correlation gap;
        ms6_vibe.md entries 48/78/79, README's Security section): two
        proofs issued against this batch cancel S(r,j) via their ratio
        only because they share the SAME S. Rotating draws a fresh one, so
        any proof issued AFTER this call shares nothing with any proof
        issued BEFORE it -- the ratio no longer cancels. This is NOT per
        query: rotate on whatever cadence an operator chooses (e.g. once
        QueryGovernor.history_for_batch(b) approaches max_openings_per_
        batch), and every query served between two rotations is free.
        It is NOT a new commitment either: same Commitment object, same
        vals/indices/every-other-batch, same top-level secret `s` -- only
        this one batch's h/S (and therefore `c`, the seal-tree root)
        change.

        WHAT THIS DOES NOT DO: it does not stop ratio-cancellation BETWEEN
        two proofs issued in the SAME window (QueryGovernor's job, still
        needed), and it does not touch the underlying cause (S reused
        across queries at all) -- only the WINDOW during which any one S
        stays exploitable. Mitigation, not proof, exactly like
        QueryGovernor itself. Pair with governor.forget_batch(b) (if using
        one) so its history doesn't keep tracking against a now-stale S.

        WHY IT'S CHEAP: only S0 -- and therefore h_list[b]/s_list[b] --
        is recomputed, via the same _reseal() replace()/delete() already
        call on every single-item update. perm, h1_salt, hm_list[b], and
        every item's cntH/cntS contribution are untouched: nothing but
        _s0() ever reads self.salts[b] (grep the class -- one call site).
        No item is re-hashed or re-permuted, unlike a full batch rebuild
        (which WOULD need that, since perm/h1_salt are themselves
        salt-derived but are deliberately not rotated here -- their job,
        per _h1_salt's own docstring, is the offline dictionary-guessing
        gap, not obs:ratio; rotating them would cost re-hashing every
        item in the batch for no benefit to the gap this method targets).

        new_salt: pin an explicit value (reproducibility in tests); None
        (the default) draws a fresh one the same way _next_salt does.
        Returns the new salt.
        """
        if not 0 <= b < len(self.h_list):
            raise IndexError(f"batch {b} outside 0..{len(self.h_list) - 1}")
        self.salts[b] = new_salt if new_salt is not None else gen.randrange(self.s)
        self._reseal(b)
        self._refresh_root(leaf=b)
        return self.salts[b]

    @property
    def live_count(self):
        """Items still in the commitment. len(self.vals) counts tombstoned
        slots too, since those slots are deliberately retained."""
        return len(self.vals) - len(self.dead)


def _get_batch_ids(indices, batch_size=DEFAULT_BATCH_SIZE):
    """Given a list of indices, return the corresponding batch (group) id for each."""
    return [index // batch_size for index in indices]


class QueryPolicyViolation(Exception):
    """Raised by QueryGovernor.authorize() when a claim set should not be
    served -- see QueryGovernor's own docstring for what this does and
    does not defend against."""


class QueryGovernor:
    """A deployment-level POLICY layer, not a cryptographic fix, for the
    multi-query correlation risk the eprint documents (Observation
    obs:ratio / "What an observer can still compute"): the blinding grid
    S(r,j) is fixed for the whole life of a commitment -- it is folded
    into H'(r,j) = H(r,j) * S(r,j)^d at commit time, which is what gets
    row-sealed into h_row, then h_batch, then c itself (_seal_grid). It
    cannot be refreshed per query without changing c; Commitment.replace()/
    append() deliberately reuse the SAME s/perm/S0 for exactly this reason
    (see thm:update-equiv). So closing this cryptographically would mean
    decoupling c from S entirely and adding a per-query rerandomization
    proof -- a real redesign, not a drop-in fix (see the eprint's
    discussion of why blinding S more heavily does not, by itself, change
    that it's fixed across openings).

    What CAN be done without touching the scheme's math: refuse to serve
    an opening whose claim set is suspiciously close to one already
    served against the same batch, and cap how many distinct openings a
    batch will ever serve before an operator should rotate that batch's
    salt via Commitment.rotate_batch_salt() (the actual reseal is out of
    scope for this class -- it just tracks when that's due), then clear
    this governor's own record of it via forget_batch() (below).

    WHY min_new_items=3, not 2: the literal obs:ratio construction queries
    claim sets differing by exactly one item (symmetric difference 1) to
    cancel S(r,j) in the ratio between the two proofs -- both the "add one
    claimed item" direction (I1={i1} then I2={i1,i0}, as stated in the
    eprint) and its mirror, "drop one claimed item" (I2 first, then I1),
    are symmetric difference 1 and are both blocked once min_new_items >=
    2. A THIRD shape -- swapping one claimed item for an unrelated one
    (I1={a} then I2={b}, a != b) -- is symmetric difference 2, not 1 (the
    two claim sets share no elements at all), and needs min_new_items >= 3
    to catch.

    That third shape is not a marginal case worth a lower priority than
    the other two: it is a full, clean break, not a partial one. Every
    column p -- edge or interior, not just the handful mul_combinations_mod's
    own KNOWN LEAK comment calls out -- has a pure (p,...,p) combo sitting
    in bucket idx=p*d at a publicly-computable list position, so
    combined[j] = row[j] * S(r,j)^d is root-extractable column-by-column
    from ONE proof alone (confirmed against the shipped defaults with an
    ad-hoc verification script, same spirit as tests/test_leak.py). A single
    OTHER query with a disjoint single-item claim is then all it takes to
    cancel S(r,j) via ratio and recover BOTH claimed items' actual digit
    at every real column via a 10x10 brute force over DIGIT_PRIMES -- two
    ordinary, unrelated single-item opens, no crafted similarity required.
    min_new_items=3 is the default specifically because 2 does not stop
    this.

    This is deliberately NOT presented as a complete defense: a patient
    adversary submitting many claim sets that are each individually >=
    min_new_items away from every prior one can, in principle, still
    assemble a chain of pairwise-permitted queries whose CUMULATIVE
    differences let it isolate individual items' contributions (e.g.
    three queries A, B, C where no pair is closer than min_new_items but
    A/C's own difference, or some linear combination across all three, is
    small) -- and even a single pair AT exactly min_new_items still leaks
    the aggregate ratio of the differing items, just mixed across more
    than one item's digits instead of cleanly isolated to one. Raising
    min_new_items narrows the cleanly-exploitable room but does not
    eliminate the underlying exposure; max_openings_per_batch is the
    actual backstop, since it bounds how many queries an adversary ever
    gets to chain in the first place. Defense in depth, not a proof.

    SCOPE: per-process, in-memory history. This does not survive a
    restart and does not coordinate across multiple prover processes/
    replicas serving the same commitment -- a deployment that needs either
    must back this with shared storage (e.g. swap self._history for a
    lookup against a shared store) or front multiple provers with a
    single governor instance. Flagged here rather than silently assumed.
    """

    def __init__(self, batch_size=DEFAULT_BATCH_SIZE, min_new_items=3,
                 max_openings_per_batch=None, logger=None):
        """batch_size must match the commitment's own (ps6/vs6 read it
        from params; this class is handed it directly since it has no
        other way to learn it, and is meant to run in front of ps6 rather
        than wrap it).

        min_new_items: smallest symmetric-difference size, between a
        requested claim set and every DISTINCT claim set already served
        against the same batch, that authorize() will allow. A repeat of
        an EXACT prior claim set (symmetric difference 0) is always
        allowed and does not consume a max_openings_per_batch slot --
        re-fetching a proof already served is not a new correlation
        opportunity.

        max_openings_per_batch: refuse to record a DISTINCT new claim set
        against a batch once that batch has already served this many
        (None = uncapped). Once a batch hits this, the recommended
        operator action is to rotate that batch's salt.

        logger: optional object with a .warning(msg) method (a stdlib
        logging.Logger works directly), called with a human-readable
        reason on every refusal, before the exception is raised -- so an
        operator gets a durable record even if the caller catches
        QueryPolicyViolation and moves on.
        """
        self.batch_size = batch_size
        self.min_new_items = min_new_items
        self.max_openings_per_batch = max_openings_per_batch
        self.logger = logger
        self._history = {}            # batch_index -> list[frozenset(local indices)]

    def _local_claim_sets(self, iset):
        """Split a GLOBAL claim set into {batch_index: frozenset(local indices)}."""
        by_batch = {}
        for g in iset:
            b = g // self.batch_size
            by_batch.setdefault(b, set()).add(g - b * self.batch_size)
        return {b: frozenset(s) for b, s in by_batch.items()}

    def _warn(self, msg):
        if self.logger is not None:
            self.logger.warning(msg)

    def authorize(self, iset):
        """Call BEFORE generating a proof for `iset` (i.e. before ps6()).
        Raises QueryPolicyViolation and refuses to record anything if any
        touched batch's history makes this claim set too close to one
        already served, or if a touched batch is already at its opening
        cap. Otherwise records the (per-batch) claim sets and returns
        None. Checked read-only against ALL touched batches before
        recording ANY of them, so a violation on one batch never leaves a
        partial record for the others."""
        local = self._local_claim_sets(iset)

        # pass 1: validate every touched batch before recording anything
        for b, claim in local.items():
            history = self._history.get(b, [])
            if claim in history:
                continue                  # exact repeat: always fine, no cap consumed
            if (self.max_openings_per_batch is not None
                    and len(history) >= self.max_openings_per_batch):
                self._warn(f"QueryGovernor: batch {b} refused -- already served "
                           f"{len(history)} distinct claim set(s), at its cap of "
                           f"{self.max_openings_per_batch}; rotate this batch's salt")
                raise QueryPolicyViolation(
                    f"batch {b} is at its opening cap ({self.max_openings_per_batch})")
            for prev in history:
                diff = len(claim ^ prev)
                if diff < self.min_new_items:
                    self._warn(f"QueryGovernor: batch {b} refused -- claim set differs "
                               f"from a previously served one by only {diff} item(s) "
                               f"(minimum {self.min_new_items}); this is the shape "
                               f"Observation obs:ratio exploits")
                    raise QueryPolicyViolation(
                        f"batch {b}: claim set differs from a prior one by only "
                        f"{diff} item(s) (< min_new_items={self.min_new_items})")

        # pass 2: everything validated, now record
        for b, claim in local.items():
            history = self._history.setdefault(b, [])
            if claim not in history:
                history.append(claim)

    def history_for_batch(self, batch_index):
        """Read-only view of the distinct claim sets recorded so far for
        one batch (local indices) -- e.g. to decide whether a batch is
        approaching its cap and due for salt rotation."""
        return list(self._history.get(batch_index, []))

    def forget_batch(self, batch_index):
        """Clears a batch's recorded history -- call this AFTER actually
        rotating that batch's salt (Commitment.rotate_batch_salt), not
        instead of it. Forgetting history alone changes nothing about S;
        it only stops this governor comparing FUTURE claim sets against
        claim sets that were served under a now-replaced S, which would
        otherwise needlessly refuse legitimate new queries once the real
        correlation risk they guarded against no longer applies. Returns
        the number of claim sets forgotten."""
        return len(self._history.pop(batch_index, []))


def ps6_governed(governor, iset, h_list, hm_list, s_list, params, d, workers=DEFAULT_WORKERS, expect=None):
    """Convenience wrapper: governor.authorize(iset) then ps6(...). Purely
    additive -- ps6() itself is unchanged and can still be called directly
    by anyone who doesn't want this policy layer (e.g. a deployment doing
    its own query governance, or one that has decided the risk is
    acceptable for its use case). d is passed through unchanged -- see
    ps6's own docstring for why it's a separate argument now rather than
    part of params."""
    governor.authorize(iset)
    return ps6(iset, h_list, hm_list, s_list, params, d, workers=workers, expect=expect)


def _ps6_batch(hm, iset, chunk_size, d, q, S, mod=DEFAULT_MOD, workers=DEFAULT_WORKERS):
    """hm is ms6's per-item hashed-digit-chunk list (hm[i][r] = a
    chunk_size-length digit string), the same thing ms6 feeds into
    accH/accS.

    row[j] (oset's contribution to column j) is recomputed directly from
    oset's own hm rows every call, via col_digit_counts (a C-speed Counter
    over the joined row strings) + cell_pow_product_mod (folds each column's
    digit counts into a single value via prime factorisation, since digits
    are always 1-9). Mathematically identical to multiplying together every
    oset item's own pow(digit,q,mod) value one at a time, at the cost of
    redoing the O(len(oset)) counting work on every call instead of caching
    anything across calls.

    No full-dataset aggregate is precomputed or subtracted/divided anywhere
    here (see ms6's note on why that would be unsound), so row[j] stays
    exactly as independent of iset/claimed vals as it always was.
    """
    x = len(S)
    iset = set(iset)

    # A tombstoned slot (Commitment.delete) is hm[i] is None: the slot stays
    # so no later index shifts, but the item is gone from the batch's counts
    # and must therefore be gone from oset too, or the proof would fold back
    # a contribution the commitment no longer carries.
    claimed_dead = sorted(i for i in iset if hm[i] is None)
    if claimed_dead:                      # defensive; ps6 checks first, in global indices
        raise ValueError(f"cannot open deleted slot(s), batch-local index: {claimed_dead}")
    oset = {i for i in range(len(hm)) if i not in iset and hm[i] is not None}

    result = []
    for r in range(x):
        row_strings = [hm[i][r] for i in oset]
        cnt = ut.col_digit_counts(row_strings, chunk_size)
        row = [ut.cell_pow_product_mod(cnt[j], q, mod) for j in range(chunk_size)]

        Srow = S[r]
        result.append([(row[j] * pow(Srow[j], d, mod)) % mod for j in range(chunk_size)])

    return _finish_ps6(result, d, chunk_size, workers, mod)


def ps6(iset, h_list, hm_list, s_list, params, d, workers=DEFAULT_WORKERS, expect=None):
    """`params` is ms6()'s own returned parameter dict (see PARAM_KEYS) --
    q/chunk_size/batch_size/mod/seal_batch_size are read from it rather
    than passed loose, so ps6 cannot be run under different parameters than
    the commitment was built with.

    `d` (the row-seal degree) is its own separate, required argument, NOT
    part of `params` -- see PARAM_KEYS's own comment for why: it is
    pre-shared between committer and verifier out of band rather than
    carried in the dict that travels alongside every opening. The caller
    here already knows it (they are the one who called ms6/Commitment with
    it, or are C.d for a Commitment) -- ps6 does not derive or guess it.

    iset holds GLOBAL indices into the original vals list ms6 was given
    (0..sum(len(hm_b) for hm_b in hm_list)-1) -- mapped to each batch's own
    local indices here via hm_list's own per-batch lengths (so callers
    don't need to separately track/pass batch_size). Requires ms6 was
    called with keep_hm=True.

    Every batch gets its own full proof here, not just batches containing a
    claimed item: an unclaimed batch's iset_b is empty, so _ps6_batch's oset
    ends up being every item in that batch -- exactly what "claiming nothing
    there" should produce, still routed through the same per-row nonlinear
    seal as a claimed batch. Returning a raw, un-proven h scalar for
    unclaimed batches instead would be unsound.

    workers>1 parallelizes across TOUCHED batches when a claim spans more
    than one -- each is an independent _ps6_batch call. As in ms6, each
    batch's own call then runs with workers=1 to avoid nesting process
    pools; row-level parallelism inside _ps6_batch/_finish_ps6 is only
    used when a single batch is touched.
    """
    q, chunk_size, batch_size, mod, _sbs, _red = unpack_params(params, expect)
    _validate_d(d, mod)
    iset = set(iset)

    boundaries = []
    offset = 0
    for hm_b in hm_list:
        boundaries.append(offset)
        offset += len(hm_b)

    # Tombstoned slots (Commitment.delete) can't be opened -- reported here
    # in the caller's own GLOBAL indices; _ps6_batch repeats the check in
    # batch-local ones as a defensive guard.
    deleted = sorted(g for g in iset
                     if hm_list[g // batch_size][g - boundaries[g // batch_size]] is None)
    if deleted:
        raise ValueError(f"cannot open deleted slot(s): {deleted}")

    def batch_args(b):
        start = boundaries[b]
        end = start + len(hm_list[b])
        iset_b = {g - start for g in iset if start <= g < end}
        return hm_list[b], iset_b, s_list[b]

    ps_list = h_list.copy()
    touched = set(_get_batch_ids(iset, batch_size))

    if workers and workers > 1 and len(touched) > 1:
        from concurrent.futures import ProcessPoolExecutor
        with ProcessPoolExecutor(max_workers=workers) as ex:
            futures = {}
            for b in touched:
                hm_b, iset_b, S_b = batch_args(b)
                futures[b] = ex.submit(_ps6_batch, hm_b, iset_b, chunk_size, d, q, S_b, mod=mod, workers=1)
            for b, fut in futures.items():
                ps_list[b] = fut.result()
    else:
        for b in touched:
            hm_b, iset_b, S_b = batch_args(b)
            ps_list[b] = _ps6_batch(hm_b, iset_b, chunk_size, d, q, S_b, mod=mod, workers=workers)

    return ps_list


def _finish_ps6(result, d, chunk_size, workers, mod):
    # eval_row_grouped (per-group, per-degree combinatorial enumeration --
    # see its own docstring) leaks a handful of edge columns per row via
    # modular root extraction, at the cost of combinatorial blow-up for
    # large d -- see eval_level_mod's own docstring's KNOWN LEAK
    # discussion. This construction only supports the small-d regime that
    # combinatorial blow-up keeps tractable; reaching larger d without
    # that blow-up would need a fundamentally different (and, per the same
    # discussion, more leaky) enumeration strategy, not something wired
    # into this codebase.
    #
    # Each row draws its OWN, independent partition choice from `gen` (the
    # same RNG source ms6.core already uses for salt draws) -- an index
    # into ut.partition_menu(chunk_size), the public per-chunk_size list of
    # RECIPES (each a list of (orientation, q) steps -- row-major/
    # transposed, possibly several levels deep, or [] for flat)
    # ut.eval_row_grouped's swappable multi-level fold supports (see
    # partition_menu/build_partition's own docstrings for why this can't
    # instead be derived from iset: that was tried, q_chunk_size, and was
    # gameable -- see ms6_vibe.md). The choice is disclosed alongside the
    # row's sweep (as (choice_idx, sweep) pairs) since the verifier needs
    # it to rebuild the same partition and cannot derive it from anything
    # else public.
    #
    # eval_row_grouped's own disclosure (this function's whole job) does
    # NOT depend on which row-seal target (the original h_d(row), or the
    # two-stage fold _seal_grid now builds) the verifier reconstructs from
    # it -- STAGE1's Y-side (this function's own oset sweep) is the same
    # coef=False raw, per-group-per-degree enumeration either way; only
    # vs6.utils6.Utils.mul_row_grouped vs. mul_row_grouped_two_stage (the
    # verifier's own choice of reconstruction) differs. See
    # mul_row_grouped_two_stage's own docstring, and ms6_vibe.md for the
    # verified group-composition derivation (binomial-weighted Cauchy
    # product of each group's own STAGE1 bucket vector) that makes this
    # possible without the combinatorial blow-up a flat, single-group
    # eval_level_mod(d, row, mod, coef=True) call would pay at real
    # chunk_size.
    menu = ut.partition_menu(chunk_size)
    choices = [gen.randrange(len(menu)) for _ in result]
    partitions = [ut.build_partition(menu[c], chunk_size) for c in choices]

    if workers and workers > 1 and len(result) > 1:
        from concurrent.futures import ProcessPoolExecutor
        with ProcessPoolExecutor(max_workers=workers) as ex:
            sweeps = list(ex.map(ut.eval_row_grouped, [d] * len(result), result,
                                  [mod] * len(result), partitions))
    else:
        sweeps = [ut.eval_row_grouped(d, vals, mod, partition)
                  for vals, partition in zip(result, partitions)]

    return list(zip(choices, sweeps))
