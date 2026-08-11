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
DEFAULT_CHUNK_SIZE = 40
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
# vsum_level_fold_mod, mul_combinations_mod, eval_level_mod). All three must use
# the exact same value or verification of honest proofs fails.
DEFAULT_MOD = u.DEFAULT_MOD

# Modulus for building S (the secret-salt blinding grid) in _ms6_batch,
# separate from DEFAULT_MOD so S's ring can be chosen independently of the
# H-side accumulator ring -- e.g. a safe prime, where the subgroup order has
# a large prime factor.
#
# ps6/vs6 need NO matching change: S's *value* is carried in s_list, and both
# ms6 and ps6 use that same integer as a base in the mod-DEFAULT_MOD ring
# (pow(S[j], d, mod)), so how the value was derived never enters the check.
#
# S's ring is the SAME unknown-order composite as the H side, and this is
# now the default for every commit (ms6() no longer generates a per-commit
# prime for it).
#
# TRADE-OFF, deliberately made. S's ring used to be a freshly generated
# 512-bit prime, secret per commit and never shared with the verifier. That
# secrecy is gone; this modulus is public. What replaces it is hardness:
# with phi(n) unknown, an attacker holding S[j] cannot unwind it through
# cell_product_mod to recover accS's counts, whereas a public prime ring
# would have let them.
#
# The two cannot be combined. A per-commit SECRET unknown-order modulus
# would mean generating an RSA modulus per commit, and whoever generated it
# would hold p and q -- a trapdoor that permits exactly the root extraction
# the H-side change exists to prevent. Unknown order therefore requires a
# public nothing-up-my-sleeve value, not a secret one.
#
# What did NOT change: commitments over the same data are still unlinkable,
# because the per-batch salt is still drawn fresh and S0 is a SHAKE-256
# expansion of it (see _s0_grid). The salt, not the modulus, is what makes
# two commits of the same data differ.
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
DEFAULT_S_Q = 10

DEFAULT_S_EXP = 3
DEFAULT_HMAX_PAD_SIZE = int(str(ut.hash(ut.hash(9),DEFAULT_S_EXP)))

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
#   s_mod, s          per-commit secrets -- this dict goes to the verifier
#   s_exp, pad_size,
#   keep_hm           prover-only, never consulted by ps6/vs6
#   workers           a local performance choice; each party picks its own
PARAM_KEYS = ("d", "q", "chunk_size", "batch_size", "mod", "seal_batch_size")


def make_params(d, q, chunk_size=DEFAULT_CHUNK_SIZE, batch_size=DEFAULT_BATCH_SIZE,
                mod=DEFAULT_MOD, seal_batch_size=DEFAULT_SEAL_BATCH_SIZE):
    """The public parameter set, as returned by ms6() and consumed by
    ps6()/vs6()."""
    return {"d": d, "q": q, "chunk_size": chunk_size, "batch_size": batch_size,
            "mod": mod, "seal_batch_size": seal_batch_size}


def _brief(v):
    """Abbreviate a value for an error message -- `mod` is a 2048-bit int and
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
    self-authenticating either, so nonsense or hostile values (mod=1, d=0)
    should not get as far as the arithmetic.

    `expect` may be a subset -- pin only the keys you actually care about
    (typically mod/d/q) and leave the rest free. Unknown keys in `expect`
    raise rather than being silently ignored, so a typo can't quietly
    disable the check it was meant to add.
    """
    missing = [k for k in PARAM_KEYS if k not in params]
    if missing:
        raise KeyError(f"params missing required key(s): {', '.join(missing)}")

    for k in ("d", "q", "chunk_size", "batch_size", "seal_batch_size"):
        v = params[k]
        if not isinstance(v, int) or v < 1:
            raise ParamMismatch(f"params[{k!r}] must be a positive int, got {v!r}")
    if not isinstance(params["mod"], int) or params["mod"] < 2:
        raise ParamMismatch(f"params['mod'] must be an int >= 2, got {params['mod']!r}")

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
    """params -> (d, q, chunk_size, batch_size, mod, seal_batch_size),
    validated first -- see _validate_params."""
    _validate_params(params, expect)
    return tuple(params[k] for k in PARAM_KEYS)


def chunk_of(val, iden, x, chunk_size):
    """Digit rows for one value. Short first chunks and missing rows are
    filled with u.PAD, which occupies its own count slot and contributes no
    prime -- padding is deterministic and public, so it must not affect the
    cell value. It cannot be a decimal digit: every digit indexes a prime
    and therefore carries information."""
    chunks = list(ut.backward_chunk(val, chunk_size))
    chunks[0] = f"{chunks[0]:{u.PAD}>{chunk_size}}"
    return [u.PAD * chunk_size] * (x - len(chunks)) + chunks


def chunks(iden, x, chunk_size):
    def internal(val):
        return chunk_of(val, iden, x, chunk_size)

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


def _hash_item(val, s_exp):
    """One item's two independent hash-digit strings -- H1 (feeds accH, the
    primary commitment grid) and H2 = hash(H1, s_exp) (feeds accS, the
    blinding-side accumulator) -- with the '0' digit remapped to '1'
    throughout ('0' would annihilate its own column's product outright
    rather than contributing neutrally; '1' contributes nothing either,
    since 1**k == 1, so it doubles as the "blank" digit used everywhere in
    this codebase, e.g. `iden`).

    Split out of _item_rows so _ms6_batch can measure every item's actual
    digest width BEFORE deciding how many rows (x) this batch's grid
    needs -- see _ms6_batch's own x-sizing comment for why that ordering
    matters."""
    h1s = _s(ut.hash(val))
    h2s = _s(ut.hash(h1s, s_exp))
    return h1s, h2s


def _item_rows(val, chunk_of, perm, s_exp):
    """One item's permuted digit rows for the H side (hm1) and the S side
    (hm2), against an ALREADY-SIZED chunk_of (x fixed). Factored out of
    _ms6_batch's own loop so the incremental update path (Commitment.
    append/replace) derives an item's contribution the exact same way the
    original commit did -- the two must agree character-for-character or
    the counts they add and subtract won't cancel."""
    h1s, h2s = _hash_item(val, s_exp)
    hm1 = [_permute_row(r, perm) for r in chunk_of(h1s)]
    hm2 = [_permute_row(r, perm) for r in chunk_of(h2s)]
    return hm1, hm2


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
    one over the same items."""
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
        H = [ut.vsum_level_fold_mod(d, mod, values=H1) for H1 in H]

    return ut.vsum_level(1, values=H, b=chunk_size), S


def _ms6_batch(vals, chunk_size, d, q, s, s_exp=DEFAULT_S_EXP, mod=DEFAULT_MOD, s_mod=DEFAULT_S_MOD,
               s_q=DEFAULT_S_Q,
               keep_hm=DEFAULT_KEEP_HM, workers=DEFAULT_WORKERS, batch_index=0, batch_salt=None):
    """Commits a single batch: builds its own accH/accS/S0 from just the
    `vals` it's given, and returns that batch's own h.

    batch_salt pins the per-batch salt instead of drawing a fresh one from
    `s`. ms6() leaves it None (unchanged behaviour); Commitment passes the
    stored salt so a batch can be resealed later against the same S0/perm/x
    it was originally built with."""
    s = gen.randrange(s) if batch_salt is None else batch_salt

    # batch_index is mixed into the permutation seed (not just `s` alone)
    # so batches within the SAME commit don't all leak the same 4 real
    # columns -- every batch here shares one `s` (ms6 passes the same s to
    # every _ms6_batch call), so without this, perm would be identical
    # across the whole commit. See _column_perm's docstring.
    perm = _column_perm(s * 1_000_000_007 + batch_index, chunk_size)
    iden = u.PAD * chunk_size

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
    hashed = [_hash_item(val, s_exp) for val in vals]
    widest = max((len(h) for pair in hashed for h in pair), default=1)
    rows = max(1, -(-widest // chunk_size))                # ceil(widest / chunk_size)

    S0 = _s0_grid(s, batch_index, rows, chunk_size, s_mod)
    x = len(S0)
    accH = u.Acc(x, chunk_size)
    accS = u.Acc(x, chunk_size)

    hm = []
    chunk_of = chunks(iden, x, chunk_size)
    for t, (h1s, h2s) in enumerate(hashed):
        hm1 = [_permute_row(r, perm) for r in chunk_of(h1s)]
        hm2 = [_permute_row(r, perm) for r in chunk_of(h2s)]
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
    #
    # accH/accS's counts and the batch salt are returned for Commitment's
    # sake: the counts are what an update edits in place (no rehashing of
    # untouched items), and the salt is what lets a later reseal rebuild
    # the same S0/perm/x. ms6() discards both.
    return h, x, S, hm, perm, accH.cnt, accS.cnt, s


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


def _seal_batch(vals, chunk_size, x, d, q, mod=None, seal_batch_size=DEFAULT_SEAL_BATCH_SIZE):
    """Folds a list of big-int h scalars into a single scalar: hash+chunk+
    accumulate each value, then row-seal + combine, exactly like
    _ms6_batch's own H does for one row -- just one level up.

    When `vals` is larger than seal_batch_size, it's folded hierarchically
    instead of in one Acc pass: split into seal_batch_size-sized groups,
    seal each group (recursively, in case a group's own sub-groups are
    still oversized), then recurse on the resulting list of group-seals --
    repeating until a single pass at the top covers everything. Below the
    threshold this is exactly the original flat fold, so output for any
    `vals` that already fit in one pass is unchanged.
    """
    vals = list(vals)
    if len(vals) > seal_batch_size:
        vals = [
            _seal_batch(vals[start:start + seal_batch_size], chunk_size, x, d, q, mod, seal_batch_size)
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
    return chunks(u.PAD * chunk_size, x, chunk_size)


def _seal_rows(val, chunk_of):
    """One folded value's digit rows, as _seal_batch accumulates them.
    Shared with _SealTree so a cached node can add or subtract exactly the
    rows the flat fold would have contributed."""
    return chunk_of(_s(ut.hash(val, 1)))


def _seal_from_counts(cnt, chunk_size, d, q, mod):
    """Digit counts -> one sealed scalar: the tail of _seal_batch's flat
    fold. Pure function of the counts, which is what lets _SealTree refresh
    a node by editing its counts instead of re-folding its children."""
    H = [[ut.cell_product_mod(cnt[i][j], q, mod) for j in range(chunk_size)]
             for i in range(len(cnt))]

    H = [ut.vsum_level_fold_mod(d, mod, values=H1) for H1 in H]
    return ut.vsum_level(1, values=H,b=chunk_size)


def ms6(vals, d, q, s=None, pad_size=DEFAULT_HMAX_PAD_SIZE, s_exp=DEFAULT_S_EXP, chunk_size=DEFAULT_CHUNK_SIZE, batch_size=DEFAULT_BATCH_SIZE,
        mod=DEFAULT_MOD, s_mod=None, s_q=DEFAULT_S_Q, keep_hm=DEFAULT_KEEP_HM,
        workers=DEFAULT_WORKERS, seal_batch_size=DEFAULT_SEAL_BATCH_SIZE):
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

    s_mod=None (the default) builds every batch's S grid in DEFAULT_S_MOD,
    the same unknown-order composite the H side uses. It is deliberately not
    returned and not placed in params: nothing downstream needs it. S's own
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
    hmax = pad_size+int(str(ut.hash(ut.hash(max(vals),s_exp))))

    # S's ring: the shared unknown-order composite, not a per-commit prime.
    # See DEFAULT_S_MOD for why the per-commit secret was given up for
    # hardness, and why the two cannot both be had.
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
        s = _seal_batch([s0,s], chunk_size, 1+len(str(s0))//chunk_size, d, q, mod=seal_mod)

    starts = list(range(0, len(vals), batch_size))

    if workers and workers > 1 and len(starts) > 1:
        from concurrent.futures import ProcessPoolExecutor
        with ProcessPoolExecutor(max_workers=workers) as ex:
            futures = [
                ex.submit(_ms6_batch, vals[start:start + batch_size], chunk_size, d, q, s,
                          s_exp=s_exp, mod=mod, s_mod=s_mod, s_q=s_q, keep_hm=keep_hm,
                          workers=1, batch_index=batch_index)
                for batch_index, start in enumerate(starts)
            ]
            batch_results = [f.result() for f in futures]
    else:
        batch_results = [
            _ms6_batch(vals[start:start + batch_size], chunk_size, d, q, s, s_exp=s_exp,
                       mod=mod, s_mod=s_mod, s_q=s_q, keep_hm=keep_hm, workers=workers,
                       batch_index=batch_index)
            for batch_index, start in enumerate(starts)
        ]

    h_list, x_list, s_list, hm_list, perm_list = [], [], [], [], []
    for h_b, x_b, s_b, hm_b, perm_b, _cntH, _cntS, _salt in batch_results:
        h_list.append(h_b)
        x_list.append(x_b)
        s_list.append(s_b)
        hm_list.append(hm_b)
        perm_list.append(perm_b)

    params = make_params(d, q, chunk_size, batch_size, mod, seal_batch_size)
    h = _seal_batch(h_list, chunk_size, max(x_list), d, q, mod, seal_batch_size)

    return h, h_list, x_list, s_list, hm_list, perm_list, params


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
        changes (a new node or level appears, or x changes)."""
        self.levels = [list(leaves)]
        self.counts = [None]                    # level 0 are raw leaves, no counts
        level = self.levels[0]
        while True:
            groups = ([level] if len(level) <= self.sbs
                      else [level[i:i + self.sbs] for i in range(0, len(level), self.sbs)])
            cnts = [self._counts_of(g) for g in groups]
            level = [_seal_from_counts(c, self.chunk_size, self.d, self.q, self.mod) for c in cnts]
            self.levels.append(level)
            self.counts.append(cnts)
            if len(level) == 1:
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
        counts in place. old_v=None means the child is newly present."""
        for k in range(1, len(self.levels)):
            j = idx // self.sbs
            cnt = self.counts[k][j]
            if old_v is not None:
                _apply_rows(cnt, _seal_rows(old_v, self._chunk_of), -1)
            _apply_rows(cnt, _seal_rows(new_v, self._chunk_of), +1)
            old_v = self.levels[k][j]
            new_v = _seal_from_counts(cnt, self.chunk_size, self.d, self.q, self.mod)
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
    """

    def __init__(self, vals, d, q, s=None, pad_size=DEFAULT_HMAX_PAD_SIZE, s_exp=DEFAULT_S_EXP,
                 chunk_size=DEFAULT_CHUNK_SIZE, batch_size=DEFAULT_BATCH_SIZE, mod=DEFAULT_MOD,
                 s_mod=None, s_q=DEFAULT_S_Q, workers=DEFAULT_WORKERS,
                 batch_salts=None, seal_batch_size=DEFAULT_SEAL_BATCH_SIZE):
        """batch_salts pins each batch's salt instead of drawing fresh ones.
        Only for reproducing a commitment (the incremental-vs-from-scratch
        equivalence test relies on it); leave it None in normal use."""
        vals = list(vals)
        if not vals:
            raise ValueError("Commitment needs at least one value")

        self.d, self.q, self.s_exp = d, q, s_exp
        self.chunk_size, self.batch_size = chunk_size, batch_size
        self.mod, self.workers = mod, workers
        self.seal_batch_size = seal_batch_size
        # captured, not re-read from the constant: a changed DEFAULT_S_Q
        # would otherwise rebuild S differently on the next reseal and
        # invalidate this commitment.
        self.s_q = s_q

        hmax = pad_size + int(str(ut.hash(ut.hash(max(vals), s_exp))))
        self.s_mod = DEFAULT_S_MOD if s_mod is None else s_mod
        if s is None:
            s = gen.randrange(hmax)
        self.s = s

        self.vals = []
        self.dead = set()
        self.salts, self.x_list, self.perms = [], [], []
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
        h, x, S, hm, perm, cntH, cntS, salt = _ms6_batch(
            batch_vals, self.chunk_size, self.d, self.q, self.s, self.s_exp,
            mod=self.mod, s_mod=self.s_mod, keep_hm=True, workers=self.workers,
            batch_index=b, batch_salt=salt)
        self.vals.extend(batch_vals)
        self.salts.append(salt)
        self.x_list.append(x)
        self.perms.append(perm)
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
                          s_exp=self.s_exp, mod=self.mod, s_mod=self.s_mod,
                          s_q=self.s_q, keep_hm=True, workers=1,
                          batch_index=b0 + i, batch_salt=salts[i])
                for i, group in enumerate(batch_groups)
            ]
            results = [f.result() for f in futures]

        for group, (h, x, S, hm, perm, cntH, cntS, salt) in zip(batch_groups, results):
            self.vals.extend(group)
            self.salts.append(salt)
            self.x_list.append(x)
            self.perms.append(perm)
            self.cntH.append(cntH)
            self.cntS.append(cntS)
            self.hm_list.append(hm)
            self.s_list.append(S)
            self.h_list.append(h)

    # --- accessors --------------------------------------------------------

    @property
    def params(self):
        """The public parameter dict for this commitment -- same contents
        ms6() returns, so ps6/vs6 are driven by it identically."""
        return make_params(self.d, self.q, self.chunk_size, self.batch_size,
                           self.mod, self.seal_batch_size)

    def opening(self):
        """(c, h_list, x_list, s_list, hm_list, perm_list, params) -- same
        shape and meaning as ms6()'s return, so ps6/vs6 take it unchanged."""
        return (self.c, self.h_list, self.x_list, self.s_list, self.hm_list,
                self.perms, self.params)

    def _chunk_of(self, b):
        iden = u.PAD * self.chunk_size
        return chunks(iden, self.x_list[b], self.chunk_size)

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

        hm1, hm2 = _item_rows(val, self._chunk_of(last), self.perms[last], self.s_exp)
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

        old_h1, old_h2 = _item_rows(self.vals[index], chunk_of, perm, self.s_exp)
        new_h1, new_h2 = _item_rows(new_val, chunk_of, perm, self.s_exp)
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
                                    self.perms[b], self.s_exp)
        _apply_rows(self.cntH[b], old_h1, -1)
        _apply_rows(self.cntS[b], old_h2, -1)

        self.hm_list[b][local] = None
        self.vals[index] = None
        self.dead.add(index)
        self._reseal(b)
        self._refresh_root(leaf=b)
        return index

    @property
    def live_count(self):
        """Items still in the commitment. len(self.vals) counts tombstoned
        slots too, since those slots are deliberately retained."""
        return len(self.vals) - len(self.dead)


def _get_batch_ids(indices, batch_size=DEFAULT_BATCH_SIZE):
    """Given a list of indices, return the corresponding batch (group) id for each."""
    return [index // batch_size for index in indices]


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

    return _finish_ps6(result, d, workers, mod, q)


def ps6(iset, h_list, hm_list, s_list, params, workers=DEFAULT_WORKERS, expect=None):
    """`params` is ms6()'s own returned parameter dict (see PARAM_KEYS) --
    d/q/chunk_size/batch_size/mod/seal_batch_size are read from it rather
    than passed loose, so ps6 cannot be run under different parameters than
    the commitment was built with.

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
    d, q, chunk_size, batch_size, mod, _sbs = unpack_params(params, expect)
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


def _finish_ps6(result, d, workers, mod, q):
    # eval_level_mod (combinatorial enumeration over combinations_with_
    # replacement) leaks a handful of edge columns per row via modular root
    # extraction, at the cost of combinatorial blow-up for large d. This is
    # a deliberate tradeoff: eval_level_rec_mod is a documented alternative
    # that reaches large d at the cost of a materially larger leak (every
    # column, not a handful) -- intentionally not wired in here.
    if workers and workers > 1 and len(result) > 1:
        from concurrent.futures import ProcessPoolExecutor
        with ProcessPoolExecutor(max_workers=workers) as ex:
            return list(ex.map(ut.eval_level_mod, [d] * len(result), result, [mod] * len(result)))
    return [ut.eval_level_mod(d, vals, mod) for vals in result]
