"""vs6: the verifier side of ms6/ps6/vs6, split into its own module (paired
with vs6/utils6.py) so a party that only ever verifies proofs -- e.g.
the bank in zk_sanctions_screening_scale_demo.py -- can import/audit a
self-contained package with zero code paths that could generate a secret
salt, fabricate a proof, or touch prover-only machinery.

This module has NO import dependency on ms6.py or utils6.py: chunk_of/
chunks/_permute_row/_seal_batch/_get_batch_ids are small enough that they're
duplicated here rather than shared, so this file plus vs6/utils6.py
form a complete, independent verifier package -- deploy/install/audit just
these two files to verify proofs, without ever pulling in ms6.py's
SystemRandom-based salt generation or utils6.py's prover-only combinatorics
(col_digit_counts, cell_pow_product_mod, eval_level_mod, seal_row_mod).

If either the shared functions here or their ms6.py counterparts change,
the other copy must be updated to match -- there is no automated check
enforcing that; a regression test comparing the two files' outputs
bit-for-bit would be a reasonable follow-up if this split is kept
long-term (see vs6/utils6.py's own docstring for the same caveat on
the Utils-method side).

vs6's full trust domain, after this split: chunk_of/chunks/_permute_row
(pure reshaping, no state), interlace_mod (rebuilds the claimed items' own
contribution from the claims themselves, not trusted from the prover),
_seal_batch (the same batch-fold ms6 uses, re-run independently here to
recompute the same value from h_list and check it against c), _vs6_batch,
vs6, and vs6.utils6.Utils's hash/mul_combinations_mod/vsum_level(_mod)/
cell_product(_mod)/backward_chunk/Acc. Everything ms6.py/utils6.py
additionally contain is unreachable from here.

PLATFORM NOTE: vs6() uses ProcessPoolExecutor internally when workers>1 and
multiple batches are touched. This is safe to import as a library from any
script (there's no module-top-level multiprocessing call here), but a
*caller* script that itself uses multiprocessing must still guard its own
top-level code with `if __name__ == "__main__":` for correctness on macOS/
Windows (spawn start method) -- see ms6.py's and the demo files' own notes.
"""
import hashlib

from . import utils6 as u
from .utils6 import _s

DEFAULT_CHUNK_SIZE = 40
DEFAULT_BATCH_SIZE = 1000
DEFAULT_WORKERS = 1

# Must match ms6.py's DEFAULT_SEAL_BATCH_SIZE -- _seal_batch below has to
# fold h_list into c the exact same hierarchical way ms6.py folded it into
# c in the first place, or a large-dataset commitment will never verify.
DEFAULT_SEAL_BATCH_SIZE = 1000

# Must stay numerically identical to utils6.DEFAULT_MOD / ms6.DEFAULT_MOD --
# sourced from vs6/utils6's own copy (see that module's DEFAULT_MOD
# comment for provenance) rather than duplicated a fourth time here.
DEFAULT_MOD = u.DEFAULT_MOD

# The former default -- see u.LEGACY_MOD_2048's own comment. Exported for
# any caller who wants the old unknown-order composite explicitly.
LEGACY_MOD_2048 = u.LEGACY_MOD_2048

ut = u.Utils()

# EDGE-COLUMN DECOY PADDING -- vs6's own copy of ms6.core's constants/
# helpers (see that module's own comment for the full rationale). Must stay
# numerically/textually identical to ms6's copy -- H_EDGE_TAG in particular,
# since interlace_mod has to reproduce a claimed item's own decoy digits
# byte-for-byte from the claim alone.
DEFAULT_RAND_EDGE_SIZE = 6
H_EDGE_TAG = "ms6-edge-h"

# Must stay textually identical to ms6.core.H1_TAG -- _vs6_batch uses this
# to independently recompute a claimed item's H1 via Utils.domain_hash
# (SHAKE128), the same way ms6.core._hash_item computes it during commit.
# vs6 never needs H2_TAG: H2/accS/S are prover-only, never reconstructed
# here (see this module's own docstring).
H1_TAG = "ms6-h1"


def _front_back_edge_counts(rand_edge_size):
    return rand_edge_size // 2 + rand_edge_size % 2, rand_edge_size // 2


def _edge_digits(digit_str, row_index, n, tag):
    if n <= 0:
        return ""
    nbytes = max(n, 8)
    digest = hashlib.shake_256(f"{tag}:{row_index}:{digit_str}".encode()).digest(nbytes)
    return str(int.from_bytes(digest, "big")).zfill(n * 4)[-n:]


def _attach_edges(row, digit_str, row_index, rand_edge_size, tag):
    if rand_edge_size <= 0:
        return row
    front_n, back_n = _front_back_edge_counts(rand_edge_size)
    edge = _edge_digits(digit_str, row_index, rand_edge_size, tag)
    return edge[:front_n] + row + edge[front_n:]


# Must match ms6.PARAM_KEYS. Duplicated rather than imported, in keeping with
# this module's zero-prover-dependency goal (see the module docstring).
#
# NOTE FOR VERIFIERS: this dict arrives from the prover alongside the proof.
# It carries no secrets -- but it is also not self-authenticating. A verifier
# that has agreed public parameters out of band should compare `params`
# against them before calling vs6, rather than accepting whatever d/q/mod the
# prover supplies.
PARAM_KEYS = ("d", "q", "chunk_size", "batch_size", "mod", "seal_batch_size", "rand_edge_size")


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


def _permute_row(row, perm):
    return ''.join(row[p] for p in perm)


def interlace_mod(hm, x, chunk_size, k1, mod, perm=None, rand_edge_size=0):
    """Builds vs6's M: for each of the x rows, the product over every
    claimed value's digit at that row/column, each raised to k1, mod `mod`.
    This is vs6's own reconstruction of the claimed items' contribution to
    ms6's H, computed independently from the claimed values rather than
    trusted from the prover.

    Every chunk_of() result is sliced to [:x] so len(H) always matches x
    exactly, mirroring the same convention ms6/ps6 use for hm.

    perm, when given, must be the SAME per-batch column permutation
    _ms6_batch used (see ms6.py's _column_perm) -- applied here to each
    claimed value's own chunked rows before the column-wise power/multiply,
    so M's columns line up with the same real digit positions ps6's
    row[j]/S[j] do. chunk_of is narrowed to chunk_size - rand_edge_size and
    the SAME deterministic decoy digits ms6's _ms6_batch attached (see
    _attach_edges/_edge_digits) are attached here too, AFTER permuting --
    this is what lets a claimed item's edge columns reconstruct
    byte-for-byte even though those columns were never real per-item
    digest data to begin with (see ms6.core's own comment on why the
    decoys must be deterministic, not secret-random).
    """
    real_width = chunk_size - rand_edge_size
    iden = u.PAD * real_width
    chunk_of = chunks(iden, x, real_width)

    def rows_of(val):
        # val is already a digit string: routing it through int() would
        # discard leading zeros, which now index a prime like any other digit
        rows = chunk_of(val)[:x]
        permuted = [_permute_row(r, perm) for r in rows] if perm is not None else rows
        return [_attach_edges(row, val, i, rand_edge_size, H_EDGE_TAG)
                for i, row in enumerate(permuted)]

    def base(ch):
        """Digit -> its own prime; padding -> 1 (contributes nothing).

        Must mirror utils6.cell_product_mod's encoding exactly: M is
        multiplied against the opener's row[j], and the two only cancel if
        both raise the SAME base for a given digit."""
        return 1 if ch == u.PAD else u.DIGIT_PRIMES[int(ch)]

    H = rows_of(hm[0])
    H = [[pow(base(ch), k1, mod) for ch in H1] for H1 in H]
    for val in hm[1:]:
        for row, H1 in zip(H, rows_of(val)):
            for j, ch in enumerate(H1):
                row[j] = (row[j] * pow(base(ch), k1, mod)) % mod

    return H


def _seal_batch(vals, chunk_size, x, d, q, mod=None, seal_batch_size=DEFAULT_SEAL_BATCH_SIZE):
    """Folds a list of big-int h scalars into a single scalar: hash+chunk+
    accumulate each value, then row-seal + combine -- identical logic to
    ms6.py's own _seal_batch (duplicated here, not imported, per this
    module's zero-prover-dependency goal). ms6() uses this to fold
    per-batch h's into one commitment c; vs6() re-runs the exact same fold
    independently over the reconstructed per-batch h's and checks the
    result equals c.

    When `vals` is larger than seal_batch_size, it's folded hierarchically
    instead of in one Acc pass -- see ms6.py's _seal_batch docstring for the
    scheme. Must stay in lockstep with ms6.py's copy: the same seal_batch_size
    partitioning must be used on both sides for the final fold to match.
    """
    vals = list(vals)
    if len(vals) > seal_batch_size:
        vals = [
            _seal_batch(vals[start:start + seal_batch_size], chunk_size, x, d, q, mod, seal_batch_size)
            for start in range(0, len(vals), seal_batch_size)
        ]
        return _seal_batch(vals, chunk_size, x, d, q, mod, seal_batch_size)

    FLUSH = 4096
    accH = u.Acc(x, chunk_size)
    iden = u.PAD * chunk_size
    chunk_of = chunks(iden, x, chunk_size)
    for t, val in enumerate(vals):
        hm1 = chunk_of(_s(ut.hash(val, 1)))
        accH.add(hm1)
        if (t & (FLUSH - 1)) == FLUSH - 1:
            accH.flush()
    accH.flush()

    if mod is None:
        H = [[ut.cell_product(accH.cnt[i][j], q) for j in range(chunk_size)]
                     for i in range(accH.rows)]
        H = [ut.vsum_level(d, values=H1) for H1 in H]
        return ut.vsum_level(1, values=H, b=chunk_size)

    H = [[ut.cell_product_mod(accH.cnt[i][j], q, mod) for j in range(chunk_size)]
             for i in range(accH.rows)]

    H = [ut.vsum_level_mod(d, mod, values=H1) for H1 in H]
    return ut.vsum_level(1, values=H, b=chunk_size)


def _get_batch_ids(indices, batch_size=DEFAULT_BATCH_SIZE):
    """Given a list of indices, return the corresponding batch (group) id
    for each. Identical one-liner to ms6.py's copy, duplicated for the same
    zero-prover-dependency reason."""
    return [index // batch_size for index in indices]


def _vs6_batch(ps, vals, x, chunk_size, d, q, workers=DEFAULT_WORKERS, mod=DEFAULT_MOD, perm=None,
               rand_edge_size=0, h1_salt=""):
    """Single-batch reconstruction: returns the batch's own h instead of
    asserting against anything, so vs6() below can fold every batch's h
    together and do one final check against c.

    `vals` may be empty (an unclaimed batch): cnt_in_claimed is then
    all-zero at every cell, and cell_pow_product_mod of an all-zero count
    (on ps6's side) is 1 (identity) -- so M is the identity matrix here and
    ps6's oset-only row[j] (oset = every item in this batch) passes through
    unchanged, exactly matching what ms6's _ms6_batch computed for this
    batch from its own full accH/accS.

    perm must be this batch's own column permutation (ms6's perm_list[b])
    -- interlace_mod applies it to every claimed value's own chunked rows
    so M lines up column-for-column with ps6's already-permuted row[j]/
    S[j]. h1_salt must likewise be this batch's own H1 salt (ms6's
    h1_salt_list[b], see ms6.core._h1_salt) -- without it a claimed
    item's H1 is recomputed against the wrong (default, unsalted) input
    and never matches what ms6 actually committed.
    """

    # interlace's exponent must match ps6/ms6's q, so M[j] = prod over
    # claimed iset items of digit_j**q -- exactly the factor ps6 deliberately
    # left out (see ps6's _ps6_batch docstring for why).
    if vals:
        hm = [ut.domain_hash(f"{H1_TAG}:{h1_salt}:{val}".encode()) for val in vals]
        M = interlace_mod(hm, x, chunk_size, q, mod, perm=perm, rand_edge_size=rand_edge_size)
    else:
        M = [[1] * chunk_size for _ in range(x)]

    # mul_combinations_mod (combinatorial pairing, paired with ps6's
    # eval_level_mod) only leaks a handful of edge columns rather than every
    # column -- see vs6.utils6.Utils.mul_combinations_mod's docstring.
    #
    # NOTE: mul_combinations_mod's signature is (N, ps, vals, mod) -- 4
    # positional args, q already folded into `ps`/`M` upstream (ps6's own
    # exponentiation, and interlace_mod's k1=q above) rather than reapplied
    # here. The ex.map call below must ship exactly 4 argument lists to
    # match; shipping a stray 5th (e.g. a [q]*len(ps) list) raises at call
    # time only under workers>1 with more than one touched batch, which is
    # why this exact mismatch has recurred silently in this codebase before.
    if workers and workers > 1 and len(ps) > 1:
        from concurrent.futures import ProcessPoolExecutor
        with ProcessPoolExecutor(max_workers=workers) as ex:
            H = list(ex.map(ut.mul_combinations_mod,
                             [d] * len(ps), ps, M, [mod] * len(ps)))
    else:
        H = [ut.mul_combinations_mod(d, ps[i], M[i], mod) for i in range(len(ps))]

    return ut.vsum_level(1, values=H, b=chunk_size)


def vs6(c, claims, ps_list, x_list, perm_list, h1_salt_list, params, workers=DEFAULT_WORKERS, expect=None):
    """`params` is ms6()'s own returned parameter dict (see PARAM_KEYS) --
    d/q/chunk_size/batch_size/mod/seal_batch_size come from it rather than
    being passed loose, so a proof cannot be verified under different
    parameters than it was produced under.

    `expect` pins that dict against parameters agreed out of band, e.g.
    expect={"mod": MY_MOD, "d": 3}. It may name any subset of PARAM_KEYS;
    a mismatch raises ParamMismatch rather than AssertionError, so
    "verified under the wrong parameters" is distinguishable from "proof
    invalid". Structural validation of params runs either way -- see
    _validate_params. Pass it whenever the verifier has its own notion of
    the correct parameters, which is any setting where the prover is not
    also the caller.

    perm_list is ms6's own per-batch column-permutation list (its 6th
    return value) -- required so this can reconstruct M with the same
    column layout _ms6_batch/_ps6_batch used (see ms6.py's _column_perm).
    h1_salt_list is ms6's own per-batch H1/H2 salt list (its 7th return
    value, see ms6.core._h1_salt) -- required for the same reason, so a
    claimed item's H1 is recomputed against the salt it was actually
    committed under rather than the unsalted default.

    claims maps each claimed item's GLOBAL index (into the original vals
    list ms6 was given) to its claimed value, e.g. {0: vals[0], 1001:
    vals[1001]} -- same global indices as ps6's iset. A dict, rather than
    two parallel index/value collections, so the index<->value pairing
    can't silently desync.

    batch_size must match what ms6/ps6 used to slice the dataset -- it's
    public, but not derivable from anything the verifier is otherwise
    given, since hm (which would reveal per-batch item counts) is
    prover-only data.

    Every batch is reconstructed and folded here, whether or not it holds a
    claimed item (an unclaimed batch still needs its own full nonlinear
    check -- see ms6.py's ps6 docstring for why a raw, un-proven h scalar
    there would be unsound) -- the final fold across batches mirrors
    _ms6_batch's own row-combine, one level up.

    workers>1 parallelizes across touched batches when a claim spans more
    than one -- each is an independent _vs6_batch call. Each batch's own
    call then runs with workers=1 to avoid nesting process pools; row-level
    parallelism inside _vs6_batch is only used when a single batch is
    touched.
    """
    d, q, chunk_size, batch_size, mod, seal_batch_size, rand_edge_size = unpack_params(params, expect)
    assert len(ps_list) == len(x_list) == len(h1_salt_list)

    per_batch_vals = [[] for _ in ps_list]
    for g, v in claims.items():
        per_batch_vals[g // batch_size].append(v)

    h_list = ps_list.copy()
    touched = set(_get_batch_ids(list(claims), batch_size))

    if workers and workers > 1 and len(touched) > 1:
        from concurrent.futures import ProcessPoolExecutor
        with ProcessPoolExecutor(max_workers=workers) as ex:
            futures = {
                b: ex.submit(_vs6_batch, ps_list[b], per_batch_vals[b], x_list[b], chunk_size, d, q,
                             1, mod, perm_list[b], rand_edge_size, h1_salt_list[b])
                for b in touched
            }
            for b, fut in futures.items():
                h_list[b] = fut.result()
    else:
        for b in touched:
            h_list[b] = _vs6_batch(ps_list[b], per_batch_vals[b], x_list[b], chunk_size, d, q,
                               workers=workers, mod=mod, perm=perm_list[b], rand_edge_size=rand_edge_size,
                               h1_salt=h1_salt_list[b])

    h = _seal_batch(h_list, chunk_size, max(x_list), d, q, mod, seal_batch_size)
    assert h == c

    return True
