"""Minimal, self-contained arithmetic toolkit for vs6/core.py (the verifier
side of ms6/ps6/vs6). A deliberately reduced subset of the prover's
ms6/utils6.py: it
contains ONLY the primitives vs6's own call graph actually touches --
hash, mul_combinations_mod and its full dependency chain
(vsum_level_fold_mod -> fold_h_vector_mod -> h_vector_mod,
convolve_h_vectors_mod), vsum_level, cell_product/
cell_product_mod, backward_chunk, and the Acc class -- duplicated here
rather than imported from ms6/utils6.py, so this module plus vs6/core.py form a
complete, independent package with zero import-time dependency on the
prover's code (ms6/core.py, ms6/utils6.py).

Deliberately EXCLUDED (prover-only, never reached from vs6's call graph):
col_digit_counts, cell_pow_product_mod, seal_row_mod, eval_level_mod, and
everything in ms6/core.py that generates or handles the secret salt
(SystemRandom, _column_perm's generation -- vs6 only ever *receives* a
perm, never derives one).

Rationale: a party deploying only the verifier (e.g. a bank checking a
sanctions-registry proof, see zk_sanctions_screening_scale_demo.py) can
install/audit just this module + vs6/core.py, without ever loading code that
could fabricate proofs or handle prover secrets -- a much smaller surface
than the full ms6/ package the prover needs. Whenever ms6/utils6.py's
verifier-relevant methods change, this file must be updated to match --
there is no automated check enforcing that; a regression test comparing
the two files' outputs bit-for-bit would be a reasonable follow-up if
this split is kept long-term.
"""
import sys
import hashlib
import math
from collections import Counter, defaultdict
from itertools import combinations_with_replacement

try:
    from gmpy2 import mpz as _mpz

    _Z = _mpz
    _HAVE_GMP = True

    def _s(v):
        return _mpz(v).digits()

    def _i(t):
        return int(_mpz(t))
except ImportError:                   # pragma: no cover
    _mpz = None
    _Z = int
    _HAVE_GMP = False
    _s = str
    _i = int

sys.set_int_max_str_digits(2000000)          # results are routinely thousands of digits

# The accumulator modulus. Every multiplication and exponentiation in
# ms6/ps6/vs6 is reduced by it, so no intermediate value grows with the
# dataset.
#
# 256-bit prime, nothing-up-my-sleeve: pi's fractional part scaled to its
# top 256 significant binary bits, then advanced to the first prime
# satisfying gcd(3, p-1) == 1. See ms6.utils6's own copy of this constant
# for the full derivation and rationale (the modulus's job here is
# fingerprinting, not hiding -- the edge-column padding is what
# closes the singleton-bucket leak at the data level, unconditionally and
# regardless of modulus; root-extraction hardness was never achievable
# via modulus choice under this construction at any size).
#
# Must stay numerically identical to ms6.utils6.DEFAULT_MOD -- see this
# file's own module docstring for why the two copies exist and how they're
# kept in lockstep. A caller free to ignore ms6()'s params dict can still
# pass any mod= explicitly; a commitment records the modulus it used, and
# ps6/vs6 read it from there rather than assuming this constant.
DEFAULT_MOD = 0x90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b31f

# The former default (2048-bit RSA Factoring Challenge composite, unknown
# order). Kept available, unchanged, for any commitment choosing to pass
# mod=LEGACY_MOD_2048 explicitly. Must stay numerically identical to
# ms6.utils6.LEGACY_MOD_2048 -- see that copy's own comment for why it is
# no longer the default.
LEGACY_MOD_2048 = 0xc7970ceedcc3b0754490201a7aa613cd73911081c790f5f1a8726f463550bb5b7ff0db8e1ea1189ec72f93d1650011bd721aeeacc2acde32a04107f0648c2813a31f5b0b7765ff8b44b4b6ffc93384b646eb09c7cf5e8592d40ea33c80039f35b4f14a04b51f7bfd781be4d1673164ba8eb991c2c4d730bbbe35f592bdef524af7e8daefd26c66fc02c479af89d64d373f442709439de66ceb955f3ea37d5159f6135809f85334b5cb1813addc80cd05609f10ac6a95ad65872c909525bdad32bc729592642920f24c61dc5b3c3b7923e56b16a4d9d373d8721f24a3fc0f1b3131f55615172866bccc30f95054c824e733a5eb6817f7bc16399d48c6361cc7e5


# Each decimal digit indexes its OWN prime, rather than being used as the
# multiplicative base directly. Using the digit itself collapses the ten
# digits onto the four primes 2,3,5,7 (4=2^2, 6=2*3, 8=2^3, 9=3^2) and
# annihilates 1 entirely, so distinct digit multisets produce identical cell
# values -- {6} == {2,3}, {4} == {2,2}, {1,1,1,6} == {2,3} -- independently
# of the modulus. That collapse is what stopped the accumulator binding the
# digit grid; no choice of modulus repairs it, because the two inputs map to
# the same group element rather than colliding by chance.
#
# With one prime per digit the exponent vector (cnt_0..cnt_9) is recoverable
# from the product over Z by unique factorisation, and finding a collision
# mod n means exhibiting prod p_i^{d_i} = 1 with some d_i != 0 -- a
# multiplicative relation among small primes modulo n, the same discrete-log-
# flavored assumption RSA-style accumulators rest on regardless of whether n
# is prime or composite.
DIGIT_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29)

# chunk_of pads short digests and narrow first chunks. Padding is
# deterministic and identical on both sides, so it should carry no
# information; it gets its own count slot (index 10) that no prime is
# assigned to, rather than reusing a real digit. ':' is chr(58), so
# ord(ch)-48 lands it in slot 10 with no change to Acc.flush.
PAD = ':'

# Must stay numerically identical to ms6.utils6's own copy -- see that
# module's domain_hash/DOMAIN_HASH_BYTES comments for the full rationale
# (SHAKE128, 128-bit collision resistance as a deliberate target, fixed-
# width zero-padded output).
DOMAIN_HASH_BYTES = 32
DOMAIN_HASH_DIGITS = len(str(256 ** DOMAIN_HASH_BYTES - 1))

_PLANES = {}
_POWSET = None


class Acc:
    """Per-cell digit counts for one grid, with C-speed batched counting.
    Used by _seal_batch (the same batch-fold logic ms6 runs, which vs6
    re-runs independently to check the final h against c)."""

    def __init__(self, rows, cols):
        self.rows, self.cols = rows, cols
        self.cnt = [[[0] * 11 for _ in range(cols)] for _ in range(rows)]
        self.buf = [[] for _ in range(rows)]

    def add(self, chunks):
        if len(chunks) < self.rows:            # map() truncates to the shorter
            self.rows = len(chunks)
            del self.cnt[self.rows:]
            del self.buf[self.rows:]
        for i in range(self.rows):
            self.buf[i].append(chunks[i])

    def flush(self):
        cols = self.cols
        for i in range(self.rows):
            if not self.buf[i]:
                continue
            big = ''.join(self.buf[i])
            self.buf[i] = []
            row = self.cnt[i]
            for j in range(cols):
                col = row[j]
                for ch, k in Counter(big[j::cols]).items():
                    col[ord(ch) - 48] += k


class Utils:
    """Verifier-safe subset of ms6.utils6.Utils -- see module docstring for
    exactly what's included/excluded and why."""

    def cell_product(self, cnt, mult):
        """prod(DIGIT_PRIMES[d]**cnt[d] for d in 0..9) ** mult.

        One distinct prime per digit; PAD (slot 10) is assigned none, so
        padding contributes nothing."""
        val = _Z(1)
        for v in range(10):
            e = cnt[v] * mult
            if e:
                val *= _Z(DIGIT_PRIMES[v]) ** e
        return val

    def cell_product_mod(self, cnt, mult, mod):
        """Modular counterpart of cell_product."""
        val = _Z(1)
        for v in range(10):
            e = cnt[v] * mult
            if e:
                val = (val * pow(_Z(DIGIT_PRIMES[v]), e, mod)) % mod
        return val

    def _prep(self, p, mod):
        P = [self._powset(mod)[v][p - 1] for v in range(10)]
        S = [str(v) for v in P]
        W = max(len(s) for s in S)
        tabs = []
        for j in range(W):                                  # plane of the 10**j digit
            tabs.append(str.maketrans({
                48 + v: (S[v][len(S[v]) - 1 - j] if j < len(S[v]) else '0')
                for v in range(10)}))
        # digits whose coefficient is 0 cannot carry the top key, so trailing runs
        # of them shift the result -- mirrors the `if v` filter in vsum_level.
        zeros = ''.join(str(v) for v in range(10) if not P[v])
        _PLANES[p] = (W, tabs, zeros)
        return _PLANES[p]


    def _powset(self, mod):
        global _POWSET
        if _POWSET is None:
            nums = list(combinations_with_replacement([1, 3, 5, 7], 2))
            _POWSET = {d: [self.vsum_level_fold_mod(i + 1, mod, nums[d]) for i in range(10)]
                    for d in range(10)}
        return _POWSET


    def hash(self, val, mod, k=10):
        if k == 0:
            return 1
        W, tabs, zeros = _PLANES.get(k) or self._prep(k, mod)
        s = _s(val)
        if zeros:
            s = s.rstrip(zeros)
            if not s:
                return 0
        tot = _Z(0)
        for j in range(W - 1, -1, -1):
            tot = tot * 10 + _Z(s.translate(tabs[j]))

        return int(tot)


    def sparse_expand(self, digest_str, target_len, mod, k=10):
        """Extend a fixed-width domain_hash digit string out to
        `target_len` decimal digits by APPENDING bespoke-hash-derived
        filler digits after it -- never transforming digest_str's own
        digits. Must stay byte-for-byte identical to ms6.utils6.Utils's
        own copy (see that module's docstring for the full rationale --
        why appending rather than transforming keeps this safe to build
        on `hash()`, which has no collision-resistance argument of its
        own) -- vs6 needs this to independently reproduce the SAME
        widened H1 rows ms6.core._vs6_batch's own interlace_mod
        reconstruction must line up against, column-for-column, for a
        claimed item.

        A no-op (returns digest_str unchanged) whenever target_len is
        already met."""
        if len(digest_str) >= target_len:
            return digest_str
        need = target_len - len(digest_str)
        filler = str(self.hash(int(digest_str), mod, k)).zfill(need)
        return digest_str + filler[-need:]


    def domain_hash(self, data):
        """SHAKE128 digest of `data` (bytes), as a fixed-width decimal digit
        string. Must stay byte-for-byte identical to ms6.utils6.Utils's own
        copy -- see that module's docstring for the full rationale; vs6
        needs this to independently recompute a claimed item's H1 (see
        vs6.core's _vs6_batch), the same way it already needed hash() to
        match ms6's copy before this change."""
        digest = hashlib.shake_128(data).digest(DOMAIN_HASH_BYTES)
        return str(int.from_bytes(digest, "big")).zfill(DOMAIN_HASH_DIGITS)

    def backward_chunk(self, ds, size):
        start = 0
        for end in range(len(ds) % size, len(ds) + 1, size):
            if start == end:
                continue

            yield ds[start:end]
            start = end

    def vsum_level(self, values, b=1):
        """Fast path: the vsum integer, without building any key-indexed table."""
        values = list(values)
        keys = list(range(len(values)))
        pairs = [(k, v) for k, v in zip(keys, values) if v]
        if not pairs:
            return 0
        M = 10 ** b
        C = max(k for k, v in pairs)             # largest key => Kmax

        bucket = [0] * (C + 1)
        for k, v in pairs:
            bucket[C - k] += v              # place value e = C - k
        if all(a < M for a in bucket):
            if b == 1:
                return int(''.join([str(a) for a in reversed(bucket)]))
            return int(''.join([str(a).zfill(b) for a in reversed(bucket)]))
        cur = [_Z(a) for a in bucket] if _HAVE_GMP else bucket
        p = _Z(M)
        while len(cur) > 1:
            nxt = [cur[i] + cur[i + 1] * p for i in range(0, len(cur) - 1, 2)]
            if len(cur) & 1:
                nxt.append(cur[-1])
            cur = nxt
            p *= p

        return _i(cur[0])


    def h_vector_mod(self, N, mod, keys=None, values=range(1, 10), b=1, C=None):
        """The modular h_N DP (same (k, key) -> weight convention as
        vsum_level, weight = M**(C-k), evaluated via pow(..., mod) instead
        of exact exponentiation), returning the whole [h_0..h_N] vector --
        needed by fold_h_vector_mod's Cauchy-product fold (see
        mul_combinations_mod's call chain)."""
        values = list(values)
        keys = list(range(len(values))) if keys is None else list(keys)
        pairs = [(k, v) for k, v in zip(keys, values) if v]
        if not pairs or N <= 0:
            return [1] + [0] * max(N, 0)
        M = 10 ** b
        C = max(k for k, v in pairs) if C is None else C

        W = [(v * pow(M, C - k, mod)) % mod for k, v in pairs]
        W.sort()
        dp = [0] * (N + 1)
        dp[0] = 1
        for w in W:
            for c in range(1, N + 1):          # ascending, same as vsum_level -- repeats allowed (h_N, not e_N)
                dp[c] = (dp[c] + dp[c - 1] * w) % mod
        return dp

    def convolve_h_vectors_mod(self, A, B, N, mod):
        """Cauchy product of two h-vectors (each [h_0..h_N] for its own
        group), truncated to degree N."""
        C = [0] * (N + 1)
        for k in range(N + 1):
            C[k] = sum(A[i] * B[k - i] for i in range(k + 1)) % mod
        return C

    def fold_h_vector_mod(self, N, mod, group_values, b=1, global_keys=False):
        """See ms6.utils6.Utils.fold_h_vector_mod for the full identity and
        rationale, including the global_keys=True requirement for this to
        match a single unsplit h_N call over the same values -- vs6 reaches
        this via vsum_level_fold_mod (below), from both mul_combinations_mod
        and vs6.core._seal_batch's row-seal fold, and both call sites must
        pass global_keys=True for the same reason."""
        groups = [list(g) for g in group_values if list(g)]
        acc = None

        if global_keys:
            total_len = sum(len(g) for g in groups)
            C = total_len - 1
            offset = 0
            for group in groups:
                gkeys = list(range(offset, offset + len(group)))
                gvec = self.h_vector_mod(N, mod, keys=gkeys, values=group, b=b, C=C)
                acc = gvec if acc is None else self.convolve_h_vectors_mod(acc, gvec, N, mod)
                offset += len(group)
        else:
            for group in groups:
                gvec = self.h_vector_mod(N, mod, values=group, b=b)
                acc = gvec if acc is None else self.convolve_h_vectors_mod(acc, gvec, N, mod)

        if acc is None:
            return [1] + [0] * N
        return acc


    def vsum_level_fold_mod(self, k, mod, values, chunk_size=20, b=1, global_keys=False):
        """Thin wrapper around fold_h_vector_mod -- see ms6/utils6.py's copy for
        the full rationale. Reached only via mul_combinations_mod
        (global_keys=True), to seal its bucket_sums into a single scalar."""
        groups = self.backward_chunk(list(values), chunk_size)
        return self.fold_h_vector_mod(k, mod, groups, b=b, global_keys=global_keys)[k]


    def multinomial(self, P, deg):
            """deg! / prod(p! for p in P) -- gen.py's fast_coeff, without the cache."""
            return math.prod(range(P[0] + 1, deg + 1)) // math.prod(
                math.factorial(p) for p in P[1:])

    
    def deep_prod(self, a, b):
        """Recursively compute elementwise (Hadamard) product of arbitrarily nested lists."""
        if isinstance(a, list) and isinstance(b, list):
            if len(a) != len(b):
                raise ValueError("Nested lists must have equal length at every level")
            return [self.deep_prod(x, y) for x, y in zip(a, b)]
        return a * b
    
    def eval_level_mod(self, N, values, mod, max_idx=None, coef=False, keyed=False):
        """Groups per-position multiset products into per-idx buckets,
        every power and every combo product reduced mod `mod` so the
        accumulated products never grow past `mod`'s size no matter how
        large N or len(values) get. Driven through
        itertools.combinations_with_replacement (C speed) plus one
        run-length pass per combo -- e.g. for L=40, N=3 that's exactly
        11480 Python-level iterations (one per combo), versus an
        unmemoized recursive enumeration revisiting O(L) partial-state
        frames per leaf (~123k calls for the same case).

        `coef` controls whether each combo's product is scaled by its own
        public multinomial coefficient (self.multinomial, from the combo's
        run-length shape) before landing in its idx bucket: coef=True makes
        the buckets this returns sum to (sum_j values[j])**N, not h_N(values)
        the way the default (coef=False) unweighted enumeration does -- the
        multinomial theorem's twisted-bilinear form, (sum_j x_j*y_j)**N =
        sum_C ce(C)*monomial_x(C)*monomial_y(C), is exactly what a coef=True/
        coef=False pairing reconstructs (see mul_combinations_mod's own
        coef= paragraph, and mul_combinations_bucket_vec below, which keep
        that pairing's result as a vector instead of collapsing it) --
        ms6.core._seal_grid's own two-stage row-seal is coef=True's real,
        live use: H'=H*S^d gets bucket-summed via eval_level_mod(d, H1,
        mod, coef=True) before the outer degree-d fold. coef=False (the
        default) is what ps6/vs6's Y-side disclosure (ms6.utils6.Utils.
        eval_row_grouped) always used and still does -- see the next
        paragraph.

        The multinomial weight is 1 at idx=0 and idx=N*(L-1) (each realized
        by exactly one combo, all N copies at one position) -- so it does
        not change mul_combinations_mod's own KNOWN LEAK discussion (below,
        in this file), only the buckets in between.

        `max_idx`, when given, skips the (often large) value multiplication
        for any combo whose idx would land at or beyond it -- safe whenever
        the caller only ever consumes buckets 0..max_idx-1 of the result.
        idx itself is cheap (small-int arithmetic only) so it's still
        derived for every combo; only the conditionally-large product is
        skipped.

        ms6.core._finish_ps6/ps6 call this (coef=False, the default) via
        ms6.utils6.Utils.eval_row_grouped, per group and per degree 1..d
        (or once, at degree d only, when the chosen partition is a single
        group -- see eval_row_grouped's own docstring) -- the SAME
        disclosure serves two different verifier-side reconstructions,
        chosen independently of anything this function or eval_row_grouped
        does: mul_row_grouped (paired against mul_combinations_mod/
        mul_group_hvec) reconstructs the plain h_d(H1) target;
        mul_row_grouped_two_stage (paired against
        mul_combinations_bucket_vec/mul_group_bucket_vec, coef=True on the
        verifier's own X-side) reconstructs ms6.core._seal_grid's actual,
        currently shipped row-seal target instead -- the two-stage fold
        (bucket-sum via eval_level_mod(d,H1,mod,coef=True), then a second
        degree-d vsum_level_fold_mod, NOT (sum)**N/pow(vsum_level(...), N,
        mod) -- see ms6_vibe.md for why that construction was replaced).
        Both reconstructions are exact regardless of grouping (see
        h_vector_mod/fold_h_vector_mod's own docstrings for the identity
        that makes that grouping-invariance exact, not approximate).

        A per-query GROUPING parameter now exists at the row level (see
        partition_menu/build_partition/mul_group_hvec below) -- but it
        lives one level up from this function's own Y-side input, not as
        a parameter here: the earlier, removed q_chunk_size design tried
        to group q raw VALUES together before this bilinear pairing ran at
        all, which produces unavoidable cross-digit terms regardless of
        grouping method (combining two q>1-wide numbers before multiplying
        them always does -- grouping [X0,X1] into X0+X1*10 and [Y0,Y1] the
        same way gives (X0+X1*10)*(Y0+Y1*10), which carries an X0*Y1+X1*Y0
        term the flat, ungrouped target never has). The swappable fold
        instead groups whole COLUMNS of a row into g-wide blocks, each
        block getting its OWN full eval_level_mod/mul_combinations_mod
        pairing at every degree up to d, then Cauchy-products the blocks'
        own h-vectors together -- an exact identity, not a pre-transform on
        top of this function's own per-value arithmetic.

        `keyed`, when True, returns {idx: [bucket values]} instead of the
        default list(r.values()) -- the same buckets, in the same content,
        just with their idx label attached instead of discarded. Every
        EXISTING caller relies only on list(r.values())'s own insertion
        order lining up combo-for-combo between an X-side and a Y-side
        generated the same way (deep_prod's pairing needs no explicit idx
        at all for that). keyed=True exists for mul_combinations_bucket_vec
        (below), which DOES need the idx labels -- reconstructing a GROUP's
        own two-stage bucket vector (see mul_group_bucket_vec's own
        docstring) requires remapping each bucket's idx from the group's
        local position numbering into the row's shared, true-column one
        before combining it with sibling groups', which is only possible
        if the idx survives past this function's own return."""
        L = len(values)
        if L == 1:
            if max_idx is not None and max_idx <= 0:
                return {} if keyed else []
            val = pow(values[0], N, mod)
            return {0: [val]} if keyed else [[val]]

        powers = [[1] * (N + 1) for _ in range(L)]
        for pos, v in enumerate(values):
            row = powers[pos]
            acc = 1
            for c in range(1, N + 1):
                acc = (acc * v) % mod
                row[c] = acc

        r = defaultdict(list)
        for combo in combinations_with_replacement(range(L), N):
            runs = []
            prev = combo[0]
            cnt = 1
            for pos in combo[1:]:
                if pos == prev:
                    cnt += 1
                else:
                    runs.append((prev, cnt))
                    prev = pos
                    cnt = 1
            runs.append((prev, cnt))

            idx = sum(p * c for p, c in runs)
            if max_idx is not None and idx >= max_idx:
                continue
            val = 1
            for p, c in runs:
                val = (val * powers[p][c]) % mod

            if coef:
                ce = self.multinomial([c for p, c in runs], N) % mod
                r[idx].append((val * ce) % mod)
            else:
                r[idx].append(val)

        return dict(r) if keyed else list(r.values())


    def mul_combinations_mod(self, N, ps, values, mod, b=1, coef=False):
        """`ps` (from eval_level_mod) and `vals` (from interlace_mod) are
        already mod-reduced, and every product/power here is reduced mod
        `mod` too, so nothing this function touches ever exceeds `mod`'s
        size. Same combo enumeration/order as eval_level_mod (positions
        picked via itertools.combinations_with_replacement, walked once
        per combo into (position, run-length) pairs), so its bucket order
        lines up with eval_level_mod's own.

        `b` sets the tail vsum_level_fold_mod's own base (10**b) for the
        positional weighting across `values`' own positions -- default 1
        matches every pre-existing call site (a row folded at its true,
        global column stride). The swappable multi-level fold (see
        partition_menu/build_partition/mul_group_hvec below) is the one
        caller that passes b != 1: reconstructing a single GROUP's own
        local h_i needs the group's own column stride (B from
        build_partition) here, not the row's global stride 1, so a later
        constant correction factor (mul_group_hvec) can convert the
        group-local result into the row-global one it needs to Cauchy-
        product against every other group's.

        KNOWN LEAK -- STRUCTURAL, and not something a modulus choice fixes:
        idx=0 and idx=N*(L-1) (choosing one column with full multiplicity
        N -- the two combinatorial extremes) are each realized by exactly
        one combo, so their `ps` buckets hold a single raw
        pow(combined[0], N, mod) / pow(combined[L-1], N, mod) term, and
        anyone who can take an N-th root mod `mod` reads it straight out --
        trivially if `mod` is prime (the group order p-1 is public), harder
        but not impossible if `mod` is a composite of unknown order.

        idx=1 and idx=N*(L-1)-1 are *also* singleton buckets (combo
        (0,...,0,1) and its mirror), leaking combined[0]**(N-1)*combined[1]
        and combined[L-2]*combined[L-1]**(N-1) -- products, not raw single-
        column values, but dividing out the already-recovered combined[0]/
        combined[L-1] cascades to combined[1] and combined[L-2] as well.
        Verified empirically (tests/test_leak.py): at chunk_size=40, d=3
        (118 buckets), this is 4 singleton buckets -> 4 real columns
        recovered per row (0, 1, 38, 39), not 2. The cascade is 2 columns
        deep at d=3 because idx=1's combo only ever touches 2 distinct
        columns (multiplicity N-1 and 1); larger d admits deeper cascades
        from each end (idx=2 touches up to 3 distinct columns, etc.), so
        the leaked-column count grows with d, not just chunk_size.

        What actually closes this leak lives one layer up, in ms6.core:
        the columns this cascade can ever reach (the outer rand_edge_size
        of them, from each edge) never carry real per-item digest data to
        begin with -- see ms6.core's EDGE-COLUMN PADDING comment and
        _attach_edges_pad/_attach_edges_s. A successful extraction here,
        against any modulus, hands back a single fixed public constant,
        not a rate-limited path to real data. DEFAULT_MOD's
        unknown group order (see its own comment in this file) is kept
        anyway as a second, independent layer against any column this
        leak reaches that the edge padding did not already neutralize.

        A recursive, non-combinatorial enumeration could reach larger d
        without the combinatorial blow-up this version pays for -- at the
        cost of a materially larger leak (every column invertible, not
        just a handful from each edge), since it would no longer collapse
        most of the L^N combinations into shared, multi-term buckets the
        way combinations_with_replacement does here. Not pursued: this
        codebase only targets the small-d regime where the combinatorial
        blow-up stays tractable. Neither hashing nor multiplicatively
        blinding the per-column values closes this leak without breaking
        correctness or being just as invertible itself -- doing so for
        real needs exponent-based (discrete-log) hiding, not this
        codebase's "value as the base of a public power mod a prime"
        construction. This smaller-leak combinatorial version is the
        default in ps6/vs6; d=27 is unsupported by that tradeoff, not by
        oversight.

        `coef`, when True, folds this function's own X-side (`values`)
        with the same multinomial-coefficient weighting eval_level_mod's
        own coef=True branch applies, and collapses the paired result via
        a full degree-N fold (vsum_level_fold_mod(N, ...)) instead of the
        default degree-1 weighted sum. This is the verifier-side
        counterpart to a two-stage row-seal (fold H' once with coef=True,
        then fold THAT result again, degree N both times -- see
        ms6.core._seal_grid): pairing a coef=True X-side against ps's own
        coef=False Y-side (both raw, unsummed, matched combo-for-combo by
        deep_prod, same as always) fully recovers the SAME inner
        bucket-summed vector the coef=True commit-side fold produces --
        ce(C) lands on the pairing exactly once per combo either way, see
        eval_level_mod's own "twisted-bilinear form" paragraph. Once that
        inner vector is reconstructed it is fully public (built from
        `values`, known to the verifier, and ps, already disclosed), so
        the outer fold needs no further secret-splitting -- an ordinary
        vsum_level_fold_mod(N, ...) call on it, not another bilinear
        pairing. coef=False (the default) preserves every existing call
        site's own behaviour exactly, including the degree-1 outer
        collapse. Verified: 20/20 randomized (L, N) trials matching
        _seal_grid's own two-stage construction exactly (ms6_vibe.md).

        A wrong `N` (the caller passing the wrong degree, e.g. vs6() given
        a wrong `d`) reshapes `r`'s own bucket structure relative to `ps`
        (`ps` was sized by the PROVER's true degree at disclosure time) --
        deep_prod's own equal-length check catches that as a ValueError,
        re-raised here as IndexError so it lands in the same "reconstruction
        itself breaks, never a silent True" bucket vs6()'s own docstring
        already documents for a wrong d (AssertionError low / IndexError
        high) -- this is that same contract's low-level enforcement point,
        not a new failure mode."""
        r = self.eval_level_mod(N, values, mod, coef=coef)

        try:
            paired = self.deep_prod(r, ps)
        except ValueError as e:
            raise IndexError(
                f"mul_combinations_mod: reconstructed sweep shape does not "
                f"match disclosed ps (wrong degree/params?) -- {e}") from e

        bucket_sums = [
            sum(v % mod for v in val_list) % mod
            for val_list in paired
        ]

        # vsum_level_fold_mod, see ms6.py's row-seal for the same substitution/rationale.
        outer_N = N if coef else 1
        return self.vsum_level_fold_mod(outer_N, mod, bucket_sums, b=b, global_keys=True)


    def mul_combinations_bucket_vec(self, N, ps, values, mod, coef=True):
        """Same bilinear reconstruction as mul_combinations_mod's own
        coef=True path (X-side eval_level_mod(coef=True) paired against
        ps's own coef=False Y-side, combo-for-combo via deep_prod), but
        returns the reconstructed {idx: bucket_sum} dict itself instead of
        collapsing it through the outer vsum_level_fold_mod(N, ...) fold --
        this is STAGE 1 alone, kept as a vector rather than folded to a
        scalar, because mul_group_bucket_vec/convolve_bucket_vecs_mod
        (below) need to combine one GROUP's own stage-1 vector with
        sibling groups' before any outer fold runs (see
        mul_row_grouped_two_stage's own docstring for why the outer fold
        can only happen once, on the fully-assembled row).

        idx here is still in the CALLER's own local position numbering
        (0..len(values)-1) -- mul_group_bucket_vec is what remaps it into
        the row's shared, true-column numbering; this function stays
        agnostic to where its `values`/`ps` came from, same as
        mul_combinations_mod itself."""
        r_keyed = self.eval_level_mod(N, values, mod, coef=coef, keyed=True)
        idx_list = list(r_keyed.keys())
        r = list(r_keyed.values())

        try:
            paired = self.deep_prod(r, ps)
        except ValueError as e:
            raise IndexError(
                f"mul_combinations_bucket_vec: reconstructed sweep shape "
                f"does not match disclosed ps (wrong degree/params?) -- "
                f"{e}") from e

        return {
            idx: sum(v % mod for v in val_list) % mod
            for idx, val_list in zip(idx_list, paired)
        }


    def partition_menu(self, chunk_size):
        """Public per-row partition menu for the swappable MULTI-level fold
        (see ms6.utils6.Utils.eval_row_grouped and mul_row_grouped below)
        -- every RECIPE (a list of (orientation, q) steps, applied in
        order by build_partition) that recursively splits a chunk_size-
        wide row down to a set of equal-width leaf groups h_vector_mod's
        exact Cauchy-product identity can reconstruct (see h_vector_mod/
        fold_h_vector_mod's own docstrings). Each entry is a full recipe,
        not a single step: [] (the empty recipe) is 'flat' -- one leaf,
        the whole row, entry 0 -- and every other entry recursively
        refines it: at each step, EVERY leaf produced so far is
        independently split q-ways, 'row-major' (locally contiguous,
        local stride 1 within that leaf) or 'transposed' (locally
        strided, local stride = that leaf's own current width // q) --
        see build_partition for exactly how a step's LOCAL split composes
        into each leaf's TRUE row-column (A, B). This is genuinely deeper
        than a single split: composing row-major/transposed steps across
        levels realizes leaf strides no single-level (orientation, q)
        pair can (e.g. offset+stride-5 leaves of width 2 from a row-
        major(10)-then-transposed(5) recipe, on a chunk_size=100 row --
        neither plain 'row-major' nor 'transposed' at ANY single q
        produces that shape) -- a materially richer set of distinct
        disclosure patterns for the SAME prover to draw from at query
        time, not just a re-expression of the one-level menu at smaller q.

        Recursion at each leaf stops once its own width has no divisor q
        with 1 < q < width -- the same q=1/q=width exclusions the one-
        level menu always applied, just re-applied at every level instead
        of only the top one: a step that would leave a width-1 leaf
        discloses one column's raw value outright (q=width), and q=1 is a
        no-op split, so neither is ever offered. This makes recursion
        depth a function of chunk_size's own factorization -- 111 total
        recipes (max depth 3) at chunk_size=100, cheap to generate once
        per proof; no explicit depth cap is needed since the
        factorization itself bounds it.

        Pure function of the public chunk_size only -- never derived from
        iset or any other claim-dependent input, for the same reason the
        since-removed q_chunk_size = len(touched)//3 design was gameable
        (see ms6_vibe.md). Kept identical to ms6.utils6.Utils's own copy
        (parity-checked, tests/test_parity.py) so both sides agree on
        every row's menu from chunk_size alone -- the prover's disclosed
        per-row choice is just an index into this list."""
        menu = [[]]

        def _extend(width, recipe):
            for q in range(2, width):
                if width % q != 0:
                    continue
                for orientation in ('row-major', 'transposed'):
                    next_recipe = recipe + [(orientation, q)]
                    menu.append(next_recipe)
                    _extend(width // q, next_recipe)

        _extend(chunk_size, [])
        return menu


    def build_partition(self, recipe, chunk_size):
        """Realizes one partition_menu entry -- a RECIPE, a list of
        (orientation, q) steps -- as a list of (positions, A, B) leaf
        triples, applying each step to every leaf produced by the steps
        before it (starting from one leaf: the whole row).

        positions -- a leaf's column indices into the chunk_size-wide row,
        in the order its own local h-vector treats as local positions
        0..len(positions)-1.

        A -- the leaf's own lowest-local-position true column; B -- the
        column-index stride between the leaf's consecutive local
        positions. A column at leaf-local position p therefore sits at
        true row column A + B*p -- same meaning as a single-level
        partition's own (A, B), because composing affine maps stays
        affine at any depth: splitting a CURRENT leaf (itself A_old +
        B_old*(local index)) row-major-wise into q pieces of width
        w=len(leaf)//q gives piece i the local sub-range [i*w, (i+1)*w),
        i.e. true columns A_old + B_old*(i*w) .. stride B_old -- so the
        piece's own (A, B) is (A_old + B_old*i*w, B_old), UNCHANGED
        stride, just a shifted offset. Splitting transposed-wise instead
        picks local sub-positions i, i+q, i+2q, ... within the leaf, i.e.
        true columns A_old + B_old*i, stride B_old*q -- so the piece's
        own (A, B) is (A_old + B_old*i, B_old*q). Either way the result is
        again a simple (positions, A, B) triple, so a second (or third,
        ...) step composes onto it exactly the same way -- this is what
        lets a recipe be applied as a plain left-to-right loop instead of
        needing explicit tree recursion. Both A and B feed the constant
        per-leaf correction factor mul_group_hvec applies to convert a
        leaf's own locally-weighted h-vector into the row's globally-
        weighted one, before every leaf's h-vector is Cauchy-product-
        folded together (convolve_h_vectors_mod) into the row's final h_d
        -- see mul_group_hvec's own docstring for the derivation; that
        derivation only ever depends on a leaf's final (A, B, width),
        never on how many steps produced it.

        recipe=[] (the empty recipe, 'flat''s own realization) returns the
        single whole-row leaf, A=0, B=1 -- same as before.

        Every q in `recipe` must evenly divide the width of whatever leaf
        it's applied to at that point -- partition_menu only ever offers
        such recipes (see its own docstring for why an uneven division
        isn't supported, the same reasoning as the original single-level
        menu, just checked at every level here instead of only the top
        one)."""
        leaves = [(list(range(chunk_size)), 0, 1)]
        for orientation, q in recipe:
            next_leaves = []
            for leaf in leaves:
                next_leaves.extend(self._split_leaf(leaf, orientation, q))
            leaves = next_leaves
        return leaves


    def _split_leaf(self, leaf, orientation, q):
        """One (orientation, q) split applied to a single (positions, A, B)
        leaf -- the same affine composition build_partition's own loop uses,
        factored out so build_targeted_partition can apply it to ONE leaf
        without re-deriving the row-major/transposed math. See
        build_partition's own docstring for the derivation of why this
        composition stays affine at any depth. Bit-identical to
        ms6.utils6.Utils._split_leaf -- parity-checked, tests/test_parity.py."""
        positions, A, B = leaf
        w = len(positions)
        if w % q != 0:
            raise ValueError(
                f"split step q={q} does not evenly divide leaf width {w}")
        g = w // q
        if orientation == 'row-major':
            return [(positions[i * g:(i + 1) * g], A + B * (i * g), B) for i in range(q)]
        elif orientation == 'transposed':
            return [(positions[i::q], A + B * i, B * q) for i in range(q)]
        else:
            raise ValueError(f"unknown partition orientation: {orientation!r}")


    def build_targeted_partition(self, base_partition, targets):
        """Split a FEW leaves of an already-built partition one level
        deeper, leaving every other leaf untouched -- a cheap, TARGETED
        counterpart to partition_menu/build_partition's own uniform (every
        leaf split the same way, every level) recipes. See
        ms6.utils6.Utils.build_targeted_partition's own docstring for the
        full derivation (mathematically this needs nothing new: the
        group-folding theorem already holds for groups of any offset,
        stride, and size); this is the verifier's bit-identical copy,
        needed here because the verifier rebuilds the same partition from
        the prover's disclosed (base recipe, targets) rather than
        receiving the leaf list directly -- parity-checked,
        tests/test_parity.py.

        base_partition -- a build_partition(recipe, chunk_size) result.
        targets -- a list of (leaf_idx, orientation, q); leaves not named
        are returned unchanged, in the same order, each targeted leaf
        replaced by its own q-way split in place."""
        seen = set()
        result = []
        by_idx = {}
        for leaf_idx, orientation, q in targets:
            if leaf_idx in seen:
                raise ValueError(f"leaf_idx {leaf_idx} targeted more than once")
            seen.add(leaf_idx)
            by_idx[leaf_idx] = (orientation, q)
        for i, leaf in enumerate(base_partition):
            if i in by_idx:
                orientation, q = by_idx[i]
                result.extend(self._split_leaf(leaf, orientation, q))
            else:
                result.append(leaf)
        return result


    def mul_group_hvec(self, sweep, Y_group, A, B, q_local, C_global, d, mod):
        """Verifier-side reconstruction of one group's own h-vector
        [1, h_1, ..., h_d] from the prover's disclosed per-degree sweep
        (ms6.utils6.Utils.eval_row_grouped, one group's worth) plus this
        group's own Y-side values -- mul_combinations_mod, called once per
        degree 1..d (not a single top-degree call, for the same reason
        eval_row_grouped discloses every degree).

        mul_combinations_mod(i, sweep[i-1], Y_group, mod, b=B) reconstructs
        h_i of the group's own elementwise product, positionally weighted
        as if the group's own local index 0..q_local-1 (stride B apart)
        were the WHOLE dataset -- i.e. the group's own *local* h_i, using
        its own top local position q_local-1 as the reference point, not
        the row's shared reference point C_global = chunk_size - 1 a
        single unsplit h_vector_mod call over the whole row would use.

        The two differ by one constant factor per column: a column at
        group-local position p sits at true row column A + B*p, so its
        true (row-global) weight is 10**(B*(C_global - A - B*p)), while
        the call above assigned it the LOCAL weight 10**(B*(q_local-1-p))
        (reference point = the group's own top local position). Dividing
        true by local cancels every p-dependent term (both are B*p
        offsets from their own reference point), leaving one FIXED
        per-group ratio -- 10**(B*(C_global - A - B*(q_local-1))) --
        common to every column in the group. Since h_i is a degree-i
        homogeneous sum of i-fold column products, raising that fixed
        ratio to the i-th power converts the local h_i into the true,
        row-globally-weighted one -- with no per-column work, one pow()
        per degree.

        This is the exact derivation validated against real ps6/vs6-shaped
        data this session (both row-major, B=1, and transposed, B=q,
        partitions reconstruct bit-identically to the unsplit h_d(row)
        this way) -- see ms6_vibe.md. It's what makes the partition
        swappable at query time without _seal_grid itself ever changing:
        _seal_grid's own row fold (vsum_level_fold_mod's h_d) is exactly
        what mul_row_grouped below reconstructs, for ANY partition on the
        menu."""
        exp = (C_global - A - B * (q_local - 1)) % (mod - 1)
        correction = pow(10, exp, mod)
        hvec = [1]
        for i in range(1, d + 1):
            h_local = self.mul_combinations_mod(i, sweep[i - 1], Y_group, mod, b=B)
            hvec.append((h_local * pow(correction, i, mod)) % mod)
        return hvec


    def mul_row_grouped(self, sweeps, Y_row, partition, d, mod):
        """Verifier-side row-level reconstruction: combine every group's
        own h-vector (mul_group_hvec) via convolve_h_vectors_mod's Cauchy
        product -- the disjoint-union identity h_vector_mod's docstring
        proves -- into the row's final h_d. Matches ms6.core._seal_grid's
        own row fold (vsum_level_fold_mod(d, mod, values=H1,
        global_keys=True)) bit-for-bit, REGARDLESS of which partition
        (partition_menu) the prover chose for this row: swapping
        row-major for transposed grouping, or any other menu entry, never
        changes this result -- that grouping-invariance (built on
        h_vector_mod's exact Cauchy-product identity, not the (sum)**N
        construction _seal_grid used before this session's revert -- see
        ms6_vibe.md) is what makes the fold swappable at query time. This
        is the one function _vs6_batch actually calls to replace its old
        flat `mul_combinations_mod(d, ps[i], M[i], mod)` per-row call.

        C_global (the shared reference point every group's correction
        factor in mul_group_hvec is computed against) is chunk_size - 1,
        i.e. len(Y_row) - 1 -- the same derivation fold_h_vector_mod's own
        global_keys=True path uses, from the row's total width.

        SINGLE-GROUP SPECIAL CASE: with only one group there's nothing to
        Cauchy-product against, so this skips building the full [1..d]
        h-vector entirely and reconstructs h_d directly from ms6.utils6.
        Utils.eval_row_grouped's own single-degree disclosure (see its
        docstring's matching special case) -- mul_combinations_mod(d,
        sweeps[0][0], Yg, mod, b=B) once, corrected by pow(correction, d,
        mod) once, exactly mirroring the pre-swappable-fold flat path's
        cost (one degree-d combinatorial pairing, not d of them)."""
        C_global = len(Y_row) - 1
        if len(partition) == 1:
            positions, A, B = partition[0]
            Yg = [Y_row[j] for j in positions]
            h_local = self.mul_combinations_mod(d, sweeps[0][0], Yg, mod, b=B)
            exp = (C_global - A - B * (len(positions) - 1)) % (mod - 1)
            correction = pow(10, exp, mod)
            return (h_local * pow(correction, d, mod)) % mod
        acc = None
        for sweep, (positions, A, B) in zip(sweeps, partition):
            Yg = [Y_row[j] for j in positions]
            hv = self.mul_group_hvec(sweep, Yg, A, B, len(positions), C_global, d, mod)
            acc = hv if acc is None else self.convolve_h_vectors_mod(acc, hv, d, mod)
        return acc[d]


    def mul_group_bucket_vec(self, sweep, Y_group, A, B, d, mod):
        """Verifier-side reconstruction of one group's own TWO-STAGE bucket
        vector at every degree 0..d -- the coef=True counterpart of
        mul_group_hvec (which reconstructs the group's plain h-vector for
        the original, non-two-stage h_d target). Returns {0: {0: 1}, 1:
        {idx: val, ...}, ..., d: {...}}.

        `sweep` is ms6.utils6.Utils.eval_row_grouped's own per-group
        disclosure (unchanged by any of this -- see
        mul_row_grouped_two_stage's own docstring for why the SAME
        disclosure serves both targets): sweep[i-1] = eval_level_mod(i,
        oset_group, mod), coef=False, for i=1..d.

        For each degree i, mul_combinations_bucket_vec(i, sweep[i-1],
        Y_group, mod, coef=True) reconstructs bucket_vec(M_group *
        result_group, i) -- see that function's own docstring -- but keyed
        by the group's own LOCAL position numbering (0..q_local-1), since
        that's what both eval_level_mod calls that produced it used.

        A column at group-local position p sits at true row column A+B*p,
        so a degree-i combo's true idx is i*A + B*local_idx (each of the i
        picks contributes one +A offset and B*(its own local position); the
        A term is picked up i times, once per pick, and the B*local_idx sum
        across picks is exactly local_idx by eval_level_mod's own idx
        definition) -- remapping every bucket's key this way is enough to
        make this group's own bucket vector directly combinable (via
        convolve_bucket_vecs_mod) with any other group's, in the row's one
        shared idx space -- no separate multiplicative correction factor
        like mul_group_hvec's own `correction` is needed here, because
        STAGE1's bucket vector already carries positional information
        explicitly in its idx keys (unlike a group's plain h_i scalar,
        which carries none, hence mul_group_hvec's own fixup). Verified
        against real partition_menu leaves, both row-major and transposed,
        single- and multi-level recipes, and the full bilinear (claimed/
        oset) split (ms6_vibe.md)."""
        out = {0: {0: 1}}
        for i in range(1, d + 1):
            local_bv = self.mul_combinations_bucket_vec(i, sweep[i - 1], Y_group, mod, coef=True)
            out[i] = {i * A + B * local_idx: v for local_idx, v in local_bv.items()}
        return out


    def convolve_bucket_vecs_mod(self, acc, gvec, d, mod):
        """Binomial-weighted Cauchy product of two groups' own bucket-vec
        dicts (each {degree: {idx: val}} for degree 0..d) -- the STAGE1
        counterpart of convolve_h_vectors_mod, which combines plain h-
        vectors with NO binomial weight (h_k(A u B) = sum_i h_i(A)h_{k-i}(B)
        has none). This one needs C(k,i): bucket_vec(A u B, k) sums the
        coefficients of g_{A u B}(x)^k = (g_A(x)+g_B(x))^k, whose binomial
        expansion is sum_i C(k,i) g_A(x)^i g_B(x)^{k-i} -- each term a
        POLYNOMIAL PRODUCT (coefficients convolve, i.e. idx keys ADD) of
        that degree's own bucket vectors, weighted by C(k,i). Verified
        exactly against a flat (non-grouped) eval_level_mod(k,...,coef=True)
        call across 2-way and 4-way group splits, several group sizes and
        degrees (ms6_vibe.md)."""
        out = {0: {0: 1}}
        for k in range(1, d + 1):
            combined = {}
            for i in range(k + 1):
                j = k - i
                c = math.comb(k, i)
                for ia, va in acc.get(i, {}).items():
                    for ib, vb in gvec.get(j, {}).items():
                        key = ia + ib
                        combined[key] = (combined.get(key, 0) + c * va * vb) % mod
            out[k] = combined
        return out


    def mul_row_grouped_two_stage(self, sweeps, Y_row, partition, d, mod):
        """Verifier-side row-level reconstruction for the TWO-STAGE fold
        (ms6.core._seal_grid's H'=H*S^d -> eval_level_mod(d,...,coef=True)
        bucket-sum -> vsum_level_fold_mod(d,...) construction -- see
        ms6_vibe.md), the coef=True/group-composed counterpart of
        mul_row_grouped (which reconstructs the original, non-two-stage
        h_d(row) target).

        Takes the exact same disclosure ms6.utils6.Utils.eval_row_grouped
        already produces for the non-two-stage target -- STAGE1's Y-side
        requirement (coef=False, raw, per group per degree 1..d) doesn't
        change with what the X-side does with it (see
        mul_combinations_bucket_vec's own docstring) -- so no prover-side
        change was needed to support this; only this reconstruction path
        is new.

        Combines every group's own bucket vector (mul_group_bucket_vec) via
        convolve_bucket_vecs_mod's binomial-weighted Cauchy product into the
        FULL ROW's own bucket vector at degree d, then applies the same
        outer STAGE2 fold (vsum_level_fold_mod(d, mod, ..., global_keys=
        True)) _seal_grid's own flat construction uses -- STAGE2 is an
        ordinary (non-bilinear) DP pass, always cheap regardless of
        grouping, so there is nothing left to decompose once the row's
        bucket vector is fully assembled; only STAGE1 (the combinatorial
        blow-up) benefits from grouping.

        The assembled bucket vector's values MUST be sorted by ascending
        idx before the outer fold: vsum_level_fold_mod(global_keys=True)
        weights entries by their LIST POSITION, not by their idx label, and
        a flat eval_level_mod(d,...,coef=True) call happens to already
        yield its buckets in ascending-idx order (a side effect of how
        combinations_with_replacement visits combos, not a documented
        contract) -- the group-assembled dict has no reason to come out in
        that order on its own, so this sorts explicitly rather than relying
        on incidental dict-insertion order.

        SINGLE-GROUP SPECIAL CASE: mirrors mul_row_grouped's own -- with
        only one group (e.g. the 'flat' recipe) there is nothing to
        convolve against, so this reconstructs bucket_vec(row, d) directly
        via one mul_combinations_bucket_vec call, remapped by the group's
        own (A, B) (A=0, B=1 for 'flat' -- a no-op remap), then folds.
        Costs exactly what the pre-grouped flat two-stage bypass always
        did.

        Verified bit-identical to a flat (non-grouped) two-stage
        computation over the same row, across row-major, transposed, and
        nested recipes, and the full bilinear claimed/oset split
        (ms6_vibe.md)."""
        if len(partition) == 1:
            positions, A, B = partition[0]
            Yg = [Y_row[j] for j in positions]
            bv = self.mul_combinations_bucket_vec(d, sweeps[0][0], Yg, mod, coef=True)
            bv = {d * A + B * local_idx: v for local_idx, v in bv.items()}
        else:
            acc = {0: {0: 1}}
            for sweep, (positions, A, B) in zip(sweeps, partition):
                Yg = [Y_row[j] for j in positions]
                gvec = self.mul_group_bucket_vec(sweep, Yg, A, B, d, mod)
                acc = self.convolve_bucket_vecs_mod(acc, gvec, d, mod)
            bv = acc[d]
        vals = [bv[k] for k in sorted(bv)]
        return self.vsum_level_fold_mod(d, mod, vals, global_keys=True)
