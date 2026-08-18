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


    def deep_prod(self, a, b):
        """Recursively compute elementwise (Hadamard) product of arbitrarily nested lists."""
        if isinstance(a, list) and isinstance(b, list):
            if len(a) != len(b):
                raise ValueError("Nested lists must have equal length at every level")
            return [self.deep_prod(x, y) for x, y in zip(a, b)]
        return a * b
    
    def eval_level_mod(self, N, values, mod, max_idx=None, coef=True):
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
        run-length shape) before landing in its idx bucket: coef=True (the
        default) makes the buckets this returns sum to (sum_j values[j])**N,
        not h_N(values) the way an unweighted enumeration would -- used this
        way by ms6.core._finish_ps6/ps6, paired against mul_combinations_mod
        below (which calls back into this same enumeration with coef=False,
        so the two never duplicate the combinatorial walk) -- the
        multinomial theorem's twisted-bilinear form, (sum_j x_j*y_j)**N =
        sum_C ce(C)*monomial_x(C)*monomial_y(C), makes that pairing
        reconstruct the same total either way, as long as the weight lands
        on exactly one side. See _seal_grid's own row-fold
        (pow(vsum_level(...), N, mod)) for the matching commit-time side of
        this identity.

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

        No per-query grouping parameter here (there was one, q_chunk_size,
        removed): this reconstruction is a bilinear pairing (this function's
        own X-side output against mul_combinations_mod's independent Y-side
        one), and grouping q raw values into one on either side before that
        pairing runs into the same wall regardless of the grouping method --
        combining two q>1-wide numbers and then multiplying them always
        produces cross-digit terms (grouping [X0,X1] into X0+X1*10 and
        [Y0,Y1] the same way gives (X0+X1*10)*(Y0+Y1*10), which carries an
        X0*Y1+X1*Y0 term the flat, ungrouped target never has). Real
        per-query grouping would need _seal_grid's own row identity to
        become a genuinely nested/multi-level construction, not a
        prove/verify-side-only pre-transform on top of this one."""
        L = len(values)
        if L == 1:
            if max_idx is not None and max_idx <= 0:
                return []
            return [[pow(values[0], N, mod)]]

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

        return list(r.values())
    
    
    def mul_combinations_mod(self, N, ps, values, mod):
        """`ps` (from eval_level_mod) and `vals` (from interlace_mod) are
        already mod-reduced, and every product/power here is reduced mod
        `mod` too, so nothing this function touches ever exceeds `mod`'s
        size. Same combo enumeration/order as eval_level_mod (positions
        picked via itertools.combinations_with_replacement, walked once
        per combo into (position, run-length) pairs), so its bucket order
        lines up with eval_level_mod's own.

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
        oversight."""
        r = self.eval_level_mod(N, values, mod, coef=False)

        bucket_sums = [
            sum(v % mod for v in val_list) % mod
            for val_list in self.deep_prod(r, ps)
        ]

        # vsum_level_fold_mod, see ms6.py's row-seal for the same substitution/rationale.
        return self.vsum_level_fold_mod(1, mod, bucket_sums, b=1, global_keys=True)
