"""Minimal, self-contained arithmetic toolkit for vs6/core.py (the verifier
side of ms6/ps6/vs6). A deliberately reduced subset of the prover's
ms6/utils6.py: it
contains ONLY the primitives vs6's own call graph actually touches --
hash, mul_combinations_mod and its full dependency chain
(vsum_level_fold_mod -> fold_h_vector_mod -> h_vector_mod,
convolve_h_vectors_mod), vsum_level/vsum_level_mod, cell_product/
cell_product_mod, backward_chunk, and the Acc class -- duplicated here
rather than imported from ms6/utils6.py, so this module plus vs6/core.py form a
complete, independent package with zero import-time dependency on the
prover's code (ms6/core.py, ms6/utils6.py).

Deliberately EXCLUDED (prover-only, never reached from vs6's call graph):
col_digit_counts, cell_pow_product(_mod), seal_row_mod, eval_level(_mod),
eval_level_rec_mod, mul_combinations (non-mod)/mul_combinations_rec_mod,
hash_sha256/hash_poseidon (unused prototypes), and everything in ms6/core.py
that generates or handles the secret salt (SystemRandom, _column_perm's
generation -- vs6 only ever *receives* a perm, never derives one).

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
# A fixed 256-bit prime. The singleton-bucket leak documented in
# mul_combinations_mod's docstring is closed at the data level (see
# ms6.core's EDGE-COLUMN DECOY PADDING): the columns a root extraction can
# reach never carry real per-item digest data, regardless of the modulus,
# so there is nothing to gain by making extraction expensive. That frees
# the modulus to be chosen for cost alone -- modular exponentiation
# dominates ps6/vs6, and a 256-bit prime is materially cheaper than a
# wider modulus at every operation that scales with its bit length.
#
# Prime rather than composite is not load-bearing either way -- no modular
# inverse is ever taken mod this value (audited), so a composite would
# drop in unchanged -- prime is simply the easier thing to generate and
# verify: primality is checked directly (Miller-Rabin), where a trustworthy
# composite of unknown order needs either a nothing-up-my-sleeve source or
# a generation process nobody kept the factors from.
#
# Must stay numerically identical to ms6.utils6.DEFAULT_MOD -- see this
# file's own module docstring for why the two copies exist and how they're
# kept in lockstep. A caller free to ignore ms6()'s params dict can still
# pass any mod= explicitly; a commitment records the modulus it used, and
# ps6/vs6 read it from there rather than assuming this constant.
DEFAULT_MOD = 0xa4436df368a6037b5634e0c192096ad8a7289bf1af153aef98ed9c4cbac951e1


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
PAD_SLOT = 10

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

    def _prep(self, p):
        P = [self._powset()[v][p - 1] for v in range(10)]
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

    def _powset(self):
        global _POWSET
        if _POWSET is None:
            nums = list(combinations_with_replacement([1, 3, 5, 7], 2))
            _POWSET = {d: [self.vsum_level(i + 1, values=nums[d]) for i in range(10)]
                    for d in range(10)}
        return _POWSET

    def hash(self, val, k=10):
        if k == 0:
            return 1
        W, tabs, zeros = _PLANES.get(k) or self._prep(k)
        s = _s(val)
        if zeros:
            s = s.rstrip(zeros)
            if not s:
                return 0
        tot = _Z(0)
        for j in range(W - 1, -1, -1):
            tot = tot * 10 + _Z(s.translate(tabs[j]))

        return int(tot)

    def backward_chunk(self, ds, size):
        start = 0
        for end in range(len(ds) % size, len(ds) + 1, size):
            if start == end:
                continue

            yield ds[start:end]
            start = end

    def vsum_level(self, N, keys=None, values=range(1, 10), b=1):
        """Fast path: the vsum integer, without building any key-indexed table."""
        values = list(values)
        keys = list(range(len(values))) if keys is None else list(keys)
        pairs = [(k, v) for k, v in zip(keys, values) if v]
        if not pairs or N <= 0:
            return 0
        M = 10 ** b
        C = max(k for k, v in pairs)             # largest key => Kmax = N*C

        if N == 1:
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

        W = sorted(v * M ** (C - k) for k, v in pairs)
        if _HAVE_GMP:
            W = [_mpz(w) for w in W]
            dp = [_mpz(0)] * (N + 1)
            dp[0] = _mpz(1)
            for w in W:
                for c in range(1, N + 1):
                    dp[c] += dp[c - 1] * w
            return int(dp[N])
        dp = [0] * (N + 1)
        dp[0] = 1
        for w in W:
            for c in range(1, N + 1):            # increasing c => repeats allowed (multisets)
                dp[c] += dp[c - 1] * w
        return dp[N]

    def vsum_level_mod(self, N, mod, keys=None, values=range(1, 10), b=1):
        """Modular counterpart of vsum_level."""
        values = list(values)
        keys = list(range(len(values))) if keys is None else list(keys)
        pairs = [(k, v) for k, v in zip(keys, values) if v]
        if not pairs or N <= 0:
            return 0
        M = 10 ** b
        C = max(k for k, v in pairs)

        if N == 1:
            total = 0
            for k, v in pairs:
                total = (total + v * pow(M, C - k, mod)) % mod
            return total

        W = [(v * pow(M, C - k, mod)) % mod for k, v in pairs]
        W.sort()
        dp = [0] * (N + 1)
        dp[0] = 1
        for w in W:
            for c in range(1, N + 1):
                dp[c] = (dp[c] + dp[c - 1] * w) % mod
        return dp[N]

    def h_vector_mod(self, N, mod, keys=None, values=range(1, 10), b=1, C=None):
        """Same DP as vsum_level_mod, but returns the whole [h_0..h_N]
        vector -- needed by fold_h_vector_mod's Cauchy-product fold (see
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
            for c in range(1, N + 1):          # ascending, same as vsum_level_mod -- repeats allowed (h_N, not e_N)
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
        rationale -- vs6 only ever reaches this via vsum_level_fold_mod
        (below), always with global_keys=True."""
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

    def vsum_level_fold_mod(self, k, mod, values, chunk_size=100, b=1, global_keys=False):
        """Thin wrapper around fold_h_vector_mod -- see ms6/utils6.py's copy for
        the full rationale. Reached only via mul_combinations_mod
        (global_keys=True), to seal its bucket_sums into a single scalar."""
        groups = self.backward_chunk(list(values), chunk_size)
        return self.fold_h_vector_mod(k, mod, groups, b=b, global_keys=global_keys)[k]

    def mul_combinations_mod(self, N, ps, vals, mod):
        """Modular counterpart of mul_combinations -- see ms6/utils6.py's copy
        for the full KNOWN LEAK docstring. In short: idx=0/1/N*(L-1)-1/
        N*(L-1) are singleton buckets holding raw per-column values, and
        extracting an N-th root mod `mod` reads one back -- trivially if
        `mod` is prime, harder if it's a composite of unknown order. The
        buckets are structural, but the columns this reaches never carry
        real per-item digest data in the first place (ms6.core's
        EDGE-COLUMN DECOY PADDING), so what a successful extraction hands
        back is decoy either way."""
        L = len(vals)

        powers = [[1] * (N + 1) for _ in range(L)]
        for pos, v in enumerate(vals):
            row = powers[pos]
            acc = 1
            for c in range(1, N + 1):
                acc = (acc * v) % mod
                row[c] = acc

        r = defaultdict(list)
        for combo in combinations_with_replacement(range(L), N):
            idx = 0
            val = 1
            prev = combo[0]
            cnt = 1
            for pos in combo[1:]:
                if pos == prev:
                    cnt += 1
                else:
                    idx += prev * cnt
                    val = (val * powers[prev][cnt]) % mod
                    prev = pos
                    cnt = 1
            idx += prev * cnt
            val = (val * powers[prev][cnt]) % mod

            r[idx].append(val)

        bucket_sums = [
            sum((p * v) % mod for p, v in zip(ps[idx], val_list)) % mod
            for idx, val_list in r.items()
        ]
        # vsum_level_fold_mod (not vsum_level_mod directly): identical
        # result, global_keys=True to reproduce vsum_level_mod's global
        # bucket-position weighting rather than per-chunk local positions.
        return self.vsum_level_fold_mod(1, mod, bucket_sums, b=1, global_keys=True)