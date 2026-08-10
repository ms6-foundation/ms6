import sys
import secrets
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

# The modulus for the "_mod" family below. Every multiplication and
# exponentiation in ms6/ps6/vs6 is reduced by it, so no intermediate value
# grows with the dataset.
#
# SIZED FOR THE JOB IT ACTUALLY DOES, which is fingerprinting: the exact
# h == c comparison is traded for a probabilistic one, and two genuinely
# different values collide only by chance, with probability ~1/DEFAULT_MOD
# (the standard Schwartz-Zippel/fingerprinting argument, as in Freivalds').
# At 256 bits that is ~2^-256 against honest error and ~2^128 work for an
# adversary doing birthday search -- i.e. the usual 128-bit bar.
#
# Why not larger: the other property people size a modulus for -- hardness
# of extracting d-th roots, which is what utils6.mul_combinations_mod's
# KNOWN LEAK turns on -- is NOT obtainable from a prime at ANY size. Root
# extraction mod a prime is efficient because the group order is known
# (measured: ~39 ms to recover x from x^3 mod a 2048-bit prime here). Wider
# primes buy nothing there; hardness would need a modulus of UNKNOWN order
# (RSA modulus / class group), a different construction entirely. So the
# previous 2048 bits was ~8x wider than the fingerprint needs while adding
# no hardness, and every modmul in the scheme paid for it.
#
# Provenance: generated here via a fresh 256-bit random odd candidate,
# confirmed prime by utils6.is_prime (Miller-Rabin, 64 rounds) and again by
# an independently written Miller-Rabin -- not transcribed from a published
# constant, so no risk of a transcription error making it composite.
DEFAULT_MOD = 0xbb451c13c2c59bc9e400ec787e175266aa806d1ff7382aceda7c98501b848ce5

# The 2048-bit prime this replaced. Retained so commitments produced under
# it still verify: ms6() records the modulus in its returned params, and
# ps6/vs6 read it from there, so an old proof carrying old params is
# unaffected by the default moving. Also makes reverting a one-line edit.
LEGACY_MOD_2048 = 0xd5fffd2fb08d20c26c48fbbe28a4318db27be5a781b4a22f97c579b997eb652b51c28d75143726a073190b0cd9185446bc036472f191d5d06f5bfb2469dae20c6f42792962b6fb4eab3965b42cf33247f19bd6049c0e9840d7425fe36828b1466d29deec081b067c460304be3cb43be254eb7459a3b8d19de2b77ccad491d3da27eaa807c9c921e4654627ba807c5c9c47f9f28f84f18e70d743718e5f08a692edc4665ee006555579e9af611b2575dd95668c24ccb49a6794e2f9b96b3d660d2ff544513289efe44bef4c78e5a62397efbd75069b80588c4abdee63bcfc43eb2355e3a95224a4bc57b79991038b491904aa163119739223e39f9982eee69b05

# hash() (below) evaluates sum_e powset[digit_e][k-1] * 10**e over the
# decimal digits of val. A digit can only take 10 values, so the
# coefficients come from a fixed set of 10 numbers; writing each in W
# (=max digit-width) decimal planes lets each plane be produced by a
# single str.translate of the digit string plus a Horner fold, instead of
# a per-digit recursion -- W (2 for k=1, 19 for k=10) subquadratic
# string->int conversions rather than O(len(val)) Python-level calls.
_PLANES = {}
_POWSET = None

class Acc:
    """Per-cell digit counts for one grid, with C-speed batched counting."""

    def __init__(self, rows, cols):
        self.rows, self.cols = rows, cols
        self.cnt = [[[0] * 10 for _ in range(cols)] for _ in range(rows)]
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
    def is_prime(self, n, k=64):
        """Miller-Rabin primality test with k rounds (probabilistic, very low error rate)."""
        if n < 2:
            return False
        for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            if n % p == 0:
                return n == p

        # Write n-1 as 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            d //= 2
            r += 1

        for _ in range(k):
            a = secrets.randbelow(n - 3) + 2  # random witness in [2, n-2]
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def generate_prime(self, bits=2048):
        """Generate a random prime of the given bit length."""
        while True:
            candidate = secrets.randbits(bits)
            candidate |= (1 << (bits - 1)) | 1  # set top bit (full bit length) and bottom bit (odd)
            if self.is_prime(candidate):
                return candidate

            
    # col_digit_counts + cell_pow_product(_mod) avoid a sequential
    # len(oset)-long chain of big-int multiplications per output cell
    # (which would cost O(len(oset)^2) overall, since the accumulator
    # grows roughly linearly in digit-count with every step): hm entries
    # only ever contain characters '1'-'9' (digit '1' contributes nothing,
    # 1**k==1), and every other digit factors into primes 2/3/5/7:
    #
    #     2 -> 2^1   3 -> 3^1   4 -> 2^2   5 -> 5^1
    #     6 -> 2*3   7 -> 7^1   8 -> 2^3   9 -> 3^2
    #
    # So rather than one multiplication per item per cell, it's enough to
    # know how many times each digit occurs at that cell across the
    # relevant rows (a cheap count, done at C speed via str.join + slice +
    # Counter) and then evaluate the cell as a single 2^e2 * 3^e3 * 5^e5 *
    # 7^e7 -- four big-int powers total per cell.
    def col_digit_counts(self, row_strings, chunk_size):
        """Per-column digit counts, across several equal-length digit strings
        belonging to the same output row."""
        big = ''.join(row_strings)
        return [Counter(big[j::chunk_size]) for j in range(chunk_size)]
    
    
    def cell_pow_product(self, cnt, mult):
        """prod(v**cnt[v] for v in 1..9) ** mult, via prime factorisation."""
        e2 = (cnt.get('2', 0) + 2*cnt.get('4', 0) + cnt.get('6', 0) + 3*cnt.get('8', 0)) * mult
        e3 = (cnt.get('3', 0) + cnt.get('6', 0) + 2*cnt.get('9', 0)) * mult
        e5 = cnt.get('5', 0) * mult
        e7 = cnt.get('7', 0) * mult
        val = _Z(1)
        if e2: val *= _Z(2) ** e2
        if e3: val *= _Z(3) ** e3
        if e5: val *= _Z(5) ** e5
        if e7: val *= _Z(7) ** e7
        return val


    def cell_pow_product_mod(self, cnt, mult, mod):
        """Same as cell_pow_product, but every power and the running product
        are reduced mod `mod` via 3-argument pow() instead of computed
        exactly. e2/e3/e5/e7 can reach the tens of thousands at dataset
        scale -- pow(base, e, mod) is O(log e) modular multiplications
        (each bounded by `mod`'s size) instead of producing a base**e that
        is itself e*log10(base) decimal digits long."""
        e2 = (cnt.get('2', 0) + 2*cnt.get('4', 0) + cnt.get('6', 0) + 3*cnt.get('8', 0)) * mult
        e3 = (cnt.get('3', 0) + cnt.get('6', 0) + 2*cnt.get('9', 0)) * mult
        e5 = cnt.get('5', 0) * mult
        e7 = cnt.get('7', 0) * mult
        val = _Z(1)
        if e2: val = (val * pow(_Z(2), e2, mod)) % mod
        if e3: val = (val * pow(_Z(3), e3, mod)) % mod
        if e5: val = (val * pow(_Z(5), e5, mod)) % mod
        if e7: val = (val * pow(_Z(7), e7, mod)) % mod
        return val


    def cell_product(self, cnt, mult):
        """prod(d**cnt[d] for d in 1..9) ** mult, via prime factorisation."""
        e2 = (cnt[2] + 2 * cnt[4] + cnt[6] + 3 * cnt[8]) * mult
        e3 = (cnt[3] + cnt[6] + 2 * cnt[9]) * mult
        e5 = cnt[5] * mult
        e7 = cnt[7] * mult
        two, three, five, seven = (_mpz(2), _mpz(3), _mpz(5), _mpz(7)) if _mpz else (2, 3, 5, 7)
        return (two ** e2) * (three ** e3) * (five ** e5) * (seven ** e7)


    def cell_product_mod(self, cnt, mult, mod):
        """Modular counterpart of cell_product -- see cell_pow_product_mod."""
        e2 = (cnt[2] + 2 * cnt[4] + cnt[6] + 3 * cnt[8]) * mult
        e3 = (cnt[3] + cnt[6] + 2 * cnt[9]) * mult
        e5 = cnt[5] * mult
        e7 = cnt[7] * mult
        two, three, five, seven = (_mpz(2), _mpz(3), _mpz(5), _mpz(7)) if _mpz else (2, 3, 5, 7)
        val = pow(two, e2, mod) if e2 else _Z(1)
        if e3: val = (val * pow(three, e3, mod)) % mod
        if e5: val = (val * pow(five, e5, mod)) % mod
        if e7: val = (val * pow(seven, e7, mod)) % mod
        return val


    def seal_row_mod(self, args):
        """Modular counterpart of seal_row, for the ProcessPoolExecutor path.
        Uses vsum_level_fold_mod (chunk_size=100, global_keys=True) rather
        than vsum_level_mod directly -- identical result (verified
        bit-identical, see test_fold_h_vector.py), same global column-
        position weighting, just computed via chunked h_vector_mod +
        Cauchy-product folding. Mirrors ms6's own row-seal choice (see
        ms6.py)."""
        values, N, mod = args
        return int(self.vsum_level_fold_mod(N, mod, values, global_keys=True))


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


    def backward_chunk(self, ds,size):
        start = 0
        for end in range(len(ds)%size, len(ds)+1, size):
            if start==end:
                continue
            
            yield ds[start:end]
            start = end

        
    def vsum(self, ds, b=1):
        s = (sum(s) for s in reversed(ds))
        carry = 0
        m = 10**b
        sr = []
        for d in s:
            carry,v = divmod(d+carry,m)
            sr.insert(0,str(v).zfill(b))

        while carry!=0:
            carry,v = divmod(carry,m)
            sr.insert(0,str(v).zfill(b))

        return int(''.join(sr))

    
    def eval_level(self, N, values, max_idx=None):
        """Groups per-position multiset products into per-idx buckets.
        Driven through itertools.combinations_with_replacement (C speed)
        plus one run-length pass per combo -- e.g. for L=40, N=3 that's
        exactly 11480 Python-level iterations (one per combo), versus an
        unmemoized recursive enumeration revisiting O(L) partial-state
        frames per leaf (~123k calls for the same case).

        `max_idx`, when given, skips the (often large) value multiplication
        for any combo whose idx would land at or beyond it -- safe whenever
        the caller only ever consumes buckets 0..max_idx-1 of the result.
        idx itself is cheap (small-int arithmetic only) so it's still
        derived for every combo; only the conditionally-large product is
        skipped. Not currently used by ms6/ps6/vs6 (which always want
        every bucket), kept for callers that only need a low-idx slice.
        """
        L = len(values)
        if L == 1:
            if max_idx is not None and max_idx <= 0:
                return []
            return [[values[0] ** N]]
 
        powers = [[1] * (N + 1) for _ in range(L)]
        for pos, v in enumerate(values):
            row = powers[pos]
            acc = 1
            for c in range(1, N + 1):
                acc *= v
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
                val *= powers[p][c]
            r[idx].append(val)
 
        return list(r.values())


    def eval_level_mod(self, N, values, mod, max_idx=None):
        """Modular counterpart of eval_level: every power and every combo
        product is reduced mod `mod`, so the accumulated products never grow
        past `mod`'s size no matter how large N or len(values) get. Same
        idx grouping/order as eval_level (verified against it below), just
        with modular instead of exact arithmetic."""
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
            r[idx].append(val)

        return list(r.values())


    def mul_combinations(self, N, q, ps, vals):
        L = len(vals)

        # Precompute vals[pos]**count once per (pos, count), reused across all combos
        powers = [[1] * (N + 1) for _ in range(L)]
        for pos, v in enumerate(vals):
            row = powers[pos]
            acc = 1
            for c in range(1, N + 1):
                acc *= v
                row[c] = acc

        r = defaultdict(list)
        for combo in combinations_with_replacement(range(L), N):
            # combo is already sorted, so walk it once to get (position, run-length)
            # pairs directly — no Counter, no dict.fromkeys, no extra map() passes.
            idx = 0
            val = 1
            prev = combo[0]
            cnt = 1
            for pos in combo[1:]:
                if pos == prev:
                    cnt += 1
                else:
                    idx += prev * cnt
                    val *= powers[prev][cnt]
                    prev = pos
                    cnt = 1
            idx += prev * cnt
            val *= powers[prev][cnt]

            r[idx].append(val)

        # vsum_level(1, ...) does the same positional (base-10^b) packing
        # as self.vsum(), but via a balanced power-of-M doubling split
        # (O(log n) big multiplications) instead of vsum()'s O(n) small
        # divmod-by-10 divisions -- each of those is itself O(n) on an
        # n-digit number, so O(n^2) total, which dominates once summed
        # values reach the hundreds-of-thousands-of-digits scale ps6's
        # oset-derived operands can produce.
        bucket_sums = [
            sum(pow(p * v, q) for p, v in zip(ps[idx], val_list))
            for idx, val_list in r.items()
        ]
        return self.vsum_level(1, values=bucket_sums, b=1)


    def mul_combinations_mod(self, N, ps, vals, mod):
        """Modular counterpart of mul_combinations: `ps` (from
        eval_level_mod) and `vals` (from interlace_mod) are already
        mod-reduced, and every product/power here is reduced mod `mod` too,
        so nothing this function touches ever exceeds `mod`'s size. Same
        combo enumeration/order as mul_combinations (so it lines up with
        eval_level_mod's bucket order the same way mul_combinations lines
        up with eval_level's).

        KNOWN LEAK (documented, not fixed; corrected count -- see
        check_leak.py): idx=0 and idx=N*(L-1) (choosing one column with
        full multiplicity N -- the two combinatorial extremes) are each
        realized by exactly one combo, so their `ps` buckets hold a single
        raw pow(combined[0], N, mod) / pow(combined[L-1], N, mod) term.
        Since N and mod are public, each is invertible via modular root
        extraction whenever gcd(N, mod-1)==1 (generically true, checked
        directly), recovering combined[0] and combined[L-1] = row[j]*
        S[j]**d for those 2 edge columns directly.

        That's not the whole leak, though: idx=1 and idx=N*(L-1)-1 are
        *also* singleton buckets (combo (0,...,0,1) and its mirror), and
        their leaked values are combined[0]**(N-1)*combined[1] and
        combined[L-2]*combined[L-1]**(N-1) -- products, not raw single-
        column values, but since combined[0] and combined[L-1] are
        already recovered from idx=0/idx=N*(L-1) above, dividing them back
        out cascades to combined[1] and combined[L-2] as well. Verified
        empirically (check_leak.py): at chunk_size=40, d=3 (118 buckets),
        this is 4 singleton buckets -> 4 real columns recovered per row
        (0, 1, 38, 39), not 2. The cascade is 2 columns deep at d=3
        because idx=1's combo only ever touches 2 distinct columns
        (multiplicity N-1 and 1); larger d admits deeper cascades from
        each end (idx=2 touches up to 3 distinct columns, etc.), so the
        leaked-column count grows with d, not just chunk_size.

        eval_level_rec_mod/mul_combinations_rec_mod (below) trade this for
        a materially larger leak (every column invertible, not just a
        handful from each edge) in exchange for making d=27 feasible --
        moot in practice since neither is wired into ps6/vs6's default
        path. Neither hashing nor multiplicatively blinding the per-column
        values closes this leak without breaking correctness or being
        just as invertible itself (see forge_ps.py) -- doing so for real
        needs exponent-based (discrete-log) hiding, not this codebase's
        "value as the base of a public power mod a prime" construction.
        This smaller-leak combinatorial version is the default in ps6/
        vs6; d=27 is unsupported by that tradeoff, not by oversight."""
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
        # bucket-position weighting rather than per-chunk local positions --
        # see ms6.py's row-seal for the same substitution/rationale.
        return self.vsum_level_fold_mod(1, mod, bucket_sums, b=1, global_keys=True)


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
            # h_1 is just the positional (base-M) sum of the weighted values.
            # Doing it by string assembly is O(total digits) instead of the
            # O(n^2) big-int accumulation the DP below would perform.
            bucket = [0] * (C + 1)
            for k, v in pairs:
                bucket[C - k] += v              # place value e = C - k
            if all(a < M for a in bucket):
                # no carries possible -> assemble digits directly (high -> low)
                if b == 1:
                    return int(''.join([str(a) for a in reversed(bucket)]))
                return int(''.join([str(a).zfill(b) for a in reversed(bucket)]))
            # Carry propagation is just integer addition, so the result is
            # simply sum(bucket[e] * M**e).  Balanced binary split as before,
            # but bottom-up: each pass consumes one power of M and squares it,
            # so we spend O(log n) pow-by-squaring steps instead of O(n)
            # M**e evaluations and 2n recursive frames.
            cur = [_Z(a) for a in bucket] if _HAVE_GMP else bucket
            p = _Z(M)
            while len(cur) > 1:
                nxt = [cur[i] + cur[i + 1] * p for i in range(0, len(cur) - 1, 2)]
                if len(cur) & 1:
                    nxt.append(cur[-1])
                cur = nxt
                p *= p

            return _i(cur[0])

        # dp[N] is h_N (complete homogeneous symmetric polynomial) of the
        # weighted values, so it is invariant under permutation of them.
        # Processing smallest-first keeps the running dp entries smaller for
        # longer, which cuts total big-int multiplication cost.
        W = sorted(v * M ** (C - k) for k, v in pairs)
        if _HAVE_GMP:
            # CPython multiplies via Karatsuba; GMP uses FFT-based routines,
            # which is a large win once operands reach tens of thousands of
            # digits. Exact integer arithmetic either way.
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
        """Modular counterpart of vsum_level: every weighted value, and
        every DP/positional-sum accumulation, is reduced mod `mod`. The
        N==1 fast path's "no-carry, assemble digits directly" shortcut
        relies on base-M positional digits with *no* modular reduction
        (that is precisely what lets it skip carry propagation) -- reducing
        mod a prime that has nothing to do with base M would silently
        corrupt that shortcut, so this always takes the explicit
        weighted-sum-mod-`mod` path instead, for both N==1 and N>1. Same
        (k, key) -> weight convention as vsum_level (weight = M**(C-k)),
        just evaluated via pow(..., mod) instead of exact exponentiation."""
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

        # Same h_N DP as vsum_level (increasing c => repeats allowed), with
        # every weight and every accumulation reduced mod `mod`.
        W = [(v * pow(M, C - k, mod)) % mod for k, v in pairs]
        W.sort()
        dp = [0] * (N + 1)
        dp[0] = 1
        for w in W:
            for c in range(1, N + 1):
                dp[c] = (dp[c] + dp[c - 1] * w) % mod
        return dp[N]


    def h_vector_mod(self, N, mod, keys=None, values=range(1, 10), b=1, C=None):
        """Same DP as vsum_level_mod, but returns the *whole* vector
        [h_0, h_1, ..., h_N] instead of just h_N. h_0..h_{N-1} aren't waste
        product -- they're exactly what's needed to correctly fold two
        groups of values together (see fold_h_vector_mod): the complete
        homogeneous symmetric polynomials of a disjoint union obey a Cauchy
        product, h_k(A u B) = sum_{i=0}^{k} h_i(A) * h_{k-i}(B), which needs
        every h_i up to k on both sides, not just the top one. Verified
        against direct brute-force combinatorial enumeration (200/200
        randomized trials, various group sizes and degrees).

        `C`, when given, overrides the auto-derived max-key used for
        positional weighting (vsum_level_mod always derives it as
        max(keys) *within this one call*). That's the right thing when
        values arrive pre-split into groups -- vsum_level_mod's positional
        packing is defined relative to *one shared* C across the whole
        dataset (e.g. chunk_size-1), not each group's own local max key;
        passing the same global C into every group's h_vector_mod call is
        what makes fold_h_vector_mod's result match a single vsum_level_mod
        call over the unsplit values -- see fold_h_vector_mod's docstring
        and test_fold_h_vector.py."""
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
        group), truncated to degree N: this *is* h_k of the disjoint union
        of the two groups, for k=0..N -- see h_vector_mod's docstring for
        the identity. Truncating at N is safe because h_k(A u B) for k<=N
        only ever needs A[i]/B[j] with i,j<=N (i+j<=k<=N implies i<=N and
        j<=N), so nothing above degree N is ever needed regardless of how
        many more groups get folded in afterward."""
        C = [0] * (N + 1)
        for k in range(N + 1):
            C[k] = sum(A[i] * B[k - i] for i in range(k + 1)) % mod
        return C


    def fold_h_vector_mod(self, N, mod, group_values, b=1, global_keys=False):
        """Compute h_N of a large dataset by processing it in groups
        (`group_values` is an iterable of value-lists, e.g. from
        backward_chunk), computing each group's own h-vector via
        h_vector_mod, and folding groups together via convolve_h_vectors_mod
        -- one group (and one running [h_0..h_N] accumulator, both O(N)) in
        memory at a time, rather than needing the whole dataset's derived
        data materialized at once.

        global_keys=False (default): each group is weighted by its own
        *local* positions (0..len(group)-1) using whatever b is passed
        (default b=1, same as vsum_level_mod's default) -- pass b=0 (so
        M=10**0=1, weight collapses to the value itself regardless of
        position) if you want a truly plain, unordered-multiset h_N of the
        flattened values with no positional packing at all.

        global_keys=True: reproduces vsum_level_mod's *global*, dataset-
        position-weighted packing exactly (the convention ms6's row-seal
        actually uses: weight = value * mod**(C - global_position)). Each
        group is passed its true global keys and a shared global C
        (= total_len - 1) via h_vector_mod's C= override, so every group's
        weighting is normalized against the *same* reference point instead
        of its own local max -- that shared reference is what makes the
        folded result match a single vsum_level_mod call over the unsplit
        sequence, not just "a" valid packing of the same values.

        Verified against vsum_level_mod's own single-pass h_N -- bit-
        identical, same b, same flattened value list, both with and
        without global_keys -- across randomized group counts/sizes/
        degrees/moduli (see test_fold_h_vector.py).
        """
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
        """DP + modular-arithmetic counterpart of fold6.py's vsum_level_fold:
        same hierarchical idea (fold a large flat `values` list down via
        chunk_size-sized groups, degree k held fixed throughout), but every
        group's own h-vector is computed via h_vector_mod's O(k*chunk_size)
        DP instead of combinations_with_replacement enumeration, and groups
        are recombined via convolve_h_vectors_mod's Cauchy product instead
        of re-expanding combinatorially -- both implement the same
        identity, just DP-based rather than enumeration-based, with every
        operation reduced mod `mod` so intermediate values stay bounded
        regardless of dataset size or degree. Thin, explicitly-named
        wrapper around fold_h_vector_mod (identical result) so the
        connection to fold6.py's vsum_level_fold is obvious by name.
        """
        groups = self.backward_chunk(list(values), chunk_size)
        return self.fold_h_vector_mod(k, mod, groups, b=b, global_keys=global_keys)[k]