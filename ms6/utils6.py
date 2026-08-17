import sys
import hashlib
import math
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

# The accumulator modulus. Every multiplication and exponentiation in
# ms6/ps6/vs6 is reduced by it, so no intermediate value grows with the
# dataset.
#
# 256-bit prime, nothing-up-my-sleeve: pi's fractional part computed to
# 100 decimal digits (Chudnovsky series), scaled to its top 256
# significant binary bits, then advanced through odd candidates to the
# first one that is both prime and satisfies gcd(3, p-1) == 1 (126
# candidates in) -- kept there, not resampled, so d=3's own root-
# extraction demo in tests/test_leak.py applies directly to this exact
# shipped constant rather than a substitute. Independently reproducible
# by anyone from that recipe; this codebase does not control its value.
#
# Why prime is fine: the modulus's job here is fingerprinting (Schwartz-
# Zippel), not hiding. The singleton-bucket leak documented in
# mul_combinations_mod's docstring is closed at the data level (see
# ms6.core's EDGE-COLUMN PADDING) -- the columns a root extraction
# can reach never carry real per-item digest data, regardless of the
# modulus, so what a successful extraction recovers is a fixed public
# constant, not data correlated with any item. An
# unknown-order modulus was never load-bearing for that leak; it only ever
# added a second, redundant layer, at the cost of modular exponentiation
# scaling with a 2048-bit rather than 256-bit modulus throughout ps6/vs6 --
# measured at roughly 2-3x slower for the exponentiation-dominated
# operations (docs/ms6_eprint.tex's efficiency section). Root-extraction
# hardness itself is not achievable via modulus choice under this
# construction at any size: mod a prime the group order p-1 is public, so
# a d-th root is a single pow() away regardless of bit length (ms6_vibe.md
# entry 10 measured 39ms against a 2048-bit prime); mod a composite that
# hardness is real (the RSA problem) but at the cost above for a property
# nothing here relies on. See tests/test_leak.py for the corresponding
# checks.
#
# The old RSA-2048 Factoring Challenge composite is kept as LEGACY_MOD_2048
# below for any deployment that still wants that redundant second layer.
#
# A caller free to ignore ms6()'s params dict can still pass any mod=
# explicitly; a commitment records the modulus it used, and ps6/vs6 read it
# from there rather than assuming this constant.
DEFAULT_MOD = 0x90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b31f

# The former default (2048-bit RSA Factoring Challenge composite, unknown
# order to everyone including the parties running ms6/ps6/vs6). Kept
# available, unchanged, for any commitment or deployment choosing to pass
# mod=LEGACY_MOD_2048 explicitly for the extra (redundant, per the
# reasoning above) unknown-order layer. Not the default because it buys no
# real security here at a measured ~2-3x arithmetic cost -- see
# DEFAULT_MOD's own comment above.
LEGACY_MOD_2048 = 0xc7970ceedcc3b0754490201a7aa613cd73911081c790f5f1a8726f463550bb5b7ff0db8e1ea1189ec72f93d1650011bd721aeeacc2acde32a04107f0648c2813a31f5b0b7765ff8b44b4b6ffc93384b646eb09c7cf5e8592d40ea33c80039f35b4f14a04b51f7bfd781be4d1673164ba8eb991c2c4d730bbbe35f592bdef524af7e8daefd26c66fc02c479af89d64d373f442709439de66ceb955f3ea37d5159f6135809f85334b5cb1813addc80cd05609f10ac6a95ad65872c909525bdad32bc729592642920f24c61dc5b3c3b7923e56b16a4d9d373d8721f24a3fc0f1b3131f55615172866bccc30f95054c824e733a5eb6817f7bc16399d48c6361cc7e5

# hash() (below) evaluates sum_e powset[digit_e][k-1] * 10**e over the
# decimal digits of val. A digit can only take 10 values, so the
# coefficients come from a fixed set of 10 numbers; writing each in W
# (=max digit-width) decimal planes lets each plane be produced by a
# single str.translate of the digit string plus a Horner fold, instead of
# a per-digit recursion -- W (2 for k=1, 19 for k=10) subquadratic
# string->int conversions rather than O(len(val)) Python-level calls.

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

# domain_hash's output width: 32 bytes (256 bits) is the point past which
# SHAKE128 stops buying any more collision resistance -- its 256-bit
# capacity caps collision resistance at min(output_bits/2, 128), so 256
# bits of output already reaches that 128-bit ceiling; asking for more
# would only lengthen the digit string, not strengthen it. See
# Utils.domain_hash's own docstring for why 128-bit is the deliberate
# target rather than a shortfall.
DOMAIN_HASH_BYTES = 32
# Every domain_hash() output is zero-padded to this many decimal digits --
# ceil(DOMAIN_HASH_BYTES * 8 * log10(2)) -- so item digests have a FIXED
# width regardless of the item's own value, rather than the input-
# magnitude-dependent width the old hash() produced. A fixed width means
# grid depth (x, in ms6.core) no longer needs to be discovered by
# measuring every item's digest before committing.
DOMAIN_HASH_DIGITS = len(str(256 ** DOMAIN_HASH_BYTES - 1))

_PLANES = {}
_POWSET = None

class Acc:
    """Per-cell digit counts for one grid, with C-speed batched counting."""

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
    # contain the ten decimal digits plus PAD, and each digit contributes
    # DIGIT_PRIMES[digit] raised to its own count:
    #
    #     0 -> 2   1 -> 3   2 -> 5   3 -> 7   4 -> 11
    #     5 -> 13  6 -> 17  7 -> 19  8 -> 23  9 -> 29     PAD -> nothing
    #
    # So rather than one multiplication per item per cell, it's enough to
    # know how many times each digit occurs at that cell across the
    # relevant rows (a cheap count, done at C speed via str.join + slice +
    # Counter) and then evaluate the cell as one power per distinct digit
    # present -- at most ten big-int powers per cell, independent of how
    # many items the cell aggregates.
    def col_digit_counts(self, row_strings, chunk_size):
        """Per-column digit counts, across several equal-length digit strings
        belonging to the same output row."""
        big = ''.join(row_strings)
        return [Counter(big[j::chunk_size]) for j in range(chunk_size)]
    
    
    def cell_pow_product_mod(self, cnt, mult, mod):
        """prod(DIGIT_PRIMES[v]**cnt[v] for v in 0..9) ** mult, every power
        and the running product reduced mod `mod` via 3-argument pow()
        instead of computed exactly.

        One distinct prime per digit, so the exponent vector is recoverable
        from the product by unique factorisation. PAD occupies count slot
        10 and is assigned no prime, so padding contributes nothing.
        e2/e3/e5/e7 can reach the tens of thousands at dataset
        scale -- pow(base, e, mod) is O(log e) modular multiplications
        (each bounded by `mod`'s size) instead of producing a base**e that
        is itself e*log10(base) decimal digits long."""
        val = _Z(1)
        for v in range(10):
            e = cnt.get(str(v), 0) * mult
            if e:
                val = (val * pow(_Z(DIGIT_PRIMES[v]), e, mod)) % mod
        return val


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
        """Modular counterpart of cell_product -- see cell_pow_product_mod."""
        val = _Z(1)
        for v in range(10):
            e = cnt[v] * mult
            if e:
                val = (val * pow(_Z(DIGIT_PRIMES[v]), e, mod)) % mod
        return val


    def seal_row_mod(self, args):
        """Modular row-seal for the ProcessPoolExecutor path -- a thin
        wrapper so ex.map has a single picklable callable to dispatch.
        Folds one row as pow(vsum_level(1, values=values), N, mod), the
        same (sum)^N construction ms6.core._seal_grid's own sequential
        branch uses -- must stay in lockstep with it, or a commit built
        with workers>1 diverges from one built with workers=1 (see
        tests/test_sizing.py's row-fold parallelism check)."""
        values, N, mod = args
        return pow(self.vsum_level(1, values=values), N, mod)

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


    def domain_hash(self, data):
        """SHAKE128 digest of `data` (bytes), as a fixed-width decimal digit
        string -- the item-level domain hash behind H1/H2 in ms6.core's
        _hash_item, replacing the digit-substitution `hash()` above for
        that specific use. `hash()` itself is UNCHANGED and still used
        elsewhere (the seal-tree fold's per-batch hashing, hmax sizing) --
        this is a new, separate primitive, not a replacement for those.

        SHAKE128 rather than SHAKE256: this scheme's binding argument
        already reduces item-digest collision resistance to an ordinary
        hash-collision assumption (a separate, independent layer from the
        per-cell prime encoding's own injectivity -- DIGIT_PRIMES). 128-bit
        collision resistance is a deliberate, explicit target for that
        layer -- the same effective floor SHA-256 itself has under the
        generic birthday bound -- not an oversight; see the eprint's
        binding section for the full argument. SHAKE128's larger rate
        (smaller 256-bit capacity than SHAKE256's 512-bit one) buys
        meaningfully faster hashing in exchange, at DOMAIN_HASH_BYTES=32
        output the ceiling this construction is willing to pay for anyway.

        Fixed-width, zero-padded output (DOMAIN_HASH_DIGITS decimal digits,
        regardless of the digest's own leading zero bytes) rather than
        stripping leading zeros -- a variable-width digest would leak
        (weakly) through grid-row count if not otherwise masked, and would
        reintroduce the "measure every item's actual digest width" dance
        _ms6_batch's x-sizing used to need for the old, input-magnitude-
        scaling hash()."""
        digest = hashlib.shake_128(data).digest(DOMAIN_HASH_BYTES)
        return str(int.from_bytes(digest, "big")).zfill(DOMAIN_HASH_DIGITS)


    def backward_chunk(self, ds,size):
        start = 0
        for end in range(len(ds)%size, len(ds)+1, size):
            if start==end:
                continue
            
            yield ds[start:end]
            start = end

        
    def mul_combinations_mod(self, N, ps, vals, mod):
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
        # vsum_level_fold_mod, see ms6.py's row-seal for the same substitution/rationale.
        return self.vsum_level_fold_mod(1, mod, bucket_sums, b=1, global_keys=True)


    def multinomial(self, P, deg):
        """deg! / prod(p! for p in P) -- gen.py's fast_coeff, without the cache."""
        return math.prod(range(P[0] + 1, deg + 1)) // math.prod(
            math.factorial(p) for p in P[1:])


    def eval_level_mod(self, N, values, mod, max_idx=None):
        """Groups per-position multiset products into per-idx buckets,
        every power and every combo product reduced mod `mod` so the
        accumulated products never grow past `mod`'s size no matter how
        large N or len(values) get. Driven through
        itertools.combinations_with_replacement (C speed) plus one
        run-length pass per combo -- e.g. for L=40, N=3 that's exactly
        11480 Python-level iterations (one per combo), versus an
        unmemoized recursive enumeration revisiting O(L) partial-state
        frames per leaf (~123k calls for the same case).

        Each combo's product is scaled by its own public multinomial
        coefficient (self.multinomial, from the combo's run-length shape)
        before landing in its idx bucket -- so the buckets this returns sum
        to (sum_j values[j])**N, not h_N(values) the way an unweighted
        enumeration would. Used this way by ms6.core._finish_ps6/ps6, paired
        against mul_combinations_mod's own (unweighted) enumeration on the
        verifier side -- the multinomial theorem's twisted-bilinear form,
        (sum_j x_j*y_j)**N = sum_C ce(C)*monomial_x(C)*monomial_y(C), makes
        that pairing reconstruct the same total either way, as long as the
        weight lands on exactly one side. See _seal_grid's own row-fold
        (pow(vsum_level(1,...), N, mod)) for the matching commit-time side
        of this identity.

        The multinomial weight is 1 at idx=0 and idx=N*(L-1) (each realized
        by exactly one combo, all N copies at one position) -- so it does
        not change mul_combinations_mod's own KNOWN LEAK discussion (above,
        in this file), only the buckets in between.

        `max_idx`, when given, skips the (often large) value multiplication
        for any combo whose idx would land at or beyond it -- safe whenever
        the caller only ever consumes buckets 0..max_idx-1 of the result.
        idx itself is cheap (small-int arithmetic only) so it's still
        derived for every combo; only the conditionally-large product is
        skipped."""
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

        r1 = defaultdict(list)
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
            ce = self.multinomial([c for p, c in runs], N) % mod
            r1[idx].append((val * ce) % mod)

        return list(r1.values())
    

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


    def h_vector_mod(self, N, mod, keys=None, values=range(1, 10), b=1, C=None):
        """The modular h_N DP (same (k, key) -> weight convention as
        vsum_level, weight = M**(C-k), evaluated via pow(..., mod) instead
        of exact exponentiation, every accumulation reduced mod `mod`), but
        returns the *whole* vector [h_0, h_1, ..., h_N] instead of just
        h_N. h_0..h_{N-1} aren't waste product -- they're exactly what's
        needed to correctly fold two groups of values together (see
        fold_h_vector_mod): the complete homogeneous symmetric polynomials
        of a disjoint union obey a Cauchy product, h_k(A u B) =
        sum_{i=0}^{k} h_i(A) * h_{k-i}(B), which needs every h_i up to k on
        both sides, not just the top one. Verified against direct
        brute-force combinatorial enumeration (200/200 randomized trials,
        various group sizes and degrees).

        `C`, when given, overrides the auto-derived max-key used for
        positional weighting (otherwise derived as max(keys) *within this
        one call*). That's the right thing when values arrive pre-split
        into groups -- the positional packing is defined relative to *one
        shared* C across the whole dataset (e.g. chunk_size-1), not each
        group's own local max key; passing the same global C into every
        group's h_vector_mod call is what makes fold_h_vector_mod's result
        match a single h_vector_mod call's h_N over the unsplit values,
        provided the caller also passes global_keys=True there -- see
        fold_h_vector_mod's docstring."""
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
        (default b=1, same default as h_vector_mod's own) -- pass b=0 (so
        M=10**0=1, weight collapses to the value itself regardless of
        position) if you want a truly plain, unordered-multiset h_N of the
        flattened values with no positional packing at all.

        global_keys=True: reproduces the *global*, dataset-position-
        weighted packing ms6's row-seal actually relies on (weight = value
        * mod**(C - global_position), the same convention h_vector_mod/
        vsum_level use). Each group is passed its true global keys and a
        shared global C (= total_len - 1) via h_vector_mod's C= override,
        so every group's weighting is normalized against the *same*
        reference point instead of its own local max -- that shared
        reference is what makes the folded result match taking h_N of the
        whole flattened, unsplit sequence directly in one call, not just
        "a" valid packing of the same values.

        Verified bit-identical to h_vector_mod's own single-pass h_N over
        the unsplit, flattened value list (same b) -- PROVIDED the caller
        passes global_keys=True; global_keys=False computes a different
        (locally-weighted) value on purpose, per the two paragraphs above,
        not a bug. A caller that wants this function's output to match a
        single unsplit h_N call over the same values MUST pass
        global_keys=True explicitly -- the default is False, and every
        call site that omitted it while splitting a real row/list into
        more than one group silently computed the wrong scalar (found and
        fixed across ms6.core/vs6.core, see ms6_vibe.md).
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


    def vsum_level_fold_mod(self, k, mod, values, chunk_size=20, b=1, global_keys=False):
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