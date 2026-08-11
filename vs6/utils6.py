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
# THIS IS THE RSA-2048 FACTORING CHALLENGE MODULUS -- a 617-digit / 2048-bit
# COMPOSITE, published by RSA Laboratories in 1991 and never factored. It is
# deliberately not a prime.
#
# Why a composite of unknown order. The documented leak in
# mul_combinations_mod recovers a handful of columns per row by extracting
# d-th roots out of singleton buckets. Mod a PRIME that is efficient at any
# size, because the group order (p-1) is public: the attacker just computes
# d^-1 mod (p-1) and exponentiates (measured earlier in this project: ~39 ms
# against a 2048-bit prime). Widening the prime bought nothing. Mod a
# composite whose factorisation nobody holds, phi(n) is unknown, there is no
# exponent to invert, and extracting d-th roots is the RSA problem. That is
# what closes the leak's mechanism -- not a parameter choice, a change of
# group.
#
# TRUST ASSUMPTION, stated plainly: RSA-2048's factors are believed unknown
# because RSA Security generated the challenge numbers and says it destroyed
# them. You are trusting that claim. It is a far better position than a
# locally generated modulus -- where whoever ran the generator could have
# kept p and q, and could then forge -- but it is not zero-trust. Only a
# class group of an imaginary quadratic field removes the trusted party
# entirely, at the cost of slower arithmetic and a less familiar assumption.
#
# Nothing in this codebase requires the modulus to be prime: no modular
# inverse is ever taken mod this value (audited), so the composite drops
# straight in.
#
# Verified before adoption: 617 decimal digits; 2048 bits; composite by
# Miller-Rabin (64 rounds); no factor below 100,000; Pollard rho finds
# nothing in 200k iterations; and the value was cross-checked against an
# independently written reconstruction, digit for digit.
#
# COST: ps6 is ~14x slower here than under the 256-bit prime, being almost
# entirely modular exponentiation. commit and verify are ~2x. That is the
# price of the hardness.
DEFAULT_MOD = 0xc7970ceedcc3b0754490201a7aa613cd73911081c790f5f1a8726f463550bb5b7ff0db8e1ea1189ec72f93d1650011bd721aeeacc2acde32a04107f0648c2813a31f5b0b7765ff8b44b4b6ffc93384b646eb09c7cf5e8592d40ea33c80039f35b4f14a04b51f7bfd781be4d1673164ba8eb991c2c4d730bbbe35f592bdef524af7e8daefd26c66fc02c479af89d64d373f442709439de66ceb955f3ea37d5159f6135809f85334b5cb1813addc80cd05609f10ac6a95ad65872c909525bdad32bc729592642920f24c61dc5b3c3b7923e56b16a4d9d373d8721f24a3fc0f1b3131f55615172866bccc30f95054c824e733a5eb6817f7bc16399d48c6361cc7e5

# NOTE on older commitments: no constant is kept here for the primes this
# replaced. None is needed -- ms6() records the modulus it used in the
# params dict it returns, and ps6/vs6 read it from there, so a commitment
# made under any earlier modulus still verifies from its own params. A
# caller reproducing one just passes mod=<that value> explicitly.

_PLANES = {}
_POWSET = None


class Acc:
    """Per-cell digit counts for one grid, with C-speed batched counting.
    Used by _seal_batch (the same batch-fold logic ms6 runs, which vs6
    re-runs independently to check the final h against c)."""

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
    """Verifier-safe subset of ms6.utils6.Utils -- see module docstring for
    exactly what's included/excluded and why."""

    def cell_product(self, cnt, mult):
        """prod(d**cnt[d] for d in 1..9) ** mult, via prime factorisation."""
        e2 = (cnt[2] + 2 * cnt[4] + cnt[6] + 3 * cnt[8]) * mult
        e3 = (cnt[3] + cnt[6] + 2 * cnt[9]) * mult
        e5 = cnt[5] * mult
        e7 = cnt[7] * mult
        two, three, five, seven = (_mpz(2), _mpz(3), _mpz(5), _mpz(7)) if _mpz else (2, 3, 5, 7)
        return (two ** e2) * (three ** e3) * (five ** e5) * (seven ** e7)

    def cell_product_mod(self, cnt, mult, mod):
        """Modular counterpart of cell_product."""
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
        N*(L-1) are singleton buckets holding raw per-column values. Reading
        them back means extracting an N-th root mod `mod`, which is free if
        `mod` is prime and is the RSA problem if it is a composite of
        unknown order -- as DEFAULT_MOD now is. The buckets are structural;
        what the modulus decides is whether they can be inverted."""
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