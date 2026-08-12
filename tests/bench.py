"""Update cost vs. a full recommit -- informational, not a pass/fail check.

Kept out of the check modules deliberately: it reports a timing, and a timing
is not something a CI gate should fail on.
"""
import time

from tests.harness import Commitment, D, Q, mk  # noqa: F401


def run(check=None):
    U = Commitment([mk(i) for i in range(600)], D, Q, chunk_size=40, batch_size=20)
    # XORing mk(300) rather than picking an unrelated value: item digests
    # now come from Utils.domain_hash (SHAKE128, fixed-width), so unlike
    # the old hash()'s input-magnitude-scaling width, no value can overflow
    # _check_fits's guard anymore regardless of magnitude -- this timing
    # probe just wants a value distinct from the original at index 300,
    # not a specific magnitude class.
    t0 = time.time(); U.replace(300, mk(300) ^ 0xABCDEF1234567); t_upd = time.time() - t0
    t0 = time.time()
    Commitment(U.vals, D, Q, chunk_size=40, batch_size=20, s_mod=U.s_mod)
    t_full = time.time() - t0
    print(f"  [info] {len(U.h_list)} batches: replace {t_upd * 1000:.1f} ms "
          f"vs full recommit {t_full * 1000:.1f} ms ({t_full / t_upd:.0f}x)")


if __name__ == "__main__":
    run()
