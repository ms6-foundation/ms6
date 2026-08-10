"""Update cost vs. a full recommit -- informational, not a pass/fail check.

Kept out of the check modules deliberately: it reports a timing, and a timing
is not something a CI gate should fail on.
"""
import time

from tests.harness import Commitment, D, Q, mk  # noqa: F401


def run(check=None):
    U = Commitment([mk(i) for i in range(600)], D, Q, chunk_size=40, batch_size=20)
    # A same-magnitude-class replacement, not mk(4242): mk(i)'s hash width
    # grows with i (see _check_fits), so a value from a far larger i would
    # legitimately overflow index 300's batch -- this timing probe isn't
    # exercising that guard, just the replace-vs-recommit cost, so it needs
    # a value that actually fits.
    t0 = time.time(); U.replace(300, mk(300) ^ 0xABCDEF1234567); t_upd = time.time() - t0
    t0 = time.time()
    Commitment(U.vals, D, Q, chunk_size=40, batch_size=20, s_mod=U.s_mod)
    t_full = time.time() - t0
    print(f"  [info] {len(U.h_list)} batches: replace {t_upd * 1000:.1f} ms "
          f"vs full recommit {t_full * 1000:.1f} ms ({t_full / t_upd:.0f}x)")


if __name__ == "__main__":
    run()
