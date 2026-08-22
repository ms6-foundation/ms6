"""Run every test module and report one combined pass/fail.

    python3 tests/run_all.py      # or: python3 -m tests

Exits non-zero if any check fails, listing the failures by name.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.harness import Checker                    # noqa: E402
from tests import (                                  # noqa: E402
    bench, test_roundtrip, test_updatability, test_modulus,
    test_sealtree, test_params, test_parity, test_sizing,
    test_completeness, test_adversarial, test_leak, test_hiding,
    test_query_governance, test_salt_rotation,
)

MODULES = [
    ("round trip", test_roundtrip),
    ("updatability", test_updatability),
    ("modulus", test_modulus),
    ("seal tree", test_sealtree),
    ("params", test_params),
    ("copy parity", test_parity),
    ("sizing", test_sizing),
    ("completeness", test_completeness),
    ("adversarial", test_adversarial),
    ("leak", test_leak),
    ("hiding", test_hiding),
    ("query governance", test_query_governance),
    ("salt rotation", test_salt_rotation),
]


def main():
    check = Checker()
    for title, mod in MODULES:
        print(f"\n{title}")
        mod.run(check)
    print("\nbenchmark (informational, never fails the run)")
    bench.run()
    return check.report("checks")


if __name__ == "__main__":
    raise SystemExit(main())
