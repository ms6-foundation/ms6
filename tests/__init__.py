"""Tests for the ms6 (prover) and vs6 (verifier) packages.

Run everything:

    python3 -m tests            # or: python3 tests/run_all.py

Run one group:

    python3 -m tests.test_parity

Each module exposes a `run(check)` taking the shared reporter from
tests.harness, so the modules compose into one pass/fail report and also
stand alone. Exit status is non-zero if any check fails, so this works as a
CI gate.
"""
