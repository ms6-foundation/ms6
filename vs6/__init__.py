"""vs6 -- the verifier side of the ms6/ps6/vs6 commitment scheme.

    vs6(c, claims, ps_list, x_list, perm_list, params, expect=None) -> True

Self-contained: this package and verifier_utils6 import NOTHING from the
prover package. A party that only ever verifies proofs can install and audit
just this directory, without ever loading code that could generate a secret
salt or fabricate a proof.

That independence is why several functions here duplicate prover-side ones
(_seal_batch, chunk_of, _get_batch_ids, most of Utils) rather than importing
them. Nothing in the language enforces the copies staying in step, so
examples/selftest.py compares their outputs bit-for-bit.

`expect=` pins the incoming params against parameters agreed out of band --
params arrives from the prover and is not self-authenticating. Use it
whenever the prover is not also the caller.
"""
from .core import (
    vs6, interlace_mod,
    unpack_params, PARAM_KEYS, ParamMismatch,
    DEFAULT_CHUNK_SIZE, DEFAULT_BATCH_SIZE, DEFAULT_WORKERS,
    DEFAULT_SEAL_BATCH_SIZE, DEFAULT_MOD,
)
from . import verifier_utils6

__all__ = [
    "vs6", "interlace_mod", "unpack_params", "PARAM_KEYS", "ParamMismatch",
    "DEFAULT_CHUNK_SIZE", "DEFAULT_BATCH_SIZE", "DEFAULT_WORKERS",
    "DEFAULT_SEAL_BATCH_SIZE", "DEFAULT_MOD", "verifier_utils6",
]
