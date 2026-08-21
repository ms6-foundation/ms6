"""vs6 -- the verifier side of the ms6/ps6/vs6 commitment scheme.

    vs6(c, claims, ps_list, x_list, perm_list, h1_salt_list, params, d,
        expect=None) -> True

Self-contained: this package and its utils6 import NOTHING from the
prover package. A party that only ever verifies proofs can install and audit
just this directory, without ever loading code that could generate a secret
salt or fabricate a proof.

That independence is why several functions here duplicate prover-side ones
(_seal_batch, chunk_of, _get_batch_ids, most of Utils) rather than importing
them. Nothing in the language enforces the copies staying in step, so
examples/selftest.py compares their outputs bit-for-bit.

`d` (the row-seal degree) is a separate, required argument, not part of
`params` -- the verifier must already know it from an out-of-band
agreement with the committer, same as any other trust boundary here.

`expect=` pins the incoming params against parameters agreed out of band --
params arrives from the prover and is not self-authenticating. Use it
whenever the prover is not also the caller.
"""
from .core import (
    vs6, interlace_mod,
    unpack_params, PARAM_KEYS, ParamMismatch,
    DEFAULT_CHUNK_SIZE, DEFAULT_BATCH_SIZE, DEFAULT_WORKERS,
    DEFAULT_SEAL_BATCH_SIZE, DEFAULT_MOD, LEGACY_MOD_2048,
)
from . import utils6

__all__ = [
    "vs6", "interlace_mod", "unpack_params", "PARAM_KEYS", "ParamMismatch",
    "DEFAULT_CHUNK_SIZE", "DEFAULT_BATCH_SIZE", "DEFAULT_WORKERS",
    "DEFAULT_SEAL_BATCH_SIZE", "DEFAULT_MOD", "LEGACY_MOD_2048", "utils6",
]
