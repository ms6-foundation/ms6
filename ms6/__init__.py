"""ms6 -- the prover side of the ms6/ps6/vs6 commitment scheme.

    ms6(vals, d, q, ...)   commit    -> (c, h_list, x_list, s_list, hm_list, perm_list, params)
    ps6(iset, ..., params) open      -> ps_list
    Commitment(...)        updatable commit: append / replace / delete

`params` is the public parameter dict every side must agree on; hand it
straight to ps6/vs6 rather than passing d/q/chunk_size/... separately (see
PARAM_KEYS).

This package has NO dependency on the verifier package -- and the verifier
has none on this one. That separation is the point: a party that only
verifies installs `vs6` alone and never loads prover code (salt generation,
eval_level_mod, the opening data). The two share several deliberately
duplicated functions; examples/selftest.py asserts the copies still agree.
"""
from .core import (
    ms6, ps6, Commitment,
    make_params, unpack_params, PARAM_KEYS, ParamMismatch,
    DEFAULT_CHUNK_SIZE, DEFAULT_BATCH_SIZE, DEFAULT_WORKERS, DEFAULT_KEEP_HM,
    DEFAULT_SEAL_BATCH_SIZE, DEFAULT_SEAL_MOD_BITS, DEFAULT_MOD,
    DEFAULT_S_MOD, DEFAULT_S_EXP, DEFAULT_HMAX_PAD_SIZE,
)
from . import utils6

__all__ = [
    "ms6", "ps6", "Commitment",
    "make_params", "unpack_params", "PARAM_KEYS", "ParamMismatch",
    "DEFAULT_CHUNK_SIZE", "DEFAULT_BATCH_SIZE", "DEFAULT_WORKERS",
    "DEFAULT_KEEP_HM", "DEFAULT_SEAL_BATCH_SIZE", "DEFAULT_SEAL_MOD_BITS",
    "DEFAULT_MOD", "DEFAULT_S_MOD", "DEFAULT_S_EXP",
    "DEFAULT_HMAX_PAD_SIZE", "utils6",
]
