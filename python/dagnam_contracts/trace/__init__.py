"""Trace envelope contract: the one-line JSON record every Dagnam recorder writes and reader parses.

Pure Python over the standard library, like ``hygiene`` and ``audit``: the local recorder, the
upload path and the platform must agree on what a valid line is, so the rule lives here once.
"""

from __future__ import annotations

from dagnam_contracts.trace.envelope import (
    ENDPOINTS,
    ENVELOPE_VERSION,
    MAX_LINE_BYTES,
    NORM_VERSION,
    PROVIDERS,
    EnvelopeError,
    Norm,
    NormMessage,
    TraceEnvelope,
    UnsupportedEnvelopeVersion,
    encode_envelope,
    parse_envelope,
)

__all__ = [
    "ENDPOINTS",
    "ENVELOPE_VERSION",
    "MAX_LINE_BYTES",
    "NORM_VERSION",
    "PROVIDERS",
    "EnvelopeError",
    "Norm",
    "NormMessage",
    "TraceEnvelope",
    "UnsupportedEnvelopeVersion",
    "encode_envelope",
    "parse_envelope",
]
