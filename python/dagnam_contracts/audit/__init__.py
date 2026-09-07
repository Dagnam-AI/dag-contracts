"""Workload-audit contract: the scorers, the winner and verdict rules, the report shape.

Pure Python over the standard library, like ``hygiene``: the SDK scores a
holdout on the customer's machine and the platform scores one on a worker,
and both must reach the same number for the same rows.
"""

from __future__ import annotations

from dagnam_contracts.audit.scoring import (
    Z95,
    Agreement,
    modal_keys,
    normalize_label,
    score_json,
    score_labels,
    wilson_interval,
)

__all__ = [
    "Z95",
    "Agreement",
    "modal_keys",
    "normalize_label",
    "score_json",
    "score_labels",
    "wilson_interval",
]
