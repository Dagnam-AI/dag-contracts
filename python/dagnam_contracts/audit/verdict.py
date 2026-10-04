"""The economics bands, the frontier rule and the three customer words.

Copied from the SDK's ``thresholds``/``economics``/``frontier`` so the platform
derives the same winner and verdict from the same candidate numbers.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
import math
from typing import Literal

RATIO_NOT_WORTH_IT = 3.0
"""Teacher $/month over (student $/month + maintenance) below this is ``not_worth_it``."""
RATIO_CANDIDATE = 10.0
"""At or above this the workload is a ``candidate``; between the two ratios, ``marginal``."""
MAINTENANCE_USD_MONTH = 50.0
"""Per replaced workload, added to the student's monthly cost."""
FLOOR_LABEL = 0.97
"""Quality floor on the agreement lower bound for label workloads."""
FLOOR_JSON = 0.95
"""Quality floor on the agreement lower bound for JSON workloads."""
MIN_TRACES_PER_WORKLOAD = 1_000
"""Below this a workload is ``too_few_samples`` (still reported)."""
MIN_HOLDOUT = 200
"""Below this after the split a workload is ``too_few_samples``."""
DAYS_PER_MONTH = 30
"""Monthly figures are per-day rates times this."""
UNRELIABLE_ERROR_SHARE = 0.10
"""A replay whose error share exceeds this is scored as unreliable."""
MIN_CLASS_RECALL_FLOOR = 0.5
"""A label candidate must recall at least this share of every class with support.

Exact match alone passes a student that never predicts a rare class: on a
1%-positive holdout, always answering the majority scores 0.99 with a lower
bound above the 0.97 floor. This is the second criterion that refuses it.
"""
MIN_CLASS_SUPPORT = 5
"""A class needs this many holdout rows before its recall counts toward the floor."""

VerdictStatus = Literal[
    "candidate", "marginal", "not_worth_it", "not_audited", "too_few_samples", "unknown_cost"
]
CustomerVerdict = Literal["REPLACE", "NOT YET", "KEEP"]
_AUDITED: frozenset[str] = frozenset({"candidate", "marginal"})


def ratio_status(ratio: float) -> VerdictStatus:
    """``not_worth_it`` below 3, ``candidate`` at or above 10, ``marginal`` between."""
    if ratio < RATIO_NOT_WORTH_IT:
        return "not_worth_it"
    if ratio < RATIO_CANDIDATE:
        return "marginal"
    return "candidate"


def customer_verdict(status: VerdictStatus, *, winner: bool) -> CustomerVerdict:
    """The three words the customer reads."""
    if status not in _AUDITED:
        return "KEEP"
    return "REPLACE" if winner else "NOT YET"


@dataclass(frozen=True, slots=True)
class CandidateResult:
    """One scored point on the frontier: its interval, monthly cost and tail latency."""

    kind: str
    ci: tuple[float, float]
    cost_usd_month: float
    p95_ms: float | None
    min_class_recall: float | None = None
    """A label score's worst per-class recall; ``None`` for JSON, or when no class has support."""


@dataclass(frozen=True, slots=True)
class Winner:
    """The frontier's choice and the numbers it was chosen on."""

    kind: str
    cost_usd_month: float
    agreement_lo: float


def frontier(points: Sequence[CandidateResult], *, floor: float) -> Winner | None:
    """The cheapest point whose interval's lower bound clears ``floor``.

    Ties go to the more certain point, then to ``kind`` ascending, so the choice
    never depends on the order of ``points``; a point whose cost or lower bound
    is not finite, or whose cost is negative, is never chosen, nor one whose
    ``min_class_recall`` is below :data:`MIN_CLASS_RECALL_FLOOR`. This is the bare rule over bare points, one
    floor for all of them. A report's winner is
    :func:`~dagnam_contracts.audit.report.winner_of`, which also holds each
    candidate to its own floor, skips unreliable ones and breaks ties on the
    candidate's ids.
    """
    passing = [
        p
        for p in points
        if math.isfinite(p.cost_usd_month)
        and p.cost_usd_month >= 0
        and math.isfinite(p.ci[0])
        and p.ci[0] >= floor
        and (p.min_class_recall is None or p.min_class_recall >= MIN_CLASS_RECALL_FLOOR)
    ]
    if not passing:
        return None
    best = min(passing, key=lambda p: (p.cost_usd_month, -p.ci[0], p.kind))
    return Winner(kind=best.kind, cost_usd_month=best.cost_usd_month, agreement_lo=best.ci[0])


__all__ = [
    "DAYS_PER_MONTH",
    "FLOOR_JSON",
    "FLOOR_LABEL",
    "MAINTENANCE_USD_MONTH",
    "MIN_CLASS_RECALL_FLOOR",
    "MIN_CLASS_SUPPORT",
    "MIN_HOLDOUT",
    "MIN_TRACES_PER_WORKLOAD",
    "RATIO_CANDIDATE",
    "RATIO_NOT_WORTH_IT",
    "UNRELIABLE_ERROR_SHARE",
    "CandidateResult",
    "CustomerVerdict",
    "VerdictStatus",
    "Winner",
    "customer_verdict",
    "frontier",
    "ratio_status",
]
