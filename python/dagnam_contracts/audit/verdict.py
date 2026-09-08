"""The economics bands, the frontier rule and the three customer words.

Copied from the SDK's ``thresholds``/``economics``/``frontier`` so the platform
derives the same winner and verdict from the same candidate numbers.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
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


@dataclass(frozen=True, slots=True)
class Winner:
    """The frontier's choice and the numbers it was chosen on."""

    kind: str
    cost_usd_month: float
    agreement_lo: float


def frontier(points: Sequence[CandidateResult], *, floor: float) -> Winner | None:
    """The cheapest point whose interval's lower bound clears ``floor``; ties to the more certain."""
    passing = [p for p in points if p.ci[0] >= floor]
    if not passing:
        return None
    best = min(passing, key=lambda p: (p.cost_usd_month, -p.ci[0]))
    return Winner(kind=best.kind, cost_usd_month=best.cost_usd_month, agreement_lo=best.ci[0])


__all__ = [
    "DAYS_PER_MONTH",
    "FLOOR_JSON",
    "FLOOR_LABEL",
    "MAINTENANCE_USD_MONTH",
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
