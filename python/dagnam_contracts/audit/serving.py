"""What a student costs to serve, at the platform's rate card.

The rates are ``basis: "estimated"`` and stay labelled that way in every report
until billing exists; measured latency is reported beside them. They come from
the deployment cost planner's instance-hour prices, as
``hourly_rate / (throughput_per_second * 3600 * utilization) * unit``:

- ``cpu-classifier``: a t3.medium at $0.0416/h serving a small encoder
  classifier at 20 requests/s sustained with 25% average utilization —
  ``0.0416 / (20 * 3600 * 0.25) * 1000 = 0.00231`` USD per 1k requests.
- ``gpu-small-llm``: a g4dn.xlarge (one T4) at $0.526/h serving a
  <=3B-parameter model at 300 output tokens/s aggregate with batching and 25%
  average utilization — ``0.526 / (300 * 3600 * 0.25) * 1e6 = 1.948`` USD per
  million output tokens.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal

from dagnam_contracts.audit.verdict import DAYS_PER_MONTH

StudentKind = Literal["cpu-classifier", "gpu-small-llm"]

SERVING_RATES: Mapping[StudentKind, Mapping[str, float]] = {
    "cpu-classifier": {"usd_per_1k_requests": 0.0023},
    "gpu-small-llm": {"usd_per_m_output_tokens": 1.95},
}
"""The two student kinds' estimated rates; the assumptions behind them are this module's docstring."""


def serving_cost_usd_month(
    kind: StudentKind, *, calls_per_day: float, completion_tokens: int, calls: int
) -> float:
    """Monthly serving cost of a student at this volume, from :data:`SERVING_RATES`."""
    calls_month = calls_per_day * DAYS_PER_MONTH
    if kind == "cpu-classifier":
        return calls_month / 1_000 * SERVING_RATES[kind]["usd_per_1k_requests"]
    output_tokens_month = calls_month * completion_tokens / calls
    return output_tokens_month / 1_000_000 * SERVING_RATES[kind]["usd_per_m_output_tokens"]


__all__ = ["SERVING_RATES", "StudentKind", "serving_cost_usd_month"]
