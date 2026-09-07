"""The report's derived blocks, computed from candidate dicts in the report's own shape."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from dagnam_contracts.audit.verdict import CandidateResult, frontier

REPORT_SCHEMA = "dagnam.audit.report/1"
DEFAULT_BASE_URL = "https://api.dagnam.ai/v1"
"""The OpenAI-compatible root a switched client points at."""


def _number(value: object) -> float | None:
    """``value`` as a float, or ``None`` when it is not a number — a JSON ``true`` is not 1.0."""
    return float(value) if isinstance(value, int | float) and not isinstance(value, bool) else None


def _sub(entry: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    """``entry[key]`` when it is an object; an empty one when it is absent or ``null``."""
    value = entry.get(key)
    return value if isinstance(value, Mapping) else {}


def winner_of(candidates: Sequence[Mapping[str, Any]], *, floor: float) -> dict[str, Any] | None:
    """The report's ``winner`` block over the candidate dicts, or ``None``.

    A candidate with no ``agreement`` or no priced ``serving_cost_usd_month`` is
    not a point on the frontier, so it is skipped -- on its numbers, never on a
    status word, which keeps the report's status vocabulary out of the contract.

    ``floor`` is the default; a candidate whose ``agreement`` records its own
    ``floor`` replaces it, so the run's own quality bar wins over the caller's.
    Like the CLI this is one running value rather than a per-candidate one: the
    last recorded floor is the bar every point is then held to.
    """
    points: list[CandidateResult] = []
    for c in candidates:
        agreement = _sub(c, "agreement")
        cost = _number(_sub(c, "serving_cost_usd_month").get("value"))
        if not agreement or cost is None:
            continue
        floor = float(agreement.get("floor", floor))
        ci = agreement.get("ci95")
        if not isinstance(ci, list) or len(ci) != 2:
            continue
        points.append(
            CandidateResult(
                str(c["kind"]),
                (float(ci[0]), float(ci[1])),
                cost,
                _number(_sub(c, "latency_ms").get("p95")),
            )
        )
    winner = frontier(points, floor=floor)
    if winner is None:
        return None
    chosen = next(c for c in candidates if str(c["kind"]) == winner.kind)
    return {
        "kind": winner.kind,
        "cost_usd_month": winner.cost_usd_month,
        "agreement_lo": winner.agreement_lo,
        "deployment_id": chosen.get("deployment_id"),
    }


def switch_block(
    winner: Mapping[str, Any] | None, key_ref: str | None, *, base_url: str
) -> dict[str, Any] | None:
    """The three values a stock client needs, or ``None`` without a winner."""
    if winner is None:
        return None
    return {"base_url": base_url, "model": winner.get("deployment_id"), "key_ref": key_ref}


def render_switch_snippet(
    deployment_id: str, key_ref: str, *, base_url: str = DEFAULT_BASE_URL
) -> str:
    """The stock OpenAI-client snippet that switches a workload; the key stays a ``key_ref``."""
    return "\n".join(
        [
            "from openai import OpenAI",
            "",
            "client = OpenAI(",
            f'    base_url="{base_url}",',
            (
                f"    api_key=DEPLOYMENT_KEY,  # key_ref {key_ref}: read it from your keyring"
                " or audit secrets.json; never paste it here"
            ),
            ")",
            f'client.chat.completions.create(model="{deployment_id}", messages=[...])',
        ]
    )


__all__ = [
    "DEFAULT_BASE_URL",
    "REPORT_SCHEMA",
    "render_switch_snippet",
    "switch_block",
    "winner_of",
]
