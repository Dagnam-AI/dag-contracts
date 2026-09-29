"""The report's derived blocks and the schema ids audit artifacts are stamped with.

The blocks are computed from candidate dicts in the report's own shape.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import math
from typing import Any

from dagnam_contracts.audit.verdict import MIN_CLASS_RECALL_FLOOR

REPORT_SCHEMA = "dagnam.audit.report/1"
DELETED_SCHEMA = "dagnam.audit.deleted/1"
"""The receipt a delete writes; unchanged, and never used for a cancel."""
CANCELLED_SCHEMA = "dagnam.audit.cancelled/1"
"""The receipt a cancel writes.

Cancelling and deleting are different events -- one stops a run and leaves its
artifacts, the other removes them -- and a reader that has to inspect a status
word to tell which receipt it is holding cannot route on the schema id, which
is the one field a schema id exists to make sufficient.
"""
DEFAULT_BASE_URL = "https://api.dagnam.ai/v1"
"""The OpenAI-compatible root a switched client points at."""


def _number(value: object) -> float | None:
    """``value`` as a finite float, else ``None`` — a JSON ``true`` is not 1.0, and a NaN
    compares False both ways, so it would pass a floor check and make ``min`` order-dependent."""
    if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value):
        return None
    return float(value)


def _sub(entry: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    """``entry[key]`` when it is an object; an empty one when it is absent or ``null``."""
    value = entry.get(key)
    return value if isinstance(value, Mapping) else {}


def _point(candidate: Mapping[str, Any], default_floor: float) -> tuple[float, float] | None:
    """``(cost, agreement lower bound)`` when ``candidate`` may win, else ``None``.

    It may win only when it is priced, has a finite lower bound that clears
    its OWN recorded ``agreement.floor`` (``default_floor`` when it recorded
    none), and is not flagged ``unreliable``. A recorded floor that is not a
    finite number is a malformed row, never a pass. A label candidate whose
    ``agreement.min_class_recall`` is below
    :data:`~dagnam_contracts.audit.verdict.MIN_CLASS_RECALL_FLOOR` -- it misses
    a whole class the exact-match score hides -- is refused the same way.
    """
    if candidate.get("unreliable"):
        return None
    agreement = _sub(candidate, "agreement")
    cost = _number(_sub(candidate, "serving_cost_usd_month").get("value"))
    ci = agreement.get("ci95")
    if cost is None or not isinstance(ci, list) or len(ci) != 2:
        return None
    lo = _number(ci[0])
    recorded = agreement.get("floor")
    own_floor = _number(recorded)
    if lo is None or (recorded is not None and own_floor is None):
        return None
    if not lo >= (default_floor if own_floor is None else own_floor):
        return None
    reported = agreement.get("min_class_recall")
    recall = _number(reported)
    if reported is not None and (recall is None or recall < MIN_CLASS_RECALL_FLOOR):
        return None
    return cost, lo


def _text(value: object) -> str:
    return "" if value is None else str(value)


def winner_of(candidates: Sequence[Mapping[str, Any]], *, floor: float) -> dict[str, Any] | None:
    """The report's ``winner`` block over the candidate dicts, or ``None``.

    A candidate with no ``agreement`` interval or no priced
    ``serving_cost_usd_month`` is not a point on the frontier, so it is
    skipped -- on its numbers, never on a status word, which keeps the report's
    status vocabulary out of the contract. So is one flagged ``unreliable``:
    more than :data:`~dagnam_contracts.audit.verdict.UNRELIABLE_ERROR_SHARE`
    of its replay calls failed, and its score covers only the calls that
    answered, so it never earns a switch however well those agreed.

    Each candidate is held to its own recorded ``agreement.floor``, falling
    back to ``floor`` -- a JSON candidate's 0.95 and a label candidate's 0.97
    can sit in one list. The cheapest passing point wins; ties go to the higher
    lower bound, then to ``candidate_id``, ``kind`` and ``deployment_id``
    ascending, so the answer never depends on the order of ``candidates``. The
    block carries the winning dict's OWN ids, so two rows of one kind (the
    CLI's and a Studio retrain) can never lend each other theirs.
    """
    eligible = [(point, c) for c in candidates if (point := _point(c, floor)) is not None]
    if not eligible:
        return None
    (cost, lo), chosen = min(
        eligible,
        key=lambda entry: (
            entry[0][0],
            -entry[0][1],
            _text(entry[1].get("candidate_id")),
            str(entry[1]["kind"]),
            _text(entry[1].get("deployment_id")),
        ),
    )
    return {
        "kind": str(chosen["kind"]),
        "cost_usd_month": cost,
        "agreement_lo": lo,
        "deployment_id": chosen.get("deployment_id"),
        "candidate_id": chosen.get("candidate_id"),
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
    "CANCELLED_SCHEMA",
    "DEFAULT_BASE_URL",
    "DELETED_SCHEMA",
    "REPORT_SCHEMA",
    "render_switch_snippet",
    "switch_block",
    "winner_of",
]
