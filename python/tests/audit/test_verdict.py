"""Tests for dagnam_contracts/audit/verdict.py — the economics bands and the frontier rule."""

from __future__ import annotations

import math
from pathlib import Path
import re

from dagnam_contracts import audit
from dagnam_contracts.audit import verdict
from dagnam_contracts.audit.verdict import (
    MIN_CLASS_RECALL_FLOOR,
    MIN_CLASS_SUPPORT,
    RATIO_CANDIDATE,
    RATIO_NOT_WORTH_IT,
    UNRELIABLE_ERROR_SHARE,
    CandidateResult,
    customer_verdict,
    frontier,
    ratio_status,
)


def test_ratio_status_bands() -> None:
    assert ratio_status(RATIO_NOT_WORTH_IT - 0.01) == "not_worth_it"
    assert ratio_status(RATIO_NOT_WORTH_IT) == "marginal"
    assert ratio_status(RATIO_CANDIDATE) == "candidate"


def test_customer_verdict_words() -> None:
    assert customer_verdict("candidate", winner=True) == "REPLACE"
    assert customer_verdict("marginal", winner=False) == "NOT YET"
    assert customer_verdict("not_worth_it", winner=False) == "KEEP"
    assert customer_verdict("not_audited", winner=True) == "KEEP"


def test_frontier_picks_cheapest_passing_then_more_certain() -> None:
    points = [
        CandidateResult("head_tune", (0.96, 0.99), 12.0, 400.0),
        CandidateResult("sft_small", (0.98, 0.99), 12.0, 2000.0),
        CandidateResult("hosted_floor", (0.99, 1.0), 900.0, None),
    ]
    winner = frontier(points, floor=0.95)
    assert winner is not None
    assert (winner.kind, winner.cost_usd_month, winner.agreement_lo) == ("sft_small", 12.0, 0.98)


def test_frontier_none_when_nothing_clears_the_floor() -> None:
    assert frontier([CandidateResult("head_tune", (0.90, 0.95), 1.0, None)], floor=0.95) is None


def test_unreliable_error_share_is_the_shipped_value() -> None:
    """Task 8 reads this from the contract; dag-lib steps_serve.py pinned 0.10."""
    assert UNRELIABLE_ERROR_SHARE == 0.10


def test_frontier_breaks_a_full_tie_on_kind_whatever_the_order() -> None:
    """Equal price and equal certainty used to go to whichever point came first."""
    points = [
        CandidateResult("sft_small", (0.98, 0.99), 12.0, None),
        CandidateResult("head_tune", (0.98, 0.99), 12.0, None),
    ]
    for order in (points, points[::-1]):
        winner = frontier(order, floor=0.95)
        assert winner is not None and winner.kind == "head_tune"


def test_unreliable_error_share_is_defined_once() -> None:
    """C5: the report, the SDK and the platform read one threshold; nothing restates it."""
    package = Path(verdict.__file__).resolve().parents[1]
    definitions = [
        path.relative_to(package).as_posix()
        for path in sorted(package.rglob("*.py"))
        if re.search(r"^UNRELIABLE_ERROR_SHARE\s*[:=]", path.read_text(), re.MULTILINE)
    ]
    assert definitions == ["audit/verdict.py"]
    assert audit.UNRELIABLE_ERROR_SHARE is verdict.UNRELIABLE_ERROR_SHARE


def test_frontier_never_picks_a_non_finite_point() -> None:
    """A NaN cost compared False both ways, so `min` kept whichever came first."""
    sound = CandidateResult("sound", (0.98, 0.99), 50.0, None)
    for broken in (
        CandidateResult("nan_cost", (0.99, 1.0), math.nan, None),
        CandidateResult("inf_cost", (0.99, 1.0), math.inf, None),
        CandidateResult("nan_lo", (math.nan, 1.0), 1.0, None),
    ):
        for order in ([broken, sound], [sound, broken]):
            winner = frontier(order, floor=0.95)
            assert winner is not None and winner.kind == "sound"


def test_frontier_refuses_a_point_that_misses_a_whole_class() -> None:
    """Q4: a label point needs min_class_recall >= 0.5 when it has one; None is no claim."""
    assert (MIN_CLASS_RECALL_FLOOR, MIN_CLASS_SUPPORT) == (0.5, 5)
    blind = CandidateResult("head_tune", (0.98, 1.0), 1.0, None, min_class_recall=0.0)
    nan = CandidateResult("nan", (0.98, 1.0), 1.0, None, min_class_recall=math.nan)
    fair = CandidateResult("sft_small", (0.98, 1.0), 9.0, None, min_class_recall=0.5)
    json_point = CandidateResult("json", (0.98, 1.0), 20.0, None)

    for order in ([blind, nan, fair, json_point], [json_point, fair, nan, blind]):
        winner = frontier(order, floor=0.95)
        assert winner is not None and winner.kind == "sft_small"
    only_json = frontier([blind, json_point], floor=0.95)
    assert only_json is not None and only_json.kind == "json"


def test_the_npm_package_ships_the_same_class_recall_constants() -> None:
    """B7: the Studio hand-copied the floor; the tarball now carries it, held equal here."""
    source = (Path(verdict.__file__).resolve().parents[3] / "npm" / "src" / "audit.ts").read_text()
    shipped = dict(re.findall(r"export const (MIN_CLASS_\w+) = ([\d.]+);", source))
    assert shipped == {
        "MIN_CLASS_RECALL_FLOOR": str(MIN_CLASS_RECALL_FLOOR),
        "MIN_CLASS_SUPPORT": str(MIN_CLASS_SUPPORT),
    }
