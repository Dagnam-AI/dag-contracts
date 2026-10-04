"""Tests for dagnam_contracts/audit/report.py — the report's derived blocks."""

from __future__ import annotations

import math
from typing import Any

import pytest

from dagnam_contracts.audit.report import (
    CANCELLED_SCHEMA,
    DEFAULT_BASE_URL,
    DELETED_SCHEMA,
    REPORT_SCHEMA,
    render_switch_snippet,
    switch_block,
    winner_of,
)
from dagnam_contracts.audit.scoring import score_labels

CANDIDATES: list[dict[str, Any]] = [
    {
        "kind": "head_tune",
        "status": "scored",
        "deployment_id": "dep-1",
        "candidate_id": "cand-1",
        "agreement": {"ci95": [0.99, 1.0]},
        "latency_ms": {"p95": 556.0},
        "serving_cost_usd_month": {"value": 12.0},
    },
    {
        "kind": "sft_small",
        "status": "scored",
        "deployment_id": "dep-2",
        "agreement": {"ci95": [0.90, 0.93]},
        "latency_ms": {"p95": 2800.0},
        "serving_cost_usd_month": {"value": 40.0},
    },
    {"kind": "hosted_floor", "status": "untested", "deployment_id": None},
]


def test_schema_and_base_url_are_the_shipped_values() -> None:
    assert REPORT_SCHEMA == "dagnam.audit.report/1"
    assert DEFAULT_BASE_URL == "https://api.dagnam.ai/v1"


def test_a_cancel_receipt_has_its_own_schema_id() -> None:
    """A cancel is not a delete: routing on the schema id must be enough to tell them apart."""
    assert DELETED_SCHEMA == "dagnam.audit.deleted/1"
    assert CANCELLED_SCHEMA == "dagnam.audit.cancelled/1"
    assert CANCELLED_SCHEMA != DELETED_SCHEMA


# The contract's `winner` block is the SDK's own, key for key -- four keys, no
# `p95_ms`, which a fifth key would have had to guess for a row with none. Since 0.3.1
# `candidate_id` joins them, so the block NAMES the winning row instead of leaving every
# reader to re-derive it by kind; the original four are unchanged.
def test_winner_of_reads_candidate_dicts() -> None:
    winner = winner_of(CANDIDATES, floor=0.95)
    assert winner == {
        "kind": "head_tune",
        "deployment_id": "dep-1",
        "candidate_id": "cand-1",
        "cost_usd_month": 12.0,
        "agreement_lo": 0.99,
    }


def test_winner_of_carries_an_explicitly_null_candidate_id_through() -> None:
    """A row that records `candidate_id: null` reads the same as one that omits it."""
    winner = winner_of([{**CANDIDATES[0], "candidate_id": None}], floor=0.95)
    assert winner is not None
    assert winner["candidate_id"] is None


def test_winner_of_ignores_unscored_and_returns_none() -> None:
    assert winner_of(CANDIDATES[1:], floor=0.95) is None


def test_switch_block_and_snippet() -> None:
    winner = winner_of(CANDIDATES, floor=0.95)
    block = switch_block(winner, "w1/head_tune", base_url=DEFAULT_BASE_URL)
    assert block == {"base_url": DEFAULT_BASE_URL, "model": "dep-1", "key_ref": "w1/head_tune"}
    snippet = render_switch_snippet("dep-1", "w1/head_tune")
    assert 'base_url="https://api.dagnam.ai/v1"' in snippet
    assert 'model="dep-1"' in snippet
    assert "key_ref w1/head_tune" in snippet
    assert switch_block(None, None, base_url=DEFAULT_BASE_URL) is None


def test_winner_of_skips_a_candidate_whose_numbers_are_unusable() -> None:
    """A candidate is skipped on its numbers -- no interval, or no price -- never on a status.

    The costed row is the one that would win on price, so a bug that let any of
    these through would change the answer, not just widen the field.
    """
    unusable: list[dict[str, Any]] = [
        {**CANDIDATES[0], "kind": "no_agreement", "agreement": None},
        {**CANDIDATES[0], "kind": "half_an_interval", "agreement": {"ci95": [0.99]}},
        {**CANDIDATES[0], "kind": "unpriced", "serving_cost_usd_month": {"value": None}},
        # A JSON `true` is not a price of $1.00.
        {**CANDIDATES[0], "kind": "boolean_cost", "serving_cost_usd_month": {"value": True}},
    ]
    assert winner_of(unusable, floor=0.95) is None
    assert winner_of([*unusable, CANDIDATES[1]], floor=0.90) == {
        "kind": "sft_small",
        "deployment_id": "dep-2",
        # `sft_small` carries no id -- the CLI's local candidates never do -- so
        # the key is present and null rather than absent.
        "candidate_id": None,
        "cost_usd_month": 40.0,
        "agreement_lo": 0.90,
    }


def test_winner_of_honours_a_candidates_recorded_floor() -> None:
    """A run that recorded its own floor is held to it, not to the caller's default.

    ``cheap`` clears the 0.95 keyword floor and is the cheaper of the two, so it
    wins outright once its recorded 0.999 floor is dropped -- which is what makes
    the first half a real test of the floor and not of the price.
    """
    strict: list[dict[str, Any]] = [
        {
            "kind": "dear",
            "deployment_id": "dep-dear",
            "agreement": {"ci95": [0.9995, 1.0]},
            "serving_cost_usd_month": {"value": 40.0},
        },
        {
            "kind": "cheap",
            "deployment_id": "dep-cheap",
            "agreement": {"ci95": [0.998, 0.999], "floor": 0.999},
            "serving_cost_usd_month": {"value": 5.0},
        },
    ]
    winner = winner_of(strict, floor=0.95)
    assert winner is not None
    assert (winner["kind"], winner["cost_usd_month"]) == ("dear", 40.0)

    lenient = [strict[0], {**strict[1], "agreement": {"ci95": [0.998, 0.999]}}]
    relaxed = winner_of(lenient, floor=0.95)
    assert relaxed is not None
    assert (relaxed["kind"], relaxed["cost_usd_month"]) == ("cheap", 5.0)


def _row(kind: str, lo: float, cost: float, **extra: Any) -> dict[str, Any]:
    """A scored candidate dict in the report's shape; ``floor`` goes on its agreement."""
    agreement: dict[str, Any] = {"ci95": [lo, 1.0]}
    if "floor" in extra:
        agreement["floor"] = extra.pop("floor")
    return {
        "kind": kind,
        "agreement": agreement,
        "serving_cost_usd_month": {"value": cost},
        **extra,
    }


def _both_orders(candidates: list[dict[str, Any]]) -> list[dict[str, Any] | None]:
    return [winner_of(order, floor=0.97) for order in (candidates, candidates[::-1])]


def test_an_unreliable_candidate_never_wins() -> None:
    """200 of 1,000 replay calls failed and the 800 that answered all agreed.

    Scored on the calls that answered, its lower bound (0.9952) clears 0.97 and
    it is the cheaper row -- so on its numbers it wins, and the switch would
    send a customer to an endpoint that failed one call in five. Its flag is the
    only thing that keeps it out: the same row unflagged still wins.
    """
    flaky = _row("head_tune", 0.995221123794324, 5.0, unreliable=True, deployment_id="dep-flaky")
    steady = _row("sft_small", 0.98, 40.0, unreliable=False, deployment_id="dep-steady")

    assert winner_of([flaky], floor=0.97) is None
    winner = winner_of([flaky, steady], floor=0.97)
    assert winner is not None and winner["deployment_id"] == "dep-steady"
    unflagged = winner_of([{**flaky, "unreliable": False}, steady], floor=0.97)
    assert unflagged is not None and unflagged["deployment_id"] == "dep-flaky"


def test_each_candidate_is_held_to_its_own_floor_whatever_the_order() -> None:
    """The floor used to be the LAST candidate's, so order picked the winner.

    ``[sft 0.955@0.95, head 0.96@0.97]`` gave no winner and the reverse gave
    ``head_tune``, which fails its own 0.97. Held to its own floor, ``sft_small``
    passes and ``head_tune`` does not, in either order.
    """
    rows = [
        _row("sft_small", 0.955, 10.0, floor=0.95, deployment_id="dep-sft"),
        _row("head_tune", 0.96, 5.0, floor=0.97, deployment_id="dep-head"),
    ]
    assert [w and w["kind"] for w in _both_orders(rows)] == ["sft_small", "sft_small"]


def test_the_winner_names_its_own_row_not_the_first_of_its_kind() -> None:
    """Two ``head_tune`` rows, the CLI's and a Studio retrain, at one price.

    The retrain's 0.99 wins; the block used to carry the CLI row's ids beside
    it, so the switch pointed at a model that did not earn the verdict.
    """
    rows = [
        _row("head_tune", 0.975, 5.0, deployment_id="dep-cli", candidate_id="cand-cli"),
        _row("head_tune", 0.99, 5.0, deployment_id="dep-web", candidate_id="cand-web"),
    ]
    for winner in _both_orders(rows):
        assert winner is not None
        assert (winner["agreement_lo"], winner["deployment_id"], winner["candidate_id"]) == (
            0.99,
            "dep-web",
            "cand-web",
        )


@pytest.mark.parametrize(
    ("cli", "retrain"),
    [
        # A JSON workload at the default floors: the CLI row clears its own 0.95;
        # the retrain was held to the header's 0.97 and is a hair cheaper.
        (
            _row("sft_small", 0.955, 2.4804, floor=0.95, candidate_id="cli"),
            _row("sft_small", 0.965, 2.457, floor=0.97, candidate_id="web"),
        ),
        # short_span: a retrain priced at the CPU rate, far below the floor.
        (
            _row("sft_small", 0.98, 351.0, floor=0.97, candidate_id="cli"),
            _row("sft_small", 0.90, 69.0, floor=0.97, candidate_id="web"),
        ),
        # Same floor, and the failing twin is one cent cheaper.
        (
            _row("head_tune", 0.99, 10.0, floor=0.97, candidate_id="cli"),
            _row("head_tune", 0.50, 9.99, floor=0.97, candidate_id="web"),
        ),
    ],
)
def test_a_failing_cheaper_twin_never_hides_a_passing_row(
    cli: dict[str, Any], retrain: dict[str, Any]
) -> None:
    """Every live row goes in, and the passing CLI row still wins.

    The platform used to keep one row per kind BEFORE any floor was applied,
    so the cheaper failing twin was kept and the workload read NOT YET.
    """
    for winner in _both_orders([cli, retrain]):
        assert winner is not None and winner["candidate_id"] == "cli"


def test_ties_break_on_certainty_then_on_the_ids() -> None:
    """Order-independent all the way down: equal price, then the higher lower bound,
    then ``candidate_id``, then ``kind``, then ``deployment_id``, all ascending."""
    surer = [_row("b", 0.98, 5.0, candidate_id="z"), _row("a", 0.99, 5.0, candidate_id="y")]
    assert [w and w["candidate_id"] for w in _both_orders(surer)] == ["y", "y"]

    by_id = [_row("a", 0.99, 5.0, candidate_id="z"), _row("b", 0.99, 5.0, candidate_id="y")]
    assert [w and w["candidate_id"] for w in _both_orders(by_id)] == ["y", "y"]

    # The CLI's local rows carry no id; the kind decides, then the deployment.
    by_kind = [_row("sft_small", 0.99, 5.0), _row("head_tune", 0.99, 5.0)]
    assert [w and w["kind"] for w in _both_orders(by_kind)] == ["head_tune", "head_tune"]
    by_dep = [
        _row("head_tune", 0.99, 5.0, deployment_id="dep-2"),
        _row("head_tune", 0.99, 5.0, deployment_id="dep-1"),
    ]
    assert [w and w["deployment_id"] for w in _both_orders(by_dep)] == ["dep-1", "dep-1"]


def test_a_null_recorded_floor_falls_back_and_a_non_numeric_bound_is_no_point() -> None:
    """``floor: null`` is no recorded floor, and a bound that is not a number is not a point."""
    assert winner_of([_row("a", 0.96, 5.0, floor=None)], floor=0.95) is not None
    assert winner_of([_row("a", 0.96, 5.0, floor=None)], floor=0.97) is None
    unbounded = {**_row("a", 0.99, 5.0), "agreement": {"ci95": [None, 1.0]}}
    assert winner_of([unbounded], floor=0.5) is None


@pytest.mark.parametrize(
    "broken",
    [
        _row("nan_lo", math.nan, 1.0),
        _row("inf_lo", math.inf, 1.0),
        _row("nan_floor", 0.10, 1.0, floor=math.nan),
        _row("text_floor", 0.99, 1.0, floor="high"),
        _row("nan_cost", 0.99, math.nan),
        _row("inf_cost", 0.99, math.inf),
    ],
    ids=lambda row: row["kind"],
)
def test_a_non_finite_number_is_never_a_point(broken: dict[str, Any]) -> None:
    """NaN passed `lo < floor` (every comparison with NaN is False) and won,
    and a NaN cost made the winner depend on the order of the list."""
    sound = _row("sound", 0.98, 50.0)
    assert winner_of([broken], floor=0.05) is None
    for winner in _both_orders([broken, sound]):
        assert winner is not None and winner["kind"] == "sound"


def test_a_negative_cost_is_never_a_point() -> None:
    """A cost below zero is a malformed row, and it would always be the cheapest:
    it used to win over every sound candidate. Free is still a price."""
    sound = _row("sound", 0.98, 50.0)
    refund = _row("refund", 0.99, -5.0)

    assert winner_of([refund], floor=0.05) is None
    for winner in _both_orders([refund, sound]):
        assert winner is not None and winner["kind"] == "sound"
    for winner in _both_orders([_row("free", 0.99, 0.0), sound]):
        assert winner is not None and winner["kind"] == "free"


def test_the_constant_majority_student_does_not_win() -> None:
    """End to end: the 1%-positive constant "ok" student's own agreement block
    clears the 0.97 floor on exact match, and it must still not be the winner."""
    truth = ["flag"] * 10 + ["ok"] * 990
    constant = score_labels(["ok"] * 1000, truth).to_json()
    detector = score_labels(["flag"] * 9 + ["ok"] * 991, truth).to_json()
    rows = [
        {
            "kind": "head_tune",
            "agreement": {**constant, "floor": 0.97},
            "serving_cost_usd_month": {"value": 1.0},
        },
        {
            "kind": "sft_small",
            "agreement": {**detector, "floor": 0.97},
            "serving_cost_usd_month": {"value": 9.0},
        },
    ]

    assert winner_of(rows[:1], floor=0.97) is None
    for winner in _both_orders(rows):
        assert winner is not None and winner["kind"] == "sft_small"


@pytest.mark.parametrize(
    ("min_class_recall", "wins"),
    [(None, True), (0.5, True), (0.49, False), (math.nan, False), ("high", False)],
)
def test_min_class_recall_gates_a_label_candidate(min_class_recall: object, wins: bool) -> None:
    row = _row("head_tune", 0.99, 5.0)
    row["agreement"]["min_class_recall"] = min_class_recall
    assert (winner_of([row], floor=0.97) is not None) is wins
