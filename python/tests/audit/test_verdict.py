"""Tests for dagnam_contracts/audit/verdict.py — the economics bands and the frontier rule."""

from __future__ import annotations

from dagnam_contracts.audit.verdict import (
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
