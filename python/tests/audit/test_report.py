"""Tests for dagnam_contracts/audit/report.py — the report's derived blocks."""

from __future__ import annotations

from typing import Any

from dagnam_contracts.audit.report import (
    DEFAULT_BASE_URL,
    REPORT_SCHEMA,
    render_switch_snippet,
    switch_block,
    winner_of,
)

CANDIDATES: list[dict[str, Any]] = [
    {
        "kind": "head_tune",
        "status": "scored",
        "deployment_id": "dep-1",
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


def test_winner_of_reads_candidate_dicts() -> None:
    winner = winner_of(CANDIDATES, floor=0.95)
    assert winner == {
        "kind": "head_tune",
        "deployment_id": "dep-1",
        "cost_usd_month": 12.0,
        "agreement_lo": 0.99,
        "p95_ms": 556.0,
    }


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


def test_winner_of_skips_a_scored_candidate_whose_numbers_are_unusable() -> None:
    """``scored`` is not enough: a missing interval or an unpriced candidate cannot be ranked.

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
        "cost_usd_month": 40.0,
        "agreement_lo": 0.90,
        "p95_ms": 2800.0,
    }
