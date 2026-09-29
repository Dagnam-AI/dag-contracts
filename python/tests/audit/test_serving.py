"""Tests for dagnam_contracts/audit/serving.py — the two serving-rate formulas.

The numbers are hand-computed from the rate card so a rate edit fails here
rather than silently re-pricing every audit.
"""

from __future__ import annotations

import pytest

from dagnam_contracts.audit.serving import (
    SERVING_RATES,
    load_serving_rates,
    serving_cost_usd_month,
)


def test_rates_are_the_shipped_rate_card() -> None:
    assert SERVING_RATES["cpu-classifier"]["usd_per_1k_requests"] == 0.0023
    assert SERVING_RATES["gpu-small-llm"]["usd_per_m_output_tokens"] == 4.08


def test_cpu_classifier_is_priced_per_thousand_requests() -> None:
    cost = serving_cost_usd_month(
        "cpu-classifier", calls_per_day=266.7, completion_tokens=300, calls=100
    )
    assert cost == pytest.approx(266.7 * 30 / 1_000 * 0.0023)
    assert cost == pytest.approx(0.0184023)


def test_gpu_small_llm_is_priced_per_million_output_tokens() -> None:
    cost = serving_cost_usd_month(
        "gpu-small-llm", calls_per_day=266.7, completion_tokens=300, calls=100
    )
    assert cost == pytest.approx(266.7 * 30 * 3 / 1_000_000 * 4.08)
    assert cost == pytest.approx(0.09793224)


def test_the_shipped_card_carries_the_rates_the_formulas_use() -> None:
    """The literal above is what prices an audit; the card is what a report and
    the Studio display. Two statements of one number drift, so this is the gate
    that says they cannot -- including the `estimated` basis, which is a claim
    about the numbers and not decoration."""
    card = load_serving_rates()
    assert card["basis"] == "estimated"
    for kind, rates in SERVING_RATES.items():
        row = card["rates"][kind]
        assert row["basis"] == "estimated"
        assert row["assumptions"]
        assert {k: v for k, v in row.items() if isinstance(v, int | float)} == rates


def test_the_gpu_rate_prices_the_machine_that_serves() -> None:
    """R2-6: the rate priced a T4 (g4dn.xlarge) while Modal serves on an A10G.

    Modal bills the A10 at $0.000306/s, $1.1016/h; the throughput and
    utilization assumptions are unchanged: 1.1016 / (300 * 3600 * 0.25) * 1e6.
    """
    row = load_serving_rates()["rates"]["gpu-small-llm"]
    assert "A10G" in row["assumptions"]
    assert "T4" not in row["assumptions"]
    assert 1.1016 / (300 * 3600 * 0.25) * 1e6 == pytest.approx(4.08, abs=0.005)
