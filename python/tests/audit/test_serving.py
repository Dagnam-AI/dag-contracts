"""Tests for dagnam_contracts/audit/serving.py — the two serving-rate formulas.

The numbers are hand-computed from the rate card so a rate edit fails here
rather than silently re-pricing every audit.
"""

from __future__ import annotations

import pytest

from dagnam_contracts.audit.serving import SERVING_RATES, serving_cost_usd_month


def test_rates_are_the_shipped_rate_card() -> None:
    assert SERVING_RATES["cpu-classifier"]["usd_per_1k_requests"] == 0.0023
    assert SERVING_RATES["gpu-small-llm"]["usd_per_m_output_tokens"] == 1.95


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
    assert cost == pytest.approx(266.7 * 30 * 3 / 1_000_000 * 1.95)
    assert cost == pytest.approx(0.04680585)
