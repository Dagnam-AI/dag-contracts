"""Tests for dagnam_contracts/audit/scoring.py — the shared agreement scorers.

The numbers here are the ones dag-lib's tests pinned before the move, so the
platform and the SDK score a holdout identically.
"""

from __future__ import annotations

import pytest

from dagnam_contracts.audit.scoring import (
    Z95,
    Agreement,
    modal_keys,
    normalize_label,
    score_json,
    score_labels,
    wilson_interval,
)


class TestWilson:
    def test_z95_is_the_two_sided_normal_quantile(self) -> None:
        """Pinned: every consumer's interval is only comparable if this literal is."""
        assert Z95 == 1.959963984540054

    def test_zero_n_is_the_unit_interval(self) -> None:
        assert wilson_interval(0, 0) == (0.0, 1.0)

    def test_all_hits_lower_bound_below_one(self) -> None:
        lo, hi = wilson_interval(396, 396)
        assert hi == 1.0
        assert 0.990 < lo < 0.991

    def test_bounds_clamped(self) -> None:
        lo, hi = wilson_interval(1, 1)
        assert 0.0 <= lo <= hi <= 1.0


class TestNormalizeLabel:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [("Billing.", "billing"), ("  cancel_order\n", "cancel_order"), ('"Refund"', "refund")],
    )
    def test_normalizes_case_punctuation_and_quotes(self, raw: str, expected: str) -> None:
        assert normalize_label(raw) == expected


class TestScoreLabels:
    def test_exact_with_macro_f1(self) -> None:
        agreement = score_labels(["a", "b", "a", "c"], ["a", "b", "b", "c"])
        assert agreement.metric == "exact"
        assert agreement.value == pytest.approx(0.75)
        assert agreement.n == 4
        assert agreement.exact == pytest.approx(0.75)
        assert agreement.macro_f1 is not None and 0.0 < agreement.macro_f1 < 1.0
        assert agreement.ci95[0] < 0.75 < agreement.ci95[1]

    def test_normalization_applies_to_both_sides(self) -> None:
        assert score_labels(["Billing."], ["billing"]).value == 1.0

    def test_a_class_only_ever_predicted_has_no_recall(self) -> None:
        """``b`` is never a truth, so its F1 is 0 and macro-F1 averages that in."""
        agreement = score_labels(["a", "b"], ["a", "a"])
        assert agreement.value == pytest.approx(0.5)
        assert agreement.macro_f1 == pytest.approx(1 / 3)

    def test_empty_is_zero(self) -> None:
        agreement = score_labels([], [])
        assert (agreement.value, agreement.n, agreement.macro_f1) == (0.0, 0, 0.0)

    def test_unpaired_lengths_raise(self) -> None:
        with pytest.raises(ValueError, match="2 predictions but 1 truths"):
            score_labels(["a", "b"], ["a"])

    def test_to_json_omits_absent_extras(self) -> None:
        js = score_labels(["a"], ["a"]).to_json()
        assert js == {
            "metric": "exact",
            "value": 1.0,
            "ci95": [wilson_interval(1, 1)[0], 1.0],
            "n": 1,
            "exact": 1.0,
            "macro_f1": 1.0,
        }


class TestScoreJson:
    def test_field_f1_micro_averaged(self) -> None:
        truth = ['{"a": 1, "b": "x"}', '{"a": 2, "b": "y"}']
        pred = ['{"a": 1, "b": "z"}', '{"a": 2}']
        keys = modal_keys(truth)
        assert keys == ["a", "b"]
        agreement = score_json(pred, truth, keys)
        assert agreement.metric == "field_f1"
        # tp=2 (a twice), fp=1 (b wrong), fn=2 (b wrong, b missing) -> f1 = 4/7
        assert agreement.value == pytest.approx(4 / 7)
        assert agreement.n == 2
        assert agreement.field_precision == pytest.approx(2 / 3)
        assert agreement.field_recall == pytest.approx(0.5)

    def test_non_object_predictions_count_as_no_fields(self) -> None:
        agreement = score_json(["not json", "[1]"], ['{"a": 1}', '{"a": 1}'], ["a"])
        assert agreement.value == 0.0

    def test_key_absent_from_truth_is_a_false_positive_only(self) -> None:
        agreement = score_json(['{"a": 1}'], ["{}"], ["a"])
        assert agreement.n == 1
        assert agreement.field_precision == 0.0
        assert agreement.field_recall == 0.0
        assert agreement.value == 0.0

    def test_modal_keys_empty_when_nothing_parses(self) -> None:
        assert modal_keys(["nope"]) == []


def test_agreement_is_frozen() -> None:
    agreement = Agreement(metric="exact", value=1.0, ci95=(1.0, 1.0), n=1)
    # Through `setattr`, so the assertion is the frozen dataclass's runtime refusal
    # rather than a type error the checker would have to be told to ignore.
    field = "value"
    with pytest.raises(AttributeError):
        setattr(agreement, field, 0.5)
