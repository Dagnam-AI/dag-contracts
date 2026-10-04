"""Tests for dagnam_contracts/audit/scoring.py — the shared agreement scorers.

The numbers here are the ones dag-lib's tests pinned before the move, so the
platform and the SDK score a holdout identically.
"""

from __future__ import annotations

import json

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
            # A label block always carries it; null when no class has support.
            "min_class_recall": None,
        }

    def test_a_constant_majority_student_has_zero_minority_recall(self) -> None:
        """1% positives, and a student that always answers the majority.

        Exact match is 0.99 with a lower bound that clears the 0.97 floor; the
        minority class's recall is 0, which is what the frontier now refuses.
        """
        truth = ["flag"] * 10 + ["ok"] * 990
        agreement = score_labels(["ok"] * 1000, truth)

        assert agreement.value == pytest.approx(0.99)
        assert agreement.ci95[0] > 0.97
        assert agreement.min_class_recall == 0.0
        assert agreement.to_json()["min_class_recall"] == 0.0

    def test_min_class_recall_counts_only_classes_with_support(self) -> None:
        """``rare`` has 4 holdout rows, below MIN_CLASS_SUPPORT: its misses do not count."""
        truth = ["a"] * 10 + ["b"] * 6 + ["rare"] * 4
        pred = ["a"] * 10 + ["b"] * 3 + ["a"] * 3 + ["a"] * 4

        assert score_labels(pred, truth).min_class_recall == pytest.approx(0.5)
        assert score_labels(["a"] * 4, ["a"] * 4).min_class_recall is None


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

    def test_one_row_is_one_observation_however_many_fields_it_holds(self) -> None:
        """The interval counted every correct field as two independent trials.

        One row with one correct field came out at lo 0.342 against 0.207 for
        the same single observation scored as a label, and a row of ten correct
        fields at 0.839 -- a bound the JSON floor then decided on. ``n`` is the
        scored rows now, so the interval is the label one's for the same rows.
        """
        label_lo = wilson_interval(1, 1)
        one = score_json(['{"a": 1}'], ['{"a": 1}'], ["a"])
        ten_fields = {f"k{i}": i for i in range(10)}
        ten = score_json([json.dumps(ten_fields)], [json.dumps(ten_fields)], sorted(ten_fields))
        assert one.ci95 == ten.ci95 == label_lo

    def test_the_interval_is_wilson_around_the_micro_f1_over_the_rows(self) -> None:
        """p-hat is the unchanged micro-F1 (4/7) and n is the two rows, not 2tp+fp+fn = 7."""
        truth = ['{"a": 1, "b": "x"}', '{"a": 2, "b": "y"}']
        pred = ['{"a": 1, "b": "z"}', '{"a": 2}']
        agreement = score_json(pred, truth, ["a", "b"])
        assert agreement.value == pytest.approx(4 / 7)
        assert agreement.ci95 == pytest.approx((0.1204, 0.9285), abs=1e-4)
        assert agreement.ci95[0] < wilson_interval(4, 7)[0]

    def test_a_json_block_carries_no_min_class_recall(self) -> None:
        """Class recall is a label criterion; the JSON agreement block is unchanged."""
        js = score_json(['{"a": 1}'], ['{"a": 1}'], ["a"]).to_json()
        assert "min_class_recall" not in js
        assert js["metric"] == "field_f1"

    def test_no_rows_is_the_unit_interval(self) -> None:
        assert score_json([], [], ["a"]).ci95 == (0.0, 1.0)

    def test_a_prediction_nested_past_the_parser_is_a_miss_not_a_crash(self) -> None:
        """A student's output is untrusted: ``json.loads`` raises RecursionError on it."""
        deep = "[" * 100_000
        assert score_json([deep], ['{"a": 1}'], ["a"]).value == 0.0
        assert score_json([deep], [_dump(_call("f"))], []).value == 0.0


def _call(name: str, arguments: object = None) -> dict[str, object]:
    return {"arguments": {} if arguments is None else arguments, "name": name}


def _dump(value: object) -> str:
    return json.dumps(value, sort_keys=True)


class TestScoreToolCalls:
    """A truth that is a tool call is scored per row, name first."""

    def test_a_router_that_misroutes_7_percent_does_not_clear_the_json_floor(self) -> None:
        """Every call carries ``{}`` arguments, so field-F1 over ``name`` and
        ``arguments`` gave each misrouted row a free hit on the arguments:
        0.965 over 1,000 rows, lower bound 0.952, a pass at 0.95. Scored on the
        row, a misroute is a miss: 0.93, and it does not pass."""
        truth = [_dump(_call(f"route_{i % 5}")) for i in range(1000)]
        pred = [_dump(_call("wrong" if i < 70 else f"route_{i % 5}")) for i in range(1000)]

        agreement = score_json(pred, truth, modal_keys(truth))

        assert agreement.metric == "tool_call"
        assert agreement.value == pytest.approx(0.93)
        assert agreement.n == 1000
        assert agreement.ci95 == wilson_interval(930, 1000)
        assert agreement.ci95[0] < 0.95

    @pytest.mark.parametrize(
        ("pred", "truth", "score"),
        [
            # The right tool: its arguments' field-F1 (one of two fields right).
            (_call("f", {"a": 1, "b": 3}), _call("f", {"a": 1, "b": 2}), 0.5),
            (_call("f", {"b": 2, "a": 1}), _call("f", {"a": 1, "b": 2}), 1.0),
            # The wrong tool scores nothing, however well its arguments match.
            (_call("g", {"a": 1}), _call("f", {"a": 1}), 0.0),
            # Several calls are matched in order; a different count is a miss.
            ([_call("f"), _call("g", {"x": 1})], [_call("f"), _call("g", {"x": 1})], 1.0),
            ([_call("g", {"x": 1}), _call("f")], [_call("f"), _call("g", {"x": 1})], 0.0),
            ([_call("f")], [_call("f"), _call("g")], 0.0),
            # One call and a list of that one call are the same answer.
            ([_call("f")], _call("f"), 1.0),
            # Arguments the export kept as a string compare as one value.
            (_call("f", "raw text"), _call("f", "raw text"), 1.0),
            (_call("f", "raw text"), _call("f", "other"), 0.0),
            # Not a tool call at all.
            ({"answer": "f"}, _call("f"), 0.0),
            ([], [_call("f")], 0.0),
        ],
    )
    def test_one_row(self, pred: object, truth: object, score: float) -> None:
        agreement = score_json([_dump(pred)], [_dump(truth)], [])
        assert agreement.value == pytest.approx(score)

    def test_text_that_is_not_json_is_a_miss(self) -> None:
        assert score_json(["call f"], [_dump(_call("f"))], []).value == 0.0

    def test_a_plain_json_row_beside_tool_calls_scores_its_own_field_f1(self) -> None:
        """A workload that sometimes answers in text JSON: that row's F1 over the keys."""
        truth = [_dump(_call("f")), '{"a": 1, "b": 2}']
        pred = [_dump(_call("f")), '{"a": 1, "b": 9}']

        assert score_json(pred, truth, ["a", "b"]).value == pytest.approx((1.0 + 0.5) / 2)

    @pytest.mark.parametrize(
        ("pred", "truth", "score"),
        [
            # An agent that sometimes answers in text; the text is scored as text.
            ("Sure, it is done.", "Sure, it is done.", 1.0),
            ("sure, it is done", "Sure, it is done.", 1.0),
            ("It failed.", "Sure, it is done.", 0.0),
            # A JSON truth that is not a call is compared on its own fields,
            # not on the calls' modal `arguments`/`name` keys.
            ('{"answer": 1}', '{"answer": 1}', 1.0),
            ('{"answer": 2}', '{"answer": 1}', 0.0),
            ("42", "42", 1.0),
        ],
    )
    def test_a_row_that_is_not_a_call_is_scored_on_its_own_content(
        self, pred: str, truth: str, score: float
    ) -> None:
        call = _dump(_call("f"))
        agreement = score_json([call, pred], [call, truth], ["arguments", "name"])
        assert agreement.value == pytest.approx((1.0 + score) / 2)

    def test_a_truth_with_more_keys_than_a_call_is_plain_json(self) -> None:
        truth = [_dump({**_call("f"), "id": "c1"})]
        assert score_json(truth, truth, ["arguments", "id", "name"]).metric == "field_f1"


def test_agreement_is_frozen() -> None:
    agreement = Agreement(metric="exact", value=1.0, ci95=(1.0, 1.0), n=1)
    # Through `setattr`, so the assertion is the frozen dataclass's runtime refusal
    # rather than a type error the checker would have to be told to ignore.
    field = "value"
    with pytest.raises(AttributeError):
        setattr(agreement, field, 0.5)
