"""
Tests for `dagnam_contracts/hygiene/near_dedup.py`.

The three properties the plan names, plus the ones that make them meaningful:
idempotence, no false merge below the threshold, and a decision at the
threshold that does not depend on set/dict iteration order.
"""

from __future__ import annotations

import random

from hypothesis import given, settings as hyp_settings, strategies as st
import pytest

from dagnam_contracts.hygiene.near_dedup import (
    _MASK64,
    DEFAULT_THRESHOLD,
    NUM_PERMUTATIONS,
    compute_near_duplicates,
    estimate_jaccard,
    minhash_signature,
    row_text,
    shingles,
)

_WORDS = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota"]


def _sentence(rng: random.Random, length: int = 20) -> str:
    return " ".join(rng.choice(_WORDS) for _ in range(length))


class TestRowText:
    def test_punctuation_case_and_whitespace_are_normalised(self) -> None:
        assert row_text({"a": "Hello,   WORLD!"}) == "hello world"

    def test_nested_strings_are_included_in_key_order(self) -> None:
        row = {"b": "second", "a": {"inner": "first"}, "c": ["third", "fourth"]}

        assert row_text(row) == "first second third fourth"

    def test_non_string_leaves_are_skipped(self) -> None:
        """A shared numeric label must not pull two unrelated rows together."""
        assert row_text({"text": "hello", "label": 3, "score": 0.5}) == "hello"


class TestShingles:
    def test_a_short_row_shingles_to_its_token_set(self) -> None:
        assert shingles("one two") == frozenset({"one", "two"})

    def test_an_empty_string_has_no_shingles(self) -> None:
        assert shingles("") == frozenset()


class TestSignatureDeterminism:
    def test_an_empty_shingle_set_is_the_all_mask_signature(self) -> None:
        signature = minhash_signature(frozenset())

        assert signature == (_MASK64,) * NUM_PERMUTATIONS

    def test_the_signature_does_not_depend_on_insertion_order(self) -> None:
        """A `hash()`-based signature would vary with PYTHONHASHSEED; this
        one must not, or the same dataset yields different duplicate sets in
        different worker processes."""
        left = minhash_signature(frozenset({"a b c", "d e f", "g h i"}))
        right = minhash_signature(frozenset({"g h i", "a b c", "d e f"}))

        assert left == right

    def test_identical_shingle_sets_estimate_jaccard_one(self) -> None:
        signature = minhash_signature(shingles("the quick brown fox jumps over"))

        assert estimate_jaccard(signature, signature) == 1.0


class TestNearDuplicateDetection:
    def test_a_punctuation_only_difference_is_a_near_duplicate(self) -> None:
        rows = [
            {"instruction": "Translate the following sentence into French"},
            {"instruction": "Translate the following sentence into French!"},
        ]

        result = compute_near_duplicates(rows, 0.9)

        assert result.duplicate_indices == [1]
        assert result.kept_count == 1
        assert result.pairs[0].kept_index == 0

    def test_unrelated_rows_are_never_merged(self) -> None:
        rng = random.Random(11)
        rows = [{"text": _sentence(rng)} for _ in range(60)]

        result = compute_near_duplicates(rows, DEFAULT_THRESHOLD)

        assert result.duplicate_count == 0
        assert result.kept_count == 60

    def test_the_first_occurrence_of_a_cluster_is_always_kept(self) -> None:
        rows = [{"t": "same words repeated here exactly"}] * 4

        result = compute_near_duplicates(rows, 0.9)

        assert result.duplicate_indices == [1, 2, 3]

    def test_an_empty_dataset_is_handled(self) -> None:
        result = compute_near_duplicates([], 0.9)

        assert result.duplicate_count == 0
        assert result.kept_count == 0

    @pytest.mark.parametrize("threshold", [0, -0.1, 1.5])
    def test_a_threshold_outside_the_open_unit_interval_is_refused(self, threshold: float) -> None:
        with pytest.raises(ValueError, match="threshold"):
            compute_near_duplicates([{"t": "x"}], threshold)


class TestProperties:
    @hyp_settings(max_examples=25, deadline=None)
    @given(
        seed=st.integers(min_value=0, max_value=10_000),
        threshold=st.floats(min_value=0.4, max_value=1.0),
    )
    def test_idempotence(self, seed: int, threshold: float) -> None:
        """Re-running over the kept rows finds nothing further.

        Only true because the LOWEST index of a cluster is the survivor; an
        implementation that kept an arbitrary member would leave pairs behind.
        """
        rng = random.Random(seed)
        rows: list[dict[str, object]] = []
        for _ in range(12):
            base = _sentence(rng, 10)
            rows.append({"t": base})
            if rng.random() < 0.4:
                rows.append({"t": base + "!"})

        first = compute_near_duplicates(rows, threshold)
        kept = [row for i, row in enumerate(rows) if i not in set(first.duplicate_indices)]

        assert compute_near_duplicates(kept, threshold).duplicate_count == 0

    @hyp_settings(max_examples=25, deadline=None)
    @given(seed=st.integers(min_value=0, max_value=10_000))
    def test_no_reported_pair_falls_below_the_threshold(self, seed: int) -> None:
        """The LSH band can cost recall; it can never cause a false merge."""
        rng = random.Random(seed)
        threshold = 0.75
        rows = [{"t": _sentence(rng, rng.randint(4, 15))} for _ in range(15)]

        result = compute_near_duplicates(rows, threshold)

        signatures = [minhash_signature(shingles(row_text(row))) for row in rows]
        for pair in result.pairs:
            assert (
                estimate_jaccard(signatures[pair.kept_index], signatures[pair.duplicate_index])
                >= threshold
            )
            assert pair.kept_index < pair.duplicate_index

    @hyp_settings(max_examples=15, deadline=None)
    @given(seed=st.integers(min_value=0, max_value=10_000))
    def test_the_result_is_identical_across_repeated_runs(self, seed: int) -> None:
        """A pair sitting exactly on the threshold must be decided the same
        way every time — not by whichever candidate the set yielded first."""
        rng = random.Random(seed)
        base = _sentence(rng, 12)
        rows = [{"t": base}, {"t": base + " tail"}, {"t": base.replace("alpha", "omega")}]

        runs = [compute_near_duplicates(rows, 0.5) for _ in range(5)]

        assert all(run.duplicate_indices == runs[0].duplicate_indices for run in runs)
        assert all(
            [(p.kept_index, p.duplicate_index) for p in run.pairs]
            == [(p.kept_index, p.duplicate_index) for p in runs[0].pairs]
            for run in runs
        )
