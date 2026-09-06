"""
Tests for dagnam_contracts/hygiene/contamination.py — cross-split overlap detection.

Covers:
- compute_split_overlap: no overlap on distinct content; identical content at
  different indices and different key order is detected; overlap count
  across three splits; the returned overlapping_pairs names which splits
  collided
- the mapping signature checks every unordered pair, not a hardcoded
  train/eval_holdout pair
"""

from __future__ import annotations

from dagnam_contracts.hygiene.contamination import ContaminationResult, compute_split_overlap


class TestComputeSplitOverlap:
    def test_no_overlap_on_distinct_content(self) -> None:
        splits = {
            "train": [{"a": 1}, {"a": 2}],
            "eval_holdout": [{"a": 3}, {"a": 4}],
        }
        result = compute_split_overlap(splits)
        assert isinstance(result, ContaminationResult)
        assert result.has_contamination is False
        assert result.overlapping_pairs == []

    def test_identical_content_different_index_and_key_order_detected(self) -> None:
        splits = {
            "train": [{"a": 1, "b": 2}, {"a": 9}],
            "eval_holdout": [{"a": 5}, {"b": 2, "a": 1}],
        }
        result = compute_split_overlap(splits)
        assert result.has_contamination is True
        assert len(result.overlapping_pairs) == 1
        pair = result.overlapping_pairs[0]
        assert {pair.split_a, pair.split_b} == {"train", "eval_holdout"}
        assert pair.overlap_count == 1

    def test_overlap_count_across_three_splits(self) -> None:
        shared_row = {"x": 1}
        splits = {
            "train": [shared_row, {"x": 2}],
            "eval_holdout": [shared_row],
            "test": [shared_row, {"x": 3}],
        }
        result = compute_split_overlap(splits)
        assert result.has_contamination is True
        pair_names = {frozenset((p.split_a, p.split_b)) for p in result.overlapping_pairs}
        assert pair_names == {
            frozenset({"train", "eval_holdout"}),
            frozenset({"train", "test"}),
            frozenset({"eval_holdout", "test"}),
        }

    def test_non_standard_split_names_are_still_checked(self) -> None:
        """Any split naming must be checked — not just train/eval_holdout.

        An earlier draft's two-argument signature hardcoded exactly that
        pair and failed open on anything else; the mapping form must not
        repeat that mistake.
        """
        shared_row = {"y": 1}
        splits = {
            "training": [shared_row],
            "holdout": [shared_row],
        }
        result = compute_split_overlap(splits)
        assert result.has_contamination is True
        pair = result.overlapping_pairs[0]
        assert {pair.split_a, pair.split_b} == {"training", "holdout"}

    def test_single_split_no_pairs(self) -> None:
        result = compute_split_overlap({"train": [{"a": 1}]})
        assert result.has_contamination is False
        assert result.overlapping_pairs == []

    def test_empty_splits_mapping(self) -> None:
        result = compute_split_overlap({})
        assert result.has_contamination is False
        assert result.overlapping_pairs == []
