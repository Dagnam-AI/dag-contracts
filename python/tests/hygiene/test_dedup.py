"""
Tests for dagnam_contracts/hygiene/dedup.py — exact-duplicate detection.

Covers:
- canonical_row_hash: stable across key order, differs on content
- compute_exact_duplicates: reports only second-and-later occurrences,
  no-duplicate case
- property: idempotence (re-running on kept rows finds nothing further)
- property: no false merge (distinct content is never flagged)
"""

from __future__ import annotations

from hypothesis import given, settings as hypothesis_settings, strategies as st

from dagnam_contracts.hygiene.dedup import DedupResult, canonical_row_hash, compute_exact_duplicates


class TestCanonicalRowHash:
    def test_stable_across_key_order(self) -> None:
        row_a = {"a": 1, "b": 2}
        row_b = {"b": 2, "a": 1}
        assert canonical_row_hash(row_a) == canonical_row_hash(row_b)

    def test_differs_on_content(self) -> None:
        assert canonical_row_hash({"a": 1}) != canonical_row_hash({"a": 2})

    def test_returns_hex_digest(self) -> None:
        digest = canonical_row_hash({"a": 1})
        assert isinstance(digest, str)
        assert len(digest) == 64
        int(digest, 16)  # raises ValueError if not hex


class TestComputeExactDuplicates:
    def test_no_duplicates(self) -> None:
        rows = [{"a": 1}, {"a": 2}, {"a": 3}]
        result = compute_exact_duplicates(rows)
        assert isinstance(result, DedupResult)
        assert result.duplicate_indices == []
        assert result.duplicate_count == 0
        assert result.kept_count == 3

    def test_reports_second_and_later_occurrences_only(self) -> None:
        rows = [{"a": 1}, {"a": 1}, {"a": 2}, {"a": 1}]
        result = compute_exact_duplicates(rows)
        # index 0 is the kept first occurrence; 1 and 3 are duplicates.
        assert result.duplicate_indices == [1, 3]
        assert result.duplicate_count == 2
        assert result.kept_count == 2

    def test_key_order_does_not_prevent_duplicate_detection(self) -> None:
        rows = [{"a": 1, "b": 2}, {"b": 2, "a": 1}]
        result = compute_exact_duplicates(rows)
        assert result.duplicate_indices == [1]

    def test_empty_rows(self) -> None:
        result = compute_exact_duplicates([])
        assert result.duplicate_indices == []
        assert result.duplicate_count == 0
        assert result.kept_count == 0


# ---------------------------------------------------------------------------
# Property-based tests
# ---------------------------------------------------------------------------

_ROW_STRATEGY = st.dictionaries(
    keys=st.sampled_from(["a", "b", "c"]),
    values=st.one_of(st.integers(), st.text(max_size=10), st.booleans()),
    min_size=1,
    max_size=3,
)

_ROWS_STRATEGY = st.lists(_ROW_STRATEGY, min_size=0, max_size=25)


@given(rows=_ROWS_STRATEGY)
@hypothesis_settings(max_examples=100)
def test_dedup_is_idempotent(rows: list[dict[str, object]]) -> None:
    """Re-running dedup on the kept rows must find nothing further."""
    first = compute_exact_duplicates(rows)
    kept_rows = [row for index, row in enumerate(rows) if index not in set(first.duplicate_indices)]
    second = compute_exact_duplicates(kept_rows)
    assert second.duplicate_indices == []


@given(
    rows=st.lists(_ROW_STRATEGY, min_size=1, max_size=25, unique_by=lambda r: canonical_row_hash(r))
)
@hypothesis_settings(max_examples=100)
def test_dedup_no_false_merge_on_distinct_content(rows: list[dict[str, object]]) -> None:
    """Genuinely distinct content must never be flagged as a duplicate."""
    result = compute_exact_duplicates(rows)
    assert result.duplicate_indices == []
    assert result.kept_count == len(rows)
