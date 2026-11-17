"""The memory of near-duplicate detection, and the candidate pairs it is built on.

`compute_near_duplicates` used to put every pair of rows that share an LSH band in a set,
sort the set, and then hold the verified pairs: with n identical texts that is three
copies of n * (n - 1) / 2 pairs, about 1 GB for 3,000 of them. The candidates are now
streamed in sorted order from a pointer per row and band, so what is held beside the
signatures is linear in the rows; the verified pairs are the result, listed in full, and
are the only part that grows with the square of the identical texts (`MAX_PAIRS` bounds
it). The peak is measured with `tracemalloc`.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from itertools import combinations
import random
import tracemalloc

import pytest

from dagnam_contracts.hygiene import _backend
from dagnam_contracts.hygiene.near_dedup import (
    BANDS,
    NUM_PERMUTATIONS,
    _candidate_pairs,
    compute_near_duplicates,
    minhash_signature,
    shingles,
)


@pytest.fixture(autouse=True, scope="module")
def _python_reference() -> Iterator[None]:
    with _backend.reference():
        yield


def _old_candidates(signatures: list[tuple[int, ...]]) -> list[tuple[int, int]]:
    """The set of pairs that sharing a band proposes, sorted: what `_candidate_pairs` was."""
    rows_per_band = NUM_PERMUTATIONS // BANDS
    candidates: set[tuple[int, int]] = set()
    for band in range(BANDS):
        start = band * rows_per_band
        buckets: dict[tuple[int, ...], list[int]] = {}
        for index, signature in enumerate(signatures):
            buckets.setdefault(signature[start : start + rows_per_band], []).append(index)
        for members in buckets.values():
            if len(members) > 1:
                candidates.update(combinations(members, 2))
    return sorted(candidates)


def _signatures(seed: int, count: int) -> list[tuple[int, ...]]:
    """Signatures that share some bands and not others: a few bases, each copied with a
    few of its 32 bands replaced, and some rows of their own."""
    generator = random.Random(seed)
    bases = [
        minhash_signature(shingles(" ".join(f"w{generator.randrange(60)}" for _ in range(9))))
        for _ in range(5)
    ]
    out: list[tuple[int, ...]] = []
    for _ in range(count):
        values = list(generator.choice(bases))
        for _ in range(generator.randint(0, 40)):
            values[generator.randrange(NUM_PERMUTATIONS)] = generator.randrange(1 << 61)
        out.append(tuple(values))
    return out


class TestTheCandidatePairs:
    @pytest.mark.parametrize("seed", range(6))
    def test_they_are_the_sorted_pairs_that_share_a_band(self, seed: int) -> None:
        signatures = _signatures(seed, 70)

        assert list(_candidate_pairs(signatures)) == _old_candidates(signatures)

    def test_a_row_alone_in_every_band_has_none(self) -> None:
        signatures = [tuple(range(row, row + NUM_PERMUTATIONS)) for row in range(0, 1000, 500)]

        assert list(_candidate_pairs(signatures)) == []

    def test_nothing_is_a_pair_of_a_row_with_itself_or_an_earlier_one(self) -> None:
        signatures = _signatures(7, 40)

        assert all(left < right for left, right in _candidate_pairs(signatures))

    def test_no_rows_no_pairs(self) -> None:
        assert list(_candidate_pairs([])) == []


def _peak(work: Callable[[], int]) -> int:
    tracemalloc.start()
    try:
        work()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("shape", ["identical", "in two groups"])
def test_four_times_the_identical_rows_take_about_four_times_the_candidate_memory(
    shape: str,
) -> None:
    """Counting the candidates of n identical signatures: n * (n - 1) / 2 pairs, and a peak
    that grows with n. A set of the pairs grows sixteen times for four times the rows."""
    signature = minhash_signature(shingles("the same words in every single row here"))
    other = minhash_signature(shingles("another set of words repeated over and over"))

    def consume(count: int) -> int:
        rows = [signature if shape == "identical" or i % 2 else other for i in range(count)]
        return sum(1 for _ in _candidate_pairs(rows))

    small = _peak(lambda: consume(800))
    large = _peak(lambda: consume(3200))

    assert large <= 5.5 * small


class TestTheResultIsTheOnlyQuadraticPart:
    def test_identical_rows_hold_little_beyond_the_pairs_they_return(self) -> None:
        """300 identical rows: 44,850 pairs. What the peak holds beyond the result is linear
        in the rows (their signatures, a pointer per band) and not in the pairs: it was a set
        and a sorted list of all the pairs, 5 MB here. A pair costs a list slot and its
        object, and nothing else: the floats are shared."""
        rows = [{"t": "the same words in every single row here"}] * 300
        tracemalloc.start()
        try:
            result = compute_near_duplicates(rows)
            retained, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        assert len(result.pairs) == 300 * 299 // 2
        assert retained / len(result.pairs) <= 72
        assert peak - retained <= 9_000 * len(rows)
        assert len({id(pair.similarity) for pair in result.pairs}) == 1

    def test_the_pairs_are_the_same_as_ever_in_the_same_order(self) -> None:
        rows = [{"t": "same words repeated here exactly"}] * 4

        result = compute_near_duplicates(rows)

        assert [(p.kept_index, p.duplicate_index, p.similarity) for p in result.pairs] == [
            (0, 1, 1.0),
            (0, 2, 1.0),
            (0, 3, 1.0),
            (1, 2, 1.0),
            (1, 3, 1.0),
            (2, 3, 1.0),
        ]
        assert result.duplicate_indices == [1, 2, 3]
