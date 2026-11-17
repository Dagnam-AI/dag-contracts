"""What `compute_near_duplicates` refuses before it spends memory or time on it.

The limits that the rows themselves answer (`MAX_TEXTS`, the characters of a row's string
values, and of all of them) are read on the rows as they were sent: a row of a hundred
megabytes is refused having cost nothing, not after the copies that normalising it makes,
and a compiled core is not called for a batch the wrapper can already refuse. The limit
that the walk answers (`MAX_COMPARISONS`, one for each candidate pair compared) stops it
before the comparison that would pass it, so a port counting the same way stops at the
same one.
"""

from __future__ import annotations

from collections.abc import Iterator
import tracemalloc
from types import SimpleNamespace
from typing import Any

import pytest

from dagnam_contracts.hygiene import _backend, near_dedup
from dagnam_contracts.hygiene.near_dedup import NearDedupLimitError, compute_near_duplicates

_PLANTED = "zebra-quokka-4417"


@pytest.fixture(autouse=True, scope="module")
def _python_reference() -> Iterator[None]:
    with _backend.reference():
        yield


def _rows(*texts: str) -> list[dict[str, Any]]:
    return [{"t": text} for text in texts]


def _fail(*_: object) -> None:
    raise AssertionError("work was done on a batch that is over a limit")


def _over_the_cheap_limits(monkeypatch: pytest.MonkeyPatch, which: str) -> list[dict[str, Any]]:
    """A batch over one of the limits the rows answer, with that limit lowered to fit it."""
    if which == "rows":
        monkeypatch.setattr(near_dedup, "MAX_TEXTS", 2)
        return _rows("a", "b", "c")
    if which == "row":
        monkeypatch.setattr(near_dedup, "MAX_TEXT_CHARS", 4)
        return _rows("a", "abcde")
    monkeypatch.setattr(near_dedup, "MAX_TOTAL_CHARS", 8)
    return _rows("abcde", "fghij")


@pytest.mark.parametrize("which", ["rows", "row", "total"])
class TestTheCheapLimitsComeBeforeAnyWork:
    def test_nothing_is_normalised(self, monkeypatch: pytest.MonkeyPatch, which: str) -> None:
        rows = _over_the_cheap_limits(monkeypatch, which)
        monkeypatch.setattr(near_dedup, "row_text", _fail)

        with pytest.raises(NearDedupLimitError):
            compute_near_duplicates(rows)

    def test_the_compiled_core_is_not_called(
        self, monkeypatch: pytest.MonkeyPatch, which: str
    ) -> None:
        """A fake core that fails the test if it is called: the wrapper refuses first."""
        rows = _over_the_cheap_limits(monkeypatch, which)
        monkeypatch.setattr(_backend, "active", lambda: SimpleNamespace(near_duplicates=_fail))

        with pytest.raises(NearDedupLimitError):
            compute_near_duplicates(rows)


def test_a_row_of_many_millions_of_characters_is_refused_at_no_cost() -> None:
    """Nothing is allocated in proportion to the row's words: 21 million characters of 7
    million words are refused for a few kilobytes, where normalising them held about 20
    times the row."""
    row = {"t": "ab " * 7_000_000}
    tracemalloc.start()
    try:
        with pytest.raises(NearDedupLimitError, match="MAX_TEXT_CHARS"):
            compute_near_duplicates([row])
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()

    assert peak < 50_000


class TestTheLimitsReadAgainOnTheNormalisedText:
    """Casefolding lengthens some characters (`ß` is `ss`), so a row inside the limits as
    written can be over them as compared; the second read refuses it before it is shingled."""

    def test_a_text_that_grows_past_the_row_limit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(near_dedup, "MAX_TEXT_CHARS", 10)
        monkeypatch.setattr(near_dedup, "shingles", _fail)

        with pytest.raises(NearDedupLimitError, match=r"12 characters .* MAX_TEXT_CHARS \(10\)"):
            compute_near_duplicates(_rows("ß" * 6))

    def test_texts_that_grow_past_the_total(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(near_dedup, "MAX_TOTAL_CHARS", 20)
        monkeypatch.setattr(near_dedup, "shingles", _fail)

        with pytest.raises(NearDedupLimitError, match=r"MAX_TOTAL_CHARS \(20\)"):
            compute_near_duplicates(_rows("ß" * 6, "ß" * 6))


@pytest.mark.parametrize(
    "rows",
    [_rows(_PLANTED * 3, "b"), _rows("a", _PLANTED, _PLANTED), [{"a": [_PLANTED, "x"]}] * 2],
)
def test_no_message_holds_a_word_of_the_rows(
    monkeypatch: pytest.MonkeyPatch, rows: list[dict[str, Any]]
) -> None:
    monkeypatch.setattr(near_dedup, "MAX_TEXT_CHARS", 20)
    monkeypatch.setattr(near_dedup, "MAX_TOTAL_CHARS", 30)

    with pytest.raises(NearDedupLimitError) as raised:
        compute_near_duplicates(rows)
    assert "zebra" not in str(raised.value) and "quokka" not in str(raised.value)


class TestTheComparisons:
    @staticmethod
    def _counting(monkeypatch: pytest.MonkeyPatch) -> list[tuple[int, int]]:
        """Replace the candidates with five pairs of rows that are not duplicates, and
        record the comparisons that are made."""
        pairs = [(0, 1), (0, 2), (1, 2), (0, 3), (2, 3)]
        compared: list[tuple[int, int]] = []
        estimate = near_dedup.estimate_jaccard
        order = iter(pairs)

        def counting(left: tuple[int, ...], right: tuple[int, ...]) -> float:
            compared.append(next(order))
            return estimate(left, right)

        monkeypatch.setattr(near_dedup, "_candidate_pairs", lambda _signatures: iter(pairs))
        monkeypatch.setattr(near_dedup, "estimate_jaccard", counting)
        return compared

    @staticmethod
    def _four_different_rows() -> list[dict[str, Any]]:
        return _rows(
            *(f"{word} one two three four" for word in ("alpha", "beta", "gamma", "delta"))
        )

    def test_every_candidate_pair_is_one_whether_or_not_it_is_a_duplicate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        compared = self._counting(monkeypatch)
        monkeypatch.setattr(near_dedup, "MAX_COMPARISONS", 5)

        result = compute_near_duplicates(self._four_different_rows())

        assert len(compared) == 5 and result.pairs == []

    def test_the_comparison_past_the_limit_is_not_made(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        compared = self._counting(monkeypatch)
        monkeypatch.setattr(near_dedup, "MAX_COMPARISONS", 4)

        with pytest.raises(NearDedupLimitError, match=r"MAX_COMPARISONS \(4\)"):
            compute_near_duplicates(self._four_different_rows())
        assert compared == [(0, 1), (0, 2), (1, 2), (0, 3)]

    def test_identical_rows_are_stopped_by_whichever_limit_comes_first(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Every candidate pair of identical rows is a pair: five rows have ten of each."""
        rows = _rows(*["same words here"] * 5)
        monkeypatch.setattr(near_dedup, "MAX_COMPARISONS", 10)
        monkeypatch.setattr(near_dedup, "MAX_PAIRS", 10)
        assert len(compute_near_duplicates(rows).pairs) == 10

        monkeypatch.setattr(near_dedup, "MAX_COMPARISONS", 9)
        with pytest.raises(NearDedupLimitError, match="MAX_COMPARISONS"):
            compute_near_duplicates(rows)

        monkeypatch.setattr(near_dedup, "MAX_COMPARISONS", 10)
        monkeypatch.setattr(near_dedup, "MAX_PAIRS", 9)
        with pytest.raises(NearDedupLimitError, match="MAX_PAIRS"):
            compute_near_duplicates(rows)

    def test_the_message_names_the_limit_and_no_text(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(near_dedup, "MAX_COMPARISONS", 1)

        with pytest.raises(NearDedupLimitError) as raised:
            compute_near_duplicates(_rows(*[_PLANTED] * 3))
        assert "MAX_COMPARISONS (1)" in str(raised.value)
        assert "zebra" not in str(raised.value)

    def test_a_compiled_core_counts_none_of_them(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The comparisons are the Python walk's: a core reports the pairs it found, and
        `dagnam-core` 0.2.0 is where it learns the limit (see the CHANGELOG)."""
        monkeypatch.setattr(near_dedup, "MAX_COMPARISONS", 1)
        core = SimpleNamespace(near_duplicates=lambda texts, threshold: ([1], [(0, 1, 1.0)]))
        monkeypatch.setattr(_backend, "active", lambda: core)

        assert compute_near_duplicates(_rows("a b c", "a b c")).duplicate_indices == [1]
