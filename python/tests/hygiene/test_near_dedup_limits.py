"""The limits on a batch of rows for `compute_near_duplicates`.

A service calls it on rows it did not write. The batch is refused before anything is
shingled or hashed when it has more rows than `MAX_TEXTS`, a comparison text longer than
`MAX_TEXT_CHARS` or more characters in all than `MAX_TOTAL_CHARS`; the result is refused,
as soon as it is known to be too large, when it lists more than `MAX_PAIRS` pairs. The
error says which limit and its value, and never a word of the rows.
"""

from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest

import dagnam_contracts
from dagnam_contracts import hygiene
from dagnam_contracts.hygiene import _backend, near_dedup
from dagnam_contracts.hygiene.near_dedup import (
    MAX_PAIRS,
    MAX_TEXT_CHARS,
    MAX_TEXTS,
    MAX_TOTAL_CHARS,
    NearDedupLimitError,
    compute_near_duplicates,
)

# What no message may hold: the words of the rows under test.
_SECRET = "zebra-quokka-4417"


@pytest.fixture(autouse=True, scope="module")
def _python_reference() -> Iterator[None]:
    with _backend.reference():
        yield


def _rows(*texts: str) -> list[dict[str, Any]]:
    return [{"t": text} for text in texts]


def test_the_limits_are_public_numbers_and_the_error_is_a_value_error() -> None:
    for name in ("MAX_TEXTS", "MAX_TEXT_CHARS", "MAX_TOTAL_CHARS", "MAX_PAIRS"):
        value = getattr(hygiene, name)
        assert type(value) is int and value > 0
        assert getattr(near_dedup, name) == value
        assert name in near_dedup.__all__ and name in hygiene.__all__
    assert issubclass(NearDedupLimitError, ValueError)
    assert (
        hygiene.NearDedupLimitError is NearDedupLimitError is dagnam_contracts.NearDedupLimitError
    )


def test_the_limits_are_the_documented_ones() -> None:
    """The compiled core mirrors these four numbers: a change here is a change there."""
    assert (MAX_TEXTS, MAX_TEXT_CHARS, MAX_TOTAL_CHARS, MAX_PAIRS) == (
        50_000,
        1_000_000,
        64_000_000,
        10_000_000,
    )


class TestRowsAndCharacters:
    def test_a_batch_of_exactly_the_most_rows_is_read(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(near_dedup, "MAX_TEXTS", 3)

        assert compute_near_duplicates(_rows("a b c", "d e f", "g h i")).duplicate_count == 0

    def test_one_row_more_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(near_dedup, "MAX_TEXTS", 3)

        with pytest.raises(NearDedupLimitError, match=r"MAX_TEXTS \(3\)") as raised:
            compute_near_duplicates(_rows(_SECRET, "b", "c", "d"))
        assert _SECRET not in str(raised.value)
        assert "4 texts" in str(raised.value)

    def test_the_real_most_rows_refuses_one_more_before_reading_any(self) -> None:
        with pytest.raises(NearDedupLimitError, match="MAX_TEXTS"):
            compute_near_duplicates([{}] * (MAX_TEXTS + 1))

    def test_a_text_of_exactly_the_most_characters_is_read(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(near_dedup, "MAX_TEXT_CHARS", 10)

        assert compute_near_duplicates(_rows("abcde fghi", "x")).kept_count == 2

    def test_one_character_more_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(near_dedup, "MAX_TEXT_CHARS", 10)

        with pytest.raises(NearDedupLimitError, match=r"MAX_TEXT_CHARS \(10\)") as raised:
            compute_near_duplicates(_rows("x", f"{_SECRET[:5]} {_SECRET[6:11]}"))
        assert "11 characters" in str(raised.value)
        assert _SECRET[:5] not in str(raised.value)

    def test_a_text_is_counted_as_row_text_makes_it(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The comparison text, not the row's own: punctuation and runs of spaces are gone."""
        monkeypatch.setattr(near_dedup, "MAX_TEXT_CHARS", 5)

        result = compute_near_duplicates(_rows("a, , ,  ,   b!!!!!!!!!!!!!!!"))

        assert result.kept_count == 1

    def test_the_real_most_characters_of_one_text_pass_and_one_more_does_not(self) -> None:
        compute_near_duplicates(_rows("a" * MAX_TEXT_CHARS))
        with pytest.raises(NearDedupLimitError, match="MAX_TEXT_CHARS"):
            compute_near_duplicates(_rows("a" * (MAX_TEXT_CHARS + 1)))

    def test_exactly_the_most_characters_in_all_are_read(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(near_dedup, "MAX_TOTAL_CHARS", 20)

        assert compute_near_duplicates(_rows("a" * 10, "b" * 10)).kept_count == 2

    def test_one_more_in_all_is_refused_at_the_row_that_crosses_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(near_dedup, "MAX_TOTAL_CHARS", 20)

        with pytest.raises(NearDedupLimitError, match=r"MAX_TOTAL_CHARS \(20\)") as raised:
            compute_near_duplicates(_rows("a" * 10, _SECRET + "x" * 10, "c"))
        assert _SECRET not in str(raised.value)


class TestTheOrderOfTheChecks:
    def test_the_threshold_error_comes_first(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(near_dedup, "MAX_TEXTS", 1)

        with pytest.raises(ValueError, match="threshold") as raised:
            compute_near_duplicates(_rows("a", "b"), 0)
        assert not isinstance(raised.value, NearDedupLimitError)

    def test_a_refused_batch_is_never_shingled_or_hashed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(*_: object) -> None:
            raise AssertionError("heavy work before the limit check")

        monkeypatch.setattr(near_dedup, "MAX_TOTAL_CHARS", 3)
        monkeypatch.setattr(near_dedup, "shingles", boom)
        monkeypatch.setattr(near_dedup, "minhash_signature", boom)
        monkeypatch.setattr(near_dedup, "_candidate_pairs", boom)

        with pytest.raises(NearDedupLimitError):
            compute_near_duplicates(_rows("ab cd", "ef gh"))

    def test_the_core_is_not_called_for_a_refused_batch(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(*_: object) -> None:
            raise AssertionError("the core was called")

        monkeypatch.setattr(near_dedup, "MAX_TEXTS", 1)
        monkeypatch.setattr(_backend, "active", lambda: SimpleNamespace(near_duplicates=boom))

        with pytest.raises(NearDedupLimitError):
            compute_near_duplicates(_rows("a", "b"))


class TestThePairs:
    def test_exactly_the_most_pairs_are_returned(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(near_dedup, "MAX_PAIRS", 3)

        assert len(compute_near_duplicates(_rows(*["same words here"] * 3)).pairs) == 3

    def test_one_more_is_refused_as_soon_as_it_is_found(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Sixty identical rows hold 1,770 pairs; the walk stops at the fourth."""
        monkeypatch.setattr(near_dedup, "MAX_PAIRS", 3)
        compared: list[int] = []
        estimate = near_dedup.estimate_jaccard

        def counting(left: tuple[int, ...], right: tuple[int, ...]) -> float:
            compared.append(1)
            return estimate(left, right)

        monkeypatch.setattr(near_dedup, "estimate_jaccard", counting)

        with pytest.raises(NearDedupLimitError, match=r"MAX_PAIRS \(3\)") as raised:
            compute_near_duplicates(_rows(*[_SECRET] * 60))
        assert len(compared) == 4
        assert _SECRET not in str(raised.value)

    @pytest.mark.parametrize(("pairs", "refused"), [(3, False), (4, True)])
    def test_the_core_s_pairs_are_held_to_the_same_limit(
        self, monkeypatch: pytest.MonkeyPatch, pairs: int, refused: bool
    ) -> None:
        monkeypatch.setattr(near_dedup, "MAX_PAIRS", 3)
        found = [(0, i + 1, 1.0) for i in range(pairs)]
        core = SimpleNamespace(near_duplicates=lambda texts, threshold: ([1, 2], found))
        monkeypatch.setattr(_backend, "active", lambda: core)

        if refused:
            with pytest.raises(NearDedupLimitError, match="MAX_PAIRS"):
                compute_near_duplicates(_rows("a", "b", "c"))
        else:
            assert len(compute_near_duplicates(_rows("a", "b", "c")).pairs) == 3
