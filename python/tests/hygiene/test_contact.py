"""Tests for `dagnam_contracts/hygiene/contact.py`: the phone and address finders.

Phone numbers in runs: nothing 0.4.0 redacted is left behind.

A number written with its country code hides the next one from the pattern's lookbehind, so
the finder reads on from an accepted number without it. That chain must not run into the
number after the next: the body of a number takes digits, spaces and parentheses, so a
chain left alone took the area code of a parenthesised number and stranded the seven digits
behind it. The oracle is 0.4.0's finder as it shipped; every digit it found is redacted.
"""

from __future__ import annotations

from itertools import product
import random
import re

from pii_corpus import SHAPE_NAMES, SHAPES, everything_problems, found
import pytest

from dagnam_contracts.hygiene import contact
from dagnam_contracts.hygiene.spans import findings

# 0.4.0's phone finder, verbatim.
_OLD_CANDIDATE = re.compile(r"(?<![\d+])(?<![\d][ -])\+?\d(?:[\d\s.()-]{7,20})\d(?![\d]|[ -]\d)")


def _old_phone_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for match in _OLD_CANDIDATE.finditer(text):
        raw = match.group()
        digits = re.sub(r"\D", "", raw)
        international = raw.startswith("+")
        if not (9 if international else 10) <= len(digits) <= 15:
            continue
        if not international and not re.search(r"[\s.()-]", raw):
            continue
        spans.append(match.span())
    return spans


# Every format the pattern accepts, one number each.
FORMATS = [
    "+44 20 7946 0958",
    "(415) 555-0132",
    "415.555.0132",
    "+1 415-555-0132",
    "+14155551234",
    "+91 98765 43210",
    "415 555 0132",
    "(415)555-0132",
    "+49 30 901820",
    "+33 1 42 68 53 00",
    "1-800-555-0199",
    "+81-3-1234-5678",
    "+1 (415) 555-0132",
]
SEPARATORS = [" ", "\t", ", ", "\n", "-", " - ", "\r\n", "  ", " / ", ""]


def _digit_positions(spans: list[tuple[int, int]], text: str) -> set[int]:
    return {i for a, b in spans for i in range(a, b) if text[i].isdigit()}


def _redacted_positions(text: str) -> set[int]:
    return {i for a, b, _ in findings(text) for i in range(a, b)}


def _missing(text: str) -> set[int]:
    """The digits 0.4.0's finder took that 0.4.1 leaves in the text."""
    return _digit_positions(_old_phone_spans(text), text) - _redacted_positions(text)


def test_every_format_is_a_number_to_the_finder() -> None:
    for number in FORMATS:
        assert _old_phone_spans(number), number


class TestThreeNumbersTheLastParenthesised:
    @pytest.mark.parametrize("separator", [" ", "\n"])
    def test_each_number_is_found_whole(self, separator: str) -> None:
        """Two numbers with a plus, one space apart, then one with its area code in
        parentheses: the second number's chain took `(415` and left the seven digits
        behind. 0.4.0 left the second number instead; 0.4.1 finds all three."""
        text = "+44 20 7946 0958 +44 20 7946 0958" + separator + "(415) 555-0132"

        assert _missing(text) == set()
        redacted = text
        for a, b, _ in reversed(findings(text)):
            redacted = redacted[:a] + "#" + redacted[b:]
        assert "0132" not in redacted
        assert redacted.count("#") == 3

    @pytest.mark.parametrize("shape", SHAPE_NAMES)
    def test_in_every_shape_of_row(self, shape: str) -> None:
        text = "+44 20 7946 0958 +44 20 7946 0958\n(415) 555-0132"
        row = SHAPES[shape](text)

        assert everything_problems(row) == []
        assert found([{"text": text}])["PII_PHONE"] == 3


class TestEveryDigitZeroFourZeroRedactedIsRedacted:
    def test_two_numbers_in_every_format_and_separator(self) -> None:
        for first, second, separator in product(FORMATS, FORMATS, SEPARATORS):
            text = first + separator + second

            assert _missing(text) == set(), text

    def test_three_numbers_in_every_separator_pair(self) -> None:
        generator = random.Random(2026)
        for _ in range(12_000):
            numbers = [generator.choice(FORMATS) for _ in range(3)]
            text = (
                numbers[0]
                + generator.choice(SEPARATORS)
                + numbers[1]
                + generator.choice(SEPARATORS)
                + numbers[2]
            )

            assert _missing(text) == set(), text

    def test_longer_runs_with_text_between(self) -> None:
        generator = random.Random(7)
        noise = ["call", "or", "x", "id 3", "ext.", "tel:"]
        for _ in range(6_000):
            parts: list[str] = []
            for _ in range(generator.randint(2, 6)):
                parts.append(generator.choice(FORMATS))
                if generator.random() < 0.3:
                    parts.append(generator.choice(noise))
            text = generator.choice(SEPARATORS).join(parts)

            assert _missing(text) == set(), text


# The address pattern as it stood, one repeated group of labels.
_OLD_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_PIECES = [
    "@",
    "a",
    "b1",
    "x.co",
    ".",
    "..",
    "-",
    "_",
    "+",
    " ",
    ":",
    "a@b.co",
    "@@",
    "/",
    "9",
]


class TestTheDomainOfAnAddress:
    def test_it_is_the_pattern_it_replaced_on_fuzzed_text(self) -> None:
        generator = random.Random(4)
        for _ in range(40_000):
            text = "".join(generator.choice(_PIECES) for _ in range(generator.randint(1, 18)))
            assert contact.find_emails(text) == [m.span() for m in _OLD_EMAIL.finditer(text)], text

    def test_a_domain_ends_at_a_double_dot_or_a_trailing_dot(self) -> None:
        text = "a@b.c..d a@b.c. a@.b.c a@b a@b-.c"

        assert [text[a:b] for a, b in contact.find_emails(text)] == ["a@b.c", "a@b.c", "a@b-.c"]
