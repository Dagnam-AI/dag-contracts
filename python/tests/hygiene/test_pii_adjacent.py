"""Tests for `dagnam_contracts/hygiene/pii.py`: findings that stand next to each other.

A pattern refuses a candidate that follows a digit (a phone number after "digit, space"),
and a candidate that follows a token another class has not yet replaced is exactly such a
case. A redaction used to need several passes to be clean, then a bounded number of them.
It now needs one, by construction, so these hold the property over pairs and triples of
every class in every separator, over chains of any length, and over a seeded random
corpus -- each time that the redacted rows scan clean, redact to themselves, and carry
one placeholder per finding.
"""

from __future__ import annotations

from itertools import product
import json
from typing import Any

from pii_corpus import (
    ALL,
    SAMPLES,
    SEPARATORS,
    SHAPE_NAMES,
    SHAPES,
    everything_problems,
    found,
    random_rows,
)
import pytest

from dagnam_contracts.hygiene.detectors import PII_CODES, PII_DETECTORS
from dagnam_contracts.hygiene.pii import apply_pii_policy, redact_json_text, scan_rows

_BY_CODE = {detector.code: detector for detector in PII_DETECTORS}
_POOL = [(code, text) for code in sorted(SAMPLES) for text in SAMPLES[code]]


def _problems(rows: list[dict[str, Any]]) -> list[str]:
    return [problem for row in rows for problem in everything_problems(row)]


def test_every_sample_is_found_by_its_own_class() -> None:
    assert sorted(SAMPLES) == sorted(PII_CODES)
    for code, texts in SAMPLES.items():
        for text in texts:
            assert _BY_CODE[code].find(text), (code, text)


class TestFindingsNextToEachOther:
    @pytest.mark.parametrize(
        ("text", "redacted"),
        [
            # A phone number after a phone number, one space between.
            ("+44 20 7946 0958 +44 20 7946 0958", "[REDACTED:PII_PHONE] [REDACTED:PII_PHONE]"),
            # A phone number after a secret that ends in a digit.
            ("password: hunter22 +1 415-555-0132", "password: <SECRET> [REDACTED:PII_PHONE]"),
            # A card after a `pwd=` value that ends in a digit: 0.4.0 found neither.
            ("Pwd=letmein4 4111111111111111", "Pwd=<SECRET> [REDACTED:PII_PAYMENT_CARD]"),
        ],
    )
    def test_both_are_redacted_in_the_one_call(self, text: str, redacted: str) -> None:
        rows, changed, _ = apply_pii_policy([{"text": text}], ALL)

        assert (rows, changed) == ([{"text": redacted}], 1)
        assert sum(scan_rows([{"text": text}]).counts_by_code.values()) == 2
        assert not any(scan_rows(rows).counts_by_code.values())
        assert apply_pii_policy(rows, ALL) == (rows, 0, 0)
        assert redact_json_text(json.dumps({"a": text})) == (json.dumps({"a": redacted}), 2)

    def test_every_ordered_pair_of_samples_in_every_separator(self) -> None:
        """Every pair and every separator once, the row shape rotating from one to the next."""
        rows = [
            SHAPES[SHAPE_NAMES[index % len(SHAPE_NAMES)]](f"{first}{separator}{second}")
            for index, ((_, first), (_, second), separator) in enumerate(
                product(_POOL, _POOL, SEPARATORS)
            )
        ]

        assert len(rows) == len(_POOL) ** 2 * len(SEPARATORS)
        assert _problems(rows) == []

    def test_every_ordered_triple_of_classes_in_every_separator_and_shape(self) -> None:
        codes = sorted(SAMPLES)
        rows: list[dict[str, Any]] = []
        for index, triple in enumerate(product(codes, repeat=3)):
            texts = [
                SAMPLES[code][(index + place) % len(SAMPLES[code])]
                for place, code in enumerate(triple)
            ]
            rows += [
                SHAPES[SHAPE_NAMES[(index + step) % len(SHAPE_NAMES)]](separator.join(texts))
                for step, separator in enumerate(SEPARATORS)
            ]

        assert len(rows) == len(codes) ** 3 * len(SEPARATORS)
        assert _problems(rows) == []

    def test_a_long_glued_run_of_findings_that_hide_one_another(self) -> None:
        run = "4111111111111111" + "+44 20 7946 0958" + "Pwd=letmein4" + "415-555-0132"

        assert _problems([{"text": " ".join([run] * 30)}]) == []
        assert _problems([{"text": run * 30}]) == []


class TestChainsOfAnyLength:
    @pytest.mark.parametrize("length", [2, 3, 5, 10, 17, 40, 100])
    def test_a_chain_of_every_sample_in_every_separator(self, length: int) -> None:
        rows = [
            {"text": separator.join([sample] * length)}
            for _, sample in _POOL
            for separator in SEPARATORS
        ]

        assert _problems(rows) == []

    @pytest.mark.parametrize("separator", [" ", "-", "\t", ", ", "\n"])
    def test_numbers_one_separator_apart_are_each_a_finding(self, separator: str) -> None:
        """17 was the number that reached the pass limit; none does now. Each number is
        one finding, in the scan and in the redaction."""
        for length in (17, 40, 1000):
            text = separator.join(f"+1415555{1000 + i % 9000}" for i in range(length))

            result = scan_rows([{"text": text}])
            redacted, _, _ = apply_pii_policy([{"text": text}], ALL)

            assert result.counts_by_code["PII_PHONE"] == length
            assert redacted[0]["text"].count("[REDACTED:PII_PHONE]") == length
            assert found(redacted) == {}

    @pytest.mark.parametrize("code", sorted(SAMPLES))
    def test_five_thousand_links_of_a_class_settle(self, code: str) -> None:
        sample = SAMPLES[code][0]
        row = {"text": " ".join([sample] * 5_000)}

        assert everything_problems(row) == []

    def test_five_thousand_links_cycling_every_class(self) -> None:
        cycle = [SAMPLES[code][0] for code in sorted(SAMPLES)]
        for separator in SEPARATORS:
            text = separator.join(cycle[i % len(cycle)] for i in range(2_000))

            assert everything_problems({"text": text}) == []


class TestASeededRandomCorpus:
    @pytest.mark.parametrize("seed", [1, 2])
    def test_random_rows_in_every_shape(self, seed: int) -> None:
        """Rows of one to six fragments -- every class in several formats, with noise --
        in every shape, from `Random(seed)`: the same rows on every machine."""
        rows = random_rows(seed, 3_000)

        assert sum(1 for row in rows if found([row])) > 2_000, "most rows must carry a finding"
        assert _problems(rows) == []
