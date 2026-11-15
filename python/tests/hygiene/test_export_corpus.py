from collections import Counter
from collections.abc import Iterator
from itertools import combinations
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

from corpus_atoms import HELD_CODE, TEST_MARKERS
from corpus_inputs import LONE_SURROGATES, VAT_SAMPLES, iban_texts, vat_texts
from corpus_near_dedup import THRESHOLDS, normalised
from corpus_regions import leaks
from export_corpus import build, export
import pytest

from dagnam_contracts.hygiene.detectors import _IBAN_LENGTHS, PII_CODES
from dagnam_contracts.hygiene.near_dedup import (
    compute_near_duplicates,
    estimate_jaccard,
    minhash_signature,
    shingles,
)
from dagnam_contracts.hygiene.spans import findings

NAMES = ("minhash.jsonl", "near_dedup.jsonl", "findings.jsonl")
ALL_NAMES = (*NAMES, "credentials.jsonl")
Corpus = tuple[Path, dict[str, int]]

# What a push-protection scanner keys on, and a little more; the exporter's own list is
# `corpus_regions.PROVIDER_MARKERS`. Both are built in `corpus_atoms`.
MARKERS = list(TEST_MARKERS)


def _read(directory: Path, name: str) -> list[dict[str, Any]]:
    # U+2028 and U+0085 are written raw, so `splitlines` would cut inside a text.
    lines = (directory / name).read_text(encoding="utf-8").split("\n")
    assert lines.pop() == ""
    return [json.loads(line) for line in lines]


def _codes(text: str) -> list[list[Any]]:
    return [[s, e, d.code] for s, e, d in findings(text)]


@pytest.fixture(scope="module")
def corpus(tmp_path_factory: pytest.TempPathFactory) -> Corpus:
    directory = tmp_path_factory.mktemp("corpus")
    return directory, export(directory)


def test_every_minhash_case_is_what_the_reference_computes(corpus: Corpus) -> None:
    cases = _read(corpus[0], "minhash.jsonl")
    assert len(cases) >= 50 and len(cases) == corpus[1]["minhash"]
    for case in cases:
        signature = minhash_signature(frozenset(case["shingles"]))
        assert [str(v) for v in signature] == case["signature"]
    assert any(case["shingles"] == ["a", "a"] for case in cases)


def test_every_findings_case_is_what_the_reference_finds(corpus: Corpus) -> None:
    cases = _read(corpus[0], "findings.jsonl")
    assert len(cases) >= 500 and len(cases) == corpus[1]["findings"]
    for case in cases:
        assert _codes(case["text"]) == case["spans"]
    found = {span[2] for case in cases for span in case["spans"]}
    assert found == set(PII_CODES) - {HELD_CODE}


def test_every_near_dedup_text_is_row_text_output_and_every_verdict_is_the_references(
    corpus: Corpus,
) -> None:
    cases = _read(corpus[0], "near_dedup.jsonl")
    assert len(cases) == corpus[1]["near_dedup"]
    for case in cases:
        texts: list[str] = case["texts"]
        assert all(normalised(text) == text for text in texts)
        result = compute_near_duplicates([{"t": text} for text in texts], case["threshold"])
        assert result.duplicate_indices == case["duplicate_indices"]
        pairs = [[p.kept_index, p.duplicate_index, p.similarity] for p in result.pairs]
        assert pairs == case["pairs"]


def test_near_dedup_pins_the_order_sensitive_shapes(corpus: Corpus) -> None:
    cases = _read(corpus[0], "near_dedup.jsonl")
    assert {len(case["texts"]) for case in cases} >= {0, 1, 2, 3, 40, 100}
    assert {case["threshold"] for case in cases} == set(THRESHOLDS)
    assert corpus[1]["chains"] >= 1 and corpus[1]["band_misses"] >= 1
    chain = band_miss = dyadic = empties = short = False
    for case in cases:
        texts: list[str] = case["texts"]
        pairs = {(p[0], p[1]) for p in case["pairs"]}
        chain |= any(
            (i, j) in pairs and (j, k) in pairs and (i, k) not in pairs
            for i, j, k in combinations(range(len(texts)), 3)
        )
        signatures = [minhash_signature(shingles(text)) for text in texts]
        band_miss |= any(
            estimate_jaccard(signatures[i], signatures[j]) >= case["threshold"]
            and (i, j) not in pairs
            for i, j in combinations(range(len(texts)), 2)
        )
        dyadic |= any(p[2] == case["threshold"] == 0.875 for p in case["pairs"])
        empties |= texts.count("") >= 3
        short |= {1, 2} <= {len(text.split()) for text in texts}
    assert chain and band_miss and dyadic and empties and short


def test_a_port_that_counts_wide_units_or_bytes_fails_the_corpus(corpus: Corpus) -> None:
    spans = [
        (case["text"][: span[0]], span)
        for case in _read(corpus[0], "findings.jsonl")
        for span in case["spans"]
    ]
    counted = [
        (len(before), len(before.encode("utf-16-le")) // 2, len(before.encode("utf-8")))
        for before, _ in spans
    ]
    assert any(len({*sizes}) == 3 for sizes in counted)


def test_every_registry_country_has_a_valid_iban_and_every_state_a_valid_vat(
    corpus: Corpus,
) -> None:
    ibans = iban_texts()
    assert len(ibans) == 4 * len(_IBAN_LENGTHS)
    for i in range(0, len(ibans), 4):
        assert all(code == "PII_IBAN" for _, _, code in _codes(ibans[i])), ibans[i]
        assert [c for _, _, c in _codes(ibans[i])] == ["PII_IBAN"]
        assert [c for _, _, c in _codes(ibans[i + 1])] == ["PII_IBAN"]
        assert "PII_IBAN" not in [c for _, _, c in _codes(ibans[i + 2])]
        assert "PII_IBAN" not in [c for _, _, c in _codes(ibans[i + 3])]
    vats = vat_texts()
    assert len(vats) == 4 * sum(len(samples) for samples in VAT_SAMPLES.values())
    for i in range(0, len(vats), 4):
        assert "PII_EU_VAT" in [c for _, _, c in _codes(vats[i])], vats[i]
    assert corpus[1]["PII_IBAN"] >= len(_IBAN_LENGTHS)


def test_export_is_deterministic(corpus: Corpus, tmp_path: Path) -> None:
    assert export(tmp_path) == corpus[1]
    for name in ALL_NAMES:
        assert (tmp_path / name).read_bytes() == (corpus[0] / name).read_bytes()
        (tmp_path / name).read_bytes().decode("utf-8")


def test_a_text_that_is_not_unicode_is_dropped_and_counted(corpus: Corpus) -> None:
    assert corpus[1]["dropped"] == len(LONE_SURROGATES) == 2
    for name in ALL_NAMES:
        content = (corpus[0] / name).read_text(encoding="utf-8")
        assert not any(text in content for text in LONE_SURROGATES)
        assert "\ud800" not in content and "\udfff" not in content


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def test_the_files_parse_to_exactly_the_cases_the_reference_produced(corpus: Corpus) -> None:
    files, counts = build()
    assert counts == corpus[1]
    for name, cases in files.items():
        assert _read(corpus[0], name) == cases


def test_no_credential_marker_is_in_the_raw_bytes_and_no_text_is_held(
    corpus: Corpus,
) -> None:
    for name in NAMES:
        content = (corpus[0] / name).read_text(encoding="utf-8").casefold()
        for marker in MARKERS:
            assert marker.casefold() not in content, (name, marker)
        for case in _read(corpus[0], name):
            for text in _strings(case):
                assert HELD_CODE not in {code for _, _, code in _codes(text)}, (name, text)
                assert not leaks(text), (name, text)


def test_credential_drops_are_counted_apart_from_encoding_drops(corpus: Corpus) -> None:
    counts = corpus[1]
    assert counts["dropped"] == 2
    for key in ("minhash", "findings", "near_dedup"):
        assert counts[f"dropped_flagged_{key}"] > 0
    assert HELD_CODE not in counts


def test_every_class_that_remains_keeps_its_minimum(corpus: Corpus) -> None:
    for code in set(PII_CODES) - {HELD_CODE}:
        assert corpus[1][code] >= 20, code


def test_near_dedup_group_sizes_survive_the_credential_drops(corpus: Corpus) -> None:
    sizes = Counter(len(case["texts"]) for case in _read(corpus[0], "near_dedup.jsonl"))
    assert sizes[40] == 8 * len(THRESHOLDS) and sizes[100] == len(THRESHOLDS)


@pytest.mark.parametrize("seed", ["1", "2"])
def test_the_bytes_do_not_depend_on_the_hash_seed(
    corpus: Corpus, tmp_path: Path, seed: str
) -> None:
    script = Path(__file__).with_name("export_corpus.py")
    env = {**os.environ, "PYTHONHASHSEED": seed}
    subprocess.run(
        [sys.executable, str(script), str(tmp_path)], env=env, check=True, capture_output=True
    )
    for name in ALL_NAMES:
        assert (tmp_path / name).read_bytes() == (corpus[0] / name).read_bytes()
