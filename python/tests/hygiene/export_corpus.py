"""Write the reference corpus a port of the hygiene code is pinned to.

Not a test module: ``python tests/hygiene/export_corpus.py <dir>`` writes three JSON
Lines files into ``<dir>``, one case per line, from the inputs the suite already pins
(`pii_corpus` and the tables it imports) and those in `corpus_inputs`:

* ``minhash.jsonl``    -- ``{"shingles": [str], "signature": [str]}`` (the 128 values are
  decimal strings: they exceed 2**53, so a JSON number would lose them);
* ``near_dedup.jsonl`` -- ``{"texts", "threshold", "duplicate_indices", "pairs"}``, see
  `corpus_near_dedup`: the texts are already ``row_text`` output;
* ``findings.jsonl``   -- ``{"text", "spans": [[start, end, code]]}``, offsets in code points.

A text that cannot be encoded as UTF-8 (a lone surrogate) is dropped: it cannot be
written to a file a port reads. The output is sorted and seeded, so it is byte-identical
from run to run, and every expected value is computed by the reference.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
import json
from pathlib import Path
import sys
from typing import Any

from corpus_inputs import (
    LONE_SURROGATES,
    STRUCTURAL_TEXTS,
    UNICODE_TEXTS,
    card_texts,
    encodable,
    iban_texts,
    long_texts,
    vat_texts,
)
from corpus_near_dedup import near_dedup_cases
from pii_corpus import FRAGMENTS, SAMPLES, TEXTS, document_rows, random_rows
from test_credentials import MEMBERS, NEGATIVES as SECRET_NEGATIVES, POSITIVES as SECRET_POSITIVES
from test_detectors import NEGATIVES as DETECTOR_NEGATIVES, POSITIVES as DETECTOR_POSITIVES
from test_pii import LABELLED_CORPUS

from dagnam_contracts.hygiene.near_dedup import (
    NUM_PERMUTATIONS,
    minhash_signature,
    row_text,
    shingles,
)
from dagnam_contracts.hygiene.spans import WINDOW, findings

SEED = 20261114
ROWS = 600


def _leaves(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _leaves(item)
    elif isinstance(value, list):
        for item in value:
            yield from _leaves(item)


def _write(path: Path, cases: Iterable[dict[str, Any]]) -> int:
    lines = [json.dumps(case, ensure_ascii=False, sort_keys=True) + "\n" for case in cases]
    path.write_text("".join(lines), encoding="utf-8", newline="")
    return len(lines)


def pinned_texts() -> set[str]:
    """Every text the suite's tables pin, each by its own import."""
    return {
        *(text for text, _ in LABELLED_CORPUS),
        *(template.format(value) for _, template, value in DETECTOR_POSITIVES),
        *(text for _, text in DETECTOR_NEGATIVES),
        *(template.format(secret) for _, template, secret in SECRET_POSITIVES),
        *(text for _, text in SECRET_NEGATIVES),
        *(json.dumps({key: value}) for key, value, _ in MEMBERS),
        *(sample for samples in SAMPLES.values() for sample in samples),
        *TEXTS,
        *FRAGMENTS,
    }


def gather(rows: list[dict[str, Any]]) -> tuple[list[str], list[str], int]:
    """``(pinned and planted texts, all texts, how many were dropped)``, sorted.

    The first list is the tables and the planted inputs (what the MinHash cases come
    from); the second adds every string leaf of the seeded rows.
    """
    base = pinned_texts()
    planted = {*UNICODE_TEXTS, *STRUCTURAL_TEXTS, *card_texts(), *iban_texts(), *vat_texts()}
    planted.update(long_texts(sorted(planted - set(LONE_SURROGATES))))
    leaves = {leaf for row in [*document_rows(), *rows] for leaf in _leaves(row)}
    first = {*base, *planted}
    everything = first | leaves
    kept = sorted(text for text in everything if encodable(text))
    return (
        sorted(text for text in first if encodable(text)),
        kept,
        len(everything) - len(kept),
    )


def _long_shingle_sets() -> list[list[str]]:
    """Shingle sets that are not the shingles of any text: the edges of the hash input."""
    many = [f"w{i} w{i + 1} w{i + 2}" for i in range(3000)]
    return [
        ["a", "a"],
        ["𝒳 y z"],
        ["a\tb"],
        ["x" * 5000],
        ["only"],
        many,
        ["ünï cödé 日本語", "٠١٢ ٣٤٥ ٦٧٨", "😀 x y", "ß ss ſ"],
    ]


def _minhash_cases(texts: list[str]) -> list[dict[str, Any]]:
    sets = {shingles(row_text({"t": text})) for text in texts}
    shingle_lists = [sorted(s) for s in sorted(sets, key=sorted)] + _long_shingle_sets()
    return [
        {"shingles": s, "signature": [str(v) for v in minhash_signature(frozenset(s))]}
        for s in shingle_lists
    ]


def _findings_cases(texts: list[str]) -> list[dict[str, Any]]:
    windows = {
        text[max(0, start - WINDOW // 2) : end + WINDOW // 2]
        for text in texts
        for start, end, _ in findings(text)
    }
    return [
        {"text": text, "spans": [[s, e, d.code] for s, e, d in findings(text)]}
        for text in sorted({*texts, *windows})
    ]


def export(out: Path) -> dict[str, int]:
    """Write the three files into ``out``; return how many cases each holds and more."""
    out.mkdir(parents=True, exist_ok=True)
    rows = random_rows(SEED, ROWS)
    first, texts, dropped = gather(rows)
    counts = {"dropped": dropped}
    counts["minhash"] = _write(out / "minhash.jsonl", _minhash_cases(first))
    near_dedup, found = near_dedup_cases(rows)
    counts["near_dedup"] = _write(out / "near_dedup.jsonl", near_dedup)
    cases = _findings_cases(texts)
    counts["findings"] = _write(out / "findings.jsonl", cases)
    counts.update(found)
    for code, number in sorted(Counter(s[2] for case in cases for s in case["spans"]).items()):
        counts[code] = number
    counts["signature_length"] = NUM_PERMUTATIONS
    return counts


if __name__ == "__main__":
    for name, count in export(Path(sys.argv[1])).items():
        print(f"{name}: {count}")
