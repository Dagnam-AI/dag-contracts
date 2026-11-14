"""Write the reference corpus a port of the hygiene code is pinned to.

Not a test module: ``python tests/hygiene/export_corpus.py <dir>`` writes three JSON
Lines files into ``<dir>``, one case per line, from the inputs the suite already pins:

* ``minhash.jsonl``    -- ``{"shingles": [str], "signature": [str]}`` (the 128 values are
  decimal strings: they exceed 2**53, so a JSON number would lose them);
* ``near_dedup.jsonl`` -- ``{"texts", "threshold", "duplicate_indices", "pairs"}`` for
  groups of normalised row texts, each with a few planted near-copies;
* ``findings.jsonl``   -- ``{"text", "spans": [[start, end, code]]}``, offsets in code points.

A text that cannot be encoded as UTF-8 (a lone surrogate) is dropped: it cannot be
written to a file a port reads. The output is sorted and seeded, so it is byte-identical
from run to run.
"""

from __future__ import annotations

from collections.abc import Iterable
import json
from pathlib import Path
import sys
from typing import Any

from pii_corpus import FRAGMENTS, SAMPLES, TEXTS, document_rows, random_rows

from dagnam_contracts.hygiene.near_dedup import (
    compute_near_duplicates,
    minhash_signature,
    row_text,
    shingles,
)
from dagnam_contracts.hygiene.spans import WINDOW, findings

SEED = 20261114
ROWS = 600
GROUP = 40
THRESHOLDS = (0.5, 0.9, 1.0)

# Casefolding, punctuation and encoding edges the pinned tables do not reach.
EXTRA = [
    "Straße ΣΑΣ ﬁnal İstanbul",
    "tab\tand nbsp and em space",
    "  ",
    "",
    "one",
    "lone surrogate \ud800 here",
]


def _encodable(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _leaves(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _leaves(item)
    elif isinstance(value, list):
        for item in value:
            yield from _leaves(item)


def _write(path: Path, cases: Iterable[dict[str, Any]]) -> None:
    lines = (json.dumps(case, ensure_ascii=False, sort_keys=True) + "\n" for case in cases)
    path.write_text("".join(lines), encoding="utf-8", newline="")


def _near_dedup_groups(rows: list[dict[str, Any]]) -> Iterable[list[str]]:
    """Groups of row texts; the last four of each repeat the first four, edited."""
    for start in range(0, len(rows) - GROUP + 1, GROUP):
        texts = [row_text(row) for row in rows[start : start + GROUP]]
        words = texts[2].split()
        texts[GROUP - 4 :] = [
            texts[0],
            texts[1].upper(),
            " ".join(words[:-1]),
            texts[3] + " extra",
        ]
        yield texts


def export(out: Path) -> None:
    """Write ``minhash.jsonl``, ``near_dedup.jsonl`` and ``findings.jsonl`` into ``out``."""
    out.mkdir(parents=True, exist_ok=True)
    rows = random_rows(SEED, ROWS)
    pinned = {*TEXTS, *FRAGMENTS, *EXTRA, *(s for group in SAMPLES.values() for s in group)}
    leaves = {leaf for row in [*document_rows(), *rows] for leaf in _leaves(row)}
    texts = sorted(text for text in pinned | leaves if _encodable(text))

    shingle_sets = {shingles(row_text({"t": text})) for text in texts}
    _write(
        out / "minhash.jsonl",
        (
            {"shingles": sorted(s), "signature": [str(v) for v in minhash_signature(s)]}
            for s in sorted(shingle_sets, key=sorted)
        ),
    )

    near_dedup: list[dict[str, Any]] = []
    for group in _near_dedup_groups(rows):
        for threshold in THRESHOLDS:
            result = compute_near_duplicates([{"t": text} for text in group], threshold)
            near_dedup.append(
                {
                    "texts": group,
                    "threshold": threshold,
                    "duplicate_indices": result.duplicate_indices,
                    "pairs": [
                        [p.kept_index, p.duplicate_index, p.similarity] for p in result.pairs
                    ],
                }
            )
    _write(out / "near_dedup.jsonl", near_dedup)

    windows = {
        text[max(0, start - WINDOW // 2) : end + WINDOW // 2]
        for text in texts
        for start, end, _ in findings(text)
    }
    cases = (
        {"text": text, "spans": [[s, e, d.code] for s, e, d in findings(text)]}
        for text in sorted({*texts, *windows})
    )
    _write(out / "findings.jsonl", cases)


if __name__ == "__main__":
    export(Path(sys.argv[1]))
