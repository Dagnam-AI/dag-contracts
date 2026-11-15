"""Write the reference corpus a port of the hygiene code is pinned to.

Not a test module: ``python tests/hygiene/export_corpus.py <dir>`` writes five JSON
Lines files into ``<dir>``, one case per line, from the inputs the suite already pins
(`pii_corpus` and the tables it imports) and those in `corpus_inputs`:

* ``minhash.jsonl``    -- ``{"shingles": [str], "signature": [str]}`` (the 128 values are
  decimal strings: they exceed 2**53, so a JSON number would lose them);
* ``near_dedup.jsonl`` -- ``{"texts", "threshold", "duplicate_indices", "pairs"}``, see
  `corpus_near_dedup`: the texts are already ``row_text`` output;
* ``findings.jsonl``   -- ``{"text", "spans": [[start, end, code]]}``, offsets in code points;
* ``credentials.jsonl`` -- ``{"parts", "spans"}``: the texts that hold a credential, as
  fragments (``"".join(parts)`` is the text), see `corpus_credentials`;
* ``classes.jsonl``    -- one line, ``{"word", "space", "digit": [[lo, hi]]}``: the inclusive
  code-point ranges Python's ``\\w``, ``\\s`` and ``\\d`` match, see `corpus_classes`.

A text that cannot be encoded as UTF-8 (a lone surrogate) is dropped: it cannot be
written to a file a port reads. So is every text, in every file, that holds a credential
(a held-credential finding, a provider prefix or a name with a value, see
`corpus_regions`): no
credential-shaped string, fake or not, is pushed, so those texts are kept only as
fragments in ``credentials.jsonl``. The counts report both kinds of drop separately. The output is sorted and seeded, so
it is byte-identical from run to run, and every expected value is computed by the
reference.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
import json
from pathlib import Path
import sys
from typing import Any

from corpus_atoms import HELD_CODE
from corpus_classes import class_case
from corpus_credentials import (
    clean_windows,
    combined_texts,
    credential_cases,
    generated_texts,
    windows,
)
from corpus_inputs import (
    LONE_SURROGATES,
    STRUCTURAL_TEXTS,
    UNICODE_TEXTS,
    card_texts,
    dumps,
    encodable,
    iban_texts,
    leaves,
    long_texts,
    vat_texts,
)
from corpus_near_dedup import near_dedup_cases
from corpus_regions import exportable, leaks, line_leaks, pool_values, use_values
from pii_corpus import FRAGMENTS, SAMPLES, TEXTS, document_rows, random_rows
from test_credentials import MEMBERS, NEGATIVES as FINDER_NEGATIVES, POSITIVES as FINDER_POSITIVES
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
ROWS = 2400


def _write(path: Path, cases: Iterable[dict[str, Any]]) -> None:
    lines = [dumps(case) + "\n" for case in cases]
    path.write_text("".join(lines), encoding="utf-8", newline="")


def pinned_texts() -> set[str]:
    """Every text the suite's tables pin, each by its own import."""
    return {
        *(text for text, _ in LABELLED_CORPUS),
        *(template.format(value) for _, template, value in DETECTOR_POSITIVES),
        *(text for _, text in DETECTOR_NEGATIVES),
        *(template.format(value) for _, template, value in FINDER_POSITIVES),
        *(text for _, text in FINDER_NEGATIVES),
        *(json.dumps({key: value}) for key, value, _ in MEMBERS),
        *(sample for samples in SAMPLES.values() for sample in samples),
        *TEXTS,
        *FRAGMENTS,
    }


def gather(rows: list[dict[str, Any]]) -> tuple[list[str], list[str], int]:
    """``(pinned and planted texts, all texts, how many cannot be written as UTF-8)``.

    The first list is the tables and the planted inputs (what the MinHash cases come
    from); the second adds every string leaf of the seeded rows. Both are sorted and
    hold encodable texts only, credential-shaped ones included.
    """
    base = pinned_texts()
    planted = {*UNICODE_TEXTS, *STRUCTURAL_TEXTS, *card_texts(), *iban_texts(), *vat_texts()}
    planted.update(long_texts(sorted(planted - set(LONE_SURROGATES))))
    row_leaves = {leaf for row in [*document_rows(), *rows] for leaf in leaves(row)}
    first = {*base, *planted}
    everything = first | row_leaves
    return (
        sorted(text for text in first if encodable(text)),
        sorted(text for text in everything if encodable(text)),
        len(everything) - sum(encodable(text) for text in everything),
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


def _clean_set(shingle_set: list[str]) -> bool:
    return not leaks(" ".join(shingle_set)) and not any(leaks(shingle) for shingle in shingle_set)


def _minhash_cases(texts: list[str]) -> tuple[list[dict[str, Any]], int]:
    """The cases, and how many candidate shingle sets were dropped for a credential.

    A set is dropped when a shingle, the joined set or every text it came from holds one.
    """
    sources: dict[frozenset[str], bool] = {}
    for text in texts:
        found = shingles(row_text({"t": text}))
        sources[found] = sources.get(found, False) or not leaks(text)
    candidates = [(sorted(s), sources[s]) for s in sorted(sources, key=sorted)]
    candidates += [(s, True) for s in _long_shingle_sets()]
    kept = [s for s, source_clean in candidates if source_clean and _clean_set(s)]
    cases = [
        {"shingles": s, "signature": [str(v) for v in minhash_signature(frozenset(s))]}
        for s in kept
    ]
    return cases, len(candidates) - len(kept)


def _safe(cases: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """The cases whose written line holds no credential, and how many were dropped."""
    kept = [case for case in cases if not line_leaks(case)]
    return kept, len(cases) - len(kept)


def _findings_cases(
    kept: list[str], dirty: list[str]
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """The cases, and the counts of windows dropped for a credential and recovered.

    The cases are the texts without a credential region, the windows around their
    findings, and (recovered) the windows around the findings of the other texts that
    hold no region.
    """
    windows = {
        text[max(0, start - WINDOW // 2) : end + WINDOW // 2]
        for text in kept
        for start, end, _ in findings(text)
    } - set(kept)
    clean = {window for window in windows if exportable(window)}
    recovered = clean_windows(dirty) - clean - set(kept)
    texts = sorted({*kept, *clean, *recovered})
    cases = [
        {"text": text, "spans": [[s, e, d.code] for s, e, d in findings(text)]} for text in texts
    ]
    counts = {"dropped_windows": len(windows) - len(clean), "recovered_windows": len(recovered)}
    by_code = Counter(d.code for text in recovered for _, _, d in findings(text))
    counts.update((f"recovered_{code}", number) for code, number in sorted(by_code.items()))
    return cases, counts


def _regions_policy(rows: list[dict[str, Any]]) -> tuple[list[str], list[str], set[str], int]:
    """Set the pool values and return ``(pinned texts, all texts, credential candidates,
    UTF-8 drops)``: the candidates are every text that may hold a credential, generated
    ones included."""
    use_values(())
    first, everything, utf8 = gather(rows)
    leaking = [text for text in everything if leaks(text)]
    holders = [text for text in leaking if any(d.code == HELD_CODE for _, _, d in findings(text))]
    candidates = {
        *leaking,
        *windows(leaking),
        *generated_texts(SEED),
        *combined_texts(holders, SEED),
    }
    use_values(pool_values({*everything, *candidates}, everything))
    return first, everything, candidates, utf8


def build() -> tuple[dict[str, list[dict[str, Any]]], dict[str, int]]:
    """The cases of each file, as the reference produced them, and the counts."""
    rows = random_rows(SEED, ROWS)
    first, everything, candidates, utf8 = _regions_policy(rows)
    kept = [text for text in everything if exportable(text)]
    dirty = [text for text in everything if not exportable(text)]
    minhash, dropped_minhash = _minhash_cases(first)
    near_dedup, found = near_dedup_cases(rows)
    cases, window_counts = _findings_cases(kept, dirty)
    minhash, lines = _safe(minhash)
    dropped_minhash += lines
    near_dedup, lines = _safe(near_dedup)
    found["dropped_flagged_near_dedup"] += lines
    cases, lines = _safe(cases)
    credentials, shapes = credential_cases({*candidates, *dirty, *windows(dirty)})
    files = {
        "minhash.jsonl": minhash,
        "near_dedup.jsonl": near_dedup,
        "findings.jsonl": cases,
        "credentials.jsonl": credentials,
        "classes.jsonl": [class_case()],
    }
    counts = {"dropped": utf8, **{name[:-6]: len(cases) for name, cases in files.items()}}
    counts.update((f"credentials_{shape}", number) for shape, number in sorted(shapes.items()))
    counts["dropped_flagged_minhash"] = dropped_minhash
    counts["dropped_flagged_findings"] = len(dirty) + window_counts.pop("dropped_windows") + lines
    counts.update(window_counts)
    counts.update(found)
    by_code = Counter(span[2] for case in cases for span in case["spans"])
    counts.update(sorted(by_code.items()))
    counts["signature_length"] = NUM_PERMUTATIONS
    counts.update(
        (f"classes_{name}", len(runs)) for name, runs in files["classes.jsonl"][0].items()
    )
    return files, counts


def export(out: Path) -> dict[str, int]:
    """Write the five files into ``out``; return how many cases each holds and more."""
    out.mkdir(parents=True, exist_ok=True)
    files, counts = build()
    for name, cases in files.items():
        _write(out / name, cases)
    return counts


if __name__ == "__main__":
    for name, count in export(Path(sys.argv[1])).items():
        print(f"{name}: {count}")
