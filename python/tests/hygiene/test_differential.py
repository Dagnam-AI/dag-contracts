"""The compiled core and the Python reference agree, input for input.

The reference is `findings`, `minhash_signature` and `compute_near_duplicates` with the
core switched off; the core is `dagnam_core.hygiene` called directly. The PII inputs are
built from the reference corpus (`pii_corpus.SAMPLES`) glued with arbitrary UTF-8 text, so
a span can start and end next to anything. Runs under both backends: neither run depends
on which one is active.
"""

from __future__ import annotations

from collections import Counter

from dagnam_core import hygiene as core
from hypothesis import given, settings, strategies as st
from pii_corpus import SAMPLES
import pytest

from dagnam_contracts.hygiene import _backend, near_dedup, spans

_PIECES = st.sampled_from(sorted({s for group in SAMPLES.values() for s in group}))
# Arbitrary UTF-8 between the pieces, from blocks whose letters and digits every Unicode
# version agrees on (Latin, Greek, Cyrillic, punctuation, CJK ideographs, Hangul syllables) plus
# emoji, which are astral and not word characters. A character a later Unicode version
# adds (a letter in Python 3.14, not yet one in the core's tables) is a difference of
# data tables, not of code, and would make this test depend on the interpreter's version.
_GLUE_CHARS = st.one_of(
    *(
        st.characters(min_codepoint=low, max_codepoint=high, codec="utf-8")
        for low, high in [
            (0x00, 0x24F),
            (0x370, 0x52F),
            (0x2000, 0x206F),
            (0x4E00, 0x9FA5),
            (0xAC00, 0xD7A3),
            (0x1F300, 0x1F64F),
        ]
    )
)
_GLUE = st.text(alphabet=_GLUE_CHARS, max_size=12)
_TEXTS = st.lists(st.one_of(_PIECES, _GLUE), max_size=12).map("".join)

_WORDS = st.sampled_from(["alpha", "beta", "gamma", "delta", "eps", "zeta", "eta", "theta"])
_ROW_TEXTS = st.lists(_WORDS, max_size=14).map(" ".join)
_THRESHOLDS = st.sampled_from([0.1, 0.5, 0.75, 0.9, 1.0])


@settings(max_examples=2000, deadline=None)
@given(_TEXTS)
def test_the_core_and_the_reference_find_the_same_spans(text: str) -> None:
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(_backend, "active", lambda: None)
        reference = [(s, e, d.code) for s, e, d in spans.findings(text)]
    assert [tuple(span) for span in core.findings(text)] == reference


def _chain(*parts: tuple[str, int, str]) -> str:
    """Corpus samples, each followed by its glue: ``(class, index in SAMPLES[class], glue)``."""
    return "".join(SAMPLES[code][index] + glue for code, index, glue in parts)


# Texts whose findings hide one another, so the reference reads the leftovers through its
# windows: one makes a candidate reach the window's edge (the window doubles), the other
# ends a region next to the edge (the next window reads it). Random draws reach those two
# branches only now and then, and the 100% floor must not depend on a draw.
_CHAINS = [
    _chain(("PII_IBAN", 0, ""), ("PII_IBAN", 0, "\n"), ("PII_IN_PAN", 0, "")),
    _chain(
        ("PII_SECRET", 2, ""), ("PII_PHONE", 0, ""), ("PII_SECRET", 2, " "), ("PII_CA_SIN", 1, "-")
    ),
]


@pytest.mark.parametrize("text", _CHAINS)
def test_the_core_and_the_reference_agree_on_a_chain_of_hidden_findings(text: str) -> None:
    stats: Counter[str] = Counter()
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(_backend, "active", lambda: None)
        reference = [(s, e, d.code) for s, e, d in spans.findings(text)]
    spans.findings(text, stats)  # always the reference, whichever backend is active
    assert stats["windows"] > 0
    assert [tuple(span) for span in core.findings(text)] == reference


@settings(max_examples=500, deadline=None)
@given(_ROW_TEXTS)
def test_the_core_and_the_reference_sign_the_same_shingles(text: str) -> None:
    shingle_set = near_dedup.shingles(text)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(_backend, "active", lambda: None)
        reference = near_dedup.minhash_signature(shingle_set)
    assert tuple(core.minhash_signature(list(shingle_set))) == reference


@settings(max_examples=500, deadline=None)
@given(st.lists(_ROW_TEXTS, max_size=10), _THRESHOLDS)
def test_the_core_and_the_reference_find_the_same_near_duplicates(
    texts: list[str], threshold: float
) -> None:
    rows = [{"text": text} for text in texts]
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(_backend, "active", lambda: None)
        reference = near_dedup.compute_near_duplicates(rows, threshold)
    # The words carry no punctuation or capitals, so a row's text is its comparison string.
    duplicates, pairs = core.near_duplicates([near_dedup.row_text(row) for row in rows], threshold)
    assert list(duplicates) == reference.duplicate_indices
    assert [tuple(pair) for pair in pairs] == [
        (p.kept_index, p.duplicate_index, p.similarity) for p in reference.pairs
    ]
