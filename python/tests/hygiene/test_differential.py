"""The compiled core and the Python reference agree, input for input.

The reference is `findings`, `minhash_signature` and `compute_near_duplicates` with the
core switched off; the core is `dagnam_core.hygiene` called directly. The PII inputs are
built from the reference corpus (`pii_corpus.SAMPLES`) glued with arbitrary UTF-8 text, so
a span can start and end next to anything. Runs under both backends: neither run depends
on which one is active.
"""

from __future__ import annotations

from collections import Counter
import os
import unicodedata

from dagnam_core import hygiene as core
from hypothesis import given, settings, strategies as st
from pii_corpus import SAMPLES
import pytest

from dagnam_contracts.hygiene import _backend, near_dedup, spans

_PIECES = st.sampled_from(sorted({s for group in SAMPLES.values() for s in group}))


# `DAGNAM_DIFFERENTIAL_EXAMPLES` widens the run (50,000 for the check before a release).
_EXAMPLES = int(os.environ.get("DAGNAM_DIFFERENTIAL_EXAMPLES", "2000"))

# Arbitrary UTF-8 between the pieces: every code point there is, assigned or not. The core's
# tables are those of the interpreter's own Unicode version (`UNICODE_SUPPORTED` is checked
# before the core is used), so the two classify every character alike, and the run holds on
# every interpreter the core supports.
#
# The characters a hand-written `\w`, `\d` or `\s` gets wrong next to a span, drawn from
# ranges (never typed as literals): combining marks, decimal digits of every script, Arabic and
# Devanagari letters, the fullwidth forms, the space separators and the right-to-left controls;
# then the scripts Unicode added after 3.2 and after 15.0 (CJK Extension I, Egyptian
# hieroglyphs extended-A, Ol Onal), which a draw reaches only now and then. Hypothesis draws
# non-ASCII text mostly from Latin-1, so without these a run of 2000 examples holds almost none.
_TRAPS = [
    char
    for low, high in [
        (0x0300, 0x036F),
        (0x0620, 0x064A),
        (0x0660, 0x0669),
        (0x0905, 0x0939),
        (0x0966, 0x096F),
        (0x2000, 0x200F),
        (0x202A, 0x202E),
        (0x2066, 0x2069),
        (0x3000, 0x3000),
        (0xFF01, 0xFF5E),
        (0x1D7CE, 0x1D7FF),
        (0x13460, 0x143FA),
        (0x1E5D0, 0x1E5FF),
        (0x2EBF0, 0x2EE5D),
    ]
    for char in map(chr, range(low, high + 1))
]
_GLUE_CHARS = st.one_of(
    st.characters(codec="utf-8"),
    st.sampled_from(_TRAPS),
)
_GLUE = st.text(alphabet=_GLUE_CHARS, max_size=12)
_TEXTS = st.lists(st.one_of(_PIECES, _GLUE), max_size=12).map("".join)

_WORDS = st.sampled_from(
    ["alpha", "beta", "gamma", "delta", "eps", "zeta", "eta", "theta", "café", "日本語", "ﬁn"]
)
_ROW_TEXTS = st.lists(_WORDS, max_size=14).map(" ".join)
_THRESHOLDS = st.sampled_from([0.1, 0.5, 0.75, 0.9, 1.0])


def test_the_alphabet_holds_the_characters_a_hand_ported_class_gets_wrong() -> None:
    for char in ["\u0301", "\u0663", "\u0915", "\u0967", "\uff11", "\u200f", "\u202e", "\u3000"]:
        assert char in _TRAPS, hex(ord(char))
    assert {unicodedata.category(char) for char in _TRAPS} >= {"Mn", "Nd", "Lo", "Zs", "Cf"}


def _reference_spans(text: str) -> list[tuple[int, int, str]]:
    """The spans of the Python reference, whichever backend is active."""
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(_backend, "active", lambda: None)
        return [(s, e, d.code) for s, e, d in spans.findings(text)]


@settings(max_examples=_EXAMPLES, deadline=None)
@given(_TEXTS)
def test_the_core_and_the_reference_find_the_same_spans(text: str) -> None:
    assert [tuple(span) for span in core.findings(text)] == _reference_spans(text)


def test_the_core_binds_the_contract_this_release_was_written_against() -> None:
    assert core.CORE_API == _backend.CORE_API
    assert core.UNICODE_SUPPORTED


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


@settings(max_examples=_EXAMPLES // 4, deadline=None)
@given(_ROW_TEXTS)
def test_the_core_and_the_reference_sign_the_same_shingles(text: str) -> None:
    shingle_set = near_dedup.shingles(text)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(_backend, "active", lambda: None)
        reference = near_dedup.minhash_signature(shingle_set)
    assert tuple(core.minhash_signature(list(shingle_set))) == reference


@settings(max_examples=_EXAMPLES // 4, deadline=None)
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
