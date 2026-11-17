"""The compiled core and the Python reference agree, input for input.

The reference is `findings`, `minhash_signature` and `compute_near_duplicates` with the
core switched off; the core is `dagnam_core.hygiene` called directly. The PII inputs are
built from the reference corpus (`pii_corpus.SAMPLES`) glued with arbitrary UTF-8 text, so
a span can start and end next to anything. Runs under both backends: neither run depends
on which one is active.
"""

from __future__ import annotations

from collections import Counter
import unicodedata

from dagnam_core import hygiene as core
from hypothesis import assume, given, settings, strategies as st
from pii_corpus import SAMPLES
import pytest
from test_credentials_flat import bare_walk_before_r1
from test_credentials_refused import _LONG, _PW_NAME, _WITH_DIGITS

from dagnam_contracts.hygiene import _backend, credentials, near_dedup, spans

_PIECES = st.sampled_from(sorted({s for group in SAMPLES.values() for s in group}))


# Arbitrary UTF-8 between the pieces: every code point that Unicode 3.2 assigned and whose
# general category has not changed since. That keeps the scripts, digits, combining marks,
# space separators and mathematical letters, and leaves out the characters that the core's
# tables (Unicode 15.1) and the interpreter's own may classify differently: those assigned
# in a later version, which is a difference of data tables, not of code, and would make this
# test depend on the interpreter it runs on (see the README).
def _stable(char: str) -> bool:
    return unicodedata.ucd_3_2_0.category(char) == unicodedata.category(char) != "Cn"


# The characters a hand-written `\w`, `\d` or `\s` gets wrong next to a span, drawn from
# ranges and filtered by the same rule (never typed as literals): combining marks, decimal
# digits of every script, Arabic and Devanagari letters, the fullwidth forms, the space
# separators and the right-to-left controls. Hypothesis draws non-ASCII text mostly from
# Latin-1, so without these a run of 2000 examples holds almost none of them.
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
    ]
    for char in map(chr, range(low, high + 1))
    if _stable(char)
]
_GLUE_CHARS = st.one_of(
    st.characters(codec="utf-8").filter(_stable),
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
    assert all(_stable(char) for char in _TRAPS)
    assert {unicodedata.category(char) for char in _TRAPS} >= {"Mn", "Nd", "Lo", "Zs", "Cf"}


def _reference_spans(text: str, *, before_r1: bool = False) -> list[tuple[int, int, str]]:
    """The spans of the Python reference; with ``before_r1`` its bare-value walk is the one
    it had before an assignment inside a refused value was found (`test_credentials_refused`)."""
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(_backend, "active", lambda: None)
        if before_r1:
            patch.setattr(credentials, "_bare_assignments", bare_walk_before_r1)
        return [(s, e, d.code) for s, e, d in spans.findings(text)]


@settings(max_examples=2000, deadline=None)
@given(_TEXTS)
def test_the_core_and_the_reference_find_the_same_spans(text: str) -> None:
    reference = _reference_spans(text)
    # The core of this release's pin has not learned the R1 fix: a text on which the reference
    # now reads differently is the one place they are meant to differ, until the pin moves
    # (the reference corpus holds those texts, and the core's own gate holds it to them).
    assume(reference == _reference_spans(text, before_r1=True))
    assert [tuple(span) for span in core.findings(text)] == reference


def test_the_pinned_core_has_not_learned_the_r1_fix_yet() -> None:
    """The canary for two temporary adjustments: the ``assume`` above, and the reference-only
    read of the texts the R1 fix changes in `test_corpus_credentials.py` (`_spans`).

    `dagnam-core` 0.1.1 binds ``CORE_API`` 1 and reads a value an ambiguous name refuses
    whole, so a password after it is missed. The day the pin moves to a core that has the
    fix (0.2.0), this fails: delete the ``assume``, the ``before_r1`` argument of
    `_reference_spans`, the reference-only branch of `_spans`, and this test, so that the
    core is held to the reference on every text again.
    """
    text = f"token={_LONG}?{_PW_NAME}={_WITH_DIGITS}"
    assert core.CORE_API == 1
    assert [tuple(span) for span in core.findings(text)] == _reference_spans(text, before_r1=True)
    assert _reference_spans(text) != _reference_spans(text, before_r1=True)


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
