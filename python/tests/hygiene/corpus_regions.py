"""What makes a text credential-shaped, for the reference corpus.

Not a test module. No credential-shaped string, fake or not, may sit in a repository,
and "credential-shaped" is wider than "the reference finds it": the reference reads a
credential in context, and a text it passes (a header with a short value, an assignment
with a short value) is as readable in a file. A *credential region* of a
text is the union of

* every span the reference reports as a held credential (`HELD_CODE`);
* every marker (`PROVIDER_MARKERS`, case-folded) with the unbroken non-blank run around it;
* every occurrence (case-folded) of a *pool value*: a value of six or more characters
  that the reference reports, from any candidate text of any file, so a value fragmented
  in one case is not whole in another, and the sample key of the AWS
  documentation (`DOC_VALUES`);
* every match of a *name shape* (`NAME_SHAPES`), found from every position of the text so
  that a second name inside the first match is found too: a credential-like name (and up
  to sixteen word characters or hyphens after it), a separator (a colon, an equals sign,
  ``:=``, ``=>`` or ``->``) and at least three characters of value, or a header that names
  a scheme;
* every URL whose host part holds credentials (`USERINFO`): a scheme (or none), two
  slashes, and anything but a slash or a blank up to the last ``@`` before one, whether
  or not it holds a colon.

A text with a region is credential-shaped. ``use_values`` sets the pool values the
regions use; the exporter calls it once its candidates are known.

The sources of this feature hold no credential-shaped string either, and no name, value,
prefix or header: each is built from the pieces of `corpus_atoms`.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from functools import cache
import re
from typing import Any

from corpus_atoms import DOC_VALUES, HEADER, HEADER_SCHEMES, HELD_CODE, MARKERS, NAME_PATTERNS
from corpus_inputs import dumps, encodable, leaves

from dagnam_contracts.hygiene.spans import findings

# The markers a text may hold (compared case-folded): provider prefixes, the literal
# prefixes of the shapes in `hygiene/credentials.py`, and the words a header or a settings
# file puts before a value.
PROVIDER_MARKERS = MARKERS

_BLANK = re.compile(r"\s")
_NAME = "(?:" + "|".join(NAME_PATTERNS) + r")[\w-]{0,16}"
_SEPARATOR = r"(?::=|=>|->|[:=])"
_AROUND = r"[\s\\\"']*"
_SCHEMES = "|".join(HEADER_SCHEMES)
# A zero-width match that captures the shape: one is found at EVERY position, so the name
# inside the value of an earlier match is a match of its own (``finditer`` on the shape
# itself would continue after the first match's greedy value).
NAME_SHAPES = (
    re.compile(rf"(?i)(?=({_NAME}{_AROUND}{_SEPARATOR}{_AROUND}\S{{3,}}))"),
    re.compile(rf"(?i)(?=({HEADER}\s*:\s*(?:{_SCHEMES})\s+\S+))"),
)
USERINFO = re.compile(r"(?=([\w+.-]*://[^/\s]*@))")
_PREFIX = 6
COMMON = 3
Index = dict[str, list[str]]
_state: dict[str, Index] = {"values": {}, "safe": {}}
_active: list[frozenset[str]] = [frozenset()]


def _index(values: Iterable[str]) -> Index:
    index: Index = {}
    for value in sorted({v.casefold() for v in values}):
        if len(value) >= _PREFIX:
            index.setdefault(value[:_PREFIX], []).append(value)
    return index


def line_safe(value: str) -> bool:
    """Whether ``value`` is written in a JSON line exactly as it is (no quote, backslash or
    control character), so that it can be looked for in raw bytes. A value that holds
    ``", "`` or ``": [`` would be found in the line's own punctuation."""
    return value.isprintable() and '"' not in value and "\\" not in value


def pool_values(texts: Iterable[str], originals: Iterable[str]) -> frozenset[str]:
    """The held values of six or more characters in ``texts``, and `DOC_VALUES`.

    A value of letters only, or of digits only, that also stands outside any held span
    in `COMMON` or more of the ``originals`` (not the windows and combinations cut from
    them, which would count a value whose context was cut away) is an ordinary word or
    number the corpus uses freely (``approved``, ``Aadhaar``, a short run of digits): it
    is not a pool value, or every text that
    says it would be a credential. A value that mixes the two, or has a symbol, always is
    one, wherever the reference misses it (inside escaped JSON, say).
    """
    everything = list(texts)
    originals = list(originals)
    spans = {
        text: [(s, e) for s, e, d in findings(text) if d.code == HELD_CODE]
        for text in {*everything, *originals}
    }
    found = {text[s:e] for text in everything for s, e in spans[text] if e - s >= _PREFIX}
    index = _index(found)
    free: Counter[str] = Counter()
    for text in originals:
        folded, origin = _folded(text)
        hits = _unfold(_occurrences(folded, index), origin)
        free.update(
            {
                text[a:b].casefold()
                for a, b in hits
                if not any(s <= a and b <= e for s, e in spans[text])
            }
        )
    words = {v for v in found if (v.isalpha() or v.isdigit()) and free[v.casefold()] >= COMMON}
    return frozenset((found - words) | set(DOC_VALUES))


def use_values(values: Iterable[str]) -> None:
    """Make ``values`` the pool the regions of every text are computed against."""
    values = list(values)
    _active[0] = frozenset(values)
    _state["values"] = _index(values)
    _state["safe"] = _index(value for value in values if line_safe(value))
    _raw_regions.cache_clear()


def active_values() -> frozenset[str]:
    """The pool values `use_values` last set."""
    return _active[0]


def _folded(text: str) -> tuple[str, list[int] | None]:
    """``text`` case-folded, and where each folded character came from (None if unchanged)."""
    folded = text.casefold()
    if len(folded) == len(text):
        return folded, None
    origin: list[int] = []
    for index, char in enumerate(text):
        origin.extend([index] * len(char.casefold()))
    return folded, origin


def _occurrences(folded: str, index: Index) -> list[tuple[int, int]]:
    hits: list[tuple[int, int]] = []
    for at in range(len(folded) - _PREFIX + 1):
        for value in index.get(folded[at : at + _PREFIX], ()):
            if folded.startswith(value, at):
                hits.append((at, at + len(value)))
    return hits


def _unfold(hits: list[tuple[int, int]], origin: list[int] | None) -> list[tuple[int, int]]:
    if origin is None:
        return hits
    return [(origin[start], origin[end - 1] + 1) for start, end in hits]


def _marker_runs(text: str, folded: str, origin: list[int] | None) -> list[tuple[int, int]]:
    """Every marker occurrence in ``text``, widened to the unbroken run around it."""
    runs: list[tuple[int, int]] = []
    for marker in PROVIDER_MARKERS:
        at = folded.find(marker)
        while at != -1:
            (start, end), *_ = _unfold([(at, at + len(marker))], origin)
            while start > 0 and not _BLANK.match(text[start - 1]):
                start -= 1
            while end < len(text) and not _BLANK.match(text[end]):
                end += 1
            runs.append((start, end))
            at = folded.find(marker, at + 1)
    return runs


@cache
def _raw_regions(text: str) -> tuple[tuple[int, int], ...]:
    """Every region source of ``text``, unmerged."""
    folded, origin = _folded(text)
    found = [(s, e) for s, e, d in findings(text) if d.code == HELD_CODE]
    found += _marker_runs(text, folded, origin)
    found += _unfold(_occurrences(folded, _state["values"]), origin)
    found += [m.span(1) for shape in (*NAME_SHAPES, USERINFO) for m in shape.finditer(text)]
    return tuple(found)


def regions(text: str, widen: int = 0) -> list[tuple[int, int]]:
    """The merged credential regions of ``text``, each reaching ``widen`` characters
    further on both sides (the name an assigned value belongs to, and what the written
    line puts after it)."""
    merged: list[tuple[int, int]] = []
    widened = ((max(0, s - widen), min(len(text), e + widen)) for s, e in _raw_regions(text))
    for start, end in sorted(widened):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def leaks(text: str) -> bool:
    """Whether ``text`` holds a credential region."""
    return bool(_raw_regions(text))


def exportable(text: str) -> bool:
    """Whether ``text`` may be written: UTF-8 encodable and credential-free."""
    return encodable(text) and not leaks(text)


def line_leaks(case: dict[str, Any]) -> bool:
    """Whether the written line of ``case`` reads as a credential: as raw text (JSON
    punctuation included) or in any decoded string. A local stand-in for a scanner that
    reads the raw bytes. The pool values are looked for in the raw line only when they are
    `line_safe`; every value is looked for in each decoded string."""
    line = dumps(case)
    folded, _ = _folded(line)
    return (
        any(d.code == HELD_CODE for _, _, d in findings(line))
        or any(marker in folded for marker in PROVIDER_MARKERS)
        or bool(_occurrences(folded, _state["safe"]))
        or any(shape.search(line) for shape in (*NAME_SHAPES, USERINFO))
        or any(leaks(leaf) for leaf in leaves(case))
    )
