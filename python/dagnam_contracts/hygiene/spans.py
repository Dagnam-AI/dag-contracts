"""Where the PII findings in one string are, and how a redaction writes them.

**A placeholder is an opaque token.** A finding is a span inside one maximal run of
text that holds no placeholder (a *segment*), and whether it is reported is a function
of that segment alone, read as an independent string. The findings of a string are the
least fixed point of "detect in each piece, cut at the accepted spans, read every piece
left over again".

That is what makes a redaction scan clean *by construction*. Every pattern decides on
characters outside the span it reports (a digit before it, a keyword in front of it),
and a replacement rewrites exactly those characters: the card number that ends in the
character a phone pattern refuses to follow is a placeholder after the redaction, and
the phone is a finding on the next scan. Redacting again and again chases that, and has
to stop somewhere. Here the text a redaction leaves is, by definition, text in which every piece
read on its own holds no finding -- and the next scan reads exactly those pieces,
because it cuts at every placeholder the redaction wrote and at nothing else. A
placeholder cannot join user text into a longer placeholder (it opens with ``[`` or
``<`` and ends with ``]`` or ``>``), so there is no pass count to bound and no residue
past one.

Overlapping candidates from different classes are one region over their union (see
:func:`resolve`); no detector consults another class.

Cost: every piece is read whole once, and the text after each accepted span is read
again through a small window (`WINDOW`) -- the only place a finding that was hidden
by its neighbour can appear is the start of the text that follows it -- so a chain of
findings that each hide the next costs a window apiece, not a pass over the text.
Linear in the text.

Pure -- no I/O.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
import re

from dagnam_contracts.hygiene.detectors import PII_DETECTORS, REDACTION_TEMPLATE, PiiDetector

Span = tuple[int, int, PiiDetector]
"""``(start, end, detector)``, half-open, in the coordinates of the string it was found in."""

# Every placeholder a redaction writes: the template for any `PII_` code (so a class a
# later registry adds is opaque too) and each class's own placeholder.
PLACEHOLDER = re.compile(
    "|".join(
        [
            re.escape(REDACTION_TEMPLATE).replace(re.escape("{code}"), "PII_[A-Z0-9_]+"),
            *(re.escape(d.placeholder) for d in PII_DETECTORS if d.placeholder),
        ]
    )
)

# After an accepted span the text right after it is read as a string of its own through
# a window of this many characters, doubled while a candidate reaches the window's edge
# (so a long finding costs its own length).
WINDOW = 48
# A guard looks at most two characters past a span; a candidate that ends closer to the
# window's edge than this may read differently in the whole piece and is not trusted.
MARGIN = 3

_EVERY_CODE = frozenset(detector.code for detector in PII_DETECTORS)

# What a piece of text must hold before any detector can find anything in it: a letter or a
# digit, or an at sign. The address pattern needs no letter or digit (`_@_._` is one), and
# neither does a URL's password (`://:-@`), but both need the at sign; every other class
# needs a letter or a digit. Narrower than the union of the patterns' required characters
# would hide a finding from the read that decides it (`test_spans.py` enumerates each
# class's shortest match and fuzzes the converse), so this is derived from them, not guessed.
_CAN_HOLD_A_FINDING = re.compile(r"[^\W_]|@")


def segments(text: str) -> list[tuple[int, int]]:
    """Maximal runs of ``text`` between placeholders, as half-open ranges; empty runs dropped."""
    pieces: list[tuple[int, int]] = []
    cursor = 0
    for match in PLACEHOLDER.finditer(text):
        if match.start() > cursor:
            pieces.append((cursor, match.start()))
        cursor = match.end()
    if cursor < len(text):
        pieces.append((cursor, len(text)))
    return pieces


def member_text(text: str) -> str:
    """What a member rule reads of a value: its non-placeholder segments, one space apart.

    A value that is nothing but placeholders reads as empty, so it is never a credential;
    the space keeps a shape from forming across a placeholder.
    """
    return " ".join(text[a:b] for a, b in segments(text))


def _rank(span: Span) -> tuple[int, int, int, int]:
    start, end, detector = span
    # A class that is not `loose` first, then the earliest start, then the shorter span
    # (the more specific reading: a URL password inside `pw@host`), then registry order.
    return (int(detector.loose), start, end - start, PII_DETECTORS.index(detector))


def resolve(candidates: Iterable[Span]) -> list[Span]:
    """Overlapping candidates form one region over their union, replaced once and named
    by the best-ranked member.

    A union, not a drop: a value pattern that over-matches into a neighbouring number
    (``auth: sk-...(415) 555-0132``) must not leave the rest of that number as text.
    Its cost is that a host glued to a URL password through the email pattern goes with
    the password.
    """
    regions: list[tuple[int, int, Span]] = []  # (start, end, the best-ranked member)
    for span in sorted(candidates, key=lambda s: (s[0], s[1])):
        start, end, _ = span
        if regions and start < regions[-1][1]:
            first, last, best = regions[-1]
            regions[-1] = (first, max(last, end), min(best, span, key=_rank))
        else:
            regions.append((start, end, span))
    return [(start, end, best[2]) for start, end, best in regions]


def detect(piece: str) -> list[Span]:
    """Every detector's spans in ``piece``, read as an independent string.

    Always every class: a class a policy does not act on can still be what hides, or
    is hidden by, one it does, so the scan and every policy resolve the same set.
    """
    return [
        (start, end, detector)
        for detector in PII_DETECTORS
        for start, end in detector.find(piece)
        if end > start
    ]


def _cut(a: int, b: int, spans: list[Span]) -> list[tuple[int, int]]:
    """The non-empty pieces of ``[a, b)`` between ``spans``, in absolute coordinates."""
    pieces: list[tuple[int, int]] = []
    cursor = a
    for start, end, _ in spans:
        if start > cursor:
            pieces.append((cursor, start))
        cursor = end
    if cursor < b:
        pieces.append((cursor, b))
    return pieces


def _holds_content(piece: str) -> bool:
    """Whether any detector can find anything in ``piece`` (see `_CAN_HOLD_A_FINDING`)."""
    return _CAN_HOLD_A_FINDING.search(piece) is not None


def _shift(spans: list[Span], by: int) -> list[Span]:
    return [(start + by, end + by, detector) for start, end, detector in spans]


def findings(text: str, stats: Counter[str] | None = None) -> list[Span]:
    """Every finding in ``text``, sorted by start: a fixed point in which
    every piece of text left is clean when read as an independent string.

    Each segment is read whole; the text after every accepted span is then read again
    through `WINDOW` (the chain case), and the pieces neither reading settled go back on
    the worklist. Every step accepts a span or retires a piece, so the worklist empties.
    ``stats`` counts the ``full reads``, the ``windows`` and the ``characters read`` by
    both, for a caller that measures the cost.
    """
    counts: Counter[str] = Counter() if stats is None else stats
    out: list[Span] = []
    work = segments(text)
    while work:
        a, b = work.pop()
        counts["full reads"] += 1
        counts["characters read"] += b - a
        spans = resolve(detect(text[a:b]))
        if not spans:
            continue
        shifted = _shift(spans, a)
        out += shifted
        for p, q in _cut(a, b, shifted):
            if not _holds_content(text[p:q]):
                continue  # no letter, digit or at sign: nothing to find
            # Read the leftover piece from its start, one window at a time. A region of the
            # window that nothing near the window's edge can change is a region the whole
            # piece has too, so each such region is accepted and the text between them is
            # read as pieces of their own.
            width = WINDOW
            while p < q:
                edge = min(q, p + width)
                counts["windows"] += 1
                counts["characters read"] += edge - p
                window = text[p:edge]
                candidates = detect(window)
                regions = resolve(candidates)
                whole = edge == q
                limit = len(window) - MARGIN
                first = regions[0] if regions else None
                reaches = not whole and any(
                    end > limit and (first is None or start < first[1])
                    for start, end, _ in candidates
                )
                if reaches:
                    width *= 2  # a candidate may continue past the edge: look further
                    continue
                if first is None:
                    if not whole:
                        work.append((p, q))  # nothing in the window; the rest gets a full read
                    break
                cursor = 0
                for start, end, detector in regions:
                    if not whole and end > limit:
                        break  # near the edge: the next window reads it
                    out.append((p + start, p + end, detector))
                    if start > cursor and _holds_content(window[cursor:start]):
                        work.append((p + cursor, p + start))  # its right edge changed
                    cursor = end
                p += cursor
                width = WINDOW
    out.sort(key=lambda span: span[0])
    return out


def rounds_needed(text: str) -> int:
    """How many times `findings` reads a piece whole on ``text``: the cost measure the
    tests pin (windows are bounded; whole reads are what could grow with the text)."""
    stats: Counter[str] = Counter()
    findings(text, stats)
    return stats["full reads"]


def render(text: str, spans: list[Span], act: Iterable[str]) -> str:
    """``text`` with every span of a class in ``act`` replaced by its placeholder, in one pass."""
    acting = set(act)
    pieces: list[str] = []
    cursor = 0
    for start, end, detector in spans:
        if detector.code in acting:
            pieces += (text[cursor:start], detector.replacement)
            cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def redact_both(text: str, act: Iterable[str]) -> tuple[str, str, Counter[str]]:
    """``(fully redacted, redacted for act only, findings per class over every class)``.

    One placeholder is written per acted span, so the count of an acted class equals the
    placeholders of it written; a class outside ``act`` is counted and left as text, so
    a policy acts on exactly what the scan reports.
    """
    spans = findings(text)
    if not spans:
        return text, text, Counter()
    full = render(text, spans, _EVERY_CODE)
    acting = set(act)
    acted = full if acting >= _EVERY_CODE else render(text, spans, acting)
    return full, acted, Counter(detector.code for _, _, detector in spans)


__all__ = [
    "MARGIN",
    "PLACEHOLDER",
    "WINDOW",
    "Span",
    "detect",
    "findings",
    "member_text",
    "redact_both",
    "render",
    "resolve",
    "rounds_needed",
    "segments",
]
