"""The credential cases of the reference corpus, stored as fragments.

Not a test module. No credential-shaped string, fake or not, may sit in a repository, so
``credentials.jsonl`` never holds one contiguously. A case is ``{"parts": [str],
"spans": [[start, end, code]]}``: the text is ``"".join(parts)`` and ``spans`` is what
`spans.findings` returns for it, offsets in code points, like ``findings.jsonl``.

The rule that splits a text into parts: every *credential region* is cut into pieces of
at most `PIECE` characters, and the text around the regions stays in whole plain parts.
A region is what `corpus_regions.regions` returns: the held spans, the markers with
their non-blank runs, the pool values and the name shapes, which is what puts a near
miss (a provider prefix followed by too little, a name and separator with no value) in
pieces although the reference finds nothing there.

A piece is cut shorter than `PIECE` where it would otherwise hold a whole marker, so
the raw bytes (``", "`` between parts) hold no marker and no run long enough for a
body pattern. Expected values are the reference's; the inputs are the texts earlier
rounds dropped plus the ones generated here.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable
import itertools
import random
import re
import string
from typing import Any

from corpus_atoms import (
    CONTEXT_LABELS,
    HELD_CODE,
    HOSTS,
    LABELLED_PREFIXES,
    NAMES as _NAMES,
    ODD_URLS,
    PEM_KINDS,
    PEM_WORDS,
    PROVIDER_PREFIXES,
    URL_LABEL,
    URL_SCHEMES,
    URL_SEP,
    URL_SPANS_FN,
    USERS,
    VALUES,
)
from corpus_inputs import encodable
from corpus_regions import PROVIDER_MARKERS, exportable, leaks, line_leaks, regions
from test_credentials import _key

from dagnam_contracts.hygiene import credentials as _finder
from dagnam_contracts.hygiene.spans import WINDOW, findings

PIECE = 4
# How far from a credential region the pieces reach, tried in turn; the last is all.
WIDENINGS = (0, 16, 64, 1 << 30)
_PREFIX_SHAPES = tuple(
    zip(
        LABELLED_PREFIXES,
        (
            "pem",
            "jwt",
            "openai_anthropic",
            "stripe",
            "stripe",
            "aws_key_id",
            "aws_key_id",
            "github",
            "slack",
            "google",
            "huggingface",
            "gitlab",
        ),
        strict=True,
    )
)
_CONTEXT_SHAPES = tuple(
    (re.compile(rf"(?i){word}{tail}"), word)
    for word, tail in zip(CONTEXT_LABELS, (r"\s+$", r"\s+$", r"=[\"']?$"), strict=True)
)
NAMES = list(_NAMES)
_url_spans: Callable[[str], list[tuple[int, int]]] = getattr(_finder, URL_SPANS_FN)
_SEPARATORS = [": ", "=", "= ", ":", '": "', "': '", '="', "='", "=\n", ":=", " => ", " -> "]


def _holds_marker(piece: str) -> bool:
    folded = piece.casefold()
    return any(marker in folded for marker in PROVIDER_MARKERS)


def pieces(region: str) -> list[str]:
    """``region`` in pieces of at most `PIECE` characters, none holding a whole marker."""
    out: list[str] = []
    at = 0
    while at < len(region):
        size = PIECE
        while size > 1 and _holds_marker(region[at : at + size]):
            size -= 1
        out.append(region[at : at + size])
        at += size
    return out


def fragments(text: str, widen: int = 0) -> list[str]:
    """The parts of ``text``: plain text whole, every credential region in pieces."""
    parts: list[str] = []
    at = 0
    for start, end in regions(text, widen):
        if start > at:
            parts.append(text[at:start])
        parts += pieces(text[start:end])
        at = end
    if at < len(text):
        parts.append(text[at:])
    return parts


def shape(text: str, start: int, end: int) -> str:
    """Which format of the finder the credential span ``text[start:end]`` is."""
    value = text[start:end]
    for prefix, name in _PREFIX_SHAPES:
        if value.startswith(prefix):
            return name
    if value.startswith(("gh", "github")) and "_" in value[:12]:
        return "github"
    if any(a < end and start < b for a, b in _url_spans(text)):
        return URL_LABEL
    for pattern, name in _CONTEXT_SHAPES:
        if pattern.search(text[:start]):
            return name
    if start > 0 and text[start - 1] in "\"'" and text[end : end + 1] == text[start - 1]:
        return "assignment_quoted"
    return "assignment_bare"


def _case(text: str, counts: Counter[str]) -> dict[str, Any]:
    spans = findings(text)
    shapes = {shape(text, s, e) for s, e, d in spans if d.code == HELD_CODE}
    counts.update(shapes or {"no_span"})
    encoded = [[s, e, d.code] for s, e, d in spans]
    # The serialised line must itself hold no credential for the finder: a plain part
    # that ends in a quoted name and its separator, and the pieces after it, read as an
    # assignment.
    # Widen the pieces over the neighbouring text, then over the whole text, until it does not.
    for widen in WIDENINGS:
        case = {"parts": fragments(text, widen), "spans": encoded}
        if not line_leaks(case):
            return case
    raise RuntimeError(f"a text of {len(text)} characters reads as a credential in pieces")


def credential_cases(texts: Iterable[str]) -> tuple[list[dict[str, Any]], Counter[str]]:
    """The cases of every text that holds a credential or a marker, and counts per shape."""
    counts: Counter[str] = Counter()
    kept = sorted({text for text in texts if encodable(text) and leaks(text)})
    return [_case(text, counts) for text in kept], counts


def clean_windows(texts: Iterable[str]) -> set[str]:
    """For each finding that is not a credential, in a text that holds a credential
    region, the `WINDOW` characters around it cut back to hold no region (and the
    reference's spans on the window are what a case then records)."""
    half = WINDOW // 2
    out: set[str] = set()
    for text in texts:
        found = regions(text)
        for start, end, detector in findings(text):
            if detector.code == HELD_CODE or any(a < end and start < b for a, b in found):
                continue
            low, high = max(0, start - half), min(len(text), end + half)
            for a, b in found:
                if b <= start:
                    low = max(low, b)
                elif a >= end:
                    high = min(high, a)
            window = text[low:high]
            if exportable(window) and findings(window):
                out.add(window)
    return out


def windows(texts: Iterable[str]) -> set[str]:
    """The `WINDOW` characters around every finding of every text, widened to hold every
    credential region they touch whole (a cut credential would still be readable)."""
    half = WINDOW // 2
    out: set[str] = set()
    for text in texts:
        found = regions(text)
        for start, end, _ in findings(text):
            low, high = max(0, start - half), min(len(text), end + half)
            touching = [(a, b) for a, b in found if a < high and low < b]
            low, high = (
                min([low, *(a for a, _ in touching)]),
                max([high, *(b for _, b in touching)]),
            )
            out.add(text[low:high])
    return out


def _random_run(generator: random.Random, size: int) -> str:
    alphabet = string.ascii_letters + string.digits + "_-"
    return "".join(generator.choice(alphabet) for _ in range(size))


def _provider_texts() -> set[str]:
    """Each provider format at the shortest length it takes, one shorter and one longer."""
    formats = list(
        zip(PROVIDER_PREFIXES, (20, 16, 16, 16, 16, 36, 36, 22, 10, 10, 35, 30, 20), strict=True)
    )
    wrappers = ["key {} end", "{}", "x{}", "{}x", '"{}"', "{}\n{}", "a={}&b=2", "({})"]
    texts: set[str] = set()
    for (prefix, least), size in itertools.product(formats, (-1, 0, 1, 28)):
        key = _key(prefix, max(least + size, 1))
        texts.update(wrapper.format(key, key + "Z") for wrapper in wrappers)
    return texts


def _assignment_texts() -> set[str]:
    first, second, digits = VALUES
    values = [first, second, "short", "Paris", "approved", "x1", digits]
    values.append(_key(LABELLED_PREFIXES[2], 30))
    wrappers = ["{}", "export {}", "{{{}}}", "cfg: {} ok", "?a=1&{}&b=2"]
    texts: set[str] = set()
    cells = itertools.product(NAMES, _SEPARATORS, values)
    for index, (name, separator, value) in enumerate(cells):
        quoted = separator.startswith(('"', "'"))
        head = (separator[0] + name if quoted else name) + separator
        tail = separator[0] if quoted else ""
        texts.add(wrappers[index % len(wrappers)].format(head + value + tail))
    return texts


def _refused_run_texts() -> set[str]:
    """An assignment inside a value an ambiguous name refuses (the R1 shapes).

    The refused value is 20 letters, which no ambiguous name vouches for. What follows
    it, joined by characters a value may hold, is read on its own: an assignment that
    takes any value, one that does vouch, a run cut by a colon, a run of names, and the
    joiners (`/ + . =`) that make the whole run one value when it holds a digit.
    """
    first, second, digits = VALUES
    ambiguous = [n for n in NAMES if _finder._credential_name(n) in _finder._AMBIGUOUS]
    anything = [n for n in NAMES if _finder._credential_name(n) not in {None, *_finder._AMBIGUOUS}]
    refused = "Paris" * 4
    joiners = ["?", "|", ":-", ":_", "#", "!", "@", "/", "+", ".", "=", "&", " "]
    values = [first, "horse" * 4, second, digits]
    wrappers = ["{}", "GET /x?{} ok", "export {}", "cfg: {};"]
    texts: set[str] = set()
    cells = itertools.product(ambiguous, _SEPARATORS[:3], joiners, anything)
    for index, (name, separator, joiner, other) in enumerate(cells):
        text = f"{name}{separator}{refused}{joiner}{other}={values[index % len(values)]}"
        texts.add(wrappers[index % len(wrappers)].format(text))
    for name, other in itertools.product(ambiguous, ambiguous):
        for tail in (second, "short", refused, f"{first}:{anything[0]}={second}"):
            texts.add(f"{name}={refused}?{other}={tail}")
        for unit in (f"a.{other}=", f"aa.{other}=:x", f"a-{other}=b:"):
            texts.add(f"{name}=?" + unit * 6)
            texts.add(f"{name}=?" + unit * 6 + second)
    return texts


def _url_and_pem_texts(generator: random.Random) -> set[str]:
    texts = {
        f"{scheme}{URL_SEP}{user}@{host}"
        for scheme in URL_SCHEMES
        for user in USERS
        for host in HOSTS
    }
    texts |= set(ODD_URLS)
    dash = "-" * 5
    opener, closer, private, public = PEM_WORDS
    for kind, body, end in itertools.product(PEM_KINDS, (0, 1, 3), ("end", "cut", "other")):
        lines = "\n".join(_random_run(generator, 64) for _ in range(body))
        tail = {
            "end": f"\n{dash}{closer}{kind}{private}{dash}",
            "cut": "",
            "other": f"\n{dash}{closer}{public}{dash}",
        }[end]
        texts.add(f"{dash}{opener}{kind}{private}{dash}\n{lines}{tail} after")
    texts.add(f"{dash}{opener}{public}{dash}\nabc\n{dash}{closer}{public}{dash}")
    return texts


def _jwt_texts(generator: random.Random) -> set[str]:
    head = LABELLED_PREFIXES[1]
    texts: set[str] = set()
    for first, second, third in itertools.product((9, 10, 18), (9, 10, 18), (0, 1, 30)):
        parts = [head + _random_run(generator, first), head + _random_run(generator, second)]
        for text in (".".join([*parts, _random_run(generator, third)]), ".".join(parts)):
            texts.add(f"jwt {text} end")
    return texts


def generated_texts(seed: int) -> set[str]:
    """Inputs the suite's tables do not hold: shapes, near misses, assignments, URLs, PEM, JWT."""
    generator = random.Random(seed)
    return (
        _provider_texts()
        | _assignment_texts()
        | _refused_run_texts()
        | _url_and_pem_texts(generator)
        | _jwt_texts(generator)
    )


def combined_texts(holders: list[str], seed: int) -> set[str]:
    """Several credential texts in one text, adjacent and overlapping ones, non-ASCII neighbours."""
    generator = random.Random(seed)
    short = [text for text in holders if len(text) <= 300]
    separators = [" ", "\n", "", "; ", ", ", " ", " ", "é"]
    neighbours = ["é ", "日本語: ", "😀 ", "\u0085", "x́ "]
    texts: set[str] = set()
    for _ in range(300):
        picks = generator.sample(short, generator.choice((2, 3, 4)))
        texts.add(generator.choice(separators).join(picks))
    for text in generator.sample(short, min(150, len(short))):
        texts.add(generator.choice(neighbours) + text + generator.choice(neighbours))
    return texts
