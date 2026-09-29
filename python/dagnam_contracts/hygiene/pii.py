"""
Best-effort PII detection over dataset rows, and the redact/drop/ignore policy
that acts on it.

**The governing constraint, which must survive into every surface that shows
these results:** a scan that misses things is worse than no scan if it implies
certification. Nothing here returns "clean", "safe" or "PII-free" — the result
model reports what was FOUND and, in `pass_list`, exactly which classes were
looked for, so a reader can see the boundary of the check rather than infer a
guarantee from an empty list. `PII_DISCLAIMER` is the copy the UI renders;
it lives here, beside the detectors, so it cannot drift from what they do.

**In-repo regex + Luhn, not presidio.** Decided against the labelled corpus in
`tests/hygiene/test_pii.py`, not in the abstract — that corpus
records the measured per-class recall (and the misses, named), and is the
thing to re-run before revisiting the choice. What it showed:

* the classes here are precisely the ones a pattern gets right — an
  email, a card number and a US SSN are *syntactic*, and Luhn is a checksum,
  not a guess; so is a credential with a provider's prefix or a PEM header
  (`PII_SECRET`, whose finder and precision rules live in `credentials.py`);
* presidio's advantage is entity types this scan does not claim (person
  names, addresses, locations), which need a NER model — i.e. an ML
  dependency, which this deliberately dependency-free package cannot carry;
* an auditable rule the user can read beats a black box for a feature whose
  whole framing is "best effort, here is what we looked for".

Adding a class means adding a `PiiDetector` to `PII_DETECTORS` — never an
``if class == ...`` branch in a task or a router, same rule the format
registry states.

A string that holds a JSON object or array is read value by value, by the
scan and the redaction alike: a card number that was a JSON number is redacted
to a JSON string rather than a bare placeholder no parser accepts, and a
member whose key names a credential is a `PII_SECRET` -- under an unambiguous
name (`{"password": ...}`) whatever its value, under `token`, `authorization`,
`auth` or `key` only when the value is a credential on its own
(`credentials.py` has the rule). A redacted document is re-serialised with `json.dumps`
defaults, so its spacing, duplicate keys and float spelling are normalised,
and two keys redacted to one placeholder collide (the later value wins). A
document that does not parse, or nests too deep to walk, is read as plain
text. `redact_json_text` is the same path for a caller holding JSON text.

Findings are `PiiIssue`-shaped on purpose — the same ``row_index`` / ``code``
/ ``message`` / ``severity`` record a row-level format issue uses, so a report
viewer renders them with no new type. Severity is ``"warning"``, never
``"error"`` — a row containing an email address is not malformed.

Pure — no session, no I/O.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import json
from typing import TYPE_CHECKING, Any, Literal

from dagnam_contracts.hygiene.detectors import (
    PII_CODES,
    PII_DETECTORS,
    REDACTION_TEMPLATE,
    PiiDetector,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping

PII_DISCLAIMER = (
    "Best-effort assistance, not certification. This scan looks only for the "
    "classes listed below, using pattern and checksum rules; it will miss "
    "personal data it was not built to recognise (names, addresses, free-text "
    "identifiers, anything in an unsupported locale). An empty result means "
    "nothing matched these rules — it does not mean the dataset is free of "
    "personal data, and no artifact produced here may be labelled as such."
)

PiiAction = Literal["redact", "drop", "ignore"]

_ALL_CODES = set(PII_CODES)


@dataclass(frozen=True, slots=True)
class PiiIssue:
    """One row-level PII finding.

    The same record shape as a row-level format-validation issue, so a
    report viewer that already renders those renders these with no new type.
    """

    row_index: int
    code: str
    message: str
    severity: Literal["error", "warning"] = "warning"


@dataclass(frozen=True, slots=True)
class PiiScanResult:
    """What the scan found, and — just as load-bearing — what it looked for."""

    issues: tuple[PiiIssue, ...] = ()
    """`PiiIssue`-shaped so an existing row-issue report viewer renders them."""
    counts_by_code: dict[str, int] = field(default_factory=dict)
    pass_list: tuple[str, ...] = ()
    """Every class this scan is capable of finding, present or not.

    Visible by contract: it is the only thing that lets a reader tell "we
    looked and found none" from "we never looked", and the difference between
    those two is the difference between assistance and a false guarantee.
    """
    disclaimer: str = PII_DISCLAIMER
    rows_scanned: int = 0


def _walk_strings(value: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Yield ``(json-ish path, text)`` for every string anywhere in `value`.

    Fully recursive, and it has to be: `chat-messages` — the platform's most
    common format — holds its text at ``messages[0].content``, two levels
    down inside a list of dicts. A one-level flatten would report zero
    findings on exactly the dataset shape a user is most likely to scan,
    which is the silent-miss failure this feature exists to avoid.
    """
    if isinstance(value, str):
        yield path or "<row>", value
    elif isinstance(value, dict):
        for key in sorted(value):
            yield from _walk_strings(value[key], f"{path}.{key}" if path else str(key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _walk_strings(item, f"{path}[{index}]")


def _map_strings(
    value: Any, transform: Callable[[str], tuple[str, Counter[str]]]
) -> tuple[Any, Counter[str]]:
    """Rebuild `value` with `transform` applied to every string inside it.

    The write-side mirror of `_walk_strings` — same traversal, so anything the
    scan can report is something the redactor can actually rewrite. Returns
    the new value and the findings per class.
    """
    if isinstance(value, str):
        return transform(value)
    total: Counter[str] = Counter()
    if isinstance(value, dict):
        rebuilt: dict[Any, Any] = {}
        for key, item in value.items():
            rebuilt[key], found = _map_strings(item, transform)
            total += found
        return rebuilt, total
    if isinstance(value, list):
        items: list[Any] = []
        for item in value:
            new_item, found = _map_strings(item, transform)
            items.append(new_item)
            total += found
        return items, total
    return value, total


def scan_rows(rows: list[dict[str, Any]], max_issues: int = 500) -> PiiScanResult:
    """Report every PII finding in `rows`, capped at `max_issues` samples.

    `counts_by_code` is complete regardless of the cap — the sample is
    bounded so a pathological dataset cannot produce an unbounded task
    result, but the totals a user decides on are not.
    """
    issues: list[PiiIssue] = []
    counts: dict[str, int] = dict.fromkeys(PII_CODES, 0)

    for row_index, row in enumerate(rows):
        for field_path, text in _walk_strings(row):
            _, found = _findings(text, _ALL_CODES)
            for detector in PII_DETECTORS:
                matched = found[detector.code]
                if not matched:
                    continue
                counts[detector.code] += matched
                if len(issues) < max_issues:
                    issues.append(
                        PiiIssue(
                            row_index=row_index,
                            code=detector.code,
                            message=(
                                f"{detector.label} matched {matched} time(s) in field {field_path!r}"
                            ),
                            severity="warning",
                        )
                    )

    return PiiScanResult(
        issues=tuple(issues),
        counts_by_code=counts,
        pass_list=PII_CODES,
        rows_scanned=len(rows),
    )


def _redact_text(text: str, codes: set[str]) -> tuple[str, Counter[str]]:
    """``text`` with every span the named detectors match replaced; the findings per class.

    Overlapping findings (an email inside a password value, a phone pattern
    over an IP address) are one region over their union, replaced once --
    replacing each in turn would cut the text at offsets the first replacement
    already moved -- and counted once, under the earliest finder that is not
    `PiiDetector.loose`.
    """
    hits = sorted(
        (
            (start, end, detector)
            for detector in PII_DETECTORS
            if detector.code in codes
            for start, end in detector.find(text)
        ),
        key=lambda hit: (hit[0], hit[1]),
    )
    regions: list[tuple[int, int, PiiDetector]] = []
    for start, end, detector in hits:
        if regions and start < regions[-1][1]:
            first, last, named = regions[-1]
            regions[-1] = (first, max(last, end), detector if named.loose else named)
        else:
            regions.append((start, end, detector))
    pieces: list[str] = []
    cursor = 0
    for start, end, detector in regions:
        pieces += (text[cursor:start], detector.replacement)
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces), Counter(detector.code for _, _, detector in regions)


def _member_text(value: Any) -> str | None:
    """A JSON member's value as text when it is a string or a number, else ``None``."""
    if isinstance(value, str):
        return value
    if isinstance(value, int | float) and not isinstance(value, bool):
        return json.dumps(value)
    return None


def _redact_member(key: str, value: Any, codes: set[str]) -> tuple[Any, Counter[str]]:
    """One member's value: whole, when a class finds it by its key; else like any value."""
    text = _member_text(value)
    for detector in PII_DETECTORS:
        if (
            text is not None
            and detector.member is not None
            and detector.code in codes
            and detector.member(key, text)
        ):
            return detector.replacement, Counter({detector.code: 1})
    return _redact_json_value(value, codes)


def _redact_json_value(value: Any, codes: set[str]) -> tuple[Any, Counter[str]]:
    """`value` with every string, key and number inside it redacted; the findings per class.

    A number that matched is replaced by the redacted text of it, a JSON
    string -- the placeholder is text, and a bare one is not JSON.
    """
    text = _member_text(value)
    if text is not None:
        redacted, found = _redact_text(text, codes)
        return (redacted if found or isinstance(value, str) else value), found
    total: Counter[str] = Counter()
    if isinstance(value, list):
        items: list[Any] = []
        for item in value:
            new_item, found = _redact_json_value(item, codes)
            items.append(new_item)
            total += found
        return items, total
    if isinstance(value, dict):
        rebuilt: dict[str, Any] = {}
        for key, item in value.items():
            new_key, key_found = _redact_text(key, codes)
            rebuilt[new_key], found = _redact_member(key, item, codes)
            total += key_found + found
        return rebuilt, total
    return value, total


def _redact_document(text: str, value: Any, codes: set[str]) -> tuple[str, Counter[str]]:
    """``text``, which parsed to ``value``, redacted and re-serialised only if it changed."""
    redacted, found = _redact_json_value(value, codes)
    return (json.dumps(redacted, ensure_ascii=False) if found else text), found


def _findings(text: str, codes: set[str]) -> tuple[str, Counter[str]]:
    """One string of a row, redacted for ``codes``, and what was found per class.

    Only a document that opens with ``{`` or ``[`` is read as JSON: a field of
    plain text that happens to parse as a number is still plain text. One that
    does not parse, or nests deeper than the parser or the walk can go
    (``RecursionError``), is read as plain text -- never a crash.
    """
    if text.lstrip()[:1] in ("{", "["):
        try:
            return _redact_document(text, json.loads(text), codes)
        except (ValueError, RecursionError):
            pass
    return _redact_text(text, codes)


def redact_json_text(text: str) -> tuple[str, int]:
    """Redact every PII class in JSON ``text`` and keep it JSON; ``(text, findings)``.

    Every string, key and number is redacted where it stands, and the value
    of a member whose key names a credential is replaced whole, so the result
    parses to the same shape; a number that matched becomes a JSON string.
    Text with nothing to redact comes back byte for byte. Text that is not
    JSON, or nests too deep to walk, is redacted as plain text.
    """
    try:
        redacted, found = _redact_document(text, json.loads(text), _ALL_CODES)
    except (ValueError, RecursionError):
        redacted, found = _redact_text(text, _ALL_CODES)
    return redacted, sum(found.values())


def apply_pii_policy(
    rows: list[dict[str, Any]], policy: Mapping[str, PiiAction]
) -> tuple[list[dict[str, Any]], int, int]:
    """Apply a per-class `policy` to `rows`.

    Returns ``(new_rows, rows_changed, rows_removed)``. A class absent from
    `policy` is treated as ``"ignore"``: the default is always to leave the
    user's data alone.

    ``"drop"`` beats ``"redact"`` for a row that matches both — dropping is
    the stricter answer, and a row the user asked to remove must not survive
    in redacted form because a different class happened to match it too.
    """
    unknown = sorted(set(policy) - set(PII_CODES))
    if unknown:
        raise ValueError(f"Unknown PII finding class(es): {', '.join(unknown)}")

    drop_codes = {code for code, action in policy.items() if action == "drop"}
    redact_codes = {code for code, action in policy.items() if action == "redact"}

    kept: list[dict[str, Any]] = []
    rows_changed = 0
    rows_removed = 0

    for row in rows:
        if drop_codes and any(_findings(text, drop_codes)[1] for _, text in _walk_strings(row)):
            rows_removed += 1
            continue

        if not redact_codes:
            kept.append(row)
            continue

        new_row, found = _map_strings(row, lambda text: _findings(text, redact_codes))
        rows_changed += int(bool(found))
        kept.append(new_row)

    return kept, rows_changed, rows_removed


__all__ = [
    "PII_CODES",
    "PII_DETECTORS",
    "PII_DISCLAIMER",
    "REDACTION_TEMPLATE",
    "PiiAction",
    "PiiDetector",
    "PiiIssue",
    "PiiScanResult",
    "apply_pii_policy",
    "redact_json_text",
    "scan_rows",
]
