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

* the four classes here are precisely the ones a pattern gets right — an
  email, a card number and a US SSN are *syntactic*, and Luhn is a checksum,
  not a guess;
* presidio's advantage is entity types this scan does not claim (person
  names, addresses, locations), which need a NER model — i.e. an ML
  dependency, which this deliberately dependency-free package cannot carry;
* an auditable rule the user can read beats a black box for a feature whose
  whole framing is "best effort, here is what we looked for".

Adding a class means adding a `PiiDetector` to `PII_DETECTORS` — never an
``if class == ...`` branch in a task or a router, same rule the format
registry states.

Findings are `PiiIssue`-shaped on purpose — the same ``row_index`` / ``code``
/ ``message`` / ``severity`` record a row-level format issue uses, so a report
viewer renders them with no new type. Severity is ``"warning"``, never
``"error"`` — a row containing an email address is not malformed.

Pure — no session, no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import TYPE_CHECKING, Any, Literal

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

REDACTION_TEMPLATE = "[REDACTED:{code}]"


def _luhn_ok(digits: str) -> bool:
    """Standard Luhn check over a digit string."""
    total = 0
    for position, char in enumerate(reversed(digits)):
        value = int(char)
        if position % 2:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


_CARD_CANDIDATE = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")


def _find_payment_cards(text: str) -> list[tuple[int, int]]:
    """Spans of 13-19 digit runs that pass Luhn.

    The Luhn check is what makes this class worth shipping: without it, every
    order id and phone number in the dataset is a false positive, and a scan
    that cries wolf gets switched off.
    """
    spans: list[tuple[int, int]] = []
    for match in _CARD_CANDIDATE.finditer(text):
        digits = re.sub(r"[ -]", "", match.group())
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            spans.append(match.span())
    return spans


# Not preceded by a digit, a `+`, or a digit-then-separator: the last of the
# three is what stops a 16-digit card number from yielding a 12-digit "phone"
# starting at its second group.
# `(?![\d]|[ -]\d)` is the important half: without it the pattern backtracks
# out of a 16-digit card number and reports its first 12 digits as a phone.
_PHONE_CANDIDATE = re.compile(r"(?<![\d+])(?<![\d][ -])\+?\d(?:[\d\s.()-]{7,20})\d(?![\d]|[ -]\d)")


def _find_phones(text: str) -> list[tuple[int, int]]:
    """Spans that look like a dialable number rather than a long id.

    Filters on top of the pattern, each removing a false positive the corpus
    actually produced: a leading ``+`` admits 9-15 digits, without one the
    floor rises to 10 (which is what stops a dashed 9-digit US SSN reading as
    a phone number); at least one separator or a leading ``+`` is required (a
    bare digit run is an order id far more often than a phone number); and no
    trailing digit, so a 23-digit id cannot yield a 14-digit "phone" from its
    prefix.
    """
    spans: list[tuple[int, int]] = []
    for match in _PHONE_CANDIDATE.finditer(text):
        raw = match.group()
        digits = re.sub(r"\D", "", raw)
        international = raw.startswith("+")
        if not (9 if international else 10) <= len(digits) <= 15:
            continue
        if not international and not re.search(r"[\s.()-]", raw):
            continue
        spans.append(match.span())
    return spans


def _regex_finder(pattern: re.Pattern[str]) -> Callable[[str], list[tuple[int, int]]]:
    def _find(text: str) -> list[tuple[int, int]]:
        return [match.span() for match in pattern.finditer(text)]

    return _find


@dataclass(frozen=True)
class PiiDetector:
    """One finding class: what it is called, and how to locate it in text."""

    code: str
    label: str
    find: Callable[[str], list[tuple[int, int]]]


PII_DETECTORS: tuple[PiiDetector, ...] = (
    PiiDetector(
        code="PII_EMAIL",
        label="Email address",
        find=_regex_finder(re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")),
    ),
    PiiDetector(code="PII_PHONE", label="Phone number", find=_find_phones),
    PiiDetector(code="PII_PAYMENT_CARD", label="Payment card number", find=_find_payment_cards),
    PiiDetector(
        code="PII_NATIONAL_ID",
        label="National identifier (US SSN)",
        # The area/group/serial rules are part of the pattern: 000/666/9xx
        # areas and 00 groups / 0000 serials are never issued, and excluding
        # them is what keeps ordinary 9-digit ids out of the results.
        find=_regex_finder(
            re.compile(r"(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])")
        ),
    ),
)

PII_CODES: tuple[str, ...] = tuple(detector.code for detector in PII_DETECTORS)


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


def _map_strings(value: Any, transform: Callable[[str], tuple[str, int]]) -> tuple[Any, int]:
    """Rebuild `value` with `transform` applied to every string inside it.

    The write-side mirror of `_walk_strings` — same traversal, so anything the
    scan can report is something the redactor can actually rewrite. Returns
    the new value and how many replacements were made.
    """
    if isinstance(value, str):
        return transform(value)
    if isinstance(value, dict):
        rebuilt: dict[Any, Any] = {}
        total = 0
        for key, item in value.items():
            rebuilt[key], count = _map_strings(item, transform)
            total += count
        return rebuilt, total
    if isinstance(value, list):
        items: list[Any] = []
        total = 0
        for item in value:
            new_item, count = _map_strings(item, transform)
            items.append(new_item)
            total += count
        return items, total
    return value, 0


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
            for detector in PII_DETECTORS:
                found = detector.find(text)
                if not found:
                    continue
                counts[detector.code] += len(found)
                if len(issues) < max_issues:
                    issues.append(
                        PiiIssue(
                            row_index=row_index,
                            code=detector.code,
                            message=(
                                f"{detector.label} matched {len(found)} time(s) in field {field_path!r}"
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


def _redact_text(text: str, codes: set[str]) -> tuple[str, int]:
    """Replace every span the named detectors match, right-to-left."""
    spans: list[tuple[int, int, str]] = []
    for detector in PII_DETECTORS:
        if detector.code in codes:
            spans.extend((start, end, detector.code) for start, end in detector.find(text))
    if not spans:
        return text, 0

    # Right-to-left so an earlier replacement cannot shift a later span's
    # offsets; overlapping matches from two detectors are applied
    # outermost-first and the inner one then finds nothing to move.
    redacted = text
    for start, end, code in sorted(spans, reverse=True):
        redacted = redacted[:start] + REDACTION_TEMPLATE.format(code=code) + redacted[end:]
    return redacted, len(spans)


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
        if drop_codes and any(
            detector.find(text)
            for _, text in _walk_strings(row)
            for detector in PII_DETECTORS
            if detector.code in drop_codes
        ):
            rows_removed += 1
            continue

        if not redact_codes:
            kept.append(row)
            continue

        new_row, replacements = _map_strings(row, lambda text: _redact_text(text, redact_codes))
        rows_changed += int(replacements > 0)
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
    "scan_rows",
]
