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
text; and when what that redaction leaves parses (a raw tab inside a phone
number was what kept it from parsing), the result is walked as a document too,
once. `redact_json_text` is the same path for a caller holding JSON text.

The row itself, and every object nested in it, gets the member rule for the
credential column names only: the value under `password`, `client_secret` and the
like is a `PII_SECRET`, string or number. A name counts when it is, or ends in as a
word of its own, one of the unambiguous names (`db_password`, `userPassword`,
`aws-secret-access-key`), unless it opens with `has`, `is`, `needs`, `requires`,
`use`, `allow`, `enable`, `enabled`, `show`, `with`, `no` or `top`, which makes it a
flag or a label (`has_password`, `is_secret`, `top_secret`); `password_hint` and
`passwords` are not credential names. A boolean, `None`, a blank string and a
flag-like one (`yes`, `no`, `true`, `false`, `n/a`, `none`, `null`, `-`, in any
case) under such a name is not a secret; a list or an object under it has each
scalar in it replaced by that rule, at any depth. That is all a row shares with a
document, because a row's keys are column names:

* `token`, `authorization`, `auth` and `key` decide nothing in a row. A column
  named `row_key`, `idempotency_key` or `nextPageToken` holds ids, and a drop
  policy would lose every row of a dataset keyed on one. The value is still
  scanned as text, so a credential in a known format under such a name is found.
* A bare number in a row is not scanned. A card number held as a number is
  left alone: an id or a timestamp column would read as a card one row in ten
  and come back as a string.
* A row's keys are not redacted, at any depth.

**Redacted rows scan clean, by construction.** The platform scans again what the SDK
redacted and uploaded, so a placeholder is an opaque token: text that is already a
redaction placeholder -- any class's -- is never a finding, and a finding is decided
on one run of text between placeholders read as a string of its own (`spans.py` has the
argument). Redaction replaces every finding in one pass, so, for every row shape and
every policy that redacts every class:

* `scan(redact(rows))` finds nothing;
* `redact(redact(rows)) == redact(rows)`;
* the count a scan gives for the original, per class, is the number of placeholders
  of that class the redaction wrote -- except that two keys of a document that redact to
  the same placeholder collide (one member takes the other's place), and that in a document
  which parses only once its own redaction has replaced something, a member taken whole
  removes the placeholders of the findings in its value, which the scan counted.

There is no exception clause and no pass limit: findings glued together, a list of
any length, a document that only parses after its own redaction, a key or a member
whose reading changes when the text beside it is replaced, all settle in the one call.
`tests/hygiene/test_pii_rescan.py`, `test_pii_adjacent.py` and `test_pii_policy.py` hold
this over every input the PII tests pin, in every row shape, over every pair and
triple of classes in each separator, and over seeded random rows.

**Policies.** The scan is the single source of truth: it resolves every class, and a
policy resolves every class too and then acts on its subset. A class set to `redact`
has exactly the findings the scan reports for it replaced -- a phone number that only
reads as one once a neighbouring secret is a finding is replaced by a phone-only policy
too -- and a class set to `drop` drops the row when the scan reports one. Nothing more
is promised for a policy that redacts only some classes: once class A's text is
replaced, text of B that was glued to it or joined to it by one separator may read
differently, so a later scan of a partly redacted row can count a different number of B,
and can still report more of A (replacing a finding can lift a guard that was refusing a
neighbour). A document that parses only once some classes are replaced has its credential
members replaced when the policy redacts the classes that made it parse; one that
does not leaves the members to a policy that does. Redacting every class has no such
caveat.

Findings are `PiiIssue`-shaped on purpose — the same ``row_index`` / ``code``
/ ``message`` / ``severity`` record a row-level format issue uses, so a report
viewer renders them with no new type. Severity is ``"warning"``, never
``"error"`` — a row containing an email address is not malformed.

Pure — no session, no I/O.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
import json
from typing import Any, Literal

from dagnam_contracts.hygiene.detectors import (
    PII_CODES,
    PII_DETECTORS,
    REDACTION_TEMPLATE,
    PiiDetector,
)
from dagnam_contracts.hygiene.rows import redact_document, redact_fields, redact_string

PII_DISCLAIMER = (
    "Best-effort assistance, not certification. This scan looks only for the "
    "classes listed below, using pattern and checksum rules; it will miss "
    "personal data it was not built to recognise (names, addresses, free-text "
    "identifiers, anything in an unsupported locale) and a credential in a "
    "format it does not know. An empty result means nothing matched these "
    "rules — it does not mean the dataset is free of personal data or of "
    "secrets, and no artifact produced here may be labelled as such."
)

PiiAction = Literal["redact", "drop", "ignore"]

_ALL_CODES = frozenset(PII_CODES)


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


def scan_rows(rows: list[dict[str, Any]], max_issues: int = 500) -> PiiScanResult:
    """Report every PII finding in `rows`, capped at `max_issues` samples.

    `counts_by_code` is complete regardless of the cap — the sample is
    bounded so a pathological dataset cannot produce an unbounded task
    result, but the totals a user decides on are not.
    """
    issues: list[PiiIssue] = []
    counts: dict[str, int] = dict.fromkeys(PII_CODES, 0)

    for row_index, row in enumerate(rows):
        for field_path, found in redact_fields(row, _ALL_CODES)[1]:
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


def redact_json_text(text: str) -> tuple[str, int]:
    """Redact every PII class in JSON ``text`` and keep it JSON; ``(text, findings)``.

    Every string, key and number is redacted where it stands, and the value
    of a member whose key names a credential is replaced whole, so the result
    parses to the same shape; a number that matched becomes a JSON string.
    Text with nothing to redact comes back byte for byte. Text that is not
    JSON, or nests too deep to walk, is redacted as plain text.
    """
    try:
        document: Any = json.loads(text)
    except (ValueError, RecursionError):
        _, redacted, found = redact_string(text, _ALL_CODES)
    else:
        _, redacted, found = redact_document(text, document, _ALL_CODES)
    return redacted, sum(found.values())


def redact_rows(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Redact every class in `rows`; ``(rows, counts_by_code)``.

    The redact-everything policy in one call, and what a client does last before it
    uploads: ``scan_rows`` of the result finds nothing, and ``counts_by_code`` (every
    class, zero included) is what `scan_rows` of the input reports, which is also the
    number of placeholders of each class written. A row with nothing to redact is
    returned as the same object. Redact the row exactly as it will be uploaded --
    after any cut to a length, after any case folding -- and never cut it afterwards:
    a cut can split a placeholder into text a scan reads.
    """
    redacted: list[dict[str, Any]] = []
    counts: dict[str, int] = dict.fromkeys(PII_CODES, 0)
    for row in rows:
        new_row, fields = redact_fields(row, _ALL_CODES)
        for _, found in fields:
            for code, matched in found.items():
                counts[code] += matched
        redacted.append(new_row if fields else row)
    return redacted, counts


def apply_pii_policy(
    rows: list[dict[str, Any]], policy: Mapping[str, PiiAction]
) -> tuple[list[dict[str, Any]], int, int]:
    """Apply a per-class `policy` to `rows`.

    Returns ``(new_rows, rows_changed, rows_removed)``. A class absent from
    `policy` is treated as ``"ignore"``: the default is always to leave the
    user's data alone.

    Every class is resolved, as the scan does, and the policy acts on its subset: a
    row is removed when the scan reports a class set to ``"drop"`` in it, and a
    ``"redact"`` class has exactly the spans the scan reports for it replaced.

    ``"drop"`` beats ``"redact"`` for a row that matches both — dropping is
    the stricter answer, and a row the user asked to remove must not survive
    in redacted form because a different class happened to match it too.
    """
    unknown = sorted(set(policy) - _ALL_CODES)
    if unknown:
        raise ValueError(f"Unknown PII finding class(es): {', '.join(unknown)}")

    drop_codes = {code for code, action in policy.items() if action == "drop"}
    redact_codes = frozenset(code for code, action in policy.items() if action == "redact")

    kept: list[dict[str, Any]] = []
    rows_changed = 0
    rows_removed = 0

    for row in rows:
        new_row, fields = redact_fields(row, redact_codes)
        found: Counter[str] = Counter()
        for _, per_field in fields:
            found += per_field
        if any(found[code] for code in drop_codes):
            rows_removed += 1
        elif new_row != row:
            # A class that is found but not acted on leaves the row as it was; so does
            # a document that only parses once another class is replaced (see
            # `rows.redact_string`), when that class is not among the ones to redact.
            rows_changed += 1
            kept.append(new_row)
        else:
            kept.append(row)

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
    "redact_rows",
    "scan_rows",
]
