"""The inputs and the checks the PII redaction properties run on (shared by several test files).

Not a test module: the inputs are every PII table the other tests pin, one sample of
each class, the shapes of row the scan reads, and a seeded generator of rows that mix
them. The checks are the three properties of a redaction by every class --
`scan(redact(x))` is empty, `redact(redact(x)) == redact(x)`, and the count of a class
is the number of its placeholders written -- plus the properties of redacting one class.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
import json
import random
import re
from typing import Any

from test_credentials import (
    MEMBERS,
    NEGATIVES as SECRET_NEGATIVES,
    POSITIVES as SECRET_POSITIVES,
    _key,
)
from test_detectors import NEGATIVES as DETECTOR_NEGATIVES, POSITIVES as DETECTOR_POSITIVES
from test_pii import LABELLED_CORPUS
from test_pii_json import CONTACT, NAMED, TOOL_CALL
from test_pii_rows import IDS, KEYS

from dagnam_contracts.hygiene.pii import (
    PII_CODES,
    PiiAction,
    apply_pii_policy,
    scan_rows,
)

ALL: dict[str, PiiAction] = dict.fromkeys(PII_CODES, "redact")

# Texts each class finds on its own, ending and starting in a digit and not.
SAMPLES: dict[str, list[str]] = {
    "PII_EMAIL": ["jane@example.com", "a.b+c@mail.example.co.uk"],
    "PII_PHONE": ["+44 20 7946 0958", "(415) 555-0132", "415.555.0132"],
    "PII_PAYMENT_CARD": ["4111 1111 1111 1111", "5500-0000-0000-0004", "4111111111111111"],
    "PII_NATIONAL_ID": ["078-05-1120"],
    "PII_SECRET": [
        "password: hunter22",
        "Pwd=letmein4",
        "api_key=abc123def456",
        "ftp://anonymous:pw@ftp.example.com/",
        _key("gh" + "p_", 36),
    ],
    "PII_IBAN": ["DE89 3704 0044 0532 0130 00", "GB29NWBK60161331926819"],
    "PII_IP_ADDRESS": ["192.168.1.20", "2001:db8::1"],
    "PII_DATE_OF_BIRTH": ["DOB: 14/03/1987"],
    "PII_UK_NINO": ["AB123456C"],
    "PII_CA_SIN": ["SIN 130 692 544", "SIN: 712345677"],
    "PII_IN_AADHAAR": ["Aadhaar Number 580927525309", "2345 6789 0124"],
    "PII_IN_PAN": ["ABCPE1234F"],
    "PII_EU_VAT": ["DE123456789", "NL123456789B01"],
}
SEPARATORS = [" ", "\t", ", ", "\n", "-", ""]

# Inputs that left a residue before redaction was made to settle by construction: the
# lists of numbers, the documents that read differently once redacted, the findings
# glued to a PEM block or to a keyword, a URL that is a port and an address.
TROUBLE: dict[str, str] = {
    "two phone numbers": "+44 20 7946 0958 +44 20 7946 0958",
    "a secret then a phone number": "password: hunter22 +1 415-555-0132",
    "a pwd value then a card": "Pwd=letmein4 4111111111111111",
    "an upper-case pwd value then a spaced card": "PWD=hunter22 4111 1111 1111 1111",
    "a named Aadhaar then a card": "Aadhaar Number 580927525309 5500-0000-0000-0004",
    "two named Aadhaar numbers then a card": (
        "AADHAAR NO. 234567890124 Aadhaar Number 234567890124 4111 1111 1111 1111"
    ),
    "17 numbers, one space apart": " ".join(f"+1415555{1000 + i}" for i in range(17)),
    "40 numbers, one space apart": " ".join(f"+1415555{1000 + i}" for i in range(40)),
    "40 numbers, one hyphen apart": "-".join(f"+1415555{1000 + i}" for i in range(40)),
    "a document that parses once its phone is replaced": (
        '{"note": "call +1 415\t555 0132", "password": 1234}'
    ),
    "a key that names a credential once its card is replaced": (
        '{"4111111111111111secret": "hello"}'
    ),
    "a member whose pwd value shows once its card is replaced": (
        '{"token": "x 4111111111111111pwd=abc"}'
    ),
    "a document that parses once its newline-split number is replaced": (
        '{"ids": "ids 2001 555\n0100 77", "password": 9}'
    ),
    "a URL password with a quote and a document": (
        '{"dsn": "postgres://app:pa"ss1@db/x", "api_key": 7}'
    ),
    "a URL with a port, a comma and an address": "http://localhost:8080,john@example.com",
    "a URL with a port, a semicolon and an address": "http://db:5432;ops@corp.example",
    "a query with a port, an ampersand and an address": "url=http://h:1&cc=a@b.co",
    "a URL with a port, a bar and an address": "http://localhost:3000|admin@x.co",
    "a URL with a port, a bracket and an address": "http://h:80>a@b.co",
    "a URL password and its host": "ftp://anonymous:pw@ftp.example.com/",
    "a password with a dotted cluster host": (
        "mongodb+srv://admin:Sup3rS3cret@cluster0.abcde.mongodb.net/db"
    ),
    "a placeholder glued to a value": "password=[REDACTED:PII_EMAIL]!x",
    "a secret placeholder glued to symbols": "password: <SECRET>!@#$",
    "a document member that is a placeholder": '{"password": "#$%^<SECRET>"}',
    "a card glued to a PEM block": (
        "4111111111111111-----BEGIN PRIVATE KEY-----\nMIIEow\n-----END PRIVATE KEY-----"
    ),
    "a card glued to an address": "4111111111111111jane@x.com",
    "a card glued to a SIN": "4111111111111111SIN 130 692 544",
    "a card glued to a URL scheme": "4111111111111111://u:pw@h",
    "two phone numbers with the known miss": "415-555-0132 415-555-0132",
    "a quantity then a card": "Qty 2 4111111111111111",
    "an order count then a spaced card": "order 12 4111 1111 1111 1111",
    "a password that is an address, as a document": '{"password": "a@b.co"}',
    "a password in code": 'cfg = {"client_secret": "abc"}',
    "a password that is an address": "password: jane@example.com",
    "a password of two addresses": "password: a@b.co/c@d.co",
    "a quoted pwd with spaces": 'Pwd="my pass phrase";',
    "a SIN after an address": "SIN a@b.co 130 692 544",
    "a phone number and a PEM block": (
        "+1415555 -----BEGIN PRIVATE KEY-----" + "x" * 500 + "-----END PRIVATE KEY----- 0132"
    ),
}

# Every input the PII tests pin, positive or near-miss, and the troublesome ones.
TEXTS: list[str] = sorted(
    {
        *(text for text, _ in LABELLED_CORPUS),
        *(template.format(value) for _, template, value in DETECTOR_POSITIVES),
        *(text for _, text in DETECTOR_NEGATIVES),
        *(template.format(secret) for _, template, secret in SECRET_POSITIVES),
        *(text for _, text in SECRET_NEGATIVES),
        *(json.dumps({key: value}) for key, value, _ in MEMBERS),
        CONTACT,
        NAMED,
        TOOL_CALL,
        *TROUBLE.values(),
    }
)

# A document that is not JSON until another class's finding (a raw tab inside a phone
# number) is replaced. A policy that redacts every class reads it as the document it
# becomes; one that redacts only the credential cannot, because the text it leaves still
# holds the tab. See `test_pii_policy.py`.
PARSES_ONLY_AFTER_REDACTION: list[str] = [
    TROUBLE["a document that parses once its phone is replaced"],
    TROUBLE["a document that parses once its newline-split number is replaced"],
]
# The inputs a single-class policy is held to the scan on, without that exception.
ONE_CLASS_TEXTS: list[str] = [t for t in TEXTS if t not in PARSES_ONLY_AFTER_REDACTION]

# Every shape of row the scan reads, each holding one input.
SHAPES: dict[str, Callable[[str], dict[str, Any]]] = {
    "plain text": lambda t: {"text": t},
    "two fields": lambda t: {"a": t, "b": t},
    "chat messages": lambda t: {
        "messages": [
            {"role": "system", "content": t},
            {"role": "user", "content": t},
            {"role": "assistant", "content": t},
        ]
    },
    "tool call with arguments as a JSON string": lambda t: {
        "messages": [
            {
                "role": "assistant",
                "tool_calls": [
                    {"function": {"name": "f", "arguments": json.dumps({"q": t, "n": [t]})}}
                ],
            }
        ]
    },
    "a structured row": lambda t: {"note": t, "items": [t, {"deep": t}], "n": 3, "ok": True},
    "a JSON document in a string": lambda t: {
        "text": json.dumps({"note": t, "items": [t, {"deep": t}]})
    },
    "a JSON document holding a JSON document": lambda t: {
        "text": json.dumps({"inner": json.dumps({"note": t, "k": [t]}), "n": 1})
    },
    "a JSON array in a string": lambda t: {"text": json.dumps([t, {"x": t}, 4])},
    "under a credential column": lambda t: {
        "password": t,
        "cfg": {"client_secret": [t, {"v": t}]},
    },
    "under an ambiguous column": lambda t: {"token": t, "row_key": t},
    "a brace that does not parse": lambda t: {"text": "{" + t + " not json"},
    "a labelled example": lambda t: {"input": t, "label": t[:40]},
    "a prompt and a response": lambda t: {
        "messages": [{"role": "user", "content": t}],
        "response": t,
    },
}
SHAPE_NAMES = sorted(SHAPES)


def document_rows() -> list[dict[str, Any]]:
    """Every input that is a JSON object, as the row itself and nested one level down."""
    documents: list[dict[str, Any]] = []
    for text in TEXTS:
        try:
            value = json.loads(text)
        except ValueError:
            continue
        if isinstance(value, dict):
            documents.append(value)
    documents += [dict(IDS), dict(KEYS)]
    return [*documents, *({"arguments": document} for document in documents)]


# Fragments for seeded random rows: every class in several formats, with noise.
FRAGMENTS: list[str] = sorted(
    {
        *(sample for samples in SAMPLES.values() for sample in samples),
        *(template.format(value) for _, template, value in DETECTOR_POSITIVES),
        *(template.format(secret) for _, template, secret in SECRET_POSITIVES),
        *(text for _, text in DETECTOR_NEGATIVES),
        *(text for _, text in SECRET_NEGATIVES),
        *list(TROUBLE.values())[:6],
        "<SECRET>",
        "[REDACTED:PII_EMAIL]",
        "[REDACTED:PII_OF_A_LATER_VERSION]",
        "hello",
        "4111111111111112",
        "order 130692544",
        "v1.2.3.4",
        "Qty 2",
        "id 3",
        "12",
        "x",
        "ünïcödé 日本語",
        "٠١٢٣٤٥٦٧٨٩",
        "a@",
        "://",
        "pwd=",
        "password:",
        "DOB:",
        "SIN",
        "Aadhaar Number",
    }
)


def random_rows(seed: int, count: int) -> list[dict[str, Any]]:
    """``count`` rows of one to six fragments in a shape, from `Random(seed)`: the same rows everywhere."""
    generator = random.Random(seed)
    rows: list[dict[str, Any]] = []
    for _ in range(count):
        size = generator.randint(1, 6)
        text = "".join(
            generator.choice(FRAGMENTS) + (generator.choice(SEPARATORS) if i < size - 1 else "")
            for i in range(size)
        )
        rows.append(SHAPES[generator.choice(SHAPE_NAMES)](text))
    return rows


_PLACEHOLDER = re.compile(r"\[REDACTED:(PII_[A-Z0-9_]+)\]|(<SECRET>)")


def found(rows: list[dict[str, Any]]) -> Counter[str]:
    """What a scan of ``rows`` counts, per class, classes with none left out."""
    return Counter({c: n for c, n in scan_rows(rows).counts_by_code.items() if n})


def placeholders(rows: list[dict[str, Any]]) -> Counter[str]:
    """The placeholders per class in the JSON text of ``rows``."""
    out: Counter[str] = Counter()
    for match in _PLACEHOLDER.finditer(json.dumps(rows, ensure_ascii=False)):
        out[match.group(1) or "PII_SECRET"] += 1
    return out


def everything_problems(row: dict[str, Any]) -> list[str]:
    """How redacting every class of ``row`` breaks a property; empty when none does.

    The rescan of the output is empty, redacting it again changes nothing, one row is
    changed exactly when the scan found something, and (for a row with no placeholder
    of its own to begin with) the placeholders written per class are the findings per class.
    """
    problems: list[str] = []
    original = found([row])
    redacted, changed, removed = apply_pii_policy([row], ALL)
    if rescan := found(redacted):
        problems.append(f"rescan {dict(rescan)}")
    again, changed_again, _ = apply_pii_policy(redacted, ALL)
    if again != redacted or changed_again:
        problems.append(f"second redaction {again!r}")
    if (changed == 1) != bool(original) or removed:
        problems.append(f"changed {changed}, removed {removed}, found {dict(original)}")
    if not placeholders([row]) and placeholders(redacted) != original:
        problems.append(f"found {dict(original)} wrote {dict(placeholders(redacted))}")
    return [f"{row!r} -> {redacted!r}: {problem}" for problem in problems]


def one_class_problems(row: dict[str, Any]) -> list[str]:
    """How redacting or dropping ONE class of ``row`` disagrees with the scan; empty when it agrees.

    For each class the scan finds: redacting it writes exactly the placeholders the scan
    counted, a rescan counts none of it, redacting again is a no-op and dropping it
    removes the row. Classes the scan does not find, all dropped at once, never change
    or drop the row.
    """
    problems: list[str] = []
    original = found([row])
    had_placeholders = bool(placeholders([row]))
    for code in original:
        only, _, _ = apply_pii_policy([row], {code: "redact"})
        kept, _, dropped = apply_pii_policy([row], {code: "drop"})
        if not had_placeholders and placeholders(only)[code] != original[code]:
            problems.append(f"{code} wrote {placeholders(only)[code]} of {original[code]}")
        if found(only)[code]:
            problems.append(f"{code} still counts {found(only)[code]} after its own redaction")
        if apply_pii_policy(only, {code: "redact"}) != (only, 0, 0):
            problems.append(f"{code} redacted twice differs")
        if dropped != 1 or kept:
            problems.append(f"{code} found but not dropped")
    absent: dict[str, PiiAction] = {code: "drop" for code in PII_CODES if not original[code]}
    if apply_pii_policy([row], absent) != ([row], 0, 0):
        problems.append("classes the scan does not find changed or dropped the row")
    return [f"{row!r}: {problem}" for problem in problems]


__all__ = [
    "ALL",
    "FRAGMENTS",
    "ONE_CLASS_TEXTS",
    "PARSES_ONLY_AFTER_REDACTION",
    "SAMPLES",
    "SEPARATORS",
    "SHAPES",
    "SHAPE_NAMES",
    "TEXTS",
    "TROUBLE",
    "document_rows",
    "everything_problems",
    "found",
    "one_class_problems",
    "placeholders",
    "random_rows",
]
