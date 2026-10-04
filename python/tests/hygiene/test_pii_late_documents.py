"""Tests for `dagnam_contracts/hygiene/pii.py`: a document that parses only after its redaction.

A text that opens with a brace and is not JSON because of a raw line break inside a PEM
block becomes JSON once the block is a placeholder. The plain redaction runs first, and the
document is then walked: the member rules take whole values, which can take placeholders
the plain pass had just written, and a policy for one class sees the document only when its
own class is what made it parse. A document nested deeper than the walk reads is plain text,
on any stack.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from pii_corpus import ALL, SAMPLES, everything_problems, found, placeholders
from test_credentials import _key

from dagnam_contracts.hygiene.pii import apply_pii_policy

_PEM = "-----BEGIN PRIVATE KEY-----\nMIIEvQabcd\n-----END PRIVATE KEY-----"
_PHONE = SAMPLES["PII_PHONE"][0]
_AADHAAR = SAMPLES["PII_IN_AADHAAR"][1]
_GHP = _key("gh" + "p_", 36)


def _late_document(*members: tuple[str, str]) -> dict[str, str]:
    """A brace-opened text with a raw line break in a string: not JSON until the PEM goes."""
    return {"text": "{" + ", ".join(f'"{key}": "{value}"' for key, value in members) + "}"}


class TestWhatIsCountedInADocumentThatParsesLate:
    def test_a_member_taken_whole_leaves_fewer_placeholders_than_the_scan_counted(self) -> None:
        """The plain pass found a card and a `pwd=` value in the `password` value and wrote
        placeholders; the walk then replaced the whole value by one. The scan counts what it
        found, the redaction leaves one placeholder, and a policy that drops cards drops the
        row, as the count promises."""
        card = SAMPLES["PII_PAYMENT_CARD"][2]
        row = _late_document(("password", f"{card} pwd=None {_PEM}"))

        counts = found([row])
        redacted = apply_pii_policy([row], ALL)[0]

        assert counts["PII_PAYMENT_CARD"] == 1
        assert json.loads(redacted[0]["text"]) == {"password": "<SECRET>"}
        assert sum(counts.values()) > sum(placeholders(redacted).values())
        assert found(redacted) == {}
        assert apply_pii_policy(redacted, ALL) == (redacted, 0, 0)
        assert apply_pii_policy([row], {"PII_PAYMENT_CARD": "drop"}) == ([], 0, 1)

    def test_a_key_with_findings_that_ends_in_a_credential_name(self) -> None:
        key = f"{_PHONE}[REDACTED:PII_]{_AADHAAR}secret"
        row = _late_document((key, f"{_PEM} VPVBD9999"))

        redacted = apply_pii_policy([row], ALL)[0]

        assert found(redacted) == {}
        assert apply_pii_policy(redacted, ALL) == (redacted, 0, 0)

    def test_everything_else_is_counted_as_written(self) -> None:
        row = _late_document(("note", f"call {_PHONE}"), ("k", _PEM))

        assert everything_problems(row) == []


class TestAPolicyWhoseClassMadeItParse:
    def test_the_credential_members_are_replaced_when_the_secret_class_is_acted_on(self) -> None:
        """The PEM block is the policy's own class, and replacing it makes the text a
        document; its `password` member is then replaced too. A phone number elsewhere is
        not the policy's class and stays."""
        row = _late_document(("k", _PEM), ("ph", _PHONE))
        row["text"] = row["text"][:-1] + ', "password": 1234}'

        kept, changed, _ = apply_pii_policy([row], {"PII_SECRET": "redact"})

        assert changed == 1
        document = json.loads(kept[0]["text"])
        assert document == {"k": "<SECRET>", "ph": _PHONE, "password": "<SECRET>"}
        assert found([row])["PII_SECRET"] == placeholders(kept)["PII_SECRET"] == 2


def _from_a_deeper_stack(depth: int, call: Any) -> Any:
    return call() if depth == 0 else _from_a_deeper_stack(depth - 1, call)


def _nested(levels: int) -> dict[str, str]:
    """A member `"password": 9` (short, so only the member rule takes it) under `levels` lists."""
    return {"text": "[" * levels + '{"password": 9 }' + "]" * levels}


class TestADeepDocumentIsReadTheSameOnAnyStack:
    def test_nesting_up_to_the_walk_limit_is_read_as_a_document_on_any_stack(self) -> None:
        """The member is a secret 150 and 450 lists down, here or 300 frames further down."""
        assert sys.getrecursionlimit() >= 1000
        for levels in (50, 150, 450):
            row = _nested(levels)

            shallow = found([row])
            deeper = _from_a_deeper_stack(300, lambda row=row: found([row]))

            assert shallow == deeper
            assert shallow["PII_SECRET"] == 1
            assert everything_problems(row) == []

    def test_nesting_beyond_the_walk_is_plain_text_however_deep_the_stack_is(self) -> None:
        """600 and 5,000 lists are not read as a document, here or 300 frames further down:
        the number is not a secret as text, the call ends, and nothing is raised."""
        for levels in (600, 5000):
            row = _nested(levels)

            shallow = found([row])
            deeper = _from_a_deeper_stack(300, lambda row=row: found([row]))

            assert shallow == deeper == {}
