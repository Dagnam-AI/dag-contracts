"""Tests for `dagnam_contracts/hygiene/pii.py`: a member whose KEY holds a finding.

The rule that takes a member of a JSON document whole reads its key, and a key is itself
text that gets redacted. If a finding swallows the credential word (an address whose
domain runs on into `_password`), the redacted key no longer names a credential, but the
key as it was given does, and the value is the credential. The rule must read both.
"""

from __future__ import annotations

import json
from typing import Any

from pii_corpus import ALL, SAMPLES, SHAPES, everything_problems, found
import pytest

from dagnam_contracts.hygiene.credentials import is_credential_member
from dagnam_contracts.hygiene.pii import apply_pii_policy, redact_json_text, redact_rows

_MAIL = "alice@example.com"
_TOKEN = "a1B2c3D4e5F6g7H8i9J0"
# Names a document member is a credential under, with a value each takes.
_UNAMBIGUOUS = ["password", "passwd", "secret", "api_key", "apiKey", "client_secret"]
_AMBIGUOUS = ["token", "auth", "key"]
_GLUES = ["", "_", "-", "."]
# Shapes in which the document string is a leaf of the row, so the member rule applies.
_DOCUMENT_SHAPES = [
    "plain text",
    "two fields",
    "chat messages",
    "a structured row",
    "a prompt and a response",
]


def _redacted(row: dict[str, Any]) -> str:
    return json.dumps(apply_pii_policy([row], ALL)[0], ensure_ascii=False)


class TestTheKeyAsGivenAndAsRedacted:
    @pytest.mark.parametrize(
        ("key", "value"),
        [
            (_MAIL + "_password", "hunter2"),
            (_MAIL + "_password", "correct horse"),
            (_MAIL + "-token", _TOKEN),
            ("sk-" + "AbCdEfGhIjKlMnOpQrStUv12" + "_password", "hunter2"),
        ],
    )
    @pytest.mark.parametrize("shape", _DOCUMENT_SHAPES)
    def test_a_finding_that_takes_the_credential_word_leaves_the_value_redacted(
        self, key: str, value: str, shape: str
    ) -> None:
        """The email pattern reads the whole key as one address, so the redacted key is a
        placeholder. 0.4.0 replaced the value; a rule that read only the redacted key
        uploaded it, and the rescan, finding a placeholder and a short word, was clean."""
        row = SHAPES[shape](json.dumps({key: value}))

        assert is_credential_member(key, value)
        assert value not in _redacted(row)
        assert found([row])["PII_SECRET"] >= 1
        assert everything_problems(row) == []

    def test_the_same_in_tool_call_arguments(self) -> None:
        arguments = json.dumps({_MAIL + "_password": "correct horse"})
        row = {
            "messages": [
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{"function": {"name": "set", "arguments": arguments}}],
                }
            ]
        }

        # The arguments are a document held in a string inside the row: its members are read.
        assert "correct horse" not in _redacted(row)
        assert everything_problems(row) == []
        assert redact_json_text(arguments)[0] == json.dumps({"[REDACTED:PII_EMAIL]": "<SECRET>"})

    @pytest.mark.parametrize("nesting", ["object", "list", "deep"])
    def test_inside_nested_objects_and_lists(self, nesting: str) -> None:
        member = {_MAIL + "_password": "hunter2"}
        document = {
            "object": {"outer": member},
            "list": [member, 1],
            "deep": {"a": [{"b": {"c": [member]}}]},
        }[nesting]

        redacted, count = redact_json_text(json.dumps(document))

        assert "hunter2" not in redacted
        assert count == 2
        assert redact_json_text(redacted) == (redacted, 0)

    def test_a_policy_for_secrets_alone_replaces_the_value_and_leaves_the_key(self) -> None:
        row = {"text": json.dumps({_MAIL + "_password": "hunter2"})}

        kept, _, _ = apply_pii_policy([row], {"PII_SECRET": "redact"})

        assert json.loads(kept[0]["text"]) == {_MAIL + "_password": "<SECRET>"}
        assert apply_pii_policy([row], {"PII_EMAIL": "redact"})[0] == [
            {"text": json.dumps({"[REDACTED:PII_EMAIL]": "hunter2"})}
        ]

    def test_a_row_key_is_never_rewritten_so_the_row_rule_reads_it_as_it_stands(self) -> None:
        row = {_MAIL + "_password": "hunter2", "nested": {_MAIL + "_secret": ["x1y2z3", "yes"]}}

        redacted, counts = redact_rows([row])

        assert redacted == [
            {_MAIL + "_password": "<SECRET>", "nested": {_MAIL + "_secret": ["<SECRET>", "yes"]}}
        ]
        assert counts["PII_SECRET"] == 2


class TestEveryFindingBesideEveryCredentialName:
    """A seeded property: whatever finding is glued before a credential name, the member is
    taken whenever the rule takes it by the key as given, and the redaction scans clean."""

    @pytest.mark.parametrize("glue", _GLUES)
    def test_the_value_is_redacted_whenever_the_key_as_given_names_a_credential(
        self, glue: str
    ) -> None:
        samples = [sample for texts in SAMPLES.values() for sample in texts]
        names = [(name, "hunter22x9") for name in _UNAMBIGUOUS] + [
            (name, _TOKEN) for name in _AMBIGUOUS
        ]
        taken = 0
        for sample in samples:
            for name, value in names:
                key = sample + glue + name
                if not is_credential_member(key, value):
                    continue
                taken += 1
                for row in (
                    {"text": json.dumps({key: value})},
                    {"text": json.dumps({"outer": [{key: value}]})},
                ):
                    assert value not in _redacted(row), (key, row)
                    assert everything_problems(row) == []
        assert taken >= len(names), "the property must be exercised"

    def test_a_finding_after_the_name_makes_it_no_credential_key_and_nothing_regresses(
        self,
    ) -> None:
        for sample in (sample for texts in SAMPLES.values() for sample in texts):
            row = {"text": json.dumps({"password_" + sample: "hunter22x9"})}

            assert everything_problems(row) == []
