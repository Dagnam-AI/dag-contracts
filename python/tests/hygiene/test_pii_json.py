"""Tests for `dagnam_contracts/hygiene/pii.py` on JSON documents inside rows.

A string that holds a JSON object or array is scanned and redacted value by
value, stays valid JSON, finds a credential by the name of its key, and falls
back to plain text -- never a crash -- when it will not parse or nests too
deep. Split from `test_pii.py`, which covers the detectors and the policy.
"""

from __future__ import annotations

import json

import pytest

from dagnam_contracts.hygiene.pii import (
    PII_CODES,
    PiiAction,
    apply_pii_policy,
    redact_json_text,
    scan_rows,
)

_KEY = "s" + "k-a1B2c3D4e5F6g7H8i9J0k1L2m3"


# A-7: a contact-extraction truth. The card is a JSON number, so textual
# redaction wrote `"card": [REDACTED:PII_PAYMENT_CARD]` -- not JSON.
_CONTACT = (
    '{"name": "Jane Doe", "email": "jane@example.com", '
    '"phone": "+1 415 555 2671", "card": 4111111111111111, "vip": true, "orders": [3, null]}'
)


class TestRedactJsonText:
    def test_a_redacted_json_truth_still_parses(self) -> None:
        redacted, count = redact_json_text(_CONTACT)

        assert json.loads(redacted) == {
            "name": "Jane Doe",
            "email": "[REDACTED:PII_EMAIL]",
            "phone": "[REDACTED:PII_PHONE]",
            "card": "[REDACTED:PII_PAYMENT_CARD]",
            "vip": True,
            "orders": [3, None],
        }
        assert count == 3

    def test_an_escape_beside_a_finding_does_not_break_the_string(self) -> None:
        """Textually, `\\nbob@x.com` matched from the `n` of the escape and left a bare `\\`."""
        redacted, _ = redact_json_text('{"note": "line\\nbob@x.com"}')

        assert json.loads(redacted) == {"note": "line\n[REDACTED:PII_EMAIL]"}

    def test_keys_and_secrets_are_redacted_too(self) -> None:
        redacted, count = redact_json_text(json.dumps({"x@y.com": {"note": f"Bearer {_KEY}"}}))

        assert json.loads(redacted) == {"[REDACTED:PII_EMAIL]": {"note": "Bearer <SECRET>"}}
        assert count == 2

    def test_text_with_nothing_to_redact_is_returned_byte_for_byte(self) -> None:
        compact = '{"a":1,"b":[2.5,"ok"]}'
        assert redact_json_text(compact) == (compact, 0)

    def test_a_bare_json_scalar_stays_json(self) -> None:
        redacted, count = redact_json_text("4111111111111111")

        assert json.loads(redacted) == "[REDACTED:PII_PAYMENT_CARD]"
        assert count == 1

    def test_text_that_is_not_json_is_redacted_as_text(self) -> None:
        assert redact_json_text("mail x@y.com") == ("mail [REDACTED:PII_EMAIL]", 1)


class TestPolicyKeepsJsonValid:
    def test_a_json_document_inside_a_row_still_parses_after_redaction(self) -> None:
        """What the audit uploads: a chat row whose assistant turn IS the JSON truth."""
        rows = [
            {
                "messages": [
                    {"role": "user", "content": "extract"},
                    {"role": "assistant", "content": _CONTACT},
                ]
            }
        ]

        kept, changed, _ = apply_pii_policy(rows, dict.fromkeys(PII_CODES, "redact"))

        truth = json.loads(kept[0]["messages"][1]["content"])
        assert truth["card"] == "[REDACTED:PII_PAYMENT_CARD]"
        assert changed == 1

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            # Plain text that happens to parse as a JSON number stays plain text.
            ("4111111111111111", "[REDACTED:PII_PAYMENT_CARD]"),
            # Plain text that opens with a bracket and is not JSON.
            ("[URGENT] call 415-555-2671", "[URGENT] call [REDACTED:PII_PHONE]"),
        ],
    )
    def test_a_string_that_is_not_a_json_document_is_redacted_as_text(
        self, text: str, expected: str
    ) -> None:
        kept, _, _ = apply_pii_policy([{"a": text}], dict.fromkeys(PII_CODES, "redact"))

        assert kept == [{"a": expected}]


_ALL: dict[str, PiiAction] = dict.fromkeys(PII_CODES, "redact")


class TestNeverCrashes:
    @pytest.mark.parametrize(
        ("text", "changed"),
        [
            ("[" * 5000, 0),
            ("[" * 1500, 0),
            ("[" * 100_000, 0),
            # Parses, but deeper than the redactor can walk: redacted as text.
            ("[" * 990 + '"x@y.com"' + "]" * 990, 1),
        ],
        ids=["5000-open", "1500-open", "100k-open", "990-deep-email"],
    )
    def test_deeply_nested_json_falls_back_to_text(self, text: str, changed: int) -> None:
        """N1: `json.loads` raises RecursionError, not ValueError, past ~1,000 levels.

        One such row used to abort the whole call -- the audit's scan and the
        platform's PII task alike -- where 0.3.1 returned.
        """
        kept, rows_changed, removed = apply_pii_policy([{"a": text}], _ALL)

        assert (rows_changed, removed) == (changed, 0)
        assert ("[REDACTED:PII_EMAIL]" in kept[0]["a"]) is bool(changed)
        assert redact_json_text(text)[1] == changed
        assert scan_rows([{"a": text}]).counts_by_code["PII_EMAIL"] == changed


# A P4 tool-call truth, as dag-lib writes it (sorted keys).
_TOOL_CALL = json.dumps(
    {"arguments": {"password": "hunter22", "user": "jane"}, "name": "create_user"},
    sort_keys=True,
)
_NAMED = json.dumps(
    {
        "password": "a",
        "apiKey": 12345,
        "Authorization": "Basic dXNlcjpwYXNz",
        "aws": {"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
        "max_token": 1024,
        "token_count": "abc123def456",
        "password_hint": "pet",
        "secret": "",
        "enabled": True,
    }
)


class TestNamedCredentialsInJson:
    def test_a_password_in_a_tool_call_truth_is_redacted(self) -> None:
        """N2: the student was trained on this password, and the upload carried it."""
        rows = [{"messages": [{"role": "assistant", "content": _TOOL_CALL}]}]

        kept, changed, _ = apply_pii_policy(rows, _ALL)

        assert json.loads(kept[0]["messages"][0]["content"]) == {
            "arguments": {"password": "<SECRET>", "user": "jane"},
            "name": "create_user",
        }
        assert changed == 1

    def test_the_value_of_a_credential_key_is_redacted_whatever_it_looks_like(self) -> None:
        redacted, count = redact_json_text(_NAMED)

        assert json.loads(redacted) == {
            "password": "<SECRET>",
            "apiKey": "<SECRET>",
            "Authorization": "<SECRET>",
            "aws": {"secret_access_key": "<SECRET>"},
            "max_token": 1024,
            "token_count": "abc123def456",
            "password_hint": "pet",
            "secret": "",
            "enabled": True,
        }
        assert count == 4

    def test_the_scan_counts_what_the_redaction_replaces(self) -> None:
        result = scan_rows([{"a": _NAMED}, {"a": _TOOL_CALL}])

        assert result.counts_by_code["PII_SECRET"] == 5

    def test_a_policy_that_drops_secrets_drops_the_row(self) -> None:
        kept, _, removed = apply_pii_policy([{"a": _TOOL_CALL}], {"PII_SECRET": "drop"})

        assert (kept, removed) == ([], 1)

    def test_a_credential_key_is_left_alone_when_secrets_are_not_redacted(self) -> None:
        rows = [{"a": _TOOL_CALL}]

        assert apply_pii_policy(rows, {"PII_EMAIL": "redact"}) == (rows, 0, 0)

    @pytest.mark.parametrize(
        "text",
        [
            'Config: {"api_key": "abcd1234efgh5678", "db_password": "Sup3rS3cret"}',
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        ],
    )
    def test_named_credentials_in_plain_text_are_redacted(self, text: str) -> None:
        (row,), changed, _ = apply_pii_policy([{"a": text}], _ALL)

        assert changed == 1
        assert "Sup3rS3cret" not in row["a"]
        assert "abcd1234efgh5678" not in row["a"]
        assert "wJalr" not in row["a"]


class TestAmbiguousNames:
    """R1: data under `token` / `authorization` is kept unless it IS a credential."""

    def test_ordinary_values_under_an_ambiguous_name_are_kept(self) -> None:
        text = json.dumps(
            {
                "rows": [{"token": "Paris", "label": "LOC"}, {"token": "the", "pos": "DET"}],
                "authorization": "approved",
                "nextPageToken": "abc",
                "key": "Enter",
                "max_token": 1024,
            }
        )

        assert redact_json_text(text) == (text, 0)
        assert scan_rows([{"a": text}]).counts_by_code["PII_SECRET"] == 0

    def test_a_credential_under_an_ambiguous_name_is_redacted(self) -> None:
        github = "gh" + "p_" + "a1B2c3D4e5" * 4
        redacted, count = redact_json_text(
            json.dumps({"token": github[:40], "authorization": f"Bearer {_KEY}"})
        )

        assert json.loads(redacted) == {"token": "<SECRET>", "authorization": "<SECRET>"}
        assert count == 2

    def test_the_a11_token_under_an_ambiguous_name_is_redacted(self) -> None:
        """H1: digitless, so neither the bare `sk-` shape nor the entropy rule took it."""
        a11 = "s" + "k-live-AbCdEfGhIjKlMnOpQrStUvWx"
        redacted, count = redact_json_text(json.dumps({"auth": a11, "token": a11}))

        assert json.loads(redacted) == {"auth": "<SECRET>", "token": "<SECRET>"}
        assert count == 2
