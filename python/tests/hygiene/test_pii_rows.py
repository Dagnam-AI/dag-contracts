"""Tests for `dagnam_contracts/hygiene/pii.py` on the row itself: its members, numbers and keys.

A structured row gets the credential-name rule for unambiguous names only, and
nothing else a JSON document held in a string gets. Split from `test_pii.py`,
which covers the detectors and the policy; `test_pii_json.py` covers documents.
"""

from __future__ import annotations

import json
from typing import Any, cast

from dagnam_contracts.hygiene.pii import PII_CODES, PiiAction, apply_pii_policy, scan_rows

_ALL: dict[str, PiiAction] = dict.fromkeys(PII_CODES, "redact")
_DROP: dict[str, PiiAction] = dict.fromkeys(PII_CODES, "drop")

# Ids of 16+ letters and digits, under names an id column carries. In a JSON
# document held in a string each is a `PII_SECRET`, as in 0.4.0; in a row it is not.
IDS = {
    "row_key": "a81f3c9e2b7d4f60",
    "idempotency_key": "ord_9f8e7d6c5b4a3210",
    "nextPageToken": "CAESEAoOc29tZS1wYWdlLXRva2Vu",
}
# Credentials in a format the text scan knows, under the same names; the last
# is an `sk-` key with no digit, which only a name could vouch for.
KEYS = {
    "row_key": "gh" + "p_" + "a1B2c3D4e5" * 3 + "a1B2c3",
    "idempotency_key": "s" + "k-a1B2c3D4e5F6g7H8i9J0k1L2m3",
    "nextPageToken": "Bearer a1B2c3D4e5F6g7H8i9J0k1L2",
    "auth": "s" + "k-abcdefghijklmnopqrstuvwxyz",
}


class TestStructuredRows:
    """A row is data, not text: a value under a name that can only be a credential
    (`password`, `client_secret`, ...) is one. Until 0.4.1 only the row's strings
    were read. Its bare numbers and its keys are still left as they are, and a
    name that an id column also carries (`row_key`, `nextPageToken`) decides nothing."""

    def test_a_credential_named_member_of_the_row_is_counted_and_redacted(self) -> None:
        rows = [{"user": "jane", "password": "correcthorse", "client_secret": "abc"}]

        result = scan_rows(rows)
        kept, changed, _ = apply_pii_policy(rows, _ALL)

        assert result.counts_by_code["PII_SECRET"] == 2
        assert [issue.message for issue in result.issues] == [
            "Secret or credential matched 1 time(s) in field 'client_secret'",
            "Secret or credential matched 1 time(s) in field 'password'",
        ]
        assert kept == [{"user": "jane", "password": "<SECRET>", "client_secret": "<SECRET>"}]
        assert changed == 1

    def test_an_id_under_a_name_an_id_column_carries_is_not_a_finding(self) -> None:
        """`row_key`, `idempotency_key` and `nextPageToken` hold ids. Counting each as a
        secret would flag every row of a dataset keyed on one, and a drop policy
        would lose them all."""
        rows = [dict(IDS), {"arguments": dict(IDS)}]

        assert not any(scan_rows(rows).counts_by_code.values())
        assert apply_pii_policy(rows, _ALL) == (rows, 0, 0)
        assert apply_pii_policy(rows, _DROP) == (rows, 0, 0)

    def test_a_known_format_under_the_same_names_is_still_found(self) -> None:
        """The value is scanned as text: the credential's own span is replaced, as in
        0.4.0, not the whole value. A format only a name could vouch for is left."""
        rows = [dict(KEYS)]

        kept, changed, _ = apply_pii_policy(rows, _ALL)

        assert kept == [
            {
                "row_key": "<SECRET>",
                "idempotency_key": "<SECRET>",
                "nextPageToken": "Bearer <SECRET>",
                "auth": KEYS["auth"],
            }
        ]
        assert changed == 1
        assert scan_rows(rows).counts_by_code["PII_SECRET"] == 3
        assert apply_pii_policy(rows, _DROP) == ([], 0, 1)

    def test_a_bare_number_is_not_scanned(self) -> None:
        """An id or a timestamp passes Luhn one time in ten, and redacting it would
        turn a numeric column's cell into a string. So a card held as a number in
        the row is left alone; the same digits in a string are still a finding."""
        number = [{"card": 4111111111111111, "ts": 1727600000000, "orders": 3, "score": 0.5}]
        text = [{"card": "4111111111111111"}]
        document = [{"a": json.dumps({"card": 4111111111111111})}]

        assert not any(scan_rows(number).counts_by_code.values())
        assert apply_pii_policy(number, _ALL) == (number, 0, 0)
        assert apply_pii_policy(number, dict.fromkeys(PII_CODES, "drop")) == (number, 0, 0)
        assert apply_pii_policy(text, _ALL) == ([{"card": "[REDACTED:PII_PAYMENT_CARD]"}], 1, 0)
        assert apply_pii_policy(document, _ALL) == (
            [{"a": '{"card": "[REDACTED:PII_PAYMENT_CARD]"}'}],
            1,
            0,
        )

    def test_a_number_under_a_credential_name_is_replaced(self) -> None:
        """The name finds it, not its digits: it is one secret, and no card."""
        rows = [{"password": 4111111111111111, "pin": 4111111111111111}]

        counts = scan_rows(rows).counts_by_code
        kept, changed, _ = apply_pii_policy(rows, _ALL)

        assert (counts["PII_SECRET"], counts["PII_PAYMENT_CARD"]) == (1, 0)
        assert kept == [{"password": "<SECRET>", "pin": 4111111111111111}]
        assert changed == 1

    def test_tool_call_arguments_held_as_an_object_are_read_member_by_member(self) -> None:
        arguments = {"password": "hunter22", "user": "jane", "apiKey": 12345, "max_token": 1024}
        call = {"name": "create_user", "arguments": arguments}
        rows = [{"messages": [{"role": "assistant", "tool_calls": [call]}]}]

        result = scan_rows(rows)
        kept, _, _ = apply_pii_policy(rows, _ALL)

        assert result.counts_by_code["PII_SECRET"] == 2
        assert [issue.message.split("field ")[1] for issue in result.issues] == [
            "'messages[0].tool_calls[0].arguments.apiKey'",
            "'messages[0].tool_calls[0].arguments.password'",
        ]
        assert kept[0]["messages"][0]["tool_calls"][0]["arguments"] == {
            "password": "<SECRET>",
            "user": "jane",
            "apiKey": "<SECRET>",
            "max_token": 1024,
        }

    def test_ordinary_data_under_an_ambiguous_name_is_kept(self) -> None:
        github = "gh" + "p_" + "a1B2c3D4e5" * 4
        rows = [
            {"token": "Paris", "key": "Enter", "authorization": "approved", "password": True},
            {"token": github[:40]},
        ]

        kept, changed, _ = apply_pii_policy(rows, _ALL)

        assert kept == [rows[0], {"token": "<SECRET>"}]
        assert changed == 1
        assert scan_rows(rows).counts_by_code["PII_SECRET"] == 1

    def test_the_policy_decides_what_happens_to_a_named_credential(self) -> None:
        rows = [{"password": "correcthorse"}]

        assert apply_pii_policy(rows, {"PII_SECRET": "drop"}) == ([], 0, 1)
        assert apply_pii_policy(rows, {"PII_EMAIL": "redact"}) == (rows, 0, 0)

    def test_a_rows_own_keys_are_its_schema_and_are_left_alone(self) -> None:
        """Only its values are read, at every depth: a column name is not data, and a
        nested key is treated the same. A key of a document held in a string is redacted."""
        rows = cast(
            "list[dict[str, Any]]",
            [{"x@y.com": "hello", 7: "mail a@b.com", "contacts": {"c@d.com": {"e@f.com": 1}}}],
        )

        kept, changed, _ = apply_pii_policy(rows, _ALL)

        assert kept == [{**rows[0], 7: "mail [REDACTED:PII_EMAIL]"}]
        assert changed == 1
        assert [issue.message.split("field ")[1] for issue in scan_rows(rows).issues] == ["'7'"]


class TestCredentialNamedMembersOfARow:
    """The rule for a column name (`credentials.py` has it) and for what is under it."""

    def test_a_flag_or_label_column_is_left_alone(self) -> None:
        rows = [
            {
                "has_password": "yes",
                "top_secret": "banana",
                "is_secret": "x1y2z3",
                "password_hint": "your first pet",
                "no_password": "needs a reset",
            }
        ]

        assert apply_pii_policy(rows, _ALL) == (rows, 0, 0)
        assert not any(scan_rows(rows).counts_by_code.values())

    def test_a_boolean_none_blank_or_flag_like_value_is_not_a_secret(self) -> None:
        rows: list[dict[str, Any]] = [
            {
                "password": True,
                "secret": False,
                "api_key": None,
                "client_secret": "",
                "private_key": " ",
                "access_key": "N/A",
                "passwd": "none",
                "secret_key": "-",
            }
        ]

        assert apply_pii_policy(rows, _ALL) == (rows, 0, 0)
        assert apply_pii_policy(rows, _DROP) == (rows, 0, 0)
        assert not any(scan_rows(rows).counts_by_code.values())

    def test_every_scalar_in_a_list_under_a_credential_name_is_replaced_by_the_same_rule(
        self,
    ) -> None:
        rows: list[dict[str, Any]] = [
            {"user": "jane", "password": ["hunter2", "yes", "", True, None, 5, "correcthorse"]}
        ]

        result = scan_rows(rows)
        kept, changed, _ = apply_pii_policy(rows, _ALL)

        assert kept == [
            {
                "user": "jane",
                "password": ["<SECRET>", "yes", "", True, None, "<SECRET>", "<SECRET>"],
            }
        ]
        assert changed == 1
        assert result.counts_by_code["PII_SECRET"] == 3
        assert [issue.message.split("field ")[1] for issue in result.issues] == [
            "'password[0]'",
            "'password[5]'",
            "'password[6]'",
        ]

    def test_every_scalar_in_an_object_under_a_credential_name_is_replaced(self) -> None:
        rows: list[dict[str, Any]] = [
            {
                "secret": {
                    "value": "hunter2",
                    "hint": "yes",
                    "history": [{"old": "correcthorse"}, ["a", "b"]],
                },
                "note": "kept",
            }
        ]

        result = scan_rows(rows)
        kept, _, _ = apply_pii_policy(rows, _ALL)

        assert kept == [
            {
                "secret": {
                    "value": "<SECRET>",
                    "hint": "yes",
                    "history": [{"old": "<SECRET>"}, ["<SECRET>", "<SECRET>"]],
                },
                "note": "kept",
            }
        ]
        assert [issue.message.split("field ")[1] for issue in result.issues] == [
            "'secret.history[0].old'",
            "'secret.history[1][0]'",
            "'secret.history[1][1]'",
            "'secret.value'",
        ]
        assert apply_pii_policy(rows, _DROP) == ([], 0, 1)

    def test_a_container_under_a_name_that_decides_nothing_is_read_as_before(self) -> None:
        rows = [
            {
                "tokens": ["a81f3c9e2b7d4f60"],
                "row_key": {"id": IDS["row_key"]},
                "has_password": ["yes", "hunter2abc"],
                "users": [{"name": "jane", "password_hint": ["pet"]}],
            }
        ]

        assert apply_pii_policy(rows, _ALL) == (rows, 0, 0)

    def test_a_credential_deep_in_a_list_of_objects_is_found(self) -> None:
        rows = [{"users": [{"name": "jane", "password": ["a1", "yes"]}, {"name": "joe"}]}]

        kept, _, _ = apply_pii_policy(rows, _ALL)

        assert kept == [
            {"users": [{"name": "jane", "password": ["<SECRET>", "yes"]}, {"name": "joe"}]}
        ]

    def test_a_placeholder_under_a_credential_name_is_not_found_again(self) -> None:
        rows = [{"password": ["<SECRET>", {"a": "[REDACTED:PII_EMAIL]"}]}]

        assert apply_pii_policy(rows, _ALL) == (rows, 0, 0)

    def test_a_text_finding_under_a_flag_column_is_still_found(self) -> None:
        """A flag column holds no secret by its name; the text in it is read like any text."""
        rows = [{"has_password": "mail jane@example.com"}]

        assert apply_pii_policy(rows, _ALL)[0] == [{"has_password": "mail [REDACTED:PII_EMAIL]"}]
