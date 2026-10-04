"""Tests for `dagnam_contracts/hygiene/pii.py`: inputs that once left a residue, or a miss.

Each is the exact input, with the output a redaction must give and the properties that
make a redaction safe to upload: it scans clean, redacting it again changes nothing, and
the scan counted what was written.
"""

from __future__ import annotations

import json
from typing import Any

from pii_corpus import ALL, SHAPE_NAMES, SHAPES, everything_problems, found, placeholders
import pytest

from dagnam_contracts.hygiene.pii import (
    PII_CODES,
    PiiAction,
    apply_pii_policy,
    redact_json_text,
    redact_rows,
    scan_rows,
)

_SEPARATORS = {"space": " ", "hyphen": "-", "tab": "\t", "comma": ", ", "newline": "\n"}
_EMAIL_ONLY: dict[str, PiiAction] = {"PII_EMAIL": "redact"}


def _numbers(count: int, separator: str) -> str:
    return separator.join(f"+1415555{1000 + i}" for i in range(count))


def _clean(row: dict[str, Any]) -> None:
    assert everything_problems(row) == []


class TestListsOfPhoneNumbers:
    @pytest.mark.parametrize("separator", sorted(_SEPARATORS))
    @pytest.mark.parametrize("count", [17, 20, 40])
    def test_every_number_of_a_list_is_redacted(self, count: int, separator: str) -> None:
        """17 `+` numbers one space apart reached the 16-pass limit: the 17th stayed in the
        row and the platform's rescan found it. 40 left 24."""
        text = _numbers(count, _SEPARATORS[separator])
        rows, _, _ = apply_pii_policy([{"text": text}], ALL)

        assert scan_rows([{"text": text}]).counts_by_code["PII_PHONE"] == count
        assert rows[0]["text"].count("[REDACTED:PII_PHONE]") == count
        assert not any(char.isdigit() for char in rows[0]["text"])
        assert found(rows) == {}

    def test_seventeen_numbers_one_space_apart(self) -> None:
        row = {"text": " ".join(f"+1415555{1000 + i}" for i in range(17))}

        _clean(row)
        assert redact_rows([row])[1]["PII_PHONE"] == 17

    def test_a_megabyte_of_numbers_is_all_redacted(self) -> None:
        text = " ".join(f"+1415555{1000 + i % 9000}" for i in range(77_000))

        redacted, counts = redact_rows([{"text": text}])

        assert counts["PII_PHONE"] == 77_000
        assert found(redacted) == {}


class TestAFieldThatReadsDifferentlyOnceRedacted:
    def test_a_document_that_only_parses_once_its_phone_is_replaced(self) -> None:
        """A raw tab inside a phone number is not valid inside a JSON string. The first
        read was plain text; the rescan read a document and took `"password": 1234`."""
        row = {"text": '{"note": "call +1 415\t555 0132", "password": 1234}'}

        redacted, changed, _ = apply_pii_policy([row], ALL)

        assert changed == 1
        assert found([row]) == {"PII_PHONE": 1, "PII_SECRET": 1}
        assert json.loads(redacted[0]["text"]) == {
            "note": "call [REDACTED:PII_PHONE]",
            "password": "<SECRET>",
        }
        _clean(row)

    def test_a_pem_block_with_real_newlines_and_a_secret_member(self) -> None:
        block = "-----BEGIN PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END PRIVATE KEY-----"
        row = {"text": '{"key": "' + block + '", "secret": 42}'}

        _clean(row)

    def test_a_number_split_across_a_newline_and_a_password_of_nine(self) -> None:
        row = {"text": '{"ids": "ids 2001 555\n0100 77", "password": 9}'}

        _clean(row)
        assert found([row])["PII_SECRET"] == 1

    def test_a_url_password_with_a_quote_and_an_api_key_member(self) -> None:
        row = {"text": '{"dsn": "postgres://app:pa"ss1@db/x", "api_key": 7}'}

        _clean(row)
        assert found([row])["PII_SECRET"] >= 1

    def test_a_key_that_names_a_credential_once_its_head_is_redacted(self) -> None:
        """`4111111111111111secret` becomes `[REDACTED:PII_PAYMENT_CARD]secret`, whose
        suffix is a credential name; the rescan took the member. The first scan takes it
        too, so the one redaction replaces both."""
        row = {"text": '{"4111111111111111secret": "hello"}'}

        redacted, _, _ = apply_pii_policy([row], ALL)

        assert json.loads(redacted[0]["text"]) == {"[REDACTED:PII_PAYMENT_CARD]secret": "<SECRET>"}
        assert found([row]) == {"PII_PAYMENT_CARD": 1, "PII_SECRET": 1}
        _clean(row)

    def test_a_member_whose_pwd_value_shows_once_its_card_is_replaced(self) -> None:
        """`x 4111111111111111pwd=abc` becomes `x [REDACTED:PII_PAYMENT_CARD]pwd=<SECRET>`,
        and the raw `pwd=` finder matches `<SECRET>`, so the member rule took the whole value."""
        row = {"text": '{"token": "x 4111111111111111pwd=abc"}'}

        redacted, _, _ = apply_pii_policy([row], ALL)

        assert found(redacted) == {}
        assert apply_pii_policy(redacted, ALL) == (redacted, 0, 0)
        _clean(row)

    @pytest.mark.parametrize("shape", SHAPE_NAMES)
    def test_the_same_documents_inside_every_shape_of_row(self, shape: str) -> None:
        for text in (
            '{"note": "call +1 415\t555 0132", "password": 1234}',
            '{"4111111111111111secret": "hello"}',
            '{"token": "x 4111111111111111pwd=abc"}',
        ):
            _clean(SHAPES[shape](text))

    def test_redact_json_text_settles_the_same_way(self) -> None:
        text = '{"note": "call +1 415\t555 0132", "password": 1234}'

        redacted, count = redact_json_text(text)

        assert count == 2
        assert redact_json_text(redacted) == (redacted, 0)


class TestAPortThenAnAddress:
    @pytest.mark.parametrize(
        ("text", "redacted"),
        [
            (
                "http://localhost:8080,john@example.com",
                "http://localhost:8080,[REDACTED:PII_EMAIL]",
            ),
            ("http://db:5432;ops@corp.example", "http://db:5432;[REDACTED:PII_EMAIL]"),
            ("url=http://h:1&cc=a@b.co", "url=http://h:1&cc=[REDACTED:PII_EMAIL]"),
            ("http://localhost:3000|admin@x.co", "http://localhost:3000|[REDACTED:PII_EMAIL]"),
            ("http://h:80>a@b.co", "http://h:80>[REDACTED:PII_EMAIL]"),
        ],
    )
    def test_the_address_is_an_email_under_every_policy(self, text: str, redacted: str) -> None:
        """`8080,john` was read as a password, so the address was a secret and an
        email-only policy left it (0.4.0 redacted it)."""
        row = {"text": text}

        assert found([row]) == {"PII_EMAIL": 1}
        assert apply_pii_policy([row], _EMAIL_ONLY) == ([{"text": redacted}], 1, 0)
        assert apply_pii_policy([row], {"PII_EMAIL": "drop"}) == ([], 0, 1)
        assert apply_pii_policy([row], ALL) == ([{"text": redacted}], 1, 0)

    def test_a_space_or_a_slash_after_the_port_was_always_right(self) -> None:
        for text in ("http://h:8080 me@x.co", '"http://host:8080","a@b.co"'):
            assert found([{"text": text}]) == {"PII_EMAIL": 1}


class TestAPortThenADotOrAnEqualsSign:
    @pytest.mark.parametrize(
        "text",
        ["http://h:8080.john@x.co", "see http://h:8080=john@x.co", "https://u:1234.abc@host.com"],
    )
    def test_it_is_a_url_password_and_an_address_policy_leaves_it(self, text: str) -> None:
        """`8080.john` and `8080=john` are passwords as much as `1234.abc` is, and reading
        them as a port and an address would leave a credential. Under redact-everything the
        whole is one secret; an email-only policy has nothing to act on."""
        row = {"text": text}

        assert found([row]) == {"PII_SECRET": 1}
        assert apply_pii_policy([row], _EMAIL_ONLY) == ([row], 0, 0)
        assert everything_problems(row) == []


class TestAPolicyThatActsOnOneClass:
    def test_a_phone_policy_redacts_a_phone_a_secret_hid(self) -> None:
        row = {"text": "password: hunter22 +1 415-555-0132"}

        assert apply_pii_policy([row], {"PII_PHONE": "redact"})[0] == [
            {"text": "password: hunter22 [REDACTED:PII_PHONE]"}
        ]

    def test_a_card_policy_redacts_a_card_a_pwd_value_hid(self) -> None:
        row = {"text": "Pwd=letmein4 4111111111111111"}

        assert apply_pii_policy([row], {"PII_PAYMENT_CARD": "drop"}) == ([], 0, 1)


class TestCutThenRedact:
    """The SDK uploads the last `max_seq_length` characters of a rendered prompt. A cut
    after redaction can split a placeholder, or cut into the context of a miss, so the row
    is redacted as it will be uploaded."""

    @pytest.mark.parametrize(
        "text",
        [
            "Qty 2 4111111111111111",
            "415-555-0132 415-555-0132",
            "order 12 4111 1111 1111 1111",
            "1 +14155551001 2 +14155551002",
            "acct XDE89370400440532013000",
            "password: hunter22 +1 415-555-0132 mail jane@example.com",
        ],
    )
    def test_a_row_redacted_at_every_cut_scans_clean(self, text: str) -> None:
        for start in range(len(text)):
            rows, counts = redact_rows([{"text": text[start:]}])

            assert found(rows) == {}, (text, start)
            assert sum(counts.values()) == sum(placeholders(rows).values()), (text, start)

    def test_a_miss_is_found_once_a_cut_removes_its_context(self) -> None:
        """Why the order matters: `Qty 2 ` is what hides the card from every pattern, and
        a cut that drops it leaves a bare card number for the platform to find. A row
        redacted after the cut has no such context to lose."""
        assert found([{"text": "Qty 2 4111111111111111"}]) == {}
        assert found([{"text": "4111111111111111"}]) == {"PII_PAYMENT_CARD": 1}
        assert redact_rows([{"text": "4111111111111111"}])[0] == [
            {"text": "[REDACTED:PII_PAYMENT_CARD]"}
        ]

    def test_a_case_folded_placeholder_is_text(self) -> None:
        """Normalising the row after redaction breaks the placeholder (`<secret>`); the
        label is redacted after it is normalised."""
        folded = {"label": json.dumps({"password": "<secret>"})}

        assert found([folded]) == {"PII_SECRET": 1}
        redacted, counts = redact_rows([folded])
        assert counts["PII_SECRET"] == 1
        assert found(redacted) == {}


def test_every_class_is_counted_by_redact_rows_even_at_zero() -> None:
    _, counts = redact_rows([{"text": "nothing"}])

    assert counts == dict.fromkeys(PII_CODES, 0)
