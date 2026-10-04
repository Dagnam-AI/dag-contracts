"""Tests for `dagnam_contracts/hygiene/pii.py`: where 0.4.1 deliberately answers differently from 0.4.0.

Everything 0.4.0 found in its first pass is still found, with the same class and the same
placeholder, except the cases below; each docstring states what 0.4.0 did. They follow from
reading every stretch of text between placeholders on its own, or are a pattern fix named
in the changelog. The last class holds the misses that are kept on purpose.
"""

from __future__ import annotations

import json

from pii_corpus import ALL, found
import pytest

from dagnam_contracts.hygiene.pii import (
    PII_CODES,
    PiiAction,
    apply_pii_policy,
    redact_json_text,
    scan_rows,
)

_DROP_ALL: dict[str, PiiAction] = dict.fromkeys(PII_CODES, "drop")


def _redacted(text: str, policy: dict[str, PiiAction] | None = None) -> str:
    return apply_pii_policy([{"a": text}], policy or ALL)[0][0]["a"]


class TestMoreIsFoundInOneScan:
    @pytest.mark.parametrize(
        ("text", "counts", "redacted"),
        [
            (
                "+44 20 7946 0958 +44 20 7946 0958",
                {"PII_PHONE": 2},
                "[REDACTED:PII_PHONE] [REDACTED:PII_PHONE]",
            ),
            (
                "password: hunter22 +1 415-555-0132",
                {"PII_SECRET": 1, "PII_PHONE": 1},
                "password: <SECRET> [REDACTED:PII_PHONE]",
            ),
            (
                "Pwd=letmein4 4111111111111111",
                {"PII_SECRET": 1, "PII_PAYMENT_CARD": 1},
                "Pwd=<SECRET> [REDACTED:PII_PAYMENT_CARD]",
            ),
        ],
    )
    def test_a_finding_next_to_another_is_found_in_the_same_scan(
        self, text: str, counts: dict[str, int], redacted: str
    ) -> None:
        """0.4.0 found one number of the first (`PII_PHONE` 1, the second left in place),
        only the secret of the second, and neither of the third."""
        assert found([{"a": text}]) == counts
        assert _redacted(text) == redacted

    def test_a_document_that_parses_only_after_a_replacement_is_walked_in_the_same_call(
        self,
    ) -> None:
        """0.4.0 counted `PII_PHONE` 1 and left `"password": 1234`, which its own rescan
        then took as a secret."""
        text = '{"note": "call +1 415\t555 0132", "password": 1234}'

        assert found([{"a": text}]) == {"PII_PHONE": 1, "PII_SECRET": 1}
        assert json.loads(_redacted(text)) == {
            "note": "call [REDACTED:PII_PHONE]",
            "password": "<SECRET>",
        }
        assert redact_json_text(text)[1] == 2

    def test_a_card_glued_to_a_pem_block_is_found_with_it(self) -> None:
        """0.4.0 found the PEM block, left the card (`4111111111111111<SECRET>`) and its
        own rescan then found the card."""
        text = "4111111111111111-----BEGIN PRIVATE KEY-----\nMIIEow\n-----END PRIVATE KEY-----"

        assert found([{"a": text}]) == {"PII_PAYMENT_CARD": 1, "PII_SECRET": 1}
        assert _redacted(text) == "[REDACTED:PII_PAYMENT_CARD]<SECRET>"

    @pytest.mark.parametrize(
        ("text", "code", "redacted"),
        [
            ("1987DOB: 14/03/1987", "PII_DATE_OF_BIRTH", "1987DOB: [REDACTED:PII_DATE_OF_BIRTH]"),
            ("order 9SIN 130 692 544", "PII_CA_SIN", "order 9SIN [REDACTED:PII_CA_SIN]"),
            (
                "id 9Aadhaar Number 580927525309",
                "PII_IN_AADHAAR",
                "id 9Aadhaar Number [REDACTED:PII_IN_AADHAAR]",
            ),
        ],
    )
    def test_a_keyword_may_open_right_after_a_digit(
        self, text: str, code: str, redacted: str
    ) -> None:
        """0.4.0 read `\\b` before the keyword, so a digit glued to it hid it: all three
        were found by nothing."""
        assert found([{"a": text}]) == {code: 1}
        assert _redacted(text) == redacted

    @pytest.mark.parametrize("text", ["adobe 14/03/1987", "BASIN 130 692 544", "basin SIN-less"])
    def test_a_keyword_inside_a_word_is_still_refused(self, text: str) -> None:
        assert found([{"a": text}]) == {}


class TestAPlaceholderIsNeverAFinding:
    @pytest.mark.parametrize(
        "text",
        [
            "password: <SECRET>",
            "password: [REDACTED:PII_EMAIL]",
            '{"password": "<SECRET>"}',
            "password=[REDACTED:PII_EMAIL]!x",
        ],
    )
    def test_the_redactors_own_output_counts_nothing(self, text: str) -> None:
        """0.4.0 counted one `PII_SECRET` in each of the last three: the placeholder was
        the value of `password`, and its own rescan stopped on it."""
        assert found([{"a": text}]) == {}
        assert _redacted(text) == text


class TestAUrlPasswordAndTheAddressOverIt:
    @pytest.mark.parametrize(
        ("text", "redacted"),
        [
            ("ftp://anonymous:pw@ftp.example.com/", "ftp://anonymous:<SECRET>/"),
            ("mysql://root:toor@10.0.0.7:3306/app", "mysql://root:<SECRET>:3306/app"),
        ],
    )
    def test_they_are_one_region_named_a_secret(self, text: str, redacted: str) -> None:
        """0.4.0 redacted the same span as an address: `ftp://anonymous:[REDACTED:PII_EMAIL]/`
        and `mysql://root:[REDACTED:PII_EMAIL]:3306/app`."""
        assert found([{"a": text}]) == {"PII_SECRET": 1}
        assert _redacted(text) == redacted

    def test_a_policy_for_addresses_alone_leaves_the_url_as_it_is(self) -> None:
        """0.4.0 redacted `pw@ftp.example.com` under an email-only policy, as an address."""
        text = "ftp://anonymous:pw@ftp.example.com/"

        assert _redacted(text, {"PII_EMAIL": "redact"}) == text
        assert scan_rows([{"a": text}]).counts_by_code["PII_EMAIL"] == 0

    def test_a_policy_for_the_ip_address_alone_leaves_the_host_the_secret_took(self) -> None:
        """0.4.0 redacted the IP address under an IP-only policy (`root:toor@[REDACTED...]`)."""
        text = "mysql://root:toor@10.0.0.7:3306/app"

        assert _redacted(text, {"PII_IP_ADDRESS": "redact"}) == text
        assert found([{"a": text}]) == {"PII_SECRET": 1}

    def test_a_card_glued_to_a_scheme_leaves_the_password_found(self) -> None:
        """0.4.0 found the card, and its rescan found nothing because the scheme's last
        character was gone and the password pattern needs one."""
        text = "4111111111111111://u:pw@h"

        assert found([{"a": text}]) == {"PII_PAYMENT_CARD": 1, "PII_SECRET": 1}
        assert _redacted(text) == "[REDACTED:PII_PAYMENT_CARD]://u:<SECRET>@h"


class TestAPolicyActsOnTheFullResolution:
    def test_a_phone_policy_redacts_the_phone_a_secret_hid(self) -> None:
        """0.4.0 left it, and never counted it."""
        text = "password: hunter22 +1 415-555-0132"

        assert _redacted(text, {"PII_PHONE": "redact"}) == "password: hunter22 [REDACTED:PII_PHONE]"
        assert _redacted(text, {"PII_SECRET": "redact"}) == "password: <SECRET> +1 415-555-0132"

    def test_an_address_after_a_port_is_an_email_under_every_policy(self) -> None:
        """As in 0.4.0, which redacted it as an address: `8080,john` is a port and some
        text, not a password."""
        text = "http://localhost:8080,john@example.com"

        assert found([{"a": text}]) == {"PII_EMAIL": 1}
        assert (
            _redacted(text, {"PII_EMAIL": "redact"}) == "http://localhost:8080,[REDACTED:PII_EMAIL]"
        )


class TestKnownMisses:
    """Findings no pattern reads. They are missed by the scan, the redaction, the rescan
    and a drop-everything policy alike -- the same in 0.4.0 -- and, nothing being replaced,
    they are stable: what the scan of the redacted row sees is what it saw before."""

    @pytest.mark.parametrize(
        "text",
        [
            "415-555-0132 415-555-0132",
            "Qty 2 4111111111111111",
            "order 12 4111 1111 1111 1111",
            "1 +14155551001 2 +14155551002",
            "items: 3 5500000000000004",
        ],
    )
    def test_a_number_run_into_a_count_is_not_found_and_stays_stable(self, text: str) -> None:
        row = {"a": text}

        assert found([row]) == {}
        assert apply_pii_policy([row], ALL) == ([row], 0, 0)
        assert apply_pii_policy([row], _DROP_ALL) == ([row], 0, 0)
