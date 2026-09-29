"""Tests for `dagnam_contracts/hygiene/detectors.py` — the PII finder registry.

R3-08: the scan knew four PII classes and leaked 19 of 25 Presidio-style
samples. Each class added here is one a pattern gets right, backed by a
checksum (IBAN mod-97, Luhn, Verhoeff), a validating parser (IP addresses), a
strict issuing format (UK NINO, Indian PAN, EU VAT) or a keyword (a date is a
date of birth only beside one). Each has its positives and the near-misses it
must not match.
"""

from __future__ import annotations

import time

import pytest

from dagnam_contracts.hygiene.detectors import (
    PII_CODES,
    PII_DETECTORS,
    _luhn_ok,
    _verhoeff_ok,
)
from dagnam_contracts.hygiene.pii import apply_pii_policy, scan_rows

_BY_CODE = {detector.code: detector for detector in PII_DETECTORS}


def _found(code: str, text: str) -> list[str]:
    return [text[start:end] for start, end in _BY_CODE[code].find(text)]


def test_the_registry_names_every_class_in_order() -> None:
    assert PII_CODES == (
        "PII_EMAIL",
        "PII_PHONE",
        "PII_PAYMENT_CARD",
        "PII_NATIONAL_ID",
        "PII_SECRET",
        "PII_IBAN",
        "PII_IP_ADDRESS",
        "PII_DATE_OF_BIRTH",
        "PII_UK_NINO",
        "PII_CA_SIN",
        "PII_IN_AADHAAR",
        "PII_IN_PAN",
        "PII_EU_VAT",
    )


POSITIVES: list[tuple[str, str, str]] = [
    # IBAN: mod-97 and the country's registered length, spaced or compact.
    ("PII_IBAN", "pay {} today", "DE89 3704 0044 0532 0130 00"),
    ("PII_IBAN", "pay {} today", "GB29NWBK60161331926819"),
    ("PII_IBAN", "iban: {}.", "FR14 2004 1010 0505 0001 3M02 606"),
    ("PII_IBAN", "to {} NOW", "BE68 5390 0754 7034"),
    ("PII_IBAN", "({})", "NL91ABNA0417164300"),
    # IP addresses, validated by the standard library's parser.
    ("PII_IP_ADDRESS", "from {} at noon", "192.168.1.20"),
    ("PII_IP_ADDRESS", "resolver {}.", "8.8.8.8"),
    ("PII_IP_ADDRESS", "curl {}:8080/x", "10.0.0.7"),
    # B8: a URL host, a URL or file path, and after `@` are addresses, not versions.
    ("PII_IP_ADDRESS", "call http://{}:8080/api", "203.0.113.7"),
    ("PII_IP_ADDRESS", "open https://{}/login", "10.1.2.3"),
    ("PII_IP_ADDRESS", "path /srv/{} now", "192.168.1.20"),
    ("PII_IP_ADDRESS", "ssh admin@{}", "192.168.1.21"),
    ("PII_IP_ADDRESS", "addr {} up", "2001:db8::1"),
    ("PII_IP_ADDRESS", "link {} up", "fe80::1ff:fe23:4567:890a"),
    ("PII_IP_ADDRESS", "mapped {} up", "::ffff:192.0.2.128"),
    # A date of birth: a date right after a birth keyword; the date only.
    ("PII_DATE_OF_BIRTH", "DOB: {}", "14/03/1987"),
    ("PII_DATE_OF_BIRTH", "D.O.B. {}", "03/14/87"),
    ("PII_DATE_OF_BIRTH", "Date of birth is {}", "1987-03-14"),
    ("PII_DATE_OF_BIRTH", "born on {}, in Leeds", "March 14, 1987"),
    ("PII_DATE_OF_BIRTH", "birthdate - {}", "14th Mar 1987"),
    ("PII_DATE_OF_BIRTH", "Birthday: {}", "14.03.1987"),
    # UK National Insurance number.
    ("PII_UK_NINO", "NI {} on file", "AB123456C"),
    ("PII_UK_NINO", "NI {} on file", "JG 10 37 64 A"),
    # Canadian SIN: Luhn, and always beside its name (B2), grouped or bare.
    ("PII_CA_SIN", "SIN {} ok", "130 692 544"),
    ("PII_CA_SIN", "SIN no. {} ok", "527-348-916"),
    ("PII_CA_SIN", "SIN: {}", "712345677"),
    ("PII_CA_SIN", "Social Insurance Number {}", "130692544"),
    ("PII_CA_SIN", "NAS : {}", "527 348 916"),
    ("PII_CA_SIN", "numéro d'assurance sociale {}", "712 345 677"),
    # Indian Aadhaar: Verhoeff, grouped 4-4-4, or bare beside its name.
    ("PII_IN_AADHAAR", "uid {} ok", "2345 6789 0124"),
    ("PII_IN_AADHAAR", "uid {} ok", "4987-6543-2102"),
    ("PII_IN_AADHAAR", "Aadhaar no. {}", "987654321012"),
    # Indian PAN: the fourth letter is the holder type.
    ("PII_IN_PAN", "PAN {} filed", "ABCPE1234F"),
    # EU VAT numbers, by the member state's format.
    ("PII_EU_VAT", "VAT {} ok", "DE123456789"),
    ("PII_EU_VAT", "VAT {} ok", "ATU12345678"),
    ("PII_EU_VAT", "VAT {} ok", "FR 12345678901"),
    ("PII_EU_VAT", "VAT {} ok", "NL123456789B01"),
    ("PII_EU_VAT", "VAT {} ok", "ESB12345678"),
    ("PII_EU_VAT", "VAT {} ok", "IE1234567T"),
    ("PII_EU_VAT", "VAT {} ok", "SE123456789001"),
]


@pytest.mark.parametrize(
    ("code", "template", "value"), POSITIVES, ids=[f"{p[0]}:{p[2]}" for p in POSITIVES]
)
def test_each_class_finds_exactly_its_value(code: str, template: str, value: str) -> None:
    assert _found(code, template.format(value)) == [value]


NEGATIVES: list[tuple[str, str]] = [
    ("PII_IBAN", "DE89 3704 0044 0532 0130 01"),  # check digits off by one
    ("PII_IBAN", "XX89 3704 0044 0532 0130 00"),  # no such country
    ("PII_IBAN", "GB29NWBK6016133192681"),  # one character short for GB
    ("PII_IBAN", "ref AB12CD34EF56GH78 attached"),
    ("PII_IBAN", "de89 3704 0044 0532 0130 00"),  # lowercase
    ("PII_IP_ADDRESS", "version 1.2.3 and v1.2.3.4 and 1.2.3.4.5"),
    ("PII_IP_ADDRESS", "999.1.1.1 and 256.0.0.1"),
    ("PII_IP_ADDRESS", "loopback 127.0.0.1, any 0.0.0.0, ::1 and ::"),
    ("PII_IP_ADDRESS", "at 12:30:45, MAC 00:1A:2B:3C:4D:5E"),
    ("PII_IP_ADDRESS", "std::vector, a :: b, cafe::bad, Foo::Bar"),
    # B1: slices are valid IPv6 to the parser; a real address has a 3+ hex group.
    ("PII_IP_ADDRESS", "numpy: a[::2], b[1::2], c[3::], d[10::20], e[::-1], arr[i::j]"),
    ("PII_IP_ADDRESS", "x = y[12::34]; z = w[::100]"),
    # B3: a network id (last octet 0) and a version after its product or keyword.
    ("PII_IP_ADDRESS", "Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36, .NET Framework 4.8.1.0"),
    ("PII_IP_ADDRESS", "firmware 2.1.0.4, version 10.2.3.4, build 3.2.1.9, v 1.2.3.4"),
    ("PII_IP_ADDRESS", "agent MyApp/2.3.4.5 (Linux; x64) curl/8.4.0.1"),
    ("PII_IP_ADDRESS", "Chrome/120.1.2.3 at the start of the text"),
    ("PII_DATE_OF_BIRTH", "Date: 14/03/1987, due 1987-03-14"),  # no birth keyword
    ("PII_DATE_OF_BIRTH", "born in 1987; DOB: unknown"),
    ("PII_DATE_OF_BIRTH", "birthday party on 14/03/2026"),  # not right after it
    ("PII_DATE_OF_BIRTH", "adobe 14/03/1987"),
    ("PII_DATE_OF_BIRTH", "DOB: 32/13/1987"),
    ("PII_UK_NINO", "QQ123456C"),  # Q is never a first letter
    ("PII_UK_NINO", "GB123456A"),  # an excluded prefix
    ("PII_UK_NINO", "AB123456E"),  # suffix past D
    ("PII_UK_NINO", "AO123456C"),  # O is never a second letter
    ("PII_UK_NINO", "ab123456c AB1234567C"),
    ("PII_CA_SIN", "130 692 545"),  # Luhn fails
    ("PII_CA_SIN", "830 692 548"),  # 8 is never a first digit
    ("PII_CA_SIN", "order 130692544"),  # bare 9 digits, no name
    ("PII_CA_SIN", "SIN 130 692-544"),  # mixed separators
    # B2: grouped and Luhn-valid is not enough; a grouped 9-digit number is
    # also French thousands, an order id, or part of a longer number.
    ("PII_CA_SIN", "Budget: 130 692 544 EUR"),
    ("PII_CA_SIN", "Order 527-348-916 shipped"),
    ("PII_CA_SIN", "total 3 130 692 544"),
    ("PII_IN_AADHAAR", "2345 6789 0125"),  # Verhoeff fails
    ("PII_IN_AADHAAR", "1345 6789 0124"),  # never starts with 0 or 1
    ("PII_IN_AADHAAR", "order 234567890124"),  # bare 12 digits, no name
    ("PII_IN_PAN", "ABCDE1234F"),  # D is not a holder type
    ("PII_IN_PAN", "ABCPE12345 abcpe1234f"),
    ("PII_EU_VAT", "DE12345678 and DE1234567890"),  # wrong length for DE
    ("PII_EU_VAT", "XY123456789 GB123456789"),  # not an EU member state
    ("PII_EU_VAT", "RO12 is a room"),  # too short to be a Romanian CUI
    ("PII_EU_VAT", "de123456789"),
]


@pytest.mark.parametrize(("code", "text"), NEGATIVES, ids=[f"{n[0]}:{n[1]}" for n in NEGATIVES])
def test_near_misses_are_not_found(code: str, text: str) -> None:
    assert _found(code, text) == []


class TestChecksums:
    @pytest.mark.parametrize("digits", ["4111111111111111", "378282246310005", "5555555555554444"])
    def test_valid_card_numbers_pass_luhn(self, digits: str) -> None:
        assert _luhn_ok(digits) is True

    @pytest.mark.parametrize("digits", ["4111111111111112", "1234567890123456"])
    def test_invalid_card_numbers_fail_luhn(self, digits: str) -> None:
        assert _luhn_ok(digits) is False

    def test_verhoeff_matches_its_published_example(self) -> None:
        """236 has check digit 3 (Verhoeff's own example)."""
        assert _verhoeff_ok("2363") is True
        assert _verhoeff_ok("2364") is False


class TestOverlaps:
    def test_an_ip_address_is_one_ip_finding_not_a_phone_number(self) -> None:
        """R3-08: the phone pattern read dotted quads as numbers; a stricter class
        that covers the same span names it, once."""
        rows = [{"a": "client 192.168.100.200 connected"}]

        counts = scan_rows(rows).counts_by_code
        kept, _, _ = apply_pii_policy(rows, dict.fromkeys(PII_CODES, "redact"))

        assert (counts["PII_IP_ADDRESS"], counts["PII_PHONE"]) == (1, 0)
        assert kept == [{"a": "client [REDACTED:PII_IP_ADDRESS] connected"}]

    def test_an_aadhaar_is_an_aadhaar_not_a_phone_number(self) -> None:
        """R3-08 found Aadhaar redacted as `PII_PHONE`."""
        rows = [{"a": "uid 2345 6789 0124"}]

        counts = scan_rows(rows).counts_by_code

        assert (counts["PII_IN_AADHAAR"], counts["PII_PHONE"]) == (1, 0)

    def test_a_phone_number_alone_is_still_a_phone_number(self) -> None:
        assert scan_rows([{"a": "call +1 (415) 555-2671"}]).counts_by_code["PII_PHONE"] == 1


@pytest.mark.parametrize(
    "text",
    [
        "1." * 50_000,
        "1:" * 50_000,
        "a:" * 50_000,
        "::" * 50_000,
        "DE89 " * 20_000,
        "AB " * 33_000,
        "DOB: " * 20_000,
        "born on " * 12_000,
        "1234 " * 20_000,
        "123 " * 25_000,
        "A" * 100_000,
        "DE" + "1" * 100_000,
        "10.1.2.3 " * 11_000,
        "fe80::1 " * 12_000,
        "a[1::2] " * 12_000,
    ],
    ids=[
        "dots",
        "digit-colons",
        "hex-colons",
        "double-colons",
        "iban-heads",
        "nino-heads",
        "dob-keywords",
        "born-on",
        "aadhaar-groups",
        "sin-groups",
        "capitals",
        "vat-digits",
        "many-ipv4",
        "many-ipv6",
        "many-slices",
    ],
)
def test_a_100_kb_adversarial_row_scans_in_well_under_a_second(text: str) -> None:
    started = time.perf_counter()
    scan_rows([{"a": text}])
    apply_pii_policy([{"a": text}], dict.fromkeys(PII_CODES, "redact"))
    assert time.perf_counter() - started < 2.0
