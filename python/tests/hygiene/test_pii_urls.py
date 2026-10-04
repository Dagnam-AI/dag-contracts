"""Tests for `dagnam_contracts/hygiene/pii.py` on a URL that carries a password.

The password is the secret. The email pattern also reads `password@host.com` as an
address; where the two overlap the scan names the region a secret, so the host that
follows the `@` goes with it when it is dotted (and stays when it is a single label or an
IPv6 address, which the email pattern does not take). No pattern consults another: the
email-only policy leaves such a URL as it is, and a URL with a port and a separator
before an address is a port and an address. Split from `test_pii.py`, which covers the
detectors and the policy.
"""

from __future__ import annotations

import time

import pytest

from dagnam_contracts.hygiene.pii import PII_CODES, PiiAction, apply_pii_policy, scan_rows

_ALL: dict[str, PiiAction] = dict.fromkeys(PII_CODES, "redact")
# Every class but the one that would read an IP address in the host.
_NO_IP: dict[str, PiiAction] = {c: "redact" for c in PII_CODES if c != "PII_IP_ADDRESS"}

URLS = [
    # A dotted host, a port, a path, a query, an IPv6 host and a single-label host.
    ("ftp://anonymous:pw@ftp.example.com/", "ftp://anonymous:<SECRET>/"),
    ("https://u:pw@host.com:8443/x", "https://u:<SECRET>:8443/x"),
    ("https://u:pw@host.com/a/b?c=d#e", "https://u:<SECRET>/a/b?c=d#e"),
    ("https://u:p@host.com?x=1", "https://u:<SECRET>?x=1"),
    ("http://ci:tok3n@[2001:db8::1]:8080/job", "http://ci:<SECRET>@[2001:db8::1]:8080/job"),
    ("postgres://user:pw@localhost/db", "postgres://user:<SECRET>@localhost/db"),
    (
        "mongodb+srv://admin:Sup3rS3cret@cluster0.abcde.mongodb.net/db",
        "mongodb+srv://admin:<SECRET>/db",
    ),
    # An `@` in the password: the address-shaped tail is part of the one secret.
    ("mongodb://admin:p@ssw0rd@cluster0.abcde.net/db", "mongodb://admin:<SECRET>/db"),
    ('x "https://u:pa"ss@h.example.com/x"', 'x "https://u:<SECRET>/x"'),
    ("https://u:pa>ss@h.example.com", "https://u:<SECRET>"),
    # Text after the URL is not swallowed: `a@b.co` is an email, on its own.
    ('"https://u:pw@h.com","a@b.co"', '"https://u:<SECRET>","[REDACTED:PII_EMAIL]"'),
]


class TestAUrlPassword:
    @pytest.mark.parametrize(("url", "redacted"), URLS)
    def test_the_password_is_replaced_and_a_dotted_host_goes_with_it(
        self, url: str, redacted: str
    ) -> None:
        """0.4.0 redacted `pw@ftp.example.com` as an address (`ftp://anonymous:[REDACTED:PII_EMAIL]/`):
        the same span, a different class. The span is the same now, and its class is the secret."""
        rows, changed, _ = apply_pii_policy([{"a": url}], _NO_IP)

        assert (rows, changed) == ([{"a": redacted}], 1)
        assert apply_pii_policy(rows, _NO_IP) == (rows, 0, 0)

    def test_the_secret_policy_alone_leaves_the_rest_of_the_url_as_it_is(self) -> None:
        rows = [{"a": '"http://ci:tok3n@[2001:db8::1]:8080/job","a@b.co"'}]

        assert apply_pii_policy(rows, {"PII_SECRET": "redact"})[0] == [
            {"a": '"http://ci:<SECRET>@[2001:db8::1]:8080/job","a@b.co"'}
        ]

    @pytest.mark.parametrize(("url", "redacted"), URLS[:4] + URLS[5:7])
    def test_the_host_is_not_a_second_finding_under_every_class(
        self, url: str, redacted: str
    ) -> None:
        counts = {code: n for code, n in scan_rows([{"a": url}]).counts_by_code.items() if n}

        assert counts == {"PII_SECRET": 1}
        assert apply_pii_policy([{"a": url}], _ALL)[0] == [{"a": redacted}]

    @pytest.mark.parametrize("url", [url for url, _ in URLS[:4]])
    def test_the_email_policy_leaves_a_url_password_and_its_host_alone(self, url: str) -> None:
        """No pattern consults another class: the address the email pattern reads over
        `pw@host.com` is one region with the password, named the secret, so a policy that
        only redacts addresses has nothing to act on (0.4.0 redacted it as an address)."""
        rows = [{"a": url}]

        assert scan_rows(rows).counts_by_code["PII_EMAIL"] == 0
        assert apply_pii_policy(rows, {"PII_EMAIL": "redact"}) == (rows, 0, 0)
        assert apply_pii_policy(rows, {"PII_EMAIL": "drop"}) == (rows, 0, 0)

    def test_an_email_that_is_not_part_of_a_url_password_is_still_an_email(self) -> None:
        rows = [{"a": "mail jane@example.com or https://u:pw@host.com/x"}]

        assert apply_pii_policy(rows, _ALL)[0] == [
            {"a": "mail [REDACTED:PII_EMAIL] or https://u:<SECRET>/x"}
        ]

    def test_an_email_that_is_the_password_is_one_finding(self) -> None:
        """The password and the address are the same span, and a tie goes to the class the
        registry lists first: the email."""
        rows = [{"a": "https://u:jane@example.com@host.com/x"}]

        assert apply_pii_policy(rows, _ALL)[0] == [
            {"a": "https://u:[REDACTED:PII_EMAIL]@host.com/x"}
        ]


class TestTheScanIsLinear:
    @pytest.mark.parametrize(
        "unit",
        [
            "https://u:pw@h.com/a@b.co ",
            '"https://u:p@h.com","a@b.co"',
            "a://b:c@d.e,",
            "://:",
            'http://h:80"x@y.co',
        ],
    )
    def test_a_megabyte_of_urls_and_emails_scans_in_seconds(self, unit: str) -> None:
        """32 KB first, so a quadratic pattern fails in a second. The megabyte is a
        backstop only (about 1 s here, 5 s on a loaded CI runner; quadratic would
        take minutes), so its budget leaves room for a slow runner."""
        for size, limit in [(32_000, 0.5), (1_000_000, 30.0)]:
            text = unit * (size // len(unit))
            started = time.perf_counter()
            scan_rows([{"a": text}])
            assert time.perf_counter() - started < limit, (unit, size)
