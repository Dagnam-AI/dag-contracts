"""Tests for the walks in `dagnam_contracts/hygiene/credentials.py` and `detectors.py` that
replaced a repeated regex group.

A group that repeats once per character (`(?:plain|quote(?=...)|@(?=...))+`) keeps a stack
entry per character in the regex engine: a megabyte token cost 200 to 430 MB. The password
of a URL, a bare value after a credential name, the labels of an address's domain and the
prefix segments of an `sk-` key are read now without one. Each is held equal, on fuzzed
text, to the pattern it replaced (kept here, as the oracle).
"""

from __future__ import annotations

import random
import re

import pytest

from dagnam_contracts.hygiene import credentials as cred

_NAMES = cred._NAMES
_NAME_START = cred._NAME_START
_VALUE_CHAR = cred._VALUE_CHAR

# The patterns as they stood, one repeated group each.
_OLD_PASSWORD_CHAR = r"(?:[^\s/?#@\"'`<>]|[\"'`<>](?=[\w%]))"
_OLD_URL_PASSWORD = re.compile(
    r"(?<!\s)://[^\s/?#@:\"'`<>]*:(?!\d{1,5}[,;|&>])"
    rf"(?P<s>(?:{_OLD_PASSWORD_CHAR}|@(?=[\w\[]{_OLD_PASSWORD_CHAR}*@))+)@(?!\s)"
)
_OLD_BARE_CHAR = rf"(?:(?!:\s*(?i:{_NAMES})[\"']?\s*[:=]){_VALUE_CHAR})"
_OLD_BARE = re.compile(
    _NAME_START + rf"(?P<n>(?i:{_NAMES}))[\"']?\s*[:=]\s*[\"']?"
    rf"(?P<s>(?={_OLD_BARE_CHAR}*\d){_OLD_BARE_CHAR}{{6,}}|{_OLD_BARE_CHAR}{{16,}})"
)
_OLD_QUOTED = re.compile(
    _NAME_START + rf"(?P<n>(?i:{_NAMES}))[\"']\s*[:=]\s*(?P<q>[\"'])"
    r"(?P<s>(?:(?!(?P=q))[^\n])+)(?P=q)"
)
_OLD_SK = re.compile(
    r"(?<![A-Za-z0-9_-])(?P<s>sk-(?:[A-Za-z0-9_]*-)*"
    r"(?:(?=[A-Za-z_]*\d)|(?=[a-z0-9_]*[A-Z])(?=[A-Z0-9_]*[a-z]))"
    r"[A-Za-z0-9_]{20,}[A-Za-z0-9_-]*)"
)
_PIECES = [
    "://",
    "x://u:",
    "https://h:",
    "u:",
    ":",
    "@",
    "@@",
    "a",
    "b1",
    "pw",
    "Z9",
    "7",
    "12345",
    '"',
    "'",
    "`",
    "<",
    ">",
    "/",
    "?",
    "#",
    " ",
    "\n",
    "\t",
    ",",
    ";",
    "&",
    "=",
    "[",
    "]",
    "%",
    "-",
    "_",
    ".",
    "..",
    "\\",
    "x.co",
    "a@b.co",
    "8080",
    "8080,",
    "password",
    "Password:",
    "token=",
    "api_key=",
    "key:",
    "secret = ",
    '"password": "',
    "'token': '",
    "pwd=",
    "sk-",
    "sk-a-",
    "sk-1",
    "0123456789012345678901",
    "AbCdEfGhIjKlMnOpQrStUv",
    "-----BEGIN PRIVATE KEY-----",
    "Bearer ",
]


def _texts(seed: int, count: int) -> list[str]:
    generator = random.Random(seed)
    return [
        "".join(generator.choice(_PIECES) for _ in range(generator.randint(1, 18)))
        for _ in range(count)
    ]


class TestEachWalkIsTheirPatternOnFuzzedText:
    def test_the_password_of_a_url(self) -> None:
        for text in _texts(1, 40_000):
            oracle = [m.span("s") for m in _OLD_URL_PASSWORD.finditer(text)]
            assert cred._url_password_spans(text) == oracle, text

    def test_a_bare_value_after_a_name(self) -> None:
        for text in _texts(2, 40_000):
            oracle = [(m["n"], *m.span("s")) for m in _OLD_BARE.finditer(text)]
            assert cred._bare_assignments(text) == oracle, text

    def test_a_quoted_value_after_a_name(self) -> None:
        for text in _texts(3, 40_000):
            oracle = [(m["n"], *m.span("s")) for m in _OLD_QUOTED.finditer(text)]
            new = [
                (m["n"], *m.span("s" if m["s"] is not None else "t"))
                for m in cred._QUOTED_ASSIGNMENT.finditer(text)
            ]
            assert new == oracle, text

    def test_the_prefix_segments_of_an_sk_key(self) -> None:
        shape = next(p for p in cred._SHAPES if "sk-" in p.pattern)
        generator = random.Random(5)
        parts = ["sk-", "a", "-", "1", "_", "Ab", "x-", "ant-", "api03-", "Z", "0123456789"]
        for _ in range(40_000):
            text = "".join(generator.choice(parts) for _ in range(generator.randint(1, 16)))
            old = [m.span("s") for m in _OLD_SK.finditer(text)]
            new = [m.span("s") for m in shape.finditer(text) if m["s"].startswith("sk-")]
            assert new == old, text

    def test_a_key_the_name_vouches_for_reads_its_segments_the_same_way(self) -> None:
        old = re.compile(r"(?<![A-Za-z0-9_-])sk-(?:[A-Za-z0-9_]*-)*[A-Za-z0-9_]{20,}")
        generator = random.Random(6)
        parts = ["sk-", "a", "-", "1", "_", "Ab", "x-", "ant-", "0123456789", "z"]
        for _ in range(40_000):
            text = "".join(generator.choice(parts) for _ in range(generator.randint(1, 16)))
            assert [m.span() for m in cred._VOUCHED_KEY.finditer(text)] == [
                m.span() for m in old.finditer(text)
            ], text


class TestTheWalksOnTheShapesThatBrokeThePatterns:
    @pytest.mark.parametrize(
        ("text", "password"),
        [
            ("mongodb://admin:p@ssw0rd@cluster0/db", "p@ssw0rd"),
            ("x://u:a@b@ c", "a"),  # the last `@` is followed by a space, so the first ends it
            ('x://u:pa"ss@h', 'pa"ss'),
            ('x://u:pa"@h', None),  # a quote before the `@` needs a word character after it
            ("x://:-@h", "-"),
            ("x://u:@h", None),
            ("x://u:8080,a@b.co", None),
        ],
    )
    def test_a_password_by_hand(self, text: str, password: str | None) -> None:
        spans = cred._url_password_spans(text)

        assert [text[a:b] for a, b in spans] == ([] if password is None else [password])

    def test_a_value_after_a_name_stops_before_the_next_assignment(self) -> None:
        text = "token=abc123def456ghi789:password=hunter22"

        assert [(n, text[a:b]) for n, a, b in cred._bare_assignments(text)] == [
            ("token", "abc123def456ghi789"),
            ("password", "hunter22"),
        ]
