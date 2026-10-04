"""Tests for the memory a scan takes on a single giant token.

A pattern whose body is a repeated group makes the regex engine keep a stack entry per
repetition, so one unbroken megabyte (a password in a URL, a value after `password:`, an
address with ten thousand labels) cost 60 to 430 MB, and eight megabytes cost gigabytes.
Every pattern in `credentials.py` and `detectors.py` now reads such a token in memory that
does not grow with it. The peak is measured with `tracemalloc`, which sees the regex
engine's own allocations, around the whole redaction of one row.
"""

from __future__ import annotations

import tracemalloc

import pytest

from dagnam_contracts.hygiene.pii import redact_rows

# (head, repeated unit, tail): the text is the head, as many units as fit, the tail.
_TOKENS: dict[str, tuple[str, str, str]] = {
    "letters": ("", "a", ""),
    "an address's local part": ("", "a", "@b.c"),
    "an address's domain labels": ("a@b", ".c", ""),
    "at signs": ("", "a@", ""),
    "colons": ("", "a:", ""),
    "quotes": ("", 'a"', ""),
    "an sk- key's segments": ("sk-", "a-", ""),
    "a value after a name": ("password: ", "a", ""),
    "colons after a name": ("password: ", "a:", ""),
    "a half-quoted value": ('password="', "a", ""),
    "a quoted value never closed": ('"password": "', "a", ""),
    "a quoted value with escaped quotes": ('"password": "', 'a\\"', ""),
    "a URL password": ("x://u:", "a", "@h"),
    "a URL password of at signs": ("x://u:", "a@", "@h"),
    "a URL password of quotes": ("x://u:", 'a"', "@h"),
    "a URL password of colons": ("x://u:", "a:", "@h"),
    "a URL host": ("x://", "a:", ""),
    "a pwd value": ("pwd=", "a", ""),
    "a bearer token": ("Bearer ", "a", ""),
    "a PEM block never closed": ("-----BEGIN PRIVATE KEY-----", "A", ""),
    "a key's run": ("ghp_", "a", ""),
}


def _peak_bytes(name: str, size: int) -> int:
    head, unit, tail = _TOKENS[name]
    text = head + unit * ((size - len(head) - len(tail)) // len(unit)) + tail
    rows = [{"text": text}]
    tracemalloc.start()
    try:
        redact_rows(rows)
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("name", sorted(_TOKENS))
def test_a_giant_token_is_read_in_memory_that_is_a_few_copies_of_it(name: str) -> None:
    """Half a megabyte of one token: the redacted copy and a few slices of the text,
    never the hundreds of times its size the repeated groups took."""
    size = 500_000

    assert _peak_bytes(name, size) <= 4 * size


@pytest.mark.parametrize(
    "name", ["a URL password", "a value after a name", "an address's domain labels"]
)
def test_four_times_the_token_takes_no_more_than_four_times_the_memory(name: str) -> None:
    small, large = _peak_bytes(name, 250_000), _peak_bytes(name, 1_000_000)

    assert large <= 4.5 * max(small, 100_000)
