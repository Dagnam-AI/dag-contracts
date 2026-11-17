"""A value an ambiguous name refuses does not hide the assignment inside it.

`token=<16+ characters>` is a value, and then a credential only when it is one on its own
(`credentials.py`, "Ambiguous"). The walk over bare values used to jump past the whole
run when it refused one, so a `password=` that stood in that run -- after a `?`, a `|`, a
`:-`, a `#` -- was never looked at: a query string or a colon-joined pair of settings kept
its password. The walk now resumes right after the refused name, so every assignment is
judged on its own, and does so in time and memory that do not grow with how many names the
refused value holds.

These tests read the Python reference (`find_secrets`, and `findings` with the compiled
core off): the core is brought to the same answer from the corpus, not here.
"""

from __future__ import annotations

import random
import time

import pytest
from test_credentials_flat import _credentials_of_the_old_bare

from dagnam_contracts.hygiene import _backend, credentials as cred
from dagnam_contracts.hygiene.credentials import find_secrets
from dagnam_contracts.hygiene.spans import findings

_LONG = "Paris" * 4  # 20 letters: a value, and no credential on its own
_AMBIGUOUS_NAMES = ["token", "auth", "key", "authorization", "Token", "accessToken"]
_UNAMBIGUOUS_NAMES = ["password", "passwd", "secret", "api_key", "client_secret", "PASSWORD"]
# The characters between the refused value and the next name that are not a stop of a
# value, and are not a `/ + . =`, which a value with a digit in it takes whole.
_JOINERS = ["?", "|", ":-", ":_", "#", "!", "@"]
_PASSWORDS = ["hunter22", "correcthorsebattery"]


def _found(text: str) -> list[str]:
    return [text[a:b] for a, b in find_secrets(text)]


@pytest.mark.parametrize("password", _PASSWORDS)
@pytest.mark.parametrize("joiner", _JOINERS)
@pytest.mark.parametrize("name", _AMBIGUOUS_NAMES)
def test_a_password_after_a_refused_value_is_found(name: str, joiner: str, password: str) -> None:
    text = f"{name}={_LONG}{joiner}password={password}"

    assert _found(text) == [password]


@pytest.mark.parametrize("name", _UNAMBIGUOUS_NAMES)
def test_whatever_unambiguous_name_follows(name: str) -> None:
    text = f"token={_LONG}?{name}=correcthorsebattery"

    assert _found(text) == ["correcthorsebattery"]


@pytest.mark.parametrize("joiner", ["/", "+", ".", "="])
def test_a_joiner_a_value_may_hold_does_not_hide_a_password_without_digits(joiner: str) -> None:
    """The run is refused for want of a digit, so the password in it is read on its own."""
    text = f"token={_LONG}{joiner}password=correcthorsebattery"

    assert _found(text) == ["correcthorsebattery"]


@pytest.mark.parametrize("joiner", ["/", "+", ".", "="])
def test_a_run_that_is_a_credential_on_its_own_is_still_one_span(joiner: str) -> None:
    """With a digit the whole run is high entropy, and a value that vouches for itself
    is taken whole, a name inside it included: that is not the defect, and it is kept."""
    text = f"token={_LONG}{joiner}password=hunter22"

    assert _found(text) == [text[len("token=") :]]


def test_an_ambiguous_assignment_after_a_refused_value_is_judged_on_its_own() -> None:
    body = "a1B2c3D4e5F6g7H8i9J0"
    text = f"auth={_LONG}?key={body}"

    assert _found(text) == [body]


def test_a_refused_assignment_after_a_refused_value_stays_refused() -> None:
    text = f"token={_LONG}?key={_LONG}|auth=Paris"

    assert _found(text) == []


@pytest.mark.parametrize(
    "text",
    [
        f"token={_LONG}?note=hello",
        f"token={_LONG}?password=required",
        f"token={_LONG}|secret=short",
        f"key={_LONG}?max_token=128000",
        f"token={_LONG}:-password=",
    ],
)
def test_the_assignments_after_a_refused_value_keep_their_own_rules(text: str) -> None:
    """Resuming inside the value finds only what would be found on its own line."""
    assert _found(text) == []


def test_the_end_to_end_scan_redacts_it() -> None:
    text = f"GET /a?token={_LONG}&x=1 token={_LONG}?password=hunter22 end"
    with _backend.reference():
        spans = [(text[s:e], d.code) for s, e, d in findings(text) if d.code == "PII_SECRET"]

    assert spans == [("hunter22", "PII_SECRET")]


def test_the_values_of_one_refused_run_are_all_read_from_the_same_end() -> None:
    """Every name inside a refused run is judged against the run's own end, which a `:`
    that opens the next assignment may cut short."""
    text = f"token={_LONG}?key=abc:password=hunter22"

    assert _found(text) == ["hunter22"]
    assert [(n, text[a:b]) for n, a, b in cred._bare_assignments(text)] == [
        ("password", "hunter22")
    ]


@pytest.mark.parametrize(
    ("head", "unit", "tail"),
    [
        ("token=?", "a.key=", ""),
        ("token=?", "a.key=", "1"),
        ("token=?", "aa.key=:x", ""),
        ("token=?", "a-auth=b:", ""),
        ("auth=#", "a.token=a1", ""),
        ("key=" + "a" * 20 + "?", "a.password=", ""),
        ("token=?", "a.key=", "a1B2c3D4e5F6g7H8i9J0"),
    ],
)
def test_a_refused_run_of_names_is_scanned_in_linear_time(head: str, unit: str, tail: str) -> None:
    """A name every few characters, all of them inside one refused value: each is judged
    on the whole rest of the run unless the run's verdict is shared. 32 KB first, so a
    quadratic walk fails here in a second; the large step is a backstop."""
    for size, limit in [(32_000, 0.5), (1_000_000, 30.0)]:
        text = head + unit * (size // len(unit)) + tail
        started = time.perf_counter()
        find_secrets(text)
        assert time.perf_counter() - started < limit, (head, unit, size)


_RUN_PIECES = [
    "token=",
    "key=",
    "auth:",
    "password=",
    "api_key=",
    "secret=",
    "_",
    ".",
    "?",
    "|",
    ":",
    ":-",
    "-",
    "/",
    "=",
    "#",
    " ",
    '"',
    ",",
    "a",
    "Paris",
    "b1",
    "7",
    "0123456789",
    "AbCdEfGhIjKlMnOpQrStUv",
    "xoxb-123456789012",
    "hunter22",
]


def test_the_walk_is_the_slow_reading_of_every_name_on_the_whole_run_after_it() -> None:
    """Held, on fuzzed runs of names, to the plain rule (judge each name on its whole
    value, and when an ambiguous name refuses it, move on by one character). The
    shortcuts inside a refused value (its end, and the starts that are high entropy) must
    give exactly that rule's answer."""
    generator = random.Random(11)
    for _ in range(60_000):
        text = "".join(generator.choice(_RUN_PIECES) for _ in range(generator.randint(1, 26)))
        assert cred._bare_assignments(text) == _credentials_of_the_old_bare(text), text
