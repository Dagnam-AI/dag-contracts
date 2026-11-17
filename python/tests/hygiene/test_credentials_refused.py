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
from test_credentials_flat import _credentials_of_the_old_bare, bare_walk_before_r1

from dagnam_contracts.hygiene import _backend, credentials as cred
from dagnam_contracts.hygiene.credentials import find_secrets
from dagnam_contracts.hygiene.spans import findings

# Nothing here is written as a whole: a credential-shaped literal is what secret scanners
# (and `find_secrets`) report, so the names and the values are put together at run time.
_PW_NAME = "pass" + "word"
_KEY_NAME = "api" + "_key"
_LONG = "Paris" * 4  # 20 letters: a value, and no credential on its own
_AMBIGUOUS_NAMES = ["token", "auth", "key", "authorization", "Token", "accessToken"]
_UNAMBIGUOUS_NAMES = [
    _PW_NAME,
    "pass" + "wd",
    "sec" + "ret",
    _KEY_NAME,
    "client_sec" + "ret",
    "PASS" + "WORD",
]
# The characters between the refused value and the next name that are not a stop of a
# value, and are not a `/ + . =`, which a value with a digit in it takes whole.
_JOINERS = ["?", "|", ":-", ":_", "#", "!", "@"]
_WITH_DIGITS = "hun" + "ter" + "22"
_PASSWORDS = [_WITH_DIGITS, "correct" + "horse" + "battery"]
_SPOKEN = _PASSWORDS[1]  # no digit: found only because its name is not an ambiguous one
_BODY = "a1B2c3" + "D4e5F6g7" + "H8i9J0"  # high entropy on its own


def _found(text: str) -> list[str]:
    return [text[a:b] for a, b in find_secrets(text)]


@pytest.mark.parametrize("password", _PASSWORDS)
@pytest.mark.parametrize("joiner", _JOINERS)
@pytest.mark.parametrize("name", _AMBIGUOUS_NAMES)
def test_a_password_after_a_refused_value_is_found(name: str, joiner: str, password: str) -> None:
    text = f"{name}={_LONG}{joiner}{_PW_NAME}={password}"

    assert _found(text) == [password]


@pytest.mark.parametrize("name", _UNAMBIGUOUS_NAMES)
def test_whatever_unambiguous_name_follows(name: str) -> None:
    text = f"token={_LONG}?{name}={_SPOKEN}"

    assert _found(text) == [_SPOKEN]


@pytest.mark.parametrize("joiner", ["/", "+", ".", "="])
def test_a_joiner_a_value_may_hold_does_not_hide_a_password_without_digits(joiner: str) -> None:
    """The run is refused for want of a digit, so the password in it is read on its own."""
    text = f"token={_LONG}{joiner}{_PW_NAME}={_SPOKEN}"

    assert _found(text) == [_SPOKEN]


@pytest.mark.parametrize("joiner", ["/", "+", ".", "="])
def test_a_run_that_is_a_credential_on_its_own_is_still_one_span(joiner: str) -> None:
    """With a digit the whole run is high entropy, and a value that vouches for itself
    is taken whole, a name inside it included: that is not the defect, and it is kept."""
    text = f"token={_LONG}{joiner}{_PW_NAME}={_WITH_DIGITS}"

    assert _found(text) == [text[len("token=") :]]


def test_an_ambiguous_assignment_after_a_refused_value_is_judged_on_its_own() -> None:
    text = f"auth={_LONG}?key={_BODY}"

    assert _found(text) == [_BODY]


def test_a_refused_assignment_after_a_refused_value_stays_refused() -> None:
    text = f"token={_LONG}?key={_LONG}|auth=Paris"

    assert _found(text) == []


@pytest.mark.parametrize(
    "text",
    [
        f"token={_LONG}?note=hello",
        f"token={_LONG}?{_PW_NAME}=required",
        f"token={_LONG}|secret=short",
        f"key={_LONG}?max_token=128000",
        f"token={_LONG}:-{_PW_NAME}=",
    ],
)
def test_the_assignments_after_a_refused_value_keep_their_own_rules(text: str) -> None:
    """Resuming inside the value finds only what would be found on its own line."""
    assert _found(text) == []


def test_the_end_to_end_scan_redacts_it() -> None:
    text = f"GET /a?token={_LONG}&x=1 token={_LONG}?{_PW_NAME}={_WITH_DIGITS} end"
    with _backend.reference():
        spans = [(text[s:e], d.code) for s, e, d in findings(text) if d.code == "PII_SECRET"]

    assert spans == [(_WITH_DIGITS, "PII_SECRET")]


def test_the_values_of_one_refused_run_are_all_read_from_the_same_end() -> None:
    """Every name inside a refused run is judged against the run's own end, which a `:`
    that opens the next assignment may cut short."""
    text = f"token={_LONG}?key=abc:{_PW_NAME}={_WITH_DIGITS}"

    assert _found(text) == [_WITH_DIGITS]
    assert [(n, text[a:b]) for n, a, b in cred._bare_assignments(text)] == [
        (_PW_NAME, _WITH_DIGITS)
    ]


@pytest.mark.parametrize(
    ("head", "unit", "tail"),
    [
        ("token=?", "a.key=", ""),
        ("token=?", "a.key=", "1"),
        ("token=?", "aa.key=:x", ""),
        ("token=?", "a-auth=b:", ""),
        ("auth=#", "a.token=a1", ""),
        ("key=" + "a" * 20 + "?", "a." + _PW_NAME + "=", ""),
        ("token=?", "a.key=", _BODY),
        # The run is a credential (a digit, or high entropy), so every name in it is passed
        # over, each for the cost of finding it; and a space before the next name ends it.
        (_KEY_NAME + "=1", "a.key=", ""),
        ("token=" + _BODY + "?", "a1.key=", ""),
        ("token=" + _BODY + "?", "a1.key = ", ""),
        (_KEY_NAME + "= ", "a1.token=" + _LONG + " ", ""),
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
    _PW_NAME + "=",
    _KEY_NAME + "=",
    "sec" + "ret=",
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
    " = ",
    '"',
    ",",
    "a",
    "abc123",
    "Paris",
    "b1",
    "7",
    "0123456789",
    "AbCdEfGhIjKlMnOpQrStUv",
    "xo" + "xb-" + "1234" + "5678" + "9012",
    _WITH_DIGITS,
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


_SHORT = (
    "abc" + "123"
)  # too short to be a credential under an ambiguous name, but not under api_key


def test_a_credential_inside_an_accepted_value_is_not_lost() -> None:
    """The first name a text gives is refused (20 letters), the next takes `abc123/` up to
    a space, and the password after that space starts inside no value of the second: it is
    its own assignment and is found, as the walk before R1 found it."""
    text = f"token={_LONG}/{_KEY_NAME} = {_SHORT}/{_PW_NAME} = {_WITH_DIGITS}"

    assert _WITH_DIGITS in _found(text)
    assert [text[a:b] for _, a, b in cred._bare_assignments(text)] == [
        f"{_SHORT}/{_PW_NAME}",
        _WITH_DIGITS,
    ]


def test_a_name_inside_an_accepted_value_is_not_read_twice() -> None:
    """A value taken whole holds the names in it: only a value that starts after it is new."""
    text = f"{_KEY_NAME}={_SHORT}/{_PW_NAME}={_WITH_DIGITS}"

    assert [text[a:b] for _, a, b in cred._bare_assignments(text)] == [
        f"{_SHORT}/{_PW_NAME}={_WITH_DIGITS}"
    ]


_UNIT_NAMES = ["token", "key", "auth", _PW_NAME, _KEY_NAME, "sec" + "ret"]
_UNIT_SEPARATORS = ["=", " = ", ": ", "="]
_UNIT_VALUES = [_LONG, _SHORT, _WITH_DIGITS, _BODY, "x", "Paris", _SPOKEN]
_UNIT_JOINERS = ["/", "?", " ", "|", "", "/", " ", ":-"]


def _assignments_text(generator: random.Random) -> str:
    """One to four ``name <separator> value <joiner>`` units: the shapes in which one
    assignment's value runs into the next one's name."""
    return "".join(
        generator.choice(_UNIT_NAMES)
        + generator.choice(_UNIT_SEPARATORS)
        + generator.choice(_UNIT_VALUES)
        + generator.choice(_UNIT_JOINERS)
        for _ in range(generator.randint(1, 4))
    )


def _covered(spans: list[tuple[str, int, int]]) -> set[int]:
    return {index for _, a, b in spans for index in range(a, b)}


def test_every_character_the_walk_before_r1_covered_is_still_covered() -> None:
    """R1 only adds: whatever the old walk found (a value it consumed whole, names in it
    included) is still found, over fuzzed assignments run into one another, and over fuzzed
    runs of names, `/`, ` = ` and short values."""
    generator = random.Random(23)
    for index in range(80_000):
        text = (
            _assignments_text(generator)
            if index % 2
            else "".join(generator.choice(_RUN_PIECES) for _ in range(generator.randint(1, 26)))
        )
        lost = _covered(bare_walk_before_r1(text)) - _covered(cred._bare_assignments(text))
        assert not lost, text


def test_the_walk_is_the_slow_reading_of_assignments_run_into_one_another() -> None:
    generator = random.Random(29)
    for _ in range(40_000):
        text = _assignments_text(generator)
        assert cred._bare_assignments(text) == _credentials_of_the_old_bare(text), text
