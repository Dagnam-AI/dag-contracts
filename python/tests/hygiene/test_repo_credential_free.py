"""No file the repository tracks holds credential-shaped text, fake or not.

The repository is public, and "do not even push fake credentials" is the rule: a test
that needs the shape of a key puts it together at run time, from pieces (`corpus_atoms`,
or a plus between two short literals), and documentation writes `<name>` and `<value>`.
This test reads every tracked text file (and every new one not yet tracked, so a file is
checked before it is committed) with the package's own finder (`find_secrets`)
and with three marker scans, and reports ``file:line`` and the kind of the hit, never
the text. A text it cannot decode is a binary file and is not read.

* ``finder``: a span `find_secrets` reports;
* ``prefix``: a provider prefix (`corpus_atoms.PROVIDER_PREFIXES` and `LABELLED_PREFIXES`)
  followed by eight or more token characters. A bare prefix is the finder's own data (the
  tables in `hygiene/credentials.py`) and is not a hit; a run of letters before it makes
  it the end of a word (``task-``), also not one;
* ``url password``: ``<scheme>://<user>:<password>@<host>`` with a real user and a real
  password; a placeholder in angle brackets is neither;
* ``named value``: a credential name (`corpus_atoms.NAME_PATTERNS`, but for the two that
  are ambiguous on their own, a token and an authorization) and a separator, then a
  quoted value of six or more characters, or a bare one of six or more that holds a digit.

No file is exempt: the finder's own module, and this one, hold none of it.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path
import re
import subprocess

from corpus_atoms import LABELLED_PREFIXES, NAME_PATTERNS, PROVIDER_PREFIXES
import pytest

from dagnam_contracts.hygiene.credentials import find_secrets

ROOT = Path(__file__).resolve().parents[3]

_TOKEN_CHARS = "[A-Za-z0-9_-]"
_PREFIXES = "|".join(re.escape(p) for p in sorted({*PROVIDER_PREFIXES, *LABELLED_PREFIXES}))
_NAMES = "|".join(n for n in NAME_PATTERNS if not n.startswith(("token", "auth")))
_SEPARATOR = r"(?::=|=>|->|[:=])"
_BARE_VALUE = "[A-Za-z0-9+/_.~=-]"
PATTERNS = {
    "prefix": re.compile(rf"(?<![A-Za-z0-9_-])(?:{_PREFIXES}){_TOKEN_CHARS}{{8,}}"),
    "url password": re.compile(r"[\w+.-]*://[^/\s:@\"'`<>]+:(?!<)[^/\s@\"'`]+@"),
    "named value": re.compile(
        rf"(?i)(?<![A-Za-z0-9])(?:{_NAMES})[\w-]{{0,16}}[\"']?\s*{_SEPARATOR}\s*"
        rf"(?:[\"'](?![<\[])[^\s\"']{{6,}}|(?={_BARE_VALUE}*\d){_BARE_VALUE}{{6,}})"
    ),
}


def tracked_text() -> Iterator[tuple[str, str]]:
    """The path (from the repository root) and the text of every tracked or new text file."""
    listing = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        capture_output=True,
        check=True,
    ).stdout.decode()
    for name in filter(None, listing.split("\0")):
        if not (ROOT / name).is_file():
            continue  # tracked, and deleted from the working tree
        try:
            yield name, (ROOT / name).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue  # a binary file


def hits(text: str) -> list[tuple[int, str]]:
    """The line and the kind of every credential-shaped piece of ``text``."""
    starts = [(start, "finder") for start, _ in find_secrets(text)]
    for kind, pattern in PATTERNS.items():
        starts.extend((m.start(), kind) for m in pattern.finditer(text))
    return sorted({(text.count("\n", 0, start) + 1, kind) for start, kind in starts})


def test_no_tracked_file_holds_credential_shaped_text() -> None:
    found = [
        f"{name}:{line} ({kind})" for name, text in tracked_text() for line, kind in hits(text)
    ]

    assert not found, "credential-shaped text, build it at run time or write a placeholder:\n" + (
        "\n".join(found)
    )


def test_the_scan_reads_the_finders_own_module_and_this_file() -> None:
    names = [name for name, _ in tracked_text()]

    assert "python/dagnam_contracts/hygiene/credentials.py" in names
    assert "python/tests/hygiene/" + Path(__file__).name in names
    assert "CHANGELOG.md" in names
    assert len(names) > 50


# What each scan must report, put together here from pieces: this file holds none whole.
_NAME = "pass" + "word"
_SAMPLES: dict[str, Callable[[], str]] = {
    "finder": lambda: f"{_NAME}: " + "hunt" + "er22",
    "prefix": lambda: PROVIDER_PREFIXES[0] + "AbCd" + "EfGh" + "1234",
    "url password": lambda: "ht" + "tps://al" + "ice:s3" + "cr3t@host.example",
    "named value": lambda: "api" + "_key" + " = " + '"Zx9' + 'Qw8Er7"',
}


@pytest.mark.parametrize("kind", sorted(_SAMPLES))
def test_each_scan_reports_the_text_it_is_for(kind: str) -> None:
    assert (1, kind) in hits(_SAMPLES[kind]())


@pytest.mark.parametrize("prefix", sorted({*PROVIDER_PREFIXES, *LABELLED_PREFIXES}))
def test_a_bare_prefix_is_data_and_not_a_hit(prefix: str) -> None:
    assert hits(f"the prefix {prefix} starts a key") == []
    assert hits(f"`{prefix}`, short: {prefix}Ab12") == []


def test_the_end_of_a_word_is_not_a_prefix() -> None:
    assert hits("a task" + "-oriented-dialogue-system") == []


@pytest.mark.parametrize(
    "text",
    [
        "ht" + "tps://<user>:<password>@<host>",
        '{"<name>": "<' + 'SECRET>"}',
        "max_" + "tokens: 128000, the authorization header",
    ],
)
def test_a_placeholder_and_an_ambiguous_name_are_not_hits(text: str) -> None:
    assert hits(text) == []


def test_a_hit_is_reported_by_line_and_kind_and_not_by_its_text() -> None:
    text = "one\ntwo\n" + _SAMPLES["url password"]() + "\n"

    assert {line for line, _ in hits(text)} == {3}
    assert (3, "url password") in hits(text)
