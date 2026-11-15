"""The pieces the corpus inputs are built from, and the sources that must not hold one whole.

Every source of the corpus exporter (and of its tests) is public. No name, value, prefix,
header or URL with a user may be recognisable in one, whole, cut with a bar or a plus, or
in a comment or docstring. The list of what that means is built here, at run time, from
`corpus_atoms`, so that this file holds none of it either.
"""

import ast
from collections.abc import Iterator
from pathlib import Path
import re
import unicodedata

import corpus_atoms as atoms
import pytest
from test_corpus_credentials import NAME_SHAPES

HERE = Path(__file__).parent
SOURCES = [
    *sorted(HERE.glob("corpus_*.py")),
    HERE / "export_corpus.py",
    *sorted(HERE.glob("test_corpus_*.py")),
    HERE / "test_export_corpus.py",
]
# The groups whose entries no source may hold, however they are cut.
FORBIDDEN_GROUPS = (
    "MARKERS",
    "DOC_VALUES",
    "TEST_MARKERS",
    "NAMES",
    "PROVIDER_PREFIXES",
    "LABELLED_PREFIXES",
    "HEADER",
    "HEADER_SCHEMES",
    "CONTEXT_LABELS",
    "URL_LABEL",
    "VALUES",
    "GUARD_VALUES",
    "USERS",
    "ODD_URLS",
    "HOSTPARTS",
    "PEM_KINDS",
    "PEM_INPUTS",
    "PEM_LONG",
    "CASE_FOLD_TEXTS",
    "LONE_TEXT",
    "NESTED",
    "WORDS3",
    "HELD_CODE",
    "URL_SPANS_FN",
)
# Provider and label prefixes: looked for as plain, case-insensitive substrings in every
# decoded constant, every run of constants joined by ``+`` or by implicit concatenation,
# and every raw line. No whole-word rule: ``s`` + ``k-`` and an escaped first letter must
# read as the prefix they spell.
PREFIX_GROUPS = ("MARKERS", "TEST_MARKERS", "PROVIDER_PREFIXES", "LABELLED_PREFIXES")
# Groups of key material: any four characters of an entry that hold a letter and two
# digits are as good as the entry.
KEY_GROUPS = ("VALUES", "GUARD_VALUES")
# How many entries each group has: the exporter's old tables, entry for entry (the export
# is byte-identical to the one the old tables made).
COUNTS = {
    "MARKERS": 41,
    "DOC_VALUES": 4,
    "TEST_MARKERS": 36,
    "NAMES": 25,
    "NAME_PATTERNS": 13,
    "TEST_STEMS": 11,
    "LABELLED_PREFIXES": 12,
    "PROVIDER_PREFIXES": 13,
    "HEADER_SCHEMES": 3,
    "CONTEXT_LABELS": 3,
    "VALUES": 3,
    "GUARD_VALUES": 10,
    "USERS": 8,
    "HOSTS": 6,
    "URL_SCHEMES": 3,
    "ODD_URLS": 3,
    "HOSTPARTS": 4,
    "PEM_WORDS": 4,
    "PEM_KINDS": 4,
    "PEM_INPUTS": 4,
    "PEM_LONG": 3,
    "CASE_FOLD_TEXTS": 6,
    "NESTED": 3,
    "WORDS3": 3,
}
SINGLES = (
    "HEADER",
    "URL_LABEL",
    "URL_SEP",
    "LONE_TEXT",
    "ASSIGN_HEAD",
    "ASSIGN_VALUE",
    "LONG_ASSIGN",
    "HELD_CODE",
    "URL_SPANS_FN",
)
# A word, a colon and three or more characters that are not blanks, in one string literal.
PAIR = re.compile(r"\w+:[^\s@]{3,}")
# A constant that is one run of base64 or hex characters, 24 or more: a key's shape.
# Found anywhere (after a character that is not one), so a blank, a ``name=``, a comment
# or a dot beside it does not hide it.
LONG_RUN = re.compile(r"(?<![A-Za-z0-9+/_.-])[A-Za-z0-9+/_.-]{24,}")


def _entries(name: str) -> tuple[str, ...]:
    value = getattr(atoms, name)
    return (value,) if isinstance(value, str) else value


def _fold(text: str) -> str:
    return unicodedata.normalize("NFKC", text).casefold()


def _squash(text: str) -> str:
    """``text`` folded, with everything but letters and digits dropped: a name cut with a
    bar, a plus or a quote reads whole."""
    return "".join(c for c in _fold(text) if c.isalnum())


def _forbidden() -> list[str]:
    """The entries as folded text, less the two families a source may name: a generic word
    (``key``) and the topic of the feature (``credential``, in every file name)."""
    entries = {_fold(t) for name in FORBIDDEN_GROUPS for t in _entries(name)}
    return sorted(t for t in entries if t != "key" and not t.startswith("cred"))


def _runs() -> set[str]:
    """Four-character runs of the key material that hold a letter and two digits."""
    out: set[str] = set()
    for name in KEY_GROUPS:
        for entry in map(_squash, _entries(name)):
            for at in range(len(entry) - 3):
                run = entry[at : at + 4]
                if sum(c.isdigit() for c in run) >= 2 and not run.isdigit():
                    out.add(run)
    return out


PREFIXES = sorted({_fold(t) for g in PREFIX_GROUPS for t in _entries(g) if t})
FORBIDDEN = _forbidden()
RUNS = _runs()


def reads(text: str) -> list[str]:
    """What ``text`` holds of the forbidden list. An entry of five or more letters and
    digits is looked for in the squashed text; a shorter one, and an all-digit one, only
    as a whole word, so that a longer word that starts with one is not read. The only
    whole-word exemptions: names of 3-4 letters (a longer word starts with one), and the
    all-digit value (a number inside a longer number is not it). Prefixes are not here:
    `prefix_hits` reads them as plain substrings."""
    folded, squashed = _fold(text), _squash(text)
    found: list[str] = []
    for entry in FORBIDDEN:
        key = _squash(entry)
        if len(key) >= 5 and not key.isdigit():
            if key in squashed:
                found.append(entry)
        elif len(key) >= 3:
            word = entry.strip()
            # A prefix that ends in a symbol (``xx_``) is read whatever follows it.
            after = r"(?!\w)" if word[-1].isalnum() else ""
            if re.search(rf"(?<!\w){re.escape(word)}{after}", folded):
                found.append(entry)
    found += [run for run in sorted(RUNS) if run in squashed]
    return found


def _constants(path: Path) -> Iterator[tuple[int, str, bool]]:
    """Every string or bytes constant of a source, decoded, and every f-string's constant
    pieces joined: its line, its text, and whether it is a docstring (a pair test would
    only find prose there)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str | bytes):
            text = node.value if isinstance(node.value, str) else node.value.decode("latin-1")
            yield node.lineno, text, id(node) in docstrings
        elif isinstance(node, ast.JoinedStr):
            pieces = [v.value for v in node.values if isinstance(v, ast.Constant)]
            yield node.lineno, "".join(str(p) for p in pieces), False


def key_runs(text: str) -> list[str]:
    """Runs of 24 or more key characters that hold a letter and a digit. Identifiers (no
    digit) and phone numbers (no letter) are not keys."""
    return [
        m.group()
        for m in LONG_RUN.finditer(text)
        if any(c.isdigit() for c in m.group()) and any(c.isalpha() for c in m.group())
    ]


def _repeat(node: ast.BinOp) -> str:
    """``"ab" * 3`` (either order) as text; ``""`` for anything else, or over 64 times."""
    left, right = node.left, node.right
    if isinstance(left, ast.Constant) and isinstance(right, ast.Constant):
        for text, count in ((left.value, right.value), (right.value, left.value)):
            if isinstance(text, str) and isinstance(count, int) and 0 <= count <= 64:
                return text * count
    return ""


def _leaves(node: ast.expr) -> Iterator[str]:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        yield from _leaves(node.left)
        yield from _leaves(node.right)
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        yield _repeat(node)
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and isinstance(node.func.value, ast.Constant)
        and isinstance(node.func.value.value, str)
        and len(node.args) == 1
        and isinstance(node.args[0], ast.List | ast.Tuple)
    ):
        yield node.func.value.value.join("".join(_leaves(e)) for e in node.args[0].elts)
    elif isinstance(node, ast.Constant) and isinstance(node.value, str | bytes):
        yield node.value if isinstance(node.value, str) else node.value.decode("latin-1")


def _joined(path: Path) -> Iterator[tuple[int, str]]:
    """The constants of every ``a + b + ...`` chain joined, whatever stands between them
    (implicit concatenation is already one constant for ``ast``); also ``"" .join([...])``
    of constants and ``"ab" * 2`` terms, followed statically."""
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.BinOp | ast.Call) and (text := "".join(_leaves(node))):
            yield node.lineno, text


def prefix_hits(text: str) -> list[str]:
    folded = _fold(text)
    return [prefix for prefix in PREFIXES if prefix in folded]


def _problems(path: Path) -> list[str]:
    found: list[str] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").split("\n"), start=1):
        if hit := reads(line):
            found.append(f"{path.name}:{number} line holds {hit[0][:3]}...")
        if prefix_hits(line):
            found.append(f"{path.name}:{number} prefix")
        if key_runs(line):
            found.append(f"{path.name}:{number} line holds a run of key characters")
        if any(pattern.search(line) for pattern in NAME_SHAPES):
            found.append(f"{path.name}:{number} name or user in a URL")
    for number, text, docstring in _constants(path):
        if hit := reads(text):
            found.append(f"{path.name}:{number} literal holds {hit[0][:3]}...")
        if prefix_hits(text):
            found.append(f"{path.name}:{number} literal holds a prefix")
        if not docstring and PAIR.search(text):
            found.append(f"{path.name}:{number} word, colon and value")
        if key_runs(text):
            found.append(f"{path.name}:{number} literal holds a run of key characters")
    for number, text in _joined(path):
        if hit := reads(text) or prefix_hits(text) or key_runs(text):
            found.append(f"{path.name}:{number} joined literals hold {hit[0][:3]}...")
    return found


def test_the_sources_of_this_corpus_hold_nothing_that_reads_as_a_credential() -> None:
    assert len(SOURCES) >= 9 and HERE / "corpus_atoms.py" in SOURCES
    assert len(FORBIDDEN) > 100
    problems = [problem for path in SOURCES for problem in _problems(path)]
    assert problems == []


KEY = bytes(range(160, 175)).hex()  # thirty hex characters, built here, as a key would be


def _escaped(text: str) -> str:
    return f"\\x{ord(text[0]):02x}{text[1:]}"


def _plants() -> list[str]:
    """One of each thing a source must not hold, as source text, built from the entries at
    run time: whole, cut with a plus or by implicit concatenation, and escaped."""
    name, value, scheme = atoms.NAMES[0], atoms.VALUES[0], atoms.HEADER_SCHEMES[0]
    short, four, upper = (
        atoms.PROVIDER_PREFIXES[0],
        atoms.PROVIDER_PREFIXES[5],
        atoms.PROVIDER_PREFIXES[3],
    )
    jwt = atoms.LABELLED_PREFIXES[1]
    return [
        f'x = "{name}: {value}"',  # a name and a value
        f'x = "{value}"',  # a value
        f'x = "{atoms.HEADER}: {scheme} x"',  # a header
        f'x = "{four}abcdefgh"',  # a prefix
        f'x = "{atoms.URL_SCHEMES[1]}{atoms.URL_SEP}{atoms.USERS[1]}@h"',  # a user in a URL
        f'x = "{name[:4]}|{name[4:]}"',  # a name cut with a bar
        f'x = "{name[:4]}" + "{name[4:]}"',  # a name cut with a plus
        f'x = "{short[:1]}" + "{short[1:]}ab12"',  # a short prefix cut with a plus
        f'x = "{short[:1]}" "{short[1:]}ab12"',  # a short prefix, implicit concatenation
        f'x = ("{short[:1]}"\n     "{short[1:]}ab12")',  # the same across lines
        f'x = "{four[:2]}" + "{four[2:]}ab12"',  # a four-character prefix cut with a plus
        f'x = "{upper[:2]}" + "{upper[2:]}ab12"',  # an upper-case prefix cut with a plus
        f'x = "{_escaped(upper)}ab12"',  # an escaped first letter
        f'x = "{_escaped(jwt)}ab12"',  # the same for the three-character label
        f'x = "{KEY}"',  # a long run of key characters
        f'x = f"{{y}}{short[:1]}" "{short[1:]}ab12"',  # a prefix after an f-string piece
        f'x = "".join(["{short[:1]}", "{short[1:]}ab12"])',  # a prefix in a join of a list
        f'x = "".join(("{four[:2]}", "{four[2:]}ab12"))',  # a prefix in a join of a tuple
        f'x = "{short[:1]}" + "{short[1:]}ab12" * 1',  # a prefix with a repeated term
        f'x = "{KEY} "',  # a key and a blank
        f"# key={KEY}",  # a key after a name, in a comment
        f'x = "{KEY[:15]}.{KEY[15:]}"',  # a key with a dot inside
        f'x = "{KEY[:15]}" + "{KEY[15:]}"',  # a key cut with a plus
    ]


@pytest.mark.parametrize("planted", range(23))
def test_a_planted_name_value_header_prefix_or_user_is_read(planted: int, tmp_path: Path) -> None:
    path = tmp_path / "planted.py"
    path.write_text(_plants()[planted], encoding="utf-8")
    assert _problems(path)


def test_every_fragment_is_short_and_none_is_a_forbidden_entry() -> None:
    assert len(set(atoms.FRAGMENTS)) == len(atoms.FRAGMENTS) > 100
    assert all(1 <= len(piece) <= 3 for piece in atoms.FRAGMENTS)
    enforced = [t for t in FORBIDDEN if len(_squash(t)) >= 3]
    assert not {_squash(piece) for piece in atoms.FRAGMENTS} & {_squash(t) for t in enforced}
    assert not {_fold(piece) for piece in atoms.FRAGMENTS} & set(enforced)


def test_the_atoms_assemble_the_entries_the_old_tables_held() -> None:
    assert atoms.atom() == ""
    assert atoms.atom(0, 1) == atoms.FRAGMENTS[0] + atoms.FRAGMENTS[1]
    for name, count in COUNTS.items():
        entries = _entries(name)
        assert len(entries) == count, name
        assert any(entries) and all(isinstance(e, str) for e in entries), name
    for name in SINGLES:
        assert isinstance(getattr(atoms, name), str) and getattr(atoms, name), name
    # The groups the exporter keys on keep their shape.
    assert len(set(atoms.MARKERS)) == 41 and all(m == m.casefold() for m in atoms.MARKERS)
    assert len(set(atoms.TEST_MARKERS)) == 36
    assert len(set(atoms.NAMES)) == 25 and "key" in atoms.NAMES
    assert len(atoms.VALUES[0]) == 9 and len(atoms.VALUES[1]) == 18
    assert atoms.URL_SEP == "://" and atoms.HELD_CODE.startswith("PII_")
