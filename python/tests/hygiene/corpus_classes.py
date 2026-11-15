"""The character classes of Python's `re`, as code-point ranges.

Not a test module: a port that cannot use Python's `\\w`, `\\s` and `\\d` (another engine
disagrees on a few thousand code points, and a Unicode release moves them) is pinned to
what `re` answers for every code point, computed here rather than read from a table.
"""

from __future__ import annotations

from collections.abc import Callable
import re
from typing import Any

# Every code point; the surrogates cannot be written to a UTF-8 file, so they are skipped.
LAST = 0x10FFFF
SURROGATES = range(0xD800, 0xE000)
CLASSES = {"word": r"\w", "space": r"\s", "digit": r"\d"}


def ranges(member: Callable[[int], bool]) -> list[list[int]]:
    """The inclusive ``[lo, hi]`` runs of the code points ``member`` accepts, ascending.

    Adjacent runs are one run, and no run spans a surrogate.
    """
    runs: list[list[int]] = []
    for code in range(LAST + 1):
        if code in SURROGATES or not member(code):
            continue
        if runs and runs[-1][1] == code - 1:
            runs[-1][1] = code
        else:
            runs.append([code, code])
    return runs


def _matches(pattern: str) -> Callable[[int], bool]:
    find = re.compile(pattern).fullmatch
    return lambda code: find(chr(code)) is not None


def class_case() -> dict[str, Any]:
    """The one ``classes.jsonl`` line: each class of `re` as its ranges."""
    return {name: ranges(_matches(pattern)) for name, pattern in CLASSES.items()}
