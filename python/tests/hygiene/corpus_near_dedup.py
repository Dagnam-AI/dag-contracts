"""The near-duplicate cases of the reference corpus.

Not a test module. A case is a list of texts, a threshold and what the reference
decided. Every stored text is already what ``row_text`` makes of it (words joined by one
U+0020, case-folded, punctuation gone), so a port shingles it directly, and the
reference is run on ``[{"t": text}]``, which hands ``row_text`` the same string back.

Besides groups of seeded rows with planted near-copies, the cases pin what a port gets
wrong when it is only mostly right: chains (A like B, B like C, A not like C), a pair
whose estimate reaches the threshold but that shares no LSH band, a pair that lands
exactly on a dyadic threshold, empty texts, and texts of fewer than three words.
"""

from __future__ import annotations

import random
from typing import Any

from corpus_inputs import leaves
from corpus_regions import exportable, leaks

from dagnam_contracts.hygiene.near_dedup import (
    _candidate_pairs,
    compute_near_duplicates,
    estimate_jaccard,
    minhash_signature,
    row_text,
    shingles,
)

THRESHOLDS = (0.3, 0.5, 0.875, 0.9, 0.99, 1.0)
GROUP = 40
GROUPS = 8
BIG_GROUP = 100
SEARCH_ATTEMPTS = 4000
_VOCABULARY = [f"w{i}" for i in range(400)]


def normalised(text: str) -> str:
    """What the reference makes of ``text`` as the one string leaf of a row."""
    return row_text({"t": text})


def usable(text: str) -> bool:
    """A text that is already normalised, UTF-8 encodable and holds no credential."""
    return exportable(text) and normalised(text) == text


def _signature(text: str) -> tuple[int, ...]:
    return minhash_signature(shingles(text))


def case(texts: list[str], threshold: float) -> dict[str, Any]:
    """The reference's verdict on ``texts``; an unusable text is dropped first."""
    kept = [text for text in texts if usable(text)]
    result = compute_near_duplicates([{"t": text} for text in kept], threshold)
    return {
        "texts": kept,
        "threshold": threshold,
        "duplicate_indices": result.duplicate_indices,
        "pairs": [[p.kept_index, p.duplicate_index, p.similarity] for p in result.pairs],
    }


def _every_threshold(texts: list[str]) -> list[dict[str, Any]]:
    return [case(texts, threshold) for threshold in THRESHOLDS]


def _edit(words: list[str], kind: int, generator: random.Random) -> str:
    """A normalised edit of ``words``: a copy, two words swapped, a middle word
    replaced, a word dropped or a word appended."""
    edited = list(words)
    if kind == 1 and len(edited) > 1:
        i, j = generator.sample(range(len(edited)), 2)
        edited[i], edited[j] = edited[j], edited[i]
    elif kind == 2 and edited:
        edited[len(edited) // 2] = "replaced"
    elif kind == 3 and edited:
        del edited[generator.randrange(len(edited))]
    elif kind == 4:
        edited.append("extra")
    return " ".join(edited)


def _plant(base: list[str], generator: random.Random) -> list[str]:
    """``base`` with some texts overwritten by edits of others, at seeded positions."""
    texts = list(base)
    positions = generator.sample(range(len(texts)), min(2 * 5, len(texts)))
    for kind, (source, target) in enumerate(zip(positions[::2], positions[1::2], strict=False)):
        texts[target] = _edit(texts[source].split(), kind, generator)
    return texts


def _mutate(text: str, count: int, generator: random.Random) -> str:
    words = text.split()
    for position in generator.sample(range(len(words)), count):
        words[position] = f"m{generator.randrange(10**6)}"
    return " ".join(words)


def _base(generator: random.Random) -> str:
    return " ".join(generator.sample(_VOCABULARY, generator.randint(20, 60)))


def find_dyadic_pair(generator: random.Random) -> tuple[str, str] | None:
    """Two texts whose estimate is exactly 0.875 (112 of 128 positions agree)."""
    for _ in range(SEARCH_ATTEMPTS):
        left = _base(generator)
        right = _mutate(left, generator.randint(1, 4), generator)
        if estimate_jaccard(_signature(left), _signature(right)) == 0.875:
            return left, right
    return None


def find_band_misses(generator: random.Random, wanted: int) -> list[tuple[str, str]]:
    """Pairs whose estimate reaches 0.5 and that share no LSH band: never compared."""
    found: list[tuple[str, str]] = []
    for _ in range(SEARCH_ATTEMPTS):
        left = _base(generator)
        right = _mutate(left, generator.randint(4, 12), generator)
        signatures = [_signature(left), _signature(right)]
        if estimate_jaccard(*signatures) >= 0.5 and not _candidate_pairs(signatures):
            found.append((left, right))
            if len(found) == wanted:
                break
    return found


def find_chain(generator: random.Random, threshold: float) -> list[str] | None:
    """Texts A, B, C with A like B and B like C but A not like C at ``threshold``."""
    for _ in range(SEARCH_ATTEMPTS):
        first = _base(generator)
        second = _mutate(first, generator.randint(1, 8), generator)
        third = _mutate(second, generator.randint(1, 8), generator)
        pairs = case([first, second, third], threshold)["pairs"]
        if [[p[0], p[1]] for p in pairs] == [[0, 1], [1, 2]]:
            return [first, second, third]
    return None


def near_dedup_cases(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Every case, and how many of the searched shapes the searches found."""
    generator = random.Random(20261114)
    # A row with a credential in any leaf is dropped, however `row_text` rewrites it.
    clean = [row for row in rows if not any(leaks(leaf) for leaf in leaves(row))]
    pool = [text for text in (row_text(row) for row in clean) if usable(text)]
    leaking_rows = len(rows) - len(clean)
    cases: list[dict[str, Any]] = []
    for index in range(GROUPS):
        group = pool[index * GROUP : (index + 1) * GROUP]
        cases += _every_threshold(_plant(group, generator))
    big = pool[GROUPS * GROUP : GROUPS * GROUP + BIG_GROUP]
    cases += _every_threshold(_plant(big, generator))
    for size in (0, 1, 2, 3):
        small = pool[:size]
        if size == 2:
            small[-1] = _edit(pool[0].split(), 2, generator)
        elif size == 3:
            small[-1] = pool[0]
        cases += _every_threshold(small)

    chains = [chain for t in (0.3, 0.5, 0.875) if (chain := find_chain(generator, t))]
    for chain in chains:
        for ordered in (chain, chain[::-1], [chain[1], chain[0], chain[2]]):
            cases += _every_threshold(ordered)
    misses = find_band_misses(generator, 3)
    for left, right in misses:
        cases += _every_threshold([left, right])
    cases += _every_threshold([text for pair in misses for text in pair])
    dyadic = find_dyadic_pair(generator)
    if dyadic:
        cases += _every_threshold(list(dyadic))
        cases += _every_threshold([dyadic[1], pool[0], dyadic[0]])
    cases += _every_threshold(["", "", "", "alpha beta gamma delta", ""])
    cases += _every_threshold(
        ["a", "a", "a b", "a b", "b a", "hello", "hello world", "world hello", "a b c", "a b c d"]
    )
    found = {
        "chains": len(chains),
        "band_misses": len(misses),
        "dyadic_pairs": int(bool(dyadic)),
        "dropped_flagged_near_dedup": leaking_rows,
    }
    return cases, found
