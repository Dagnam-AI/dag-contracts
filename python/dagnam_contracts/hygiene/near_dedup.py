"""
Near-duplicate detection over dataset rows (shingling + MinHash + LSH).

Sits beside `dedup.py`, which answers "byte-identical?" via
`canonical_row_hash`. This module answers the weaker, task-dependent question
"close enough that keeping both is probably duplicated training signal?" — and
because that answer is a judgement call, the threshold is a parameter and a
caller acting on the result should default to **preview, not apply**.

Design, and why each piece is what it is:

* **Shingling is over the row's text, not its JSON.** `canonical_row_hash`
  hashes the serialised row because exact identity should notice a changed
  key. Near-duplication should not: two rows that differ only in punctuation
  of the JSON envelope are the same text. `row_text` therefore walks the row
  and concatenates its string leaves in key order, casefolded and
  whitespace-collapsed.
* **Word 3-shingles**, falling back to the token set for rows shorter than
  that. A character-shingle would call every short row similar to every other
  short row.
* **Hashing is `blake2b`, never `hash()`.** Python randomises `hash()` per
  process (`PYTHONHASHSEED`), so a `hash()`-based signature would make the
  same dataset produce different duplicate sets in different workers — a
  non-deterministic data mutation, which is much worse than a slow one.
* **LSH banding is candidate generation only.** Every candidate pair is then
  verified against the full signature, so banding can cost recall but can
  never cause a false merge above the threshold. Comparisons use ``>=``, and
  candidate pairs are consumed in sorted order, so a pair sitting exactly on
  the threshold is decided the same way on every run rather than by set
  iteration order.
* **The first occurrence always survives**, exactly as in `dedup.py`. That
  asymmetry is what makes the operation idempotent: re-running over the kept
  rows finds nothing further.

* **A batch has limits, because the rows are not the caller's.**
  `compute_near_duplicates` raises `NearDedupLimitError` (a `ValueError`; the message names
  the limit and its value and holds no text), after the threshold check and in this order:

  - `MAX_TEXTS` rows; then, reading the rows as they were sent, before anything is
    normalised and before a compiled core is called, `MAX_TEXT_CHARS` characters in the
    string values of one row (joined by a space, as `row_text` joins them) and
    `MAX_TOTAL_CHARS` in all of them (a string's length costs nothing, so a row of a
    hundred megabytes is refused having cost nothing). Casefolding can lengthen a text
    (`ß` is `ss`), so the same two limits are read again on the normalised text, still
    before it is shingled.
  - `MAX_COMPARISONS`: the number of candidate pairs (two rows that share an LSH band, each
    pair once) the walk compares, verified or not. It is counted before each comparison,
    and the call raises instead of making the one that would be number `MAX_COMPARISONS + 1`,
    so another implementation counting this way stops at the same pair.
  - `MAX_PAIRS`: the number of pairs found to be near-duplicates, which the result lists
    in full. The call raises instead of keeping the one past it.

  `MAX_COMPARISONS` and `MAX_PAIRS` are enforced by the Python walk. A compiled core builds
  its candidates and its pairs itself: `dagnam-core` 0.1.1 reads the `MAX_PAIRS` limit only
  when it returns (a batch of identical rows has built every pair by then) and has no
  comparison limit. A release of `dagnam-core` (0.2.0) is to enforce all five before it
  allocates; until the `fast` extra pins it, the bounds below are the Python path's, and
  the compiled backend has only the three that the wrapper reads before calling it.
* **What it holds, measured** (CPython 3.14, Python path, on a laptop with other jobs
  running; one process, peak resident set including the interpreter's own 35 MB):
  one text of `MAX_TEXT_CHARS` characters of one-character words, the most shingles a
  character can buy, takes 7.9 s and 139 MB; 20 of them (`MAX_TOTAL_CHARS`) take 157 s and
  218 MB, about 8 s for each million characters. 10,000 rows that all share a band and
  duplicate nothing reach `MAX_COMPARISONS` after 149 s (3.7 microseconds a comparison) in
  116 MB. 50,000 identical rows (the rows' signatures and band pointers cost about 8 KB a
  row, 0.4 GB) reach `MAX_PAIRS` after 94 s at 1.81 GiB: the result is the one part that
  grows with the square of the identical texts, at about 70 bytes a pair. A text, a
  comparison and a pair limit can all be reached by one batch: the longest is
  `MAX_TOTAL_CHARS` of text and `MAX_COMPARISONS` comparisons, about five minutes, and the
  most memory about 2 GiB. The result is a list of pairs, not a count, so a caller that
  needs a bounded answer for a bigger batch must cluster the identical texts first.

Pure — no session, no I/O.
"""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass, field
import hashlib
import re
from typing import TYPE_CHECKING, Any

from dagnam_contracts.hygiene import _backend

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

SHINGLE_SIZE = 3
"""Words per shingle. Rows with fewer words shingle to their token set."""

NUM_PERMUTATIONS = 128
"""Signature length. 128 puts the Jaccard estimate's standard error near 9%."""

BANDS = 32
"""LSH bands; ``NUM_PERMUTATIONS // BANDS`` = 4 rows per band.

Tuned for recall rather than for the fewest candidates: a missed candidate is
a silently-kept duplicate, while a spurious candidate merely costs one
signature comparison that verification then rejects.
"""

_PUNCTUATION = re.compile(r"[^\w\s]", re.UNICODE)
"""Everything that is not a word char or whitespace, replaced with a space.

Without this, one trailing ``!`` moves two of a short row's shingles and drags
a genuinely-duplicated pair below any sane threshold — punctuation drift is
the single most common way the same example enters a dataset twice.
"""

DEFAULT_THRESHOLD = 0.9
"""Conservative by intent. Near-dedup deletes training signal when it is wrong,
so the default only merges rows that are almost the same text; a caller that
knows its task tolerates more passes a lower number explicitly."""

MAX_TEXTS = 50_000
"""The most rows `compute_near_duplicates` takes: more raises `NearDedupLimitError`."""

MAX_TEXT_CHARS = 1_000_000
"""The most characters in one row's string values (joined by a space), as sent and as
compared."""

MAX_TOTAL_CHARS = 20_000_000
"""The most characters in the string values of all the rows together, as sent and as
compared."""

MAX_COMPARISONS = 40_000_000
"""The most candidate pairs the Python walk compares (see the module docstring).

A candidate pair is two rows that share an LSH band, counted once however many bands they
share, whether or not it turns out to be a near-duplicate. The call raises
`NearDedupLimitError` instead of making the comparison after the last one this allows.

The count at which two implementations stop is the same because the candidates are walked
in one deterministic order, the one `_candidate_pairs` defines: ascending ``left`` row,
and for each ``left`` its ``right`` rows ascending, each pair once. A port counts the
pairs it yields in that order.
"""

MAX_PAIRS = 20_000_000
"""The most near-duplicate pairs `compute_near_duplicates` returns.

The result lists every pair of rows judged near-duplicates, so a batch of n identical rows
has n * (n - 1) / 2 of them (about 6,300 identical rows reach this); past this many the call
raises `NearDedupLimitError`. Rows whose string values are all empty or all punctuation, and
rows with no string values at all, compare as the same empty text.
"""


class NearDedupLimitError(ValueError):
    """A batch is larger than `compute_near_duplicates` takes (`MAX_TEXTS`, `MAX_TEXT_CHARS`,
    `MAX_TOTAL_CHARS`, `MAX_COMPARISONS` or `MAX_PAIRS`).

    The message names the limit and its value and carries no row text, so it can be logged
    and shown to the sender of the batch.
    """


_MASK64 = (1 << 64) - 1
_MERSENNE_PRIME = (1 << 61) - 1

# Fixed permutation coefficients, derived from a constant seed so the same
# rows always produce the same signature -- in this process, in a background
# worker, and in a re-run a year from now.
_COEFFICIENTS: tuple[tuple[int, int], ...] = tuple(
    (
        int.from_bytes(hashlib.blake2b(f"a{i}".encode(), digest_size=8).digest(), "big")
        % _MERSENNE_PRIME
        or 1,
        int.from_bytes(hashlib.blake2b(f"b{i}".encode(), digest_size=8).digest(), "big")
        % _MERSENNE_PRIME,
    )
    for i in range(NUM_PERMUTATIONS)
)


@dataclass(frozen=True, slots=True)
class NearDuplicatePair:
    """One row judged a near-duplicate of an earlier one."""

    kept_index: int
    duplicate_index: int
    similarity: float


@dataclass(frozen=True, slots=True)
class NearDedupResult:
    """Result of `compute_near_duplicates` over a list of rows."""

    threshold: float
    kept_count: int
    duplicate_count: int
    duplicate_indices: list[int] = field(default_factory=list)
    """Indices of the later member of each near-duplicate cluster.

    The lowest index in any cluster is always kept and never appears here —
    the same asymmetry `DedupResult` documents, for the same reason.
    """
    pairs: list[NearDuplicatePair] = field(default_factory=list)
    """Every verified pair, for the preview UI. Sorted, so a preview shown to
    a user is the same list the apply run acts on."""


def _leaves(value: Any) -> Iterator[str]:
    """The string leaves of a row, keys in sorted order; every other leaf is skipped."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key in sorted(value):
            yield from _leaves(value[key])
    elif isinstance(value, list):
        for item in value:
            yield from _leaves(item)


def row_text(row: Mapping[str, Any]) -> str:
    """Flatten `row`'s string leaves into one normalised comparison string.

    Punctuation is replaced with whitespace and the result is casefolded and
    whitespace-collapsed. Keys are visited in sorted order and non-string
    leaves are skipped: a
    numeric label or an id contributes nothing to whether two examples say the
    same thing, and including them would let a shared label pull two unrelated
    rows together.
    """
    joined = _PUNCTUATION.sub(" ", " ".join(_leaves(row)))
    return " ".join(joined.casefold().split())


def shingles(text: str, size: int = SHINGLE_SIZE) -> frozenset[str]:
    """Word `size`-shingles of `text`; the token set when it is too short."""
    words = text.split()
    if not words:
        return frozenset()
    if len(words) < size:
        return frozenset(words)
    return frozenset(" ".join(words[i : i + size]) for i in range(len(words) - size + 1))


def minhash_signature(shingle_set: frozenset[str]) -> tuple[int, ...]:
    """MinHash signature of `shingle_set`; all-`_MASK64` when it is empty."""
    core = _backend.active()
    if core is not None:
        try:
            return tuple(core.minhash_signature(list(shingle_set)))
        except UnicodeEncodeError:
            pass  # not UTF-8 (a lone surrogate): the Python below reads it
    if not shingle_set:
        return (_MASK64,) * NUM_PERMUTATIONS

    hashed = [
        int.from_bytes(hashlib.blake2b(s.encode("utf-8"), digest_size=8).digest(), "big")
        for s in shingle_set
    ]
    return tuple(min((a * h + b) % _MERSENNE_PRIME for h in hashed) for a, b in _COEFFICIENTS)


def estimate_jaccard(left: tuple[int, ...], right: tuple[int, ...]) -> float:
    """Fraction of signature positions that agree — the MinHash estimator."""
    matches = sum(1 for a, b in zip(left, right, strict=True) if a == b)
    return matches / len(left)


def _candidate_pairs(signatures: list[tuple[int, ...]]) -> Iterator[tuple[int, int]]:
    """Index pairs sharing at least one LSH band, each once, in sorted order.

    Never holds the pairs: rows that share a band's bucket are one list, a row points at
    the list it is in, and the pairs of a row ``left`` are the later members of its buckets,
    merged and sorted a row at a time. A set of all the pairs, which this used to build,
    holds the square of the number of identical texts.
    """
    rows_per_band = NUM_PERMUTATIONS // BANDS
    bucket_of: list[list[list[int] | None]] = []  # per band, per row: its bucket, if shared
    for band in range(BANDS):
        start = band * rows_per_band
        buckets: dict[tuple[int, ...], list[int]] = {}
        for index, signature in enumerate(signatures):
            buckets.setdefault(signature[start : start + rows_per_band], []).append(index)
        owner: list[list[int] | None] = [None] * len(signatures)
        for members in buckets.values():
            if len(members) > 1:
                for index in members:
                    owner[index] = members
        bucket_of.append(owner)
    for left in range(len(signatures)):
        later: set[int] = set()
        for owner in bucket_of:
            members = owner[left]
            if members is not None:
                later.update(members[bisect_right(members, left) :])
        for right in sorted(later):
            yield left, right


def _check_the_batch(rows: list[dict[str, Any]]) -> None:
    """The limits that the rows themselves answer, before any of them is normalised.

    The rows are read as they come (a string's ``len`` costs nothing, whatever its size),
    so a row of a hundred megabytes is refused having cost nothing, not the twenty-fold
    copies that normalising it makes. A row's size here is the length of its string leaves
    joined by a space, and the first row over a limit ends the read.
    """
    if len(rows) > MAX_TEXTS:
        raise NearDedupLimitError(f"{len(rows)} texts is more than MAX_TEXTS ({MAX_TEXTS})")
    total = 0
    for row in rows:
        size = -1  # the length of the leaves joined by a space, as `row_text` joins them
        for leaf in _leaves(row):
            size += len(leaf) + 1
            if size > MAX_TEXT_CHARS:
                raise NearDedupLimitError(
                    f"a text of more than MAX_TEXT_CHARS ({MAX_TEXT_CHARS}) characters"
                )
        total += max(size, 0)
        if total > MAX_TOTAL_CHARS:
            raise NearDedupLimitError(
                f"the texts hold more than MAX_TOTAL_CHARS ({MAX_TOTAL_CHARS}) characters"
            )


def _comparison_texts(rows: list[dict[str, Any]]) -> list[str]:
    """``row_text`` of every row, once `_check_the_batch` has passed it.

    The limits are read again on the normalised text, because casefolding can lengthen
    it (``ß`` becomes ``ss``, a ligature up to three letters): a row inside the limits as
    written may be over them as compared, and is refused before it is shingled.
    """
    _check_the_batch(rows)
    texts: list[str] = []
    total = 0
    for row in rows:
        text = row_text(row)
        if len(text) > MAX_TEXT_CHARS:
            raise NearDedupLimitError(
                f"a text of {len(text)} characters is more than MAX_TEXT_CHARS ({MAX_TEXT_CHARS})"
            )
        total += len(text)
        if total > MAX_TOTAL_CHARS:
            raise NearDedupLimitError(
                f"the texts hold more than MAX_TOTAL_CHARS ({MAX_TOTAL_CHARS}) characters"
            )
        texts.append(text)
    return texts


def _check_pairs(count: int) -> None:
    if count > MAX_PAIRS:
        raise NearDedupLimitError(f"more than MAX_PAIRS ({MAX_PAIRS}) near-duplicate pairs")


def compute_near_duplicates(
    rows: list[dict[str, Any]], threshold: float = DEFAULT_THRESHOLD
) -> NearDedupResult:
    """Cluster `rows` by estimated Jaccard similarity at or above `threshold`.

    Raises `ValueError` for a threshold outside ``(0, 1]``: 0 would merge
    every row in the dataset into one cluster, which is never what a caller
    meant to ask for.

    The compiled core is used only for a threshold that is exactly a ``float`` or an
    ``int``: it reads the threshold as a 64-bit float, so a ``Decimal``, a ``Fraction``, a
    ``bool`` or a subclass of ``float`` takes the Python, whose comparison is exact.
    """
    if not 0 < threshold <= 1:
        raise ValueError(f"threshold must be in (0, 1]; got {threshold}")
    texts = _comparison_texts(rows)
    core = _backend.active() if type(threshold) in (float, int) else None
    # `row_text` turns every character that is not a word character or whitespace, a lone
    # surrogate included, into a space, so the core always receives UTF-8 here.
    if core is not None:
        duplicates, found = core.near_duplicates(texts, threshold)
        _check_pairs(len(found))
        return NearDedupResult(
            threshold=threshold,
            duplicate_indices=list(duplicates),
            pairs=[NearDuplicatePair(kept, dup, sim) for kept, dup, sim in found],
            kept_count=len(rows) - len(duplicates),
            duplicate_count=len(duplicates),
        )

    signatures = [minhash_signature(shingles(text)) for text in texts]

    # Sorted (`_candidate_pairs` yields them so) so the union-find below runs in a fixed
    # order: a row that is near-duplicate of two others that are not near-duplicates of
    # each other would otherwise be attached to whichever pair set iteration reached
    # first, and the reported `kept_index` would move between runs.
    pairs: list[NearDuplicatePair] = []
    parent = list(range(len(rows)))

    def _find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    seen: dict[float, float] = {}  # one float object per similarity, not one per pair
    comparisons = 0
    for left, right in _candidate_pairs(signatures):
        comparisons += 1
        if comparisons > MAX_COMPARISONS:
            raise NearDedupLimitError(f"more than MAX_COMPARISONS ({MAX_COMPARISONS}) comparisons")
        similarity = estimate_jaccard(signatures[left], signatures[right])
        if similarity < threshold:
            continue
        _check_pairs(len(pairs) + 1)
        pairs.append(
            NearDuplicatePair(
                kept_index=left,
                duplicate_index=right,
                similarity=seen.setdefault(similarity, similarity),
            )
        )
        root_left, root_right = _find(left), _find(right)
        if root_left != root_right:
            # Always attach the higher root to the lower one, so a cluster's
            # representative is its lowest index -- the row that is kept.
            parent[max(root_left, root_right)] = min(root_left, root_right)

    duplicate_indices = [index for index in range(len(rows)) if _find(index) != index]

    return NearDedupResult(
        threshold=threshold,
        duplicate_indices=duplicate_indices,
        pairs=pairs,
        kept_count=len(rows) - len(duplicate_indices),
        duplicate_count=len(duplicate_indices),
    )


__all__ = [
    "BANDS",
    "DEFAULT_THRESHOLD",
    "MAX_COMPARISONS",
    "MAX_PAIRS",
    "MAX_TEXTS",
    "MAX_TEXT_CHARS",
    "MAX_TOTAL_CHARS",
    "NUM_PERMUTATIONS",
    "SHINGLE_SIZE",
    "NearDedupLimitError",
    "NearDedupResult",
    "NearDuplicatePair",
    "compute_near_duplicates",
    "estimate_jaccard",
    "minhash_signature",
    "row_text",
    "shingles",
]
