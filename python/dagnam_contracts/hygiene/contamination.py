"""
Cross-split contamination detection over dataset rows.

`compute_split_overlap` takes a **mapping of every split**
(``dict[str, list[dict]]``), not two positional row lists — an earlier draft
of this plan used a two-argument signature, which forced its caller into a
hardcoded ``train``/``eval_holdout`` check that failed open on any other
split naming (submit ``{"training": ..., "holdout": ...}`` and no check ran
at all). This module checks every unordered pair of splits instead, using
the same `canonical_row_hash` dedup.py uses, so "leaked across splits" means
exactly the same thing as "exact duplicate".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import combinations
from typing import TYPE_CHECKING, Any

from dagnam_contracts.hygiene.dedup import canonical_row_hash

if TYPE_CHECKING:
    from collections.abc import Mapping


@dataclass(frozen=True, slots=True)
class SplitOverlapPair:
    """A single pair of splits that share at least one identical row."""

    split_a: str
    split_b: str
    overlap_count: int


@dataclass(frozen=True, slots=True)
class ContaminationResult:
    """Result of `compute_split_overlap` across every split of a dataset version."""

    has_contamination: bool
    overlapping_pairs: list[SplitOverlapPair] = field(default_factory=list)


def compute_split_overlap(splits: Mapping[str, list[dict[str, Any]]]) -> ContaminationResult:
    """Check every unordered pair of `splits` for identical rows.

    Two rows are considered the same content if `canonical_row_hash` agrees
    — the identical definition `compute_exact_duplicates` uses. Splits are
    compared in sorted-name order so `overlapping_pairs` is deterministic
    regardless of the input mapping's iteration order.
    """
    hash_sets: dict[str, set[str]] = {
        split_name: {canonical_row_hash(row) for row in rows} for split_name, rows in splits.items()
    }

    overlapping_pairs: list[SplitOverlapPair] = []
    for split_a, split_b in combinations(sorted(hash_sets), 2):
        overlap = hash_sets[split_a] & hash_sets[split_b]
        if overlap:
            overlapping_pairs.append(
                SplitOverlapPair(split_a=split_a, split_b=split_b, overlap_count=len(overlap))
            )

    return ContaminationResult(
        has_contamination=bool(overlapping_pairs),
        overlapping_pairs=overlapping_pairs,
    )


__all__ = [
    "ContaminationResult",
    "SplitOverlapPair",
    "compute_split_overlap",
]
