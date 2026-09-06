"""
Exact-duplicate detection over dataset rows.

`canonical_row_hash` is the one definition of "identical" shared by this
module and `contamination.py` — "exact duplicate" (within a split) and
"leaked across splits" (between splits) must mean exactly the same thing,
not two subtly different definitions that drift apart over time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping


def canonical_row_hash(row: Mapping[str, Any]) -> str:
    """Return a stable sha256 hex digest for `row`.

    Hashes ``json.dumps(row, sort_keys=True, separators=(",", ":"))`` — key
    order never affects the result, and the compact separators keep the
    canonical form free of incidental whitespace differences.
    """
    canonical = json.dumps(row, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class DedupResult:
    """Result of `compute_exact_duplicates` over a list of rows."""

    kept_count: int
    duplicate_count: int
    duplicate_indices: list[int] = field(default_factory=list)
    """Indices of the *second and later* occurrence of each duplicate value.

    The first occurrence of any value is always kept and never appears
    here — that asymmetry is what makes dedup idempotent: re-running on the
    rows that remain after dropping these indices always finds nothing
    further.
    """


def compute_exact_duplicates(rows: list[dict[str, Any]]) -> DedupResult:
    """Find exact-duplicate rows by `canonical_row_hash`.

    For each distinct hash, the first row seen is kept; every later row
    sharing that hash is reported in `DedupResult.duplicate_indices`.
    """
    seen_hashes: set[str] = set()
    duplicate_indices: list[int] = []
    for index, row in enumerate(rows):
        row_hash = canonical_row_hash(row)
        if row_hash in seen_hashes:
            duplicate_indices.append(index)
        else:
            seen_hashes.add(row_hash)

    return DedupResult(
        duplicate_indices=duplicate_indices,
        kept_count=len(rows) - len(duplicate_indices),
        duplicate_count=len(duplicate_indices),
    )


__all__ = [
    "DedupResult",
    "canonical_row_hash",
    "compute_exact_duplicates",
]
