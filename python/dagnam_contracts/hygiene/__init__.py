"""Dataset hygiene: PII scan/policy, exact and near duplicates, split contamination.

Every module here is pure Python over the standard library — no session, no
I/O, no required third-party dependency — so the platform, the SDK, and any offline
audit tool reach the same verdict on the same rows. With the optional `fast` extra
the PII scan, MinHash and near-duplicate search run in the compiled `dagnam-core`
instead (`backend()` says which); the Python here stays the reference. `dedup.canonical_row_hash`
is the one definition of "identical" that `dedup` and `contamination` share.
"""

from __future__ import annotations

from dagnam_contracts.hygiene._backend import backend
from dagnam_contracts.hygiene.contamination import (
    ContaminationResult,
    SplitOverlapPair,
    compute_split_overlap,
)
from dagnam_contracts.hygiene.dedup import (
    DedupResult,
    canonical_row_hash,
    compute_exact_duplicates,
)
from dagnam_contracts.hygiene.near_dedup import (
    BANDS,
    DEFAULT_THRESHOLD,
    NUM_PERMUTATIONS,
    SHINGLE_SIZE,
    NearDedupResult,
    NearDuplicatePair,
    compute_near_duplicates,
    estimate_jaccard,
    minhash_signature,
    row_text,
    shingles,
)
from dagnam_contracts.hygiene.pii import (
    PII_CODES,
    PII_DETECTORS,
    PII_DISCLAIMER,
    REDACTION_TEMPLATE,
    PiiAction,
    PiiDetector,
    PiiIssue,
    PiiScanResult,
    apply_pii_policy,
    redact_json_text,
    redact_rows,
    scan_rows,
)

__all__ = [
    "BANDS",
    "DEFAULT_THRESHOLD",
    "NUM_PERMUTATIONS",
    "PII_CODES",
    "PII_DETECTORS",
    "PII_DISCLAIMER",
    "REDACTION_TEMPLATE",
    "SHINGLE_SIZE",
    "ContaminationResult",
    "DedupResult",
    "NearDedupResult",
    "NearDuplicatePair",
    "PiiAction",
    "PiiDetector",
    "PiiIssue",
    "PiiScanResult",
    "SplitOverlapPair",
    "apply_pii_policy",
    "backend",
    "canonical_row_hash",
    "compute_exact_duplicates",
    "compute_near_duplicates",
    "compute_split_overlap",
    "estimate_jaccard",
    "minhash_signature",
    "redact_json_text",
    "redact_rows",
    "row_text",
    "scan_rows",
    "shingles",
]
