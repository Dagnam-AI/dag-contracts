"""The canonical Dagnam.AI component/parameter validation contract.

Ships the generated ``component-schema.json`` plus a **pydantic-free**
interpreter of it. The dependency-free constraint is load-bearing, not
incidental: the ``dagnam`` SDK deliberately carries only ``requests`` and
``numpy``, so anything it depends on must stay light.

The Pydantic ``ComponentSpec`` registry that *produces* this schema lives in
``registry/`` and is an AUTHORING format — it is never packaged, which is what
lets this distribution have no runtime dependencies at all.

Public API mirrors what the SDK previously exposed from ``dagnam._contracts``,
so a consumer switching to this package changes its import path and nothing else.

Since 0.2.0 the package also carries the dataset-hygiene primitives (``hygiene``)
and the chat-prompt renderer (``prompts``). Both are Python-only — the npm
package ships the schema interpreter alone.
"""

from __future__ import annotations

from dagnam_contracts.architecture import validate_architecture
from dagnam_contracts.audit import (
    Z95,
    Agreement,
    modal_keys,
    normalize_label,
    score_json,
    score_labels,
    wilson_interval,
)
from dagnam_contracts.hygiene import (
    BANDS,
    DEFAULT_THRESHOLD,
    NUM_PERMUTATIONS,
    PII_CODES,
    PII_DETECTORS,
    PII_DISCLAIMER,
    REDACTION_TEMPLATE,
    SHINGLE_SIZE,
    ContaminationResult,
    DedupResult,
    NearDedupResult,
    NearDuplicatePair,
    PiiAction,
    PiiDetector,
    PiiIssue,
    PiiScanResult,
    SplitOverlapPair,
    apply_pii_policy,
    canonical_row_hash,
    compute_exact_duplicates,
    compute_near_duplicates,
    compute_split_overlap,
    estimate_jaccard,
    minhash_signature,
    row_text,
    scan_rows,
    shingles,
)
from dagnam_contracts.interpret import ParamError, validate_params
from dagnam_contracts.normalize import (
    normalize_architecture_config,
    normalize_diagram_state,
)
from dagnam_contracts.prompts import render_chat_prompt
from dagnam_contracts.schema import (
    COMPONENT_REGISTRY,
    LAYER_TYPE_TO_COMPONENT,
    SCHEMA_VERSION,
)

__all__ = [
    "BANDS",
    "COMPONENT_REGISTRY",
    "DEFAULT_THRESHOLD",
    "LAYER_TYPE_TO_COMPONENT",
    "NUM_PERMUTATIONS",
    "PII_CODES",
    "PII_DETECTORS",
    "PII_DISCLAIMER",
    "REDACTION_TEMPLATE",
    "SCHEMA_VERSION",
    "SHINGLE_SIZE",
    "Z95",
    "Agreement",
    "ContaminationResult",
    "DedupResult",
    "NearDedupResult",
    "NearDuplicatePair",
    "ParamError",
    "PiiAction",
    "PiiDetector",
    "PiiIssue",
    "PiiScanResult",
    "SplitOverlapPair",
    "apply_pii_policy",
    "canonical_row_hash",
    "compute_exact_duplicates",
    "compute_near_duplicates",
    "compute_split_overlap",
    "estimate_jaccard",
    "minhash_signature",
    "modal_keys",
    "normalize_architecture_config",
    "normalize_diagram_state",
    "normalize_label",
    "render_chat_prompt",
    "row_text",
    "scan_rows",
    "score_json",
    "score_labels",
    "shingles",
    "validate_architecture",
    "validate_params",
    "wilson_interval",
]
