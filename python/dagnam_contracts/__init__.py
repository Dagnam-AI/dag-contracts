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
and the chat-prompt renderer (``prompts``); since 0.3.0, the workload-audit
contract (``audit``) — the agreement scorers, the economics bands, the frontier
rule, the serving rate card, the report's derived blocks and the open-model
reference rows. All three are Python-only — the npm package ships the schema
interpreter alone.
"""

from __future__ import annotations

from dagnam_contracts.architecture import validate_architecture
from dagnam_contracts.audit import (
    DAYS_PER_MONTH,
    DEFAULT_BASE_URL,
    FLOOR_JSON,
    FLOOR_LABEL,
    MAINTENANCE_USD_MONTH,
    MIN_HOLDOUT,
    MIN_TRACES_PER_WORKLOAD,
    RATIO_CANDIDATE,
    RATIO_NOT_WORTH_IT,
    REFERENCE_AS_OF,
    REPORT_SCHEMA,
    SERVING_RATES,
    UNRELIABLE_ERROR_SHARE,
    Z95,
    Agreement,
    CandidateResult,
    CustomerVerdict,
    ReferenceModel,
    StudentKind,
    VerdictStatus,
    Winner,
    customer_verdict,
    frontier,
    load_reference_models,
    modal_keys,
    normalize_label,
    ratio_status,
    render_switch_snippet,
    score_json,
    score_labels,
    serving_cost_usd_month,
    switch_block,
    wilson_interval,
    winner_of,
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
    "DAYS_PER_MONTH",
    "DEFAULT_BASE_URL",
    "DEFAULT_THRESHOLD",
    "FLOOR_JSON",
    "FLOOR_LABEL",
    "LAYER_TYPE_TO_COMPONENT",
    "MAINTENANCE_USD_MONTH",
    "MIN_HOLDOUT",
    "MIN_TRACES_PER_WORKLOAD",
    "NUM_PERMUTATIONS",
    "PII_CODES",
    "PII_DETECTORS",
    "PII_DISCLAIMER",
    "RATIO_CANDIDATE",
    "RATIO_NOT_WORTH_IT",
    "REDACTION_TEMPLATE",
    "REFERENCE_AS_OF",
    "REPORT_SCHEMA",
    "SCHEMA_VERSION",
    "SERVING_RATES",
    "SHINGLE_SIZE",
    "UNRELIABLE_ERROR_SHARE",
    "Z95",
    "Agreement",
    "CandidateResult",
    "ContaminationResult",
    "CustomerVerdict",
    "DedupResult",
    "NearDedupResult",
    "NearDuplicatePair",
    "ParamError",
    "PiiAction",
    "PiiDetector",
    "PiiIssue",
    "PiiScanResult",
    "ReferenceModel",
    "SplitOverlapPair",
    "StudentKind",
    "VerdictStatus",
    "Winner",
    "apply_pii_policy",
    "canonical_row_hash",
    "compute_exact_duplicates",
    "compute_near_duplicates",
    "compute_split_overlap",
    "customer_verdict",
    "estimate_jaccard",
    "frontier",
    "load_reference_models",
    "minhash_signature",
    "modal_keys",
    "normalize_architecture_config",
    "normalize_diagram_state",
    "normalize_label",
    "ratio_status",
    "render_chat_prompt",
    "render_switch_snippet",
    "row_text",
    "scan_rows",
    "score_json",
    "score_labels",
    "serving_cost_usd_month",
    "shingles",
    "switch_block",
    "validate_architecture",
    "validate_params",
    "wilson_interval",
    "winner_of",
]
