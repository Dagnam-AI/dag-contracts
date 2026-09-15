"""Workload-audit contract: the scorers, the winner and verdict rules, the report shape.

Pure Python over the standard library, like ``hygiene``: the SDK scores a
holdout on the customer's machine and the platform scores one on a worker,
and both must reach the same number for the same rows. The economics bands,
the frontier rule, the serving rate card and the report's derived blocks live
here for the same reason -- one definition, three consumers.
"""

from __future__ import annotations

from dagnam_contracts.audit.reference import (
    REFERENCE_AS_OF,
    ReferenceModel,
    load_reference_models,
)
from dagnam_contracts.audit.report import (
    CANCELLED_SCHEMA,
    DEFAULT_BASE_URL,
    DELETED_SCHEMA,
    REPORT_SCHEMA,
    render_switch_snippet,
    switch_block,
    winner_of,
)
from dagnam_contracts.audit.scoring import (
    Z95,
    Agreement,
    modal_keys,
    normalize_label,
    score_json,
    score_labels,
    wilson_interval,
)
from dagnam_contracts.audit.serving import (
    SERVING_RATES,
    StudentKind,
    load_serving_rates,
    serving_cost_usd_month,
)
from dagnam_contracts.audit.verdict import (
    DAYS_PER_MONTH,
    FLOOR_JSON,
    FLOOR_LABEL,
    MAINTENANCE_USD_MONTH,
    MIN_HOLDOUT,
    MIN_TRACES_PER_WORKLOAD,
    RATIO_CANDIDATE,
    RATIO_NOT_WORTH_IT,
    UNRELIABLE_ERROR_SHARE,
    CandidateResult,
    CustomerVerdict,
    VerdictStatus,
    Winner,
    customer_verdict,
    frontier,
    ratio_status,
)

__all__ = [
    "CANCELLED_SCHEMA",
    "DAYS_PER_MONTH",
    "DEFAULT_BASE_URL",
    "DELETED_SCHEMA",
    "FLOOR_JSON",
    "FLOOR_LABEL",
    "MAINTENANCE_USD_MONTH",
    "MIN_HOLDOUT",
    "MIN_TRACES_PER_WORKLOAD",
    "RATIO_CANDIDATE",
    "RATIO_NOT_WORTH_IT",
    "REFERENCE_AS_OF",
    "REPORT_SCHEMA",
    "SERVING_RATES",
    "UNRELIABLE_ERROR_SHARE",
    "Z95",
    "Agreement",
    "CandidateResult",
    "CustomerVerdict",
    "ReferenceModel",
    "StudentKind",
    "VerdictStatus",
    "Winner",
    "customer_verdict",
    "frontier",
    "load_reference_models",
    "load_serving_rates",
    "modal_keys",
    "normalize_label",
    "ratio_status",
    "render_switch_snippet",
    "score_json",
    "score_labels",
    "serving_cost_usd_month",
    "switch_block",
    "wilson_interval",
    "winner_of",
]
