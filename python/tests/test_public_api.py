"""Golden guard for the ``dagnam_contracts`` public API (mirrors ``__init__.py``)."""

from __future__ import annotations

import dagnam_contracts
from dagnam_contracts import hygiene

EXPECTED_EXPORTS = [
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
    "normalize_architecture_config",
    "normalize_diagram_state",
    "render_chat_prompt",
    "row_text",
    "scan_rows",
    "shingles",
    "validate_architecture",
    "validate_params",
]


def test_all_matches_expected_exports() -> None:
    assert sorted(dagnam_contracts.__all__) == sorted(EXPECTED_EXPORTS)


def test_every_exported_name_is_importable() -> None:
    for name in dagnam_contracts.__all__:
        assert hasattr(dagnam_contracts, name)


def test_schema_version_is_positive_int() -> None:
    assert isinstance(dagnam_contracts.SCHEMA_VERSION, int)
    assert dagnam_contracts.SCHEMA_VERSION > 0


def test_hygiene_barrel_matches_the_top_level_re_exports() -> None:
    """Every hygiene name reaches the top level; the barrel is the one list."""
    assert set(hygiene.__all__) <= set(dagnam_contracts.__all__)


def test_hygiene_constants_are_the_documented_values() -> None:
    assert dagnam_contracts.SHINGLE_SIZE == 3
    assert dagnam_contracts.NUM_PERMUTATIONS == 128
    assert dagnam_contracts.BANDS == 32
    assert dagnam_contracts.DEFAULT_THRESHOLD == 0.9
    assert dagnam_contracts.REDACTION_TEMPLATE == "[REDACTED:{code}]"
    assert dagnam_contracts.PII_CODES == tuple(d.code for d in dagnam_contracts.PII_DETECTORS)


def test_component_registry_and_layer_map_are_populated() -> None:
    assert dagnam_contracts.COMPONENT_REGISTRY
    assert dagnam_contracts.LAYER_TYPE_TO_COMPONENT
    assert "convolution-layer" in dagnam_contracts.COMPONENT_REGISTRY
