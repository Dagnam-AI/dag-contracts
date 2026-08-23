"""Golden guard for the ``dagnam_contracts`` public API (mirrors ``__init__.py``)."""

from __future__ import annotations

import dagnam_contracts

EXPECTED_EXPORTS = [
    "COMPONENT_REGISTRY",
    "LAYER_TYPE_TO_COMPONENT",
    "SCHEMA_VERSION",
    "ParamError",
    "normalize_architecture_config",
    "normalize_diagram_state",
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


def test_component_registry_and_layer_map_are_populated() -> None:
    assert dagnam_contracts.COMPONENT_REGISTRY
    assert dagnam_contracts.LAYER_TYPE_TO_COMPONENT
    assert "convolution-layer" in dagnam_contracts.COMPONENT_REGISTRY
