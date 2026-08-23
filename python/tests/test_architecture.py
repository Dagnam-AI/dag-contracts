"""Tests for ``dagnam_contracts.architecture`` — diagram_state walker."""

from __future__ import annotations

from dagnam_contracts.architecture import _resolve_component_id, validate_architecture


def test_resolve_component_id_from_data() -> None:
    assert _resolve_component_id({"componentId": "convolution-layer"}, {}) == "convolution-layer"


def test_resolve_component_id_from_config() -> None:
    assert _resolve_component_id({}, {"componentId": "convolution-layer"}) == "convolution-layer"


def test_resolve_component_id_from_layer_type() -> None:
    assert _resolve_component_id({"layer_type": "conv2d"}, {}) == "convolution-layer"


def test_resolve_component_id_layer_type_is_case_insensitive() -> None:
    assert _resolve_component_id({"layer_type": "CONV2D"}, {}) == "convolution-layer"


def test_resolve_component_id_unresolvable() -> None:
    assert _resolve_component_id({}, {}) is None


def test_validate_architecture_no_nodes_key() -> None:
    assert validate_architecture({}) == []


def test_validate_architecture_nodes_none() -> None:
    assert validate_architecture({"nodes": None}) == []


def test_validate_architecture_skips_non_mapping_node() -> None:
    assert validate_architecture({"nodes": ["not-a-mapping"]}) == []


def test_validate_architecture_node_without_data_uses_empty_fallback() -> None:
    # No "data" -> resolves no component id -> node contributes no errors.
    assert validate_architecture({"nodes": [{"id": "n1"}]}) == []


def test_validate_architecture_config_falls_back_to_data() -> None:
    # No "config" under data -> config falls back to data itself, so
    # componentId living directly on data is still found via config.get too.
    state = {
        "nodes": [
            {"id": "n1", "data": {"componentId": "convolution-layer"}},
        ]
    }
    errors = validate_architecture(state)
    assert any(e.code == "PARAM_REQUIRED_MISSING" for e in errors)


def test_validate_architecture_unresolvable_component_is_skipped() -> None:
    state = {"nodes": [{"id": "n1", "data": {"config": {}}}]}
    assert validate_architecture(state) == []


def test_validate_architecture_node_id_defaults_to_empty_string() -> None:
    state = {
        "nodes": [
            {
                "data": {
                    "componentId": "convolution-layer",
                    "config": {"filters": 32, "kernelSize": 3},
                }
            }
        ]
    }
    assert validate_architecture(state) == []


def test_validate_architecture_collects_errors_across_nodes() -> None:
    state = {
        "nodes": [
            {
                "id": "n1",
                "data": {
                    "componentId": "convolution-layer",
                    "config": {"filters": 32, "kernelSize": 3},
                },
            },
            {
                "id": "n2",
                "data": {
                    "componentId": "convolution-layer",
                    "config": {},
                },
            },
        ]
    }
    errors = validate_architecture(state)
    assert {e.node_id for e in errors} == {"n2"}
    assert len(errors) == 2
