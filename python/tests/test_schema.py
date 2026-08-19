"""Tests for ``dagnam_contracts.schema`` — the loaded schema data and renderer."""

from __future__ import annotations

import pytest

from dagnam_contracts.schema import (
    COMPONENT_REGISTRY,
    COMPONENTS,
    DIAGNOSTICS,
    LAYER_TYPE_TO_COMPONENT,
    SCHEMA_VERSION,
    render,
)


def test_schema_version_matches_raw_json() -> None:
    assert isinstance(SCHEMA_VERSION, int)
    assert SCHEMA_VERSION >= 1


def test_components_is_a_nonempty_list_of_dicts() -> None:
    assert isinstance(COMPONENTS, list)
    assert COMPONENTS
    assert all(isinstance(c, dict) for c in COMPONENTS)


def test_component_registry_keyed_by_component_id() -> None:
    for c in COMPONENTS:
        assert COMPONENT_REGISTRY[c["component_id"]] is c


def test_layer_type_to_component_maps_every_layer_type() -> None:
    for c in COMPONENTS:
        assert LAYER_TYPE_TO_COMPONENT[c["layer_type"]] == c["component_id"]


def test_diagnostics_keyed_by_code() -> None:
    assert DIAGNOSTICS
    for code, d in DIAGNOSTICS.items():
        assert d["code"] == code


def test_render_fills_template_and_fix_hint() -> None:
    message, fix_hint = render(
        "PARAM_NUMBER_BELOW_MIN",
        component_id="convolution-layer",
        field="filters",
        expected="1",
        got="-999",
    )
    assert message == "convolution-layer: filters must be at least 1, got -999"
    assert fix_hint == "increase filters to at least 1"


def test_render_unknown_code_raises_key_error() -> None:
    with pytest.raises(KeyError):
        render("NOT_A_REAL_CODE", component_id="x")
