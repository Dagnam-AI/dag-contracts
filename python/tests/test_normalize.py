"""Tests for ``dagnam_contracts.normalize`` — legacy padding upgrade."""

from __future__ import annotations

from dagnam_contracts import normalize
from dagnam_contracts.normalize import (
    JsonValue,
    normalize_architecture_config,
    normalize_diagram_state,
)


def _dig(value: JsonValue, *path: str | int) -> JsonValue:
    """Walk a JSON structure, asserting each step is the shape it must be.

    ``normalize_*`` return ``JsonValue``, which is a union and therefore not
    subscriptable until it is narrowed. Indexing the result directly type-checks
    as an error at every call site; this walks it once, narrowing as it goes, so
    the assertions below stay readable without silencing the checker.
    """
    for step in path:
        if isinstance(step, str):
            assert isinstance(value, dict), f"expected a dict at {step!r}, got {value!r}"
            value = value[step]
        else:
            assert isinstance(value, list), f"expected a list at {step}, got {value!r}"
            value = value[step]
    return value


# ---------------------------------------------------------------------------
# Private helpers, exercised directly to reach every branch precisely.
# ---------------------------------------------------------------------------


def test_key_variants_no_case_change() -> None:
    assert normalize._key_variants("padding") == ["padding"]


def test_key_variants_with_uppercase() -> None:
    # snake inserts `_` before each uppercase run and lowercases it; camel is a
    # no-op rebuild here since there is no `_` to split on, so it dedupes away
    # against the original name.
    assert normalize._key_variants("kernelSize") == ["kernelSize", "kernel_size"]


def test_candidate_keys_dedupes() -> None:
    param = {"key": "pad", "aliases": ["padding"]}
    assert normalize._candidate_keys(param) == ["pad", "padding"]


def test_candidate_keys_dedupes_when_alias_repeats_the_key() -> None:
    # A defensive edge case: an alias list that (accidentally) repeats the key
    # itself. Every variant of the repeated alias is already in `out`, so the
    # dedup guard must skip all of them without erroring.
    param = {"key": "kernelSize", "aliases": ["kernelSize"]}
    assert normalize._candidate_keys(param) == ["kernelSize", "kernel_size"]


def test_normalize_padding_value_bool_passthrough() -> None:
    assert normalize._normalize_padding_value(True) is True
    assert normalize._normalize_padding_value(False) is False


def test_normalize_padding_value_nonnegative_int() -> None:
    assert normalize._normalize_padding_value(2) == {"mode": "explicit", "value": 2}


def test_normalize_padding_value_negative_int_unchanged() -> None:
    assert normalize._normalize_padding_value(-1) == -1


def test_normalize_padding_value_valid_list() -> None:
    assert normalize._normalize_padding_value([1, 2]) == {"mode": "explicit", "value": [1, 2]}


def test_normalize_padding_value_valid_tuple() -> None:
    assert normalize._normalize_padding_value((1, 2, 3)) == {
        "mode": "explicit",
        "value": [1, 2, 3],
    }


def test_normalize_padding_value_empty_list_unchanged() -> None:
    assert normalize._normalize_padding_value([]) == []


def test_normalize_padding_value_too_long_list_unchanged() -> None:
    value = [1, 2, 3, 4]
    assert normalize._normalize_padding_value(value) == value


def test_normalize_padding_value_list_with_bad_element_unchanged() -> None:
    value = [1, -2]
    assert normalize._normalize_padding_value(value) == value


def test_normalize_padding_value_list_with_bool_element_unchanged() -> None:
    value = [1, True]
    assert normalize._normalize_padding_value(value) == value


def test_normalize_padding_value_same_string() -> None:
    assert normalize._normalize_padding_value("same") == {"mode": "same"}


def test_normalize_padding_value_valid_string() -> None:
    assert normalize._normalize_padding_value("valid") == {"mode": "valid"}


def test_normalize_padding_value_other_string_unchanged() -> None:
    assert normalize._normalize_padding_value("explicit") == "explicit"


def test_normalize_padding_value_dict_unchanged() -> None:
    value = {"mode": "same"}
    assert normalize._normalize_padding_value(value) is value


def test_normalize_padding_value_none_unchanged() -> None:
    assert normalize._normalize_padding_value(None) is None


def test_resolve_component_id_none() -> None:
    assert normalize._resolve_component_id(None) is None


def test_resolve_component_id_empty_string() -> None:
    assert normalize._resolve_component_id("") is None


def test_resolve_component_id_non_string() -> None:
    assert normalize._resolve_component_id(123) is None


def test_resolve_component_id_direct_hit() -> None:
    assert normalize._resolve_component_id("convolution-layer") == "convolution-layer"


def test_resolve_component_id_via_layer_type() -> None:
    assert normalize._resolve_component_id("conv2d") == "convolution-layer"


def test_resolve_component_id_unresolvable() -> None:
    assert normalize._resolve_component_id("not-a-real-thing") is None


def test_normalize_unit_unresolvable_identifier_returns_config_unchanged() -> None:
    config: JsonValue = {"padding": 2}
    assert normalize._normalize_unit("not-a-real-thing", config) is config


def test_normalize_unit_non_dict_config_returns_unchanged() -> None:
    assert normalize._normalize_unit("convolution-layer", [1, 2]) == [1, 2]


def test_normalize_unit_upgrades_padding_param() -> None:
    result = normalize._normalize_unit("convolution-layer", {"padding": 2, "filters": 8})
    assert _dig(result, "padding") == {"mode": "explicit", "value": 2}
    assert _dig(result, "filters") == 8


def test_normalize_unit_via_layer_type_identifier() -> None:
    result = normalize._normalize_unit("conv2d", {"padding": "same"})
    assert _dig(result, "padding") == {"mode": "same"}


def test_normalize_unit_no_matching_padding_key() -> None:
    result = normalize._normalize_unit("convolution-layer", {"filters": 8})
    assert result == {"filters": 8}


# ---------------------------------------------------------------------------
# Public entry points.
# ---------------------------------------------------------------------------


def test_normalize_diagram_state_non_dict_input_unchanged() -> None:
    assert normalize_diagram_state([1, 2]) == [1, 2]
    assert normalize_diagram_state(None) is None


def test_normalize_diagram_state_missing_nodes_unchanged() -> None:
    state: JsonValue = {"foo": "bar"}
    assert normalize_diagram_state(state) is state


def test_normalize_diagram_state_nodes_not_list_unchanged() -> None:
    state: JsonValue = {"nodes": "not-a-list"}
    assert normalize_diagram_state(state) is state


def test_normalize_diagram_state_upgrades_padding() -> None:
    state: JsonValue = {
        "nodes": [
            {
                "id": "n1",
                "data": {"componentId": "convolution-layer", "config": {"padding": 2}},
            }
        ]
    }
    result = normalize_diagram_state(state)
    assert _dig(result, "nodes", 0, "data", "config", "padding") == {"mode": "explicit", "value": 2}


def test_normalize_diagram_state_node_without_config() -> None:
    state: JsonValue = {"nodes": [{"id": "n1", "data": {"componentId": "convolution-layer"}}]}
    result = normalize_diagram_state(state)
    assert _dig(result, "nodes", 0, "data", "config") is None


def test_normalize_diagram_state_node_without_dict_data_unchanged() -> None:
    node: JsonValue = {"id": "n1", "data": "not-a-dict"}
    state: JsonValue = {"nodes": [node]}
    result = normalize_diagram_state(state)
    assert _dig(result, "nodes", 0) is node


def test_normalize_architecture_config_non_dict_input_unchanged() -> None:
    assert normalize_architecture_config([1, 2]) == [1, 2]


def test_normalize_architecture_config_missing_layers_unchanged() -> None:
    config: JsonValue = {"foo": "bar"}
    assert normalize_architecture_config(config) is config


def test_normalize_architecture_config_layers_not_list_unchanged() -> None:
    config: JsonValue = {"layers": "not-a-list"}
    assert normalize_architecture_config(config) is config


def test_normalize_architecture_config_upgrades_padding() -> None:
    config: JsonValue = {"layers": [{"type": "convolution-layer", "config": {"padding": 2}}]}
    result = normalize_architecture_config(config)
    assert _dig(result, "layers", 0, "config", "padding") == {"mode": "explicit", "value": 2}


def test_normalize_architecture_config_layer_not_dict_unchanged() -> None:
    layer = "not-a-dict"
    config: JsonValue = {"layers": [layer]}
    result = normalize_architecture_config(config)
    assert _dig(result, "layers", 0) is layer
