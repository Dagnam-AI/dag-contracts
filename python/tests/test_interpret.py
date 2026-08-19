"""Tests for ``dagnam_contracts.interpret`` — the declarative-parameter interpreter."""

from __future__ import annotations

import pytest

from dagnam_contracts import interpret
from dagnam_contracts.interpret import ParamError, validate_params

# ---------------------------------------------------------------------------
# Small pure helpers, exercised directly so every branch is reachable
# regardless of what happens to be in the shipped schema.
# ---------------------------------------------------------------------------


def test_repr_matches_python_repr() -> None:
    assert interpret._repr("x") == "'x'"
    assert interpret._repr(3) == "3"


def test_snake_to_camel_single_word_is_unchanged() -> None:
    assert interpret._snake_to_camel("rate") == "rate"


def test_snake_to_camel_multi_word() -> None:
    assert interpret._snake_to_camel("kernel_size") == "kernelSize"


def test_camel_to_snake_no_uppercase_is_unchanged() -> None:
    assert interpret._camel_to_snake("rate") == "rate"


def test_camel_to_snake_with_uppercase() -> None:
    assert interpret._camel_to_snake("kernelSize") == "kernel_size"


def test_variants_returns_name_camel_and_snake() -> None:
    assert interpret._variants("kernel_size") == ("kernel_size", "kernelSize", "kernel_size")


def test_candidate_keys_dedupes_across_key_and_aliases() -> None:
    # "rate" has no underscore/uppercase, so all three variants collide (hits
    # the dedup skip branch); the alias "p" does too.
    param = {"key": "rate", "aliases": ["p"]}
    assert interpret._candidate_keys(param) == ["rate", "p"]


def test_candidate_keys_no_aliases() -> None:
    param = {"key": "kernel_size"}
    assert interpret._candidate_keys(param) == ["kernel_size", "kernelSize"]


def test_resolve_present_value() -> None:
    param = {"key": "filters"}
    present, value = interpret._resolve({"filters": 32}, param)
    assert (present, value) == (True, 32)


def test_resolve_value_none_counts_as_absent() -> None:
    param = {"key": "filters"}
    present, value = interpret._resolve({"filters": None}, param)
    assert (present, value) == (False, None)


def test_resolve_absent() -> None:
    param = {"key": "filters"}
    assert interpret._resolve({}, param) == (False, None)


def test_control_value_found() -> None:
    assert interpret._control_value({"optimizer": "sgd"}, "optimizer") == "sgd"


def test_control_value_not_found() -> None:
    assert interpret._control_value({}, "optimizer") is None


def test_param_active_no_applies_when() -> None:
    assert interpret._param_active({}, {}) is True


def test_param_active_satisfied() -> None:
    param = {"applies_when": {"optimizer": ["sgd", "rmsprop"]}}
    assert interpret._param_active(param, {"optimizer": "SGD"}) is True


def test_param_active_violated() -> None:
    param = {"applies_when": {"optimizer": ["sgd", "rmsprop"]}}
    assert interpret._param_active(param, {"optimizer": "adam"}) is False


def test_param_active_missing_control_value() -> None:
    param = {"applies_when": {"optimizer": ["sgd", "rmsprop"]}}
    assert interpret._param_active(param, {}) is False


# --- _check_padding -----------------------------------------------------


def test_check_padding_valid_string() -> None:
    assert interpret._check_padding("valid", "padding", "conv", "n1") == []


def test_check_padding_same_string() -> None:
    assert interpret._check_padding("same", "padding", "conv", "n1") == []


def test_check_padding_bad_string() -> None:
    errors = interpret._check_padding("bogus", "padding", "conv", "n1")
    assert len(errors) == 1
    assert errors[0].code == "PARAM_PADDING_BAD_STRING"


def test_check_padding_bad_mode() -> None:
    errors = interpret._check_padding({"mode": "nope"}, "padding", "conv", "n1")
    assert errors[0].code == "PARAM_PADDING_BAD_MODE"


def test_check_padding_mode_same_dict_no_value() -> None:
    assert interpret._check_padding({"mode": "same"}, "padding", "conv", "n1") == []


def test_check_padding_mode_valid_dict_no_value() -> None:
    assert interpret._check_padding({"mode": "valid"}, "padding", "conv", "n1") == []


def test_check_padding_explicit_scalar_ok() -> None:
    assert interpret._check_padding({"mode": "explicit", "value": 2}, "padding", "conv", "n1") == []


def test_check_padding_explicit_scalar_negative() -> None:
    errors = interpret._check_padding({"mode": "explicit", "value": -1}, "padding", "conv", "n1")
    assert errors[0].code == "PARAM_PADDING_BAD_EXPLICIT_VALUE"


def test_check_padding_explicit_scalar_bool() -> None:
    errors = interpret._check_padding({"mode": "explicit", "value": True}, "padding", "conv", "n1")
    assert errors[0].code == "PARAM_PADDING_BAD_EXPLICIT_VALUE"


def test_check_padding_explicit_scalar_non_int() -> None:
    errors = interpret._check_padding({"mode": "explicit", "value": 1.5}, "padding", "conv", "n1")
    assert errors[0].code == "PARAM_PADDING_BAD_EXPLICIT_VALUE"


def test_check_padding_explicit_list_ok() -> None:
    assert (
        interpret._check_padding({"mode": "explicit", "value": [1, 2]}, "padding", "conv", "n1")
        == []
    )


def test_check_padding_explicit_list_length_one_boundary_ok() -> None:
    assert (
        interpret._check_padding({"mode": "explicit", "value": [1]}, "padding", "conv", "n1") == []
    )


def test_check_padding_explicit_list_length_three_boundary_ok() -> None:
    assert (
        interpret._check_padding({"mode": "explicit", "value": [1, 2, 3]}, "padding", "conv", "n1")
        == []
    )


def test_check_padding_explicit_list_too_short() -> None:
    errors = interpret._check_padding({"mode": "explicit", "value": []}, "padding", "conv", "n1")
    assert errors[0].code == "PARAM_PADDING_BAD_AXIS_LENGTH"


def test_check_padding_explicit_list_too_long() -> None:
    errors = interpret._check_padding(
        {"mode": "explicit", "value": [1, 2, 3, 4]}, "padding", "conv", "n1"
    )
    assert errors[0].code == "PARAM_PADDING_BAD_AXIS_LENGTH"


def test_check_padding_explicit_list_bad_element() -> None:
    errors = interpret._check_padding(
        {"mode": "explicit", "value": [1, -2]}, "padding", "conv", "n1"
    )
    assert errors[0].code == "PARAM_PADDING_BAD_EXPLICIT_VALUE"


def test_check_padding_not_typed() -> None:
    errors = interpret._check_padding(5, "padding", "conv", "n1")
    assert errors[0].code == "PARAM_PADDING_NOT_TYPED"


def test_check_padding_not_typed_none() -> None:
    errors = interpret._check_padding(None, "padding", "conv", "n1")
    assert errors[0].code == "PARAM_PADDING_NOT_TYPED"


# --- _check_number --------------------------------------------------------


def test_check_number_no_constraint() -> None:
    assert interpret._check_number(5, {"key": "x"}, "c", "n1") == []


def test_check_number_bool_rejected() -> None:
    param = {"key": "x", "numeric": {"min": 0}}
    errors = interpret._check_number(True, param, "c", "n1")
    assert errors[0].code == "PARAM_NUMBER_NOT_A_NUMBER"


def test_check_number_non_numeric_rejected() -> None:
    param = {"key": "x", "numeric": {"min": 0}}
    errors = interpret._check_number("nope", param, "c", "n1")
    assert errors[0].code == "PARAM_NUMBER_NOT_A_NUMBER"


def test_check_number_not_integer() -> None:
    param = {"key": "x", "numeric": {"integer": True}}
    errors = interpret._check_number(1.5, param, "c", "n1")
    assert errors[0].code == "PARAM_NUMBER_NOT_INTEGER"


def test_check_number_integer_whole_float_ok() -> None:
    param = {"key": "x", "numeric": {"integer": True}}
    assert interpret._check_number(5.0, param, "c", "n1") == []


def test_check_number_below_min() -> None:
    param = {"key": "x", "numeric": {"min": 1}}
    errors = interpret._check_number(0, param, "c", "n1")
    assert errors[0].code == "PARAM_NUMBER_BELOW_MIN"


def test_check_number_above_max() -> None:
    param = {"key": "x", "numeric": {"max": 10}}
    errors = interpret._check_number(11, param, "c", "n1")
    assert errors[0].code == "PARAM_NUMBER_ABOVE_MAX"


def test_check_number_below_recommended() -> None:
    param = {"key": "x", "numeric": {"min": 0, "warn_min": 5}}
    errors = interpret._check_number(1, param, "c", "n1")
    assert errors[0].code == "PARAM_NUMBER_BELOW_RECOMMENDED"


def test_check_number_above_recommended() -> None:
    param = {"key": "x", "numeric": {"max": 100, "warn_max": 10}}
    errors = interpret._check_number(50, param, "c", "n1")
    assert errors[0].code == "PARAM_NUMBER_ABOVE_RECOMMENDED"


def test_check_number_within_all_bounds() -> None:
    param = {"key": "x", "numeric": {"min": 0, "max": 100, "warn_min": 5, "warn_max": 50}}
    assert interpret._check_number(10, param, "c", "n1") == []


def test_check_number_exactly_at_min_is_ok() -> None:
    param = {"key": "x", "numeric": {"min": 1, "max": 10}}
    assert interpret._check_number(1, param, "c", "n1") == []


def test_check_number_exactly_at_max_is_ok() -> None:
    param = {"key": "x", "numeric": {"min": 1, "max": 10}}
    assert interpret._check_number(10, param, "c", "n1") == []


def test_check_number_exactly_at_warn_min_is_ok() -> None:
    param = {"key": "x", "numeric": {"min": 0, "warn_min": 5}}
    assert interpret._check_number(5, param, "c", "n1") == []


def test_check_number_exactly_at_warn_max_is_ok() -> None:
    param = {"key": "x", "numeric": {"max": 100, "warn_max": 50}}
    assert interpret._check_number(50, param, "c", "n1") == []


# ---------------------------------------------------------------------------
# validate_params — integration-level, against the real shipped schema.
# ---------------------------------------------------------------------------


def test_validate_params_unknown_component_returns_empty() -> None:
    assert validate_params("not-a-real-component", {}, "n1") == []


def test_validate_params_required_missing() -> None:
    errors = validate_params("convolution-layer", {}, "n1")
    codes = {e.code for e in errors}
    assert "PARAM_REQUIRED_MISSING" in codes
    missing_fields = {e.field for e in errors if e.code == "PARAM_REQUIRED_MISSING"}
    assert missing_fields == {"filters", "kernelSize"}


def test_validate_params_alias_resolves() -> None:
    # "dropout"'s canonical key is "rate" with alias "p".
    errors = validate_params("dropout", {"p": 0.5}, "n1")
    assert errors == []


def test_validate_params_inactive_param_is_skipped_even_with_bad_value() -> None:
    # optimizer_momentum only applies when optimizer is sgd/rmsprop; with
    # optimizer=adam it must not be validated even though -5 would fail if
    # it were checked.
    errors = validate_params(
        "output-layer",
        {
            "outputType": "classification",
            "optimizer": "adam",
            "learningRate": 0.01,
            "optimizer_momentum": -5,
        },
        "n1",
    )
    assert not any(e.field == "optimizer_momentum" for e in errors)


def test_validate_params_active_param_is_validated() -> None:
    errors = validate_params(
        "output-layer",
        {
            "outputType": "classification",
            "optimizer": "sgd",
            "learningRate": 0.01,
            "optimizer_momentum": 5,
        },
        "n1",
    )
    assert any(e.field == "optimizer_momentum" for e in errors)


def test_validate_params_padding_kind() -> None:
    errors = validate_params(
        "convolution-layer",
        {"filters": 32, "kernelSize": 3, "padding": "bogus"},
        "n1",
    )
    assert any(e.code == "PARAM_PADDING_BAD_STRING" for e in errors)


def test_validate_params_number_kind() -> None:
    errors = validate_params("convolution-layer", {"filters": -1, "kernelSize": 3}, "n1")
    assert any(e.code == "PARAM_NUMBER_BELOW_MIN" and e.field == "filters" for e in errors)


def test_validate_params_enum_kind_rejected() -> None:
    errors = validate_params(
        "convolution-layer",
        {"filters": 32, "kernelSize": 3, "dimensions": "4d"},
        "n1",
    )
    assert any(e.code == "PARAM_ENUM_NOT_ALLOWED" and e.field == "dimensions" for e in errors)


def test_validate_params_enum_kind_accepted() -> None:
    errors = validate_params(
        "convolution-layer",
        {"filters": 32, "kernelSize": 3, "dimensions": "2d"},
        "n1",
    )
    assert not any(e.field == "dimensions" for e in errors)


def test_validate_params_bool_kind_passes_through() -> None:
    errors = validate_params("batch-normalization", {"center": True}, "n1")
    assert errors == []


def test_validate_params_advisory_matches() -> None:
    errors = validate_params(
        "convolution-layer",
        {"filters": 32, "kernelSize": 3, "activation": "linear"},
        "n1",
    )
    assert any(e.code == "INFO_LINEAR_ACTIVATION" and e.severity == "info" for e in errors)


def test_validate_params_advisory_does_not_match() -> None:
    errors = validate_params(
        "convolution-layer",
        {"filters": 32, "kernelSize": 3, "activation": "relu"},
        "n1",
    )
    assert not any(e.code == "INFO_LINEAR_ACTIVATION" for e in errors)


def test_validate_params_synthetic_enum_with_no_enum_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The real schema never ships an enum param without enum_values; a synthetic
    # spec exercises that guard directly.
    synthetic = {
        "synthetic-enum": {
            "component_id": "synthetic-enum",
            "layer_type": "synthetic-enum",
            "params": [{"key": "mode", "kind": "enum", "required": False}],
        }
    }
    monkeypatch.setattr(interpret, "COMPONENT_REGISTRY", synthetic)
    errors = validate_params("synthetic-enum", {"mode": "anything"}, "n1")
    assert errors == []


def test_validate_params_returns_param_error_dataclass() -> None:
    errors = validate_params("convolution-layer", {}, "n1")
    assert all(isinstance(e, ParamError) for e in errors)
