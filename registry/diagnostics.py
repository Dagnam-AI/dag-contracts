"""Canonical diagnostic-message catalog — the single source of every parameter
validation message and fix hint. Serialized into component-schema.json by
generate.py and rendered identically by interpret.py (backend),
schema-param-validation.ts (frontend), and dagnam/_contracts (SDK). EDIT HERE:
one template change propagates to all surfaces on regenerate.

Templates use Python str.format placeholders {component_id} {field} {expected}
{got}; a literal brace in prose is written {{ }}. fix_hint is the actionable
remediation ('' = no hint).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

DiagnosticSeverity = Literal["error", "warning", "info"]


class Diagnostic(BaseModel):
    code: str
    severity: DiagnosticSeverity = "error"
    template: str
    fix_hint: str = ""


_DIAGS: list[Diagnostic] = [
    Diagnostic(
        code="PARAM_REQUIRED_MISSING",
        template="{component_id}: missing required parameter '{field}'",
        fix_hint="provide a value for {field}",
    ),
    Diagnostic(
        code="PARAM_NUMBER_NOT_A_NUMBER",
        template="{component_id}: {field} must be a number, got {got}",
        fix_hint="set {field} to a numeric value",
    ),
    Diagnostic(
        code="PARAM_NUMBER_NOT_INTEGER",
        template="{component_id}: {field} must be a whole number, got {got}",
        fix_hint="round {field} to an integer",
    ),
    Diagnostic(
        code="PARAM_NUMBER_BELOW_MIN",
        template="{component_id}: {field} must be at least {expected}, got {got}",
        fix_hint="increase {field} to at least {expected}",
    ),
    Diagnostic(
        code="PARAM_NUMBER_ABOVE_MAX",
        template="{component_id}: {field} must be at most {expected}, got {got}",
        fix_hint="decrease {field} to at most {expected}",
    ),
    Diagnostic(
        code="PARAM_ENUM_NOT_ALLOWED",
        template="{component_id}: {field} must be one of {expected}, got {got}",
        fix_hint="choose {field} from {expected}",
    ),
    Diagnostic(
        code="PARAM_PADDING_NOT_TYPED",
        template="{component_id}: {field} must be a typed object {expected}, got {got}",
        fix_hint="wrap an explicit pad as {{mode:'explicit', value:N}}",
    ),
    Diagnostic(
        code="PARAM_PADDING_BAD_STRING",
        template="{component_id}: {field} must be 'valid', 'same', or a typed object {expected}, got {got}",
        fix_hint="use {{mode:'same'}} or {{mode:'explicit', value:N}}",
    ),
    Diagnostic(
        code="PARAM_PADDING_BAD_MODE",
        template="{component_id}: {field}.mode must be 'valid', 'same', or 'explicit', got {got}",
        fix_hint="set {field}.mode to one of valid|same|explicit",
    ),
    Diagnostic(
        code="PARAM_PADDING_BAD_EXPLICIT_VALUE",
        template="{component_id}: explicit {field} needs a non-negative integer or a list of "
        "non-negative integers, got {got}",
        fix_hint="set {field}.value to a non-negative integer or a list of non-negative integers",
    ),
    Diagnostic(
        code="PARAM_PADDING_BAD_AXIS_LENGTH",
        template="{component_id}: explicit {field} list must hold 1 to 3 entries (one symmetric "
        "pad per spatial axis), got {got}",
        fix_hint="provide one pad per spatial axis, e.g. [padH, padW]",
    ),
    # ---- Advisory diagnostics (non-blocking) -------------------------------
    # WARNINGS: the value is inside the hard min/max (so not an error) but
    # outside the recommended band — almost always a mistake, occasionally
    # deliberate. Driven declaratively by NumericConstraint.warn_min/warn_max.
    Diagnostic(
        code="PARAM_NUMBER_BELOW_RECOMMENDED",
        severity="warning",
        template="{component_id}: {field} = {got} is unusually low (recommended >= {expected})",
        fix_hint="increase {field} toward {expected} unless this is deliberate",
    ),
    Diagnostic(
        code="PARAM_NUMBER_ABOVE_RECOMMENDED",
        severity="warning",
        template="{component_id}: {field} = {got} is unusually high (recommended <= {expected})",
        fix_hint="reduce {field} toward {expected} unless this is deliberate",
    ),
    # INFO / WARNING categorical notes: a specific (valid) enum value is worth
    # flagging. Driven declaratively by ParamSpec.advisories ({when_value: code}).
    Diagnostic(
        code="INFO_NO_LR_SCHEDULE",
        severity="info",
        template="{component_id}: {field} = {got} keeps the learning rate constant; a schedule "
        "(cosine/step/plateau) often improves convergence",
        fix_hint="set {field} to cosine, step, or plateau to anneal the learning rate",
    ),
    Diagnostic(
        code="INFO_MIXED_PRECISION_OFF",
        severity="info",
        template="{component_id}: {field} = {got} trains in full precision; bf16/fp16 cuts memory "
        "and speeds up training on supported accelerators",
        fix_hint="set {field} to bf16 (or fp16) on supported hardware",
    ),
    Diagnostic(
        code="INFO_LINEAR_ACTIVATION",
        severity="info",
        template="{component_id}: {field} = {got} applies no nonlinearity; consecutive linear "
        "layers without an activation collapse into a single linear map",
        fix_hint="add a nonlinear activation (relu/gelu/...) unless a linear projection is intended",
    ),
    Diagnostic(
        code="INFO_NO_NORMALIZATION_AFFINE",
        severity="info",
        template="{component_id}: {field} = {got} disables the learnable affine transform; the "
        "layer normalizes but adds no trainable scale/shift",
        fix_hint="enable {field} to restore the per-feature scale/shift unless intended",
    ),
]

DIAGNOSTICS: dict[str, Diagnostic] = {d.code: d for d in _DIAGS}


def render(
    code: str, *, component_id: str, field: str = "", expected: str = "", got: str = ""
) -> tuple[str, str]:
    """Render (message, fix_hint) for *code* from the shared catalog."""
    d = DIAGNOSTICS[code]
    ctx = {"component_id": component_id, "field": field, "expected": expected, "got": got}
    return d.template.format(**ctx), d.fix_hint.format(**ctx)
