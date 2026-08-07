/**
 * Schema-driven parameter validation (frontend interpreter).
 *
 * This is the frontend half of FE/BE parameter parity. It interprets the SAME
 * generated `component-schema.json` that the backend reads
 * (`src/validation/contracts/interpret.py`), so the two runtimes produce
 * identical per-parameter verdicts — constraints, enums, and typed padding all
 * come from one source of truth that cannot drift.
 *
 * Scope: declarative, per-parameter constraints only (numeric bounds, enums,
 * typed padding, required-ness, conditional applicability). Cross-parameter /
 * relational rules (e.g. "num heads must divide embed dim") are intentionally
 * out of scope and remain in `node-validation.ts`.
 *
 * Key resolution mirrors the backend: case-insensitive across
 * camelCase/snake_case plus any explicit `aliases`, so the schema reads the
 * frontend's camelCase configs and any snake_case legacy configs alike.
 */

import schema from "./component-schema.json" with { type: "json" };
import type { ValidationResult } from "./types.js";

interface NumericConstraint {
  min?: number;
  max?: number;
  integer?: boolean;
  warn_min?: number;
  warn_max?: number;
}

interface Advisory {
  when_value: string;
  code: string;
}

interface ParamSpec {
  key: string;
  kind: "number" | "enum" | "padding" | "bool" | "string";
  required?: boolean;
  numeric?: NumericConstraint;
  enum_values?: string[];
  aliases?: string[];
  applies_when?: Record<string, string[]>;
  advisories?: Advisory[];
}

interface ComponentSpec {
  component_id: string;
  layer_type: string;
  params: ParamSpec[];
}

interface Diagnostic {
  code: string;
  severity: string;
  template: string;
  fix_hint: string;
}

const REGISTRY = new Map<string, ComponentSpec>(
  (schema.components as ComponentSpec[]).map((c) => [c.component_id, c]),
);

const DIAGNOSTICS = new Map<string, Diagnostic>(
  (schema.diagnostics as Diagnostic[]).map((d) => [d.code, d]),
);

const PADDING_SHAPE = "{mode:'same'|'valid'|'explicit', value?}";

const SEVERITY_TYPE: Record<string, string> = {
  error: "parameter error",
  warning: "parameter warning",
  info: "parameter info",
};

/** Mirror Python str.format: substitute {key}; honor {{ }} as literal braces. */
function fill(tpl: string, ctx: Record<string, string>): string {
  return tpl.replace(/\{\{|\}\}|\{(\w+)\}/g, (m, key: string | undefined) => {
    if (m === "{{") return "{";
    if (m === "}}") return "}";
    return ctx[key as string] ?? "";
  });
}

/** Python list repr (`['a', 'b']`) so FE `expected` matches backend `str(list)`. */
function pyList(values: string[]): string {
  return `[${values.map((v) => `'${v}'`).join(", ")}]`;
}

/** Build a structured diagnostic from the shared catalog (single source). */
function diag(
  code: string,
  nodeId: string,
  ctx: {
    component_id: string;
    field?: string;
    expected?: string;
    got?: string;
  },
): ValidationResult {
  const d = DIAGNOSTICS.get(code)!;
  const full = {
    component_id: ctx.component_id,
    field: ctx.field ?? "",
    expected: ctx.expected ?? "",
    got: ctx.got ?? "",
  };
  // Severity comes from the shared catalog, never hardcoded. The type encodes
  // severity too: error keeps the historical "parameter error" (-> PARAMETER_ERROR
  // rule), while advisory severities get types that are NOT spec rule ids, so they
  // stay out of the count-stable corpus multiset and never flip is_valid.
  const severity = (d.severity as ValidationResult["severity"]) ?? "error";
  return {
    type: SEVERITY_TYPE[severity] ?? "parameter error",
    severity,
    message: fill(d.template, full),
    node_id: nodeId,
    code,
    field: ctx.field,
    expected: ctx.expected,
    got: ctx.got,
    fix_hint: fill(d.fix_hint, full) || undefined,
  };
}

function snakeToCamel(key: string): string {
  return key.replace(/_([a-z0-9])/g, (_, c: string) => c.toUpperCase());
}

function camelToSnake(key: string): string {
  return key.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);
}

function candidateKeys(spec: ParamSpec): string[] {
  const names = [spec.key, ...(spec.aliases ?? [])];
  const candidates: string[] = [];
  for (const name of names) {
    for (const variant of [name, snakeToCamel(name), camelToSnake(name)]) {
      if (!candidates.includes(variant)) candidates.push(variant);
    }
  }
  return candidates;
}

/** Resolve a param's value; a key whose value is null/undefined counts as absent. */
function resolve(
  config: Record<string, unknown>,
  spec: ParamSpec,
): { present: boolean; value: unknown } {
  for (const candidate of candidateKeys(spec)) {
    const value = config[candidate];
    if (candidate in config && value != null) return { present: true, value };
  }
  return { present: false, value: undefined };
}

function controlValue(
  config: Record<string, unknown>,
  controlKey: string,
): unknown {
  for (const candidate of [
    controlKey,
    snakeToCamel(controlKey),
    camelToSnake(controlKey),
  ]) {
    const value = config[candidate];
    if (candidate in config && value != null) return value;
  }
  return undefined;
}

function paramActive(p: ParamSpec, config: Record<string, unknown>): boolean {
  if (!p.applies_when) return true;
  return Object.entries(p.applies_when).every(([key, allowed]) => {
    const allowedLower = allowed.map((a) => a.toLowerCase());
    return allowedLower.includes(
      String(controlValue(config, key)).toLowerCase(),
    );
  });
}

/** Mirror Python's `repr` closely enough for parity on the common cases. */
function fmtValue(value: unknown): string {
  if (typeof value === "string") return `'${value}'`;
  if (value === null) return "None";
  if (typeof value === "boolean") return value ? "True" : "False";
  // Python list repr: `[1, 2]` (a space after each comma) so a per-axis pad's
  // `got` renders identically to the backend `repr(list)`.
  if (Array.isArray(value)) return `[${value.map(fmtValue).join(", ")}]`;
  return String(value);
}

function checkPadding(
  value: unknown,
  key: string,
  cid: string,
  nodeId: string,
): ValidationResult[] {
  // Legacy bare strings ('valid'/'same') are tolerated (the normalizer upgrades
  // them; the shared corpus still carries them). Only malformed/bare-int padding
  // — the actual parity bug — is rejected.
  if (typeof value === "string") {
    if (value === "valid" || value === "same") return [];
    return [
      diag("PARAM_PADDING_BAD_STRING", nodeId, {
        component_id: cid,
        field: key,
        expected: PADDING_SHAPE,
        got: fmtValue(value),
      }),
    ];
  }
  if (value !== null && typeof value === "object") {
    const mode = (value as { mode?: unknown }).mode;
    if (mode !== "valid" && mode !== "same" && mode !== "explicit") {
      return [
        diag("PARAM_PADDING_BAD_MODE", nodeId, {
          component_id: cid,
          field: key,
          got: fmtValue(mode),
        }),
      ];
    }
    if (mode === "explicit") {
      const v = (value as { value?: unknown }).value;
      // A per-axis list holds one symmetric pad per spatial axis; length must be
      // 1..3 (broadcast .. Conv3D). Element validity mirrors the scalar check.
      // A scalar is the length-1 broadcast case and stays valid.
      if (Array.isArray(v)) {
        if (v.length < 1 || v.length > 3) {
          return [
            diag("PARAM_PADDING_BAD_AXIS_LENGTH", nodeId, {
              component_id: cid,
              field: key,
              got: fmtValue(v),
            }),
          ];
        }
        if (
          v.some((e) => typeof e !== "number" || !Number.isInteger(e) || e < 0)
        ) {
          return [
            diag("PARAM_PADDING_BAD_EXPLICIT_VALUE", nodeId, {
              component_id: cid,
              field: key,
              got: fmtValue(v),
            }),
          ];
        }
      } else if (typeof v !== "number" || !Number.isInteger(v) || v < 0) {
        return [
          diag("PARAM_PADDING_BAD_EXPLICIT_VALUE", nodeId, {
            component_id: cid,
            field: key,
            got: fmtValue(v),
          }),
        ];
      }
    }
    return [];
  }
  return [
    diag("PARAM_PADDING_NOT_TYPED", nodeId, {
      component_id: cid,
      field: key,
      expected: PADDING_SHAPE,
      got: fmtValue(value),
    }),
  ];
}

/** Match Python's `f"{x:g}"` for the integer/simple bounds used in the schema. */
function fmtNum(x: number): string {
  return String(x);
}

function checkNumber(
  value: unknown,
  p: ParamSpec,
  cid: string,
  nodeId: string,
): ValidationResult[] {
  const nc = p.numeric;
  if (!nc) return [];
  if (typeof value !== "number" || Number.isNaN(value)) {
    return [
      diag("PARAM_NUMBER_NOT_A_NUMBER", nodeId, {
        component_id: cid,
        field: p.key,
        got: fmtValue(value),
      }),
    ];
  }
  if (nc.integer && !Number.isInteger(value)) {
    return [
      diag("PARAM_NUMBER_NOT_INTEGER", nodeId, {
        component_id: cid,
        field: p.key,
        got: fmtValue(value),
      }),
    ];
  }
  if (nc.min !== undefined && value < nc.min) {
    return [
      diag("PARAM_NUMBER_BELOW_MIN", nodeId, {
        component_id: cid,
        field: p.key,
        expected: fmtNum(nc.min),
        got: fmtValue(value),
      }),
    ];
  }
  if (nc.max !== undefined && value > nc.max) {
    return [
      diag("PARAM_NUMBER_ABOVE_MAX", nodeId, {
        component_id: cid,
        field: p.key,
        expected: fmtNum(nc.max),
        got: fmtValue(value),
      }),
    ];
  }
  // Hard bounds passed: advisory SOFT bounds (non-blocking warnings).
  if (nc.warn_min !== undefined && value < nc.warn_min) {
    return [
      diag("PARAM_NUMBER_BELOW_RECOMMENDED", nodeId, {
        component_id: cid,
        field: p.key,
        expected: fmtNum(nc.warn_min),
        got: fmtValue(value),
      }),
    ];
  }
  if (nc.warn_max !== undefined && value > nc.warn_max) {
    return [
      diag("PARAM_NUMBER_ABOVE_RECOMMENDED", nodeId, {
        component_id: cid,
        field: p.key,
        expected: fmtNum(nc.warn_max),
        got: fmtValue(value),
      }),
    ];
  }
  return [];
}

/**
 * Validate `config` against the canonical schema for `componentId`.
 * Components not in the schema yield no errors (out of contract scope).
 */
export function validateParamsAgainstSchema(
  componentId: string,
  config: Record<string, unknown>,
  nodeId: string,
): ValidationResult[] {
  const spec = REGISTRY.get(componentId);
  if (!spec) return [];

  const errors: ValidationResult[] = [];
  for (const p of spec.params) {
    if (!paramActive(p, config)) continue;
    const { present, value } = resolve(config, p);
    if (!present) {
      if (p.required) {
        errors.push(
          diag("PARAM_REQUIRED_MISSING", nodeId, {
            component_id: componentId,
            field: p.key,
          }),
        );
      }
      continue;
    }
    if (p.kind === "padding") {
      errors.push(...checkPadding(value, p.key, componentId, nodeId));
    } else if (p.kind === "number") {
      errors.push(...checkNumber(value, p, componentId, nodeId));
    } else if (
      p.kind === "enum" &&
      p.enum_values &&
      !p.enum_values.includes(String(value))
    ) {
      errors.push(
        diag("PARAM_ENUM_NOT_ALLOWED", nodeId, {
          component_id: componentId,
          field: p.key,
          expected: pyList(p.enum_values),
          got: fmtValue(value),
        }),
      );
    }
    // Categorical advisories (non-blocking info/warning), kind-independent.
    if (p.advisories) {
      const presentValue = String(value).toLowerCase();
      for (const adv of p.advisories) {
        if (adv.when_value.toLowerCase() === presentValue) {
          errors.push(
            diag(adv.code, nodeId, {
              component_id: componentId,
              field: p.key,
              got: fmtValue(value),
            }),
          );
        }
      }
    }
  }
  return errors;
}
