/**
 * Schema-driven field metadata for the component-library renderer.
 *
 * The studio's config-panel renders fields (sliders, number inputs, visibility)
 * from the hand-authored component library; this module lets it instead consult
 * the **generated** `component-schema.json` — the SAME source the validators
 * read — so a field's integer-ness and conditional applicability can never
 * drift from the rule that validates it. Mirrors the backend `_param_active`
 * (case-insensitive `applies_when`) and the `integer` numeric flag exactly.
 */

import schema from "./component-schema.json" with { type: "json" };

interface NumericConstraint {
  integer?: boolean;
}
interface ParamSpec {
  key: string;
  kind: "number" | "enum" | "padding" | "bool" | "string";
  numeric?: NumericConstraint;
  aliases?: string[];
  applies_when?: Record<string, string[]>;
}
interface ComponentSpec {
  component_id: string;
  params: ParamSpec[];
}

const REGISTRY = new Map<string, ComponentSpec>(
  (schema.components as ComponentSpec[]).map((c) => [c.component_id, c]),
);

function snakeToCamel(key: string): string {
  return key.replace(/_([a-z0-9])/g, (_, c: string) => c.toUpperCase());
}
function camelToSnake(key: string): string {
  return key.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);
}
function keyVariants(name: string): string[] {
  return [...new Set([name, snakeToCamel(name), camelToSnake(name)])];
}

function findParam(componentId: string, key: string): ParamSpec | undefined {
  const spec = REGISTRY.get(componentId);
  if (!spec) return undefined;
  const wanted = new Set(keyVariants(key));
  return spec.params.find((p) => keyVariants(p.key).some((v) => wanted.has(v)));
}

function controlValue(
  config: Record<string, unknown>,
  controlKey: string,
): unknown {
  for (const candidate of keyVariants(controlKey)) {
    const value = config[candidate];
    if (candidate in config && value != null) return value;
  }
  return undefined;
}

/**
 * The canonical `integer` flag for a numeric param, or `undefined` when the
 * component/param is not in the schema (caller falls back to the library).
 */
export function paramIsInteger(
  componentId: string,
  key: string,
): boolean | undefined {
  const param = findParam(componentId, key);
  if (!param || param.kind !== "number") return undefined;
  return param.numeric?.integer ?? false;
}

/**
 * Whether a param is *applicable* (and therefore should be shown + validated)
 * given the current config — the schema's `applies_when` rule. Params with no
 * `applies_when`, and params/components outside the schema, are always
 * applicable (the caller's own visibility rules still apply). Comparison is
 * case-insensitive, matching the backend `_param_active`.
 */
export function isParamApplicable(
  componentId: string,
  key: string,
  config: Record<string, unknown>,
): boolean {
  const param = findParam(componentId, key);
  if (!param?.applies_when) return true;
  return Object.entries(param.applies_when).every(([controlKey, allowed]) => {
    const allowedLower = allowed.map((a) => a.toLowerCase());
    return allowedLower.includes(
      String(controlValue(config, controlKey)).toLowerCase(),
    );
  });
}
