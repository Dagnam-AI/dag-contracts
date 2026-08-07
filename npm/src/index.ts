/**
 * `@dagnam/contracts` — the canonical component/parameter validation contract.
 *
 * The TypeScript twin of the `dagnam-contracts` Python package: both carry the
 * byte-identical `component-schema.json` and interpret it to the same verdicts,
 * so the Studio cannot accept a parameter the backend rejects.
 */

import schema from "./component-schema.json" with { type: "json" };

export { validateParamsAgainstSchema } from "./schema-param-validation.js";
export { isParamApplicable, paramIsInteger } from "./component-schema-fields.js";
export type { Severity, ValidationResult } from "./types.js";

/** Schema version the shipped contract was generated at. */
export const SCHEMA_VERSION: number = (schema as { version: number }).version;

/** Every component in the contract, keyed by `component_id`. */
export const COMPONENT_REGISTRY: Record<string, unknown> = Object.fromEntries(
  (schema as { components: { component_id: string }[] }).components.map((c) => [c.component_id, c]),
);

export { default as componentSchema } from "./component-schema.json" with { type: "json" };
