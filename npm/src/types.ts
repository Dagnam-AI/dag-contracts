/**
 * Diagnostic shape shared by every Dagnam validator.
 *
 * Defined here rather than imported from the Studio so this package depends on
 * nothing: the contract is the thing consumers pin, so it cannot in turn depend
 * on one of its consumers.
 *
 * The field names are deliberately snake_case where they cross the wire
 * (`node_id`, `edge_id`) — they mirror the backend's payload exactly, and a
 * camelCase rename here would silently break parity between the two engines.
 */

export type Severity = "error" | "warning" | "info";

export interface ValidationResult {
  type: string;
  message: string;
  /**
   * `null` mirrors the backend's `node_id=None` — a diagnostic not anchored to
   * any single node. `undefined` means the field was never set. Both render
   * identically in a UI (falsy), but they are not the same statement.
   */
  node_id?: string | null;
  edge_id?: string;
  severity: Severity;
  /** Stable structured diagnostic code, e.g. `"PARAM_NUMBER_BELOW_MIN"`. */
  code?: string;
  /** Offending parameter key. */
  field?: string;
  /** Expected value or shape, rendered to a parity-stable string. */
  expected?: string;
  /** Actual value or shape, rendered to a parity-stable string. */
  got?: string;
  /** Actionable remediation shown to the user. */
  fix_hint?: string;
}
