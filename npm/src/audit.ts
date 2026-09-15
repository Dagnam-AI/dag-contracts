/**
 * The workload audit's reference data, as the tarball ships it.
 *
 * The scorers, the frontier rule and the report blocks stay Python-only — the
 * SDK and a platform worker are the only things that compute them. What a
 * TypeScript consumer needs is what it *displays*: the open instruct models a
 * report is compared against and what the platform charges to serve one. Those
 * are data, and shipping them here is what stops the Studio from carrying a
 * hand-refreshed copy that can silently disagree with the wheel that produced
 * the report it is rendering.
 *
 * Both JSON files are byte-identical to the ones in `dagnam_contracts/audit/`;
 * `tests/audit/test_distribution_parity.py` on the Python side is the gate.
 */

import openModels from "./open-models.json" with { type: "json" };
import servingRates from "./serving-rates.json" with { type: "json" };

/** One open instruct model: hub id, series, parameter count, license, window. */
export interface ReferenceModel {
  id: string;
  family: string;
  parameters: number;
  license: string;
  context_length: number;
}

/** One student kind's rate, with the basis and assumptions behind the figure. */
export interface ServingRate {
  usd_per_1k_requests?: number;
  usd_per_m_output_tokens?: number;
  basis: string;
  assumptions: string;
}

/**
 * The platform's rate card for the two student kinds.
 *
 * Every figure is `basis: "estimated"` and stays labelled that way in every
 * report until billing exists — a number the platform did not measure must
 * never be shown as one it did.
 */
export interface ServingRateCard {
  basis: string;
  note: string;
  rates: {
    "cpu-classifier": ServingRate & { usd_per_1k_requests: number };
    "gpu-small-llm": ServingRate & { usd_per_m_output_tokens: number };
  };
}

/** The bundled open instruct models the audit compares against; never measured. */
export const REFERENCE_MODELS: ReferenceModel[] = openModels.models;

/** The day every bundled row was checked against its Hugging Face model card. */
export const REFERENCE_AS_OF: string = openModels.as_of;

/** The two student kinds' estimated serving rates. */
export const SERVING_RATES: ServingRateCard = servingRates;

/** The schema id an audit report is stamped with. */
export const REPORT_SCHEMA = "dagnam.audit.report/1";

/** The receipt a delete writes. */
export const DELETED_SCHEMA = "dagnam.audit.deleted/1";

/**
 * The receipt a cancel writes. Cancelling stops a run and leaves its artifacts;
 * deleting removes them. A reader that had to inspect a status word to tell the
 * two apart could not route on the schema id, which is what a schema id is for.
 */
export const CANCELLED_SCHEMA = "dagnam.audit.cancelled/1";
