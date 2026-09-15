/**
 * The audit reference data the tarball ships (mirrors `src/audit.ts`).
 *
 * The Studio used to carry its own copy of `open-models.json`, refreshed by a
 * script somebody had to remember to run. These assertions are what make the
 * installed package a usable replacement for that copy: the rows are here, the
 * date they were checked is here, and the rates carry their `estimated` basis
 * rather than arriving as bare numbers.
 */

import { describe, expect, it } from "vitest";

import {
  CANCELLED_SCHEMA,
  DELETED_SCHEMA,
  REFERENCE_AS_OF,
  REFERENCE_MODELS,
  REPORT_SCHEMA,
  SERVING_RATES,
} from "../src/index.js";

describe("open-model reference rows", () => {
  it("ships every row with the fields a comparison table renders", () => {
    expect(REFERENCE_MODELS.length).toBeGreaterThanOrEqual(8);
    const ids = REFERENCE_MODELS.map((m) => m.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const model of REFERENCE_MODELS) {
      expect(model.parameters).toBeGreaterThan(0);
      expect(model.context_length).toBeGreaterThan(0);
      expect(model.family).toBeTruthy();
      expect(model.license).toBeTruthy();
    }
  });

  it("dates the rows, because none of them is measured", () => {
    expect(REFERENCE_AS_OF).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });
});

describe("serving rates", () => {
  it("prices both student kinds and says the figures are estimates", () => {
    expect(SERVING_RATES.basis).toBe("estimated");
    expect(SERVING_RATES.rates["cpu-classifier"].usd_per_1k_requests).toBe(
      0.0023,
    );
    expect(SERVING_RATES.rates["gpu-small-llm"].usd_per_m_output_tokens).toBe(
      1.95,
    );
    for (const row of Object.values(SERVING_RATES.rates)) {
      expect(row.basis).toBe("estimated");
      expect(row.assumptions).toBeTruthy();
    }
  });
});

describe("audit artifact schema ids", () => {
  it("gives a cancel receipt an id of its own", () => {
    expect(REPORT_SCHEMA).toBe("dagnam.audit.report/1");
    expect(DELETED_SCHEMA).toBe("dagnam.audit.deleted/1");
    expect(CANCELLED_SCHEMA).toBe("dagnam.audit.cancelled/1");
    expect(CANCELLED_SCHEMA).not.toBe(DELETED_SCHEMA);
  });
});
