/**
 * Golden guard for the `@dagnam/contracts` public API (mirrors `index.ts`).
 */

import { describe, expect, it } from "vitest";

import {
  COMPONENT_REGISTRY,
  SCHEMA_VERSION,
  componentSchema,
  isParamApplicable,
  paramIsInteger,
  validateParamsAgainstSchema,
} from "../src/index.js";

describe("public API surface", () => {
  it("exports every documented name", () => {
    expect(typeof SCHEMA_VERSION).toBe("number");
    expect(typeof COMPONENT_REGISTRY).toBe("object");
    expect(typeof componentSchema).toBe("object");
    expect(typeof validateParamsAgainstSchema).toBe("function");
    expect(typeof isParamApplicable).toBe("function");
    expect(typeof paramIsInteger).toBe("function");
  });

  it("SCHEMA_VERSION is a positive integer", () => {
    expect(SCHEMA_VERSION).toBeGreaterThan(0);
  });

  it("COMPONENT_REGISTRY is keyed by component_id", () => {
    const conv = COMPONENT_REGISTRY["convolution-layer"] as {
      component_id: string;
    };
    expect(conv.component_id).toBe("convolution-layer");
  });
});
