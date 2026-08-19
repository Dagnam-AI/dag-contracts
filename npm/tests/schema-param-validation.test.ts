/**
 * Tests for `schema-param-validation.ts` — the frontend declarative-parameter
 * interpreter (the TypeScript twin of the Python `interpret.py`).
 *
 * Every branch is exercised through the exported `validateParamsAgainstSchema`
 * against the real shipped schema wherever the real schema has a component
 * that reaches it. A handful of defensive branches never occur in the real
 * schema (a `number` param with no `numeric` block, an `enum` param with no
 * `enum_values`, a diagnostic missing `severity`/using an unknown `severity`,
 * a template referencing an unset placeholder, an empty `fix_hint`) — those
 * are exercised against a synthetic schema injected via `vi.doMock` + a fresh
 * dynamic import, mirroring the Python side's `monkeypatch.setattr`.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { validateParamsAgainstSchema } from "../src/schema-param-validation.js";

describe("validateParamsAgainstSchema — real schema", () => {
  it("returns no errors for an unknown component", () => {
    expect(validateParamsAgainstSchema("not-a-real-component", {}, "n1")).toEqual([]);
  });

  it("flags missing required params", () => {
    const errors = validateParamsAgainstSchema("convolution-layer", {}, "n1");
    const codes = errors.map((e) => e.code);
    expect(codes).toContain("PARAM_REQUIRED_MISSING");
    const missingFields = errors
      .filter((e) => e.code === "PARAM_REQUIRED_MISSING")
      .map((e) => e.field);
    expect(missingFields.sort()).toEqual(["filters", "kernelSize"]);
  });

  it("resolves a param via its alias", () => {
    // dropout's canonical key is "rate" with alias "p".
    expect(validateParamsAgainstSchema("dropout", { p: 0.5 }, "n1")).toEqual([]);
  });

  it("skips an inactive param even when its value would fail if checked", () => {
    const errors = validateParamsAgainstSchema(
      "output-layer",
      {
        outputType: "classification",
        optimizer: "adam",
        learningRate: 0.01,
        optimizer_momentum: -5,
      },
      "n1",
    );
    expect(errors.some((e) => e.field === "optimizer_momentum")).toBe(false);
  });

  it("validates an active param", () => {
    const errors = validateParamsAgainstSchema(
      "output-layer",
      {
        outputType: "classification",
        optimizer: "sgd",
        learningRate: 0.01,
        optimizer_momentum: 5,
      },
      "n1",
    );
    expect(errors.some((e) => e.field === "optimizer_momentum")).toBe(true);
  });

  it("passes a bool-kind param through untouched", () => {
    expect(validateParamsAgainstSchema("batch-normalization", { center: true }, "n1")).toEqual([]);
  });

  describe("padding", () => {
    const base = { filters: 32, kernelSize: 3 };

    it.each([
      ["valid", []],
      ["same", []],
    ] as const)("string %s is accepted", (padding) => {
      expect(
        validateParamsAgainstSchema("convolution-layer", { ...base, padding }, "n1"),
      ).toEqual([]);
    });

    it("rejects a bogus string", () => {
      const errors = validateParamsAgainstSchema(
        "convolution-layer",
        { ...base, padding: "bogus" },
        "n1",
      );
      expect(errors[0]?.code).toBe("PARAM_PADDING_BAD_STRING");
    });

    it("rejects an unknown mode", () => {
      const errors = validateParamsAgainstSchema(
        "convolution-layer",
        { ...base, padding: { mode: "nope" } },
        "n1",
      );
      expect(errors[0]?.code).toBe("PARAM_PADDING_BAD_MODE");
    });

    it("a bare array hits the object branch, not NOT_TYPED (FE/BE parity gap, see report)", () => {
      // Python's `_check_padding` treats a bare list as "not a dict" and
      // returns PARAM_PADDING_NOT_TYPED. TypeScript's `typeof [] === "object"`
      // means a bare array instead falls into the mode-dispatch branch here
      // and (having no `.mode`) comes out as PARAM_PADDING_BAD_MODE. Same
      // malformed input, two different diagnostic codes across languages.
      const errors = validateParamsAgainstSchema(
        "convolution-layer",
        { ...base, padding: [1, 2] },
        "n1",
      );
      expect(errors[0]?.code).toBe("PARAM_PADDING_BAD_MODE");
    });

    it("mode same/valid as an object needs no value", () => {
      expect(
        validateParamsAgainstSchema("convolution-layer", { ...base, padding: { mode: "same" } }, "n1"),
      ).toEqual([]);
      expect(
        validateParamsAgainstSchema(
          "convolution-layer",
          { ...base, padding: { mode: "valid" } },
          "n1",
        ),
      ).toEqual([]);
    });

    it("explicit scalar accepts a non-negative integer", () => {
      expect(
        validateParamsAgainstSchema(
          "convolution-layer",
          { ...base, padding: { mode: "explicit", value: 2 } },
          "n1",
        ),
      ).toEqual([]);
    });

    it.each([-1, true, false, 1.5, "2", null])("explicit scalar rejects %j", (value) => {
      const errors = validateParamsAgainstSchema(
        "convolution-layer",
        { ...base, padding: { mode: "explicit", value } },
        "n1",
      );
      expect(errors[0]?.code).toBe("PARAM_PADDING_BAD_EXPLICIT_VALUE");
    });

    it("explicit list accepts 1..3 non-negative integers (boundaries)", () => {
      for (const value of [[1], [1, 2], [1, 2, 3]]) {
        expect(
          validateParamsAgainstSchema(
            "convolution-layer",
            { ...base, padding: { mode: "explicit", value } },
            "n1",
          ),
        ).toEqual([]);
      }
    });

    it.each([{ value: [] }, { value: [1, 2, 3, 4] }])(
      "explicit list rejects length $value.length",
      ({ value }) => {
        const errors = validateParamsAgainstSchema(
          "convolution-layer",
          { ...base, padding: { mode: "explicit", value } },
          "n1",
        );
        expect(errors[0]?.code).toBe("PARAM_PADDING_BAD_AXIS_LENGTH");
      },
    );

    it("explicit list rejects a bad element", () => {
      const errors = validateParamsAgainstSchema(
        "convolution-layer",
        { ...base, padding: { mode: "explicit", value: [1, -2] } },
        "n1",
      );
      expect(errors[0]?.code).toBe("PARAM_PADDING_BAD_EXPLICIT_VALUE");
    });

    it("rejects a non string/object value", () => {
      const errors = validateParamsAgainstSchema(
        "convolution-layer",
        { ...base, padding: 5 },
        "n1",
      );
      expect(errors[0]?.code).toBe("PARAM_PADDING_NOT_TYPED");
    });

    it.each([null, undefined])(
      "null/undefined count as absent (padding isn't required), no error: %j",
      (padding) => {
        expect(validateParamsAgainstSchema("convolution-layer", { ...base, padding }, "n1")).toEqual(
          [],
        );
      },
    );
  });

  describe("number", () => {
    it("rejects a boolean", () => {
      const errors = validateParamsAgainstSchema(
        "convolution-layer",
        { filters: true, kernelSize: 3 },
        "n1",
      );
      expect(errors.find((e) => e.field === "filters")?.code).toBe("PARAM_NUMBER_NOT_A_NUMBER");
    });

    it("rejects NaN", () => {
      const errors = validateParamsAgainstSchema(
        "convolution-layer",
        { filters: Number.NaN, kernelSize: 3 },
        "n1",
      );
      expect(errors.find((e) => e.field === "filters")?.code).toBe("PARAM_NUMBER_NOT_A_NUMBER");
    });

    it("rejects a non-integer when integer is required", () => {
      const errors = validateParamsAgainstSchema(
        "convolution-layer",
        { filters: 3.5, kernelSize: 3 },
        "n1",
      );
      expect(errors.find((e) => e.field === "filters")?.code).toBe("PARAM_NUMBER_NOT_INTEGER");
    });

    it("rejects below min / above max, accepts exactly at the boundary", () => {
      // numClasses (min:1, max:10000) has no warn bounds, so the boundary
      // values are unambiguous (filters' warn_max would also fire at 2048).
      expect(
        validateParamsAgainstSchema("output-layer", { numClasses: 0 }, "n1").find(
          (e) => e.field === "numClasses",
        )?.code,
      ).toBe("PARAM_NUMBER_BELOW_MIN");
      expect(
        validateParamsAgainstSchema("output-layer", { numClasses: 10001 }, "n1").find(
          (e) => e.field === "numClasses",
        )?.code,
      ).toBe("PARAM_NUMBER_ABOVE_MAX");
      expect(
        validateParamsAgainstSchema("output-layer", { numClasses: 1 }, "n1").find(
          (e) => e.field === "numClasses",
        ),
      ).toBeUndefined();
      expect(
        validateParamsAgainstSchema("output-layer", { numClasses: 10000 }, "n1").find(
          (e) => e.field === "numClasses",
        ),
      ).toBeUndefined();
    });

    it("flags below/above the recommended soft bound, accepts exactly at it", () => {
      const below = validateParamsAgainstSchema(
        "output-layer",
        { learningRate: 0.0000001 },
        "n1",
      ).find((e) => e.field === "learningRate");
      expect(below?.code).toBe("PARAM_NUMBER_BELOW_RECOMMENDED");

      const above = validateParamsAgainstSchema(
        "output-layer",
        { learningRate: 0.5 },
        "n1",
      ).find((e) => e.field === "learningRate");
      expect(above?.code).toBe("PARAM_NUMBER_ABOVE_RECOMMENDED");

      expect(
        validateParamsAgainstSchema(
          "output-layer",
          { learningRate: 0.00001 },
          "n1",
        ).find((e) => e.field === "learningRate"),
      ).toBeUndefined();
      expect(
        validateParamsAgainstSchema(
          "output-layer",
          { learningRate: 0.1 },
          "n1",
        ).find((e) => e.field === "learningRate"),
      ).toBeUndefined();
    });
  });

  describe("enum", () => {
    it("rejects a value outside enum_values", () => {
      const errors = validateParamsAgainstSchema(
        "convolution-layer",
        { filters: 32, kernelSize: 3, dimensions: "4d" },
        "n1",
      );
      expect(errors.find((e) => e.field === "dimensions")?.code).toBe("PARAM_ENUM_NOT_ALLOWED");
    });

    it("accepts a value inside enum_values", () => {
      const errors = validateParamsAgainstSchema(
        "convolution-layer",
        { filters: 32, kernelSize: 3, dimensions: "2d" },
        "n1",
      );
      expect(errors.some((e) => e.field === "dimensions")).toBe(false);
    });
  });

  describe("advisories", () => {
    it("fires when the value matches", () => {
      const errors = validateParamsAgainstSchema(
        "convolution-layer",
        { filters: 32, kernelSize: 3, activation: "linear" },
        "n1",
      );
      expect(errors.some((e) => e.code === "INFO_LINEAR_ACTIVATION" && e.severity === "info")).toBe(
        true,
      );
    });

    it("does not fire when the value does not match", () => {
      const errors = validateParamsAgainstSchema(
        "convolution-layer",
        { filters: 32, kernelSize: 3, activation: "relu" },
        "n1",
      );
      expect(errors.some((e) => e.code === "INFO_LINEAR_ACTIVATION")).toBe(false);
    });
  });
});

describe("validateParamsAgainstSchema — synthetic schema (branches the real data never hits)", () => {
  afterEach(() => {
    vi.doUnmock("../src/component-schema.json");
    vi.resetModules();
  });

  it("a number param with no numeric block is never checked", async () => {
    vi.doMock("../src/component-schema.json", () => ({
      default: {
        version: 1,
        components: [
          {
            component_id: "synthetic",
            layer_type: "synthetic",
            params: [{ key: "x", kind: "number" }],
          },
        ],
        diagnostics: [],
      },
    }));
    vi.resetModules();
    const fresh = await import("../src/schema-param-validation.js");
    expect(fresh.validateParamsAgainstSchema("synthetic", { x: "anything" }, "n1")).toEqual([]);
  });

  it("an enum param with no enum_values is never checked", async () => {
    vi.doMock("../src/component-schema.json", () => ({
      default: {
        version: 1,
        components: [
          {
            component_id: "synthetic",
            layer_type: "synthetic",
            params: [{ key: "mode", kind: "enum" }],
          },
        ],
        diagnostics: [],
      },
    }));
    vi.resetModules();
    const fresh = await import("../src/schema-param-validation.js");
    expect(fresh.validateParamsAgainstSchema("synthetic", { mode: "anything" }, "n1")).toEqual([]);
  });

  it("defaults severity to error and type to 'parameter error' when unset", async () => {
    vi.doMock("../src/component-schema.json", () => ({
      default: {
        version: 1,
        components: [
          {
            component_id: "synthetic",
            layer_type: "synthetic",
            params: [{ key: "x", kind: "number", required: true }],
          },
        ],
        diagnostics: [{ code: "PARAM_REQUIRED_MISSING", template: "missing {field}", fix_hint: "" }],
      },
    }));
    vi.resetModules();
    const fresh = await import("../src/schema-param-validation.js");
    const errors = fresh.validateParamsAgainstSchema("synthetic", {}, "n1");
    expect(errors).toHaveLength(1);
    expect(errors[0]!.severity).toBe("error");
    expect(errors[0]!.type).toBe("parameter error");
    // Empty fix_hint renders to "" which is falsy -> `|| undefined`.
    expect(errors[0]!.fix_hint).toBeUndefined();
  });

  it("falls back to 'parameter error' type for an unrecognized severity", async () => {
    vi.doMock("../src/component-schema.json", () => ({
      default: {
        version: 1,
        components: [
          {
            component_id: "synthetic",
            layer_type: "synthetic",
            params: [{ key: "x", kind: "number", required: true }],
          },
        ],
        diagnostics: [
          {
            code: "PARAM_REQUIRED_MISSING",
            severity: "critical",
            template: "missing {field}",
            fix_hint: "fix it",
          },
        ],
      },
    }));
    vi.resetModules();
    const fresh = await import("../src/schema-param-validation.js");
    const errors = fresh.validateParamsAgainstSchema("synthetic", {}, "n1");
    expect(errors[0]!.type).toBe("parameter error");
    expect(errors[0]!.severity).toBe("critical");
  });

  it("renders an unset template placeholder as an empty string", async () => {
    vi.doMock("../src/component-schema.json", () => ({
      default: {
        version: 1,
        components: [
          {
            component_id: "synthetic",
            layer_type: "synthetic",
            params: [{ key: "x", kind: "number", required: true }],
          },
        ],
        diagnostics: [
          {
            code: "PARAM_REQUIRED_MISSING",
            severity: "error",
            template: "missing {field} ({unknown_placeholder})",
            fix_hint: "fix it",
          },
        ],
      },
    }));
    vi.resetModules();
    const fresh = await import("../src/schema-param-validation.js");
    const errors = fresh.validateParamsAgainstSchema("synthetic", {}, "n1");
    expect(errors[0]!.message).toBe("missing x ()");
  });
});
