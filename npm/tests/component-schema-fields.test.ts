/**
 * Tests for `component-schema-fields.ts` — schema-driven field metadata.
 *
 * The public surface (`paramIsInteger`, `isParamApplicable`) is exercised
 * against the real shipped schema for realistic cases. A couple of defensive
 * branches (a `number` param with no `numeric` block) never occur in the real
 * schema, so those are exercised against a synthetic schema injected via
 * `vi.doMock` + a fresh dynamic import — the TS equivalent of the Python
 * side's `monkeypatch.setattr(COMPONENT_REGISTRY, ...)`.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { isParamApplicable, paramIsInteger } from "../src/component-schema-fields.js";

describe("paramIsInteger", () => {
  it("returns undefined for an unknown component", () => {
    expect(paramIsInteger("not-a-real-component", "x")).toBeUndefined();
  });

  it("returns undefined for an unknown param on a known component", () => {
    expect(paramIsInteger("convolution-layer", "not-a-real-param")).toBeUndefined();
  });

  it("returns undefined for a non-number kind", () => {
    expect(paramIsInteger("convolution-layer", "padding")).toBeUndefined();
  });

  it("returns true for an integer numeric param", () => {
    expect(paramIsInteger("convolution-layer", "filters")).toBe(true);
  });

  it("returns false for a non-integer numeric param", () => {
    expect(paramIsInteger("dropout", "rate")).toBe(false);
  });

  it("does not resolve through aliases (only the canonical key)", () => {
    // dropout's canonical key is "rate" with alias "p"; findParam only
    // compares against p.key's variants, never p.aliases.
    expect(paramIsInteger("dropout", "p")).toBeUndefined();
  });
});

describe("isParamApplicable", () => {
  it("is true for an unknown component", () => {
    expect(isParamApplicable("not-a-real-component", "x", {})).toBe(true);
  });

  it("is true for a param with no applies_when", () => {
    expect(isParamApplicable("convolution-layer", "filters", {})).toBe(true);
  });

  it("is true when the control value satisfies applies_when (case-insensitively)", () => {
    expect(
      isParamApplicable("output-layer", "optimizer_momentum", { optimizer: "SGD" }),
    ).toBe(true);
  });

  it("is false when the control value violates applies_when", () => {
    expect(
      isParamApplicable("output-layer", "optimizer_momentum", { optimizer: "adam" }),
    ).toBe(false);
  });

  it("is false when the control value is entirely missing", () => {
    expect(isParamApplicable("output-layer", "optimizer_momentum", {})).toBe(false);
  });
});

describe("paramIsInteger against a synthetic schema", () => {
  afterEach(() => {
    vi.doUnmock("../src/component-schema.json");
    vi.resetModules();
  });

  it("falls back to false when a number param has no numeric block", async () => {
    vi.doMock("../src/component-schema.json", () => ({
      default: {
        version: 1,
        components: [
          {
            component_id: "synthetic",
            layer_type: "synthetic",
            params: [{ key: "mode", kind: "number" }],
          },
        ],
        diagnostics: [],
      },
    }));
    vi.resetModules();
    const fresh = await import("../src/component-schema-fields.js");
    expect(fresh.paramIsInteger("synthetic", "mode")).toBe(false);
  });
});
