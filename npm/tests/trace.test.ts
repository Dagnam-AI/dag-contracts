/**
 * Trace envelope v1 (mirrors `src/trace.ts`): the cases file shared with the Python reader, plus
 * the ported Python-side checks. JavaScript-specific traps live in `trace-js.test.ts`.
 */

import { describe, expect, it } from "vitest";

import {
  ENDPOINTS,
  ENVELOPE_VERSION,
  EnvelopeError,
  MAX_LINE_BYTES,
  NORM_VERSION,
  PROVIDERS,
  UnsupportedEnvelopeVersion,
  encodeEnvelope,
  parseEnvelope,
} from "../src/index.js";
import type { TraceEnvelope } from "../src/index.js";

import { BAD_TEXT, CASES, ERRORS, FIRST, compact, expectRejected, failure } from "./trace-support.js";


// JSON.parse turns 2.0 into 2, so only Python can tell these apart; a new one must be noticed.
const PYTHON_ONLY = [
  "norm_v_float_1_0",
  "status_float_200_0",
  "version_float_1_0",
  "version_float_2_0",
];

describe("shared cases", () => {
  it("skips exactly the python-only cases", () => {
    const skipped = CASES.filter((c) => c.python_only === true).map((c) => c.name);
    console.info(`python_only skipped: ${skipped.length} of ${CASES.length}: ${skipped.join(", ")}`);
    expect(skipped.sort()).toEqual(PYTHON_ONLY);
  });

  it("has the shape the Python reader pins", () => {
    const names = CASES.map((c) => c.name);
    expect(new Set(names).size).toBe(names.length);
    expect(names[0]).toBe("raw_and_norm");
    for (const c of CASES) {
      expect("expect" in c).toBe(c.ok);
      expect(c.error === null).toBe(c.ok);
    }
  });

  for (const c of CASES) {
    it.skipIf(c.python_only === true)(`${c.name}`, () => {
      if (c.ok) {
        const parsed = parseEnvelope(compact(c.line));
        expect(parsed).toStrictEqual(c.expect);
        // An already-decoded object gives the same envelope, and the encoder round-trips it.
        expect(parseEnvelope(c.line)).toStrictEqual(parsed);
        expect(parseEnvelope(encodeEnvelope(parsed))).toStrictEqual(parsed);
        return;
      }
      const error = failure(compact(c.line));
      expect(error).toBeInstanceOf(ERRORS[c.error as string]!);
      // Class-exact: a plain EnvelopeError case must not be the unsupported-version error.
      expect(error!.constructor).toBe(ERRORS[c.error as string]);
      expect(error!.name).toBe(c.error);
    });
  }
});

describe("constants", () => {
  it("pin the v1 contract", () => {
    expect([ENVELOPE_VERSION, NORM_VERSION, MAX_LINE_BYTES]).toEqual([1, 1, 1_000_000]);
    expect(PROVIDERS).toEqual(["openai", "anthropic", "other"]);
    expect(ENDPOINTS).toEqual(["chat.completions", "responses", "messages", "custom"]);
  });
});

describe("round trip", () => {
  it("is one line and lossless", () => {
    const env = parseEnvelope(compact(FIRST));
    const text = encodeEnvelope(env);
    expect(text).not.toContain("\n");
    expect(parseEnvelope(text)).toStrictEqual(env);
  });

  it("preserves unicode instead of escaping it", () => {
    const line = { ...FIRST, norm: { ...FIRST.norm, response: "héllo 你好" } };
    expect(encodeEnvelope(parseEnvelope(line))).toContain("你好");
  });

  it("encodes norm-only without raw bodies, and raw-only without norm", () => {
    const normOnly = Object.fromEntries(
      Object.entries(FIRST).filter(([k]) => k !== "request" && k !== "response"),
    );
    const a = JSON.parse(encodeEnvelope(parseEnvelope(normOnly)));
    expect(a).not.toHaveProperty("request");
    expect(a).not.toHaveProperty("response");
    expect(a.norm_v).toBe(1);
    const rawOnly = Object.fromEntries(
      Object.entries(FIRST).filter(([k]) => k !== "norm" && k !== "norm_v"),
    );
    const b = JSON.parse(encodeEnvelope(parseEnvelope(rawOnly)));
    expect(b).not.toHaveProperty("norm");
    expect(b).not.toHaveProperty("norm_v");
    expect(b.request).toEqual(FIRST.request);
  });
});

describe("input types", () => {
  it("rejects input that is neither a line nor an object", () => {
    for (const bad of [5, null, [FIRST], 1.5, undefined, true]) {
      expectRejected(bad as never, "string or an object");
    }
  });

  it("rejects non-envelope JSON", () => {
    for (const bad of ["[1, 2]", "not json", "", '"x"', "null", "{}", "5"]) expectRejected(bad);
  });

  it("rejects objects that are not plain JSON values", () => {
    for (const bad of [
      { s: new Set([1]) },
      { d: new Date(0) },
      { m: new Map() },
      { u: undefined },
      { f: () => 1 },
      { b: 1n },
      { sym: Symbol("x") },
      { sparse: new Array<number>(3) },
    ]) {
      expectRejected({ ...FIRST, request: bad }, "JSON values");
    }
    expectRejected(Object.create({ inherited: 1 }), "JSON values");
  });

  it("accepts an object with a null prototype", () => {
    const bare = Object.assign(Object.create(null), FIRST) as object;
    expect(parseEnvelope(bare).trace_id).toBe(FIRST.trace_id);
  });
});

describe("defaults and shapes", () => {
  const norm = (changes: Record<string, unknown>): Record<string, unknown> => ({
    ...FIRST,
    norm: { ...FIRST.norm, ...changes },
  });
  const without = (obj: Record<string, unknown>, ...keys: string[]): Record<string, unknown> =>
    Object.fromEntries(Object.entries(obj).filter(([k]) => !keys.includes(k)));

  it("default cached_prompt_tokens, has_media, tool_calls and system when absent, never when null", () => {
    const bare = { ...FIRST, norm: without(FIRST.norm, "cached_prompt_tokens", "has_media", "tool_calls", "system") };
    const parsed = parseEnvelope(bare).norm!;
    expect([parsed.cached_prompt_tokens, parsed.has_media, parsed.tool_calls, parsed.system]).toEqual([0, false, [], null]);
    expect(parseEnvelope(norm({ system: null })).norm?.system).toBeNull();
    for (const key of ["cached_prompt_tokens", "has_media", "tool_calls"]) {
      expectRejected(norm({ [key]: null }));
    }
  });

  it("require typed norm fields", () => {
    for (const changes of [
      { system: 5 },
      { response: null },
      { response: 5 },
      { model: "" },
      { model: 5 },
      { messages: "ab" },
      { messages: [5] },
      { messages: [[]] },
      { messages: [{ role: "user", content: 5 }] },
      { messages: [{ role: 1, content: "x" }] },
      { tool_calls: {} },
      { tool_calls: ["ab"] },
      { tool_calls: [null] },
      { tool_calls: [{ type: "function", function: { name: "f" } }] },
      { tool_calls: [{ type: "function", function: "f" }] },
      { tool_calls: [{ type: "function", function: { name: 1, arguments: "{}" } }] },
      { tool_calls: [{ type: "other", function: { name: "f", arguments: "{}" } }] },
      { has_media: 1 },
    ]) {
      expectRejected(norm(changes));
    }
    expectRejected({ ...FIRST, norm: 5 }, "norm must be an object");
    expectRejected({ ...FIRST, norm: [] }, "norm must be an object");
  });

  it("keeps a tool call's extra keys and copies the call", () => {
    const call = { id: "c1", type: "function", function: { name: "f", arguments: "{}" } };
    const kept = parseEnvelope(norm({ tool_calls: [call] })).norm!.tool_calls[0];
    expect(kept).toEqual(call);
    expect(kept).not.toBe(call);
  });

  it("drops unknown top-level keys and message extras", () => {
    const env = parseEnvelope({
      ...norm({ messages: [{ role: "user", content: "x", extra: 1 }] }),
      surprise: 1,
    });
    expect(env.norm?.messages).toEqual([{ role: "user", content: "x" }]);
    expect(env).not.toHaveProperty("surprise");
  });

  it("requires bodies to be objects and to come as a pair", () => {
    for (const bad of [5, "x", []]) {
      expectRejected({ ...FIRST, request: bad }, "request must be an object");
      expectRejected({ ...FIRST, response: bad }, "response must be an object");
    }
    expectRejected(without(FIRST, "response"), "both");
    expectRejected(without(FIRST, "request"), "both");
    expectRejected(without(FIRST, "request", "response", "norm", "norm_v"), "needs");
    expect(parseEnvelope({ ...FIRST, request: null, response: null }).request).toBeNull();
  });

  it("ignores norm_v when there is no norm", () => {
    const env = parseEnvelope({ ...without(FIRST, "norm"), norm_v: 7 });
    expect(env.norm).toBeNull();
    expect(env.norm_v).toBeNull();
  });

  it("requires non-empty strings and known providers and endpoints", () => {
    for (const key of ["trace_id", "ts", "provider", "endpoint"]) {
      for (const bad of ["", null, 5]) expectRejected({ ...FIRST, [key]: bad });
    }
    expectRejected({ ...FIRST, provider: "gemini" }, "unknown provider");
    expectRejected({ ...FIRST, endpoint: "embeddings" }, "unknown provider");
    expectRejected(without(FIRST, "trace_id"));
  });

  it("reads own properties only", () => {
    expectRejected({ ...without(FIRST, "norm"), norm: Object.create({ model: "x" }) });
  });
});

describe("line cap", () => {
  const lineOfExactly = (size: number): string => {
    const stub = compact({ ...FIRST, request: { pad: "" } });
    const bytes = (s: string): number => new TextEncoder().encode(s).length;
    const line = compact({ ...FIRST, request: { pad: "é".repeat(Math.floor((size - bytes(stub)) / 2)) } });
    return line + " ".repeat(size - bytes(line));
  };

  it("counts UTF-8 bytes: at the cap parses, one more is rejected", () => {
    const atCap = lineOfExactly(MAX_LINE_BYTES);
    expect(new TextEncoder().encode(atCap).length).toBe(MAX_LINE_BYTES);
    expect(parseEnvelope(atCap).trace_id).toBe(FIRST.trace_id);
    expectRejected(atCap + " ", "exceeds");
    // Characters would fit under the cap but their UTF-8 bytes do not.
    const wide = "é".repeat(MAX_LINE_BYTES / 2 + 1);
    expect(wide.length).toBeLessThan(MAX_LINE_BYTES);
    expectRejected(wide, "exceeds");
  });

  it("does not cap an object", () => {
    const env = parseEnvelope({ ...FIRST, request: { blob: "x".repeat(MAX_LINE_BYTES + 1) } });
    expect(Object.keys(env.request!)).toEqual(["blob"]);
  });

  it("is enforced on encode, in bytes", () => {
    const env = parseEnvelope(compact(FIRST));
    expect(() => encodeEnvelope({ ...env, response: { blob: "x".repeat(MAX_LINE_BYTES) } })).toThrow(/exceeds/);
    expect(() => encodeEnvelope({ ...env, response: { blob: "é".repeat(MAX_LINE_BYTES / 2) } })).toThrow(/exceeds/);
    expect(encodeEnvelope(env)).toBeTruthy();
  });
});

describe("encode refuses what JSON cannot carry", () => {
  const env = (): TraceEnvelope => parseEnvelope(compact(FIRST));

  it("raises only EnvelopeError", () => {
    for (const changes of [
      { latency_ms: NaN },
      { latency_ms: Infinity },
      { request: { x: NaN } },
      { request: { x: new Set([1]) } },
      { request: { x: BAD_TEXT } },
      { request: { [BAD_TEXT]: 1 } },
    ]) {
      expect(() => encodeEnvelope({ ...env(), ...changes })).toThrow(EnvelopeError);
    }
    const norm = { ...env().norm!, response: BAD_TEXT };
    expect(() => encodeEnvelope({ ...env(), norm })).toThrow(EnvelopeError);
  });

  it("raises EnvelopeError, not TypeError, for an envelope that is not shaped like one", () => {
    const { norm: _norm, ...noNorm } = env();
    for (const bad of [noNorm, { ...env(), norm: undefined }, { ...env(), norm: 5 }, { ...env(), norm: {} }]) {
      expect(() => encodeEnvelope(bad as unknown as TraceEnvelope)).toThrow(EnvelopeError);
    }
    expect(() => encodeEnvelope({ ...env(), request: undefined } as unknown as TraceEnvelope)).toThrow(EnvelopeError);
  });

  it("turns runaway nesting into an EnvelopeError", () => {
    const deep: Record<string, unknown> = {};
    let node = deep;
    for (let i = 0; i < 200_000; i++) {
      const next: Record<string, unknown> = {};
      node["a"] = next;
      node = next;
    }
    expect(() => encodeEnvelope({ ...env(), request: deep })).toThrow(EnvelopeError);
  });

  it("walks deeply nested parsed JSON without recursing", () => {
    const text = `{"a":${"[".repeat(5000)}${"]".repeat(5000)}}`;
    const request = JSON.parse(text) as Record<string, unknown>;
    expect(parseEnvelope({ ...FIRST, request }).request).toBe(request);
  });
});
