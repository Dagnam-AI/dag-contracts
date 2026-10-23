/**
 * Trace envelope v1, the JavaScript-specific traps (mirrors `src/trace.ts`): what JSON.parse and
 * JS numbers and strings change compared with the Python reader.
 */

import { describe, expect, it } from "vitest";

import { UnsupportedEnvelopeVersion, parseEnvelope } from "../src/index.js";

import { BAD_TEXT, FIRST, compact, expectRejected, failure } from "./trace-support.js";

describe("non-finite numbers", () => {
  it("cannot come from text, but an object can carry them", () => {
    for (const bad of [NaN, Infinity, -Infinity]) {
      expectRejected({ ...FIRST, request: { deep: [{ x: bad }] } }, "finite");
      expectRejected({ ...FIRST, response: { deep: [{ x: bad }] } }, "finite");
      expectRejected({ ...FIRST, latency_ms: bad });
    }
  });

  it("rejects NaN and Infinity spelled in text, and a number too big for a double", () => {
    for (const c of ["NaN", "Infinity", "-Infinity"]) {
      expectRejected(compact(FIRST).replace('"messages"', `"x":${c},"messages"`));
    }
    expectRejected(compact(FIRST).replace('"status":200', `"status":${"9".repeat(400)}`));
  });
});

describe("lone surrogates", () => {
  it("are rejected in values, keys, norm and ids of an object", () => {
    const cases: Record<string, unknown>[] = [
      { ...FIRST, request: { a: BAD_TEXT } },
      { ...FIRST, request: { [BAD_TEXT]: 1 } },
      { ...FIRST, norm: { ...FIRST.norm, response: BAD_TEXT } },
      { ...FIRST, response: { a: [{ b: BAD_TEXT }] } },
      { ...FIRST, trace_id: BAD_TEXT },
      { ...FIRST, request: { a: "\udc00" } },
      { ...FIRST, request: { a: "x\ud800y" } },
    ];
    for (const bad of cases) expectRejected(bad, "surrogate");
  });

  it("are rejected as a JSON escape in text and as raw text in a line", () => {
    expectRejected(compact({ ...FIRST, request: { a: "x" } }).replace('"x"', '"\\ud800"'), "surrogate");
    expectRejected(BAD_TEXT, "UTF-8");
  });

  it("accept a well-formed pair", () => {
    const line = { ...FIRST, request: { a: "😀" } };
    expect(parseEnvelope(line).request).toEqual({ a: "😀" });
  });
});

describe("cycles", () => {
  it("are rejected instead of walked forever", () => {
    const loop: Record<string, unknown> = {};
    loop["self"] = loop;
    expectRejected({ ...FIRST, request: loop }, "cycle");
    const twoStep: Record<string, unknown> = {};
    twoStep["child"] = { back: twoStep };
    expectRejected({ ...FIRST, response: twoStep }, "cycle");
    const list: unknown[] = [];
    list.push(list);
    expectRejected({ ...FIRST, request: { a: list } }, "cycle");
  });

  it("allow one object referenced twice side by side", () => {
    const shared = { k: [1, 2] };
    const env = parseEnvelope({ ...FIRST, request: { a: shared, b: shared }, response: { c: shared } });
    expect(env.request).toEqual({ a: { k: [1, 2] }, b: { k: [1, 2] } });
  });
});

describe("timestamps", () => {
  const withTs = (ts: string): string => compact({ ...FIRST, ts });

  it("accept fractional seconds of any length", () => {
    for (const ts of ["2026-10-12T09:30:00Z", "2026-10-12T09:30:00.1Z", "2026-10-12T09:30:00.123456789012Z"]) {
      expect(parseEnvelope(withTs(ts)).ts).toBe(ts);
    }
  });

  it("accept the calendar's edges", () => {
    for (const ts of [
      "2024-02-29T23:59:59Z",
      "2000-02-29T00:00:00Z",
      "0001-01-01T00:00:00Z",
      "9999-12-31T23:59:59.999Z",
      "2026-04-30T00:00:00Z",
    ]) {
      expect(parseEnvelope(withTs(ts)).ts).toBe(ts);
    }
  });

  it("reject what is not a strict UTC RFC 3339 time", () => {
    for (const ts of [
      "2026-10-12T09:30:00z",
      "2026-10-12t09:30:00Z",
      "2026-10-12 09:30:00Z",
      "2026-10-12",
      "20261012T093000Z",
      "2026-10-12T09:30Z",
      "2026-10-12T09:30:00",
      "2026-10-12T09:30:00+00:00",
      "2026-10-12T09:30:00.Z",
      "2026-10-12T09:30:00Z\n",
      " 2026-10-12T09:30:00Z",
      "٢٠٢٦-10-12T09:30:00Z",
    ]) {
      expectRejected(withTs(ts), "RFC 3339");
    }
  });

  it("reject times that do not exist", () => {
    for (const ts of [
      "2026-10-12T24:00:00Z",
      "2026-10-12T09:60:00Z",
      "2026-10-12T09:30:60Z",
      "2026-13-01T00:00:00Z",
      "2026-00-10T00:00:00Z",
      "2026-10-00T00:00:00Z",
      "2026-10-32T00:00:00Z",
      "2026-04-31T00:00:00Z",
      "2026-02-29T00:00:00Z",
      "1900-02-29T00:00:00Z",
      "0000-01-01T00:00:00Z",
    ]) {
      expectRejected(withTs(ts), "real date");
    }
  });
});

describe("numbers", () => {
  const set = (changes: Record<string, unknown>): Record<string, unknown> => ({ ...FIRST, ...changes });

  it("reject negative zero latency, from text and from an object", () => {
    expectRejected(compact(FIRST).replace('"latency_ms":812.5', '"latency_ms":-0'), "latency_ms");
    expectRejected(set({ latency_ms: -0 }), "latency_ms");
    expect(parseEnvelope(set({ latency_ms: 0 })).latency_ms).toBe(0);
    expect(parseEnvelope(compact(FIRST).replace('"latency_ms":812.5', '"latency_ms":0.0')).latency_ms).toBe(0);
  });

  it("keep latency inside 0..2**53 - 1", () => {
    expect(parseEnvelope(set({ latency_ms: Number.MAX_SAFE_INTEGER })).latency_ms).toBe(Number.MAX_SAFE_INTEGER);
    for (const bad of [2 ** 53, 1e300, -1, -0.5, "5", null, true]) {
      expectRejected(set({ latency_ms: bad }), "latency_ms");
    }
  });

  it("keep integer fields inside 0..2**53 - 1", () => {
    const norm = (changes: Record<string, unknown>): Record<string, unknown> =>
      set({ norm: { ...FIRST.norm, ...changes } });
    const unsafe = [2 ** 53, 1e21, 1.5, -1, "1", null, true, []];
    for (const bad of unsafe) {
      expectRejected(norm({ prompt_tokens: bad }), "prompt_tokens");
      expectRejected(norm({ completion_tokens: bad }), "completion_tokens");
      expectRejected(norm({ cached_prompt_tokens: bad }), "cached_prompt_tokens");
    }
    for (const bad of [2 ** 53, 1e21, 200.5, "200", null, true]) expectRejected(set({ status: bad }), "status");
    const big = Number.MAX_SAFE_INTEGER;
    expect(parseEnvelope(norm({ prompt_tokens: big })).norm?.prompt_tokens).toBe(big);
  });

  it("read the text -0 token count as the integer 0", () => {
    const text = compact(FIRST).replace('"prompt_tokens":9', '"prompt_tokens":-0');
    expect(text).toContain('"prompt_tokens":-0');
    const env = parseEnvelope(text);
    expect(Object.is(env.norm?.prompt_tokens, 0)).toBe(true);
  });

  it("reject status outside the HTTP range", () => {
    for (const bad of [99, 600, 0]) expectRejected(set({ status: bad }), "HTTP status");
    for (const ok of [100, 599]) expect(parseEnvelope(set({ status: ok })).status).toBe(ok);
  });

  it("report a newer version as unsupported, a non-integer one as invalid", () => {
    for (const field of ["v", "norm_v"]) {
      for (const newer of [2, 2 ** 60]) {
        const error = failure(set({ [field]: newer }));
        expect(error).toBeInstanceOf(UnsupportedEnvelopeVersion);
      }
      for (const bad of [0, -1, "1", null, 1.5, true]) expectRejected(set({ [field]: bad }));
    }
  });
});


describe("documented differences from the Python reader", () => {
  it("reads number spellings JSON.parse cannot tell apart as integers", () => {
    for (const status of ["2e2", "200.0", "200.00000000000000001"]) {
      const text = compact(FIRST).replace('"status":200', `"status":${status}`);
      expect(parseEnvelope(text).status).toBe(200);
    }
    const text = compact(FIRST).replace('"prompt_tokens":9', '"prompt_tokens":9007199254740990.9');
    expect(parseEnvelope(text).norm?.prompt_tokens).toBe(9007199254740991);
  });

  it("reports a 400-digit version as an EnvelopeError (it parses as Infinity)", () => {
    for (const field of ["v", "norm_v"]) {
      const text = compact(FIRST).replace(`"${field}":1`, `"${field}":1${"0".repeat(400)}`);
      expectRejected(text, "finite");
    }
  });

  it("accepts a text line nested far deeper than Python allows", () => {
    const text = compact({ ...FIRST, request: {} }).replace('"request":{}', `"request":{"a":${"[".repeat(5000)}${"]".repeat(5000)}}`);
    expect(parseEnvelope(text).request).toHaveProperty("a");
  });

  it("does not range-check integers inside bodies", () => {
    const text = compact({ ...FIRST, request: {} }).replace('"request":{}', '"request":{"n":9007199254740993}');
    expect(parseEnvelope(text).request).toEqual({ n: 9007199254740992 });
  });
});
