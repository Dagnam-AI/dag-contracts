/**
 * Trace envelope v1: one JSON object per recorded LLM call, shared by every recorder and reader.
 * The TypeScript twin of `dagnam_contracts.trace.envelope`: same checks, same order, same verdicts
 * on the shared cases file. Wire field names stay snake_case.
 *
 * Unknown top-level keys are ignored on parse and are not preserved on encode. Every failure on
 * bad input is an `EnvelopeError` (`UnsupportedEnvelopeVersion` for a newer `v` or `norm_v`).
 *
 * The line cap applies to a string line; an object passed to `parseEnvelope` has no size cap.
 * `encodeEnvelope` assumes an envelope that came from `parseEnvelope`: it only guards against what
 * JSON cannot carry (and the cap), not the field rules.
 *
 * Integer fields and `latency_ms` stay within 2**53 - 1 (the JavaScript safe-integer range).
 * JSON.parse cannot tell `2.0` from `2`, `1e2` from `100` or a 400-digit integer from Infinity, so
 * the Python reader is stricter on those spellings; the shared cases it alone can tell apart are
 * marked `python_only`.
 */

export const ENVELOPE_VERSION = 1;
export const NORM_VERSION = 1;
export const MAX_LINE_BYTES = 1_000_000;
export const PROVIDERS = ["openai", "anthropic", "other"] as const;
export const ENDPOINTS = ["chat.completions", "responses", "messages", "custom"] as const;

const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;
const TS = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?Z$/;
// Code-unit regex (no `u` flag): a high surrogate not followed by a low one, or a stray low one.
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

export class EnvelopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

export class UnsupportedEnvelopeVersion extends EnvelopeError {}

export interface NormMessage {
  role: string;
  content: string;
}

export interface ToolCall {
  type: "function";
  function: { name: string; arguments: string; [key: string]: unknown };
  [key: string]: unknown;
}

export interface Norm {
  model: string;
  system: string | null;
  messages: NormMessage[];
  response: string;
  tool_calls: ToolCall[];
  prompt_tokens: number;
  completion_tokens: number;
  cached_prompt_tokens: number;
  has_media: boolean;
}

export interface TraceEnvelope {
  v: number;
  trace_id: string;
  ts: string;
  provider: string;
  endpoint: string;
  latency_ms: number;
  status: number;
  request: Record<string, unknown> | null;
  response: Record<string, unknown> | null;
  norm: Norm | null;
  norm_v: number | null;
}

type Obj = Record<string, unknown>;

// TextEncoder is a global in every runtime this ships to (Node, browsers, Workers); the package
// tsconfig has neither the DOM lib nor @types/node, so type the one method used here.
declare const TextEncoder: new () => { encode(input: string): { length: number } };

const isRecord = (value: unknown): value is Obj =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const isPlainObject = (value: object): boolean => {
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
};

const isInt = (value: unknown): value is number =>
  typeof value === "number" && Number.isInteger(value);

const byteLength = (text: string): number => new TextEncoder().encode(text).length;

function checkText(value: string): void {
  if (LONE_SURROGATE.test(value)) {
    throw new EnvelopeError("strings must be valid Unicode (no lone surrogates)");
  }
}

/** Reject anything a JSON line cannot carry: non-finite numbers, lone surrogates, non-JSON types. */
function checkJson(root: unknown): void {
  // Depth-first with an explicit stack; `onPath` holds the containers being walked, so a container
  // that contains itself is a cycle, while one referenced twice side by side is fine.
  const stack: [unknown, boolean][] = [[root, false]];
  const onPath = new Set<object>();
  while (stack.length > 0) {
    const [value, leaving] = stack.pop() as [unknown, boolean];
    if (leaving) {
      onPath.delete(value as object);
    } else if (typeof value === "string") {
      checkText(value);
    } else if (typeof value === "number") {
      if (!Number.isFinite(value)) throw new EnvelopeError("numbers must be finite");
    } else if (value !== null && typeof value !== "boolean") {
      const isArray = Array.isArray(value);
      if (typeof value !== "object" || !(isArray || isPlainObject(value))) {
        throw new EnvelopeError("values must be JSON values");
      }
      if (onPath.has(value)) throw new EnvelopeError("an envelope cannot contain a cycle");
      onPath.add(value);
      stack.push([value, true]);
      if (isArray) {
        for (const item of value as unknown[]) stack.push([item, false]);
      } else {
        for (const [key, item] of Object.entries(value)) {
          checkText(key);
          stack.push([item, false]);
        }
      }
    }
  }
}

function load(line: unknown): Obj {
  let loaded: unknown = line;
  if (typeof line === "string") {
    if (LONE_SURROGATE.test(line)) throw new EnvelopeError("a line must be valid UTF-8");
    if (byteLength(line) > MAX_LINE_BYTES) {
      throw new EnvelopeError(`line exceeds ${MAX_LINE_BYTES} bytes`);
    }
    try {
      loaded = JSON.parse(line);
    } catch {
      throw new EnvelopeError("not JSON");
    }
    if (!isRecord(loaded)) throw new EnvelopeError("an envelope is a JSON object");
  } else if (typeof line !== "object" || line === null || Array.isArray(line)) {
    throw new EnvelopeError("a line is a string or an object");
  }
  return loaded as Obj;
}

function str(obj: Obj, key: string): string {
  const value = obj[key];
  if (typeof value !== "string" || value === "") {
    throw new EnvelopeError(`${key} must be a non-empty string`);
  }
  return value;
}

function int(obj: Obj, key: string): number {
  const value = obj[key];
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new EnvelopeError(`${key} must be an integer from 0 to 2**53 - 1`);
  }
  return value + 0; // JSON text "-0" parses as -0 in JS; Python reads it as the integer 0
}

function message(raw: unknown): NormMessage {
  if (!isRecord(raw)) throw new EnvelopeError("norm.messages entries must be objects");
  const { role, content } = raw;
  if (typeof role !== "string" || typeof content !== "string") {
    throw new EnvelopeError("norm.messages entries need a string role and string content");
  }
  return { role, content };
}

/** An OpenAI-shaped call: `{"type": "function", "function": {"name": str, "arguments": str}}`. */
function toolCall(raw: unknown): ToolCall {
  if (isRecord(raw)) {
    const fn = raw["function"];
    if (
      raw["type"] === "function" &&
      isRecord(fn) &&
      typeof fn["name"] === "string" &&
      typeof fn["arguments"] === "string"
    ) {
      return { ...raw } as ToolCall;
    }
  }
  throw new EnvelopeError('norm.tool_calls entries must be {"type":"function","function":{...}}');
}

function normVersion(obj: Obj): number {
  const value = obj["norm_v"];
  if (!isInt(value)) throw new EnvelopeError("norm needs an integer norm_v");
  if (value > NORM_VERSION) {
    throw new UnsupportedEnvelopeVersion("norm_v is newer than this reader understands");
  }
  if (value !== NORM_VERSION) throw new EnvelopeError(`norm_v must be ${NORM_VERSION}`);
  return NORM_VERSION;
}

function norm(raw: unknown): Norm {
  if (!isRecord(raw)) throw new EnvelopeError("norm must be an object");
  const messages = raw["messages"];
  const calls = Object.hasOwn(raw, "tool_calls") ? raw["tool_calls"] : [];
  if (!Array.isArray(messages) || !Array.isArray(calls)) {
    throw new EnvelopeError("norm.messages and norm.tool_calls must be lists");
  }
  const system = raw["system"] ?? null;
  if (system !== null && typeof system !== "string") {
    throw new EnvelopeError("norm.system must be a string or null");
  }
  const response = raw["response"];
  if (typeof response !== "string") throw new EnvelopeError("norm.response must be a string");
  const hasMedia = Object.hasOwn(raw, "has_media") ? raw["has_media"] : false;
  if (typeof hasMedia !== "boolean") throw new EnvelopeError("norm.has_media must be a boolean");
  return {
    model: str(raw, "model"),
    system,
    messages: (messages as unknown[]).map(message),
    response,
    tool_calls: (calls as unknown[]).map(toolCall),
    prompt_tokens: int(raw, "prompt_tokens"),
    completion_tokens: int(raw, "completion_tokens"),
    cached_prompt_tokens: Object.hasOwn(raw, "cached_prompt_tokens")
      ? int(raw, "cached_prompt_tokens")
      : 0,
    has_media: hasMedia,
  };
}

function body(obj: Obj, key: string): Obj | null {
  const value = obj[key] ?? null;
  if (value === null) return null;
  if (!isRecord(value)) throw new EnvelopeError(`${key} must be an object`);
  return value;
}

function checkVersion(obj: Obj): void {
  const version = obj["v"];
  if (!isInt(version)) throw new EnvelopeError("v must be the integer 1");
  if (version > ENVELOPE_VERSION) {
    throw new UnsupportedEnvelopeVersion("envelope version is newer than this reader understands");
  }
  if (version !== ENVELOPE_VERSION) throw new EnvelopeError("v must be 1");
}

const isLeap = (year: number): boolean => (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;

/** Strict RFC 3339 UTC: the regex fixes the shape, this checks the calendar and clock ranges. */
function checkTimestamp(ts: string): void {
  const match = TS.exec(ts);
  if (match === null) throw new EnvelopeError("ts must be a UTC RFC 3339 time ending in Z");
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number) as [
    number,
    number,
    number,
    number,
    number,
    number,
  ];
  const days = [31, isLeap(year) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (
    year < 1 ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > (days[month - 1] as number) ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  ) {
    throw new EnvelopeError("ts is not a real date and time");
  }
}

/** Validate one envelope: a JSON line, or an already-decoded object. */
export function parseEnvelope(line: string | object): TraceEnvelope {
  const obj = load(line);
  checkJson(obj);
  checkVersion(obj);
  const ts = str(obj, "ts");
  checkTimestamp(ts);
  const provider = str(obj, "provider");
  const endpoint = str(obj, "endpoint");
  if (
    !(PROVIDERS as readonly string[]).includes(provider) ||
    !(ENDPOINTS as readonly string[]).includes(endpoint)
  ) {
    throw new EnvelopeError("unknown provider or endpoint");
  }
  const latency = obj["latency_ms"];
  if (typeof latency !== "number") throw new EnvelopeError("latency_ms must be a number");
  // JSON text "-0" is -0 here (Python reads the integer 0); both spellings are rejected.
  if (!(latency >= 0 && latency <= MAX_SAFE_INTEGER) || Object.is(latency, -0)) {
    throw new EnvelopeError("latency_ms must be a finite, non-negative number up to 2**53 - 1");
  }
  const status = int(obj, "status");
  if (status < 100 || status > 599) throw new EnvelopeError("status must be an HTTP status");
  const request = body(obj, "request");
  const response = body(obj, "response");
  if ((request === null) !== (response === null)) {
    throw new EnvelopeError("request and response must both be present or both absent");
  }
  let normV: number | null = null;
  let parsedNorm: Norm | null = null;
  if ((obj["norm"] ?? null) !== null) {
    normV = normVersion(obj); // first: a newer norm may have a shape we cannot read
    parsedNorm = norm(obj["norm"]);
  }
  if (request === null && parsedNorm === null) {
    throw new EnvelopeError("a line needs request and response, or norm");
  }
  return {
    v: ENVELOPE_VERSION,
    trace_id: str(obj, "trace_id"),
    ts,
    provider,
    endpoint,
    latency_ms: latency,
    status,
    request,
    response,
    norm: parsedNorm,
    norm_v: normV,
  };
}

export function encodeEnvelope(envelope: TraceEnvelope): string {
  const out: Obj = {
    v: envelope.v,
    trace_id: envelope.trace_id,
    ts: envelope.ts,
    provider: envelope.provider,
    endpoint: envelope.endpoint,
    latency_ms: envelope.latency_ms,
    status: envelope.status,
  };
  if (envelope.request !== null && envelope.response !== null) {
    out["request"] = envelope.request;
    out["response"] = envelope.response;
  }
  if (envelope.norm !== null) {
    const n = envelope.norm;
    out["norm"] = {
      model: n.model,
      system: n.system,
      messages: n.messages.map((m) => ({ role: m.role, content: m.content })),
      response: n.response,
      tool_calls: [...n.tool_calls],
      prompt_tokens: n.prompt_tokens,
      completion_tokens: n.completion_tokens,
      cached_prompt_tokens: n.cached_prompt_tokens,
      has_media: n.has_media,
    };
    out["norm_v"] = envelope.norm_v;
  }
  // JSON.stringify would turn NaN into null and escape (not reject) a lone surrogate, so walk first.
  checkJson(out);
  let text: string;
  try {
    text = JSON.stringify(out);
  } catch {
    throw new EnvelopeError("envelope cannot be encoded as JSON");
  }
  if (byteLength(text) > MAX_LINE_BYTES) {
    throw new EnvelopeError(`line exceeds ${MAX_LINE_BYTES} bytes`);
  }
  return text;
}
