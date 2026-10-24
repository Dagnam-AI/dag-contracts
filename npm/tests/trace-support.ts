/** Shared helpers for the trace envelope tests (not a test file itself). */

import { readFileSync } from "node:fs";

import { expect } from "vitest";

import { EnvelopeError, UnsupportedEnvelopeVersion, parseEnvelope } from "../src/index.js";

export interface Case {
  name: string;
  line: Record<string, unknown>;
  ok: boolean;
  error: string | null;
  expect?: unknown;
  python_only?: boolean;
}

export const CASES = JSON.parse(
  readFileSync(new URL("../../tests/fixtures/trace_envelope_cases.json", import.meta.url), "utf-8"),
) as Case[];
export const FIRST = CASES[0]!.line as Record<string, any>;
export const BAD_TEXT = "\ud800";
export const ERRORS: Record<string, typeof EnvelopeError> = {
  EnvelopeError,
  UnsupportedEnvelopeVersion,
};

// JSON.stringify writes -0 as 0; the fixture's -0.0 must reach the parser as the text -0.
export const compact = (line: unknown): string =>
  JSON.stringify(line, (_key, value: unknown) => (Object.is(value, -0) ? "__NEG0__" : value)).replaceAll(
    '"__NEG0__"',
    "-0",
  );

/** The error class of a failing parse, or null when it parses. */
export function failure(line: string | object): Error | null {
  try {
    parseEnvelope(line);
  } catch (error) {
    return error as Error;
  }
  return null;
}

export function expectRejected(line: string | object, match?: string | RegExp): void {
  const error = failure(line);
  expect(error).toBeInstanceOf(EnvelopeError);
  expect(error).not.toBeInstanceOf(UnsupportedEnvelopeVersion);
  if (match !== undefined) expect((error as Error).message).toMatch(match);
}
