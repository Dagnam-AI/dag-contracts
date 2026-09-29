/**
 * The PII classes the tarball names (mirrors `src/pii.ts`).
 *
 * The Python side's `tests/hygiene/test_pii.py` holds this list equal to the
 * wheel's `PII_CODES`, in order; this pins what a TypeScript consumer imports.
 */

import { describe, expect, it } from "vitest";

import { PII_CODES, type PiiCode } from "../src/index.js";

describe("PII classes", () => {
  it("names every class the scan reports, the secret class included", () => {
    const secret: PiiCode = "PII_SECRET";
    expect(PII_CODES).toEqual([
      "PII_EMAIL",
      "PII_PHONE",
      "PII_PAYMENT_CARD",
      "PII_NATIONAL_ID",
      secret,
      "PII_IBAN",
      "PII_IP_ADDRESS",
      "PII_DATE_OF_BIRTH",
      "PII_UK_NINO",
      "PII_CA_SIN",
      "PII_IN_AADHAAR",
      "PII_IN_PAN",
      "PII_EU_VAT",
    ]);
  });
});
