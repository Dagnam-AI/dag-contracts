/**
 * The PII finding classes the contract's scan reports, in its order.
 *
 * The detectors stay Python-only — a browser never scans a dataset. What a
 * TypeScript consumer does is *display* their results (`counts_by_code`,
 * `pass_list`, a redacted row), and typing its label map against `PiiCode`
 * turns a class added to the contract into a compile error in the Studio
 * instead of a raw code on screen. `tests/hygiene/test_pii.py` on the Python
 * side holds this list equal to the wheel's `PII_CODES`.
 *
 * A redacted `PII_SECRET` reads `<SECRET>`; every other class reads
 * `[REDACTED:<code>]`.
 */
export const PII_CODES = [
  "PII_EMAIL",
  "PII_PHONE",
  "PII_PAYMENT_CARD",
  "PII_NATIONAL_ID",
  "PII_SECRET",
  "PII_IBAN",
  "PII_IP_ADDRESS",
  "PII_DATE_OF_BIRTH",
  "PII_UK_NINO",
  "PII_CA_SIN",
  "PII_IN_AADHAAR",
  "PII_IN_PAN",
  "PII_EU_VAT",
] as const;

/** One PII finding class. */
export type PiiCode = (typeof PII_CODES)[number];
