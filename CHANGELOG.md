# Changelog

All notable changes to `dagnam-contracts` (PyPI) and `@dagnam/contracts` (npm)
are documented in this file. The two packages are released together, at one
version, from one tag.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/). Releases
before 0.4.0 are described in `README.md`.

## [0.4.0] - 2026-09-29

### Added

- **`PII_SECRET`, a PII class for credentials.** Provider keys by prefix and
  shape (OpenAI and Anthropic `sk-`, Stripe live keys, AWS key ids, GitHub,
  Slack, Google, Hugging Face, GitLab), JWTs, PEM private-key blocks, the token
  of `Bearer <token>`, the base64 of a `Basic` header when it decodes to
  `user:password`, and the value assigned to a name like a credential,
  with a `snake_`/`kebab-` prefix or camelCased. The names are of two kinds:
  - **Unambiguous** (`password`, `passwd`, `secret`, `api_key`/`apikey`,
    `access_key`, `secret_access_key`, `private_key`, `client_secret`):
    quoted on both sides (`"password": "…"`) the value is a credential
    whatever it looks like; bare (prose, YAML, INI) only when it has at
    least 6 characters with a digit, or at least 16.
  - **Ambiguous** (`token`, `authorization`, `auth`, `key`): only a value that
    is a credential on its own -- a known key shape, a JWT, `Bearer` or
    `Basic` credentials, an `sk-` key with any 20+ run (the name vouches for
    it, so no digit is needed), or a run of 16+ mixing letters and digits. So
    `{"token": "Paris"}`, `{"authorization": "approved"}` and
    `max_token=128000` stay as they are, while `{"token": "ghp_…"}` and
    `{"authorization": "Bearer eyJ…"}` are redacted.

  A bare value stops at a `:` that opens the next assignment, so in
  `token=abc:password=hunter22` each assignment is judged on its own. Bare,
  `sk-` needs a 20-character run that holds a digit or mixes upper and lower
  case, so kebab-case such as `sk-learn-compatible-estimators` is not one.
  Hex digests, UUIDs and
  ordinary words do not match. A redacted secret reads `<SECRET>`, not
  `[REDACTED:<code>]`. It is in `PII_CODES`, so every policy built from that
  tuple (the audit's redact-everything policy among them) now redacts secrets
  with no change on the caller's side.
- **Credential-named JSON members.** In a JSON object or array held in a row,
  the value of a member whose key is named like a credential is a
  `PII_SECRET` by the same two-kind rule -- whatever it looks like under an
  unambiguous name (`{"password": "a"}`, `{"apiKey": 12345}`), only when it
  looks like a credential under an ambiguous one -- and is replaced whole;
  the scan counts it too.
- **`PiiDetector.placeholder`** (what a redaction writes for that class;
  `None`, the default, keeps `REDACTION_TEMPLATE` with the code),
  **`PiiDetector.member`** (a `(key, value text) -> bool` rule that finds a
  JSON member by its key; `None` by default) and the read-only
  **`PiiDetector.replacement`**.
- **`redact_json_text(text) -> (text, findings)`** redacts every class in
  JSON text and keeps it JSON: every string, key and number is redacted in
  place, a credential-named member's value is replaced whole, a number that
  matched becomes a JSON string, and text with nothing to redact comes back
  byte for byte. Text that is not JSON, or nests too deep to walk, is
  redacted as plain text.
- **Tool-call scoring in `score_json`.** As soon as any truth is a tool call
  (an object whose keys are exactly `name` and `arguments`, or a list of
  them), the score is per row with `metric: "tool_call"`: a row scores 0
  unless the prediction calls the same tools in the same order, otherwise
  its arguments' field-F1 (1.0 when neither side has arguments). Any other
  row is scored on its own content: other JSON on its own fields, and text
  that is not JSON (an agent that sometimes just answers) by normalized exact
  match, so an exact plain-text answer scores 1. The value is the row mean, with
  the Wilson interval over the rows. A router that picked the wrong tool 7%
  of the time used to score 0.965 on free `{}` argument matches and clear
  the 0.95 floor; it now scores 0.93.
- **A second label criterion: `min_class_recall`.** `score_labels` reports
  the worst recall over the truth classes with at least `MIN_CLASS_SUPPORT`
  (5) holdout rows, `null` when none has; a label agreement block always
  carries the key. `frontier` and `winner_of` refuse a label candidate whose
  `min_class_recall` is below `MIN_CLASS_RECALL_FLOOR` (0.5), or is present
  but not a finite number. On a 1%-positive holdout, a student that always
  answers the majority scored exact 0.99 with a lower bound above the 0.97
  floor and won; its minority recall is 0, and it no longer does. JSON
  scoring is unchanged.
- **Eight more PII classes, each with its own code** (R3-08), each built on
  what makes it precise:
  - `PII_IBAN`: a registered country, its exact registry length, mod-97.
  - `PII_IP_ADDRESS`: IPv4 and IPv6 as the standard `ipaddress` parser
    accepts them, less loopback and unspecified addresses, an IPv4 network id
    (last octet 0) or one right after a version's product or keyword
    (`Chrome/120.0.0.0`, `build 3.2.1.9`; an address in a URL or path is still one), and an IPv6 candidate with fewer
    than three groups and no hex letter (a slice such as `a[1::2]`).
  - `PII_DATE_OF_BIRTH`: a date right after `DOB`, `date of birth`,
    `birth date`, `birthday` or `born (on)`; the date only.
  - `PII_UK_NINO`: the issuing letter sets and excluded prefixes.
  - `PII_CA_SIN`: Luhn, and always beside its name (`SIN`, `NAS`, `social
    insurance number`, `numéro d'assurance sociale`), grouped 3-3-3 or bare:
    a grouped 9-digit number is also French thousands or an order id.
  - `PII_IN_AADHAAR`: Verhoeff, grouped 4-4-4 or bare beside its name.
  - `PII_IN_PAN`: the holder-type fourth letter.
  - `PII_EU_VAT`: each member state's format after its prefix (format only).

  Names and street addresses stay out (they need NER). Known false positives,
  accepted: a bare four-part version such as `1.2.3.4`; any string of exactly
  a shape-only class's shape (NINO, PAN, EU VAT: `Order DE123456789`); and a
  grouped 4-4-4 number that passes Verhoeff reads as an Aadhaar where the
  phone pattern already redacted it. The registry now lives
  in `dagnam_contracts.hygiene.detectors`; every name `hygiene.pii` exported is
  still exported from it.
- **`PiiDetector.loose`.** A loose class (the phone pattern) yields a span it
  shares with a stricter one: an IP address or an Aadhaar number is reported
  and redacted under its own code, never as `PII_PHONE`.
- **npm: `MIN_CLASS_RECALL_FLOOR` and `MIN_CLASS_SUPPORT`**, held equal to
  the wheel's by a Python test, so the Studio need not hand-copy the floor.
- **npm: `PII_CODES` and the `PiiCode` union**, equal to the wheel's
  `PII_CODES` in order (a Python test enforces it), so a Studio label map can
  be typed exhaustively. All 13 classes are in it.

### Changed

- **`gpu-small-llm` is priced at the machine that serves it:** one NVIDIA
  A10G on Modal, at Modal's list price for the A10, $0.000306/s = $1.1016/h
  (https://modal.com/pricing, read 2026-09-27). The rate goes from 1.95 to
  **4.08 USD per million output tokens**, with the throughput and utilization
  assumptions unchanged. It priced a g4dn.xlarge T4 at $0.526/h, a machine the
  platform never served on, so every GPU student looked about half as dear as
  it is. The container's CPU and memory, prefill and an always-on replica are
  still not priced. Both packages' `serving-rates.json` stay byte-identical.
- **`render_chat_prompt` keeps assistant turns as context** (R1-N5). An
  assistant turn renders under `<|assistant|>`: its content, then one line of
  canonical JSON (`{"arguments": …, "name": …}`, sorted keys) per tool call,
  in the audit's shape or OpenAI's (`function` with string arguments). A tool
  result later in the prompt now has the call it answers. `messages` may carry
  `tool_calls`, a `null` content, or content as typed parts (their text,
  joined, as the serving bridge flattens them). `parse_chat_prompt` reads the turn back as
  that text, so replay re-renders the same bytes. A classifier served through
  the platform is cut to its last user turn, so only a request that ends after
  an assistant turn reaches a model trained on 0.3.x renderings differently.
- **Overlapping findings count once.** One region is one finding in
  `scan_rows`' counts, named as it is redacted.

- **`winner_of` is order-independent and never picks an unreliable
  candidate.** A candidate dict with `unreliable` truthy is skipped. Each
  candidate is held to its own `agreement.floor`, falling back to the `floor`
  argument, instead of the last candidate's floor being applied to all of
  them. A cost, lower bound or recorded floor that is not a finite number
  makes the dict no point at all. Ties on cost go to the higher agreement
  lower bound, then to `candidate_id`, `kind` and `deployment_id` ascending.
  The block carries the winning dict's own `deployment_id` and
  `candidate_id`, never those of the first dict of the same kind. A caller
  that kept one row per kind before calling it no longer needs to, and should
  pass every live row.
- **The JSON agreement interval counts rows, not fields.** `score_json`'s
  `ci95` is the Wilson interval around the micro-F1 with `n` = the scored
  rows. It was Wilson on `2tp` out of `2tp+fp+fn`, which counted each correct
  field as two independent trials and made the lower bound too optimistic. The
  point estimate is unchanged, and so is `score_labels`. A prediction nested
  too deep to parse is a miss, not a `RecursionError`.
- **The scan and the redaction read a JSON document value by value.**
  `scan_rows` and `apply_pii_policy` read a string that holds a JSON object or
  array member by member, so a redacted chat row whose assistant turn is a
  JSON truth still parses, and the counts match what the redaction replaces.
  A redacted document is re-serialised with `json.dumps` defaults. Other
  strings are read as text, as before, and a document that does not parse or
  nests too deep is read as text rather than raising.
- **Overlapping findings are replaced once, over their union.** Two findings
  over one span (an email inside a password value) used to be replaced one
  after the other at stale offsets, which corrupted the text.
- **The email detector is linear.** It had no left boundary, so a long run
  with no `@` (a base64 image in a chat message) took 18 s per 100 KB.
- `frontier` breaks a full tie (cost and lower bound) on `kind` and never
  picks a point whose cost or lower bound is not finite, so its answer no
  longer depends on the order of its points.
