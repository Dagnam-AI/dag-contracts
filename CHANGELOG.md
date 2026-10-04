# Changelog

All notable changes to `dagnam-contracts` (PyPI) and `@dagnam/contracts` (npm)
are documented in this file. The two packages are released together, at one
version, from one tag.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/). Releases
before 0.4.0 are described in `README.md`.

## [0.4.1] - 2026-10-03

### Fixed

- **Rows redacted for every class scan clean, whatever they hold.** The platform
  scans again what the SDK redacted and uploaded, and stops a workload on any
  count. With 0.4.0 on both sides that happened to a row whose findings stood
  next to each other, to a document whose reading changed once a value in it was
  replaced, and to every quoted `password` member (its own `<SECRET>` counted
  again). Redaction is now built so that it cannot happen: a redaction
  placeholder is an opaque token, and a finding is decided on one run of text
  between placeholders, read as a string of its own. Text that stands beside a
  finding is read after the finding is gone, in the same call, so there is no
  second pass to make and no limit on how many findings there are. For every
  row shape and every length, with a policy that redacts every class:
  - `scan_rows` over the redacted rows finds nothing;
  - redacting a second time returns the same rows;
  - the count of a class in the scan of the original is the number of
    placeholders of that class the redaction wrote (two exceptions, both in
    documents: two keys that redact to the same placeholder collide and one member
    takes the other's place; and in a document that parses only once its redaction
    has replaced something, a member taken whole removes the placeholders of the
    findings in its value, which the scan counted, so the count can exceed the
    placeholders left).

  That holds for text of any kind, down to an address spelt with punctuation alone
  (`_@_._`) hiding behind another address, and for a member of a document whose
  key is itself a finding: `{"alice@example.com_password": "hunter2"}` has its
  value replaced as it did in 0.4.0, because the rule that takes a member whole
  reads the key as given as well as redacted.

  With 0.4.0 a list of `+` phone numbers one space or hyphen apart had only its
  first number redacted. Now such a list, 17 or 77,000 long, is found number by
  number and redacted whole. The work is linear in the text: a megabyte of the
  worst inputs measured (lists of numbers, runs of glued findings, a
  keyword followed by a megabyte of spaces) redacts in under two seconds, and four
  times the text takes about four times as long.
- **A giant token costs memory in proportion to its size, not hundreds of times it.**
  One unbroken megabyte after `password:` took 91 MB on top of the text, an
  unclosed quoted value 195 MB, an `sk-` key of hyphenated segments 71 MB and an
  address with hundreds of thousands of labels 63 MB, because a regex group that repeats
  once per character keeps a stack entry for each (eight megabytes took gigabytes).
  The values after a credential name, the prefix of an `sk-` key, the labels of an
  address's domain and the password of a URL (new in 0.4.1) are read now without a
  repeated group, and the extra memory for any of them is a few copies of the text.
  What each finds is unchanged.
- **`PII_CA_SIN` and `PII_IN_AADHAAR` are linear in a run of whitespace.**
  After `SIN`, `NAS`, `social insurance` or `aadhaar`, 32,000 spaces took
  3.2 s and four times the spaces took sixteen times as long, so one row with
  a megabyte of whitespace would have held a scan for about 50 minutes. A
  megabyte now scans in about half a second. What the two classes match is
  unchanged.
- **`PII_IN_AADHAAR` reads `Number` and `No.` in any case.** `Aadhaar Number
  987654321012` was missed: the name matched in any case, but the `number` or
  `no.` after it only in lower case.
- **A negative cost is not a point on the frontier.** `winner_of` skips a
  candidate whose `serving_cost_usd_month.value` is below zero, and `frontier`
  a point whose `cost_usd_month` is. Either used to win over every sound
  candidate, being the cheapest. A cost of exactly zero is still a price.

### Added

- **`PiiDetector.row_member`**, a `(key, value text) -> bool` rule for a member
  of the row itself, `None` by default, declared after `loose`: a
  `PiiDetector(...)` built positionally as in 0.4.0 still means what it did.
  `PII_SECRET`'s is the new `hygiene.credentials.is_credential_row_member`: a
  credential column name and a value that is not blank or flag-like.
  `PiiDetector.member` and `is_credential_member`, the rule for a JSON document,
  are unchanged.
- **`redact_rows(rows) -> (rows, counts_by_code)`**, the redact-everything policy
  over a list of rows in one call, exported from `dagnam_contracts` and
  `dagnam_contracts.hygiene`. The rows come back redacted, a row with nothing to
  redact as the same object, and `counts_by_code` covers every class (zero
  included) and is what `scan_rows` of the input reports. It is what a client
  calls last before it uploads, on the row exactly as it will be uploaded:
  after any cut to a length and any case folding, never before. A row cut after
  redaction can split a placeholder into text a scan reads, or cut into the
  context that hid a known miss (`Qty 2 4111111111111111` cut after `2 ` is a
  bare card number).
- **`dagnam_contracts.hygiene.spans`**, the segment engine under every scan and
  redaction (`segments`, `findings`, `resolve`, `redact_both`, ...), with
  **`hygiene.rows`** (the walk over rows, documents and strings that the scan, the
  drop and the redaction share) and **`hygiene.contact`** (the phone and address
  finders). Internal: none is re-exported, and `redact_rows` and `scan_rows` are the
  surface.

### Changed

- **Where 0.4.1 answers differently from 0.4.0, on purpose.** Everything 0.4.0
  found in its first pass is still found, with the same class and the same
  placeholder, except the cases below. Each follows from reading the text
  between placeholders on its own (the first four) or is a rule and a pattern
  change (the last two).
  - *A finding next to another is found in the same scan.* The second finding in
    `+44 20 7946 0958 +44 20 7946 0958` and in `password: hunter22 +1 415-555-0132`
    was hidden from its own pattern by the last digit of the first; 0.4.0
    redacted the first and left the second, and its rescan then counted it.
    `Pwd=letmein4 4111111111111111` found neither. All three now count two
    findings and are redacted whole: `[REDACTED:PII_PHONE] [REDACTED:PII_PHONE]`,
    `password: <SECRET> [REDACTED:PII_PHONE]`, `Pwd=<SECRET> [REDACTED:PII_PAYMENT_CARD]`.
    A card glued to a PEM block (`4111111111111111-----BEGIN PRIVATE KEY-----...`)
    is found with it; 0.4.0 found the block and its rescan then found the card.
  - *A placeholder is never part of a finding.* `password: <SECRET>`,
    `password: [REDACTED:PII_EMAIL]` and `{"password": "<SECRET>"}` count nothing
    (0.4.0: one secret in the last two, which stopped the workload on its own
    output). Text glued to a placeholder is read on its own, so
    `password=[REDACTED:PII_EMAIL]!x` counts nothing and is left as it is
    (0.4.0: one secret, and the placeholder swallowed into it).
  - *A policy acts on what the scan reports.* The scan and every policy resolve
    every class, and a policy then acts on its own. `{"PII_PHONE": "redact"}` on
    `password: hunter22 +1 415-555-0132` redacts the phone number (0.4.0 never
    reported it, so a phone-only policy left it); `{"PII_PHONE": "drop"}` drops
    that row. A `drop` and a `redact` class together still drop the row.
  - *A document that parses only once another finding is replaced is read as a
    document in the same call.* `{"note": "call +1 415<TAB>555 0132", "password": 1234}`
    (a raw tab inside the number) counts a phone and a secret and is redacted
    whole; 0.4.0 redacted the phone and left `"password": 1234`, which its own
    rescan then took.
  - *A URL password and the address read over it are one finding, a secret.* The
    email pattern reads `pw@ftp.example.com` as an address and the URL pattern
    reads `pw` as a password; where they overlap the region is one `PII_SECRET`,
    so `ftp://anonymous:pw@ftp.example.com/` becomes `ftp://anonymous:<SECRET>/`
    and `mysql://root:toor@10.0.0.7:3306/app` becomes `mysql://root:<SECRET>:3306/app`.
    0.4.0 redacted the same span as `PII_EMAIL` (`ftp://anonymous:[REDACTED:PII_EMAIL]/`).
    A host with no dot, or in brackets, is not an address and stays:
    `postgres://user:<SECRET>@localhost/db`. No pattern consults another class,
    so an email-only policy leaves that URL alone.
  - *A keyword class may open right after a digit.* `1987DOB: 14/03/1987`,
    `order 9SIN 130 692 544` and `id 9Aadhaar Number 580927525309` are found
    (0.4.0 required a word boundary, so a digit glued to the keyword hid it).
    `adobe` and `BASIN` are still refused: a letter before the keyword does.
- **A value under a credential name in the row itself is a `PII_SECRET`.**
  Until now only a document held in a string was read member by member; in the
  row itself only strings were scanned. `scan_rows` and `apply_pii_policy` now
  replace, whole, a string or number under a column that is `password`,
  `passwd`, `secret`, `api_key`, `access_key`, `secret_access_key`,
  `private_key` or `client_secret`, or ends in one as a word of its own
  (`db_password`, `userPassword`, `aws-secret-access-key`), in the row and in
  every object nested in it: `{"password": "correcthorse"}` becomes
  `{"password": "<SECRET>"}`, and `{"apiKey": 12345}` becomes
  `{"apiKey": "<SECRET>"}`. Three limits keep a column that is not a
  credential out of it:
  - A name that opens with `has`, `is`, `needs`, `requires`, `use`, `allow`,
    `enable`, `enabled`, `show`, `with`, `no` or `top` is a flag or a label,
    not a credential: `has_password`, `is_secret`, `top_secret`. A name where
    the credential word is not the last (`password_hint`) is not one either,
    nor is `passwords` or `mysecret`. (In a JSON document held in a string the
    0.4.0 rule stands, to the byte: `has_password` there is still a credential.)
  - A boolean, `None`, a blank string and a flag-like one (`yes`, `no`,
    `true`, `false`, `n/a`, `none`, `null`, `-`, in any case, around any
    whitespace) under such a name is not a secret. Any other non-empty value
    is, a short word included.
  - A list or an object under such a name has each scalar in it replaced by
    the same rule, at any depth: `{"password": ["hunter2", "yes"]}` becomes
    `{"password": ["<SECRET>", "yes"]}`.

  For a caller: counts rise on datasets with such a member, a number under
  such a name comes back as the string `<SECRET>`, and a policy that drops
  `PII_SECRET` now drops those rows. Nothing else about how a row is read
  changes:
  - The ambiguous names (`token`, `authorization`, `auth`, `key`, with any
    prefix) decide nothing in a row. A column named `row_key`,
    `idempotency_key` or `nextPageToken` holds ids, and an id of 16 or more
    letters and digits there is not a finding, as before. The value is still
    scanned as text, so a credential in a known format under such a name is
    found, as before. In a JSON document held in a string the 0.4.0 rule for
    these names stands.
  - A bare number in a row is still not scanned. A card number held as a
    number in a structured row (`{"card": 4111111111111111}`) is left alone:
    an id or a timestamp column would read as a card one row in ten and come
    back as a string. The same digits in a string are found as before, and so
    is a number inside a JSON document held in a string.
  - A row's keys are still not redacted, at any depth (a top-level key is a
    column name). A key of a document held in a string still is.
  - Issue messages and their order are unchanged. Keys that are not strings
    are now ordered as text, and no longer raise when their types are mixed.
- **`PII_SECRET` finds three more formats.**
  - The password of a URL, `scheme://user:password@host`, whatever the host
    (`postgres://user:...@localhost` was missed: no dot, so not even the
    email pattern touched it). The password runs to the `@` that opens the
    host, so an `@` inside it does not end it, and a raw `/`, `?` or `#` ends it.
    It may be percent-encoded, and may hold a quote, a backtick, `<` or `>` when
    a letter, digit or `%` follows. Before punctuation such a character is
    the text around the URL, not a password: `"http://host:8080","a@b.co"`
    is a port and a string, so a password where one is followed by
    punctuation is not found. Nor is one that begins like a port and a
    separator: `http://localhost:8080,john@example.com` is a port and an
    address, an email under every policy, as in 0.4.0. A URL with a port, or a
    user and no password, has none. With a dotted host the host goes with the
    password (see the deliberate differences above).
  - A connection string's `pwd=` (`Uid=sa;Pwd=...`, `?user=x&pwd=...`),
    written with no space around the `=`. A value that starts like a path or
    a variable is the shell's working directory and is left alone, and `pwd`
    is not a credential name anywhere else (`pwd: ...`, a JSON key).
  - Slack's rotating tokens: `xoxe-` refresh tokens and `xoxe.xox?-` access
    tokens, whole.
- **`PII_DISCLAIMER` says what the secret class does not find.** It now also
  reads "... and a credential in a format it does not know" and "... free of
  personal data or of secrets". The class finds the formats its docstring
  lists and nothing else. Known misses, left because no precise pattern
  exists: a bare AWS secret access key, a key broken into short hyphenated
  pieces, a passphrase in prose.

### Upgrading

Where one side redacts and the other scans again, upgrade the side that scans
first. A client on 0.4.0 against a platform on 0.4.1 is told to upgrade: the
platform counts what 0.4.0 left in a row (a finding next to another, a URL
password that 0.4.0's email pattern did not take, as when the host has no dot or
the password ends in `!` or `$` (`postgres://app:Passw0rd!@db.example.com/x`), a `pwd=`
assignment, an `xoxe-` token, a capital `Aadhaar Number`, a value under a
credential column of a structured row, a keyword after a digit, a document that
parses only after redaction, a card glued to a PEM block) and stops the
workload, and the cure is `dagnam-contracts` 0.4.1 in the client. A client on
0.4.1 against a platform on 0.4.0 stops on its redacted credentials instead:
0.4.0 counts its own `<SECRET>` as the value of a quoted credential-named member
(`"password": "<SECRET>"`, in text or in a JSON document held in a string), and
in a few shapes a bare one followed by text, so the platform upgrades first.
Every other row a 0.4.1 client redacts is clean to 0.4.0, because what 0.4.1
leaves in text is text 0.4.0 left too, including the numbers described in Known
limits under a credential key in a document that parses only after redaction,
which neither version replaces. The one exception is a short number under a
credential key in a JSON document nested more than 500 levels, which 0.4.0 could
still read as a member (on a shallow stack, to about 950 levels) and 0.4.1 does
not. With 0.4.1 on both sides, and both calling from an ordinary stack, no row stops.
`PII_CODES` is unchanged, 13 classes in the same order.

### Known limits

- Numbers run into a count are not found, by the scan, the redaction or a drop
  policy alike (as in 0.4.0): `415-555-0132 415-555-0132`, `Qty 2 4111111111111111`,
  `order 12 4111 1111 1111 1111`. Nothing is replaced, so they are stable: a scan
  of the redacted row sees what the scan of the original saw.
- A credential in no known format (a bare AWS secret access key, a passphrase in
  prose) is not found, and no result says a row holds none.
- Redacting some classes and not others replaces exactly the findings the scan
  reports for them and promises nothing more. A later scan of the partly redacted
  row can count a different number of another class that stood glued to a finding,
  or one separator away, and can still report more of a class that was redacted
  (replacing a finding can lift a guard that was refusing its neighbour). A
  document that parses only once some classes are replaced (the raw-tab example
  above) has its credential members replaced when the policy redacts the classes
  that made it parse; under a policy that does not, the scan counts the members
  and `drop` drops the row, but the text is left as it was. Redacting every class
  has no such caveat.
- Text that already holds a redaction placeholder is read in the pieces either side
  of it, so a finding whose context a placeholder interrupts is not found whole:
  a PEM block with a placeholder in its body keeps the rest of the body and its
  END line, a quoted `password` value that begins with a placeholder keeps the
  words after it, and so does a bare one. 0.4.0 replaced each of these whole. It
  takes a row that was partly redacted already; in a document or a structured row
  a credential-named member is still replaced whole.
- A phone number run into a parenthesised one by a space or a line break (`+44 20
  7946 0958 (415) 555-0132`, or two such numbers one line apart) is read with the
  parenthesis and the area code as the end of the first, leaving `) 555-0132`
  behind. 0.4.0 does the same; a list of numbers one space or hyphen apart is
  found whole, and so is a parenthesised number after one.
- An address after `host:port` and a dot or an equals sign (`http://h:8080.john@x.co`)
  is read as a URL password, since `8080.john` and `8080=john` are passwords as
  much as anything else: redacting everything removes it as a secret, and an
  email-only policy leaves it. A comma, semicolon, bar, ampersand or closing angle
  bracket after the port is not a password and the address is an email.
- A JSON document held in a string is read as one down to 500 levels of nesting
  (0.4.0 read to about the same depth from an ordinary stack); deeper is plain text, on any machine,
  where 0.4.0 read a document of about a thousand levels or not according to the
  stack the caller was already on. A caller that is itself about 480 frames deep
  gets plain text for a document of 499 levels (a shallower one is read from a
  deeper stack), as with 0.4.0, and never an error.
- In a document that parses only after its own redaction, a number under a
  credential key whose name an earlier finding hid (an address glued to
  `_password`) is left, as 0.4.0 leaves it; a string under the same key is replaced.
- `pwd=` is read as a credential wherever it is written with no space around
  the `=`, so a keyword argument in code (`zf.extractall(path, pwd=None)`,
  `run(cmd, pwd=pwd)`) is redacted, and a quoted or braced value with spaces in
  it (`Pwd="my pass phrase";`) is replaced only to its first space.
- A missing value written `nan` (a float NaN, or the string) and a mask
  (`********`, `REDACTED`) under a credential column are counted and replaced
  as secrets.

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
  tuple (the audit's redact-everything policy among them) now redacts the
  secrets it finds with no change on the caller's side.
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
- **Eight more PII classes, each with its own code**, each built on
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
- **`render_chat_prompt` keeps assistant turns as context.** An
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
