# dagnam-contracts

The canonical component/parameter validation contract for [Dagnam.AI](https://dagnam.ai)
— the generated component schema plus a **dependency-free** interpreter of it.

An architecture is validated in three places: the platform backend when a project
is saved, the `dagnam` SDK before a job is submitted, and the Studio as nodes are
dragged onto the canvas. All three must reach identical verdicts — a parameter
the Studio accepts and the backend rejects is a bug the user experiences as the
product lying to them. This package is the one definition they all read.

```python
import dagnam_contracts as contracts

errors = contracts.validate_params(
    "convolution-layer", {"filters": -999}, node_id="conv_1"
)
for e in errors:
    print(e.message)
# convolution-layer: filters must be at least 1, got -999
# convolution-layer: missing required parameter 'kernelSize'
```

## Zero dependencies, by design

This package installs nothing else. That is a constraint rather than a
coincidence: the `dagnam` SDK ships with only `requests` and `numpy`, so a
contract package it depends on must add nothing.

It is why the Pydantic registry that *authors* the schema stays out of the
distribution — the wheel carries generated JSON and a plain-Python interpreter of
it, and the typed authoring format lives in the repository instead.

## Dataset hygiene and prompt rendering

Since 0.2.0 the Python package also ships the dataset-hygiene primitives the
platform and the `dagnam` SDK share — so a redaction, a dedup pass or a
contamination check reaches the same verdict wherever it runs — and the one
function that renders a chat request as classifier input text, so the text a
classifier saw in training is byte-for-byte the text it sees when served.
Results are frozen dataclasses; everything is standard library only.

```python
from dagnam_contracts import (
    apply_pii_policy, compute_exact_duplicates, compute_near_duplicates,
    compute_split_overlap, parse_chat_prompt, redact_rows, render_chat_prompt, scan_rows,
)

report = scan_rows(rows)                      # counts_by_code, issues, pass_list, disclaimer
rows, changed, removed = apply_pii_policy(rows, {"PII_EMAIL": "redact"})
redacted, counts = redact_rows(rows)           # every class, scan-clean by construction
compute_exact_duplicates(rows).duplicate_indices
compute_near_duplicates(rows, threshold=0.9).pairs
compute_split_overlap({"train": train_rows, "test": test_rows}).has_contamination
render_chat_prompt([{"role": "user", "content": "hi"}], system="Label it.")
# '<|system|>\nLabel it.\n<|user|>\nhi\n'
parse_chat_prompt("<|user|>\nhi\n")     # the inverse, for replaying a holdout
# [{'role': 'user', 'content': 'hi'}]
```

The PII scan is best-effort by contract: its result names the classes it looked
for (`pass_list`) and carries a disclaimer, and nothing here ever reports data
as "clean". These modules are Python-only: `@dagnam/contracts` (npm) carries the
schema interpreter plus, since 0.3.1, the audit's reference rows and serving rate
card, and since 0.4.0 the PII class names — the data a Studio displays, never the
logic that computes a verdict.

Since 0.4.0 the scan also finds credentials in the formats it knows
(`PII_SECRET`: provider keys, JWTs, PEM private keys, `Bearer` tokens,
`password=`-style assignments, the value of a JSON key named like a credential
and, since 0.4.1, a password in a URL or after `pwd=`), redacted as `<SECRET>`.
A credential in no known format (a bare AWS secret key, a passphrase in prose)
is not found. Redaction keeps JSON valid: a JSON object or array inside a row,
or the text handed to `redact_json_text`, is read and redacted value by value.
Since 0.4.1 a member of the row itself under a credential column name
(`password`, `client_secret`, `api_key`, `db_password`, ...) is found too, a
string or a number, and every scalar in a list or object under it. A flag
column (`has_password`, `is_secret`, `top_secret`) and a blank or flag-like
value (`yes`, `no`, `true`, `n/a`, `none`, `-`) are not secrets. A name an id
column also carries (`row_key`, `nextPageToken`) decides nothing there, a bare
number in a row is not scanned, and a row's keys are left as they are. A URL's
password is replaced as a secret; with a dotted host the host goes with it
(`ftp://anonymous:pw@ftp.example.com/` becomes `ftp://anonymous:<SECRET>/`),
because the email pattern reads `pw@ftp.example.com` as an address and the two
overlap.
A placeholder is an opaque token, and a finding is decided on the text between
placeholders, read as a string of its own. So rows redacted for every class
scan clean by construction, for every row shape and any number of findings, with
no exception: `scan_rows` of the result finds nothing, redacting it again returns
it, and the count for the original is the number of placeholders written (in a
document, two keys that redact to one placeholder collide and one member takes the
other's place; and in one that parses only once its redaction has replaced something,
a member taken whole removes the placeholders of findings in its value that the scan
counted).
`redact_rows(rows)` is that redact-everything policy in one call, returning the
rows and the counts; call it last, on the row exactly as it will be uploaded
(after any cut to a length), because a cut after redaction can split a
placeholder into text a scan reads. A policy that redacts only some classes
replaces exactly the findings the scan reports for them and promises nothing more
about a later scan of the row.
0.4.0 also finds IBANs, IP addresses, dates of birth (beside a birth keyword),
UK NINOs, Canadian SINs, Indian Aadhaar and PAN numbers and EU VAT numbers,
each checksum-, parser-, format- or keyword-backed and under its own code.

## Versioning

`dagnam-contracts` and `@dagnam/contracts` (npm) are published together at the
same version and carry a byte-identical schema, so a version number describes one
contract across both ecosystems. Breaking schema changes take a major bump, and
each consumer upgrades deliberately.

## License

Apache-2.0. Source: https://github.com/Dagnam-AI/dag-contracts
