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

## Dataset hygiene and prompt rendering (Python-only)

Since 0.2.0 the Python package also ships the dataset-hygiene primitives the
platform and the `dagnam` SDK share — so a redaction, a dedup pass or a
contamination check reaches the same verdict wherever it runs — and the one
function that renders a chat request as classifier input text, so the text a
classifier saw in training is byte-for-byte the text it sees when served.
Results are frozen dataclasses; everything is standard library only.

```python
from dagnam_contracts import (
    apply_pii_policy, compute_exact_duplicates, compute_near_duplicates,
    compute_split_overlap, render_chat_prompt, scan_rows,
)

report = scan_rows(rows)                      # counts_by_code, issues, pass_list, disclaimer
rows, changed, removed = apply_pii_policy(rows, {"PII_EMAIL": "redact"})
compute_exact_duplicates(rows).duplicate_indices
compute_near_duplicates(rows, threshold=0.9).pairs
compute_split_overlap({"train": train_rows, "test": test_rows}).has_contamination
render_chat_prompt([{"role": "user", "content": "hi"}], system="Label it.")
# '<|system|>\nLabel it.\n<|user|>\nhi\n'
```

The PII scan is best-effort by contract: its result names the classes it looked
for (`pass_list`) and carries a disclaimer, and nothing here ever reports data
as "clean". These modules are Python-only; `@dagnam/contracts` (npm) carries the
schema interpreter alone.

## Versioning

`dagnam-contracts` and `@dagnam/contracts` (npm) are published together at the
same version and carry a byte-identical schema, so a version number describes one
contract across both ecosystems. Breaking schema changes take a major bump, and
each consumer upgrades deliberately.

## License

Apache-2.0. Source: https://github.com/Dagnam-AI/dag-contracts
