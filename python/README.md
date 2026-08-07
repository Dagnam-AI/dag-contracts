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

## Versioning

`dagnam-contracts` and `@dagnam/contracts` (npm) are published together at the
same version and carry a byte-identical schema, so a version number describes one
contract across both ecosystems. Breaking schema changes take a major bump, and
each consumer upgrades deliberately.

## License

Apache-2.0. Source: https://github.com/Dagnam-AI/dag-contracts
