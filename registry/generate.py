"""Compile the Pydantic ``ComponentSpec`` registry to ``component-schema.json``.

The registry is the AUTHORING format; this renders it into the two shipped
distributions:

* ``python/dagnam_contracts/component-schema.json`` (the ``dagnam-contracts`` wheel)
* ``npm/src/component-schema.json`` (the ``@dagnam/contracts`` tarball)

Both must be byte-identical — a version number that means two different
contracts in two languages is worse than no version at all.

Run::

    python -m registry.generate            # rewrite both copies
    python -m registry.generate --check    # CI: fail if either has drifted

``--check`` is what makes this repo self-contained. Without it the committed
JSON is an opaque blob nobody can reproduce from source, and the registry
beside it is decoration: editable, never compiled, silently divergent. That is
exactly the state this file was resurrected to end.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

from registry.components import COMPONENT_REGISTRY
from registry.diagnostics import DIAGNOSTICS

SCHEMA_VERSION = 3  # components carry requires_incoming_input topology

_ROOT = Path(__file__).resolve().parents[1]

TARGETS = [
    _ROOT / "python" / "dagnam_contracts" / "component-schema.json",
    _ROOT / "npm" / "src" / "component-schema.json",
]


def build_schema_payload() -> dict[str, Any]:
    """Return the JSON-serializable contract.

    Components and diagnostics are emitted in sorted key order so the rendered
    JSON is byte-stable across runs (``--check`` depends on it). ``exclude_none``
    keeps the payload tight: an optional field only appears when it is set.
    """
    components = [
        COMPONENT_REGISTRY[cid].model_dump(exclude_none=True) for cid in sorted(COMPONENT_REGISTRY)
    ]
    diagnostics = [DIAGNOSTICS[code].model_dump() for code in sorted(DIAGNOSTICS)]
    return {"version": SCHEMA_VERSION, "components": components, "diagnostics": diagnostics}


def serialize(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def drift() -> list[str]:
    """Return a description per target that is missing or stale; empty = clean."""
    text = serialize(build_schema_payload())
    return [
        f"{'missing' if not t.exists() else 'drifted'}: {t.relative_to(_ROOT)}"
        for t in TARGETS
        if not t.exists() or t.read_text(encoding="utf-8") != text
    ]


def write_all() -> list[Path]:
    text = serialize(build_schema_payload())
    for target in TARGETS:
        target.write_text(text, encoding="utf-8")
    return TARGETS


def main(argv: list[str] | None = None) -> int:
    if "--check" in (argv if argv is not None else sys.argv[1:]):
        stale = drift()
        if stale:
            print(  # noqa: T201 - CLI output
                "component-schema.json is out of date (run `python -m registry.generate`):\n  "
                + "\n  ".join(stale)
            )
            return 1
        print("OK: both shipped schemas match the registry.")  # noqa: T201 - CLI output
        return 0
    for path in write_all():
        print(f"wrote: {path.relative_to(_ROOT)}")  # noqa: T201 - CLI output
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
