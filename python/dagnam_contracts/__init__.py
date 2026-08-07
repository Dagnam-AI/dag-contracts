"""The canonical Dagnam.AI component/parameter validation contract.

Ships the generated ``component-schema.json`` plus a **pydantic-free**
interpreter of it. The dependency-free constraint is load-bearing, not
incidental: the ``dagnam`` SDK deliberately carries only ``requests`` and
``numpy``, so anything it depends on must stay light.

The Pydantic ``ComponentSpec`` registry that *produces* this schema lives in
``registry/`` and is an AUTHORING format — it is never packaged, which is what
lets this distribution have no runtime dependencies at all.

Public API mirrors what the SDK previously exposed from ``dagnam._contracts``,
so a consumer switching to this package changes its import path and nothing else.
"""

from __future__ import annotations

from dagnam_contracts.architecture import validate_architecture
from dagnam_contracts.interpret import ParamError, validate_params
from dagnam_contracts.normalize import (
    normalize_architecture_config,
    normalize_diagram_state,
)
from dagnam_contracts.schema import (
    COMPONENT_REGISTRY,
    LAYER_TYPE_TO_COMPONENT,
    SCHEMA_VERSION,
)

__all__ = [
    "COMPONENT_REGISTRY",
    "LAYER_TYPE_TO_COMPONENT",
    "SCHEMA_VERSION",
    "ParamError",
    "normalize_architecture_config",
    "normalize_diagram_state",
    "validate_architecture",
    "validate_params",
]
