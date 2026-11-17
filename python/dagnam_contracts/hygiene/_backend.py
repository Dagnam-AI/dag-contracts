"""Which implementation the hygiene seams run on: the compiled core or this package's Python."""

from __future__ import annotations

import os
from typing import Any, Literal

CORE_API = 1
"""The binding contract this release was written against."""

_core: Any
# The one optional import in the package: the compiled core has no wheel on some
# platforms, and the Python below is the reference that runs there.
try:
    from dagnam_core import hygiene as _core
except ImportError:
    _core = None

_ACTIVE: Any = (
    _core
    if _core is not None
    and getattr(_core, "CORE_API", None) == CORE_API
    and not os.environ.get("DAGNAM_CONTRACTS_PURE")
    else None
)


def active() -> Any:
    """The compiled hygiene module, or ``None`` when the Python code runs."""
    return _ACTIVE


def backend() -> Literal["rust", "python"]:
    """Which implementation is active in this process."""
    return "python" if active() is None else "rust"
