"""Which implementation the hygiene seams run on: the compiled core or this package's Python.

The core is used when it is installed, its binding contract is the one this release was
written against (`CORE_API`), it exports the three functions the seams call, and
``DAGNAM_CONTRACTS_PURE`` is off. That variable is read once, when this module is first
imported: unset, empty, ``0``, ``false``, ``no`` and ``off`` (any case) leave the core on;
any other value switches it off, and the core is then not even imported.
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from contextvars import ContextVar
import os
from typing import Any, Literal

CORE_API = 1
"""The binding contract this release was written against."""

_FUNCTIONS = ("findings", "minhash_signature", "near_duplicates")
_OFF = frozenset({"", "0", "false", "no", "off"})


def _usable(core: Any) -> bool:
    return (
        core is not None
        and getattr(core, "CORE_API", None) == CORE_API
        and all(callable(getattr(core, name, None)) for name in _FUNCTIONS)
    )


_core: Any = None
# The one optional import in the package: the compiled core has no wheel on some
# platforms, and the Python below is the reference that runs there.
if os.environ.get("DAGNAM_CONTRACTS_PURE", "").strip().lower() in _OFF:
    try:
        from dagnam_core import hygiene as _core
    except ImportError:
        _core = None

_ACTIVE: Any = _core if _usable(_core) else None

_REFERENCE: ContextVar[bool] = ContextVar("dagnam_contracts_reference", default=False)


def active() -> Any:
    """The compiled hygiene module, or ``None`` when the Python code runs."""
    return None if _REFERENCE.get() else _ACTIVE


@contextmanager
def reference() -> Generator[None]:
    """Run the block on the Python reference whatever is installed.

    For code that must not depend on the core, such as the reference corpus the core
    itself is checked against. Scoped to the current thread (or task), so another thread
    keeps its own backend.
    """
    token = _REFERENCE.set(True)
    try:
        yield
    finally:
        _REFERENCE.reset(token)


def backend() -> Literal["rust", "python"]:
    """Which implementation is active in this process."""
    return "python" if active() is None else "rust"
