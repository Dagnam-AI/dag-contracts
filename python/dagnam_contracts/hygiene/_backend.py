"""Which implementation the hygiene seams run on: the compiled core or this package's Python.

The core is a dependency of this package, so it is normally installed; it is used when
every one of these holds, and the Python in this package runs otherwise, without a message:

* ``DAGNAM_CONTRACTS_PURE`` is off. That variable is read once, when this module is first
  imported: unset, empty, ``0``, ``false``, ``no`` and ``off`` (any case) leave the core on;
  any other value switches it off, and the core is then not even imported.
* ``import`` succeeds. On a platform or interpreter with no native wheel (free-threaded 3.13,
  PyPy, Windows on arm64, ...) `dagnam-core` installs a stub whose ``hygiene`` raises
  ``ImportError``. That is the only exception caught: any other is a defect to see.
* ``CORE_API`` is the contract this release was written against, and ``UNICODE_SUPPORTED``
  is true (the core has character tables for the interpreter's Unicode version; it follows
  the interpreter's own, so the two read the same characters).
* It exports the three functions the seams call and a ``NearDedupLimitError`` (a ``ValueError`` subclass, as this package's is), and its
  five limits are this package's (`_limits`): a core that stops a batch somewhere else
  would answer differently from the reference.
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from contextvars import ContextVar
import os
from typing import Any, Literal

from dagnam_contracts.hygiene import _limits

CORE_API = 2
"""The binding contract this release was written against."""

_FUNCTIONS = ("findings", "minhash_signature", "near_duplicates")
_LIMITS = ("MAX_TEXTS", "MAX_TEXT_CHARS", "MAX_TOTAL_CHARS", "MAX_COMPARISONS", "MAX_PAIRS")
_OFF = frozenset({"", "0", "false", "no", "off"})


def _is_value_error_class(value: object) -> bool:
    return isinstance(value, type) and issubclass(value, ValueError)


def _usable(core: Any) -> bool:
    return (
        core is not None
        and getattr(core, "CORE_API", None) == CORE_API
        and getattr(core, "UNICODE_SUPPORTED", None) is True
        and all(callable(getattr(core, name, None)) for name in _FUNCTIONS)
        and _is_value_error_class(getattr(core, "NearDedupLimitError", None))
        and all(getattr(core, name, None) == getattr(_limits, name) for name in _LIMITS)
    )


_core: Any = None
# The one optional import in the package: on a platform with no native wheel the core is a
# stub whose `hygiene` fails to import, and the Python below is the reference that runs there.
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
    itself is checked against. Scoped to the current context: asyncio tasks, and threads on
    builds where a thread inherits its starter's context (the free-threaded ones, by
    default), started inside the block run on the Python too; other threads keep their own
    backend.
    """
    token = _REFERENCE.set(True)
    try:
        yield
    finally:
        _REFERENCE.reset(token)


def backend() -> Literal["rust", "python"]:
    """Which implementation is active in this process."""
    return "python" if active() is None else "rust"
