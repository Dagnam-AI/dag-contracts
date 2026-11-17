"""Tests for `dagnam_contracts/hygiene/_backend.py` and the seams that dispatch on it.

A fake core stands in for `dagnam_core.hygiene`, so every dispatch branch runs on both
backends (the normal run and `DAGNAM_CONTRACTS_PURE=1`), whether or not the real core is
installed.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
from decimal import Decimal
from fractions import Fraction
import importlib
import os
import sys
import threading
import types
from typing import Any, cast

import pytest

from dagnam_contracts.hygiene import _backend, backend
from dagnam_contracts.hygiene.near_dedup import (
    NUM_PERMUTATIONS,
    NearDedupResult,
    NearDuplicatePair,
    compute_near_duplicates,
    minhash_signature,
)
from dagnam_contracts.hygiene.spans import findings

_SURROGATE = "a\udc80 x@y.co"


@pytest.fixture(autouse=True)
def _real_environment() -> Iterator[None]:
    """Reload `_backend` once the test (and its monkeypatching) is over, so no later test
    sees a fake. Requests no other fixture: it must be torn down after `monkeypatch`."""
    yield
    importlib.reload(_backend)


def _reload(
    monkeypatch: pytest.MonkeyPatch, core: types.ModuleType | None, pure: str | None
) -> types.ModuleType:
    # `None` in `sys.modules` makes `import dagnam_core` raise ImportError: "not installed".
    monkeypatch.setitem(sys.modules, "dagnam_core", cast("types.ModuleType", core))
    if pure is None:
        monkeypatch.delenv("DAGNAM_CONTRACTS_PURE", raising=False)
    else:
        monkeypatch.setenv("DAGNAM_CONTRACTS_PURE", pure)
    return importlib.reload(_backend)


def _fake(api: int, **replace: Any) -> types.ModuleType:
    """A `dagnam_core` whose `hygiene` has the contract's number and its three functions."""
    core = types.ModuleType("dagnam_core")
    functions = {name: lambda *_: None for name in _backend._FUNCTIONS}
    vars(core)["hygiene"] = types.SimpleNamespace(CORE_API=api, **{**functions, **replace})
    return core


def _use(monkeypatch: pytest.MonkeyPatch, **functions: Any) -> None:
    core = types.SimpleNamespace(**functions)
    monkeypatch.setattr(_backend, "active", lambda: core)


def _use_python(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_backend, "active", lambda: None)


def _refuse(*_: object) -> Any:
    raise UnicodeEncodeError("utf-8", "", 0, 1, "surrogates not allowed")


def test_python_is_used_when_the_core_is_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _reload(monkeypatch, None, None).active() is None


@pytest.mark.parametrize("value", ["1", "yes", "true", "TRUE", "on", "anything"])
def test_python_is_used_when_the_variable_is_on(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    assert _reload(monkeypatch, _fake(1), value).active() is None


@pytest.mark.parametrize("value", ["", "0", "false", "False", "no", "OFF", " 0 "])
def test_the_core_is_used_when_the_variable_is_off(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    assert _reload(monkeypatch, _fake(1), value).backend() == "rust"


def test_a_core_without_the_functions_is_not_used(monkeypatch: pytest.MonkeyPatch) -> None:
    bare = types.ModuleType("dagnam_core")
    vars(bare)["hygiene"] = types.SimpleNamespace(CORE_API=1)
    assert _reload(monkeypatch, bare, None).active() is None
    for name in _backend._FUNCTIONS:
        assert _reload(monkeypatch, _fake(1, **{name: None}), None).active() is None


def test_the_running_suite_is_on_the_backend_its_variable_asks_for() -> None:
    off = {"", "0", "false", "no", "off"}
    pure = os.environ.get("DAGNAM_CONTRACTS_PURE", "").strip().lower() not in off
    assert backend() == ("python" if pure else "rust")


def test_a_core_with_another_api_number_is_not_used(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _reload(monkeypatch, _fake(2), None).active() is None


def test_the_core_is_used_when_it_matches(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _reload(monkeypatch, _fake(1), None)
    assert module.active() is not None and module.backend() == "rust"


def test_backend_names_the_active_one(monkeypatch: pytest.MonkeyPatch) -> None:
    assert backend() in ("rust", "python")
    _use_python(monkeypatch)
    assert backend() == "python"
    _use(monkeypatch)
    assert backend() == "rust"


def test_findings_reads_a_lone_surrogate_in_python(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def refuse(text: str) -> list[tuple[int, int, str]]:
        calls.append(text)
        return _refuse()

    _use(monkeypatch, findings=refuse)
    assert findings(_SURROGATE)[0][2].code == "PII_EMAIL"
    assert calls == [_SURROGATE]


def test_findings_maps_the_cores_codes_to_detectors(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def core_findings(text: str) -> list[tuple[int, int, str]]:
        calls.append(text)
        return [(0, 1, "PII_PHONE")]  # not what the Python finds in this text

    _use(monkeypatch, findings=core_findings)
    assert [(s, e, d.code) for s, e, d in findings("x@y.co")] == [(0, 1, "PII_PHONE")]
    assert calls == ["x@y.co"]


def test_findings_runs_the_python_when_the_core_reports_a_code_it_does_not_know(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def core_findings(text: str) -> list[tuple[int, int, str]]:
        calls.append(text)
        return [(0, 6, "PII_EMAIL"), (0, 1, "PII_OF_A_LATER_VERSION")]

    _use(monkeypatch, findings=core_findings)
    assert [(s, e, d.code) for s, e, d in findings("x@y.co")] == [(0, 6, "PII_EMAIL")]
    assert calls == ["x@y.co"]


def test_findings_with_stats_measures_the_python_algorithm(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def core_findings(text: str) -> list[tuple[int, int, str]]:
        calls.append(text)
        return []

    _use(monkeypatch, findings=core_findings)
    stats: Counter[str] = Counter()
    assert findings("x@y.co", stats)[0][2].code == "PII_EMAIL"
    assert stats["full reads"] == 1
    assert calls == []


def test_minhash_signature_comes_from_the_core(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[list[str]] = []

    def signature(shingles: list[str]) -> tuple[int, ...]:
        seen.append(shingles)
        return tuple(range(NUM_PERMUTATIONS))

    _use(monkeypatch, minhash_signature=signature)
    assert minhash_signature(frozenset({"a b c"})) == tuple(range(NUM_PERMUTATIONS))
    assert seen == [["a b c"]]


def test_minhash_signature_of_a_lone_surrogate_fails_as_the_reference_does(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The reference hashes UTF-8, so a lone surrogate is an error there; the core's refusal
    # hands it to that same code, and the caller sees the same exception on either backend.
    shingles = frozenset({"a\udc80 b c"})
    _use_python(monkeypatch)
    with pytest.raises(UnicodeEncodeError):
        minhash_signature(shingles)
    _use(monkeypatch, minhash_signature=_refuse)
    with pytest.raises(UnicodeEncodeError):
        minhash_signature(shingles)


def test_compute_near_duplicates_comes_from_the_core(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[list[str], float]] = []

    def near_duplicates(
        texts: list[str], threshold: float
    ) -> tuple[list[int], list[tuple[int, int, float]]]:
        seen.append((texts, threshold))
        return [1], [(0, 1, 0.95)]

    _use(monkeypatch, near_duplicates=near_duplicates)
    rows = [{"t": "Hello, World!"}, {"t": "hello world"}, {"t": "other"}]
    assert compute_near_duplicates(rows, 0.5) == NearDedupResult(
        threshold=0.5,
        kept_count=2,
        duplicate_count=1,
        duplicate_indices=[1],
        pairs=[NearDuplicatePair(0, 1, 0.95)],
    )
    assert seen == [(["hello world", "hello world", "other"], 0.5)]


def test_compute_near_duplicates_never_hands_the_core_a_lone_surrogate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[list[str]] = []

    def near_duplicates(texts: list[str], threshold: float) -> tuple[list[int], list[Any]]:
        seen.append(texts)
        return [], []

    _use(monkeypatch, near_duplicates=near_duplicates)
    compute_near_duplicates([{"t": "one two\udc80 three"}])
    assert seen == [["one two three"]]


def test_compute_near_duplicates_checks_the_threshold_before_the_core(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use(monkeypatch, near_duplicates=_refuse)
    with pytest.raises(ValueError, match="threshold must be in"):
        compute_near_duplicates([{"t": "x"}], 0)


class _Float(float):
    pass


@pytest.mark.parametrize(
    "threshold", [True, Decimal("0.5"), Fraction(1, 2), _Float(0.5)], ids=lambda t: type(t).__name__
)
def test_a_threshold_that_is_not_a_float_or_an_int_runs_the_python(
    monkeypatch: pytest.MonkeyPatch, threshold: float
) -> None:
    calls: list[object] = []

    def near_duplicates(texts: list[str], value: float) -> tuple[list[int], list[Any]]:
        calls.append(value)
        return [], []

    # The signatures are exact integers, so they may still come from the core (here: refused).
    _use(monkeypatch, near_duplicates=near_duplicates, minhash_signature=_refuse)
    rows = [{"t": "alpha beta gamma"}, {"t": "alpha beta gamma"}]
    result = compute_near_duplicates(rows, threshold)
    assert result.duplicate_indices == [1] and result.threshold == threshold
    assert calls == []


@pytest.mark.parametrize("threshold", [1, 0.5], ids=lambda t: type(t).__name__)
def test_a_float_or_an_int_threshold_goes_to_the_core(
    monkeypatch: pytest.MonkeyPatch, threshold: float
) -> None:
    calls: list[object] = []

    def near_duplicates(texts: list[str], value: float) -> tuple[list[int], list[Any]]:
        calls.append(value)
        return [], []

    _use(monkeypatch, near_duplicates=near_duplicates)
    compute_near_duplicates([{"t": "a"}], threshold)
    assert calls == [threshold]


def test_reference_runs_the_python_in_its_block_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_backend, "_ACTIVE", types.SimpleNamespace())
    assert backend() == "rust"
    with _backend.reference():
        assert backend() == "python" and _backend.active() is None
    assert backend() == "rust"


def test_reference_does_not_reach_another_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_backend, "_ACTIVE", types.SimpleNamespace())
    seen: list[str] = []
    with _backend.reference():
        thread = threading.Thread(target=lambda: seen.append(backend()))
        thread.start()
        thread.join()
        assert backend() == "python"
    assert seen == ["rust"]
