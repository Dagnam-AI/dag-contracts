"""Tests for `dagnam_contracts/hygiene/_backend.py` and the seams that dispatch on it.

A fake core stands in for `dagnam_core.hygiene`, so every dispatch branch runs on both
backends (the normal run and `DAGNAM_CONTRACTS_PURE=1`), whether or not the real core is
installed.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
import contextvars
from decimal import Decimal
from fractions import Fraction
import importlib
import os
import sys
import threading
import types
from typing import Any, cast

import pytest

from dagnam_contracts.hygiene import _backend, _limits, backend, near_dedup
from dagnam_contracts.hygiene.near_dedup import (
    MAX_PAIRS,
    NUM_PERMUTATIONS,
    NearDedupLimitError,
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


class _CoreLimitError(ValueError):
    """The core's own `NearDedupLimitError`: a class of its own, as the compiled one is."""


_LIMITS = ("MAX_TEXTS", "MAX_TEXT_CHARS", "MAX_TOTAL_CHARS", "MAX_COMPARISONS", "MAX_PAIRS")


def _fake(api: int = 2, replace: dict[str, Any] | None = None) -> types.ModuleType:
    """A `dagnam_core` whose `hygiene` is what `_backend` requires: the contract's number, the
    three functions, the tables, the exception and this package's five limits."""
    core = types.ModuleType("dagnam_core")
    attributes: dict[str, Any] = {name: lambda *_: None for name in _backend._FUNCTIONS}
    attributes.update({name: getattr(_limits, name) for name in _LIMITS})
    attributes.update(UNICODE_SUPPORTED=True, NearDedupLimitError=_CoreLimitError)
    vars(core)["hygiene"] = types.SimpleNamespace(CORE_API=api, **{**attributes, **(replace or {})})
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
    assert _reload(monkeypatch, _fake(), value).active() is None


@pytest.mark.parametrize("value", ["", "0", "false", "False", "no", "OFF", " 0 "])
def test_the_core_is_used_when_the_variable_is_off(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    assert _reload(monkeypatch, _fake(), value).backend() == "rust"


def test_a_core_without_the_functions_is_not_used(monkeypatch: pytest.MonkeyPatch) -> None:
    bare = types.ModuleType("dagnam_core")
    vars(bare)["hygiene"] = types.SimpleNamespace(CORE_API=_backend.CORE_API)
    assert _reload(monkeypatch, bare, None).active() is None
    for name in _backend._FUNCTIONS:
        assert _reload(monkeypatch, _fake(replace={name: None}), None).active() is None


def test_the_stub_is_not_used_and_is_not_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    # The core's stub wheel installs on a platform with no native wheel, and importing its
    # `hygiene` raises ImportError (here: the submodule cannot be imported).
    stub = types.ModuleType("dagnam_core")
    monkeypatch.setitem(sys.modules, "dagnam_core.hygiene", cast("types.ModuleType", None))
    module = _reload(monkeypatch, stub, None)
    assert module.active() is None and module.backend() == "python"


def test_an_error_other_than_import_error_is_not_swallowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Broken(types.ModuleType):
        def __getattr__(self, name: str) -> Any:
            raise RuntimeError("a broken core")

    with pytest.raises(RuntimeError, match="a broken core"):
        _reload(monkeypatch, Broken("dagnam_core"), None)


def test_a_core_without_tables_for_this_interpreter_is_not_used(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _reload(monkeypatch, _fake(replace={"UNICODE_SUPPORTED": False}), None)
    assert module.active() is None and module.backend() == "python"
    assert _reload(monkeypatch, _fake(replace={"UNICODE_SUPPORTED": None}), None).active() is None


@pytest.mark.parametrize("error", [None, RuntimeError, "NearDedupLimitError", object()])
def test_a_core_without_a_limit_exception_class_is_not_used(
    monkeypatch: pytest.MonkeyPatch, error: Any
) -> None:
    assert (
        _reload(monkeypatch, _fake(replace={"NearDedupLimitError": error}), None).active() is None
    )


@pytest.mark.parametrize("name", _LIMITS)
def test_a_core_with_another_limit_is_not_used(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    assert (
        _reload(monkeypatch, _fake(replace={name: getattr(_limits, name) + 1}), None).active()
        is None
    )
    assert _reload(monkeypatch, _fake(replace={name: None}), None).active() is None
    assert _reload(monkeypatch, _fake(), None).active() is not None


def test_the_running_suite_is_on_the_backend_its_variable_asks_for() -> None:
    off = {"", "0", "false", "no", "off"}
    pure = os.environ.get("DAGNAM_CONTRACTS_PURE", "").strip().lower() not in off
    assert backend() == ("python" if pure else "rust")


@pytest.mark.parametrize("api", [1, 3])
def test_a_core_with_another_api_number_is_not_used(
    monkeypatch: pytest.MonkeyPatch, api: int
) -> None:
    assert _reload(monkeypatch, _fake(api), None).active() is None


def test_the_core_is_used_when_it_matches(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _reload(monkeypatch, _fake(), None)
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


def test_the_cores_limit_error_is_this_packages_with_the_same_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def near_duplicates(texts: list[str], threshold: float) -> Any:
        raise _CoreLimitError("more than MAX_PAIRS (20000000) near-duplicate pairs")

    _use(monkeypatch, near_duplicates=near_duplicates, NearDedupLimitError=_CoreLimitError)
    with pytest.raises(NearDedupLimitError) as raised:
        compute_near_duplicates([{"t": "a b c"}] * 2)
    assert type(raised.value) is NearDedupLimitError
    assert str(raised.value) == "more than MAX_PAIRS (20000000) near-duplicate pairs"


def test_the_real_cores_limit_error_is_this_packages_with_the_same_words(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Against the actual binary, on whichever backend the suite runs. A batch over the pair
    limit is refused by the core's counting walk before anything is allocated (about 0.6 s and
    37 MB), so the limit path needs no 1.5 GB result."""
    core = pytest.importorskip("dagnam_core.hygiene")
    if not _backend._usable(core):
        pytest.skip("the installed core is not one this release uses (e.g. no tables)")
    with pytest.raises(NearDedupLimitError) as python:
        near_dedup._check_pairs(MAX_PAIRS + 1)

    monkeypatch.setattr(_backend, "active", lambda: core)
    with pytest.raises(NearDedupLimitError) as compiled:
        # n identical rows have n * (n - 1) / 2 pairs: 6,326 of them have 20,004,475.
        compute_near_duplicates([{"t": "a b c"}] * 6326)
    assert type(compiled.value) is NearDedupLimitError
    assert str(compiled.value) == str(python.value)


def test_an_error_of_the_core_that_is_not_its_limit_is_not_turned_into_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def near_duplicates(texts: list[str], threshold: float) -> Any:
        raise RuntimeError("something else")

    _use(monkeypatch, near_duplicates=near_duplicates, NearDedupLimitError=_CoreLimitError)
    with pytest.raises(RuntimeError, match="something else"):
        compute_near_duplicates([{"t": "a"}])


def test_the_pairs_are_built_from_the_cores_tuples_one_at_a_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The result replaces the core's tuples in the list the core returned, so the two never
    exist side by side (see the module docstring of `near_dedup`): same list object out, with
    the pairs the tuples described, the one float object per similarity the core shares kept."""
    similarity = 0.75
    found: list[Any] = [(0, 1, similarity), (0, 2, similarity), (1, 2, 0.5)]
    handed = found

    _use(monkeypatch, near_duplicates=lambda texts, threshold: ([1, 2], found))
    result = compute_near_duplicates([{"t": "a"}] * 3, 0.5)
    assert result.pairs is handed
    assert result.pairs == [
        NearDuplicatePair(0, 1, 0.75),
        NearDuplicatePair(0, 2, 0.75),
        NearDuplicatePair(1, 2, 0.5),
    ]
    assert all(type(pair) is NearDuplicatePair for pair in result.pairs)
    assert result.pairs[0].similarity is result.pairs[1].similarity
    assert result.duplicate_indices == [1, 2] and result.kept_count == 1


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
        # A fresh context: where a thread inherits its starter's context (free-threaded
        # builds, by default) the block would otherwise reach it, as documented.
        fresh = contextvars.Context()
        thread = threading.Thread(target=lambda: fresh.run(lambda: seen.append(backend())))
        thread.start()
        thread.join()
        assert backend() == "python"
    assert seen == ["rust"]
