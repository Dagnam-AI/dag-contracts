"""Tests for `dagnam_contracts/hygiene/_backend.py` and the seams that dispatch on it.

A fake core stands in for `dagnam_core.hygiene`, so every dispatch branch runs on both
backends (the normal run and `DAGNAM_CONTRACTS_PURE=1`), whether or not the real core is
installed.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
import importlib
import sys
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


def _fake(api: int) -> types.ModuleType:
    core = types.ModuleType("dagnam_core")
    vars(core)["hygiene"] = types.SimpleNamespace(CORE_API=api)
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


def test_python_is_used_when_the_variable_is_set(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _reload(monkeypatch, _fake(1), "1").active() is None


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
    _use(monkeypatch, findings=lambda text: [(0, 6, "PII_EMAIL")])
    assert [(s, e, d.code) for s, e, d in findings("x@y.co")] == [(0, 6, "PII_EMAIL")]


def test_findings_with_stats_measures_the_python_algorithm(monkeypatch: pytest.MonkeyPatch) -> None:
    _use(monkeypatch, findings=_refuse)
    stats: Counter[str] = Counter()
    assert findings("x@y.co", stats)[0][2].code == "PII_EMAIL"
    assert stats["full reads"] == 1


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
