"""Trace envelope v1: the cases file shared with the TypeScript mirror, plus Python-only checks."""

from __future__ import annotations

from dataclasses import asdict, replace
import json
import math
from pathlib import Path
from typing import Any, cast

import pytest

from dagnam_contracts.trace import (
    MAX_LINE_BYTES,
    EnvelopeError,
    Norm,
    TraceEnvelope,
    UnsupportedEnvelopeVersion,
    encode_envelope,
    parse_envelope,
)

CASES: list[dict[str, Any]] = json.loads(
    (Path(__file__).parents[3] / "tests" / "fixtures" / "trace_envelope_cases.json").read_text(
        encoding="utf-8"
    )
)
ERRORS = {"EnvelopeError": EnvelopeError, "UnsupportedEnvelopeVersion": UnsupportedEnvelopeVersion}
FIRST: dict[str, Any] = CASES[0]["line"]
BAD_TEXT = "\ud800"


def _compact(line: dict[str, Any]) -> str:
    return json.dumps(line, ensure_ascii=False, separators=(",", ":"))


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_shared_cases(case: dict[str, Any]) -> None:
    text = json.dumps(case["line"])
    if case["ok"]:
        env = parse_envelope(text)
        assert env.trace_id == case["line"]["trace_id"]
        # The expected parsed value is pinned in the file, so the TypeScript mirror agrees.
        assert json.loads(json.dumps(asdict(env))) == case["expect"]
        return
    with pytest.raises(ERRORS[case["error"]]) as caught:
        parse_envelope(text)
    # Subclass-exact: a plain EnvelopeError case must not be the unsupported-version error.
    assert type(caught.value) is ERRORS[case["error"]]


def test_cases_file_shape() -> None:
    names = [c["name"] for c in CASES]
    assert len(names) == len(set(names))
    assert CASES[0]["name"] == "raw_and_norm"
    for case in CASES:
        assert ("expect" in case) is case["ok"]
        assert (case["error"] is None) is case["ok"]
        if case["ok"]:
            assert case.get("python_only") is None
    # Only Python can tell 2.0 from 2 after parsing JSON; the TypeScript mirror skips these.
    assert {c["name"] for c in CASES if c.get("python_only")} == {
        "version_float_2_0",
        "version_float_1_0",
        "norm_v_float_1_0",
        "status_float_200_0",
    }


def test_round_trip_is_one_line_and_lossless() -> None:
    env = parse_envelope(FIRST)
    text = encode_envelope(env)
    assert "\n" not in text
    assert parse_envelope(text) == env


@pytest.mark.parametrize("case", [c for c in CASES if c["ok"]], ids=lambda c: c["name"])
def test_every_valid_case_round_trips(case: dict[str, Any]) -> None:
    env = parse_envelope(case["line"])
    assert parse_envelope(encode_envelope(env)) == env


def test_unicode_is_preserved_not_escaped() -> None:
    line = {**FIRST, "norm": {**FIRST["norm"], "response": "héllo 你好"}}
    assert "你好" in encode_envelope(parse_envelope(line))


def test_parse_accepts_str_bytes_bytearray_and_mapping() -> None:
    text = _compact(FIRST)
    expected = parse_envelope(FIRST)
    assert parse_envelope(text) == expected
    assert parse_envelope(text.encode("utf-8")) == expected
    assert parse_envelope(bytearray(text.encode("utf-8"))) == expected


@pytest.mark.parametrize("bad", [b"\xff\xfe{}", b'{"v":1}\xc3', "\ud800"])
def test_parse_rejects_text_that_is_not_utf_8(bad: str | bytes) -> None:
    with pytest.raises(EnvelopeError, match="UTF-8"):
        parse_envelope(bad)


@pytest.mark.parametrize("bad", [5, None, [FIRST], 1.5, ("v", 1)])
def test_parse_rejects_input_that_is_not_a_line_or_an_object(bad: object) -> None:
    with pytest.raises(EnvelopeError):
        parse_envelope(cast(Any, bad))


@pytest.mark.parametrize("bad", ["[1, 2]", "not json", "", '"x"', "null", b"{}", "{}"])
def test_parse_rejects_non_envelope_json(bad: str | bytes) -> None:
    with pytest.raises(EnvelopeError):
        parse_envelope(bad)


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_parse_rejects_non_finite_constants_anywhere_in_a_line(constant: str) -> None:
    text = _compact(FIRST).replace('"model":"gpt-4o-mini","messages"', f'"model":{constant},"x"', 1)
    assert constant in text
    with pytest.raises(EnvelopeError):
        parse_envelope(text)
    inner = _compact({**FIRST, "response": {"a": 0}}).replace('"a":0', f'"a":{constant}')
    with pytest.raises(EnvelopeError):
        parse_envelope(inner)


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
@pytest.mark.parametrize("where", ["request", "response"])
def test_parse_rejects_non_finite_floats_in_a_mapping_body(where: str, bad: float) -> None:
    with pytest.raises(EnvelopeError):
        parse_envelope({**FIRST, where: {"deep": [{"x": bad}]}})


@pytest.mark.parametrize(
    "bad",
    [{1: "x"}, {"s": {1, 2}}, {"t": (1, 2)}, {"o": object()}],
    ids=["int-key", "set", "tuple", "object"],
)
def test_parse_rejects_values_that_are_not_json(bad: dict[Any, Any]) -> None:
    with pytest.raises(EnvelopeError):
        parse_envelope({**FIRST, "request": bad})


@pytest.mark.parametrize("where", ["value", "key", "norm", "nested", "trace_id"])
def test_parse_rejects_lone_surrogates_in_a_mapping(where: str) -> None:
    line: dict[str, Any] = dict(FIRST)
    if where == "value":
        line["request"] = {"a": BAD_TEXT}
    elif where == "key":
        line["request"] = {BAD_TEXT: 1}
    elif where == "norm":
        line["norm"] = {**FIRST["norm"], "response": BAD_TEXT}
    elif where == "nested":
        line["response"] = {"a": [{"b": BAD_TEXT}]}
    else:
        line["trace_id"] = BAD_TEXT
    with pytest.raises(EnvelopeError):
        parse_envelope(line)


def test_parse_rejects_a_surrogate_escape_in_json_text() -> None:
    text = _compact({**FIRST, "request": {"a": "x"}}).replace('"x"', '"\\ud800"')
    with pytest.raises(EnvelopeError):
        parse_envelope(text)


def test_parse_turns_runaway_json_nesting_into_an_envelope_error() -> None:
    with pytest.raises(EnvelopeError):
        parse_envelope("[" * 200_000)


def test_huge_integers_raise_envelope_errors_not_overflow() -> None:
    with pytest.raises(EnvelopeError):
        parse_envelope({**FIRST, "latency_ms": 10**400})
    with pytest.raises(EnvelopeError):
        parse_envelope(
            _compact({**FIRST, "latency_ms": 0}).replace(
                '"latency_ms":0', '"latency_ms":1' + "0" * 400
            )
        )
    with pytest.raises(EnvelopeError):
        parse_envelope({**FIRST, "status": 10**400})
    with pytest.raises(EnvelopeError):
        parse_envelope(_compact(FIRST).replace('"status":200', '"status":' + "9" * 5000))


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf, -1.0])
def test_latency_must_be_finite_and_non_negative(bad: float) -> None:
    with pytest.raises(EnvelopeError):
        parse_envelope({**FIRST, "latency_ms": bad})


def _line_of_exactly(size: int) -> str:
    stub = _compact({**FIRST, "request": {"pad": ""}})
    line = _compact({**FIRST, "request": {"pad": "é" * ((size - len(stub.encode())) // 2)}})
    return line + " " * (size - len(line.encode()))


def test_parse_enforces_the_line_cap_in_utf_8_bytes() -> None:
    at_cap = _line_of_exactly(MAX_LINE_BYTES)
    assert len(at_cap.encode()) == MAX_LINE_BYTES
    assert parse_envelope(at_cap).trace_id == FIRST["trace_id"]
    assert parse_envelope(at_cap.encode()).trace_id == FIRST["trace_id"]
    over = at_cap + " "
    for candidate in (over, over.encode()):
        with pytest.raises(EnvelopeError, match="exceeds"):
            parse_envelope(candidate)
    # Characters would fit under the cap but their UTF-8 bytes do not.
    wide = "é" * (MAX_LINE_BYTES // 2 + 1)
    assert len(wide) < MAX_LINE_BYTES < len(wide.encode())
    with pytest.raises(EnvelopeError, match="exceeds"):
        parse_envelope(wide)


def test_encode_refuses_a_line_over_the_cap() -> None:
    big = {**FIRST, "response": {"blob": "x" * MAX_LINE_BYTES}}
    with pytest.raises(EnvelopeError, match="exceeds"):
        encode_envelope(parse_envelope(big))
    assert encode_envelope(parse_envelope(FIRST))


def test_encode_measures_the_cap_in_bytes() -> None:
    env = replace(parse_envelope(FIRST), response={"blob": "é" * (MAX_LINE_BYTES // 2)})
    with pytest.raises(EnvelopeError, match="exceeds"):
        encode_envelope(env)


def _hand_built(**changes: Any) -> TraceEnvelope:
    return replace(parse_envelope(FIRST), **changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"latency_ms": math.nan},
        {"latency_ms": math.inf},
        {"request": {"x": math.nan}},
        {"request": {"x": {1, 2}}},
        {"request": {"x": BAD_TEXT}},
        {"request": {BAD_TEXT: 1}},
    ],
    ids=["nan-latency", "inf-latency", "nan-body", "set-body", "surrogate-value", "surrogate-key"],
)
def test_encode_raises_only_envelope_errors(changes: dict[str, Any]) -> None:
    with pytest.raises(EnvelopeError):
        encode_envelope(_hand_built(**changes))


def test_encode_rejects_a_surrogate_in_norm_and_runaway_nesting() -> None:
    norm = parse_envelope(FIRST).norm
    assert isinstance(norm, Norm)
    with pytest.raises(EnvelopeError):
        encode_envelope(_hand_built(norm=replace(norm, response=BAD_TEXT)))
    deep: Any = {}
    node = deep
    for _ in range(200_000):
        node["a"] = {}
        node = node["a"]
    with pytest.raises(EnvelopeError):
        encode_envelope(_hand_built(request=deep))


def test_parse_accepts_a_mapping() -> None:
    assert parse_envelope(FIRST).v == 1


def test_norm_only_encodes_without_raw_bodies() -> None:
    line = {k: v for k, v in FIRST.items() if k not in ("request", "response")}
    encoded: dict[str, Any] = json.loads(encode_envelope(parse_envelope(line)))
    assert "request" not in encoded
    assert "response" not in encoded
    assert encoded["norm_v"] == 1


def test_raw_only_encodes_without_norm() -> None:
    line = {k: v for k, v in FIRST.items() if k not in ("norm", "norm_v")}
    encoded: dict[str, Any] = json.loads(encode_envelope(parse_envelope(line)))
    assert "norm" not in encoded
    assert "norm_v" not in encoded
    assert encoded["request"] == FIRST["request"]


@pytest.mark.parametrize(
    "huge",
    [10**5000, -(10**5000), 10**400],
    ids=["5000-digits", "negative-5000-digits", "400-digits"],
)
@pytest.mark.parametrize("field", ["v", "norm_v"])
def test_huge_version_numbers_raise_only_envelope_errors(field: str, huge: int) -> None:
    # Formatting an int past 4300 digits raises a bare ValueError, so messages must omit it.
    with pytest.raises(EnvelopeError) as caught:
        parse_envelope({**FIRST, field: huge})
    assert type(caught.value) is (UnsupportedEnvelopeVersion if huge > 1 else EnvelopeError)
    assert "digits" not in str(caught.value)


class _Runaway(dict[str, Any]):
    """A dict whose ``items()`` is bounded, so a missing cycle guard fails fast instead of hanging."""

    calls = 0

    def items(self) -> Any:
        type(self).calls += 1
        assert type(self).calls < 10_000, "walker looped: no cycle guard"
        return super().items()


class _RunawayList(list[Any]):
    calls = 0

    def __iter__(self) -> Any:
        type(self).calls += 1
        assert type(self).calls < 10_000, "walker looped: no cycle guard"
        return super().__iter__()


def test_parse_rejects_a_cyclic_mapping_instead_of_hanging() -> None:
    loop = _Runaway()
    loop["self"] = loop
    with pytest.raises(EnvelopeError, match="cycl"):
        parse_envelope({**FIRST, "request": loop})
    two_step: dict[str, Any] = {}
    two_step["child"] = {"back": two_step}
    with pytest.raises(EnvelopeError, match="cycl"):
        parse_envelope({**FIRST, "response": two_step})


def test_parse_rejects_a_cyclic_list_instead_of_hanging() -> None:
    loop = _RunawayList()
    loop.append(loop)
    with pytest.raises(EnvelopeError, match="cycl"):
        parse_envelope({**FIRST, "request": {"a": loop}})


def test_parse_accepts_one_object_referenced_twice() -> None:
    shared = {"k": [1, 2]}
    env = parse_envelope(
        {**FIRST, "request": {"a": shared, "b": shared}, "response": {"c": shared}}
    )
    assert env.request == {"a": {"k": [1, 2]}, "b": {"k": [1, 2]}}


@pytest.mark.parametrize(
    "huge", [2**53, 10**400, -(10**400)], ids=["2**53", "400-digits", "negative-400-digits"]
)
def test_latency_beyond_the_safe_range_is_rejected(huge: float) -> None:
    with pytest.raises(EnvelopeError):
        parse_envelope({**FIRST, "latency_ms": huge})


def test_negative_zero_latency_is_rejected_and_positive_zero_is_not() -> None:
    with pytest.raises(EnvelopeError):
        parse_envelope({**FIRST, "latency_ms": -0.0})
    assert parse_envelope({**FIRST, "latency_ms": 0.0}).latency_ms == 0.0
