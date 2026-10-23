"""Trace envelope v1: the cases file shared with the TypeScript mirror, plus Python-only checks."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

import pytest

from dagnam_contracts.trace import (
    MAX_LINE_BYTES,
    EnvelopeError,
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


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_shared_cases(case: dict[str, Any]) -> None:
    if case["ok"]:
        assert parse_envelope(json.dumps(case["line"])).trace_id == case["line"]["trace_id"]
        return
    with pytest.raises(ERRORS[case["error"]]) as caught:
        parse_envelope(json.dumps(case["line"]))
    # Subclass-exact: a plain EnvelopeError case must not be the unsupported-version error.
    assert type(caught.value) is ERRORS[case["error"]]


def test_cases_file_covers_the_documented_shapes() -> None:
    names = {c["name"] for c in CASES}
    assert {"raw_and_norm", "raw_only", "norm_only", "version_2", "failed_call_status_429"} <= names
    assert CASES[0]["name"] == "raw_and_norm"


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


def test_encode_refuses_a_line_over_the_cap() -> None:
    big = {**FIRST, "response": {"blob": "x" * MAX_LINE_BYTES}}
    with pytest.raises(EnvelopeError, match="exceeds"):
        encode_envelope(parse_envelope(big))
    assert encode_envelope(parse_envelope(FIRST))


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf, -1.0])
def test_latency_must_be_finite_and_non_negative(bad: float) -> None:
    with pytest.raises(EnvelopeError):
        parse_envelope({**FIRST, "latency_ms": bad})


def test_parse_accepts_a_mapping_and_rejects_non_objects() -> None:
    assert parse_envelope(FIRST).v == 1
    with pytest.raises(EnvelopeError):
        parse_envelope("[1, 2]")
    with pytest.raises(EnvelopeError):
        parse_envelope("not json")


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
