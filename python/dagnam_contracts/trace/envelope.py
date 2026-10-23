"""Trace envelope v1: one JSON object per recorded LLM call, shared by every recorder and reader.

Unknown top-level keys are ignored on parse and are not preserved on encode. Every failure on bad
input is an ``EnvelopeError`` (``UnsupportedEnvelopeVersion`` for a newer ``v`` or ``norm_v``).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
import json
import math
import re
from typing import Any, Final, Never, TypeGuard, cast

ENVELOPE_VERSION: Final = 1
NORM_VERSION: Final = 1
MAX_LINE_BYTES: Final = 1_000_000
PROVIDERS: Final = ("openai", "anthropic", "other")
ENDPOINTS: Final = ("chat.completions", "responses", "messages", "custom")

_TS: Final = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z")


class EnvelopeError(ValueError):
    """The line is not a valid envelope."""


class UnsupportedEnvelopeVersion(EnvelopeError):
    """The line is an envelope of a version this reader does not know."""


@dataclass(frozen=True, slots=True)
class NormMessage:
    role: str
    content: str


@dataclass(frozen=True, slots=True)
class Norm:
    model: str
    system: str | None
    messages: tuple[NormMessage, ...]
    response: str
    tool_calls: tuple[dict[str, Any], ...]
    prompt_tokens: int
    completion_tokens: int
    cached_prompt_tokens: int
    has_media: bool


@dataclass(frozen=True, slots=True)
class TraceEnvelope:
    v: int
    trace_id: str
    ts: str
    provider: str
    endpoint: str
    latency_ms: float
    status: int
    request: dict[str, Any] | None
    response: dict[str, Any] | None
    norm: Norm | None
    norm_v: int | None


def _is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_text(value: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise EnvelopeError("strings must be valid Unicode (no lone surrogates)") from exc


def _check_json(root: object) -> None:
    """Reject anything a JSON line cannot carry: NaN/Infinity, lone surrogates, non-JSON types."""
    stack = [root]
    while stack:
        value = stack.pop()
        if isinstance(value, str):
            _check_text(value)
        elif isinstance(value, float):
            if not math.isfinite(value):
                raise EnvelopeError("numbers must be finite")
        elif isinstance(value, Mapping):
            for key, item in cast("Mapping[object, object]", value).items():
                if not isinstance(key, str):
                    raise EnvelopeError("object keys must be strings")
                _check_text(key)
                stack.append(item)
        elif isinstance(value, list):
            stack.extend(cast("list[object]", value))
        elif value is not None and not isinstance(value, int):
            raise EnvelopeError("values must be JSON values")


def _reject_constant(name: str) -> Never:
    raise EnvelopeError(f"{name} is not valid JSON")


def _load(line: object) -> Mapping[str, Any]:
    if isinstance(line, Mapping):
        return cast("Mapping[str, Any]", line)
    if isinstance(line, (bytes, bytearray)):
        size = len(line)
        try:
            text = bytes(line).decode("utf-8") if size <= MAX_LINE_BYTES else ""
        except UnicodeDecodeError as exc:
            raise EnvelopeError("a line must be valid UTF-8") from exc
    elif isinstance(line, str):
        try:
            size = len(line.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise EnvelopeError("a line must be valid UTF-8") from exc
        text = line
    else:
        raise EnvelopeError("a line is a string, bytes or an object")
    if size > MAX_LINE_BYTES:
        raise EnvelopeError(f"line exceeds {MAX_LINE_BYTES} bytes")
    try:
        loaded = json.loads(text, parse_constant=_reject_constant)
    except (ValueError, RecursionError) as exc:
        raise EnvelopeError("not JSON") from exc
    if not isinstance(loaded, dict):
        raise EnvelopeError("an envelope is a JSON object")
    return cast("Mapping[str, Any]", loaded)


def _str(obj: Mapping[str, Any], key: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value:
        raise EnvelopeError(f"{key} must be a non-empty string")
    return value


def _int(obj: Mapping[str, Any], key: str) -> int:
    value = obj.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise EnvelopeError(f"{key} must be a non-negative integer")
    return value


def _message(raw: object) -> NormMessage:
    if not isinstance(raw, Mapping):
        raise EnvelopeError("norm.messages entries must be objects")
    entry = cast("Mapping[str, Any]", raw)
    role, content = entry.get("role"), entry.get("content")
    if not isinstance(role, str) or not isinstance(content, str):
        raise EnvelopeError("norm.messages entries need a string role and string content")
    return NormMessage(role, content)


def _tool_call(raw: object) -> dict[str, Any]:
    """An OpenAI-shaped call: ``{"type": "function", "function": {"name": str, "arguments": str}}``."""
    if isinstance(raw, dict):
        call = cast("dict[str, Any]", raw)
        function = call.get("function")
        if (
            call.get("type") == "function"
            and isinstance(function, dict)
            and isinstance(cast("dict[str, Any]", function).get("name"), str)
            and isinstance(cast("dict[str, Any]", function).get("arguments"), str)
        ):
            return dict(call)
    raise EnvelopeError('norm.tool_calls entries must be {"type":"function","function":{...}}')


def _norm_version(obj: Mapping[str, Any]) -> int:
    value = obj.get("norm_v")
    if not _is_int(value):
        raise EnvelopeError("norm needs an integer norm_v")
    if value > NORM_VERSION:
        raise UnsupportedEnvelopeVersion(f"norm_v {value} is newer than {NORM_VERSION}")
    if value != NORM_VERSION:
        raise EnvelopeError(f"norm_v must be {NORM_VERSION}")
    return NORM_VERSION


def _norm(raw: object) -> Norm:
    if not isinstance(raw, Mapping):
        raise EnvelopeError("norm must be an object")
    obj = cast("Mapping[str, Any]", raw)
    messages = obj.get("messages")
    calls = obj.get("tool_calls", [])
    if not isinstance(messages, list) or not isinstance(calls, list):
        raise EnvelopeError("norm.messages and norm.tool_calls must be lists")
    system = obj.get("system")
    if system is not None and not isinstance(system, str):
        raise EnvelopeError("norm.system must be a string or null")
    response = obj.get("response")
    if not isinstance(response, str):
        raise EnvelopeError("norm.response must be a string")
    has_media = obj.get("has_media", False)
    if not isinstance(has_media, bool):
        raise EnvelopeError("norm.has_media must be a boolean")
    return Norm(
        model=_str(obj, "model"),
        system=system,
        messages=tuple(_message(m) for m in cast("list[object]", messages)),
        response=response,
        tool_calls=tuple(_tool_call(c) for c in cast("list[object]", calls)),
        prompt_tokens=_int(obj, "prompt_tokens"),
        completion_tokens=_int(obj, "completion_tokens"),
        cached_prompt_tokens=_int(obj, "cached_prompt_tokens")
        if "cached_prompt_tokens" in obj
        else 0,
        has_media=has_media,
    )


def _body(obj: Mapping[str, Any], key: str) -> dict[str, Any] | None:
    value = obj.get(key)
    if value is None:
        return None
    if not isinstance(value, dict):
        raise EnvelopeError(f"{key} must be an object")
    return cast("dict[str, Any]", value)


def _check_version(obj: Mapping[str, Any]) -> None:
    version = obj.get("v")
    if not _is_int(version):
        raise EnvelopeError("v must be the integer 1")
    if version > ENVELOPE_VERSION:
        raise UnsupportedEnvelopeVersion(f"envelope v{version} is newer than v{ENVELOPE_VERSION}")
    if version != ENVELOPE_VERSION:
        raise EnvelopeError("v must be 1")


def parse_envelope(line: str | bytes | bytearray | Mapping[str, Any]) -> TraceEnvelope:
    """Validate one envelope: a JSON line (str, or UTF-8 bytes) or an already-decoded object."""
    obj = _load(line)
    _check_json(obj)
    _check_version(obj)
    ts = _str(obj, "ts")
    if not _TS.fullmatch(ts):
        raise EnvelopeError("ts must be a UTC RFC 3339 time ending in Z")
    try:
        datetime.fromisoformat(ts)
    except ValueError as exc:
        raise EnvelopeError("ts is not a real date and time") from exc
    provider, endpoint = _str(obj, "provider"), _str(obj, "endpoint")
    if provider not in PROVIDERS or endpoint not in ENDPOINTS:
        raise EnvelopeError("unknown provider or endpoint")
    latency = obj.get("latency_ms")
    if isinstance(latency, bool) or not isinstance(latency, (int, float)):
        raise EnvelopeError("latency_ms must be a number")
    try:
        latency_ms = float(latency)
    except OverflowError as exc:
        raise EnvelopeError("latency_ms is out of range") from exc
    if not math.isfinite(latency_ms) or latency_ms < 0:
        raise EnvelopeError("latency_ms must be finite and non-negative")
    status = _int(obj, "status")
    if not 100 <= status <= 599:
        raise EnvelopeError("status must be an HTTP status")
    request, response = _body(obj, "request"), _body(obj, "response")
    if (request is None) != (response is None):
        raise EnvelopeError("request and response must both be present or both absent")
    norm_v: int | None = None
    norm: Norm | None = None
    if obj.get("norm") is not None:
        norm_v = _norm_version(obj)  # first: a newer norm may have a shape we cannot read
        norm = _norm(obj["norm"])
    if request is None and norm is None:
        raise EnvelopeError("a line needs request and response, or norm")
    return TraceEnvelope(
        v=ENVELOPE_VERSION,
        trace_id=_str(obj, "trace_id"),
        ts=ts,
        provider=provider,
        endpoint=endpoint,
        latency_ms=latency_ms,
        status=status,
        request=request,
        response=response,
        norm=norm,
        norm_v=norm_v,
    )


def encode_envelope(envelope: TraceEnvelope) -> str:
    body: dict[str, Any] = {
        "v": envelope.v,
        "trace_id": envelope.trace_id,
        "ts": envelope.ts,
        "provider": envelope.provider,
        "endpoint": envelope.endpoint,
        "latency_ms": envelope.latency_ms,
        "status": envelope.status,
    }
    if envelope.request is not None and envelope.response is not None:
        body["request"], body["response"] = envelope.request, envelope.response
    if envelope.norm is not None:
        n = envelope.norm
        body["norm"] = {
            "model": n.model,
            "system": n.system,
            "messages": [{"role": m.role, "content": m.content} for m in n.messages],
            "response": n.response,
            "tool_calls": list(n.tool_calls),
            "prompt_tokens": n.prompt_tokens,
            "completion_tokens": n.completion_tokens,
            "cached_prompt_tokens": n.cached_prompt_tokens,
            "has_media": n.has_media,
        }
        body["norm_v"] = envelope.norm_v
    try:
        text = json.dumps(body, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        size = len(text.encode("utf-8"))
    except (ValueError, TypeError, RecursionError, UnicodeEncodeError) as exc:
        raise EnvelopeError("envelope cannot be encoded as JSON") from exc
    if size > MAX_LINE_BYTES:
        raise EnvelopeError(f"line exceeds {MAX_LINE_BYTES} bytes")
    return text
