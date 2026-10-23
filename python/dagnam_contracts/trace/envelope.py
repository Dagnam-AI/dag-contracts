"""Trace envelope v1: one JSON object per recorded LLM call, shared by every recorder and reader."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
import json
import math
import re
from typing import Any, Final

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


def _str(obj: Mapping[str, Any], key: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value:
        raise EnvelopeError(f"{key} must be a non-empty string")
    return value


def _int(obj: Mapping[str, Any], key: str) -> int:
    value = obj.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EnvelopeError(f"{key} must be a non-negative integer")
    return value


def _norm(raw: object) -> Norm:
    if not isinstance(raw, Mapping):
        raise EnvelopeError("norm must be an object")
    messages = raw.get("messages")
    calls = raw.get("tool_calls", [])
    if not isinstance(messages, list) or not isinstance(calls, list):
        raise EnvelopeError("norm.messages and norm.tool_calls must be lists")
    system = raw.get("system")
    if system is not None and not isinstance(system, str):
        raise EnvelopeError("norm.system must be a string or null")
    response = raw.get("response")
    if not isinstance(response, str):
        raise EnvelopeError("norm.response must be a string")
    try:
        parsed = tuple(NormMessage(str(m["role"]), str(m["content"])) for m in messages)
    except (KeyError, TypeError) as exc:
        raise EnvelopeError("norm.messages entries need role and content") from exc
    return Norm(
        model=_str(raw, "model"),
        system=system,
        messages=parsed,
        response=response,
        tool_calls=tuple(dict(c) for c in calls),
        prompt_tokens=_int(raw, "prompt_tokens"),
        completion_tokens=_int(raw, "completion_tokens"),
        cached_prompt_tokens=_int(raw, "cached_prompt_tokens")
        if "cached_prompt_tokens" in raw
        else 0,
        has_media=bool(raw.get("has_media", False)),
    )


def _body(obj: Mapping[str, Any], key: str) -> dict[str, Any] | None:
    value = obj.get(key)
    if value is None:
        return None
    if not isinstance(value, dict):
        raise EnvelopeError(f"{key} must be an object")
    return value


def parse_envelope(line: str | Mapping[str, Any]) -> TraceEnvelope:
    if isinstance(line, str):
        try:
            loaded = json.loads(line)
        except ValueError as exc:
            raise EnvelopeError("not JSON") from exc
        if not isinstance(loaded, dict):
            raise EnvelopeError("an envelope is a JSON object")
        obj: Mapping[str, Any] = loaded
    else:
        obj = line
    version = obj.get("v")
    # ``True == 1`` in Python, so the bool check must come first or ``"v": true`` would pass.
    if isinstance(version, bool) or version != ENVELOPE_VERSION:
        if (
            isinstance(version, int)
            and not isinstance(version, bool)
            and version > ENVELOPE_VERSION
        ):
            raise UnsupportedEnvelopeVersion(
                f"envelope v{version} is newer than v{ENVELOPE_VERSION}"
            )
        raise EnvelopeError("v must be 1")
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
    if not math.isfinite(latency) or latency < 0:
        raise EnvelopeError("latency_ms must be finite and non-negative")
    status = _int(obj, "status")
    if not 100 <= status <= 599:
        raise EnvelopeError("status must be an HTTP status")
    request, response = _body(obj, "request"), _body(obj, "response")
    has_raw = request is not None and response is not None
    norm = _norm(obj["norm"]) if obj.get("norm") is not None else None
    if not has_raw and norm is None:
        raise EnvelopeError("a line needs request and response, or norm")
    norm_v = obj.get("norm_v")
    if norm is not None and (isinstance(norm_v, bool) or not isinstance(norm_v, int)):
        raise EnvelopeError("norm needs norm_v")
    return TraceEnvelope(
        v=ENVELOPE_VERSION,
        trace_id=_str(obj, "trace_id"),
        ts=ts,
        provider=provider,
        endpoint=endpoint,
        latency_ms=float(latency),
        status=status,
        request=request,
        response=response,
        norm=norm,
        norm_v=norm_v if norm is not None else None,
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
    text = json.dumps(body, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    if len(text.encode("utf-8")) > MAX_LINE_BYTES:
        raise EnvelopeError(f"line exceeds {MAX_LINE_BYTES} bytes")
    return text
