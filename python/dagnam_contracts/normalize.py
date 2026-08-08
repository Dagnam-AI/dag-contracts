"""Canonical architecture normalizer for the SDK.

A public, self-contained twin of the backend ``validation.contracts.normalize``.
It reads the GENERATED ``component-schema.json`` bundled in this package (plain
data, not a backend import), so the public SDK can upgrade legacy padding before
persisting without depending on the private backend. Upgrades ONLY
``kind == "padding"`` params; ``pooling`` padding is a plain enum and is left
untouched.
"""

from __future__ import annotations

from importlib import resources
import json
from typing import Any, cast

# Defined locally, not imported from the `dagnam` SDK: this package must not
# depend on one of its own consumers, and importing it made the wheel
# un-importable anywhere the SDK is absent -- which local testing hid,
# because the SDK happened to be installed in the dev venv.
#
# RECURSIVE, via PEP 695 (safe: requires-python is >=3.12). It was previously
# `list[object] | dict[str, object]`, which is only one level deep, so a real
# nested JSON document did not satisfy it. That leaks: this alias is the
# parameter AND return type of the two public `normalize_*` functions, so every
# consumer whose own JsonValue is recursive -- dag-lib's is -- got a hard type
# error at the call site and had to `cast` around it. Fixing the alias here
# removes that cast from every consumer instead of each one re-inventing it.
type JsonValue = (
    str | int | float | bool | None | list[JsonValue] | dict[str, JsonValue]
)


def _load() -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    text = resources.files("dagnam_contracts").joinpath("component-schema.json").read_text("utf-8")
    payload = json.loads(text)
    by_id = {c["component_id"]: c for c in payload["components"]}
    by_layer = {c["layer_type"]: c["component_id"] for c in payload["components"]}
    return by_id, by_layer


_BY_ID, _BY_LAYER = _load()


def _key_variants(name: str) -> list[str]:
    snake = "".join(f"_{ch.lower()}" if ch.isupper() else ch for ch in name)
    head, *rest = name.split("_")
    camel = head + "".join(p[:1].upper() + p[1:] for p in rest)
    out: list[str] = []
    for variant in (name, snake, camel):
        if variant not in out:
            out.append(variant)
    return out


def _candidate_keys(param: dict[str, Any]) -> list[str]:
    names = [param["key"], *(param.get("aliases") or [])]
    out: list[str] = []
    for name in names:
        for variant in _key_variants(name):
            if variant not in out:
                out.append(variant)
    return out


def _normalize_padding_value(value: Any) -> Any:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return {"mode": "explicit", "value": value} if value >= 0 else value
    # A bare tuple/list of pads (SDK/PyTorch dump of Conv2d(padding=(1, 2)))
    # upgrades to per-axis explicit; an invalid list is passed through unchanged
    # so the validator can report it.
    if isinstance(value, (list, tuple)):
        pads = list(value)
        if 1 <= len(pads) <= 3 and all(
            isinstance(e, int) and not isinstance(e, bool) and e >= 0 for e in pads
        ):
            return {"mode": "explicit", "value": pads}
        return value
    if isinstance(value, str) and value in ("same", "valid"):
        return {"mode": value}
    return value


def _resolve_component_id(identifier: Any) -> str | None:
    if not isinstance(identifier, str) or not identifier:
        return None
    if identifier in _BY_ID:
        return identifier
    return _BY_LAYER.get(identifier.lower())


def _normalize_unit(identifier: Any, config: Any) -> Any:
    """Upgrade padding params on ONE config, keyed by *identifier*.

    A non-dict config or an unresolvable identifier is returned unchanged.
    """
    component_id = _resolve_component_id(identifier)
    if component_id is None or not isinstance(config, dict):
        return config
    result: dict[str, Any] = dict(cast("dict[str, Any]", config))
    for param in _BY_ID[component_id]["params"]:
        if param["kind"] != "padding":
            continue
        for key in _candidate_keys(param):
            if key in result:
                result[key] = _normalize_padding_value(result[key])
                break
    return result


def normalize_diagram_state(diagram_state: JsonValue) -> JsonValue:
    """Normalize ``nodes[*].data.config`` (keyed by ``data.componentId``)."""
    if not isinstance(diagram_state, dict):
        return diagram_state
    state = cast("dict[str, Any]", diagram_state)
    nodes = state.get("nodes")
    if not isinstance(nodes, list):
        return diagram_state
    new_nodes: list[Any] = []
    for node in cast("list[Any]", nodes):
        data = node.get("data") if isinstance(node, dict) else None
        if isinstance(data, dict):
            new_data: dict[str, Any] = dict(cast("dict[str, Any]", data))
            new_data["config"] = _normalize_unit(
                new_data.get("componentId") or new_data.get("layer_type"),
                new_data.get("config"),
            )
            new_nodes.append({**cast("dict[str, Any]", node), "data": new_data})
        else:
            new_nodes.append(node)
    return {**state, "nodes": new_nodes}


def normalize_architecture_config(architecture_config: JsonValue) -> JsonValue:
    """Normalize ``layers[*].config`` (keyed by ``layers[*].type``)."""
    if not isinstance(architecture_config, dict):
        return architecture_config
    config = cast("dict[str, Any]", architecture_config)
    layers = config.get("layers")
    if not isinstance(layers, list):
        return architecture_config
    new_layers: list[Any] = []
    for layer in cast("list[Any]", layers):
        if isinstance(layer, dict):
            layer_dict = cast("dict[str, Any]", layer)
            new_layers.append(
                {
                    **layer_dict,
                    "config": _normalize_unit(layer_dict.get("type"), layer_dict.get("config")),
                }
            )
        else:
            new_layers.append(layer)
    return {**config, "layers": new_layers}
