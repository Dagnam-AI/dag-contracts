"""Rows, documents and strings under the PII scan: the walk the scan, the drop and the redaction share.

Every walk takes ``act`` (which classes to replace) and always detects every class, so the
scan acts on everything and a policy on its `redact` classes, and the counts returned cover
every class. `Any` stands for a JSON value.

Pure -- no I/O.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
import json
from typing import Any

from dagnam_contracts.hygiene.detectors import PII_DETECTORS, PiiDetector
from dagnam_contracts.hygiene.spans import member_text, redact_both

_Fields = list[tuple[str, Counter[str]]]
"""Each field that had a finding, as ``(json-ish path, findings per class)``."""


def _text_of(value: Any) -> str | None:
    """A member's value as text when it is a string or a number, else ``None``."""
    if isinstance(value, str):
        return value
    if isinstance(value, int | float) and not isinstance(value, bool):
        return json.dumps(value)
    return None


def _named(
    keys: Iterable[object], value: Any, redacted: Any, *, in_row: bool
) -> PiiDetector | None:
    """The class whose member rule takes the member under one of ``keys`` whole, if one does.

    A member of the row itself is judged by `PiiDetector.row_member`, a member of a
    document by `member`. The rule reads the placeholder-free text of the value as
    given AND of its fully redacted form. Both readings agree on a second look: when
    the rule takes the member the value becomes one placeholder, whose text is empty,
    so the rescan's rule is false; when it does not, the output value is the redacted
    form, and the rescan reads that same text. The first reading is what keeps
    `{"password": "a@b.co"}` one secret and `{"auth": "Bearer <token>"}` the whole value.
    The keys are likewise a document member's key as given and as redacted (the rescan's
    key is the redacted one, which the first reading tried too).
    """
    texts = [t for t in (_text_of(value), _text_of(redacted)) if t is not None]
    if not texts:
        return None
    readable = [member_text(t) for t in texts]
    for key in keys:
        if not isinstance(key, str):
            continue
        for detector in PII_DETECTORS:
            rule = detector.row_member if in_row else detector.member
            if rule is not None and any(rule(key, text) for text in readable):
                return detector
    return None


def _scalar(value: Any, act: frozenset[str]) -> tuple[Any, Any, Counter[str]]:
    """A string or number leaf as ``(fully redacted, redacted for act, findings)``.

    Anything else passes through. A number that matched becomes the placeholder as a
    JSON string: the placeholder is text, and a bare one is not JSON.
    """
    text = _text_of(value)
    if text is None:
        return value, value, Counter()
    full, acted, found = redact_both(text, act)
    if not found:
        return value, value, found
    return full, (acted if isinstance(value, str) or acted != text else value), found


# How deep a document is walked as one. Deeper is plain text, on every machine: whether a
# nesting of about a thousand levels parses or overflows the stack depends on the stack the
# caller is already on, and a client and a platform must not read one row two ways. 500 keeps
# every depth the walk used to read from an ordinary stack, with room for a caller's frames.
_MAX_DEPTH = 500


def _redact_json_value(
    value: Any, act: frozenset[str], depth: int = 0
) -> tuple[Any, Any, Counter[str]]:
    """A document value as ``(fully redacted, redacted for act, findings per class)``.

    A key is redacted as text first; the member rule then reads the key as given AND as
    redacted, and the placeholder-free text of the value as given and as redacted. A
    finding can swallow the credential word of a key (an address whose domain runs on
    into `_password`), so the redacted key alone would lose the member; the key as given
    alone would miss a name a redaction reveals (`4111111111111111secret`). A member the
    rule takes is one finding, whatever the value held.
    """
    if depth > _MAX_DEPTH:
        raise RecursionError("a document nested deeper than the walk reads")
    if isinstance(value, list):
        fulls: list[Any] = []
        acteds: list[Any] = []
        total: Counter[str] = Counter()
        for item in value:
            full, acted, found = _redact_json_value(item, act, depth + 1)
            fulls.append(full)
            acteds.append(acted)
            total += found
        return fulls, acteds, total
    if isinstance(value, dict):
        full_members: dict[str, Any] = {}
        acted_members: dict[str, Any] = {}
        total = Counter()
        for key, item in value.items():
            full_key, acted_key, key_found = redact_both(key, act)
            full_item, acted_item, item_found = _redact_json_value(item, act, depth + 1)
            named = _named((key, full_key), item, full_item, in_row=False)
            if named is not None:
                full_item = named.replacement
                acted_item = named.replacement if named.code in act else item
                item_found = Counter({named.code: 1})
            full_members[full_key] = full_item
            acted_members[acted_key] = acted_item
            total += key_found + item_found
        return full_members, acted_members, total
    return _scalar(value, act)


def _parse_document(text: str) -> Any | None:
    """``text`` as JSON when it opens with ``{`` or ``[`` and parses, else ``None``."""
    if text.lstrip()[:1] not in ("{", "["):
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def redact_document(text: str, value: Any, act: frozenset[str]) -> tuple[str, str, Counter[str]]:
    """``text``, which parsed to ``value``, as ``(fully redacted, redacted for act, findings)``;
    re-serialised only if something was found. A document that nests too deep to walk is
    plain text."""
    try:
        full, acted, found = _redact_json_value(value, act)
    except RecursionError:
        return redact_both(text, act)
    changed = any(found[code] for code in act)
    return (
        json.dumps(full, ensure_ascii=False) if found else text,
        json.dumps(acted, ensure_ascii=False) if changed else text,
        found,
    )


def redact_string(text: str, act: frozenset[str]) -> tuple[str, str, Counter[str]]:
    """One string of a row as ``(fully redacted, redacted for act, findings per class)``.

    Only a document that opens with ``{`` or ``[`` and parses is read as JSON: a field
    of plain text that happens to parse as a number is still plain text. Any other
    text is redacted as text; and when what that leaves parses as JSON (a raw tab
    inside a phone number was what kept it from parsing), the result is walked as a
    document as well, once, so a scan of the output -- which sees a document -- finds
    nothing the redaction did not. The walk's own output is JSON, so it ends there. When
    the classes to act on are not the ones that made it parse, nothing can be rewritten
    in the text left (it still holds what keeps it from parsing): the members are
    counted, and replaced only by a policy that redacts those classes too.
    """
    document = _parse_document(text)
    if document is not None:
        return redact_document(text, document, act)
    full, acted, found = redact_both(text, act)
    if found and (document := _parse_document(full)) is not None:
        plain = full
        full, acted_document, more = redact_document(plain, document, act)
        if acted == plain:  # `act` hid nothing: the text acted on is the text that parsed
            acted = acted_document
        elif (acted_parsed := _parse_document(acted)) is not None:
            acted = redact_document(acted, acted_parsed, act)[1]  # `act` alone made it parse
        # What the plain pass found and what the walk then found are both findings; a member
        # the walk takes whole removes the placeholders of the findings inside its value, so
        # here, and only here, a count can exceed the placeholders the text holds.
        found += more
    return full, acted, found


def redact_fields(
    value: Any, act: frozenset[str], path: str = "", owners: tuple[object, ...] = ()
) -> tuple[Any, _Fields]:
    """`value` rebuilt with every field redacted for ``act``, and each field that had a
    finding as ``(json-ish path, findings per class)``, in key order.

    The one walk the scan, the drop and the redaction share, so anything the scan
    reports is something the redactor rewrites: the findings always cover every
    class, and ``act`` only chooses which of them are replaced. Fully recursive, and it
    has to be: `chat-messages` -- the platform's most common format -- holds its text
    at ``messages[0].content``, two levels down inside a list of dicts.

    A member under a credential name (``password``, ``client_secret``, ...; the rule is
    `credentials.is_credential_row_member`'s) is replaced whole, string or number,
    unless it is blank, a boolean, ``None`` or a flag-like word; ``owners`` are the
    keys it sits under, so every scalar in a list or an object under such a name is
    replaced by the same rule. Every other string goes through :func:`redact_string`.
    What a document held in a string gets and a row does not (the module docstring
    has the reasons): the ambiguous names (``token``, ``auth``, ``key``, ...) decide
    nothing, a bare number is not scanned, and keys are not redacted, at any depth --
    so a row's structure, and the path of a field, is the same before and after.
    """
    if isinstance(value, dict):
        rebuilt: dict[Any, Any] = {}
        by_key: dict[Any, _Fields] = {}
        for name, item in value.items():
            child = f"{path}.{name}" if path else str(name)
            rebuilt[name], by_key[name] = redact_fields(item, act, child, (*owners, name))
        return rebuilt, [entry for name in sorted(by_key, key=str) for entry in by_key[name]]
    if isinstance(value, list):
        items: list[Any] = []
        fields: _Fields = []
        for index, item in enumerate(value):
            new_item, found_in_item = redact_fields(item, act, f"{path}[{index}]", owners)
            items.append(new_item)
            fields += found_in_item
        return items, fields
    if isinstance(value, str):
        full, acted, found = redact_string(value, act)
    else:
        full, acted, found = value, value, Counter()
    named = _named(reversed(owners), value, full, in_row=True)
    if named is not None:
        leaf = named.replacement if named.code in act else value
        return leaf, [(path or "<row>", Counter({named.code: 1}))]
    return acted, [(path or "<row>", found)] if found else []


__all__ = ["redact_document", "redact_fields", "redact_string"]
