"""The one rendering of a chat request as classifier input text, and its inverse.

A text classifier trained on chat data must see, at serving time, byte-for-byte
the text it saw in training. Training-side derivation and the serving-side
chat-completions bridge both call `render_chat_prompt`, so there is exactly one
place the format can change — and a change here is a train/serve skew, which is
why `tests/test_prompts.py` pins the output byte-for-byte.

`parse_chat_prompt` reads that text back as messages. Replaying a holdout needs
it -- the stored row is rendered text, the endpoint wants turns -- and it ran as
a copy in the CLI and another in the platform, which is the same train/serve
skew one step removed: an inverse that drifts from the rendering silently
replays something the classifier never saw.

Since 0.4.0 an assistant turn is rendered as context, with each tool call it
made as one line of canonical JSON, so a tool result later in the prompt has
the call it answers. A classifier served through the platform is cut to its
last user turn, so only a request that ends after an assistant turn (a step in
the middle of a tool loop) reaches it differently than under 0.3.x.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

_MARKER = re.compile(r"^<\|(\w+)\|>\n", re.MULTILINE)
"""One rendered turn's opening marker, as `render_chat_prompt` writes it."""


def _call_line(call: Mapping[str, Any]) -> str:
    """One tool call as ``{"arguments": ..., "name": ...}``, sorted keys.

    Takes the audit's own shape or OpenAI's (``function.name`` and
    ``function.arguments`` as a JSON string, which is parsed when it parses).
    """
    function: Mapping[str, Any] = call.get("function") or call
    arguments = function.get("arguments")
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except (ValueError, RecursionError):
            pass
    return json.dumps(
        {"arguments": {} if arguments is None else arguments, "name": function.get("name")},
        sort_keys=True,
    )


def _content_text(content: Any) -> str:
    """A turn's content as text: typed parts (OpenAI's list form) join their text."""
    if isinstance(content, list):
        return "".join(
            str(part.get("text", "")) if isinstance(part, dict) else str(part) for part in content
        )
    return "" if content is None else str(content)


def render_chat_prompt(messages: Sequence[Mapping[str, Any]], *, system: str | None) -> str:
    """Render `messages` (plus an optional `system` prompt) as classifier input.

    ``<|system|>\\n{system}\\n`` once at the top when `system` is given, then
    ``<|{role}|>\\n{content}\\n`` per turn in order, every role under its own
    marker. An assistant turn is context for the turns after it: its content
    (``None`` reads as empty), then one line per call in its ``tool_calls``.
    Content given as typed parts renders as their text, joined.
    Content is copied verbatim, trailing newlines included.
    """
    parts: list[str] = []
    if system is not None:
        parts.append(f"<|system|>\n{system}\n")
    for message in messages:
        content = _content_text(message.get("content"))
        calls = [_call_line(call) for call in message.get("tool_calls") or ()]
        body = "\n".join([content, *calls] if content else calls)
        parts.append(f"<|{message['role']}|>\n{body}\n")
    return "".join(parts)


def parse_chat_prompt(text: str) -> list[dict[str, str]]:
    """Invert :func:`render_chat_prompt`: marker blocks back to messages.

    A chunk before the first marker (a row truncated from the front) becomes
    a ``user`` turn so nothing the classifier saw is dropped. A system prompt
    comes back as a ``system`` turn, because that is how it was rendered.
    """
    # ponytail: a content line that is itself `<|role|>` splits here; the
    # rendering is this module's, so fix it there if a real export shows it.
    markers = list(_MARKER.finditer(text))
    messages: list[dict[str, str]] = []
    leading = text[: markers[0].start()] if markers else text
    if leading:
        messages.append({"role": "user", "content": leading.removesuffix("\n")})
    for index, marker in enumerate(markers):
        end = markers[index + 1].start() if index + 1 < len(markers) else len(text)
        messages.append(
            {"role": marker.group(1), "content": text[marker.end() : end].removesuffix("\n")}
        )
    return messages


__all__ = ["parse_chat_prompt", "render_chat_prompt"]
