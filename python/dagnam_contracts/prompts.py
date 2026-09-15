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
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

_MARKER = re.compile(r"^<\|(\w+)\|>\n", re.MULTILINE)
"""One rendered turn's opening marker, as `render_chat_prompt` writes it."""


def render_chat_prompt(messages: Sequence[Mapping[str, str]], *, system: str | None) -> str:
    """Render `messages` (plus an optional `system` prompt) as classifier input.

    ``<|system|>\\n{system}\\n`` once at the top when `system` is given, then
    ``<|{role}|>\\n{content}\\n`` per turn in order. Assistant turns are
    omitted — they are the model's own output, not its input — and every
    other role (``user``, ``tool``, ...) is rendered under its own marker.
    Content is copied verbatim, trailing newlines included.
    """
    parts: list[str] = []
    if system is not None:
        parts.append(f"<|system|>\n{system}\n")
    for message in messages:
        if message["role"] == "assistant":
            continue
        parts.append(f"<|{message['role']}|>\n{message['content']}\n")
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
