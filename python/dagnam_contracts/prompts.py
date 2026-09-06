"""The one rendering of a chat request as classifier input text.

A text classifier trained on chat data must see, at serving time, byte-for-byte
the text it saw in training. Training-side derivation and the serving-side
chat-completions bridge both call `render_chat_prompt`, so there is exactly one
place the format can change — and a change here is a train/serve skew, which is
why `tests/test_prompts.py` pins the output byte-for-byte.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence


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


__all__ = ["render_chat_prompt"]
