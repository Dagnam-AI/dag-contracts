"""Byte-exact tests for `dagnam_contracts/prompts.py`.

Training and serving both call `render_chat_prompt`, so the fixture strings
here ARE the contract: a change to any of them is a train/serve skew.
"""

from __future__ import annotations

from dagnam_contracts.prompts import parse_chat_prompt, render_chat_prompt


def test_render_chat_prompt_is_byte_exact_and_drops_assistant_turns() -> None:
    text = render_chat_prompt(
        [
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": "x"},
            {"role": "user", "content": "again"},
        ],
        system="Label it.",
    )
    assert text == "<|system|>\nLabel it.\n<|user|>\nhi\n<|user|>\nagain\n"


def test_render_chat_prompt_without_system() -> None:
    assert render_chat_prompt([{"role": "user", "content": "hi"}], system=None) == "<|user|>\nhi\n"


def test_render_chat_prompt_with_no_messages() -> None:
    assert render_chat_prompt([], system=None) == ""
    assert render_chat_prompt([], system="Label it.") == "<|system|>\nLabel it.\n"


def test_render_chat_prompt_keeps_a_non_user_non_assistant_role_as_its_own_marker() -> None:
    """Only assistant turns are the model's own output; every other role is
    input and is rendered under its own marker rather than silently dropped."""
    text = render_chat_prompt(
        [{"role": "tool", "content": "42"}, {"role": "user", "content": "ok"}], system=None
    )
    assert text == "<|tool|>\n42\n<|user|>\nok\n"


def test_render_chat_prompt_preserves_content_bytes_including_trailing_newlines() -> None:
    text = render_chat_prompt([{"role": "user", "content": "a\n\n"}], system="s\n")
    assert text == "<|system|>\ns\n\n<|user|>\na\n\n\n"


def test_render_chat_prompt_is_deterministic() -> None:
    messages = [{"role": "user", "content": "same"}]
    assert render_chat_prompt(messages, system="s") == render_chat_prompt(messages, system="s")


def test_parse_chat_prompt_inverts_the_rendering() -> None:
    messages = [
        {"role": "user", "content": "hi"},
        {"role": "tool", "content": "42"},
        {"role": "user", "content": "again"},
    ]
    assert parse_chat_prompt(render_chat_prompt(messages, system=None)) == messages


def test_parse_chat_prompt_reads_a_system_prompt_back_as_its_own_turn() -> None:
    """`render_chat_prompt` renders the system prompt as a marker block like any
    other, so the inverse reads it back as one; a caller that wants it separate
    splits on the role, which is what the marker records."""
    text = render_chat_prompt([{"role": "user", "content": "hi"}], system="Label it.")
    assert parse_chat_prompt(text) == [
        {"role": "system", "content": "Label it."},
        {"role": "user", "content": "hi"},
    ]


def test_parse_chat_prompt_keeps_a_chunk_before_the_first_marker() -> None:
    """A row truncated from the front has no leading marker; dropping the chunk
    would drop text the classifier actually saw, so it becomes a user turn."""
    assert parse_chat_prompt("cut off\n<|user|>\nhi\n") == [
        {"role": "user", "content": "cut off"},
        {"role": "user", "content": "hi"},
    ]
    assert parse_chat_prompt("no markers at all") == [
        {"role": "user", "content": "no markers at all"}
    ]


def test_parse_chat_prompt_of_empty_text_is_empty() -> None:
    assert parse_chat_prompt("") == []


def test_parse_chat_prompt_strips_only_the_renderings_own_trailing_newline() -> None:
    """The renderer appends exactly one newline per turn, so exactly one comes
    back off -- content that ended in a blank line keeps it."""
    text = render_chat_prompt([{"role": "user", "content": "a\n\n"}], system=None)
    assert parse_chat_prompt(text) == [{"role": "user", "content": "a\n\n"}]
