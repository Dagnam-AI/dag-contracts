"""The two finders that read a run of text in code: phone numbers and email addresses.

A number is found by a pattern and then read on, and an address by its head and then its
domain, in code rather than as one repeated regex group: a group that repeats once per
character (or per label) keeps a stack entry per repetition in the regex engine, which for
one unbroken megabyte cost 60 MB or more. `detectors.py` registers them.

Pure -- no I/O.
"""

from __future__ import annotations

import re

# Not preceded by a digit, a `+`, or a digit-then-separator: the last of the
# three is what stops a 16-digit card number from yielding a 12-digit "phone"
# starting at its second group.
# `(?![\d]|[ -]\d)` is the important half: without it the pattern backtracks
# out of a 16-digit card number and reports its first 12 digits as a phone.
_PHONE_CANDIDATE = re.compile(r"(?<![\d+])(?<![\d][ -])\+?\d(?:[\d\s.()-]{7,20})\d(?![\d]|[ -]\d)")


def _phone_ok(raw: str) -> bool:
    """The filters on top of the pattern, each removing a false positive the corpus
    actually produced: a leading ``+`` admits 9-15 digits, without one the floor rises
    to 10 (which is what stops a dashed 9-digit US SSN reading as a phone number); and
    at least one separator or a leading ``+`` is required (a bare digit run is an order
    id far more often than a phone number)."""
    digits = re.sub(r"\D", "", raw)
    international = raw.startswith("+")
    if not (9 if international else 10) <= len(digits) <= 15:
        return False
    return international or re.search(r"[\s.()-]", raw) is not None


# A number right after an accepted one, across at most one space or hyphen, without the
# lookbehinds. The accepted number's last digit is what those lookbehinds would refuse
# the next number for, and once the first is replaced that digit is gone: the next
# number is a finding then, so it is found now, and a list of numbers is one read.
_PHONE_NEXT = re.compile(r"[ -]?(?P<s>\+?\d(?:[\d\s.()-]{7,20})\d(?![\d]|[ -]\d))")


def find_phones(text: str) -> list[tuple[int, int]]:
    """Spans that look like a dialable number rather than a long id.

    A list of numbers separated by one space or hyphen is found whole. No trailing
    digit is allowed, so a 23-digit id cannot yield a 14-digit "phone" from its
    prefix.

    The chain reads on from a number only as far as the next number the pattern finds
    with its lookbehinds: the body of a number takes digits, spaces and parentheses, so
    left alone it would run into the area code of a parenthesised number that follows
    and take its ``(415`` with it, stranding the seven digits behind.
    """
    ordinary = [m.span() for m in _PHONE_CANDIDATE.finditer(text) if _phone_ok(m.group())]
    spans: list[tuple[int, int]] = []
    for index, (start, end) in enumerate(ordinary):
        spans.append((start, end))
        position = end
        stop = ordinary[index + 1][0] if index + 1 < len(ordinary) else len(text)
        while (after := _PHONE_NEXT.match(text, position, stop)) is not None and _phone_ok(
            after["s"]
        ):
            spans.append(after.span("s"))
            position = after.end()
    return spans


# An address is a local part, an ``@`` and a domain of dot-separated labels with at least
# one dot. The pattern finds the head (the local part and the ``@``, which cannot start in
# the middle of a word); the labels are read in code, because a repeated group of them
# (`(?:\.[\w-]+)+`) makes the regex engine keep a stack entry per label: 60 MB for a
# megabyte token. `test_detectors.py` holds this equal to the pattern it replaced.
_EMAIL_HEAD = re.compile(r"(?<![\w.+-])[\w.+-]+@")
_DOMAIN_RUN = re.compile(r"[\w.-]*")


def _domain_end(text: str, start: int) -> int | None:
    """The end of the domain that begins at ``start``: labels of word characters and
    hyphens between single dots, at least one dot; ``None`` when there is none."""
    end = next(_DOMAIN_RUN.finditer(text, start)).end()
    double = text.find("..", start, end)
    if double != -1:
        end = double
    while end > start and text[end - 1] == ".":
        end -= 1
    first_dot = text.find(".", start, end)
    if first_dot == -1 or first_dot == start:
        return None
    return end


def find_emails(text: str) -> list[tuple[int, int]]:
    """Every address. ``pw@host`` after a URL password is one too: where the two
    classes overlap, the scan's overlap resolution names the region a secret."""
    spans: list[tuple[int, int]] = []
    position = 0
    while (head := _EMAIL_HEAD.search(text, position)) is not None:
        end = _domain_end(text, head.end())
        if end is None:
            position = head.end()
        else:
            spans.append((head.start(), end))
            position = end
    return spans


__all__ = ["find_emails", "find_phones"]
