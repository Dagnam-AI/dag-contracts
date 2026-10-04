"""The finder behind the `PII_SECRET` class: credentials, in the formats it knows.

A credential is not personal data, but it is the one thing in a prompt that
is worse to leak -- a system prompt that carries an API key hands it to
everyone who can read a report, an excerpt or an uploaded row. So it rides the
same scan and redaction as the PII classes, and like them it is built for
**precision**: every pattern below is syntactic, and each one is pinned in
`tests/hygiene/test_credentials.py` beside the near-misses it must not match
(ordinary words, hex digests, UUIDs, prose that happens to say "token").

**What it finds is the list below, and nothing else.** A credential in none of
these formats is not found and is not redacted. Known misses: a bare AWS secret
access key (40 characters with no name beside them are any base64 run), a key
broken into short hyphenated pieces, a passphrase in prose. Nothing built on
this may say that a row holds no secrets.

* Provider keys by their documented prefix and shape (OpenAI and Anthropic
  ``sk-``, Stripe live keys, AWS key ids, GitHub, Slack -- its rotating
  ``xoxe-`` refresh tokens and ``xoxe.xox?-`` access tokens included -- Google,
  Hugging Face, GitLab). Whole match.
* JWTs: three base64url segments whose first two open a JSON object (``eyJ``).
* PEM private-key blocks, to the END line -- or to the end of the text when a
  truncation cut it off, so the key body never survives a cut.
* ``Bearer <token>``: the token only, and only one of at least 20 characters,
  which is what keeps "the bearer token" and "Bearer of bad news" out.
* ``Basic <base64>``: the base64 only, and only when it decodes to printable
  ``user:password`` text, which keeps "Basic training" out.
* ``scheme://user:password@host``: the password -- whatever the host
  (``localhost`` included). The password runs to the ``@`` that opens the host,
  so an ``@`` inside it does not cut it short; a raw ``/``, ``?`` or ``#`` ends
  it (``postgres://u:pa/ss@host/db`` has no password to find), and it may hold
  percent-encoded forms and a quote, backtick, ``<`` or ``>`` with a letter,
  digit or ``%`` after it. Before punctuation such a character is text around
  the URL (``"http://host:8080","a@b.co"`` is a port and a string), so a password
  where one is followed by punctuation is a known miss, and so is one that
  reads as a port followed by a separator (``http://host:8080,a@b.co`` is a
  port and an address). A URL with a port, or a user and no password, has
  nothing to find. The email pattern also reads ``password@host`` as an
  address; where the two overlap the scan names the one region a secret, and
  the host goes with it.
* A connection string's ``pwd=`` (``Uid=sa;Pwd=...``, ``?user=x&pwd=...``),
  written with no space around the ``=``: the value only. ``PWD`` is also the
  shell's working directory, so a value that starts like a path or a variable
  (``/``, ``~``, ``.``, ``$``, ``%``, a backslash, a backtick, a drive letter)
  is not one, and ``pwd`` is not a credential name anywhere else (``pwd: ...``,
  a JSON key).
* A value assigned with ``:`` or ``=`` to a name like a credential, bare,
  ``snake_``/``kebab-`` prefixed or camelCased: the value only. The names are
  of two kinds:

  - **Unambiguous** -- ``password``, ``passwd``, ``secret``, ``api_key``/
    ``apikey``, ``access_key``, ``secret_access_key``, ``private_key``,
    ``client_secret``: quoted on both sides (``"password": "…"``) the value
    is a credential whatever it looks like; bare (prose, YAML, INI) only when
    it has at least 6 characters with a digit, or at least 16, which keeps
    "password: required" out.
  - **Ambiguous** -- ``token``, ``authorization``, ``auth``, ``key``: only a
    value that is a credential on its own (a shape above; an ``sk-`` key
    with any 20+ run, digits or not, since the name vouches for it; or a run
    of 16+ mixing letters and digits). Token-level NER
    (``{"token": "Paris"}``), a claim status (``"authorization": "approved"``),
    a keyboard key or a count (``max_token=128000``) stays as it is.

  :func:`is_credential_member` is the same rule for a JSON member, whose name
  and value are two separate strings. :func:`is_credential_row_member` is the
  rule for a member of a row itself, whose keys are column names: the
  unambiguous names only (``row_key`` or ``nextPageToken`` names an id column),
  not one that opens with a flag word (``has_password``, ``is_secret``,
  ``top_secret``; the list is `_FLAG_WORDS`), and not a blank or flag-like value
  (``yes``, ``no``, ``true``, ``false``, ``n/a``, ``none``, ``null``, ``-``).
  A bare value stops at a ``:`` that opens the next assignment
  (``token=abc:password=…``), so each one is judged on its own.
* ``sk-`` needs a run of 20+ letters and digits that holds a digit or mixes
  upper and lower case, which a real key has and kebab-case
  (``sk-learn-compatible-estimators``) does not.

These are the raw finders: under an unambiguous name they take any value, a
redaction's own placeholder included. `spans.py` is what never shows them one:
it reads every stretch of text between placeholders on its own.

**A pattern may refuse a candidate on the context around it (a negative
lookaround), but may not REQUIRE context outside its span on a character
another class can redact.** A required neighbour that is replaced by a
placeholder stops being that character, and the finding disappears with it.

Pure -- no I/O.
"""

from __future__ import annotations

import base64
import re

SECRET_PLACEHOLDER = "<SECRET>"
"""What a redacted credential reads as, in place of the ``[REDACTED:<code>]`` form.

A credential is not personal data, and this is the same shape as the masks
the audit's template normalization writes (``<EMAIL>``, ``<NUM>``).
"""

# Each pattern names the span to redact `s`: the whole match for a key with a
# recognisable shape, only the value for `Bearer` and an assignment.
_NOT_AFTER_KEY_CHAR = r"(?<![A-Za-z0-9_-])"
_VALUE_CHAR = r"[^\s\"'`,;&]"
_UNAMBIGUOUS = (
    r"api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret"
    r"|secret(?:[_-]?access)?(?:[_-]?key)?|password|passwd"
)
_AMBIGUOUS = frozenset({"token", "authorization", "auth", "key"})
_NAMES = _UNAMBIGUOUS + "|" + "|".join(sorted(_AMBIGUOUS, key=len, reverse=True))
# A name starts a word, or a camelCase hump (`accessToken`); never mid-word (`mytoken`).
_NAME_START = r"(?:(?<![A-Za-z0-9])|(?<=[a-z0-9])(?=[A-Z]))"
# `scheme://user:password@host`: the password. It runs to the `@` that opens the
# host, and an `@` inside it does not end it when another follows before the host's
# end. A quote, backtick, `<` or `>` is part of a password only with a letter, digit
# or `%` after it, so `"http://host:8080","a@b.co"` and
# `<a href="http://host:8080">a@b.co</a>` are a port and some text, not a password.
#
# The head is a pattern and the password is walked in code, because a password written
# as a repeated group (`(?:plain|quote(?=...)|@(?=...))+`) makes the regex engine keep a
# stack entry per character: 430 MB for a megabyte token. The walk takes the same
# characters, in runs, in memory that does not grow with the token. `test_credentials_flat.py`
# holds it equal to the pattern it replaced on fuzzed text.
#
# The `://` is a negative guard (`(?<!\s)`) and so is what follows the closing `@`
# (`(?!\s)`), never a required neighbour: a character another class redacts (a card number
# ending in the scheme's last letter, an IP address that is the host) must not change the
# answer. A password does not start like a port followed by a separator
# (`:8080,john@x.co` is a port, some text and an address, not a password).
_URL_HEAD = re.compile(r"(?<!\s)://[^\s/?#@:\"'`<>]*:(?!\d{1,5}[,;|&>])")
_PLAIN_RUN = re.compile(r"[^\s/?#@\"'`<>]*")
_QUOTE_CHARS = "\"'`<>"


def _run_end(run: re.Pattern[str], text: str, start: int) -> int:
    """Where the run of ``run`` (a pattern that can match nothing) that begins at ``start`` ends."""
    return next(run.finditer(text, start)).end()


def _is_word_or(char: str, extra: str) -> bool:
    """``[\\w<extra>]``: a letter, a digit, an underscore or one of ``extra``."""
    return char.isalnum() or char in "_" + extra


def _at_opens_the_host(text: str, at: int) -> bool:
    """Whether the ``@`` at ``at`` is inside the password: a word character or `[`, then
    password characters, then another ``@`` (so the password goes on to that one)."""
    size = len(text)
    if at + 1 >= size or not _is_word_or(text[at + 1], "["):
        return False
    position = at + 2
    while True:
        position = _run_end(_PLAIN_RUN, text, position)
        if (
            position + 1 < size
            and text[position] in _QUOTE_CHARS
            and _is_word_or(text[position + 1], "%")
        ):
            position += 1
            continue
        return position < size and text[position] == "@"


def _password_end(text: str, start: int) -> int | None:
    """The ``@`` that ends the password that begins at ``start``, if there is one: the last
    ``@`` the walk reaches that is not followed by whitespace, after at least one character."""
    size = len(text)
    position, end = start, None
    while True:
        position = _run_end(_PLAIN_RUN, text, position)
        char = text[position] if position < size else ""
        if char == "@":
            if position > start and (position + 1 == size or not text[position + 1].isspace()):
                end = position
            if not _at_opens_the_host(text, position):
                return end
        elif not (
            char != ""
            and char in _QUOTE_CHARS
            and position + 1 < size
            and _is_word_or(text[position + 1], "%")
        ):
            return end
        position += 1


def _url_password_spans(text: str) -> list[tuple[int, int]]:
    """Spans of the passwords of every ``scheme://user:password@host`` in ``text``."""
    spans: list[tuple[int, int]] = []
    position = 0
    while (head := _URL_HEAD.search(text, position)) is not None:
        end = _password_end(text, head.end())
        if end is None:
            position = head.start() + 1
        else:
            spans.append((head.end(), end))
            position = end + 1
    return spans


# Credentials by their shape alone, wherever they stand.
_SHAPES: tuple[re.Pattern[str], ...] = (
    re.compile(
        _NOT_AFTER_KEY_CHAR + r"(?P<s>"
        # OpenAI (`sk-`, `sk-proj-`) and Anthropic (`sk-ant-api03-`): prefix
        # segments, then a random run of 20+ with a digit or both cases, then
        # the rest.
        r"sk-(?:[A-Za-z0-9_-]*-)?"
        r"(?:(?=[A-Za-z_]*\d)|(?=[a-z0-9_]*[A-Z])(?=[A-Z0-9_]*[a-z]))"
        r"[A-Za-z0-9_]{20,}[A-Za-z0-9_-]*"
        r"|[rs]k_live_[A-Za-z0-9]{16,}"
        r"|(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])"
        r"|gh[pousr]_[A-Za-z0-9]{36}"
        r"|github_pat_[A-Za-z0-9_]{22,}"
        r"|(?:xoxe\.)?xox[abepr]-[A-Za-z0-9-]{10,}"
        r"|AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])"
        r"|hf_[A-Za-z0-9]{30,}"
        r"|glpat-[A-Za-z0-9_-]{20,}"
        r"|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*"
        r")"
    ),
    re.compile(
        r"(?s)(?P<s>-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
        r".*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z))"
    ),
    re.compile(r"(?i)(?<![a-z0-9])bearer\s+(?P<s>[a-z0-9._~+/-]{19,}[a-z0-9]=*)"),
    # A connection string's `pwd=`, written with no space around the `=`. A
    # path or a variable there is the shell's working directory.
    re.compile(
        r"(?<!\$)" + _NAME_START + r"(?i:pwd)=[\"']?"
        r"(?![/~.$%\\`]|[A-Za-z]:[\\/])(?P<s>" + _VALUE_CHAR + "+)"
    ),
)
_BASIC = re.compile(r"(?i)(?<![a-z0-9])basic\s+(?P<s>[A-Za-z0-9+/]{4,}={0,2})(?![A-Za-z0-9+/=])")
# Credentials by the name they are assigned to; `n` is the name. Quoted name, quoted
# value: JSON, a Python dict, a quoted YAML key. The value is the text up to the next quote
# of the kind that opened it (`s` for a double quote, `t` for a single one), not a repeated
# group of "any character but that quote", which keeps a stack entry per character.
_QUOTED_ASSIGNMENT = re.compile(
    _NAME_START + rf"(?P<n>(?i:{_NAMES}))[\"']\s*[:=]\s*"
    r"(?:\"(?P<s>[^\"\n]+)\"|'(?P<t>[^'\n]+)')"
)
# Bare or half-quoted: prose, YAML, INI, a shell export. The value is a run of
# `_VALUE_CHAR`, cut short before a `:` that opens the next assignment
# (`token=abc:password=...`), and it is a value when it has 6 characters with a digit
# or 16. Walked in code rather than as a repeated group, which keeps a stack entry per
# character (200 MB for a megabyte value); `test_credentials_flat.py` holds this equal
# to the pattern it replaced.
_ASSIGNMENT_HEAD = re.compile(_NAME_START + rf"(?P<n>(?i:{_NAMES}))[\"']?\s*[:=]\s*[\"']?")
_VALUE_RUN = re.compile(_VALUE_CHAR + "*")
_NEXT_ASSIGNMENT = re.compile(rf":\s*(?i:{_NAMES})[\"']?\s*[:=]")
_DIGIT = re.compile(r"\d")


def _bare_assignments(text: str) -> list[tuple[str, int, int]]:
    """``(name, start, end)`` of every bare value assigned to a name like a credential."""
    found: list[tuple[str, int, int]] = []
    position = 0
    run_end = -1  # the run of value characters containing `start`, once computed
    while (head := _ASSIGNMENT_HEAD.search(text, position)) is not None:
        start = head.end()
        if start > run_end:
            run_end = _run_end(_VALUE_RUN, text, start)
        end = run_end
        colon = text.find(":", start, end)
        while colon != -1 and _NEXT_ASSIGNMENT.match(text, colon) is None:
            colon = text.find(":", colon + 1, end)
        if colon != -1:
            end = colon
        if end - start >= 16 or (end - start >= 6 and _DIGIT.search(text, start, end)):
            found.append((head["n"], start, end))
            position = end
        else:
            position = head.start() + 1
    return found


_MEMBER_NAME = re.compile(rf"(?:^|[^a-z0-9])(?P<n>{_NAMES})$")
# ponytail: "high entropy" is a character-class proxy (16+, letters AND digits,
# no spaces), not a measured entropy; add a Shannon floor if ids trip it.
_HIGH_ENTROPY = re.compile(r"(?=[^\s]*[A-Za-z])(?=[^\s]*\d)[A-Za-z0-9._~+/=-]{16,}")
# An `sk-` key under a name that vouches for it: any 20+ run, digits or not.
_VOUCHED_KEY = re.compile(r"(?<![A-Za-z0-9_-])sk-(?:[A-Za-z0-9_-]*-)?[A-Za-z0-9_]{20,}")


def _is_user_pass(b64: str) -> bool:
    """Whether ``b64`` decodes to printable ``user:password`` text, as a Basic header carries."""
    try:
        decoded = base64.b64decode(b64, validate=True).decode("ascii")
    except ValueError:
        return False
    return decoded.isprintable() and ":" in decoded


def _shape_spans(text: str) -> list[tuple[int, int]]:
    """Spans of every credential ``text`` carries by its shape alone, name or no name."""
    return (
        [m.span("s") for pattern in _SHAPES for m in pattern.finditer(text)]
        + _url_password_spans(text)
        + [m.span("s") for m in _BASIC.finditer(text) if _is_user_pass(m["s"])]
    )


def _looks_like_credential(value: str) -> bool:
    """A value that is a credential on its own, once a name has vouched for it."""
    return (
        bool(_shape_spans(value))
        or _VOUCHED_KEY.search(value) is not None
        or _HIGH_ENTROPY.fullmatch(value) is not None
    )


def _is_credential(name: str, value: str) -> bool:
    """A non-empty value under an unambiguous name; one that looks like it under an ambiguous one."""
    if name.lower() in _AMBIGUOUS:
        return _looks_like_credential(value)
    return bool(value)


def _snake(key: str) -> str:
    """``key`` in lower snake case: a camelCase hump becomes a word boundary."""
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key).lower()


def _credential_name(key: str) -> str | None:
    """The credential name ``key`` is or ends with, prefixed or camelCased; else ``None``."""
    match = _MEMBER_NAME.search(_snake(key))
    return match["n"] if match else None


def is_credential_member(key: str, value: str) -> bool:
    """Whether the JSON member ``key: value`` holds a credential, by the rule above.

    ``value`` is the member's text (a number's JSON text). The key may carry a
    prefix (``db_password``, ``x-api-key``, ``aws_secret_access_key``) or be
    camelCased (``accessToken``); a longer name (``password_hint``,
    ``token_count``, ``maxTokens``) is not a credential name at all.
    """
    name = _credential_name(key)
    return name is not None and _is_credential(name, value)


# A name that opens with one of these is a flag or a label about the credential
# (``has_password``, ``is_secret``, ``top_secret``), not the credential.
_FLAG_WORDS = frozenset(
    {
        "has",
        "is",
        "needs",
        "requires",
        "use",
        "allow",
        "enable",
        "enabled",
        "show",
        "with",
        "no",
        "top",
    }
)
# What a column that names a credential holds when it holds none.
_NO_VALUE = frozenset({"yes", "no", "true", "false", "n/a", "none", "null", "-"})


def _is_row_name(key: str) -> bool:
    """Whether the column ``key`` of a row names a credential.

    It does when, in lower snake case, it is one of the unambiguous names or ends in
    one as a word of its own (``password``, ``db_password``, ``userPassword``,
    ``aws-secret-access-key``) -- and its first word is not ``has``, ``is``, ``needs``,
    ``requires``, ``use``, ``allow``, ``enable``, ``enabled``, ``show``, ``with``,
    ``no`` or ``top``, which makes it a flag or a label (``has_password``,
    ``is_secret``, ``top_secret``). A name where the credential word is not the last
    (``password_hint``), a name an id column carries (``row_key``, ``nextPageToken``:
    the ambiguous names) and a longer word (``passwords``, ``mysecret``) are not.
    """
    name = _credential_name(key)
    return (
        name is not None
        and name not in _AMBIGUOUS
        and re.split(r"[^a-z0-9]+", _snake(key), maxsplit=1)[0] not in _FLAG_WORDS
    )


def is_credential_row_member(key: str, value: str) -> bool:
    """Whether the member ``key: value`` of a row itself holds a credential: a value
    under a column :func:`_is_row_name` accepts, that is neither blank nor
    a flag-like word (``yes``, ``no``, ``true``, ``false``, ``n/a``, ``none``,
    ``null``, ``-``, in any case) -- anything else, a short word included, is one.

    A row's keys are column names, and an ambiguous name is an id column's too
    (``row_key``, ``idempotency_key``, ``nextPageToken``). Taking an id of 16+
    letters and digits there would count every row of a dataset keyed on one,
    and a drop policy would lose them all. A credential in a known format under
    such a name is still found: the value is scanned as text.
    """
    return _is_row_name(key) and value.strip().lower() not in _NO_VALUE | {""}


def find_secrets(text: str) -> list[tuple[int, int]]:
    """Spans of every credential in ``text``; two patterns over one secret are one span."""
    spans = sorted(
        _shape_spans(text)
        + [
            m.span("s" if m["s"] is not None else "t")
            for m in _QUOTED_ASSIGNMENT.finditer(text)
            if _is_credential(m["n"], m["s"] or m["t"])
        ]
        + [(a, b) for name, a, b in _bare_assignments(text) if _is_credential(name, text[a:b])]
    )
    merged: list[tuple[int, int]] = []
    for start, end in spans:
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


__all__ = [
    "SECRET_PLACEHOLDER",
    "find_secrets",
    "is_credential_member",
    "is_credential_row_member",
]
