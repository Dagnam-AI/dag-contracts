"""The finder behind the `PII_SECRET` class: credentials that must never be trained on.

A credential is not personal data, but it is the one thing in a prompt that
is worse to leak -- a system prompt that carries an API key hands it to
everyone who can read a report, an excerpt or an uploaded row. So it rides the
same scan and redaction as the PII classes, and like them it is built for
**precision**: every pattern below is syntactic, and each one is pinned in
`tests/hygiene/test_credentials.py` beside the near-misses it must not match
(ordinary words, hex digests, UUIDs, prose that happens to say "token").

* Provider keys by their documented prefix and shape (OpenAI and Anthropic
  ``sk-``, Stripe live keys, AWS key ids, GitHub, Slack, Google, Hugging Face,
  GitLab). Whole match.
* JWTs: three base64url segments whose first two open a JSON object (``eyJ``).
* PEM private-key blocks, to the END line -- or to the end of the text when a
  truncation cut it off, so the key body never survives a cut.
* ``Bearer <token>``: the token only, and only one of at least 20 characters,
  which is what keeps "the bearer token" and "Bearer of bad news" out.
* ``Basic <base64>``: the base64 only, and only when it decodes to printable
  ``user:password`` text, which keeps "Basic training" out.
* A value assigned with ``:`` or ``=`` to a name like a credential, bare,
  ``snake_``/``kebab-`` prefixed or camelCased: the value only. The names are
  of two kinds (the owner's rule):

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
  and value are two separate strings. A bare value stops at a ``:`` that opens
  the next assignment (``token=abc:password=…``), so each one is judged on
  its own.
* ``sk-`` needs a run of 20+ letters and digits that holds a digit or mixes
  upper and lower case, which a real key has and kebab-case
  (``sk-learn-compatible-estimators``) does not.

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
# Credentials by their shape alone, wherever they stand.
_SHAPES: tuple[re.Pattern[str], ...] = (
    re.compile(
        _NOT_AFTER_KEY_CHAR + r"(?P<s>"
        # OpenAI (`sk-`, `sk-proj-`) and Anthropic (`sk-ant-api03-`): prefix
        # segments, then a random run of 20+ with a digit or both cases, then
        # the rest.
        r"sk-(?:[A-Za-z0-9_]*-)*"
        r"(?:(?=[A-Za-z_]*\d)|(?=[a-z0-9_]*[A-Z])(?=[A-Z0-9_]*[a-z]))"
        r"[A-Za-z0-9_]{20,}[A-Za-z0-9_-]*"
        r"|[rs]k_live_[A-Za-z0-9]{16,}"
        r"|(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])"
        r"|gh[pousr]_[A-Za-z0-9]{36}"
        r"|github_pat_[A-Za-z0-9_]{22,}"
        r"|xox[abpr]-[A-Za-z0-9-]{10,}"
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
)
_BASIC = re.compile(r"(?i)(?<![a-z0-9])basic\s+(?P<s>[A-Za-z0-9+/]{4,}={0,2})(?![A-Za-z0-9+/=])")
# A bare value stops before a `:` that opens the next assignment.
_BARE_CHAR = rf"(?:(?!:\s*(?i:{_NAMES})[\"']?\s*[:=]){_VALUE_CHAR})"
# Credentials by the name they are assigned to; `n` is the name.
_ASSIGNMENTS: tuple[re.Pattern[str], ...] = (
    # Quoted name, quoted value: JSON, a Python dict, a quoted YAML key.
    re.compile(
        _NAME_START + rf"(?P<n>(?i:{_NAMES}))[\"']\s*[:=]\s*(?P<q>[\"'])"
        r"(?P<s>(?:(?!(?P=q))[^\n])+)(?P=q)"
    ),
    # Bare or half-quoted: prose, YAML, INI, a shell export.
    re.compile(
        _NAME_START + rf"(?P<n>(?i:{_NAMES}))[\"']?\s*[:=]\s*[\"']?"
        rf"(?P<s>(?={_BARE_CHAR}*\d){_BARE_CHAR}{{6,}}|{_BARE_CHAR}{{16,}})"
    ),
)
_MEMBER_NAME = re.compile(rf"(?:^|[^a-z0-9])(?P<n>{_NAMES})$")
# ponytail: "high entropy" is a character-class proxy (16+, letters AND digits,
# no spaces), not a measured entropy; add a Shannon floor if ids trip it.
_HIGH_ENTROPY = re.compile(r"(?=[^\s]*[A-Za-z])(?=[^\s]*\d)[A-Za-z0-9._~+/=-]{16,}")
# An `sk-` key under a name that vouches for it: any 20+ run, digits or not.
_VOUCHED_KEY = re.compile(r"(?<![A-Za-z0-9_-])sk-(?:[A-Za-z0-9_]*-)*[A-Za-z0-9_]{20,}")


def _is_user_pass(b64: str) -> bool:
    """Whether ``b64`` decodes to printable ``user:password`` text, as a Basic header carries."""
    try:
        decoded = base64.b64decode(b64, validate=True).decode("ascii")
    except ValueError:
        return False
    return decoded.isprintable() and ":" in decoded


def _shape_spans(text: str) -> list[tuple[int, int]]:
    """Spans of every credential ``text`` carries by its shape alone, name or no name."""
    return [m.span("s") for pattern in _SHAPES for m in pattern.finditer(text)] + [
        m.span("s") for m in _BASIC.finditer(text) if _is_user_pass(m["s"])
    ]


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


def is_credential_member(key: str, value: str) -> bool:
    """Whether the JSON member ``key: value`` holds a credential, by the rule above.

    ``value`` is the member's text (a number's JSON text). The key may carry a
    prefix (``db_password``, ``x-api-key``, ``aws_secret_access_key``) or be
    camelCased (``accessToken``); a longer name (``password_hint``,
    ``token_count``, ``maxTokens``) is not a credential name at all.
    """
    snake = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key).lower()
    match = _MEMBER_NAME.search(snake)
    return match is not None and _is_credential(match["n"], value)


def find_secrets(text: str) -> list[tuple[int, int]]:
    """Spans of every credential in ``text``; two patterns over one secret are one span."""
    spans = sorted(
        _shape_spans(text)
        + [
            m.span("s")
            for pattern in _ASSIGNMENTS
            for m in pattern.finditer(text)
            if _is_credential(m["n"], m["s"])
        ]
    )
    merged: list[tuple[int, int]] = []
    for start, end in spans:
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


__all__ = ["SECRET_PLACEHOLDER", "find_secrets", "is_credential_member"]
