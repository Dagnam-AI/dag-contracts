"""Tests for `dagnam_contracts/hygiene/credentials.py` — the `PII_SECRET` finder.

One positive per pattern and the near-misses each one must NOT match. Every
fake key is assembled at runtime from a split prefix, so the repository never
carries a literal that a push-protection scanner would mistake for a leak.
"""

from __future__ import annotations

import base64
import json

import pytest

from dagnam_contracts.hygiene.credentials import (
    SECRET_PLACEHOLDER,
    find_secrets,
    is_credential_member,
)

_BODY = "a1B2c3D4e5F6g7H8i9J0"


def _key(prefix: str, length: int) -> str:
    """``prefix`` plus ``length`` characters of a mixed-case alphanumeric body."""
    return prefix + (_BODY * (length // len(_BODY) + 1))[:length]


def _b64(value: dict[str, object]) -> str:
    return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()


# The A-11 fixture: a digitless key the campaign's own scan found in a prompt.
_A11 = "s" + "k-live-AbCdEfGhIjKlMnOpQrStUvWx"
_JWT = ".".join([_b64({"alg": "HS256", "typ": "JWT"}), _b64({"sub": "1234567890"}), _key("", 43)])
_PRIVATE_KEY = "PRIVATE" + " KEY"
_PEM = f"-----BEGIN RSA {_PRIVATE_KEY}-----\nMIIEow{_BODY}\n-----END RSA {_PRIVATE_KEY}-----"


def _found(text: str) -> list[str]:
    return [text[start:end] for start, end in find_secrets(text)]


# (pattern, text, the one secret in it). Each prefix is split so the source
# holds no scannable literal.
POSITIVES: list[tuple[str, str, str]] = [
    ("openai", "key {} end", _key("s" + "k-", 48)),
    ("openai-project", "key {} end", _key("s" + "k-proj-", 60)),
    ("anthropic", "key {} end", _key("s" + "k-ant-api03-", 80)),
    ("stripe-secret", "key {} end", _key("sk" + "_live_", 24)),
    ("stripe-restricted", "key {} end", _key("rk" + "_live_", 24)),
    ("aws-akia", "id {} end", "AK" + "IA" + "IOSFODNN7EXAMPLE"),
    ("aws-asia", "id {} end", "AS" + "IA" + "IOSFODNN7EXAMPLE"),
    ("github-classic", "use {} now", _key("gh" + "p_", 36)),
    ("github-oauth", "use {} now", _key("gh" + "o_", 36)),
    ("github-fine-grained", "use {} now", _key("github" + "_pat_", 82)),
    ("slack", "tok {} end", _key("xo" + "xb-", 40)),
    ("google", "key={}&q=1", _key("AI" + "za", 35)),
    ("huggingface", "tok {} end", _key("h" + "f_", 34)),
    ("gitlab", "tok {} end", _key("gl" + "pat-", 20)),
    ("jwt", "cookie {} end", _JWT),
    ("bearer", "Authorization: Bearer {}", _key("", 32)),
    ("bearer-lowercase", "authorization: bearer {}", _key("", 32)),
    ("pem", "key:\n{}\nthanks", _PEM),
    ("assignment-api-key", "OPENAI_API_KEY={}", "abc123def456"),
    ("assignment-password", "password: {} please", "hunter2"),
    ("assignment-quoted", 'secret = "{}"', "a-very-long-passphrase"),
    ("assignment-secret-key", "SECRET_KEY={}", "django-insecure-9x"),
    ("assignment-token", "access_token={}&x=1", "ya29" + ".a0AfH6SMBx9876543210abcdef"),
    ("assignment-passwd", "passwd:{};", "s3cr3t!"),
    # C2b: named credentials in JSON, dict, YAML and INI form.
    ("json-quoted-key", 'Config: {{"api_key": "{}"}}', "abcd1234efgh5678"),
    ("json-prefixed-key", 'Config: {{"db_password": "{}"}}', "Sup3rS3cret"),
    # An unambiguous quoted name with a quoted value: whatever the value is.
    ("dict-single-quotes", "{{'password': '{}'}}", "letmein"),
    # R1: an ambiguous name, with a value that is a credential on its own.
    ("token-with-a-key", "{{'token': '{}'}}", _key("gh" + "p_", 36)),
    ("token-high-entropy", 'token: "{}"', "abc123def456ghi789"),
    ("auth-bearer", '{{"auth": "{}"}}', "Bearer " + _key("", 24)),
    # H1: a known key shape needs no digit when a name vouches for it -- and a
    # mixed-case run needs none even bare.
    ("a11-bare", "use {} now", _A11),
    ("a11-under-auth-text", "auth: {}", _A11),
    ("a11-under-token-text", "token: {}", _A11),
    ("a11-under-auth-json", '{{"auth": "{}"}}', _A11),
    ("vouched-lowercase-sk", '{{"key": "{}"}}', "s" + "k-abcdefghijklmnopqrstuvwxyz"),
    # H3: an HTTP request dump's Basic header.
    ("basic-header", "Authorization: Basic {}", "dXNlcjpwYXNzd29yZA=="),
    ("basic-header-lowercase", "authorization: basic {}\nHost: x", "dXNlcjpwYXNz"),
    ("json-authorization", '{{"Authorization": "{}"}}', "Basic dXNlcjpwYXNz"),
    ("ini-aws-secret", "aws_secret_access_key = {}", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("yaml-client-secret", "client_secret: {}", "abc123def456ghi"),
    ("yaml-private-key", "private_key: {}", "k3y-a1B2c3D4"),
    ("ini-access-key", "access_key = {}", "abc123def4567"),
    ("apikey", "apikey={}", "abc123def456"),
    ("camel-case", 'accessToken: "{}"', "ya29" + ".a0AfH6SMBx9876543210abcdef"),
    # A provider whose `sk-` keys are 32 lowercase hex characters.
    ("sk-hex", "key {} end", "s" + "k-0123456789abcdef0123456789abcdef"),
]


@pytest.mark.parametrize(
    ("pattern", "template", "secret"), POSITIVES, ids=[p[0] for p in POSITIVES]
)
def test_each_pattern_finds_exactly_its_secret(pattern: str, template: str, secret: str) -> None:
    assert _found(template.format(secret)) == [secret], pattern


def test_a_pem_block_cut_before_its_end_line_is_redacted_to_the_end() -> None:
    """A front- or back-truncated row can lose the END line; the key body must not survive."""
    text = f"key:\n-----BEGIN {_PRIVATE_KEY}-----\nMIIEow{_BODY}"
    assert _found(text) == [text[5:]]


def test_the_audit_excerpt_token_is_found() -> None:
    """A-11: the excerpt a run published kept this header verbatim, and the rows did too."""
    token = "s" + "k-live-AbCdEfGhIjKlMnOpQrStUvWx"
    text = f"Jane Doe (<EMAIL>). Auth header: Bearer {token}. Be polite."
    assert _found(text) == [token]


def test_overlapping_patterns_report_one_span() -> None:
    """``Bearer sk-...`` and ``api_key=sk-...`` match two patterns; that is one secret."""
    key = _key("s" + "k-", 48)
    assert _found(f"Authorization: Bearer {key}") == [key]
    assert _found(f"api_key={key}") == [key]


NEGATIVES: list[tuple[str, str]] = [
    ("ordinary words", "Please ask the desk-side team about their skills and tokens."),
    ("hex sha1", "commit da39a3ee5e6b4b0d3255bfef95601890afd80709 fixed it"),
    ("hex sha256", "digest e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ("uuid", "request 123e4567-e89b-12d3-a456-426614174000 failed"),
    ("bearer prose", "Bearer of bad news: the bearer token goes in a header."),
    ("assignment to a word", "password: required. Secret: patience. Token: a unit of text."),
    ("short assignment", "token: 5, api_key=<NUM>"),
    ("plural name", "max_tokens=1024 and secrets: 12345678"),
    ("embedded name", "mytoken=abc123def456"),
    ("hyphenated slug", "a task-oriented-dialogue-system-for-banking"),
    ("short sk", "use sk-learn today"),
    ("aws too short", "AK" + "IA" + "IOSFODNN7EXAMP"),
    ("aws too long", "AK" + "IA" + "IOSFODNN7EXAMPLEX"),
    ("one jwt segment", _b64({"alg": "HS256"})),
    ("hf identifier", "call hf_hub_download for it"),
    ("public key", "-----BEGIN PUBLIC KEY-----\nMIIBIjAN\n-----END PUBLIC KEY-----"),
    ("github short", "gh" + "p_short"),
    # N4: kebab-case that starts `sk-`, and token counts that are numbers.
    ("sk kebab-case", "use sk-learn-compatible-estimators"),
    ("sk url slug", "see /sk-slovak-language-course-2024 for more"),
    ("sk css class", 'class="sk-button-primary-large-rounded"'),
    ("numeric token", "max_token=1024000, token: 128000, token=1234567 (the vocabulary id)"),
    ("numeric quoted token", '{"max_token": "4096"}'),
    ("longer name", '{"password_hint": "your first pet"}'),
    ("empty quoted value", '{"password": ""}'),
    # R1: ordinary data under an ambiguous name stays as it is.
    ("ner token", '{"token": "Paris", "label": "LOC"}'),
    ("pos token", "[{'token': 'the', 'pos': 'DET'}]"),
    ("claim authorization", '{"authorization": "approved", "amount": 2}'),
    ("keyboard key", 'key: "Enter", auth: pending'),
    ("short mixed token", "token: abc123"),
    # H1: a lowercase run with no digit is still not a key when nothing vouches.
    ("sk lowercase run", "see sk-verylongidentifierwithoutdashes"),
    ("sk kebab under a name", '{"key": "sk-learn-compatible-estimators"}'),
    # H2: a rejected value stops at the next assignment; it does not become one.
    ("colon after rejected value", "token=abc:note=hello"),
    # H3: `Basic` followed by a word, or by base64 that is not `user:pass`.
    ("basic prose", "Basic training for recruits. Basic auth is weak."),
    ("basic not user:pass", "Authorization: Basic dHJhaW5pbmc="),
]


@pytest.mark.parametrize(("case", "text"), NEGATIVES, ids=[n[0] for n in NEGATIVES])
def test_near_misses_are_not_secrets(case: str, text: str) -> None:
    assert find_secrets(text) == [], case


def test_the_placeholder_is_the_documented_one() -> None:
    assert SECRET_PLACEHOLDER == "<SECRET>"


def test_every_named_credential_in_a_config_line_is_found() -> None:
    """N2: the closing quote of a JSON key used to defeat the assignment rule."""
    text = 'Config: {"api_key": "abcd1234efgh5678", "db_password": "Sup3rS3cret"}'
    assert _found(text) == ["abcd1234efgh5678", "Sup3rS3cret"]


@pytest.mark.parametrize(
    ("key", "value", "expected"),
    [
        ("password", "a", True),
        ("db_password", "hunter22", True),
        ("apiKey", "12345", True),
        ("X-Api-Key", "abc", True),
        ("Authorization", "Basic dXNlcjpwYXNz", True),
        ("aws_secret_access_key", "wJalr", True),
        ("clientSecret", "s", True),
        ("private_key", "k", True),
        ("accessToken", "t", False),
        ("accessToken", "ya29.a0AfH6SMBx9876543210abcdef", True),
        ("max_token", "1024", False),
        ("token", "1,024.5", False),
        ("password", "", False),
        ("password_hint", "pet", False),
        ("token_count", "abc123def456", False),
        ("maxTokens", "abc", False),
        ("tokenizer", "bert-base", False),
        # R1: unambiguous names take any value...
        ("password", "string", True),
        ("secret_key", "x", True),
        ("passwd", "hunter", True),
        # ...ambiguous ones only a value that is a credential on its own.
        ("token", "Paris", False),
        ("token", _key("gh" + "p_", 36), True),
        ("token", "abc123def456ghi789", True),
        ("token", "abcdefghijklmnopqrstuvwxyz", False),
        ("token", "2024-09-27", False),
        ("authorization", "approved", False),
        ("Authorization", "Bearer " + _JWT, True),
        ("auth", "Bearer " + _key("", 24), True),
        ("key", "Enter", False),
        ("primary_key", "id", False),
        ("key", _key("s" + "k-", 48), True),
        ("nextPageToken", "abc", False),
        ("Authorization", "Basic not-base64!", False),
        ("Authorization", "Basic abcde", False),  # base64-shaped, but does not decode
        ("Authorization", "Basic /w==", False),  # decodes, but to a byte that is not text
        # H1: a vouched-for key shape needs no digit.
        ("auth", _A11, True),
        ("token", _A11, True),
        ("key", "s" + "k-abcdefghijklmnopqrstuvwxyz", True),
        ("key", "sk-learn-compatible-estimators", False),
        ("Authorization", "Basic dHJhaW5pbmc=", False),
    ],
)
def test_a_member_is_a_credential_by_its_key_whatever_its_value(
    key: str, value: str, expected: bool
) -> None:
    """C2b as the owner settled it (R1).

    Under an unambiguous name (``password``, ``secret``, ``api_key``, ...) the
    value is a credential however it looks. Under an ambiguous one (``token``,
    ``authorization``, ``auth``, ``key``) only when it is a credential on its
    own: a known key shape, a JWT, ``Bearer``/``Basic`` credentials, or a run
    of 16+ that mixes letters and digits -- so token-level NER (``"Paris"``),
    a claim status (``"approved"``) or a count (``1024``) stays as it is.
    """
    assert is_credential_member(key, value) is expected


@pytest.mark.parametrize(
    ("text", "secrets"),
    [
        ("token=abc:password=hunter22", ["hunter22"]),
        ("key=xxxxxxxxxxxxxxxxxxxxxx:password=abc123def", ["abc123def"]),
        ("token=abc123def456ghi789:password=hunter22", ["abc123def456ghi789", "hunter22"]),
        ("api_key=abc123def;token=abc&password=hunter22", ["abc123def", "hunter22"]),
        # A `:` that does not start another assignment is part of the value.
        ("password=abc:123def", ["abc:123def"]),
    ],
)
def test_each_assignment_in_a_run_is_judged_on_its_own(text: str, secrets: list[str]) -> None:
    """H2: a rejected `token=` value ran on over the `:password=` after it."""
    assert _found(text) == secrets
