"""Tests for `dagnam_contracts/hygiene/credentials.py` — the `PII_SECRET` finder.

One positive per pattern and the near-misses each one must NOT match. Every
fake key is assembled at runtime from a split prefix, so the repository never
carries a literal that a push-protection scanner would mistake for a leak.
"""

from __future__ import annotations

import base64
import json
import time

import pytest

from dagnam_contracts.hygiene.credentials import (
    SECRET_PLACEHOLDER,
    find_secrets,
    is_credential_member,
    is_credential_row_member,
)

_BODY = "a1B2c3D4e5F6g7H8i9J0"


def _key(prefix: str, length: int) -> str:
    """``prefix`` plus ``length`` characters of a mixed-case alphanumeric body."""
    return prefix + (_BODY * (length // len(_BODY) + 1))[:length]


def _b64(value: dict[str, object]) -> str:
    return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()


# A digitless key, of the kind a scan of real prompts turned up.
_DIGITLESS = "s" + "k-live-AbCdEfGhIjKlMnOpQrStUvWx"
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
    # Named credentials in JSON, dict, YAML and INI form.
    ("json-quoted-key", 'Config: {{"api_key": "{}"}}', "abcd1234efgh5678"),
    ("json-prefixed-key", 'Config: {{"db_password": "{}"}}', "Sup3rS3cret"),
    # An unambiguous quoted name with a quoted value: whatever the value is.
    ("dict-single-quotes", "{{'password': '{}'}}", "letmein"),
    # An ambiguous name, with a value that is a credential on its own.
    ("token-with-a-key", "{{'token': '{}'}}", _key("gh" + "p_", 36)),
    ("token-high-entropy", 'token: "{}"', "abc123def456ghi789"),
    ("auth-bearer", '{{"auth": "{}"}}', "Bearer " + _key("", 24)),
    # A known key shape needs no digit when a name vouches for it -- and a
    # mixed-case run needs none even bare.
    ("digitless-bare", "use {} now", _DIGITLESS),
    ("digitless-under-auth-text", "auth: {}", _DIGITLESS),
    ("digitless-under-token-text", "token: {}", _DIGITLESS),
    ("digitless-under-auth-json", '{{"auth": "{}"}}', _DIGITLESS),
    ("vouched-lowercase-sk", '{{"key": "{}"}}', "s" + "k-abcdefghijklmnopqrstuvwxyz"),
    # An HTTP request dump's Basic header.
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
    # Slack's rotating tokens: the refresh token, and an access token it issued.
    ("slack-refresh", "tok {} end", _key("xo" + "xe-1-", 40)),
    ("slack-rotated", "tok {} end", _key("xo" + "xe.xo" + "xp-1-", 40)),
    # A URL's userinfo: the password only, whatever the host looks like.
    ("url-single-label-host", "postgres://user:{}@localhost/db", "pass"),
    ("url-no-user", "redis://:{}@cache:6379/0", "s3cr3t"),
    ("url-dotted-host", "amqp://app:{}@mq.internal.example:5672", "hunter2pw"),
    ("url-ip-host", "mysql://root:{}@10.0.0.7:3306/app", "toor"),
    ("url-ipv6-host", "http://ci:{}@[2001:db8::1]:8080/job", "tok3n"),
    ("url-in-json", '{{"dsn": "https://ci:{}@git.example/repo.git"}}', "tok3n"),
    # An `@` in the password is not the end of it: the last one before the path is.
    ("url-at-in-password", "mongodb://admin:{}@cluster0/db", "p@ssw0rd"),
    # A connection string's `pwd=`, whatever the value looks like.
    ("pwd-ado", "Server=db;Database=app;Uid=sa;Pwd={};Encrypt=yes", "letmein"),
    ("pwd-odbc", "DSN=prod;UID=sa;PWD={}", "Sup3rS3cret"),
    ("pwd-query", "jdbc:mysql://db/app?user=x&pwd={}&ssl=1", "hunter22"),
    ("pwd-quoted", "userPwd='{}'", "hunter22"),
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
    """The excerpt a run published kept this header verbatim, and the rows did too."""
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
    # Kebab-case that starts `sk-`, and token counts that are numbers.
    ("sk kebab-case", "use sk-learn-compatible-estimators"),
    ("sk url slug", "see /sk-slovak-language-course-2024 for more"),
    ("sk css class", 'class="sk-button-primary-large-rounded"'),
    ("numeric token", "max_token=1024000, token: 128000, token=1234567 (the vocabulary id)"),
    ("numeric quoted token", '{"max_token": "4096"}'),
    ("longer name", '{"password_hint": "your first pet"}'),
    ("empty quoted value", '{"password": ""}'),
    # Ordinary data under an ambiguous name stays as it is.
    ("ner token", '{"token": "Paris", "label": "LOC"}'),
    ("pos token", "[{'token': 'the', 'pos': 'DET'}]"),
    ("claim authorization", '{"authorization": "approved", "amount": 2}'),
    ("keyboard key", 'key: "Enter", auth: pending'),
    ("short mixed token", "token: abc123"),
    # A lowercase run with no digit is still not a key when nothing vouches.
    ("sk lowercase run", "see sk-verylongidentifierwithoutdashes"),
    ("sk kebab under a name", '{"key": "sk-learn-compatible-estimators"}'),
    # A rejected value stops at the next assignment; it does not become one.
    ("colon after rejected value", "token=abc:note=hello"),
    # `Basic` followed by a word, or by base64 that is not `user:pass`.
    ("basic prose", "Basic training for recruits. Basic auth is weak."),
    ("basic not user:pass", "Authorization: Basic dHJhaW5pbmc="),
    # A URL with a port, a user or an `@` further on, and no password.
    ("url port and query", "see https://example.com:8080/path?mail=a:b@c and http://db:5432"),
    ("url port and path", "open http://localhost:3000/@scope/pkg or http://[::1]:8080/a@b"),
    ("url user only", "clone ssh://git@github.com/org/repo.git or https://jane@example.com:8443/x"),
    ("url empty password", "ftp://anonymous:@ftp.example.com/pub"),
    ("url no host", "the pattern is scheme://user:password@ and nothing more"),
    ("scp remote", "git@github.com:org/repo.git and mailto:jane@example.com?subject=a:b"),
    # `PWD` is the shell's working directory: a path or a variable is not a password.
    ("shell cwd", "PWD=/home/jane/project1 OLDPWD=/tmp/x9 pwd=~/code1 pwd=./rel/dir1"),
    ("shell variable", "pwd=$(pwd); pwd=$PWD; pwd=`pwd`; $pwd=Get-Location1"),
    ("windows cwd", "PWD=C:\\Users\\jane\\code1 pwd=%CD% pwd=\\\\host\\share1"),
    ("pwd spaced or with a colon", "pwd = hunter22abc and pwd: hunter22abc"),
    ("pwd in a longer name", "mypwd=abc123def"),
    ("pwd empty", "Uid=sa;Pwd=;Encrypt=yes"),
    # Slack: too short, inside a longer word, or no token type Slack issues.
    ("slack refresh short", "xo" + "xe-1-abc"),
    ("slack embedded", "bo" + "xo" + "xe-" + "1-a1B2c3D4e5F6g7H8"),
    ("slack other letter", "xo" + "xq-1-a1B2c3D4e5F6g7H8"),
]


@pytest.mark.parametrize(("case", "text"), NEGATIVES, ids=[n[0] for n in NEGATIVES])
def test_near_misses_are_not_secrets(case: str, text: str) -> None:
    assert find_secrets(text) == [], case


def test_the_placeholder_is_the_documented_one() -> None:
    assert SECRET_PLACEHOLDER == "<SECRET>"


def test_every_named_credential_in_a_config_line_is_found() -> None:
    """The closing quote of a JSON key used to defeat the assignment rule."""
    text = 'Config: {"api_key": "abcd1234efgh5678", "db_password": "Sup3rS3cret"}'
    assert _found(text) == ["abcd1234efgh5678", "Sup3rS3cret"]


MEMBERS: list[tuple[str, str, bool]] = [
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
    # Unambiguous names take any value...
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
    # A vouched-for key shape needs no digit.
    ("auth", _DIGITLESS, True),
    ("token", _DIGITLESS, True),
    ("key", "s" + "k-abcdefghijklmnopqrstuvwxyz", True),
    ("key", "sk-learn-compatible-estimators", False),
    ("Authorization", "Basic dHJhaW5pbmc=", False),
    # A URL that carries a password is a credential on its own.
    ("auth", "amqp://app:hunter2pw@mq", True),
    ("key", "https://example.com:8080/path", False),
    # `pwd` is a credential name only in a connection string's `pwd=`.
    ("pwd", "hunter22", False),
    ("dsn_key", "Uid=sa;Pwd=letmein", True),
]


@pytest.mark.parametrize(("key", "value", "expected"), MEMBERS)
def test_a_member_is_a_credential_by_its_key_whatever_its_value(
    key: str, value: str, expected: bool
) -> None:
    """The two kinds of credential name.

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
    """A rejected `token=` value ran on over the `:password=` after it."""
    assert _found(text) == secrets


@pytest.mark.parametrize(
    ("key", "value", "expected"),
    [
        ("password", "a", True),
        ("db_password", "hunter22", True),
        ("clientSecret", "s", True),
        ("X-Api-Key", "abc", True),
        ("aws_secret_access_key", "wJalr", True),
        ("password", "", False),
        ("password_hint", "pet", False),
        ("user", "jane", False),
        # A name an id column also carries decides nothing, whatever the value.
        ("row_key", "a81f3c9e2b7d4f60", False),
        ("idempotency_key", "ord_9f8e7d6c5b4a3210", False),
        ("nextPageToken", "CAESEAoOc29tZS1wYWdlLXRva2Vu", False),
        ("token", _key("gh" + "p_", 36), False),
        ("Authorization", "Basic dXNlcjpwYXNz", False),
        ("auth", _DIGITLESS, False),
    ],
)
def test_a_row_member_is_a_credential_only_under_an_unambiguous_name(
    key: str, value: str, expected: bool
) -> None:
    """A row's keys are column names, and `row_key` or `nextPageToken` names an id
    column. So in a row only a name that cannot be one takes its value; a
    credential under any other name is left to the text scan."""
    assert is_credential_row_member(key, value) is expected
    assert is_credential_member(key, value) or not expected


class TestUrlPasswords:
    """`scheme://user:password@host`: the password, to the `@` that opens the host."""

    @pytest.mark.parametrize("char", ['"', "'", "`", "<", ">"])
    def test_a_quote_backtick_or_angle_bracket_in_the_password_is_part_of_it(
        self, char: str
    ) -> None:
        """RFC 3986 wants these percent-encoded, and connection strings in the wild do
        not: all five were missed, so the whole password leaked."""
        password = f"pa{char}ss"

        assert _found(f"https://u:{password}@host/x") == [password]
        assert _found(f"https://u:{password}@host.example.com:8443/a?b=c#d") == [password]
        assert _found(f"{char}https://u:{password}@host.com/x{char}") == [password]

    @pytest.mark.parametrize(
        "password", ["pa%22ss", "p%27w", "pa%60ss", "p%3Ca", "pa%3Ess", "p%40ss%3Aw%2Frd", 'a\\"b']
    )
    def test_a_percent_encoded_or_escaped_password_is_found(self, password: str) -> None:
        assert _found(f"postgres://u:{password}@db.internal/app") == [password]

    @pytest.mark.parametrize("char", ['"', "'", "`", "<", ">"])
    def test_such_a_character_ends_the_password_when_punctuation_follows_it(
        self, char: str
    ) -> None:
        """A quote is a password character only with a letter, digit or `%` after it.
        `"http://localhost:8080","a@b.co"` is a port and a string, not a password."""
        assert find_secrets(f"{char}http://localhost:8080{char},{char}a@b.co{char}") == []
        assert find_secrets(f"http://localhost:8080{char}+{char}a@b.co") == []

    @pytest.mark.parametrize(
        "text",
        [
            '{"a":"http://localhost:8080","m":"x@y.co"}',
            "{'url': 'http://localhost:8080', 'email': 'x@y.co'}",
            '<a href="http://localhost:8080">x@y.co</a>',
            'see "http://localhost:8080">x@y.co',
            "ports http://h:80`x` or http://h:81<",
        ],
    )
    def test_a_port_followed_by_text_that_holds_an_at_sign_is_not_a_password(
        self, text: str
    ) -> None:
        assert find_secrets(text) == []

    @pytest.mark.parametrize(
        ("text", "passwords"),
        [
            ('"https://u:pw@h.com","a@b.co"', ["pw"]),
            ("'https://u:pw@h.com' and 'https://v:qw@i.com'", ["pw", "qw"]),
            ("<https://u:pw@h.com>", ["pw"]),
            ('["https://a:b@h.com","https://c:d@i.com"]', ["b", "d"]),
            # An `@` in the password: the last one before the host.
            ("mongodb://admin:p@ssw0rd@cluster0/db", ["p@ssw0rd"]),
            ("mongodb://admin:p@ss@w0rd@cluster0/db", ["p@ss@w0rd"]),
            ('x="mongodb://admin:p@ss"w0rd@cluster0/db"', ['p@ss"w0rd']),
        ],
    )
    def test_the_password_ends_at_the_at_sign_that_opens_the_host(
        self, text: str, passwords: list[str]
    ) -> None:
        assert _found(text) == passwords

    @pytest.mark.parametrize(
        "text",
        [
            "http://localhost:8080,john@example.com",
            "http://db:5432;ops@corp.example",
            "url=http://h:1&cc=a@b.co",
            "http://localhost:3000|admin@x.co",
            "http://h:80>a@b.co",
            "http://h:65535,a@b.co",
            "http://u:80,a@host.example.com",
        ],
    )
    def test_a_port_then_a_separator_then_an_address_is_not_a_password(self, text: str) -> None:
        """`8080,john` reads as a password only if one forgets it starts like a port."""
        assert find_secrets(text) == []

    @pytest.mark.parametrize(
        ("text", "password"),
        [("http://h:123456,a@b.co", "123456,a"), ("http://h:80x,a@b.co", "80x,a")],
    )
    def test_a_longer_run_or_a_letter_makes_it_a_password_again(
        self, text: str, password: str
    ) -> None:
        """Six digits are not a port, and `80x` is not digits: both keep the old reading."""
        assert _found(text) == [password]

    def test_the_scheme_and_the_host_ask_only_that_no_space_stands_there(self) -> None:
        """A neighbour that must be a particular character fails the moment another class
        replaces it; so the scheme only has to not be whitespace, and so does the host."""
        assert _found("4111111111111111://u:pw@h") == ["pw"]
        assert _found("x://u:pw@10.0.0.7:3306/app") == ["pw"]
        assert _found("x://u:pw@[2001:db8::1]/app") == ["pw"]
        assert find_secrets("x ://u:pw@h") == []
        assert find_secrets("x://u:pw@ h") == []

    @pytest.mark.parametrize(
        "shape",
        [
            "https://u:{}",
            "https://u:" + 'a"' * 20 + "{}",
            "https://u:a@{}",
            "https://u:{}@x/",
            "{}://u:{}",
            "https://u:<{}>",
        ],
    )
    def test_a_megabyte_of_password_characters_is_scanned_in_linear_time(self, shape: str) -> None:
        """Every character the password may hold, with and without the `@` that ends it:
        32 KB first, so a quadratic pattern fails here in a second."""
        for unit in ["a", "a@", 'a"', "a@b", "@a", "a'@", ":", "://", "a>"]:
            small = shape.replace("{}", unit * 16_000)
            started = time.perf_counter()
            find_secrets(small)
            assert time.perf_counter() - started < 0.5, (shape, unit)
        for unit in ["a", "a@", 'a"', "a@b", "a>"]:
            big = shape.replace("{}", unit * 400_000)
            started = time.perf_counter()
            find_secrets(big)
            assert time.perf_counter() - started < 5.0, (shape, unit)
