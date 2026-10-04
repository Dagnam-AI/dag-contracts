"""Tests for `is_credential_row_member` in `dagnam_contracts/hygiene/credentials.py`.

Which names, and which values, make a member of a row a credential. Split from
`test_credentials.py`, which covers the text patterns and a JSON document's rule.
"""

from __future__ import annotations

import pytest

from dagnam_contracts.hygiene.credentials import is_credential_member, is_credential_row_member

# A name is a credential name when it is, or ends in as a word of its own, one of
# `password`, `passwd`, `secret`, `api_key`, `access_key`, `secret_access_key`,
# `private_key`, `client_secret` (any case, snake_case, kebab-case, camelCase) --
# unless its first word is one of `has is needs requires use allow enable enabled
# show with no top`, which makes the column a flag or a label about the credential.
CREDENTIAL_NAMES = [
    "password",
    "Password",
    "PASSWORD",
    "passwd",
    "secret",
    "client_secret",
    "clientSecret",
    "api_key",
    "apiKey",
    "API_KEY",
    "apikey",
    "access_key",
    "private_key",
    "secret_key",
    "secret_access_key",
    "db_password",
    "userPassword",
    "user-password",
    "aws-secret-access-key",
    "AWS_SECRET_ACCESS_KEY",
    "x-api-key",
    "smtp_passwd",
    "github_client_secret",
    "new_password",
    "old_password",
    "confirm_password",
    "reset_password",
    "x_has_password",
    "_password",
]
NOT_CREDENTIAL_NAMES = [
    # The credential word is not the last word.
    "password_hint",
    "password_hash_algorithm",
    "passwordConfirmation",
    "secret_santa",
    "api_key_id",
    "secrets",
    "passwords",
    # A flag or a label about the credential, not the credential.
    "has_password",
    "hasPassword",
    "HAS_PASSWORD",
    "is_secret",
    "isSecret",
    "top_secret",
    "no_password",
    "needs_password",
    "requires_secret",
    "use_password",
    "allow_api_key",
    "enable_password",
    "enabled_secret",
    "show_password",
    "with_password",
    "is-private-key",
    # Names an id column carries, and names that are not credential names at all.
    "token",
    "key",
    "auth",
    "authorization",
    "row_key",
    "nextPageToken",
    "idempotency_key",
    "mysecret",
    "pwd",
    "username",
    "id",
    "",
]


class TestWhichNamesAreCredentials:
    @pytest.mark.parametrize("name", CREDENTIAL_NAMES)
    def test_a_credential_name_takes_its_value(self, name: str) -> None:
        assert is_credential_row_member(name, "hunter2abc") is True

    @pytest.mark.parametrize("name", NOT_CREDENTIAL_NAMES)
    def test_any_other_name_decides_nothing(self, name: str) -> None:
        assert is_credential_row_member(name, "hunter2abc") is False

    def test_the_table_is_balanced_and_large_enough_to_mean_something(self) -> None:
        assert len(CREDENTIAL_NAMES) + len(NOT_CREDENTIAL_NAMES) >= 40
        assert min(len(CREDENTIAL_NAMES), len(NOT_CREDENTIAL_NAMES)) >= 20
        assert len(set(CREDENTIAL_NAMES) & set(NOT_CREDENTIAL_NAMES)) == 0

    @pytest.mark.parametrize("name", ["has_password", "no_password", "top_secret", "is_secret"])
    def test_a_json_document_keeps_the_0_4_0_rule_for_these_names(self, name: str) -> None:
        """Only the row changed: in a document held in a string a name that ends in a
        credential word is a credential, as it was in 0.4.0."""
        assert is_credential_member(name, "yes") is True


class TestWhichValuesAreSecrets:
    @pytest.mark.parametrize(
        "value",
        [
            "hunter2",
            "correcthorse",
            "a",
            "0",
            "yes please",
            "none of your business",
            "n/a, ask",
            "x",
        ],
    )
    def test_a_value_under_a_credential_name_is_a_secret(self, value: str) -> None:
        assert is_credential_row_member("password", value) is True

    @pytest.mark.parametrize(
        "value",
        [
            "",
            " ",
            "\t\n",
            "yes",
            "YES",
            "No",
            "true",
            "True",
            "false",
            "FALSE",
            "n/a",
            "N/A",
            "none",
            "None",
            "null",
            "NULL",
            "-",
            " true ",
            " n/a ",
        ],
    )
    def test_a_blank_or_flag_like_value_is_not(self, value: str) -> None:
        """A column named `secret` holding `N/A`, `no` or ` ` holds no secret, and counting
        it would drop the row of a dataset that has the column."""
        assert is_credential_row_member("password", value) is False
        assert is_credential_row_member("client_secret", value) is False
