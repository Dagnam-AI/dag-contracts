"""Tests for `dagnam_contracts/hygiene/pii.py`: scanning rows that are already redacted.

The SDK redacts on the customer's machine, uploads, and the platform scans the upload
again with the same contract; anything the second scan counts stops the workload. So a
redaction must leave nothing its own scan finds, redacting twice must be redacting
once, and what the scan counted is what was written. These hold with no exception, for
every input the PII tests pin, in every shape of row.
"""

from __future__ import annotations

import json
from typing import Any

from pii_corpus import (
    ALL,
    SHAPE_NAMES,
    SHAPES,
    TEXTS,
    TROUBLE,
    document_rows,
    everything_problems,
    found,
)
import pytest

from dagnam_contracts.hygiene.pii import (
    PII_CODES,
    PII_DETECTORS,
    apply_pii_policy,
    redact_json_text,
    redact_rows,
    scan_rows,
)

_PLACEHOLDERS = [detector.replacement for detector in PII_DETECTORS]


class TestAPlaceholderIsNeverAFinding:
    @pytest.mark.parametrize(
        ("text", "redacted"),
        [
            ('{"password": "a@b.co"}', '{"password": "<SECRET>"}'),
            ('cfg = {"client_secret": "abc"}', 'cfg = {"client_secret": "<SECRET>"}'),
            ("password=hunter2abc99", "password=<SECRET>"),
            # The address names the finding; its placeholder is not a value to read again.
            ("password: jane@example.com", "password: [REDACTED:PII_EMAIL]"),
            ("password: a@b.co/c@d.co", "password: [REDACTED:PII_EMAIL]/[REDACTED:PII_EMAIL]"),
        ],
    )
    def test_a_rescan_of_redacted_text_finds_nothing(self, text: str, redacted: str) -> None:
        """Under `password`, `secret`, `api_key` and the like any non-empty value is a
        credential, and `<SECRET>` is non-empty: 0.4.0 counted its own placeholder
        again, so the platform's rescan stopped every such workload."""
        rows, changed, _ = apply_pii_policy([{"a": text}], ALL)

        assert (rows, changed) == ([{"a": redacted}], 1)
        assert found(rows) == {}
        assert apply_pii_policy(rows, ALL) == (rows, 0, 0)
        assert redact_json_text(redacted) == (redacted, 0)

    @pytest.mark.parametrize("placeholder", [*_PLACEHOLDERS, "[REDACTED:PII_OF_A_LATER_VERSION]"])
    def test_every_placeholder_is_skipped_on_every_path(self, placeholder: str) -> None:
        """Every class's placeholder, and one a later registry would write, as the
        value of a credential name in text, in a document and in the row itself."""
        rows: list[dict[str, Any]] = [
            {"a": f'"password": "{placeholder}"'},
            {"a": f"api_key = {placeholder}{placeholder}"},
            {"a": json.dumps({"config": {"client_secret": placeholder}})},
            {"config": {"client_secret": placeholder}, "passwords": [{"secret": placeholder}]},
        ]

        assert found(rows) == {}
        assert apply_pii_policy(rows, ALL) == (rows, 0, 0)
        assert apply_pii_policy(rows, dict.fromkeys(PII_CODES, "drop")) == (rows, 0, 0)

    @pytest.mark.parametrize(
        ("row", "redacted"),
        [
            ({"a": '{"password": "[REDACTED:PII_EMAIL] x"}'}, {"a": '{"password": "<SECRET>"}'}),
            ({"password": "<SECRET> and hunter2"}, {"password": "<SECRET>"}),
            ({"password": "SECRET"}, {"password": "<SECRET>"}),
            # Brackets around a value do not make it a placeholder: a code does.
            ({"password": "[REDACTED:hunter2]"}, {"password": "<SECRET>"}),
        ],
    )
    def test_real_text_beside_a_placeholder_is_still_a_finding(
        self, row: dict[str, Any], redacted: dict[str, Any]
    ) -> None:
        """A member rule reads the text that is not a placeholder: `and hunter2` is one."""
        assert found([row]) == {"PII_SECRET": 1}
        assert apply_pii_policy([row], ALL) == ([redacted], 1, 0)

    @pytest.mark.parametrize(
        "row",
        [
            {"a": "password=<SECRET>hunter2abc99"},
            {"a": '"password": "<SECRET>hunter2"'},
            {"a": "password=[REDACTED:PII_EMAIL]!x"},
        ],
    )
    def test_text_glued_to_a_placeholder_is_read_on_its_own(self, row: dict[str, Any]) -> None:
        """A finding is decided on the text between placeholders, read alone: `hunter2abc99`
        after a placeholder is not a value assigned to `password`, so it is not found.
        0.4.0 found it, and swallowed the placeholder with it."""
        assert found([row]) == {}
        assert apply_pii_policy([row], ALL) == ([row], 0, 0)


class TestRedactedRowsRescanClean:
    @pytest.mark.parametrize("shape", SHAPE_NAMES)
    def test_every_pinned_input_in_every_shape(self, shape: str) -> None:
        """``scan(redact(x))`` is empty, ``redact(redact(x)) == redact(x)``, and the
        count of each class is the placeholders of it written, for every class and
        every input the PII tests pin."""
        rows = [SHAPES[shape](text) for text in TEXTS]

        assert found(rows), "the corpus must hold findings in this shape"
        assert [problem for row in rows for problem in everything_problems(row)] == []

    def test_the_pinned_inputs_exercise_every_class(self) -> None:
        assert set(found([SHAPES["plain text"](text) for text in TEXTS])) == set(PII_CODES)

    def test_documents_as_rows_and_nested(self) -> None:
        rows = document_rows()

        assert found(rows)["PII_SECRET"] > 0
        assert [problem for row in rows for problem in everything_problems(row)] == []

    def test_json_text(self) -> None:
        for text in TEXTS:
            redacted, _ = redact_json_text(text)
            assert redact_json_text(redacted) == (redacted, 0), text

    @pytest.mark.parametrize("name", sorted(TROUBLE))
    def test_inputs_that_once_left_a_residue_in_every_shape(self, name: str) -> None:
        rows = [SHAPES[shape](TROUBLE[name]) for shape in SHAPE_NAMES]

        assert [problem for row in rows for problem in everything_problems(row)] == []

    def test_redact_rows_is_the_redact_everything_policy_in_one_call(self) -> None:
        rows = [SHAPES[shape](text) for shape in SHAPE_NAMES for text in TEXTS[::17]]

        redacted, counts = redact_rows(rows)

        assert redacted == apply_pii_policy(rows, ALL)[0]
        assert counts == scan_rows(rows).counts_by_code
        assert list(counts) == list(PII_CODES)
        assert scan_rows(redacted).counts_by_code == dict.fromkeys(PII_CODES, 0)
        assert redact_rows(redacted) == (redacted, dict.fromkeys(PII_CODES, 0))

    def test_redact_rows_returns_a_clean_row_as_the_same_object(self) -> None:
        clean = {"text": "nothing to find here"}

        redacted, counts = redact_rows([clean, {"text": "jane@example.com"}])

        assert redacted[0] is clean
        assert redacted[1] == {"text": "[REDACTED:PII_EMAIL]"}
        assert counts["PII_EMAIL"] == 1
