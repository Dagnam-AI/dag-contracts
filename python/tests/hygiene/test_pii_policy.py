"""Tests for `dagnam_contracts/hygiene/pii.py`: a policy acts on exactly what the scan reports.

The scan resolves every class, and so does a policy: it then acts on its own subset. So
for every class the scan finds, `{class: redact}` writes exactly the placeholders of it
the scan counted and `{class: drop}` drops the row, and a class the scan does not find
never changes or drops a row. What redacting one class does to the *other* classes is
not promised (text of another class that was glued to the first may read differently
once the first is replaced), and these tests do not claim it.
"""

from __future__ import annotations

from itertools import product
from typing import Any

from pii_corpus import (
    ALL,
    ONE_CLASS_TEXTS,
    PARSES_ONLY_AFTER_REDACTION,
    SAMPLES,
    SEPARATORS,
    SHAPE_NAMES,
    SHAPES,
    TROUBLE,
    found,
    one_class_problems,
    placeholders,
    random_rows,
)
import pytest

from dagnam_contracts.hygiene.pii import PII_CODES, PiiAction, apply_pii_policy, scan_rows

_POOL = sorted(sample for samples in SAMPLES.values() for sample in samples)


def _problems(rows: list[dict[str, Any]]) -> list[str]:
    return [problem for row in rows for problem in one_class_problems(row)]


class TestOneClassAgreesWithTheScan:
    @pytest.mark.parametrize("shape", SHAPE_NAMES)
    def test_every_pinned_input_in_every_shape(self, shape: str) -> None:
        rows = [SHAPES[shape](text) for text in ONE_CLASS_TEXTS[::4]]

        assert found(rows)
        assert _problems(rows) == []

    def test_the_inputs_that_once_left_a_residue_in_every_shape(self) -> None:
        rows = [
            SHAPES[shape](text)
            for text in TROUBLE.values()
            if text not in PARSES_ONLY_AFTER_REDACTION
            for shape in SHAPE_NAMES
        ]

        assert _problems(rows) == []

    def test_pairs_of_samples_in_every_separator(self) -> None:
        rows = [
            SHAPES[SHAPE_NAMES[index % len(SHAPE_NAMES)]](f"{first}{separator}{second}")
            for index, (first, second, separator) in enumerate(product(_POOL, _POOL, SEPARATORS))
            if index % 7 == 0
        ]

        assert len(rows) > 600
        assert _problems(rows) == []

    def test_seeded_random_rows(self) -> None:
        assert _problems(random_rows(4, 1_500)) == []


class TestAPolicyActsOnWhatTheScanReports:
    def test_a_phone_number_that_only_a_neighbouring_secret_reveals_is_redacted_by_a_phone_policy(
        self,
    ) -> None:
        """`hunter22` hides the phone number from its own pattern until the secret is a
        placeholder. 0.4.0 never reported that phone, so its phone-only policy never saw it."""
        row = {"text": "password: hunter22 +1 415-555-0132"}

        assert found([row]) == {"PII_SECRET": 1, "PII_PHONE": 1}
        assert apply_pii_policy([row], {"PII_PHONE": "redact"}) == (
            [{"text": "password: hunter22 [REDACTED:PII_PHONE]"}],
            1,
            0,
        )
        assert apply_pii_policy([row], {"PII_PHONE": "drop"}) == ([], 0, 1)
        assert apply_pii_policy([row], {"PII_SECRET": "redact"}) == (
            [{"text": "password: <SECRET> +1 415-555-0132"}],
            1,
            0,
        )

    def test_a_card_hidden_by_a_pwd_value_is_redacted_by_a_card_policy(self) -> None:
        row = {"text": "Pwd=letmein4 4111111111111111"}

        assert apply_pii_policy([row], {"PII_PAYMENT_CARD": "redact"}) == (
            [{"text": "Pwd=letmein4 [REDACTED:PII_PAYMENT_CARD]"}],
            1,
            0,
        )

    def test_a_row_that_a_redaction_makes_droppable_is_dropped(self) -> None:
        """`drop` beats `redact`: the phone number is hidden behind the secret's last
        digit, and it is a finding once the secret is replaced -- the scan reports it,
        so the policy drops the row."""
        rows = [{"text": "password: hunter22 +1 415-555-0132"}]

        assert apply_pii_policy(rows, {"PII_SECRET": "redact", "PII_PHONE": "drop"}) == ([], 0, 1)

    def test_what_holds_for_the_class_that_is_redacted(self) -> None:
        """Only the class that is acted on is promised: after `{class: redact}` the rescan
        counts none of that class, the output carries exactly the placeholders the scan
        counted, and redacting again is a no-op. The other classes are left as text and
        the rescan reports them as it can; nothing is promised about their counts."""
        row = {"text": "mail jane@example.com password: hunter22 +1 415-555-0132"}
        original = found([row])

        for code in original:
            only, changed, _ = apply_pii_policy([row], {code: "redact"})

            assert changed == 1
            assert placeholders(only)[code] == original[code]
            assert found(only)[code] == 0
            assert apply_pii_policy(only, {code: "redact"}) == (only, 0, 0)

    def test_a_class_the_scan_does_not_find_never_changes_or_drops_a_row(self) -> None:
        row = {"text": "mail jane@example.com"}
        absent: dict[str, PiiAction] = {code: "drop" for code in PII_CODES if code != "PII_EMAIL"}

        assert apply_pii_policy([row], absent) == ([row], 0, 0)
        assert apply_pii_policy([row], {"PII_EMAIL": "ignore"}) == ([row], 0, 0)

    def test_a_class_with_nothing_set_is_ignored(self) -> None:
        rows = [{"text": "mail jane@example.com"}]

        assert apply_pii_policy(rows, {}) == (rows, 0, 0)

    def test_an_unknown_class_is_an_error(self) -> None:
        policy: dict[str, PiiAction] = {"PII_NOT_A_CLASS": "redact"}

        with pytest.raises(ValueError, match="PII_NOT_A_CLASS"):
            apply_pii_policy([{"text": "x"}], policy)

    def test_the_scan_and_the_policy_agree_on_which_rows_hold_a_finding(self) -> None:
        rows = random_rows(5, 600)

        kept, changed, removed = apply_pii_policy(rows, ALL)

        with_findings = sum(1 for row in rows if found([row]))
        assert (len(kept), changed, removed) == (len(rows), with_findings, 0)
        assert {issue.row_index for issue in scan_rows(rows, max_issues=10**6).issues} == {
            index for index, row in enumerate(rows) if found([row])
        }


class TestKnownLimitOfAPartialPolicy:
    @pytest.mark.parametrize("text", PARSES_ONLY_AFTER_REDACTION)
    def test_a_document_that_parses_only_after_another_class_is_replaced(self, text: str) -> None:
        """A raw tab inside a phone number keeps the text from being JSON until the phone is
        replaced; the credential member that then shows is counted by the scan. Redacting
        every class replaces both. Redacting the credential alone cannot (the text it
        would leave still holds the tab, so it is still not a document), so the row is
        left as it is, and dropping the credential drops it."""
        row = {"text": text}
        assert found([row])["PII_SECRET"] == 1

        everything, _, _ = apply_pii_policy([row], ALL)
        assert found(everything) == {}

        left, changed, _ = apply_pii_policy([row], {"PII_SECRET": "redact"})
        assert (left, changed) == ([row], 0)
        assert apply_pii_policy([row], {"PII_SECRET": "drop"}) == ([], 0, 1)
