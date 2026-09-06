"""
Tests for `dagnam_contracts/hygiene/pii.py`, including the **labelled corpus** the
plan requires the in-repo-vs-presidio decision to be made against.

`LABELLED_CORPUS` is the evidence, not decoration. Each entry is a realistic
snippet plus the classes a human says are present. `test_measured_recall_per_class`
asserts the recall floors actually observed — **deliberately not 100%**, and the
known misses are listed by name in `KNOWN_MISSES` so a reader can see the
boundary of the check rather than infer a guarantee from a green test. That is
the same honesty the feature's UI copy promises.
"""

from __future__ import annotations

import pytest

from dagnam_contracts.hygiene.pii import (
    PII_CODES,
    PII_DISCLAIMER,
    _luhn_ok,
    apply_pii_policy,
    scan_rows,
)

# (text, classes a human says are present)
LABELLED_CORPUS: list[tuple[str, set[str]]] = [
    # --- email ---
    ("Contact jane.doe@example.com for details", {"PII_EMAIL"}),
    ("reply-to: a.b+tag@sub.domain.co.uk please", {"PII_EMAIL"}),
    # Labelled as the PII it IS, not as a negative. Labelling a known miss
    # "clean" would make the corpus agree with a broken detector and report a
    # recall of 1.0 that means nothing.
    ("write to J DOT SMITH AT example DOT com", {"PII_EMAIL"}),
    # --- phone ---
    ("call +1 (415) 555-2671 tomorrow", {"PII_PHONE"}),
    ("ring 020 7946 0958 after six", {"PII_PHONE"}),
    ("mobile 415-555-2671.", {"PII_PHONE"}),
    ("dial extension 4021", set()),
    # --- payment card ---
    ("card 4111 1111 1111 1111 exp 12/29", {"PII_PAYMENT_CARD"}),
    ("visa 4111-1111-1111-1111", {"PII_PAYMENT_CARD"}),
    ("amex 378282246310005 on file", {"PII_PAYMENT_CARD"}),
    ("order reference 4111111111111112", set()),  # fails Luhn -> correctly ignored
    # --- national id ---
    ("SSN 123-45-6789 on record", {"PII_NATIONAL_ID"}),
    ("ssn: 078-05-1120", {"PII_NATIONAL_ID"}),
    ("ssn 123456789 unformatted", {"PII_NATIONAL_ID"}),  # undashed: a known miss
    ("invalid ssn 000-12-3456", set()),
    # --- mixed / negative ---
    (
        "email bob@corp.io or call +44 20 7946 0958",
        {"PII_EMAIL", "PII_PHONE"},
    ),
    ("The quick brown fox jumps over the lazy dog", set()),
    ("Version 2.10.3 released on 2026-08-16", set()),
]

KNOWN_MISSES = {
    "obfuscated email (`J DOT SMITH AT example DOT com`)",
    "undashed 9-digit SSN (indistinguishable from an order id without context)",
    "person names, street addresses, locations — never claimed; they need NER",
}

# Floors, measured against LABELLED_CORPUS at the time the detectors landed.
# A ratchet: raise one when a detector genuinely improves, never lower one.
# Measured: email 3/4 (obfuscated form missed), phone 4/4, card 3/3,
# national id 2/3 (undashed form missed). Not 1.0, and deliberately so.
RECALL_FLOOR = {
    "PII_EMAIL": 3 / 4,
    "PII_PHONE": 4 / 4,
    "PII_PAYMENT_CARD": 3 / 3,
    "PII_NATIONAL_ID": 2 / 3,
}


def _classes_found(text: str) -> set[str]:
    result = scan_rows([{"text": text}])
    return {code for code, count in result.counts_by_code.items() if count}


class TestLabelledCorpus:
    def test_measured_recall_per_class(self) -> None:
        """Recall reported honestly, not asserted at 100%."""
        expected: dict[str, int] = dict.fromkeys(PII_CODES, 0)
        detected: dict[str, int] = dict.fromkeys(PII_CODES, 0)

        for text, labels in LABELLED_CORPUS:
            found = _classes_found(text)
            for code in labels:
                expected[code] += 1
                detected[code] += int(code in found)

        for code in PII_CODES:
            assert expected[code] > 0, f"{code} has no labelled positives in the corpus"
            recall = detected[code] / expected[code]
            assert recall >= RECALL_FLOOR[code], (
                f"{code} recall regressed to {recall:.2f} (floor {RECALL_FLOOR[code]:.2f})"
            )

    def test_no_false_positives_on_the_negative_examples(self) -> None:
        """Precision matters more than recall here: a scan that cries wolf on
        every order id and version string gets switched off, and a switched-off
        scan finds nothing at all."""
        for text, labels in LABELLED_CORPUS:
            if labels:
                continue
            assert _classes_found(text) == set(), f"false positive on {text!r}"

    def test_the_corpus_records_real_misses(self) -> None:
        """A corpus of only-positives or only-negatives would pass against any
        implementation, and a corpus that labels its known misses "clean"
        would report a meaningless recall of 1.0. Guard the guard."""
        assert any(floor < 1.0 for floor in RECALL_FLOOR.values())

        positives = [text for text, labels in LABELLED_CORPUS if labels]
        negatives = [text for text, labels in LABELLED_CORPUS if not labels]

        assert len(positives) >= 8
        assert len(negatives) >= 4
        assert KNOWN_MISSES  # the boundary is written down, not implied


class TestLuhn:
    @pytest.mark.parametrize("digits", ["4111111111111111", "378282246310005", "5555555555554444"])
    def test_valid_card_numbers_pass(self, digits: str) -> None:
        assert _luhn_ok(digits) is True

    @pytest.mark.parametrize("digits", ["4111111111111112", "1234567890123456"])
    def test_invalid_card_numbers_fail(self, digits: str) -> None:
        assert _luhn_ok(digits) is False


class TestScanRows:
    def test_findings_are_format_issue_shaped_warnings(self) -> None:
        result = scan_rows([{"a": "mail me at x@y.com"}])

        issue = result.issues[0]
        assert issue.row_index == 0
        assert issue.code == "PII_EMAIL"
        assert issue.severity == "warning"  # a row with an email is not malformed

    def test_nested_chat_messages_content_is_scanned(self) -> None:
        """`chat-messages` holds its text two levels down. A one-level flatten
        would report zero findings on the platform's most common format."""
        rows = [{"messages": [{"role": "user", "content": "reach me at deep@example.com"}]}]

        result = scan_rows(rows)

        assert result.counts_by_code["PII_EMAIL"] == 1
        assert result.issues[0].message.endswith("field 'messages[0].content'")

    def test_the_pass_list_and_disclaimer_travel_with_an_empty_result(self) -> None:
        """The whole framing of the feature: an empty result must not read as
        certification."""
        result = scan_rows([{"a": "nothing to see"}])

        assert result.issues == ()
        assert result.pass_list == PII_CODES
        assert result.disclaimer == PII_DISCLAIMER
        assert "not certification" in result.disclaimer
        assert not hasattr(result, "clean")

    def test_the_issue_sample_is_capped_but_the_counts_are_not(self) -> None:
        rows = [{"a": "x@y.com"} for _ in range(10)]

        result = scan_rows(rows, max_issues=3)

        assert len(result.issues) == 3
        assert result.counts_by_code["PII_EMAIL"] == 10

    def test_an_empty_list_leaf_yields_no_findings(self) -> None:
        """`_walk_strings`'s list branch with zero elements -- the recursive
        walk must terminate cleanly rather than assuming at least one item."""
        result = scan_rows([{"messages": [], "a": "x@y.com"}])

        assert result.counts_by_code["PII_EMAIL"] == 1

    def test_a_non_string_non_container_leaf_is_silently_skipped(self) -> None:
        """`_walk_strings` falls through cleanly (yields nothing) for a leaf
        that is none of str/dict/list -- an int, bool, or None sitting next
        to the string actually being scanned."""
        result = scan_rows([{"count": 5, "active": True, "score": None, "a": "x@y.com"}])

        assert result.counts_by_code["PII_EMAIL"] == 1


class TestApplyPiiPolicy:
    def test_redact_replaces_the_span_and_leaves_the_row(self) -> None:
        rows = [{"a": "mail me at x@y.com now"}]

        kept, changed, removed = apply_pii_policy(rows, {"PII_EMAIL": "redact"})

        assert kept == [{"a": "mail me at [REDACTED:PII_EMAIL] now"}]
        assert (changed, removed) == (1, 0)

    def test_redaction_reaches_nested_structures(self) -> None:
        rows = [{"messages": [{"role": "user", "content": "x@y.com"}]}]

        kept, changed, _ = apply_pii_policy(rows, {"PII_EMAIL": "redact"})

        assert kept[0]["messages"][0]["content"] == "[REDACTED:PII_EMAIL]"
        assert changed == 1

    def test_drop_removes_the_whole_row(self) -> None:
        rows = [{"a": "card 4111 1111 1111 1111"}, {"a": "clean"}]

        kept, changed, removed = apply_pii_policy(rows, {"PII_PAYMENT_CARD": "drop"})

        assert kept == [{"a": "clean"}]
        assert (changed, removed) == (0, 1)

    def test_drop_beats_redact_when_a_row_matches_both(self) -> None:
        rows = [{"a": "x@y.com and card 4111 1111 1111 1111"}]

        kept, _, removed = apply_pii_policy(
            rows, {"PII_EMAIL": "redact", "PII_PAYMENT_CARD": "drop"}
        )

        assert kept == []
        assert removed == 1

    def test_ignore_and_an_absent_class_both_leave_the_data_alone(self) -> None:
        rows = [{"a": "x@y.com"}]

        assert apply_pii_policy(rows, {"PII_EMAIL": "ignore"}) == (rows, 0, 0)
        assert apply_pii_policy(rows, {}) == (rows, 0, 0)

    def test_an_unknown_class_is_refused(self) -> None:
        with pytest.raises(ValueError, match="PII_SHOE_SIZE"):
            apply_pii_policy([{"a": "x"}], {"PII_SHOE_SIZE": "drop"})

    def test_two_overlapping_findings_in_one_string_are_both_replaced(self) -> None:
        rows = [{"a": "a@b.com then c@d.com"}]

        kept, changed, _ = apply_pii_policy(rows, {"PII_EMAIL": "redact"})

        assert kept[0]["a"] == "[REDACTED:PII_EMAIL] then [REDACTED:PII_EMAIL]"
        assert changed == 1

    def test_non_string_scalars_pass_through_the_rebuild_untouched(self) -> None:
        """`_map_strings`'s traversal must not choke on -- or mutate -- a
        non-string leaf (int, bool, None) sitting next to the string it is
        redacting."""
        rows = [{"a": "mail me at x@y.com", "count": 5, "active": True, "score": None}]

        kept, changed, _ = apply_pii_policy(rows, {"PII_EMAIL": "redact"})

        assert kept[0]["count"] == 5
        assert kept[0]["active"] is True
        assert kept[0]["score"] is None
        assert changed == 1

    def test_an_empty_list_leaf_is_left_alone(self) -> None:
        rows = [{"messages": [], "a": "x@y.com"}]

        kept, changed, _ = apply_pii_policy(rows, {"PII_EMAIL": "redact"})

        assert kept[0]["messages"] == []
        assert changed == 1
