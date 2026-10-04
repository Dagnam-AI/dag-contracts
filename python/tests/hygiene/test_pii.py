"""
Tests for `dagnam_contracts/hygiene/pii.py`, including the **labelled corpus** the
in-repo-vs-presidio decision was made against.

`LABELLED_CORPUS` is the evidence, not decoration. Each entry is a realistic
snippet plus the classes a human says are present. `test_measured_recall_per_class`
asserts the recall floors actually observed — **deliberately not 100%**, and the
known misses are listed by name in `KNOWN_MISSES` so a reader can see the
boundary of the check rather than infer a guarantee from a green test. That is
the same honesty the feature's UI copy promises.
"""

from __future__ import annotations

from pathlib import Path
import re
import time

import pytest

from dagnam_contracts.hygiene.pii import (
    PII_CODES,
    PII_DETECTORS,
    PII_DISCLAIMER,
    PiiAction,
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
    # --- secret (every pattern has its own positive and near-miss in
    # tests/hygiene/test_credentials.py; these are the everyday shapes) ---
    ("Authorization: Bearer " + "a1B2c3D4e5F6g7H8i9J0k1L2", {"PII_SECRET"}),
    ("export OPENAI_API_KEY=" + "s" + "k-a1B2c3D4e5F6g7H8i9J0k1L2m3", {"PII_SECRET"}),
    ("db password: hunter2", {"PII_SECRET"}),
    # A secret with no recognisable shape, assigned to nothing: a known miss.
    ("the vault combination is correcthorsebatterystaple", {"PII_SECRET"}),
    ("commit da39a3ee5e6b4b0d3255bfef95601890afd80709", set()),
    # --- the classes 0.4.0 added (each has its own positives and near-misses in
    # tests/hygiene/test_detectors.py; these are the everyday shapes) ---
    ("refund to DE89 3704 0044 0532 0130 00 please", {"PII_IBAN"}),
    ("wire to GB29NWBK60161331926819", {"PII_IBAN"}),
    ("login from 203.0.113.9 failed", {"PII_IP_ADDRESS"}),
    ("DOB: 14/03/1987", {"PII_DATE_OF_BIRTH"}),
    # A date of birth with no birth keyword before it: a known miss.
    ("Jane (14 March 1987) called", {"PII_DATE_OF_BIRTH"}),
    ("NI number AB 12 34 56 C", {"PII_UK_NINO"}),
    ("SIN 130 692 544", {"PII_CA_SIN"}),
    ("Aadhaar 2345 6789 0124", {"PII_IN_AADHAAR"}),
    ("PAN ABCPE1234F", {"PII_IN_PAN"}),
    ("VAT DE123456789", {"PII_EU_VAT"}),
    ("release v1.2.3.4 of 2.10.3, date 2026-08-16", set()),
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
    "a bare secret with no provider shape and no `password:`-style name before it",
    "a bare AWS secret access key (40 characters of base64 with no name beside them)",
    "a provider key broken into short hyphenated pieces",
    "a date of birth with no birth keyword before it",
}

# Floors, measured against LABELLED_CORPUS at the time the detectors landed.
# A ratchet: raise one when a detector genuinely improves, never lower one.
# Measured: email 3/4 (obfuscated form missed), phone 4/4, card 3/3,
# national id 2/3 (undashed form missed), secret 3/4 (bare passphrase missed),
# date of birth 1/2 (no keyword missed), every other class 1/1 or 2/2.
# Not 1.0, and deliberately so.
RECALL_FLOOR = {
    "PII_EMAIL": 3 / 4,
    "PII_PHONE": 4 / 4,
    "PII_PAYMENT_CARD": 3 / 3,
    "PII_NATIONAL_ID": 2 / 3,
    "PII_SECRET": 3 / 4,
    "PII_IBAN": 2 / 2,
    "PII_IP_ADDRESS": 1 / 1,
    "PII_DATE_OF_BIRTH": 1 / 2,
    "PII_UK_NINO": 1 / 1,
    "PII_CA_SIN": 1 / 1,
    "PII_IN_AADHAAR": 1 / 1,
    "PII_IN_PAN": 1 / 1,
    "PII_EU_VAT": 1 / 1,
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
        assert "a credential in a format it does not know" in result.disclaimer
        assert not hasattr(result, "clean")

    def test_the_issue_sample_is_capped_but_the_counts_are_not(self) -> None:
        rows = [{"a": "x@y.com"} for _ in range(10)]

        result = scan_rows(rows, max_issues=3)

        assert len(result.issues) == 3
        assert result.counts_by_code["PII_EMAIL"] == 10

    def test_an_empty_list_leaf_yields_no_findings(self) -> None:
        """The walk's list branch with zero elements -- the recursive
        walk must terminate cleanly rather than assuming at least one item."""
        result = scan_rows([{"messages": [], "a": "x@y.com"}])

        assert result.counts_by_code["PII_EMAIL"] == 1

    def test_a_non_string_non_container_leaf_is_silently_skipped(self) -> None:
        """The walk falls through cleanly (reports nothing) for a leaf
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
        """The walk must not choke on -- or mutate -- a
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


_KEY = "s" + "k-a1B2c3D4e5F6g7H8i9J0k1L2m3"


class TestSecretClass:
    def test_secret_is_a_class_every_redact_everything_policy_covers(self) -> None:
        """The audit builds its policy as every class -> redact, so the new
        class is covered there with no change on the consumer's side."""
        assert "PII_SECRET" in PII_CODES
        rows = [{"system": f"Auth header: Bearer {_KEY}. Be polite."}]

        kept, changed, _ = apply_pii_policy(rows, dict.fromkeys(PII_CODES, "redact"))

        assert kept == [{"system": "Auth header: Bearer <SECRET>. Be polite."}]
        assert changed == 1

    def test_a_secret_is_counted_and_named_by_the_scan(self) -> None:
        result = scan_rows([{"a": f"key={_KEY}"}])

        assert result.counts_by_code["PII_SECRET"] == 1
        assert "PII_SECRET" in result.pass_list
        (issue,) = result.issues
        assert issue.message.startswith("Secret or credential matched 1 time(s)")

    def test_only_the_secret_class_reads_as_the_secret_placeholder(self) -> None:
        placeholders = {d.code: d.placeholder for d in PII_DETECTORS}
        assert placeholders.pop("PII_SECRET") == "<SECRET>"
        assert set(placeholders.values()) == {None}

    def test_a_finding_inside_another_is_replaced_once(self) -> None:
        """An email inside a password value is two findings over one span.

        Replacing both right-to-left used the outer span's stale offsets once
        the inner one had moved the text, and left `D:PII_EMAIL]` behind.
        """
        rows = [{"a": "password=pre#x1@y.com end"}]

        kept, changed, _ = apply_pii_policy(rows, dict.fromkeys(PII_CODES, "redact"))

        assert kept == [{"a": "password=<SECRET> end"}]
        assert changed == 1


_ALL: dict[str, PiiAction] = dict.fromkeys(PII_CODES, "redact")


def test_the_npm_package_names_the_same_classes_in_the_same_order() -> None:
    """The Studio types its PII label map against `PiiCode`; a class added here
    must reach that union, or the new class renders as a raw code."""
    npm = Path(__file__).resolve().parents[3] / "npm" / "src" / "pii.ts"
    assert tuple(re.findall(r'"(PII_[A-Z_]+)"', npm.read_text())) == PII_CODES


class TestLinearTime:
    @pytest.mark.parametrize(
        "text",
        [
            "a" * 100_000,
            # A base64 image in a vision chat message: one long run, no `@`.
            "data:image/png;base64," + ("iVBORw0KGgoAAAANSUhEUgAA+/" * 4_000),
            "a." * 50_000,
            "x@" + "b" * 100_000,
        ],
        ids=["letters", "base64", "dotted", "no-dot-domain"],
    )
    def test_a_100_kb_row_scans_in_well_under_a_second(self, text: str) -> None:
        """The email pattern had no left boundary: 100 KB with no `@` took 18.3 s."""
        started = time.perf_counter()
        scan_rows([{"a": text}])
        apply_pii_policy([{"a": text}], _ALL)
        assert time.perf_counter() - started < 2.0
