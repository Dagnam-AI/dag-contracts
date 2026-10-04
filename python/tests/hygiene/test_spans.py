"""Tests for `dagnam_contracts/hygiene/spans.py`: the segment engine under every redaction.

A placeholder is an opaque token, a finding is decided on the text between placeholders
read as a string of its own, and the findings of a string are the fixed point of cutting
at the accepted spans and reading what is left again. These tests hold the pieces of
that: where the cuts are, how overlapping candidates become one region, that the fixed
point is a fixed point, and what it costs.
"""

from __future__ import annotations

from collections import Counter
from itertools import pairwise, product
import random

from pii_corpus import SAMPLES, SHAPE_NAMES, SHAPES, TEXTS, everything_problems, found
import pytest

from dagnam_contracts.hygiene.detectors import PII_CODES, PII_DETECTORS, REDACTION_TEMPLATE
from dagnam_contracts.hygiene.spans import (
    PLACEHOLDER,
    WINDOW,
    Span,
    _holds_content,
    detect,
    findings,
    member_text,
    redact_both,
    render,
    resolve,
    rounds_needed,
    segments,
)

_BY_CODE = {detector.code: detector for detector in PII_DETECTORS}
_EMAIL, _PHONE, _SECRET = _BY_CODE["PII_EMAIL"], _BY_CODE["PII_PHONE"], _BY_CODE["PII_SECRET"]
_EVERY_PLACEHOLDER = [
    *(REDACTION_TEMPLATE.format(code=detector.code) for detector in PII_DETECTORS),
    "[REDACTED:PII_OF_A_LATER_VERSION]",
]


class TestSegments:
    def test_text_without_a_placeholder_is_one_segment(self) -> None:
        assert segments("call me maybe") == [(0, 13)]
        assert segments("") == []

    @pytest.mark.parametrize("placeholder", _EVERY_PLACEHOLDER)
    def test_every_placeholder_is_a_cut(self, placeholder: str) -> None:
        text = f"ab{placeholder}cd"

        assert segments(text) == [(0, 2), (2 + len(placeholder), 4 + len(placeholder))]

    def test_the_secret_placeholder_is_a_cut(self) -> None:
        assert segments("a<SECRET>b") == [(0, 1), (9, 10)]

    def test_no_empty_segment_at_either_end_or_between_placeholders(self) -> None:
        text = "<SECRET>[REDACTED:PII_EMAIL]x<SECRET>"

        assert segments(text) == [(28, 29)]
        assert segments("<SECRET><SECRET>") == []

    @pytest.mark.parametrize("placeholder", _EVERY_PLACEHOLDER)
    def test_a_placeholder_never_joins_text_into_a_longer_placeholder(
        self, placeholder: str
    ) -> None:
        """Whatever stands beside a placeholder -- pieces of another one, brackets, a code --
        the cuts are exactly where it is and nowhere else: the segments are the text
        either side, unchanged."""
        pieces = ["", "[", "]", "<", ">", "[REDACTED:", "PII_", "PII_EMAIL", "ET>", "<SECR", "x:"]
        for before, after in product(pieces, pieces):
            text = before + placeholder + after
            expected = [
                (a, b)
                for a, b in [
                    (0, len(before)),
                    (len(before) + len(placeholder), len(text)),
                ]
                if b > a
            ]

            assert segments(text) == expected, text

    def test_an_unterminated_placeholder_is_text(self) -> None:
        assert segments("[REDACTED:PII_EMAIL") == [(0, 19)]
        assert segments("<SECRET") == [(0, 7)]
        assert segments("[REDACTED:pii_email]") == [(0, 20)]


class TestMemberText:
    def test_a_value_that_is_only_placeholders_is_empty(self) -> None:
        assert member_text("<SECRET>") == ""
        assert member_text("[REDACTED:PII_EMAIL]<SECRET>") == ""

    def test_the_text_between_placeholders_is_joined_by_one_space(self) -> None:
        assert member_text("a<SECRET>b") == "a b"
        assert member_text("pw=[REDACTED:PII_EMAIL]!x") == "pw= !x"
        assert member_text("plain") == "plain"

    def test_separators_between_placeholders_are_kept_as_they_are(self) -> None:
        assert member_text("<SECRET>/<SECRET>") == "/"


class TestResolve:
    def test_disjoint_candidates_stay_separate_and_sorted(self) -> None:
        spans: list[Span] = [(10, 12, _PHONE), (0, 3, _EMAIL)]

        assert resolve(spans) == [(0, 3, _EMAIL), (10, 12, _PHONE)]

    def test_touching_candidates_are_not_one_region(self) -> None:
        assert resolve([(0, 3, _EMAIL), (3, 6, _SECRET)]) == [(0, 3, _EMAIL), (3, 6, _SECRET)]

    def test_overlapping_candidates_are_one_region_over_their_union(self) -> None:
        assert resolve([(0, 8, _EMAIL), (5, 12, _SECRET)]) == [(0, 12, _EMAIL)]
        assert resolve([(0, 8, _EMAIL), (2, 4, _SECRET)]) == [(0, 8, _EMAIL)]

    def test_a_loose_class_never_names_a_region_a_stricter_one_overlaps(self) -> None:
        """A phone pattern reads digits of an address or an id; the other class names it."""
        assert resolve([(0, 10, _PHONE), (4, 8, _SECRET)]) == [(0, 10, _SECRET)]
        assert resolve([(0, 10, _SECRET), (4, 14, _PHONE)]) == [(0, 14, _SECRET)]

    def test_the_earlier_start_names_the_region(self) -> None:
        assert resolve([(0, 8, _SECRET), (5, 12, _EMAIL)]) == [(0, 12, _SECRET)]

    def test_the_shorter_span_names_it_when_they_start_together(self) -> None:
        """`pw` (a URL password) against `pw@host.com` (an address read over it)."""
        assert resolve([(0, 18, _EMAIL), (0, 2, _SECRET)]) == [(0, 18, _SECRET)]

    def test_the_registry_order_names_it_on_a_tie(self) -> None:
        assert resolve([(0, 5, _SECRET), (0, 5, _EMAIL)]) == [(0, 5, _EMAIL)]

    def test_a_chain_of_overlaps_is_one_region(self) -> None:
        assert resolve([(0, 4, _EMAIL), (3, 7, _SECRET), (6, 9, _EMAIL)]) == [(0, 9, _EMAIL)]

    def test_the_answer_does_not_depend_on_the_order_candidates_arrive_in(self) -> None:
        generator = random.Random(2026)
        candidates: list[Span] = [
            (start, start + generator.randint(1, 9), generator.choice(PII_DETECTORS))
            for start in (generator.randint(0, 40) for _ in range(60))
        ]
        expected = resolve(candidates)
        for _ in range(20):
            generator.shuffle(candidates)
            assert resolve(candidates) == expected


class TestDetect:
    def test_every_detector_reads_the_piece_and_empty_spans_are_dropped(self) -> None:
        spans = detect("jane@example.com +44 20 7946 0958")

        assert {(start, end, detector.code) for start, end, detector in spans} >= {
            (0, 16, "PII_EMAIL"),
            (17, 33, "PII_PHONE"),
        }
        assert all(end > start for start, end, _ in spans)


class TestFindings:
    def test_nothing_in_text_with_no_finding(self) -> None:
        assert findings("hello world") == []
        assert findings("") == []

    def test_findings_are_sorted_disjoint_and_never_inside_a_placeholder(self) -> None:
        text = "a@b.co <SECRET> +44 20 7946 0958 [REDACTED:PII_EMAIL] 4111111111111111"

        spans = findings(text)

        assert [detector.code for _, _, detector in spans] == [
            "PII_EMAIL",
            "PII_PHONE",
            "PII_PAYMENT_CARD",
        ]
        assert [start for start, _, _ in spans] == sorted(start for start, _, _ in spans)
        assert all(a[1] <= b[0] for a, b in pairwise(spans))
        assert not any(PLACEHOLDER.search(text[start:end]) for start, end, _ in spans)

    def test_a_finding_hidden_by_its_neighbour_is_found_in_the_same_read(self) -> None:
        """The digit a secret ends in is what the phone pattern refuses to follow."""
        text = "password: hunter22 +1 415-555-0132"

        assert [(text[start:end], detector.code) for start, end, detector in findings(text)] == [
            ("hunter22", "PII_SECRET"),
            ("+1 415-555-0132", "PII_PHONE"),
        ]

    def test_a_chain_of_findings_that_each_hide_the_next_is_read_a_window_apiece(self) -> None:
        text = "Aadhaar Number 580927525309" * 3_000
        stats: Counter[str] = Counter()

        spans = findings(text, stats)

        assert len(spans) == 3_000
        assert stats["full reads"] == 1
        assert stats["windows"] <= 3_000 + 2

    def test_a_long_finding_at_the_edge_of_a_window_is_read_whole(self) -> None:
        """A PEM block longer than the window, after a finding it is glued to."""
        pem = "-----BEGIN PRIVATE KEY-----" + "x" * (4 * WINDOW) + "-----END PRIVATE KEY-----"
        text = "4111111111111111" + pem

        assert [(start, end, d.code) for start, end, d in findings(text)] == [
            (0, 16, "PII_PAYMENT_CARD"),
            (16, len(text), "PII_SECRET"),
        ]

    def test_text_after_a_finding_longer_than_a_window_is_read_whole_too(self) -> None:
        text = "jane@example.com" + "x" * (3 * WINDOW) + "+44 20 7946 0958" + "Pwd=letmein4"

        assert [d.code for _, _, d in findings(text)] == ["PII_EMAIL", "PII_PHONE", "PII_SECRET"]

    def test_findings_before_the_first_one_a_window_finds_are_not_lost(self) -> None:
        """A finding after the accepted span, with ordinary text between that has letters:
        the text before it is read again, because its right edge changed."""
        text = "jane@example.com ids 4111111111111111SIN 130 692 544"

        assert [d.code for _, _, d in findings(text)] == [
            "PII_EMAIL",
            "PII_PAYMENT_CARD",
            "PII_CA_SIN",
        ]

    @pytest.mark.parametrize("text", TEXTS[::5])
    def test_the_text_that_is_left_holds_no_finding(self, text: str) -> None:
        """The fixed point: render every finding, and every segment of what is left,
        read alone, is clean."""
        every = {detector.code for detector in PII_DETECTORS}
        left = render(text, findings(text), every)

        assert findings(left) == []
        assert render(left, findings(left), every) == left


class TestRender:
    def test_a_span_of_an_acted_class_is_replaced_and_another_is_left(self) -> None:
        text = "a@b.co password: hunter22"
        spans = findings(text)

        assert render(text, spans, {"PII_EMAIL"}) == "[REDACTED:PII_EMAIL] password: hunter22"
        assert render(text, spans, {"PII_SECRET"}) == "a@b.co password: <SECRET>"
        assert render(text, spans, set()) == text
        assert render(text, spans, PII_CODES) == "[REDACTED:PII_EMAIL] password: <SECRET>"


class TestRedactBoth:
    def test_text_with_no_finding_comes_back_as_itself(self) -> None:
        text = "nothing here"

        full, acted, counts = redact_both(text, set(PII_CODES))

        assert full is text
        assert acted is text
        assert counts == Counter()

    def test_the_full_and_the_acted_text_and_every_class_counted(self) -> None:
        full, acted, counts = redact_both("a@b.co password: hunter22", {"PII_EMAIL"})

        assert full == "[REDACTED:PII_EMAIL] password: <SECRET>"
        assert acted == "[REDACTED:PII_EMAIL] password: hunter22"
        assert counts == Counter({"PII_EMAIL": 1, "PII_SECRET": 1})

    def test_acting_on_every_class_is_the_full_text(self) -> None:
        full, acted, _ = redact_both("a@b.co password: hunter22", PII_CODES)

        assert acted == full


class TestWhatTheFixedPointCosts:
    def test_a_piece_is_read_whole_a_handful_of_times_at_most(self) -> None:
        """Every pinned input and every pair of samples: the most any piece is read whole."""
        pool = sorted(sample for samples in SAMPLES.values() for sample in samples)
        texts = [*TEXTS, *(f"{a}{s}{b}" for a, b in product(pool, pool) for s in (" ", ""))]

        assert max(rounds_needed(text) for text in texts) <= 6

    @pytest.mark.parametrize(
        "unit",
        [
            "+1415555{:04d} ",
            "Aadhaar Number 580927525309",
            "pwd=x1 4111111111111111 ",
            "password: hunter22 +1 415-555-0132 ",
            "4111111111111111-----BEGIN PRIVATE KEY-----x-----END PRIVATE KEY----- ",
            "+44 20 7946 0958DE89 3704 0044 0532 0130 00",
            "password=[REDACTED:PII_EMAIL]!x ",
            "jane@example.com ",
            "SIN ",
            ":",
        ],
    )
    def test_the_work_grows_with_the_text_and_no_faster(self, unit: str) -> None:
        """Characters read, whole or through a window: four times the text, at most about
        four times the reading, and a small multiple of the text."""

        def read(size: int) -> int:
            text = "".join(unit.format(i) for i in range(size // len(unit) + 1))[:size]
            stats: Counter[str] = Counter()
            findings(text, stats)
            return stats["characters read"]

        small, large = read(60_000), read(240_000)

        assert large <= 4.5 * small
        assert large <= 40 * 240_000


_ADDRESS = "alice@example.com"
# The shortest text each class finds; the two that need no letter or digit are the address
# (`_@_._`) and the password of a URL (`://:-@`).
_SHORTEST: dict[str, list[str]] = {
    "PII_EMAIL": ["_@_._", "a@b.c"],
    "PII_PHONE": ["+123456789", "415 555 0132"],
    "PII_PAYMENT_CARD": ["4111111111111111"],
    "PII_NATIONAL_ID": ["078-05-1120"],
    "PII_SECRET": [
        "://:-@",
        "pwd=x",
        "password=abc123",
        "Bearer aaaaaaaaaaaaaaaaaaaa",
        "-----BEGIN PRIVATE KEY-----",
    ],
    "PII_IBAN": ["GB29NWBK60161331926819"],
    "PII_IP_ADDRESS": ["1.2.3.4"],
    "PII_DATE_OF_BIRTH": ["DOB 1/1/90"],
    "PII_UK_NINO": ["AB123456C"],
    "PII_CA_SIN": ["SIN 130692544"],
    "PII_IN_AADHAAR": ["2345 6789 0124"],
    "PII_IN_PAN": ["ABCPE1234F"],
    "PII_EU_VAT": ["DE123456789"],
}


class TestWhatAPieceMustHoldToBeRead:
    def test_every_class_has_a_shortest_match_and_every_one_is_read(self) -> None:
        """The shortcut that skips a piece with nothing in it may be no narrower than what
        the patterns need: each class's shortest match must count as content."""
        assert sorted(_SHORTEST) == sorted(PII_CODES)
        for code, texts in _SHORTEST.items():
            detector = _BY_CODE[code]
            for text in texts:
                assert detector.find(text), (code, text)
                assert _holds_content(text), (code, text)

    def test_text_with_no_letter_digit_or_at_sign_holds_no_finding(self) -> None:
        """The converse, fuzzed: over punctuation and whitespace alone, a detector finds
        something only where an at sign is. A new class that breaks this must widen the shortcut."""
        alphabet = list("@:/_.-+ \t\n,;&=()[]<>'\"`%#?!*~^$|{}\\")
        generator = random.Random(2026)
        for _ in range(60_000):
            text = "".join(generator.choice(alphabet) for _ in range(generator.randint(1, 14)))
            if not _holds_content(text):
                assert detect(text) == [], text
            elif "@" not in text:
                assert not any(ch.isalnum() for ch in text)
                assert detect(text) == [], text

    def test_every_short_string_over_the_characters_the_patterns_use_is_clean_without_an_at(
        self,
    ) -> None:
        for size in range(1, 6):
            for chars in product("_@:/.-+ ", repeat=size):
                text = "".join(chars)
                if "@" not in text:
                    assert detect(text) == [], text

    @pytest.mark.parametrize("name", ["alike", "pluses", "hyphen"])
    def test_an_address_made_of_punctuation_behind_another_is_read(self, name: str) -> None:
        """The cut that reveals it leaves a piece with no letter or digit; skipped, it is never
        read as a string of its own and the rescan reads it."""
        text = {
            "alike": f"{_ADDRESS}+_@_._",
            "pluses": "_@_._+_@_._",
            "hyphen": f"{_ADDRESS}-.@-.-",
        }[name]

        assert [(text[a:b], d.code) for a, b, d in findings(text)][-1][1] == "PII_EMAIL"
        assert len(findings(text)) == 2
        for shape in SHAPE_NAMES:
            assert everything_problems(SHAPES[shape](text)) == []
        assert found([{"text": text}]) == {"PII_EMAIL": 2}

    def test_a_url_password_of_punctuation_behind_an_address_is_read(self) -> None:
        text = f"{_ADDRESS}+x://:-@h"

        assert everything_problems({"text": text}) == []


class TestAFindingWhoseKeywordIsInsideTheOneBeforeIt:
    def test_a_window_keeps_every_region_it_can_trust(self) -> None:
        """The PEM header's first hyphen hides the number from its right-hand guard, so it
        is found only once the header is a finding. Then `pwd=Social` takes the first word
        of `Social Insurance Number`, and the window that reads the number holds both: taking
        only its first region left the number's digits with no keyword left to find them by."""
        text = (
            f"{SAMPLES['PII_IN_AADHAAR'][1]}pwd=Social Insurance Number 130 692 544"
            "-----BEGIN PRIVATE KEY-----"
        )

        spans = findings(text)

        assert [(d.code, text[a:b]) for a, b, d in spans] == [
            ("PII_IN_AADHAAR", "2345 6789 0124"),
            ("PII_SECRET", "Social"),
            ("PII_CA_SIN", "130 692 544"),
            ("PII_SECRET", "-----BEGIN PRIVATE KEY-----"),
        ]
        assert everything_problems({"text": text}) == []
