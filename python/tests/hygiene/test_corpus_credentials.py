"""The credentials corpus: fragment-assembled cases, and the raw bytes of all four files."""

from collections import Counter
import json
from pathlib import Path
import re
from typing import Any

from corpus_atoms import (
    CONTEXT_LABELS,
    HELD_CODE,
    HOSTPARTS,
    NESTED,
    TEST_STEMS,
    URL_LABEL,
    URL_SCHEMES,
    URL_SEP,
    WORDS3,
)
from corpus_credentials import shape
from corpus_regions import active_values, leaks, line_safe, regions
from export_corpus import export
import pytest
from test_export_corpus import ALL_NAMES, MARKERS, Corpus, _read

from dagnam_contracts.hygiene import _backend
from dagnam_contracts.hygiene.spans import findings

# The formats of the finder (hygiene/credentials.py) that a case must pin, and the least
# number of cases each has (the corpus holds hundreds; the floor only has to catch a loss).
SHAPES = sorted(
    [
        "assignment_bare",
        "assignment_quoted",
        "aws_key_id",
        *CONTEXT_LABELS,
        "github",
        "gitlab",
        "google",
        "huggingface",
        "jwt",
        "openai_anthropic",
        "pem",
        "slack",
        "stripe",
        URL_LABEL,
    ]
)
LEAST_PER_SHAPE = 20


@pytest.fixture(scope="module")
def corpus(tmp_path_factory: pytest.TempPathFactory) -> Corpus:
    directory = tmp_path_factory.mktemp("credentials")
    return directory, export(directory)


def _cases(corpus: Corpus) -> list[dict[str, Any]]:
    return _read(corpus[0], "credentials.jsonl")


def _spans(text: str) -> list[list[Any]]:
    """What the Python reference reports: the corpus is its answer, whichever backend is
    active (the compiled core is held to the corpus by its own repository, and to the
    reference by `test_differential.py`)."""
    with _backend.reference():
        return [[s, e, d.code] for s, e, d in findings(text)]


def test_every_case_assembles_to_the_text_the_reference_reports_on(corpus: Corpus) -> None:
    cases = _cases(corpus)
    assert len(cases) == corpus[1]["credentials"] >= 1000
    for case in cases:
        assert all(case["parts"]), case
        assert _spans("".join(case["parts"])) == case["spans"]


def test_the_cases_are_sorted_and_not_repeated(corpus: Corpus) -> None:
    texts = ["".join(case["parts"]) for case in _cases(corpus)]
    assert texts == sorted(set(texts))


def test_every_credential_is_in_pieces_and_no_piece_holds_a_marker(corpus: Corpus) -> None:
    for case in _cases(corpus):
        at = 0
        for part in case["parts"]:
            end = at + len(part)
            inside = any(s < end and at < e for s, e, code in case["spans"] if code == HELD_CODE)
            assert not inside or len(part) <= 4, part
            assert not any(marker.casefold() in part.casefold() for marker in MARKERS), part
            at = end


def test_every_format_of_the_finder_has_cases_and_some_cases_are_near_misses(
    corpus: Corpus,
) -> None:
    counts = corpus[1]
    for name in SHAPES:
        assert counts[f"credentials_{name}"] >= LEAST_PER_SHAPE, name
    assert counts["credentials_no_span"] >= LEAST_PER_SHAPE
    shapes = Counter()
    for case in _cases(corpus):
        text = "".join(case["parts"])
        found = {shape(text, s, e) for s, e, code in case["spans"] if code == HELD_CODE}
        shapes.update(found or {"no_span"})
    assert {
        k[len("credentials_") :]: v for k, v in counts.items() if k.startswith("credentials_")
    } == dict(shapes)


def test_the_assembled_texts_do_hold_credential_shapes(corpus: Corpus) -> None:
    # In memory only: proves the fragments assemble to credential-shaped text.
    assembled = ["".join(case["parts"]) for case in _cases(corpus)]
    with_marker = [
        text for text in assembled if any(m.casefold() in text.casefold() for m in MARKERS)
    ]
    assert len(with_marker) > 0
    assert sum(leaks(text) for text in assembled) == len(assembled)
    assert sum(any(code == HELD_CODE for _, _, code in _spans(text)) for text in assembled) > 100


def test_no_marker_is_in_the_raw_bytes_of_any_file_and_no_line_is_held(
    corpus: Corpus,
) -> None:
    for name in ALL_NAMES:
        content = (corpus[0] / name).read_text(encoding="utf-8")
        for marker in MARKERS:
            assert marker.casefold() not in content.casefold(), (name, marker)
        for number, line in enumerate(content.split("\n"), start=1):
            assert HELD_CODE not in {code for _, _, code in _spans(line)}, (name, number)


def test_a_case_serialises_with_a_separator_between_its_parts(corpus: Corpus) -> None:
    raw = (corpus[0] / "credentials.jsonl").read_text(encoding="utf-8").split("\n")[0]
    case = json.loads(raw)
    assert raw == json.dumps(case, ensure_ascii=False, sort_keys=True)
    assert '", "'.join(json.dumps(part, ensure_ascii=False)[1:-1] for part in case["parts"]) in raw


def test_the_credentials_file_is_deterministic(corpus: Corpus, tmp_path: Path) -> None:
    assert export(tmp_path) == corpus[1]
    assert (tmp_path / "credentials.jsonl").read_bytes() == (
        corpus[0] / "credentials.jsonl"
    ).read_bytes()


# What a scanner would read as "a credential-like name, a separator and a value", written
# out here (not imported) so the test does not follow the exporter's own list, and wider
# than it: a stem of a name instead of a name, up to 24 more word characters after it, any
# run of quotes, backslashes and blanks around the separator, and a match at every
# position of the text (a zero-width lookahead), not only after the previous match.
_STEMS = "|".join(TEST_STEMS)
_BLANKS = r"[\s\\\"']{0,16}"
SHAPE = re.compile(
    rf"(?i)(?=((?:{_STEMS})[\w-]{{0,24}}{_BLANKS}(?::=|=>|->|[:=]){_BLANKS}\S{{3,}}))"
)
# A URL whose host part holds credentials, with or without a colon: the span is the host
# part up to its last ``@``, after a colon and one or more slashes (whatever the scheme).
USERINFO = re.compile(r"(?=:/+([^/\s]*@))")
NAME_SHAPES = [SHAPE, USERINFO]
WORDS = list(WORDS3)


def _decoded(corpus: Corpus, name: str) -> list[tuple[str, list[str]]]:
    """Every line of a file, raw and as its decoded strings."""
    out = []
    for line in (corpus[0] / name).read_text(encoding="utf-8").split("\n")[:-1]:
        strings: list[str] = []
        stack: list[Any] = [json.loads(line)]
        while stack:
            item = stack.pop()
            if isinstance(item, str):
                strings.append(item)
            elif isinstance(item, dict):
                stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)
        out.append((line, strings))
    return out


def _strings(corpus: Corpus, name: str) -> set[str]:
    return {string for _, strings in _decoded(corpus, name) for string in strings}


def test_no_value_the_reference_holds_is_whole_in_any_file(corpus: Corpus) -> None:
    values = active_values()
    assert len(values) > 100
    raw_values = [value.casefold() for value in values if line_safe(value)]
    assert len(raw_values) > 100
    for name in ALL_NAMES:
        content = (corpus[0] / name).read_text(encoding="utf-8").casefold()
        assert not [v for v in raw_values if v in content], name
        # NUL joins the decoded strings: no value holds one, so none is found across two.
        decoded = "\x00".join(string.casefold() for string in _strings(corpus, name))
        assert not [v for v in values if v.casefold() in decoded], name


def test_no_name_with_a_value_is_in_any_decoded_string(corpus: Corpus) -> None:
    for name in ALL_NAMES:
        for text in _strings(corpus, name):
            for pattern in NAME_SHAPES:
                assert pattern.search(text) is None, (name, text[:80])
            assert not any(word in text.casefold() for word in WORDS), (name, text[:80])
        for line, _ in _decoded(corpus, name):
            assert not any(pattern.search(line) for pattern in NAME_SHAPES), name


def test_every_region_of_every_case_is_in_pieces(corpus: Corpus) -> None:
    for case in _cases(corpus):
        text = "".join(case["parts"])
        starts = [0]
        for part in case["parts"]:
            starts.append(starts[-1] + len(part))
        # The exporter's regions, and every match of the test's own wider shapes.
        found = [*regions(text), *(m.span(1) for p in NAME_SHAPES for m in p.finditer(text))]
        for start, end in found:
            for part, at in zip(case["parts"], starts, strict=False):
                if at < end and start < at + len(part):
                    assert len(part) <= 4, (part, start, end)


def test_a_name_inside_the_value_of_an_earlier_name_is_a_region_of_its_own() -> None:
    # The first match ends after its own value (cut short by a blank); the second name
    # starts inside it, and only a match at every position finds its value.
    first, second, value = NESTED
    text = f"{first}{second}{value} and more"
    end = text.index(value) + len(value)
    assert any(s <= text.index(value) and end <= e for s, e in regions(text))


def test_a_url_with_credentials_in_its_host_part_is_a_region_with_or_without_a_colon() -> None:
    head = f"{URL_SCHEMES[1]}{URL_SEP}"
    for authority in HOSTPARTS:
        text = head + authority
        (start, end), *_ = regions(text)
        userinfo = authority.split("/")[0]
        assert (start, text[start:end]) == (0, head + userinfo[: userinfo.rindex("@") + 1]), text
    assert not leaks(head + "host/path?a=b")
    assert not leaks(head + "host/a@b")


def test_the_findings_lost_to_a_credential_nearby_are_recovered_as_windows(
    corpus: Corpus,
) -> None:
    counts = corpus[1]
    assert counts["recovered_windows"] > 1000
    recovered = {k: v for k, v in counts.items() if k.startswith("recovered_PII_")}
    assert len(recovered) == 12 and min(recovered.values()) >= 10
