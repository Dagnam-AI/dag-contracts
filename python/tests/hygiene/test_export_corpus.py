import json
from pathlib import Path

from export_corpus import export

from dagnam_contracts.hygiene.near_dedup import minhash_signature
from dagnam_contracts.hygiene.spans import findings


def test_export_writes_cases_the_reference_reproduces(tmp_path: Path) -> None:
    export(tmp_path)
    minhash = [json.loads(line) for line in (tmp_path / "minhash.jsonl").read_text().splitlines()]
    found = [json.loads(line) for line in (tmp_path / "findings.jsonl").read_text().splitlines()]
    assert len(minhash) >= 50 and len(found) >= 500
    case = minhash[0]
    assert [str(v) for v in minhash_signature(frozenset(case["shingles"]))] == case["signature"]
    case = found[0]
    assert [[s, e, d.code] for s, e, d in findings(case["text"])] == case["spans"]


def test_export_is_deterministic_and_skips_text_that_is_not_utf8(tmp_path: Path) -> None:
    export(tmp_path / "a")
    export(tmp_path / "b")
    for name in ("minhash.jsonl", "near_dedup.jsonl", "findings.jsonl"):
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()
        (tmp_path / "a" / name).read_bytes().decode("utf-8")
