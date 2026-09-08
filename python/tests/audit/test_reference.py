"""Tests for dagnam_contracts/audit/reference.py — the bundled open-model reference rows."""

from __future__ import annotations

from datetime import date
from importlib import resources
import json
from typing import Any

from dagnam_contracts.audit.reference import REFERENCE_AS_OF, load_reference_models


def _bundled() -> dict[str, Any]:
    text = resources.files("dagnam_contracts.audit").joinpath("open-models.json").read_text("utf-8")
    return json.loads(text)


def test_reference_rows_are_well_formed_and_dated() -> None:
    rows = load_reference_models()
    assert len(rows) >= 8
    assert isinstance(REFERENCE_AS_OF, date)
    ids = [r.id for r in rows]
    assert len(ids) == len(set(ids))
    for row in rows:
        assert row.parameters > 0 and row.context_length > 0
        assert row.family and row.license


def test_every_row_names_the_source_it_was_verified_against() -> None:
    """A row nobody checked must not ship, so a row with no ``_sources`` entry fails here."""
    bundled = _bundled()
    sources = bundled["_sources"]
    assert {row["id"] for row in bundled["models"]} == set(sources)
    for urls in sources.values():
        assert urls
        assert all(url.startswith("https://huggingface.co/") for url in urls)


def test_the_bundled_date_is_the_exported_one() -> None:
    """``REFERENCE_AS_OF`` is what a report prints; a JSON refresh that skips it would lie."""
    assert _bundled()["as_of"] == REFERENCE_AS_OF.isoformat()
