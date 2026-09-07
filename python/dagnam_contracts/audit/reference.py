"""Open instruct models the report compares against, as reference rows (never measured)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from importlib import resources
import json

REFERENCE_AS_OF = date(2026, 9, 7)
"""The day every bundled row was checked against its Hugging Face model card."""


@dataclass(frozen=True, slots=True)
class ReferenceModel:
    """One open instruct model: its hub id, series, parameter count, license and context window."""

    id: str
    family: str
    parameters: int
    license: str
    context_length: int


def load_reference_models() -> list[ReferenceModel]:
    """The bundled ``open-models.json`` as typed rows."""
    text = resources.files("dagnam_contracts.audit").joinpath("open-models.json").read_text("utf-8")
    return [ReferenceModel(**row) for row in json.loads(text)["models"]]


__all__ = ["REFERENCE_AS_OF", "ReferenceModel", "load_reference_models"]
