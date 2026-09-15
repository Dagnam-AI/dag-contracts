"""The two distributions ship the same audit data files, byte for byte.

`component-schema.json` is kept in step by `registry/generate.py --check`,
because it is compiled from the registry. These two are hand-authored, so
nothing compiles them into place and only this test stands between a rate
edited on one side and a Studio pricing an audit differently from the wheel
that produced it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_PYTHON = Path(__file__).resolve().parents[2] / "dagnam_contracts" / "audit"
_NPM = Path(__file__).resolve().parents[3] / "npm" / "src"

MIRRORED = ["open-models.json", "serving-rates.json"]


@pytest.mark.parametrize("name", MIRRORED)
def test_the_npm_copy_is_byte_identical_to_the_wheels(name: str) -> None:
    npm = _NPM / name
    assert npm.exists(), f"npm/src/{name} is missing: the tarball would ship without it"
    assert npm.read_bytes() == (_PYTHON / name).read_bytes()
