"""The packaging promise: the compiled core is a default dependency, pinned exactly.

Reads ``pyproject.toml`` and the lock, and builds the wheel to read what a user's installer
will see. The contract must match the core's behaviour exactly (a core release can change a
result without changing its binding), so the pin is ``==``, never a range, and every core
release is a release of this package.
"""

from __future__ import annotations

from email.parser import Parser
from pathlib import Path
import re
import subprocess
import tomllib
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
PIN = re.compile(r"^dagnam-core==(\d+\.\d+\.\d+)$")


def _pin() -> str:
    [requirement] = PYPROJECT["project"]["dependencies"]
    match = PIN.fullmatch(requirement)
    assert match, requirement  # exactly one entry, `==`, and no environment marker
    return requirement


def test_the_core_is_the_one_default_dependency_and_has_no_marker() -> None:
    assert PIN.fullmatch(_pin())
    assert ";" not in _pin()


def test_the_fast_extra_is_kept_as_an_alias_with_the_same_pin() -> None:
    assert PYPROJECT["project"]["optional-dependencies"] == {"fast": [_pin()]}


def test_the_dev_group_holds_the_same_pin() -> None:
    assert _pin() in PYPROJECT["dependency-groups"]["dev"]


def test_the_lock_resolves_the_pinned_core() -> None:
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    [core] = [package for package in lock["package"] if package["name"] == "dagnam-core"]
    assert f"dagnam-core=={core['version']}" == _pin()


@pytest.fixture(scope="module")
def metadata(tmp_path_factory: pytest.TempPathFactory) -> dict[str, list[str]]:
    out = tmp_path_factory.mktemp("wheel")
    subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(out), str(ROOT)],
        check=True,
        capture_output=True,
    )
    [wheel] = out.glob("*.whl")
    with zipfile.ZipFile(wheel) as archive:
        [name] = [n for n in archive.namelist() if n.endswith(".dist-info/METADATA")]
        message = Parser().parsestr(archive.read(name).decode("utf-8"))
    return {key: message.get_all(key) or [] for key in ("Requires-Dist", "Provides-Extra")}


def test_the_built_wheel_requires_the_pin_unconditionally(metadata: dict[str, list[str]]) -> None:
    # Unconditional: no "; extra == ..." and no platform marker on the default requirement.
    assert _pin() in metadata["Requires-Dist"]
    assert metadata["Provides-Extra"] == ["fast"]
    assert f"{_pin()}; extra == 'fast'" in metadata["Requires-Dist"]
