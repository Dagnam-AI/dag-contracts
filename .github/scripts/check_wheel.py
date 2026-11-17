"""Run by CI from an empty directory, against the BUILT wheel installed into a clean venv.

``EXPECT_BACKEND`` is ``rust`` (the compiled core answers) or ``python`` (the core is
absent, off, or is the stub wheel of a platform with no native wheel). One real call on
each hygiene seam proves the backend answers, not merely that it imported.
"""

import importlib
import os
import sys

import dagnam_contracts
from dagnam_contracts.hygiene import backend, compute_near_duplicates
from dagnam_contracts.hygiene.spans import findings

assert "site-packages" in dagnam_contracts.__file__, dagnam_contracts.__file__
expected = os.environ["EXPECT_BACKEND"]
assert backend() == expected, (backend(), expected)
assert ("dagnam_core.hygiene" in sys.modules) == (expected == "rust")

spans = [(s, e, d.code) for s, e, d in findings("write to jane@example.com today")]
assert spans == [(9, 25, "PII_EMAIL")], spans

rows = [{"t": "one two three four"}, {"t": "one two three four"}, {"t": "five six"}]
result = compute_near_duplicates(rows)
assert result.duplicate_indices == [1], result
assert [(p.kept_index, p.duplicate_index, p.similarity) for p in result.pairs] == [(0, 1, 1.0)]

if os.environ.get("EXPECT_STUB") == "1":
    # The stub wheel: the package imports, the compiled module does not.
    import dagnam_core

    try:
        importlib.import_module("dagnam_core.hygiene")
    except ImportError:
        pass
    else:
        raise AssertionError("the stub wheel was expected, the native one is installed")
    print("ok: stub", dagnam_core.__version__)

print("ok:", backend(), sys.version.split()[0], spans)
