"""The five limits of a near-duplicate batch, in one place.

They are defined here, and not in `near_dedup`, because `_backend` must read them to decide
whether the compiled core enforces the same five (it is used only if it does), and `near_dedup`
imports `_backend`. The public names are `dagnam_contracts.hygiene.near_dedup.MAX_*`.
"""

MAX_TEXTS = 50_000
"""The most rows `compute_near_duplicates` takes: more raises `NearDedupLimitError`."""

MAX_TEXT_CHARS = 1_000_000
"""The most characters in one row's string values (joined by a space), as sent and as
compared."""

MAX_TOTAL_CHARS = 20_000_000
"""The most characters in the string values of all the rows together, as sent and as
compared."""

MAX_COMPARISONS = 40_000_000
"""The most candidate pairs the walk compares, in Python and in the core (see the
`near_dedup` module docstring).

A candidate pair is two rows that share an LSH band, counted once however many bands they
share, whether or not it turns out to be a near-duplicate. The call raises
`NearDedupLimitError` instead of making the comparison after the last one this allows.

The count at which two implementations stop is the same because the candidates are walked
in one deterministic order, the one `_candidate_pairs` defines: ascending ``left`` row,
and for each ``left`` its ``right`` rows ascending, each pair once. A port counts the
pairs it yields in that order.
"""

MAX_PAIRS = 20_000_000
"""The most near-duplicate pairs `compute_near_duplicates` returns.

The result lists every pair of rows judged near-duplicates, so a batch of n identical rows
has n * (n - 1) / 2 of them (about 6,300 identical rows reach this); past this many the call
raises `NearDedupLimitError`. Rows whose string values are all empty or all punctuation, and
rows with no string values at all, compare as the same empty text.
"""
