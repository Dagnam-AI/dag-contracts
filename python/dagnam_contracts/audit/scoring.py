"""Agreement between a candidate and the teacher on a holdout, as the contract defines it.

Pure Python over the standard library. Labels and short spans score as
normalized exact match (with macro-F1 alongside); JSON objects score per
field, micro-averaged; tool calls score per row, the tool's name first.
Every score carries ``n`` and a 95% Wilson interval on
the headline value, and the frontier decides on the interval's lower bound,
never the point estimate. The SDK scores a holdout on the customer's machine
and the platform scores one on a worker, so both sides live here.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
import json
import math
import string
from typing import Any

from dagnam_contracts.audit.verdict import MIN_CLASS_SUPPORT
from dagnam_contracts.normalize import JsonValue

Z95 = 1.959963984540054
"""Two-sided 95% normal quantile."""

# Both ends, unlike dag-lib `derive.py`'s `rstrip`: a quoted `"Refund"` has to normalize
# like a bare one. dag-lib adopts this at its cutover, so the two stay one definition.
_SURROUNDING = string.punctuation + string.whitespace


def normalize_label(text: str) -> str:
    """Strip, casefold and drop surrounding punctuation, so ``"Returns."`` and ``"returns"`` agree."""
    return text.strip().casefold().strip(_SURROUNDING)


@dataclass(frozen=True, slots=True)
class Agreement:
    """A score with its sample size and interval; the extra fields depend on ``metric``."""

    metric: str
    value: float
    ci95: tuple[float, float]
    n: int
    exact: float | None = None
    macro_f1: float | None = None
    field_precision: float | None = None
    field_recall: float | None = None
    field_f1: float | None = None
    min_class_recall: float | None = None

    def to_json(self) -> dict[str, JsonValue]:
        """The ``agreement`` object of ``audit-report.json`` (spec section 7).

        A label block (``metric: "exact"``) always carries ``min_class_recall``,
        ``null`` when no class had the support to count.
        """
        extras: dict[str, JsonValue] = {
            key: value
            for key, value in (
                ("exact", self.exact),
                ("macro_f1", self.macro_f1),
                ("field_precision", self.field_precision),
                ("field_recall", self.field_recall),
                ("field_f1", self.field_f1),
            )
            if value is not None
        }
        if self.metric == "exact":
            extras["min_class_recall"] = self.min_class_recall
        return {
            "metric": self.metric,
            "value": self.value,
            "ci95": [self.ci95[0], self.ci95[1]],
            "n": self.n,
            **extras,
        }


def wilson_interval(successes: int, n: int, *, z: float = Z95) -> tuple[float, float]:
    """The Wilson score interval for ``successes`` out of ``n``; ``(0, 1)`` when ``n`` is 0."""
    return _wilson(successes / n if n else 0.0, n, z)


def _wilson(p: float, n: int, z: float) -> tuple[float, float]:
    """The Wilson score interval around a proportion ``p`` observed over ``n`` trials."""
    if n == 0:
        return (0.0, 1.0)
    denominator = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denominator
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denominator
    return (max(0.0, center - half), min(1.0, center + half))


def _f1(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return precision, recall, f1


def _paired(pred: Sequence[str], truth: Sequence[str]) -> None:
    if len(pred) != len(truth):
        raise ValueError(f"{len(pred)} predictions but {len(truth)} truths")


def score_labels(pred: Sequence[str], truth: Sequence[str]) -> Agreement:
    """Normalized exact match (the headline, with its Wilson interval) plus macro-F1.

    Both sides go through :func:`normalize_label`, so ``"Billing."`` agrees
    with ``"billing"``. Macro-F1 averages the per-class F1 over every class
    either side produced. ``min_class_recall`` is the worst recall over the
    truth classes with at least :data:`MIN_CLASS_SUPPORT` holdout rows
    (``None`` when none has), which the frontier holds to
    :data:`MIN_CLASS_RECALL_FLOOR`.
    """
    _paired(pred, truth)
    pairs = [(normalize_label(p), normalize_label(t)) for p, t in zip(pred, truth, strict=True)]
    hits = sum(p == t for p, t in pairs)
    classes = {label for pair in pairs for label in pair}
    f1s = [
        _f1(
            sum(p == t == c for p, t in pairs),
            sum(p == c != t for p, t in pairs),
            sum(t == c != p for p, t in pairs),
        )[2]
        for c in classes
    ]
    support = Counter(t for _, t in pairs)
    recalls = [
        sum(p == t == c for p, t in pairs) / count
        for c, count in support.items()
        if count >= MIN_CLASS_SUPPORT
    ]
    n = len(pairs)
    exact = hits / n if n else 0.0
    return Agreement(
        metric="exact",
        value=exact,
        ci95=wilson_interval(hits, n),
        n=n,
        exact=exact,
        macro_f1=sum(f1s) / len(f1s) if f1s else 0.0,
        min_class_recall=min(recalls) if recalls else None,
    )


def _parse(text: str) -> Any:
    """``text`` as JSON, or ``None`` -- including a document nested past the parser's depth."""
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def _object_fields(value: Any) -> dict[str, str]:
    """An object's fields as canonical strings; anything else is no fields at all."""
    return {str(k): _canonical(v) for k, v in value.items()} if isinstance(value, dict) else {}


def _fields(text: str) -> dict[str, str]:
    """A JSON object's fields as canonical strings; anything else is no fields at all."""
    return _object_fields(_parse(text))


def modal_keys(truth: Sequence[str]) -> list[str]:
    """The most common key set among the truths that parse as objects, sorted."""
    key_sets = [frozenset(fields) for fields in map(_fields, truth) if fields]
    if not key_sets:
        return []
    return sorted(Counter(key_sets).most_common(1)[0][0])


_CALL_KEYS = frozenset({"arguments", "name"})


def _calls(value: Any) -> list[dict[str, Any]] | None:
    """``value`` as tool calls: one ``{"name", "arguments"}`` object or a list of them."""
    calls = value if isinstance(value, list) else [value]
    if calls and all(isinstance(c, dict) and c.keys() == _CALL_KEYS for c in calls):
        return calls
    return None


def _field_counts(
    p: dict[str, str], t: dict[str, str], keys: Iterable[str]
) -> tuple[int, int, int]:
    """``(tp, fp, fn)`` over ``keys``: a wrong value is both a false positive and a false negative."""
    tp = fp = fn = 0
    for key in keys:
        if key in p and key in t and p[key] == t[key]:
            tp += 1
            continue
        fp += key in p
        fn += key in t
    return tp, fp, fn


def _argument_fields(arguments: Any) -> dict[str, str]:
    """An arguments object's fields; arguments an export kept as a string are one field."""
    return _object_fields(arguments) if isinstance(arguments, dict) else {"": _canonical(arguments)}


def _own_field_counts(pred: Any, truth: Any) -> tuple[int, int, int]:
    """``(tp, fp, fn)`` of two values over the fields either one has."""
    p_fields, t_fields = _argument_fields(pred), _argument_fields(truth)
    return _field_counts(p_fields, t_fields, p_fields.keys() | t_fields.keys())


def _own_f1(tp: int, fp: int, fn: int) -> float:
    """Field-F1, and 1.0 when neither side has a field to compare."""
    return _f1(tp, fp, fn)[2] if tp + fp + fn else 1.0


def _call_score(pred: Any, truth: list[dict[str, Any]]) -> float:
    """One tool-call row: 0 unless every call names the right tool, in order; else the
    arguments' field-F1 over all the calls, 1.0 when neither side has any arguments."""
    calls = _calls(pred)
    if calls is None or len(calls) != len(truth):
        return 0.0
    tp = fp = fn = 0
    for p, t in zip(calls, truth, strict=True):
        if p["name"] != t["name"]:
            return 0.0
        c_tp, c_fp, c_fn = _own_field_counts(p["arguments"], t["arguments"])
        tp, fp, fn = tp + c_tp, fp + c_fp, fn + c_fn
    return _own_f1(tp, fp, fn)


def _row_score(p_text: str, t_text: str, truth_calls: list[dict[str, Any]] | None) -> float:
    """One row of a tool-call workload, by what its truth is.

    A call is scored as a call. Any other JSON is compared on its own fields
    -- not on ``keys``, which in such a workload are the calls' own. Text that
    is not JSON at all (an agent that sometimes just answers) is a normalized
    exact match, as a label is.
    """
    if truth_calls is not None:
        return _call_score(_parse(p_text), truth_calls)
    truth = _parse(t_text)
    if truth is None:
        return float(normalize_label(p_text) == normalize_label(t_text))
    return _own_f1(*_own_field_counts(_parse(p_text), truth))


def score_json(pred: Sequence[str], truth: Sequence[str], keys: Sequence[str]) -> Agreement:
    """Per-field exact precision/recall/F1 over ``keys``, micro-averaged across rows.

    A field counts as a hit when both objects carry it with the same
    (canonical JSON) value; a wrong value is both a false positive and a false
    negative. The headline is the micro-F1, ``2tp / (2tp+fp+fn)``.

    Its interval is the Wilson interval around that micro-F1 with ``n`` = the
    scored rows, the same ``n`` a label score uses. Wilson on ``2tp`` out of
    ``2tp+fp+fn`` treated every correct field as two independent trials: one
    row of ten correct fields claimed a lower bound of 0.839 where one correct
    label claims 0.207, and fields within a row are not independent anyway --
    they share one prompt and one generation. That interval was too narrow, and
    the frontier decides on its lower bound, so it favoured passing the floor.
    It is still somewhat narrow when rows carry very different numbers of
    fields, since a row with many fields weighs more in the micro-F1 than one
    row's share of ``n``; the modal key set keeps those counts close in practice.

    **Tool calls** are scored per row (``metric: "tool_call"``) as soon as any
    truth is one -- an object whose keys are exactly ``name`` and ``arguments``,
    or a list of them. A row scores 0 unless the prediction calls the same
    tools in the same order, and otherwise its arguments' field-F1; any other
    row is scored on its own content -- other JSON on its own fields, text by
    normalized exact match. The value
    is the mean over rows, with the Wilson interval over the rows. Field-F1
    over ``name`` and ``arguments`` gave a misrouted call a free hit on its
    (usually ``{}``) arguments, so a router that picked the wrong tool 7% of
    the time scored 0.965 and cleared the 0.95 floor.
    """
    _paired(pred, truth)
    truth_calls = [_calls(_parse(t)) for t in truth]
    if any(calls is not None for calls in truth_calls):
        scores = [
            _row_score(p, t, calls) for p, t, calls in zip(pred, truth, truth_calls, strict=True)
        ]
        value = sum(scores) / len(scores)
        return Agreement(
            metric="tool_call", value=value, ci95=_wilson(value, len(scores), Z95), n=len(scores)
        )
    tp = fp = fn = 0
    for p_text, t_text in zip(pred, truth, strict=True):
        row_tp, row_fp, row_fn = _field_counts(_fields(p_text), _fields(t_text), keys)
        tp, fp, fn = tp + row_tp, fp + row_fp, fn + row_fn
    precision, recall, f1 = _f1(tp, fp, fn)
    return Agreement(
        metric="field_f1",
        value=f1,
        ci95=_wilson(f1, len(pred), Z95),
        n=len(pred),
        field_precision=precision,
        field_recall=recall,
        field_f1=f1,
    )


__all__ = [
    "Z95",
    "Agreement",
    "modal_keys",
    "normalize_label",
    "score_json",
    "score_labels",
    "wilson_interval",
]
