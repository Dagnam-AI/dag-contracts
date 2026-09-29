"""Every PII class the scan knows: what each is called and how to find it in text.

`pii.py` scans and redacts with this registry; the rules for adding to it are
that module's (a class a pattern gets right, a `PiiDetector` here, never an
``if class == ...`` branch). Each class is pinned in
`tests/hygiene/test_detectors.py` beside the near-misses it must not match.

A class earns its place by what makes it precise, not by the pattern alone:

* a checksum -- Luhn (payment cards, Canadian SIN), mod-97 against the
  country's registered length (IBAN), Verhoeff (Indian Aadhaar);
* a validating parser -- IP addresses go through :mod:`ipaddress`, and
  loopback and unspecified addresses are not personal data (a bare four-part
  version number such as ``1.2.3.4`` is a valid address and is reported;
  ``v1.2.3.4`` is not);
* a strict issuing format -- a US SSN's area/group/serial rules, a UK NINO's
  letter sets, an Indian PAN's holder-type letter, an EU VAT number's member
  state format (format only: no per-state checksum);
* a keyword -- a date is a date of birth only right after ``DOB``, ``date of
  birth``, ``born (on)`` and the like; a Canadian SIN only beside its name
  (``SIN``, ``NAS``, ``social insurance number``), grouped or bare, since
  grouped 9-digit numbers are also French thousands and order ids; and a bare
  12-digit number is an Aadhaar only beside its name (grouped 4-4-4 needs
  none). A number passes Luhn or Verhoeff one time in ten.

Known false positives, accepted: a bare four-part version such as
``1.2.3.4`` is a valid IPv4 address; shape-only classes (NINO, PAN, EU VAT) flag
any string of exactly their shape (``Order DE123456789``); and a grouped
4-4-4 number that passes Verhoeff reads as an Aadhaar, where the phone pattern
already redacted it.

Free-form names and street addresses need NER and are out of scope.

Pure -- no I/O.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import ipaddress
import re

from dagnam_contracts.hygiene.credentials import (
    SECRET_PLACEHOLDER,
    find_secrets,
    is_credential_member,
)

REDACTION_TEMPLATE = "[REDACTED:{code}]"


def _luhn_ok(digits: str) -> bool:
    """Standard Luhn check over a digit string."""
    total = 0
    for position, char in enumerate(reversed(digits)):
        value = int(char)
        if position % 2:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


_CARD_CANDIDATE = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")


def _find_payment_cards(text: str) -> list[tuple[int, int]]:
    """Spans of 13-19 digit runs that pass Luhn.

    The Luhn check is what makes this class worth shipping: without it, every
    order id and phone number in the dataset is a false positive, and a scan
    that cries wolf gets switched off.
    """
    spans: list[tuple[int, int]] = []
    for match in _CARD_CANDIDATE.finditer(text):
        digits = re.sub(r"[ -]", "", match.group())
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            spans.append(match.span())
    return spans


# Not preceded by a digit, a `+`, or a digit-then-separator: the last of the
# three is what stops a 16-digit card number from yielding a 12-digit "phone"
# starting at its second group.
# `(?![\d]|[ -]\d)` is the important half: without it the pattern backtracks
# out of a 16-digit card number and reports its first 12 digits as a phone.
_PHONE_CANDIDATE = re.compile(r"(?<![\d+])(?<![\d][ -])\+?\d(?:[\d\s.()-]{7,20})\d(?![\d]|[ -]\d)")


def _find_phones(text: str) -> list[tuple[int, int]]:
    """Spans that look like a dialable number rather than a long id.

    Filters on top of the pattern, each removing a false positive the corpus
    actually produced: a leading ``+`` admits 9-15 digits, without one the
    floor rises to 10 (which is what stops a dashed 9-digit US SSN reading as
    a phone number); at least one separator or a leading ``+`` is required (a
    bare digit run is an order id far more often than a phone number); and no
    trailing digit, so a 23-digit id cannot yield a 14-digit "phone" from its
    prefix.
    """
    spans: list[tuple[int, int]] = []
    for match in _PHONE_CANDIDATE.finditer(text):
        raw = match.group()
        digits = re.sub(r"\D", "", raw)
        international = raw.startswith("+")
        if not (9 if international else 10) <= len(digits) <= 15:
            continue
        if not international and not re.search(r"[\s.()-]", raw):
            continue
        spans.append(match.span())
    return spans


def _regex_finder(
    pattern: re.Pattern[str], valid: Callable[[str], bool] | None = None
) -> Callable[[str], list[tuple[int, int]]]:
    """Every match's span -- its group ``s`` when the pattern names one -- whose
    digits pass ``valid`` when one is given."""
    group = "s" if "s" in pattern.groupindex else 0

    def _find(text: str) -> list[tuple[int, int]]:
        return [
            match.span(group)
            for match in pattern.finditer(text)
            if valid is None or valid(re.sub(r"\D", "", match[group]))
        ]

    return _find


@dataclass(frozen=True)
class PiiDetector:
    """One finding class: what it is called, and how to locate it in text."""

    code: str
    label: str
    find: Callable[[str], list[tuple[int, int]]]
    placeholder: str | None = None
    """What a redaction writes; ``None`` is `REDACTION_TEMPLATE` with the code."""
    member: Callable[[str, str], bool] | None = None
    """``(key, value text) -> bool``: a JSON member this class finds by its key alone."""
    loose: bool = False
    """A pattern that also covers other classes' spans (a phone pattern reads an IP
    address or an Aadhaar number as digits): where a stricter class's finding
    overlaps one of this class's, the stricter class names the text, once."""

    @property
    def replacement(self) -> str:
        return self.placeholder or REDACTION_TEMPLATE.format(code=self.code)


def _union(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """``spans`` sorted, overlapping ones merged: one finding per stretch of text."""
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


# The SWIFT IBAN registry's length per country.
_IBAN_REGISTRY = (
    "AD24 AE23 AL28 AT20 AZ28 BA20 BE16 BG22 BH22 BI27 BR29 BY28 CH21 CR22 CY28 CZ24 "
    "DE22 DJ27 DK18 DO28 EE20 EG29 ES24 FI18 FK18 FO18 FR27 GB22 GE22 GI23 GL18 GR27 "
    "GT28 HR21 HU28 IE22 IL23 IQ23 IS26 IT27 JO30 KW30 KZ20 LB28 LC32 LI21 LT20 LU20 "
    "LV21 LY25 MC27 MD24 ME22 MK19 MN20 MR27 MT31 MU30 NI28 NL18 NO15 OM23 PK24 PL28 "
    "PS29 PT25 QA29 RO24 RS22 RU33 SA24 SC31 SD18 SE24 SI19 SK24 SM27 SO23 ST25 SV28 "
    "TL23 TN24 TR26 UA29 VA22 VG24 XK20 YE30"
)
_IBAN_LENGTHS = {code: int(n) for code, n in re.findall(r"([A-Z]{2})(\d{2})", _IBAN_REGISTRY)}
# Spaced in fours or compact; a candidate may run on into a following word,
# which the registered length then trims off.
_IBAN_CANDIDATE = re.compile(
    r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?(?![A-Za-z0-9])"
)


def _find_ibans(text: str) -> list[tuple[int, int]]:
    """IBANs: a registered country, its exact length, and mod-97 == 1."""
    spans: list[tuple[int, int]] = []
    for match in _IBAN_CANDIDATE.finditer(text):
        raw = match.group()
        length = _IBAN_LENGTHS.get(raw[:2])
        if length is None:
            continue
        # The end of the length-th character, which must close a group.
        end = [i for i, char in enumerate(raw) if char != " "][length - 1 : length]
        if not end or raw[end[0] + 1 : end[0] + 2] not in ("", " "):
            continue
        iban = raw[: end[0] + 1].replace(" ", "")
        if int("".join(str(int(char, 36)) for char in iban[4:] + iban[:4])) % 97 == 1:
            spans.append((match.start(), match.start() + end[0] + 1))
    return spans


_IPV4_CANDIDATE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w]|\.\w)")
_IPV6_CANDIDATE = re.compile(
    r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{0,4})(?![\w:]|\.\w)"
)


# A version right after its product (`Chrome/120.0.0.0`) or keyword (`build 3.2.1.9`).
# The product is a token after whitespace or `(`/`;`, so a URL's `//` and a path's
# `/srv/` are not one: an address there is an address.
_VERSION_BEFORE = re.compile(
    r"(?i)(?:[\s(;][A-Za-z][\w.+-]*/|\bv|\bver\.?|version|build|firmware|release)\s*$"
)


def _is_ip_address(candidate: str, before: str) -> bool:
    """Whether a candidate the patterns found is a personal IP address; ``before`` is
    the text just ahead of it, after a space that stands for the text's start.

    The standard parser has the last word, less loopback and unspecified
    addresses. An IPv4 address that is a network id (last octet 0) or follows
    a version's product or keyword is a version. An IPv6 address needs a digit
    and three groups or a hex letter: a slice (``a[1::2]``, ``b[100::200]``)
    parses as IPv6 but is at most ``start::step``, all decimal.
    """
    if not re.search(r"\d", candidate):
        return False
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    if address.is_loopback or address.is_unspecified:
        return False
    if address.version == 4:
        return not (candidate.endswith(".0") or _VERSION_BEFORE.search(before))
    groups = [group for group in re.split(r":+", candidate) if group]
    return len(groups) >= 3 or re.search(r"[A-Fa-f]", candidate) is not None


def _find_ip_addresses(text: str) -> list[tuple[int, int]]:
    """IPv4 and IPv6 addresses, by :func:`_is_ip_address`."""
    return _union(
        [
            match.span()
            for pattern in (_IPV4_CANDIDATE, _IPV6_CANDIDATE)
            for match in pattern.finditer(text)
            if _is_ip_address(match.group(), " " + text[max(0, match.start() - 32) : match.start()])
        ]
    )


_MONTH = (
    r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?"
    r"|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\.?"
)
_DAY = r"(?:0?[1-9]|[12]\d|3[01])"
_MON = r"(?:0?[1-9]|1[0-2])"
_DATE = (
    rf"(?:{_DAY}[/.-]{_MON}|{_MON}[/.-]{_DAY})[/.-](?:19|20)?\d{{2}}"
    rf"|(?:19|20)\d{{2}}[/.-]{_MON}[/.-]{_DAY}"
    rf"|{_DAY}(?:st|nd|rd|th)?\s+{_MONTH},?\s+(?:19|20)\d{{2}}"
    rf"|{_MONTH}\s+{_DAY}(?:st|nd|rd|th)?,?\s+(?:19|20)\d{{2}}"
)
_DATE_OF_BIRTH = re.compile(
    r"(?i)\b(?:d\.?o\.?b\.?|date\s+of\s+birth|birth\s*date|birthday|born(?:\s+on)?)"
    rf"[\s:=,-]*(?:(?:is|was)\s+)?(?P<s>{_DATE})(?![\d/.-]?\d)"
)

_UK_NINO = re.compile(
    r"(?<![A-Za-z0-9])(?P<s>(?!BG|GB|KN|NK|NT|TN|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]"
    r" ?\d{2} ?\d{2} ?\d{2} ?[A-D])(?![A-Za-z0-9])"
)

# Always beside its name, grouped 3-3-3 or bare: a grouped 9-digit number is
# also French thousands or an order id, and passes Luhn one time in ten.
# SINs never start 0 or 8. NAS is the French name.
_CA_SIN = re.compile(
    r"(?:\bSIN|\bNAS|(?i:\bsocial\s+insurance|\bnum[ée]ro\s+d['’]assurance\s+sociale))"
    r"(?:\s+(?i:number|no\.?|#))?\s*[:#]?\s*"
    r"(?P<s>[1-79]\d{2}(?P<sep>[ -]?)\d{3}(?P=sep)\d{3})(?![\d-])"
)

_VERHOEFF_D = [
    "0123456789",
    "1234067895",
    "2340178956",
    "3401289567",
    "4012395678",
    "5987604321",
    "6598710432",
    "7659821043",
    "8765932104",
    "9876543210",
]
_VERHOEFF_P = [
    "0123456789",
    "1576283094",
    "5803796142",
    "8916043527",
    "9453126870",
    "4286573901",
    "2793806415",
    "7046913258",
]


def _verhoeff_ok(digits: str) -> bool:
    """Verhoeff's dihedral check over a digit string, as Aadhaar numbers carry."""
    check = 0
    for position, char in enumerate(reversed(digits)):
        check = int(_VERHOEFF_D[check][int(_VERHOEFF_P[position % 8][int(char)])])
    return check == 0


# Grouped 4-4-4 with one separator, or bare beside its name; never starts 0 or 1.
_IN_AADHAAR = re.compile(
    r"(?<![\d-])(?P<s>[2-9]\d{3}(?P<sep>[ -])\d{4}(?P=sep)\d{4})(?![\d-])"
    r"|(?i:\baadhaa?r)(?:\s+(?:no\.?|number))?\s*[:#]?\s*(?P<bare>[2-9]\d{11})(?!\d)"
)


def _checked_finder(
    pattern: re.Pattern[str], valid: Callable[[str], bool]
) -> Callable[[str], list[tuple[int, int]]]:
    """Spans of group ``s`` (grouped) or ``bare`` (named) whose digits pass ``valid``."""

    def _find(text: str) -> list[tuple[int, int]]:
        spans: list[tuple[int, int]] = []
        for m in pattern.finditer(text):
            group = "s" if m["s"] is not None else "bare"
            if valid(re.sub(r"\D", "", m[group])):
                spans.append(m.span(group))
        return spans

    return _find


# The fourth letter is the holder type (P person, C company, H HUF, F firm, ...).
_IN_PAN = re.compile(r"(?<![A-Za-z0-9])[A-Z]{3}[ABCFGHJLPT][A-Z]\d{4}[A-Z](?![A-Za-z0-9])")

# Each member state's format after its prefix (EL is Greece); format only.
_EU_VAT_FORMATS = {
    "AT": r"U\d{8}",
    "BE": r"[01]\d{9}",
    "BG": r"\d{9,10}",
    "CY": r"\d{8}[A-Z]",
    "CZ": r"\d{8,10}",
    "DE": r"\d{9}",
    "DK": r"\d{8}",
    "EE": r"\d{9}",
    "EL": r"\d{9}",
    "ES": r"[A-Z0-9]\d{7}[A-Z0-9]",
    "FI": r"\d{8}",
    "FR": r"[A-HJ-NP-Z0-9]{2}\d{9}",
    "HR": r"\d{11}",
    "HU": r"\d{8}",
    "IE": r"\d{7}[A-W][A-I]?|\d[A-Z+*]\d{5}[A-W]",
    "IT": r"\d{11}",
    "LT": r"\d{9}|\d{12}",
    "LU": r"\d{8}",
    "LV": r"\d{11}",
    "MT": r"\d{8}",
    "NL": r"\d{9}B\d{2}",
    "PL": r"\d{10}",
    "PT": r"\d{9}",
    # Romania's CUI runs 2-10 digits; under 6 it is too short to tell from a code.
    "RO": r"[1-9]\d{5,9}",
    "SE": r"\d{10}01",
    "SI": r"\d{8}",
    "SK": r"\d{10}",
}
_EU_VAT = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    + "|".join(f"{state} ?(?:{fmt})" for state, fmt in _EU_VAT_FORMATS.items())
    + r")(?![A-Za-z0-9])"
)


PII_DETECTORS: tuple[PiiDetector, ...] = (
    PiiDetector(
        code="PII_EMAIL",
        label="Email address",
        # The lookbehind starts a match only at the head of a local part. Without
        # it every position of a long run with no `@` (a base64 image) was a
        # start that scanned to the run's end: quadratic, 18 s on 100 KB.
        find=_regex_finder(re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+")),
    ),
    PiiDetector(code="PII_PHONE", label="Phone number", find=_find_phones, loose=True),
    PiiDetector(code="PII_PAYMENT_CARD", label="Payment card number", find=_find_payment_cards),
    PiiDetector(
        code="PII_NATIONAL_ID",
        label="National identifier (US SSN)",
        # The area/group/serial rules are part of the pattern: 000/666/9xx
        # areas and 00 groups / 0000 serials are never issued, and excluding
        # them is what keeps ordinary 9-digit ids out of the results.
        find=_regex_finder(
            re.compile(r"(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])")
        ),
    ),
    PiiDetector(
        code="PII_SECRET",
        label="Secret or credential",
        find=find_secrets,
        placeholder=SECRET_PLACEHOLDER,
        member=is_credential_member,
    ),
    PiiDetector(code="PII_IBAN", label="IBAN (bank account)", find=_find_ibans),
    PiiDetector(code="PII_IP_ADDRESS", label="IP address", find=_find_ip_addresses),
    PiiDetector(
        code="PII_DATE_OF_BIRTH",
        label="Date of birth",
        find=_regex_finder(_DATE_OF_BIRTH),
    ),
    PiiDetector(
        code="PII_UK_NINO",
        label="UK National Insurance number",
        find=_regex_finder(_UK_NINO),
    ),
    PiiDetector(
        code="PII_CA_SIN",
        label="Canadian Social Insurance Number",
        find=_regex_finder(_CA_SIN, _luhn_ok),
    ),
    PiiDetector(
        code="PII_IN_AADHAAR",
        label="Indian Aadhaar number",
        find=_checked_finder(_IN_AADHAAR, _verhoeff_ok),
    ),
    PiiDetector(code="PII_IN_PAN", label="Indian PAN", find=_regex_finder(_IN_PAN)),
    PiiDetector(code="PII_EU_VAT", label="EU VAT number", find=_regex_finder(_EU_VAT)),
)

PII_CODES: tuple[str, ...] = tuple(detector.code for detector in PII_DETECTORS)


__all__ = ["PII_CODES", "PII_DETECTORS", "REDACTION_TEMPLATE", "PiiDetector"]
