"""Inputs for the reference corpus that the suite's tables do not already hold.

Not a test module: Unicode edges a port gets wrong when it counts bytes or UTF-16 units
or folds case differently from Python, one valid IBAN and one valid VAT number for every
country the reference knows (and wrong-length variants), Luhn-valid digit runs of every
length, and the long, crowded and unterminated texts. Every expected value is computed
later by the reference; nothing here is an answer, only an input.
"""

from __future__ import annotations

import random
import string

from dagnam_contracts.hygiene.detectors import _EU_VAT_FORMATS, _IBAN_LENGTHS, _luhn_ok

# Texts that cannot be written to a UTF-8 file: the exporter drops them and counts them.
LONE_SURROGATES = ["lone \ud800 jane@example.com", "\udfffpassword: hunter22"]

_SEPARATORS = ["\u0085", "\u2028", "\u2029", "\u00a0", "\u3000", "\u200b", "\ufeff", "\x1c", "\x0b"]

_UNICODE_BASE: list[str] = [
    # Digits and letters that Python's \d, \w and \s match outside ASCII.
    "card ４１１１１１１１１１１１１１１１",
    "call (٤١٥) ٥٥٥-٠١٣٢",
    "ssn ١٢٣-٤٥-٦٧٨٩",
    "ip ١٩٢.١٦٨.١.٥",
    "call ४१५ ५५५ ०१३२ now",
    "call ๔๑๕-๕๕๕-๐๑๓๒",
    "call 415\x1c555 0132",
    "host ²192.168.1.5 up",
    "host x192.168.1.5 up",
    "jane＠example.com",
    "ＩＢＡＮ DE89 3704 0044 0532 0130 00",
    # Combining marks and joiners next to, and inside, matches.
    "áb@x.co",
    "x\u0301@x.co",
    "a\u0301b@x.co",
    "e\u0301 jane@example.com",
    "a\u0301\u0301 078-05-1120",
    "x\u200d4111111111111111",
    "\u200b415-555-0132",
    "ZWJ\u200djane@x.co",
    "👨\u200d👩\u200d👧 call +1 415 555 0100",
    "🇬🇧 GB29NWBK60161331926819 🇬🇧",
    # Case folding: dotless and dotted i, long s, Kelvin sign.
    "apı_key=abc123def",
    "bırthday 12/05/1990",
    "ſecret=abcdef1234",
    "paſſword: hunter22",
    "api_\u212aey=abc123def456",
    "\u212aey: abcdef12345",
    "İ DOB: 14/03/1987",
    "DOB: 14/03/1987 İ",
    "İNFO password: hunter22",
    "ıban DE89 3704 0044 0532 0130 00",
    "Straße ΣΑΣ ﬁnal İstanbul",
    # Astral characters: one code point, two UTF-16 units, four bytes.
    "mail 𝐀@b.co",
    "😀 call +1 415 555 0100",
    "😀😀😀 jane@example.com 😀",
    "𝒳 y z 4111 1111 1111 1111",
    "tab\tand\u00a0nbsp and\u2003em space",
    # Empty and tiny.
    "",
    "  ",
    "one",
    "@",
    "+1",
    *LONE_SURROGATES,
]
UNICODE_TEXTS: list[str] = [
    *_UNICODE_BASE,
    *(
        text
        for sep in _SEPARATORS
        for text in (
            f"call{sep}+1 415 555 0100{sep}now",
            f"{sep}jane@example.com{sep}",
            f"ssn{sep}078-05-1120",
            f"card{sep}4111 1111 1111 1111{sep}ok",
            f"password:{sep}hunter22",
            f"ip{sep}192.168.1.20{sep}",
        )
    ),
]

# Overlapping, adjacent, crowded and repeated-near-miss inputs.
STRUCTURAL_TEXTS: list[str] = [
    "jane@example.com+1 415 555 0100",
    "415-555-0132-4111111111111111",
    "4111111111111111 4111111111111111 4111111111111111",
    "a@b.co " * 200,
    "+1 415 555 0100, " * 120,
    "4111 1111 1111 1112 " * 60,
    "DE89 3704 0044 0532 0130 01 " * 25,
    "SIN 130 692 543 " * 30,
    "192.168.1 " * 40,
    "(415) 555-0132",
    "(+1) 415 555 0132",
    "((415)) 555-0132",
    "[(415) 555-0132]",
    "(415)555-0132",
    "( 415 ) 555 0132",
    "+1 (415) 555-0132 (415) 555-0133",
    "tel:(415)555-0132;(415)555-0133",
    "((((415)))) 555 0132 (((",
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEow" + "A" * 300,
    "before -----BEGIN PRIVATE KEY-----\nMIIEow\nmore text, jane@example.com",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY----- x -----END PRIVATE KEY----- y -----BEGIN PRIVATE KEY-----",
]


def _prose(words: int, seed: int) -> str:
    generator = random.Random(seed)
    vocabulary = ["the", "model", "learns", "from", "data", "and", "rows", "of", "text", "while"]
    return " ".join(generator.choice(vocabulary) for _ in range(words))


def long_texts(findings: list[str]) -> list[str]:
    """Several texts over 1000 characters; the last is the largest, and crowded."""
    pem = "-----BEGIN PRIVATE KEY-----\n" + "MIIEowIBAAKCAQEA" * 200 + "\n-----END PRIVATE KEY-----"
    crowded = " ".join(f"{_prose(4, i)} {findings[i % len(findings)]}" for i in range(2500))
    return [
        _prose(250, 1) + " jane@example.com",
        "jane@example.com " + _prose(400, 2),
        " ".join(f"{_prose(30, i)} {findings[i % len(findings)]}" for i in range(40)),
        pem + " call +1 415 555 0100",
        "password: " + "x" * 3000,
        "x" * 2000 + "4111111111111111" + "y" * 2000,
        crowded,
    ]


def card_texts() -> list[str]:
    """Luhn-valid runs of 12 to 20 digits, plain, space-separated and dash-separated."""
    generator = random.Random(412)
    texts: list[str] = []
    for length in range(12, 21):
        for _ in range(2):
            body = "4" + "".join(generator.choice(string.digits) for _ in range(length - 2))
            digits = next(body + d for d in string.digits if _luhn_ok(body + d))
            groups = [digits[i : i + 4] for i in range(0, length, 4)]
            texts += [
                f"card {digits} ok",
                f"card {' '.join(groups)} ok",
                f"card {'-'.join(groups)}",
            ]
    return texts


def _iban(country: str, length: int, generator: random.Random) -> str:
    """A mod-97 valid IBAN of ``length`` characters (the registry checks nothing else)."""
    bban = "".join(
        generator.choice(string.digits + string.ascii_uppercase) for _ in range(length - 4)
    )
    check = 98 - int("".join(str(int(c, 36)) for c in bban + country + "00")) % 97
    return f"{country}{check:02d}{bban}"


def iban_texts() -> list[str]:
    """For every registry country: a valid IBAN compact and spaced, and two wrong lengths."""
    generator = random.Random(97)
    texts: list[str] = []
    for country, length in sorted(_IBAN_LENGTHS.items()):
        iban = _iban(country, length, generator)
        spaced = " ".join(iban[i : i + 4] for i in range(0, length, 4))
        texts += [f"iban {iban}.", f"pay {spaced} now"]
        for wrong in (length - 1, length + 1):
            texts.append(f"iban {_iban(country, wrong, generator)}.")
    return texts


# One format-valid number per member state (several where a format has shapes).
VAT_SAMPLES: dict[str, list[str]] = {
    "AT": ["ATU12345678"],
    "BE": ["BE0123456789", "BE1123456789"],
    "BG": ["BG123456789", "BG1234567890"],
    "CY": ["CY12345678X"],
    "CZ": ["CZ12345678", "CZ123456789", "CZ1234567890"],
    "DE": ["DE123456789"],
    "DK": ["DK12345678"],
    "EE": ["EE123456789"],
    "EL": ["EL123456789"],
    "ES": ["ESA1234567B", "ES12345678Z"],
    "FI": ["FI12345678"],
    "FR": ["FR12345678901", "FRAB123456789"],
    "HR": ["HR12345678901"],
    "HU": ["HU12345678"],
    "IE": ["IE1234567T", "IE1234567TA", "IE1A12345B"],
    "IT": ["IT12345678901"],
    "LT": ["LT123456789", "LT123456789012"],
    "LU": ["LU12345678"],
    "LV": ["LV12345678901"],
    "MT": ["MT12345678"],
    "NL": ["NL123456789B01"],
    "PL": ["PL1234567890"],
    "PT": ["PT123456789"],
    "RO": ["RO123456", "RO1234567890"],
    "SE": ["SE123456789001"],
    "SI": ["SI12345678"],
    "SK": ["SK1234567890"],
}
assert set(VAT_SAMPLES) == set(_EU_VAT_FORMATS)


def vat_texts() -> list[str]:
    """Each sample as is, spaced after its prefix, a digit short, and in lower case.

    The reference checks the format of a VAT number and no checksum, so there is no
    bad-checksum variant to write.
    """
    texts: list[str] = []
    for samples in VAT_SAMPLES.values():
        for sample in samples:
            texts += [
                f"vat {sample} end",
                f"VAT: {sample[:2]} {sample[2:]}",
                f"vat {sample[:-1]} end",
                f"vat {sample.lower()} end",
            ]
    return texts


def encodable(text: str) -> bool:
    """Whether ``text`` can be written to a UTF-8 file (a lone surrogate cannot)."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True
