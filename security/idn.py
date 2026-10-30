"""IDN helpers: punycode decoding, per-label script detection, confusables skeleton.

Author: Prakhar Tandon (24BCI0222)

* ``decode_label``   xn--pypal-4ve -> "pаypal" (Python's built-in RFC 3492 codec)
* ``scripts_of``     set of Unicode scripts used by a label. Python has no script
                     property, so the script is read from the character's Unicode
                     name ("CYRILLIC SMALL LETTER A" -> CYRILLIC). Digits, '-' and
                     '_' count as COMMON.
* ``is_mixed_script`` follows the spirit of Unicode TS #39 "highly restrictive":
                     one script per label, except the legitimate CJK combinations.
* ``skeleton``       TS #39 skeleton(X) = NFD(map_confusables(NFD(X))), using a
                     curated subset of confusables.txt (the Latin look-alikes that
                     matter for domain spoofing) plus NFKC for full-width forms.
"""
from __future__ import annotations

import unicodedata
from functools import lru_cache
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "lexer" / "data"

# Curated subset of Unicode confusables.txt (target is the Latin prototype).
CONFUSABLES: dict[str, str] = {
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ё": "e", "һ": "h", "і": "i", "ї": "i", "ј": "j",
    "к": "k", "ӏ": "l", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c", "ԛ": "q",
    "ѕ": "s", "т": "t", "у": "y", "ԝ": "w", "х": "x", "ԁ": "d", "ɡ": "g", "ү": "y",
    "А": "a", "В": "b", "Е": "e", "К": "k", "М": "m", "Н": "h", "О": "o", "Р": "p",
    "С": "c", "Т": "t", "Х": "x",
    # Greek
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p",
    "τ": "t", "υ": "u", "χ": "x", "ω": "w", "Α": "a", "Β": "b", "Ε": "e", "Ι": "i",
    "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o", "Ρ": "p", "Τ": "t", "Χ": "x", "Ζ": "z",
    # Latin variants / IPA
    "ı": "i", "ȷ": "j", "ɩ": "i", "ɑ": "a", "ɔ": "c", "ʋ": "u", "ν": "v",
    # ASCII digit look-alikes (also in confusables.txt)
    "0": "o", "1": "l", "|": "l",
}
# multi-character confusables (TS #39 maps these sequences too)
SEQUENCES = {"rn": "m", "vv": "w", "cl": "d"}


def decode_label(label: str) -> str:
    """Decode an xn-- label; return it unchanged if it is not valid punycode."""
    if label[:4].lower() != "xn--":
        return label
    try:
        return label[4:].encode("ascii").decode("punycode")
    except (UnicodeError, ValueError):
        return label


def encode_label(label: str) -> str:
    if all(ord(c) < 128 for c in label):
        return label
    return "xn--" + label.encode("punycode").decode("ascii")


def script_of(ch: str) -> str:
    if ch.isascii():
        return "LATIN" if ch.isalpha() else "COMMON"
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "UNKNOWN"
    first = name.split(" ")[0]
    if first in ("CJK",):
        return "HAN"
    if first in ("FULLWIDTH", "HALFWIDTH"):
        return "COMMON" if not ch.isalpha() else "LATIN"
    if not ch.isalpha():
        return "COMMON"
    return first


def scripts_of(label: str) -> set[str]:
    return {s for s in (script_of(c) for c in label) if s != "COMMON"}


_ALLOWED_MIXES = [
    {"HAN", "HIRAGANA", "KATAKANA", "LATIN"},  # Japanese
    {"HAN", "HANGUL", "LATIN"},  # Korean
    {"HAN", "BOPOMOFO", "LATIN"},  # Chinese
]


def is_mixed_script(label: str) -> bool:
    s = scripts_of(label)
    if len(s) <= 1:
        return False
    return not any(s <= allowed for allowed in _ALLOWED_MIXES)


def skeleton(text: str) -> str:
    s = unicodedata.normalize("NFKC", text)
    s = unicodedata.normalize("NFD", s)
    s = "".join(CONFUSABLES.get(c, c) for c in s)
    s = "".join(c for c in s if unicodedata.category(c) != "Mn")  # drop combining marks
    s = s.lower()
    for seq, rep in SEQUENCES.items():
        s = s.replace(seq, rep)
    return s


@lru_cache(maxsize=1)
def brands() -> tuple[str, ...]:
    path = DATA / "brands.txt"
    words = [w.strip().lower() for w in path.read_text(encoding="utf-8").splitlines()]
    return tuple(w for w in words if w and not w.startswith("#"))


@lru_cache(maxsize=1)
def _brand_skeletons() -> dict[str, str]:
    return {skeleton(b): b for b in brands()}


def homoglyph_target(label: str) -> str | None:
    """Brand that ``label`` imitates (same skeleton, different text), if any."""
    decoded = decode_label(label).lower()
    if decoded in brands():
        return None
    return _brand_skeletons().get(skeleton(decoded))


def edit_distance(a: str, b: str, cap: int) -> int:
    """Damerau (optimal string alignment) distance; returns cap + 1 once it exceeds ``cap``."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] != b[j - 1]))
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)  # swapped neighbours count as one edit
        if min(cur) > cap:
            return cap + 1
        prev2, prev = prev, cur
    return prev[-1]


def typosquat_target(label: str) -> tuple[str, int] | None:
    """(brand, distance) when ``label`` is 1-2 edits away from a brand.

    shortcut: brands under 6 letters are skipped (gmail/email, adobe/abode, chase/chose are real
    words); widen once a list of legitimate near-brand domains exists to suppress them."""
    decoded = decode_label(label).lower()
    if decoded in brands():
        return None
    best: tuple[str, int] | None = None
    for brand in brands():
        if len(brand) < 6:
            continue
        cap = 2 if len(brand) >= 8 else 1
        d = edit_distance(decoded, brand, cap)
        if 0 < d <= cap and (best is None or d < best[1]):
            best = (brand, d)
    return best
