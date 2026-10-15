"""Normalise every textual IPv4 form to dotted decimal.

Author: Prakhar Tandon (24BCI0222)

Browsers and ``inet_aton`` accept far more than "a.b.c.d":

    3232235777            single 32-bit decimal   -> 192.168.1.1
    0xC0A80101            single 32-bit hex       -> 192.168.1.1
    0300.0250.01.01       octal octets            -> 192.168.1.1
    0xC0.0xA8.0x01.0x01   hex octets              -> 192.168.1.1
    192.168.257           a.b.c  (c is 16 bits)   -> 192.168.1.1
    192.11010305          a.b    (b is 24 bits)   -> 192.168.1.1

Anything other than plain dotted decimal with 4 parts is an *obfuscated* IP host
(flag S_IP_OBFUSCATED). Pure string handling, no ``re``.
"""
from __future__ import annotations

from dataclasses import dataclass

_HEX = set("0123456789abcdefABCDEF")
_DEC = set("0123456789")


@dataclass
class IPv4:
    value: int
    dotted: str
    form: str  # "dotted-decimal", "decimal", "hex", "octal", "mixed", "short"

    @property
    def obfuscated(self) -> bool:
        return self.form != "dotted-decimal"


def _parse_part(part: str) -> tuple[int, str] | None:
    if not part:
        return None
    if part[:2] in ("0x", "0X"):
        digits = part[2:]
        if digits == "":
            return 0, "hex"
        if all(c in _HEX for c in digits):
            return int(digits, 16), "hex"
        return None
    if len(part) > 1 and part[0] == "0":
        if all(c in "01234567" for c in part):
            return int(part, 8), "octal"
        return None
    if all(c in _DEC for c in part):
        return int(part), "decimal"
    return None


def parse_ipv4(host: str) -> IPv4 | None:
    """Return the IPv4 address a host string denotes, or None if it is not an IP."""
    if not host or len(host) > 64:
        return None
    if host.endswith("."):
        host = host[:-1]
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    parsed = [_parse_part(p) for p in parts]
    if any(p is None for p in parsed):
        return None
    nums = [p[0] for p in parsed]
    kinds = {p[1] for p in parsed}
    # every part but the last is one byte; the last fills the remaining bytes
    for n in nums[:-1]:
        if n > 255:
            return None
    last_bits = 8 * (5 - len(nums))
    if nums[-1] >= 1 << last_bits:
        return None
    value = 0
    for n in nums[:-1]:
        value = value << 8 | n
    value = value << last_bits | nums[-1]
    dotted = ".".join(str(value >> s & 255) for s in (24, 16, 8, 0))

    if len(parts) == 4 and kinds == {"decimal"}:
        form = "dotted-decimal"
    elif len(parts) == 1:
        form = next(iter(kinds))
    elif len(kinds) > 1:
        form = "mixed"
    elif len(parts) < 4:
        form = "short"
    else:
        form = next(iter(kinds))
    return IPv4(value, dotted, form)


def to_decimal_form(dotted: str) -> str:
    ip = parse_ipv4(dotted)
    return str(ip.value) if ip else dotted


def to_hex_form(dotted: str) -> str:
    ip = parse_ipv4(dotted)
    return "0x%08X" % ip.value if ip else dotted


def to_octal_form(dotted: str) -> str:
    ip = parse_ipv4(dotted)
    if not ip:
        return dotted
    return ".".join("0%o" % int(o) for o in ip.dotted.split("."))
