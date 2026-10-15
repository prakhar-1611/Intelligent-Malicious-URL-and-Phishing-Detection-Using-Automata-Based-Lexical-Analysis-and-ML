"""Seeded, reproducible URL mutation operators for adversarial evaluation.

Author: Prakhar Tandon (24BCI0222)

Each operator applies one evasion technique an attacker might use while keeping
the URL functional, and names the lexer flag that *should* catch it (None when
the technique has no lexical signature and only the ML layer can respond).

No mutated URL is ever resolved or fetched. The IP-form operator uses the
TEST-NET-1 documentation range 192.0.2.0/24 (RFC 5737), never a real resolution.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable

from lexer.scanner import scan
from security.idn import CONFUSABLES, encode_label
from security.ip_decode import to_decimal_form

# Latin letter -> Cyrillic/Greek look-alike (inverse of the confusables table)
LOOKALIKE: dict[str, str] = {}
for _k, _v in CONFUSABLES.items():
    if _v.isalpha() and not _k.isascii() and _v not in LOOKALIKE and _k.islower():
        LOOKALIKE[_v] = _k


@dataclass
class Parts:
    url: str
    host_start: int
    host_end: int
    path_start: int  # index where path/query/fragment begin (len(url) if none)
    base: tuple[int, int] | None  # span of BASE_DOMAIN


def parts(url: str) -> Parts | None:
    r = scan(url)
    host_toks = [t for t in r.tokens if t.type in ("SUBDOMAIN", "BASE_DOMAIN", "TLD", "IP_HOST")]
    if not host_toks:
        return None
    hs, he = host_toks[0].start, host_toks[-1].end
    rest = [t.start for t in r.tokens if t.type in ("PATH", "QUERY_PARAM", "FRAGMENT")]
    ps = min(rest) if rest else len(url)
    base = next(((t.start, t.end) for t in r.tokens if t.type == "BASE_DOMAIN"), None)
    return Parts(url, hs, he, ps, base)


def _path_char_positions(p: Parts) -> list[int]:
    return [i for i in range(p.path_start, len(p.url)) if p.url[i].isalnum()]


def op_percent_encode(url: str, rng: random.Random) -> str | None:
    p = parts(url)
    if not p:
        return None
    pos = _path_char_positions(p)
    if not pos:
        url = url + "/index"
        p = parts(url)
        pos = _path_char_positions(p)
    chosen = set(rng.sample(pos, k=min(3, len(pos))))
    return "".join("%%%02X" % ord(c) if i in chosen else c for i, c in enumerate(url))


def op_double_encode(url: str, rng: random.Random) -> str | None:
    p = parts(url)
    if not p:
        return None
    pos = _path_char_positions(p)
    if not pos:
        url = url + "/index"
        p = parts(url)
        pos = _path_char_positions(p)
    i = rng.choice(pos)
    return url[:i] + "%%25%02X" % ord(url[i]) + url[i + 1:]


def op_homoglyph(url: str, rng: random.Random) -> str | None:
    p = parts(url)
    if not p or not p.base:
        return None
    s, e = p.base
    cands = [i for i in range(s, e) if url[i].lower() in LOOKALIKE]
    if not cands:
        return None
    i = rng.choice(cands)
    return url[:i] + LOOKALIKE[url[i].lower()] + url[i + 1:]


def op_punycode(url: str, rng: random.Random) -> str | None:
    p = parts(url)
    if not p or not p.base:
        return None
    s, e = p.base
    label = url[s:e]
    cands = [i for i, c in enumerate(label) if c.lower() in LOOKALIKE]
    if not cands:
        return None
    i = rng.choice(cands)
    swapped = label[:i] + LOOKALIKE[label[i].lower()] + label[i + 1:]
    return url[:s] + encode_label(swapped) + url[e:]


def op_subdomain_insert(url: str, rng: random.Random) -> str | None:
    p = parts(url)
    if not p:
        return None
    lure = rng.choice(["paypal.com", "login.microsoft.com", "secure.apple.com", "accounts.google.com"])
    extra = rng.choice(["verify", "secure-login", "account-update", "auth"])
    return url[:p.host_start] + f"{lure}.{extra}." + url[p.host_start:]


def op_at_injection(url: str, rng: random.Random) -> str | None:
    p = parts(url)
    if not p:
        return None
    lure = rng.choice(["www.paypal.com", "accounts.google.com", "login.microsoftonline.com"])
    return url[:p.host_start] + lure + "@" + url[p.host_start:]


def op_ip_form(url: str, rng: random.Random) -> str | None:
    p = parts(url)
    if not p:
        return None
    ip = f"192.0.2.{rng.randint(1, 254)}"  # RFC 5737 TEST-NET-1: never a real host
    return url[:p.host_start] + to_decimal_form(ip) + url[p.host_end:]


def op_port_insert(url: str, rng: random.Random) -> str | None:
    p = parts(url)
    if not p or url[p.host_end:p.host_end + 1] == ":":
        return None
    return url[:p.host_end] + ":" + str(rng.choice([8080, 8443, 2083, 8888])) + url[p.host_end:]


def op_case_toggle(url: str, rng: random.Random) -> str | None:
    p = parts(url)
    if not p:
        return None
    return "".join(c.upper() if p.host_start <= i < p.host_end and rng.random() < 0.5 else c
                   for i, c in enumerate(url))


def op_dslash(url: str, rng: random.Random) -> str | None:
    p = parts(url)
    if not p:
        return None
    if p.path_start < len(url) and url[p.path_start] == "/":
        return url[:p.path_start] + "//" + url[p.path_start + 1:]
    return url[:p.path_start] + "//redirect" + url[p.path_start:]


@dataclass(frozen=True)
class Operator:
    name: str
    fn: Callable[[str, random.Random], str | None]
    expected_flag: str | None
    description: str


OPERATORS: list[Operator] = [
    Operator("percent_encoding", op_percent_encode, "S_PCT_ENCODE", "encode 3 path characters as %XX"),
    Operator("double_encoding", op_double_encode, "S_DOUBLE_ENCODE", "encode one path character as %25XX"),
    Operator("homoglyph_swap", op_homoglyph, "S_MIXED_SCRIPT", "swap one domain letter for a Cyrillic/Greek look-alike"),
    Operator("punycode", op_punycode, "S_PUNY_DETECT", "homoglyph swap, then encode the label as xn--"),
    Operator("subdomain_insertion", op_subdomain_insert, "S_SUBDOMAIN_DEPTH", "prepend a brand-like subdomain chain"),
    Operator("at_injection", op_at_injection, "S_AT_ABUSE", "prepend brand@ as fake userinfo"),
    Operator("ip_form", op_ip_form, "S_IP_OBFUSCATED", "replace host by a decimal-form IPv4 (TEST-NET)"),
    Operator("port_insertion", op_port_insert, "S_PORT_ANOMALY", "add a non-standard port"),
    Operator("case_toggle", op_case_toggle, None, "randomise host letter case (no lexical signature)"),
    Operator("dslash_injection", op_dslash, "S_REDIRECT_ABUSE", "insert // after the authority"),
]
OPERATORS_BY_NAME = {o.name: o for o in OPERATORS}


def mutate(url: str, op: Operator, seed: int) -> str | None:
    rng = random.Random(f"{seed}:{op.name}:{url}")
    try:
        return op.fn(url, rng)
    except Exception:
        return None
