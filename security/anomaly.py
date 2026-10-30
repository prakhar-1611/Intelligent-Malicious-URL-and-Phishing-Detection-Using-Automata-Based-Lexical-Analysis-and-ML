"""Security-aware anomaly detection: the 9 Review 1 flags plus 4 new ones.

Author: Prakhar Tandon (24BCI0222)

Two sources of evidence, kept explicitly separate (Flag.source):

1. DFA anomaly states ("dfa") - raised the moment the scanner accepts in an
   accept state whose rule carries a flag (lexer/rules.py):
       S_PUNY_DETECT  S_PCT_ENCODE  S_IP_HOST  S_AT_ABUSE
       S_REDIRECT_ABUSE  S_CONTROL_ANOMALY  S_DOUBLE_ENCODE (new)

2. Attribute checks ("attr") - run on token attributes after lexing, because
   they need things a regular language cannot express:
       S_PORT_ANOMALY        allowlist lookup on the PORT value
       S_SUBDOMAIN_DEPTH     counting labels against a threshold
       S_MIXED_SCRIPT        Unicode script property of each character
       S_IP_OBFUSCATED (new) integer arithmetic on decimal/hex/octal hosts
       S_OPEN_REDIRECT_PARAM (new) key allowlist + decoded value inspection
       S_HOMOGLYPH (new)     TS #39 skeleton compared with a brand list
       S_TYPOSQUAT (Review 3) registered-domain label 1-2 edits from a brand

Flags are *evidence, not verdicts*: the classifier weighs them, and the policy
layer makes the decision.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from core.types import Flag, Lexeme
from lexer.rules import SEVERITY, flag_of
from security import idn
from security.ip_decode import IPv4, parse_ipv4

PORT_ALLOWLIST = {80, 443}
SUBDOMAIN_DEPTH_THRESHOLD = 3
REDIRECT_KEYS = {
    "url", "uri", "next", "redirect", "redirect_uri", "redirect_url", "redirecturl", "redir",
    "return", "returnurl", "return_url", "return_to", "returnto", "continue", "dest",
    "destination", "goto", "target", "r", "u", "link", "out", "to", "rurl", "forward", "callback",
}


def pct_decode(s: str) -> str:
    """Percent-decode (UTF-8), leaving malformed escapes untouched. No ``re``."""
    out = bytearray()
    i = 0
    hexd = "0123456789abcdefABCDEF"
    while i < len(s):
        c = s[i]
        pair = s[i + 1:i + 3]
        if c == "%" and len(pair) == 2 and all(h in hexd for h in pair):
            out.append(int(s[i + 1:i + 3], 16))
            i += 3
        else:
            out.extend(c.encode("utf-8"))
            i += 1
    return out.decode("utf-8", errors="replace")


def flag(code: str, start: int, end: int, evidence: str, source: str) -> Flag:
    return Flag(code=code, start=start, end=end, evidence=evidence,
                severity=SEVERITY.get(code, 1), source=source)


def dfa_flag(lx: Lexeme) -> Flag | None:
    """Hook called by the scanner for every lexeme it emits."""
    code = flag_of(lx.type)
    if code is None:
        return None
    return flag(code, lx.start, lx.end, lx.value, "dfa")


@dataclass
class HostContext:
    """What the attribute checks need, assembled by the scanner."""

    scheme: str = ""
    host: str = ""
    host_start: int = 0
    labels: list[tuple[str, int, int]] = field(default_factory=list)  # (text, start, end)
    n_subdomains: int = 0
    port: tuple[str, int, int] | None = None
    params: list[tuple[str, str, int, int]] = field(default_factory=list)  # key, value, start, end
    ip: IPv4 | None = None
    ip_lexed_by_dfa: bool = False


def attribute_flags(ctx: HostContext) -> list[Flag]:
    out: list[Flag] = []

    if ctx.ip is not None and not ctx.ip_lexed_by_dfa:
        # e.g. 3232235777 or 0xC0.0xA8.1.1: the DFA saw labels, arithmetic proves it is an IP
        out.append(flag("S_IP_HOST", ctx.host_start, ctx.host_start + len(ctx.host), ctx.host, "attr"))

    if ctx.port is not None:
        value, s, e = ctx.port
        if value.isdigit() and int(value) not in PORT_ALLOWLIST:
            out.append(flag("S_PORT_ANOMALY", s, e, ":" + value, "attr"))

    if ctx.n_subdomains >= SUBDOMAIN_DEPTH_THRESHOLD:
        out.append(flag("S_SUBDOMAIN_DEPTH", ctx.host_start, ctx.host_start + len(ctx.host),
                        f"{ctx.n_subdomains} subdomain labels", "attr"))

    if ctx.ip is not None and ctx.ip.obfuscated:
        out.append(flag("S_IP_OBFUSCATED", ctx.host_start, ctx.host_start + len(ctx.host),
                        f"{ctx.host} = {ctx.ip.dotted} ({ctx.ip.form})", "attr"))

    if ctx.ip is None:
        for text, s, e in ctx.labels:
            decoded = idn.decode_label(text)
            if idn.is_mixed_script(decoded):
                scripts = "+".join(sorted(idn.scripts_of(decoded)))
                out.append(flag("S_MIXED_SCRIPT", s, e, f"{decoded} ({scripts})", "attr"))
        # homoglyph: every non-suffix label
        homoglyph = False
        for text, s, e in ctx.labels:
            target = idn.homoglyph_target(text)
            if target:
                homoglyph = True
                out.append(flag("S_HOMOGLYPH", s, e, f"{idn.decode_label(text)} imitates {target}", "attr"))
        # typosquat: registered-domain label only; a homoglyph already explains a look-alike
        if ctx.labels and not homoglyph:
            text, s, e = ctx.labels[-1]
            hit = idn.typosquat_target(text)
            if hit:
                out.append(flag("S_TYPOSQUAT", s, e, f"{text} is {hit[1]} edit(s) from {hit[0]}", "attr"))

    for key, value, s, e in ctx.params:
        k = pct_decode(key).lower()
        if k not in REDIRECT_KEYS:
            continue
        v = pct_decode(pct_decode(value)).strip().lower()
        if v.startswith(("http://", "https://", "//", "\\\\")) or "://" in v[:20]:
            out.append(flag("S_OPEN_REDIRECT_PARAM", s, e, f"{key}={value[:60]}", "attr"))
    return out


def host_ip(host: str) -> IPv4 | None:
    return parse_ipv4(host)
