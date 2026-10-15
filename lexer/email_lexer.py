"""Email header lexer for a subset of RFC 5322.

Author: Prakhar Tandon (24BCI0222)

Scope (Review 1 section 3.2.2 restricted EMAIL_KEY to unfolded lines; Review 1
section 3.8 listed folding as a limitation, which this module now removes):

1. Unfolding: a CRLF/LF followed by a space or tab continues the previous
   header line (RFC 5322 section 2.2.3). Folded lines are joined before lexing.
2. Header keys are recognised by a minimal DFA built with the project's own
   pipeline from   EMAIL_KEY = [!-9;-~]+ ':'   (printable ASCII except ':').
3. Address-bearing fields are parsed into display name, local part, domain.
4. Flags: S_FROM_REPLYTO_MISMATCH, S_RETURNPATH_MISMATCH, S_DISPLAYNAME_SPOOF.
5. URLs found in the body are handed to the URL scanner.

Keys handled specially: From, To, Reply-To, Return-Path, Received, Message-ID,
Authentication-Results. Other keys are still tokenised as EMAIL_HEADER_KEY.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from functools import lru_cache

from core.types import Flag, Token, symbol_of
from lexer.rules import SEVERITY
from security import idn

EMAIL_KEY_PATTERN = "[!-9;-~]+:"
KNOWN_KEYS = {"from", "to", "reply-to", "return-path", "received", "message-id",
              "authentication-results", "subject", "date", "cc", "sender"}


@lru_cache(maxsize=1)
def _key_dfa():
    from lexer.build_automata import pipeline

    return pipeline(EMAIL_KEY_PATTERN, "EMAIL_KEY", defs={})["min"]


def match_key(line: str) -> int:
    """Length of the longest EMAIL_KEY prefix of ``line`` (0 if none): maximal munch."""
    dfa = _key_dfa()
    state, last = dfa.start, 0
    for i, ch in enumerate(line):
        state = dfa.trans[state][symbol_of(ch)]
        if state == dfa.dead:
            break
        if state in dfa.accept:
            last = i + 1
    return last


def unfold(raw: str) -> tuple[list[str], str, int]:
    """Split header block from body and unfold continuation lines.

    Returns (unfolded header lines, body, number of folds removed)."""
    text = raw.replace("\r\n", "\n")
    sep = text.find("\n\n")
    head, body = (text, "") if sep < 0 else (text[:sep], text[sep + 2:])
    lines: list[str] = []
    folds = 0
    for line in head.split("\n"):
        if line[:1] in (" ", "\t") and lines:
            lines[-1] += " " + line.strip()
            folds += 1
        else:
            lines.append(line)
    return lines, body, folds


@dataclass
class Address:
    display: str = ""
    local: str = ""
    domain: str = ""

    @property
    def addr(self) -> str:
        return f"{self.local}@{self.domain}" if self.domain else self.local


def parse_address(value: str) -> Address:
    """'"PayPal" <service@evil.example>'  ->  Address('PayPal', 'service', 'evil.example')."""
    v = value.strip()
    display, addr = "", v
    lt, gt = v.rfind("<"), v.rfind(">")
    if lt >= 0 and gt > lt:
        display, addr = v[:lt].strip(), v[lt + 1:gt].strip()
    if len(display) >= 2 and display[0] == '"' and display[-1] == '"':
        display = display[1:-1].replace('\\"', '"')
    # drop RFC 5322 comments "(...)"
    while "(" in addr and ")" in addr[addr.find("("):]:
        a, b = addr.find("("), addr.find(")", addr.find("("))
        addr = (addr[:a] + addr[b + 1:]).strip()
    at = addr.rfind("@")
    if at < 0:
        return Address(display, addr, "")
    return Address(display, addr[:at], addr[at + 1:].strip().lower().rstrip("."))


def registered_domain(domain: str) -> str:
    if not domain:
        return ""
    from lexer.scanner import scan

    return scan(domain).registered_domain or domain


def find_urls(body: str, limit: int = 50) -> list[str]:
    """Locate http(s):// and www. URLs in free text without ``re``."""
    stops = set(" \t\r\n<>\"'()[]{}|\\^`")
    urls: list[str] = []
    low = body.lower()
    i = 0
    while i < len(body) and len(urls) < limit:
        cands = [p for p in (low.find("http://", i), low.find("https://", i), low.find("www.", i)) if p >= 0]
        if not cands:
            break
        s = min(cands)
        e = s
        while e < len(body) and body[e] not in stops:
            e += 1
        url = body[s:e].rstrip(".,;:!?")
        if len(url) > 4:
            urls.append(url)
        i = max(e, s + 1)
    return urls


@dataclass
class EmailScanResult:
    headers: list[dict] = field(default_factory=list)
    tokens: list[Token] = field(default_factory=list)
    flags: list[Flag] = field(default_factory=list)
    addresses: dict = field(default_factory=dict)
    auth_results: dict = field(default_factory=dict)
    folds: int = 0
    urls: list[dict] = field(default_factory=list)
    malformed_lines: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def _flag(code: str, evidence: str, start: int = 0, end: int = 0) -> Flag:
    return Flag(code, start, end, evidence, SEVERITY[code], "attr")


def scan_email(raw: str, scan_body_urls: bool = True) -> EmailScanResult:
    lines, body, folds = unfold(raw)
    res = EmailScanResult(folds=folds)
    offset = 0
    fields: dict[str, list[str]] = {}
    for line in lines:
        n = match_key(line)
        if n == 0:
            if line.strip():
                res.malformed_lines += 1
            offset += len(line) + 1
            continue
        key, value = line[:n - 1], line[n:].strip()
        res.tokens.append(Token("EMAIL_HEADER_KEY", key, offset, offset + n - 1))
        vstart = offset + n + (len(line[n:]) - len(line[n:].lstrip()))
        res.tokens.append(Token("EMAIL_HEADER_VAL", value, vstart, vstart + len(value)))
        res.headers.append({"key": key, "value": value, "known": key.lower() in KNOWN_KEYS})
        fields.setdefault(key.lower(), []).append(value)
        offset += len(line) + 1

    frm = parse_address(fields["from"][0]) if "from" in fields else Address()
    reply = parse_address(fields["reply-to"][0]) if "reply-to" in fields else None
    rpath = parse_address(fields["return-path"][0]) if "return-path" in fields else None
    res.addresses = {
        "from": asdict(frm),
        "reply_to": asdict(reply) if reply else None,
        "return_path": asdict(rpath) if rpath else None,
        "to": [asdict(parse_address(v)) for v in fields.get("to", [])],
        "received_count": len(fields.get("received", [])),
        "message_id_domain": parse_address(fields["message-id"][0]).domain if "message-id" in fields else "",
    }
    from_reg = registered_domain(frm.domain)

    if reply and reply.domain and from_reg and registered_domain(reply.domain) != from_reg:
        res.flags.append(_flag("S_FROM_REPLYTO_MISMATCH", f"From {frm.domain} vs Reply-To {reply.domain}"))
    if rpath and rpath.domain and from_reg and registered_domain(rpath.domain) != from_reg:
        res.flags.append(_flag("S_RETURNPATH_MISMATCH", f"From {frm.domain} vs Return-Path {rpath.domain}"))

    spoof = _display_spoof(frm, from_reg)
    if spoof:
        res.flags.append(_flag("S_DISPLAYNAME_SPOOF", spoof))

    for v in fields.get("authentication-results", []):
        for part in v.replace(";", " ").split():
            if "=" in part:
                k, _, val = part.partition("=")
                if k.lower() in ("spf", "dkim", "dmarc"):
                    res.auth_results[k.lower()] = val.lower()

    if scan_body_urls and body:
        from lexer.scanner import scan

        for url in find_urls(body):
            r = scan(url[:2048])
            res.urls.append({"url": url, "flags": [asdict(f) for f in r.flags],
                             "registered_domain": r.registered_domain})
    return res


def _display_spoof(frm: Address, from_reg: str) -> str | None:
    disp = frm.display.strip()
    if not disp:
        return None
    # 1. display name contains an address on a different domain: "service@paypal.com" <x@evil.example>
    if "@" in disp:
        inner = parse_address(disp.strip("'\""))
        if inner.domain and registered_domain(inner.domain) != from_reg:
            return f"display name shows {inner.addr} but sender domain is {frm.domain}"
    # 2. display name claims a brand the sender domain does not belong to
    base_label = from_reg.split(".")[0] if from_reg else ""
    words = "".join(c if c.isalnum() else " " for c in disp.lower()).split()
    for w in words + ["".join(words)]:
        sk = idn.skeleton(w)
        for brand in idn.brands():
            if len(brand) >= 4 and sk == idn.skeleton(brand) and brand not in base_label:
                return f'display name "{disp}" claims {brand} but sender domain is {frm.domain or "?"}'
    return None
