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
6. (Review 3) MIME: a recursive-descent parser over multipart boundaries builds the part tree
       part      := headers CRLF body
       body      := multipart | leaf
       multipart := preamble ( "--" boundary CRLF part )* "--" boundary "--" epilogue
   decoding base64 / quoted-printable leaves. Body signals: S_LINK_MISMATCH (HTML link text shows
   one domain, href goes to another), S_RISKY_ATTACHMENT; header signals: S_AUTH_FAIL
   (SPF/DKIM/DMARC), S_LOOKALIKE_SENDER (sender domain is a homoglyph/typosquat of a brand).
7. ``combine_verdict`` turns flags + the worst URL score into Safe / Suspicious / Phishing.

Keys handled specially: From, To, Reply-To, Return-Path, Received, Message-ID,
Authentication-Results. Other keys are still tokenised as EMAIL_HEADER_KEY.
"""
from __future__ import annotations

import base64
import binascii
import quopri
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from html.parser import HTMLParser

from core.types import Flag, Token, symbol_of
from lexer.rules import SEVERITY
from security import idn
from security.defang import defang

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
    if text.startswith("\n"):  # a MIME part may have no headers at all
        head, body = "", text[1:]
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
    mime: dict = field(default_factory=dict)
    mime_truncated: bool = False
    links: list[dict] = field(default_factory=list)

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

    # only the topmost header is the receiving server's own; lower ones can be written by the sender
    for v in fields.get("authentication-results", [])[:1]:
        for part in v.replace(";", " ").split():
            if "=" in part:
                k, _, val = part.partition("=")
                if k.lower() in ("spf", "dkim", "dmarc"):
                    res.auth_results[k.lower()] = val.lower()
    dmarc_pass = res.auth_results.get("dmarc") == "pass"

    if reply and reply.domain and from_reg and not same_org(registered_domain(reply.domain), from_reg):
        res.flags.append(_flag("S_FROM_REPLYTO_MISMATCH", f"From {frm.domain} vs Reply-To {reply.domain}"))
    # with DMARC pass the From domain itself signed the mail; bulk senders bounce through their
    # mailing service (sendgrid.net, amazonses.com), so a different Return-Path is expected then
    if rpath and rpath.domain and from_reg and not dmarc_pass \
            and not same_org(registered_domain(rpath.domain), from_reg):
        res.flags.append(_flag("S_RETURNPATH_MISMATCH", f"From {frm.domain} vs Return-Path {rpath.domain}"))

    spoof = _display_spoof(frm, from_reg)
    if spoof:
        res.flags.append(_flag("S_DISPLAYNAME_SPOOF", spoof))

    bad = [f"{k}={v}" for k, v in res.auth_results.items() if v in AUTH_FAILURES]
    if bad:
        res.flags.append(_flag("S_AUTH_FAIL", ", ".join(bad)))
    lookalike = _lookalike_sender(from_reg)
    if lookalike:
        res.flags.append(_flag("S_LOOKALIKE_SENDER", f"sender domain {frm.domain}: {lookalike}"))

    acc = _MimeAcc()
    res.mime = parse_part(lines, body, acc)
    res.mime_truncated = acc.truncated
    for node in acc.attachments:
        if node["risky"]:
            res.flags.append(_flag("S_RISKY_ATTACHMENT", f"attachment {node['filename']}"))

    candidates: list[str] = []
    for ctype, text in acc.texts:
        if ctype == "text/html":
            anchors = _Anchors()
            anchors.feed(text)
            anchors.close()
            candidates += find_urls(" ".join(anchors.text))
            for shown, href in anchors.links[:50]:
                res.links.append(_link(shown, href))
                candidates.append(href)
        else:
            candidates += find_urls(text)
    for link in res.links:
        # a DMARC-verified sender linking to its own domain (its click tracker) is not a lie
        first_party = dmarc_pass and same_org(link["href_domain"], from_reg)
        if link["mismatch"] and not first_party:
            res.flags.append(_flag("S_LINK_MISMATCH", f"text shows {link['text_domain']}, "
                                                      f"link goes to {link['href_domain']}"))

    if scan_body_urls:
        from lexer.scanner import scan

        seen: set[str] = set()
        for url in candidates:
            if url in seen or not url.lower().startswith(("http://", "https://", "www.")):
                continue
            seen.add(url)
            r = scan(url[:2048])
            res.urls.append({"url": url, "flags": [asdict(f) for f in r.flags],
                             "registered_domain": r.registered_domain})
            if len(res.urls) >= 50:
                break
    return res


def same_org(a: str, b: str) -> bool:
    """Same registered domain, or the same name under another suffix (unstop.news / unstop.com).
    A look-alike (unst0p.com) is a different name, so it still counts as a mismatch."""
    return a == b or (bool(a) and a.split(".")[0] == b.split(".")[0])


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


# ------------------------------------------------------------------ MIME (Review 3)
AUTH_FAILURES = {"fail", "softfail", "permerror", "temperror"}
RISKY_ATTACHMENT_EXT = (".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".wsf",
                        ".hta", ".ps1", ".jar", ".msi", ".lnk", ".iso", ".img", ".html", ".htm", ".svg",
                        ".docm", ".xlsm", ".pptm")
MAX_MIME_PARTS, MAX_MIME_DEPTH = 100, 8


def header_params(value: str) -> tuple[str, dict[str, str]]:
    """'multipart/mixed; boundary="b;1"'  ->  ('multipart/mixed', {'boundary': 'b;1'})."""
    pieces, cur, quoted = [], "", False
    for c in value:
        if c == '"':
            quoted = not quoted
        if c == ";" and not quoted:
            pieces.append(cur)
            cur = ""
        else:
            cur += c
    pieces.append(cur)
    params: dict[str, str] = {}
    for piece in pieces[1:]:
        k, sep, v = piece.partition("=")
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] == '"':
            v = v[1:-1]
        if sep:
            params[k.strip().lower()] = v
    return pieces[0].strip().lower(), params


def split_multipart(body: str, boundary: str) -> list[str]:
    """Body chunks between "--boundary" delimiter lines; preamble and epilogue are dropped."""
    delim = "--" + boundary
    parts: list[str] = []
    cur: list[str] | None = None
    for line in body.split("\n"):
        s = line.rstrip()
        if s in (delim, delim + "--"):
            if cur is not None:
                parts.append("\n".join(cur))
            if s != delim:
                return parts
            cur = []
        elif cur is not None:
            cur.append(line)
    if cur is not None:  # missing close delimiter: keep the last part
        parts.append("\n".join(cur))
    return parts


def decode_body(body: str, encoding: str) -> bytes:
    if encoding == "base64":
        try:
            return base64.b64decode("".join(body.split()))
        except (binascii.Error, ValueError):
            return body.encode("utf-8", "replace")
    if encoding == "quoted-printable":
        return quopri.decodestring(body.encode("utf-8", "replace"))
    return body.encode("utf-8", "replace")


@dataclass
class _MimeAcc:
    count: int = 0
    truncated: bool = False
    texts: list[tuple[str, str]] = field(default_factory=list)  # (content type, decoded text)
    attachments: list[dict] = field(default_factory=list)


def parse_part(lines: list[str], body: str, acc: _MimeAcc, depth: int = 0) -> dict:
    """One MIME part (headers already unfolded) -> tree node; recurses into multipart bodies."""
    fields: dict[str, str] = {}
    for line in lines:
        k, sep, v = line.partition(":")
        if sep:
            fields.setdefault(k.strip().lower(), v.strip())
    ctype, cparams = header_params(fields.get("content-type", "text/plain"))
    disp, dparams = header_params(fields.get("content-disposition", ""))
    node = {"content_type": ctype or "text/plain", "charset": cparams.get("charset", ""),
            "encoding": fields.get("content-transfer-encoding", "7bit").strip().lower(),
            "disposition": disp, "filename": dparams.get("filename") or cparams.get("name", ""),
            "size": 0, "risky": False, "children": []}
    acc.count += 1
    boundary = cparams.get("boundary")
    if ctype.startswith("multipart/") and boundary and depth < MAX_MIME_DEPTH:
        for chunk in split_multipart(body, boundary):
            if acc.count >= MAX_MIME_PARTS:
                acc.truncated = True
                break
            sub_lines, sub_body, _ = unfold(chunk)
            node["children"].append(parse_part(sub_lines, sub_body, acc, depth + 1))
        return node
    data = decode_body(body, node["encoding"])
    node["size"] = len(data)
    if node["filename"] or disp == "attachment":
        node["risky"] = node["filename"].lower().rstrip(". ").endswith(RISKY_ATTACHMENT_EXT)
        acc.attachments.append(node)
    elif node["content_type"].startswith("text/"):
        try:
            text = data.decode(node["charset"] or "utf-8", errors="replace")
        except LookupError:  # unknown charset name
            text = data.decode("utf-8", errors="replace")
        acc.texts.append((node["content_type"], text))
    return node


class _Anchors(HTMLParser):
    """Collects (visible text, href) for every <a>, plus all visible text. Nothing is fetched."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self.text: list[str] = []
        self._href: str | None = None
        self._shown: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            # WHATWG URL parsing removes every ASCII tab and newline; mail HTML wraps long hrefs
            href = dict(attrs).get("href") or ""
            self._href = "".join(c for c in href if c not in "\t\n\r").strip()
            self._shown = []

    def handle_data(self, data):
        self.text.append(data)
        if self._href is not None:
            self._shown.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((" ".join("".join(self._shown).split()), self._href))
            self._href = None


def _looks_like_domain(text: str) -> bool:
    t = text.strip().lower()
    return bool(t) and " " not in t and "." in t.strip(".") and not t.startswith("mailto:")


def _url_domain(url: str) -> str:
    from lexer.scanner import scan

    return scan(url[:2048]).registered_domain.lower()


def _link(shown: str, href: str) -> dict:
    """Compare the domain a link displays with the domain its href points to."""
    href_dom = _url_domain(href) if href.lower().startswith(("http://", "https://", "www.")) else ""
    text_dom = _url_domain(shown) if _looks_like_domain(shown) else ""
    return {"text": defang(shown[:200]) if text_dom else shown[:200], "href": defang(href[:2048]),
            "text_domain": text_dom, "href_domain": href_dom,
            "mismatch": bool(text_dom and href_dom and not same_org(text_dom, href_dom))}


def _lookalike_sender(from_reg: str) -> str | None:
    label = from_reg.split(".")[0] if from_reg else ""
    for part in [label] + (label.split("-") if "-" in label else []):
        if not part:
            continue
        target = idn.homoglyph_target(part)
        if target:
            return f"{part} imitates {target}"
        hit = idn.typosquat_target(part)
        if hit:
            return f"{part} is {hit[1]} edit(s) from {hit[0]}"
    return None


# combined verdict: policy constants, reported back in every response
PHISHING_POINTS, SUSPICIOUS_POINTS = 5, 2
VERDICT_RULE = (f"Points = sum of email flag severities (1 weak, 2 medium, 3 strong). Phishing if the worst "
                f"link reaches the model's malicious threshold or points >= {PHISHING_POINTS}; Suspicious if "
                f"the worst link reaches the suspicious threshold or points >= {SUSPICIOUS_POINTS}; "
                f"otherwise Safe. When the sender passes DMARC and no email flag is raised, links alone "
                f"can only make it Suspicious: the URL model over-scores long tracking links. A link "
                f"counts as Malicious only if the domain-only model or a strong flag backs the full "
                f"model; otherwise it takes the domain-only model's verdict.")


def combine_verdict(flags: list[Flag], url_scores: list[float], thresholds: dict,
                    authenticated: bool = False, url_verdicts: list[str] | None = None) -> dict:
    """``authenticated``: the topmost Authentication-Results says dmarc=pass for the From domain.
    ``url_verdicts``: each link's verdict when the caller decided it (else read off the scores)."""
    points = sum(f.severity for f in flags)
    worst = max(url_scores, default=0.0)
    mal, sus = thresholds["malicious"], thresholds["suspicious"]
    if url_verdicts is None:
        url_verdicts = ["Malicious" if s >= mal else "Suspicious" if s >= sus else "Safe" for s in url_scores]
    any_mal = "Malicious" in url_verdicts
    any_sus = any_mal or "Suspicious" in url_verdicts
    if any_mal and authenticated and not flags:
        v, why = "Suspicious", ("a link is rated Malicious, but the sender passed DMARC and no email flag was "
                                "raised, so links alone stop at Suspicious")
    elif any_mal:
        v, why = "Phishing", f"a link is rated Malicious (worst score {worst:.3f}, malicious line {mal:.3f})"
    elif points >= PHISHING_POINTS:
        v, why = "Phishing", f"{points} evidence points >= {PHISHING_POINTS}"
    elif any_sus:
        v, why = "Suspicious", f"a link is rated Suspicious (worst score {worst:.3f})"
    elif points >= SUSPICIOUS_POINTS:
        v, why = "Suspicious", f"{points} evidence points >= {SUSPICIOUS_POINTS}"
    else:
        v, why = "Safe", f"{points} evidence points and worst link score {worst:.3f} are below every threshold"
    return {"verdict": v, "evidence_points": points, "max_url_score": worst, "deciding_rule": why,
            "rule": VERDICT_RULE,
            "reasons": [{"code": f.code, "points": f.severity, "evidence": f.evidence} for f in flags]}
