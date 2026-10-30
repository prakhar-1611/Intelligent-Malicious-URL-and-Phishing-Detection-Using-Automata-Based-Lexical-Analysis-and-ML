"""The lexical specification: regular definitions, token rules, lexer modes.

Author: Prakhar Tandon (24BCI0222)

This is the project's equivalent of a lex/flex ``.l`` file:

* ``DEFS``  - the definitions section (Review 1, section 3.2.2), referenced as {NAME}.
* ``RULES`` - token rules with a priority (higher wins on equal-length matches,
              like rule order in lex) and, for security rules, the anomaly flag
              raised when the scanner accepts in that rule's DFA state.
* ``MODES`` - lexer modes (flex "start conditions") that follow the RFC 3986
              component order: scheme -> authority -> path -> query -> fragment.
* ``MODE_SWITCH`` - which token moves the scanner into which mode.

Flags raised *directly by DFA accept states* (the six below plus S_DOUBLE_ENCODE)
are listed in ``Rule.flag``. Flags that need information a regular language
cannot express (an allowlist, a count threshold, Unicode scripts, IP arithmetic,
a brand list) are attribute checks in ``security/anomaly.py``.
"""
from __future__ import annotations

from dataclasses import dataclass, field


def ci(word: str) -> str:
    """Case-insensitive literal: ci('xn') -> '[xX][nN]'."""
    out = []
    for ch in word:
        if ch.isalpha():
            out.append(f"[{ch.lower()}{ch.upper()}]")
        elif ch in "\\.|*+?()[]{}^-":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


# --------------------------------------------------------------- definitions
DEFS: dict[str, str] = {
    "LETTER": "[A-Za-z]",
    "DIGIT": "[0-9]",
    "HEX": "[0-9A-Fa-f]",
    "ALNUM": "{LETTER}|{DIGIT}",
    # host-label character: ALNUM, plus '_' (seen in real hostnames) and any
    # non-ASCII code point (\u), so Unicode IDN labels stay a single token
    "LCHAR": "{ALNUM}|_|\\u",
    # Review 1: LABEL = ALNUM (ALNUM | '-')* ALNUM | ALNUM   (extended with LCHAR)
    "LABEL": "{LCHAR}({LCHAR}|\\-)*{LCHAR}|{LCHAR}",
    "PCT_ENC": "%{HEX}{HEX}",
    "OCTET": "{DIGIT}+",
    "PCHAR": "{ALNUM}|\\u|[\\-_.~!$&'()*+,;=:@]",
    "QCHAR": "{ALNUM}|\\u|[\\-_.~!$'()*+,;:@/?]",
    "FCHAR": "{ALNUM}|\\u|[\\-_.~!$&'()*+,;=:@/?#]",
    "SCHEME_CH": "{LETTER}|{DIGIT}|[+\\-.]",
}

# flag severities (1 = weak evidence ... 3 = strong evidence)
SEVERITY = {
    "S_PUNY_DETECT": 2,
    "S_MIXED_SCRIPT": 3,
    "S_PCT_ENCODE": 1,
    "S_IP_HOST": 3,
    "S_PORT_ANOMALY": 2,
    "S_AT_ABUSE": 3,
    "S_REDIRECT_ABUSE": 2,
    "S_CONTROL_ANOMALY": 3,
    "S_SUBDOMAIN_DEPTH": 2,
    # new in Review 2
    "S_DOUBLE_ENCODE": 3,
    "S_IP_OBFUSCATED": 3,
    "S_OPEN_REDIRECT_PARAM": 2,
    "S_HOMOGLYPH": 3,
    # new in Review 3
    "S_TYPOSQUAT": 2,
    # email lexer
    "S_FROM_REPLYTO_MISMATCH": 2,
    "S_RETURNPATH_MISMATCH": 2,
    "S_DISPLAYNAME_SPOOF": 3,
    # email checks, new in Review 3
    "S_AUTH_FAIL": 2,
    "S_LOOKALIKE_SENDER": 3,
    "S_LINK_MISMATCH": 3,
    "S_RISKY_ATTACHMENT": 3,
}

FLAG_DESCRIPTIONS = {
    "S_PUNY_DETECT": "Domain label starts with xn-- (punycode / IDN encoding).",
    "S_MIXED_SCRIPT": "A domain label mixes Unicode scripts (e.g. Latin + Cyrillic).",
    "S_PCT_ENCODE": "Percent-encoded byte such as %2e or %61.",
    "S_IP_HOST": "Host is a literal IP address instead of a domain name.",
    "S_PORT_ANOMALY": "Explicit port outside the allowlist (80, 443).",
    "S_AT_ABUSE": "'@' in the authority: everything before it is ignored as userinfo.",
    "S_REDIRECT_ABUSE": "Repeated '//' after the authority component.",
    "S_CONTROL_ANOMALY": "Control / null byte inside the URL.",
    "S_SUBDOMAIN_DEPTH": "Subdomain depth above the configured threshold.",
    "S_DOUBLE_ENCODE": "Double percent-encoding (%25xx) used to hide a character.",
    "S_IP_OBFUSCATED": "IPv4 host written in decimal, hex or octal form.",
    "S_OPEN_REDIRECT_PARAM": "Query parameter like url= / next= carries an embedded URL.",
    "S_HOMOGLYPH": "Domain's confusables skeleton equals a well-known brand.",
    "S_TYPOSQUAT": "Registered domain is one or two typing edits away from a well-known brand.",
    "S_FROM_REPLYTO_MISMATCH": "From and Reply-To use different domains.",
    "S_RETURNPATH_MISMATCH": "From and Return-Path use different domains.",
    "S_DISPLAYNAME_SPOOF": "Display name claims a brand or address the sender domain doesn't match.",
    "S_AUTH_FAIL": "Authentication-Results reports an SPF, DKIM or DMARC failure.",
    "S_LOOKALIKE_SENDER": "Sender's registered domain imitates a well-known brand.",
    "S_LINK_MISMATCH": "An HTML link shows one domain but points to another.",
    "S_RISKY_ATTACHMENT": "Attachment with an executable or script extension.",
}
EMAIL_FLAGS = {"S_FROM_REPLYTO_MISMATCH", "S_RETURNPATH_MISMATCH", "S_DISPLAYNAME_SPOOF", "S_AUTH_FAIL",
               "S_LOOKALIKE_SENDER", "S_LINK_MISMATCH", "S_RISKY_ATTACHMENT"}

DFA_FLAGS = {"S_PUNY_DETECT", "S_PCT_ENCODE", "S_IP_HOST", "S_AT_ABUSE",
             "S_REDIRECT_ABUSE", "S_CONTROL_ANOMALY", "S_DOUBLE_ENCODE"}
ATTR_FLAGS = {"S_PORT_ANOMALY", "S_SUBDOMAIN_DEPTH", "S_MIXED_SCRIPT", "S_IP_OBFUSCATED",
              "S_OPEN_REDIRECT_PARAM", "S_HOMOGLYPH", "S_TYPOSQUAT"}
# shortcut: the saved model predates these flags, so ml/features.py ignores them; empty this set
# and retrain (python -m ml.train) to make them model inputs
UNTRAINED_FLAGS = {"S_TYPOSQUAT"}


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: str
    priority: int
    modes: tuple[str, ...]
    flag: str | None = None
    doc: str = ""
    examples: tuple[str, ...] = field(default_factory=tuple)


START, AUTHORITY, PATH, QUERY, FRAGMENT = "START", "AUTHORITY", "PATH", "QUERY", "FRAGMENT"
ALL = (START, AUTHORITY, PATH, QUERY, FRAGMENT)
MODES = list(ALL)

RULES: list[Rule] = [
    # ---- START ------------------------------------------------------------
    Rule("SCHEME", "{LETTER}({SCHEME_CH})*://", 50, (START,),
         doc="Hierarchical scheme followed by '//' (RFC 3986 scheme + authority marker).",
         examples=("https://", "http://", "ftp://", "svn+ssh://")),
    Rule("SCHEME_OPAQUE", "(" + "|".join(ci(s) for s in ("javascript", "data", "mailto", "vbscript", "file", "blob")) + "):",
         40, (START,), doc="Opaque schemes with no authority; the rest is lexed as a path.",
         examples=("javascript:", "data:", "mailto:")),
    # ---- AUTHORITY ----------------------------------------------------------
    Rule("HOST_LABEL", "{LABEL}", 10, (AUTHORITY,), doc="Domain label (Review 1 LABEL rule).",
         examples=("www", "example", "a", "login-secure", "co")),
    Rule("PUNY_LABEL", ci("xn") + "\\-\\-({LCHAR}|\\-)*{LCHAR}", 30, (AUTHORITY,), flag="S_PUNY_DETECT",
         doc="Punycode-encoded label (ACE prefix xn--).", examples=("xn--pypal-4ve", "xn--80ak6aa92e")),
    Rule("IPV4", "{OCTET}\\.{OCTET}\\.{OCTET}\\.{OCTET}", 30, (AUTHORITY,), flag="S_IP_HOST",
         doc="Dotted IPv4 host (any digit counts, so octal-looking octets are caught too).",
         examples=("192.168.1.1", "10.0.0.1", "0300.0250.01.01")),
    Rule("IPV6", "\\[[0-9A-Fa-f:.]+\\]", 30, (AUTHORITY,), flag="S_IP_HOST",
         doc="Bracketed IPv6 literal.", examples=("[::1]", "[2001:db8::1]")),
    Rule("DOT", "\\.", 5, (AUTHORITY,), examples=(".",)),
    Rule("PORT", ":{DIGIT}+", 20, (AUTHORITY,), doc="Explicit port.", examples=(":8080", ":443")),
    Rule("COLON", ":", 5, (AUTHORITY,), doc="userinfo separator user:pass", examples=(":",)),
    Rule("AT", "@", 30, (AUTHORITY,), flag="S_AT_ABUSE",
         doc="userinfo delimiter; browsers discard everything before it.", examples=("@",)),
    Rule("SUB_DELIM", "[!$&'()*+,;=~]", 5, (AUTHORITY,), examples=("!", "~")),
    Rule("DSLASH", "//+", 20, (AUTHORITY, PATH), flag="S_REDIRECT_ABUSE",
         doc="Repeated slash after the authority.", examples=("//", "///")),
    Rule("SLASH", "/", 10, (AUTHORITY, PATH), examples=("/",)),
    Rule("QMARK", "\\?", 10, (AUTHORITY, PATH), doc="Start of query.", examples=("?",)),
    Rule("HASH", "#", 10, (AUTHORITY, PATH, QUERY), doc="Start of fragment.", examples=("#",)),
    # ---- shared security rules (every mode) -------------------------------------
    Rule("PCT_ENC", "{PCT_ENC}", 30, ALL[1:], flag="S_PCT_ENCODE",
         doc="Percent-encoded byte.", examples=("%2e", "%61", "%2F")),
    Rule("DOUBLE_ENC", "%25{HEX}{HEX}", 35, ALL[1:], flag="S_DOUBLE_ENCODE",
         doc="%25 followed by two hex digits: decodes to another %xx.", examples=("%252e", "%2541")),
    Rule("CTRL", "[\\x00-\\x1f\\x7f]", 40, ALL, flag="S_CONTROL_ANOMALY",
         doc="ASCII control character or DEL.", examples=("\\x00", "\\x0a")),
    # ---- PATH ---------------------------------------------------------------
    Rule("PATH_SEG", "({PCHAR})+", 10, (PATH,), doc="Path segment characters (RFC 3986 pchar minus %).",
         examples=("account", "reset.php", "a-b_c~d")),
    # ---- QUERY --------------------------------------------------------------
    Rule("QTEXT", "({QCHAR})+", 10, (QUERY,), doc="Query key or value text.", examples=("id", "123", "http://x.y/z")),
    Rule("EQ", "=", 10, (QUERY,), examples=("=",)),
    Rule("AMP", "&", 10, (QUERY,), examples=("&",)),
    # ---- FRAGMENT -----------------------------------------------------------
    Rule("FTEXT", "({FCHAR})+", 10, (FRAGMENT,), doc="Fragment text.", examples=("login", "top/section")),
]

RULES_BY_NAME = {r.name: r for r in RULES}

# extra standalone examples from the Review 1 report (figures 3.2a and 3.2c)
EXAMPLE_PATTERNS: dict[str, str] = {
    "XN_PREFIX": "xn\\-\\-",  # Figure 3.2a: Thompson NFA for the literal xn--
    "LABEL_A": "a(a|\\-)*a|a",  # Figure 3.2c: LABEL restricted to the alphabet {a, -}
    "REDOS_NESTED": "(a+)+",  # the classic catastrophic-backtracking pattern
}

MODE_SWITCH: dict[tuple[str, str], str] = {
    (START, "SCHEME"): AUTHORITY,
    (START, "SCHEME_OPAQUE"): PATH,
    (AUTHORITY, "SLASH"): PATH,
    (AUTHORITY, "DSLASH"): PATH,
    (AUTHORITY, "QMARK"): QUERY,
    (AUTHORITY, "HASH"): FRAGMENT,
    (PATH, "QMARK"): QUERY,
    (PATH, "HASH"): FRAGMENT,
    (QUERY, "HASH"): FRAGMENT,
}

# when the START mode matches nothing, fall through to this mode without consuming
FALLTHROUGH = {START: AUTHORITY}


def rules_for_mode(mode: str) -> list[Rule]:
    return [r for r in RULES if mode in r.modes]


def flag_of(token_type: str) -> str | None:
    r = RULES_BY_NAME.get(token_type)
    return r.flag if r else None
