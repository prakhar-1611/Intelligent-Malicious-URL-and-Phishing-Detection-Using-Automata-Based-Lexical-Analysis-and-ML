"""Table-driven runtime scanner over the minimal DFAs.

Author: Amrita Bhatia (24BCI0215)   (anomaly hooks: Prakhar Tandon)

Algorithm (per lexer mode, flex-style):

    maximal munch   run the mode's minimal DFA from `pos` until the dead state,
                    remembering the last position where the state was accepting;
                    emit that longest lexeme and back up to just after it
    rule priority   already baked into the accept tag of each DFA state
    lexer modes     START -> AUTHORITY -> PATH -> QUERY -> FRAGMENT (rules.MODE_SWITCH)
    panic mode      if no rule matches at `pos`, emit an ERROR lexeme for one
                    character and continue (the offending text is kept, never dropped)
    state path      the global min-DFA state after every consumed character is
                    recorded in ScanResult.trace (the automata features + Live Trace UI)

Complexity: one table lookup per character examined. Backing up after a failed
longer match can re-examine characters, so the worst case for arbitrary rule
sets is O(m^2); for this rule set the re-scanned prefix is bounded by a small
constant (measured in bench/latency.py and reported in stats["backtracked"]).

After lexing, raw lexemes are assembled into the Review 1 token types
(SCHEME, USERINFO, SUBDOMAIN, BASE_DOMAIN, TLD, IP_HOST, PORT, PATH,
QUERY_PARAM, FRAGMENT, ERROR) using the public suffix list for the
SUBDOMAIN / BASE_DOMAIN / TLD split, and the anomaly attribute checks run.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from core.types import Flag, Lexeme, ScanResult, Token
from lexer.rules import FALLTHROUGH, MODE_SWITCH, START, flag_of
from lexer.symtab import SymbolTable
from security import anomaly
from security.ip_decode import parse_ipv4

ROOT = Path(__file__).resolve().parent.parent
TABLES_PATH = ROOT / "artifacts" / "lexer_tables.json"
PSL_PATH = Path(__file__).resolve().parent / "data" / "public_suffixes.txt"

HOST_PARTS = {"HOST_LABEL", "PUNY_LABEL", "DOT", "IPV4", "IPV6", "PCT_ENC", "DOUBLE_ENC", "CTRL", "ERROR"}


@lru_cache(maxsize=1)
def public_suffixes() -> frozenset[str]:
    lines = PSL_PATH.read_text(encoding="utf-8").splitlines()
    return frozenset(x.strip().lower() for x in lines if x.strip() and not x.startswith("#"))


class ModeTable:
    __slots__ = ("name", "start", "dead", "offset", "n_states", "class_of", "table", "accept")

    def __init__(self, name: str, d: dict):
        self.name = name
        self.start = d["start"]
        self.dead = d["dead"]
        self.offset = d["offset"]
        self.n_states = d["n_states"]
        self.class_of = d["class_of"]
        self.table = d["table"]
        self.accept = {int(k): v for k, v in d["accept"].items()}


class Scanner:
    def __init__(self, tables: dict):
        self.tables = tables
        self.modes = {m: ModeTable(m, d) for m, d in tables["modes"].items()}
        self.total_states = tables["total_states"]

    # ------------------------------------------------------------ loading
    @classmethod
    def load(cls, path: str | Path = TABLES_PATH) -> "Scanner":
        p = Path(path)
        if not p.exists():
            from lexer.build_automata import main as build

            build()
        return cls(json.loads(p.read_text(encoding="utf-8")))

    def state_names(self) -> list[dict]:
        """Metadata for every global min-DFA state (feature names, UI)."""
        out = []
        for m in self.tables["mode_order"]:
            mt = self.modes[m]
            for q in range(mt.n_states):
                tag = mt.accept.get(q)
                out.append({"g": mt.offset + q, "mode": m, "state": q, "accept": tag,
                            "anomaly": flag_of(tag) is not None if tag else False, "dead": q == mt.dead})
        return out

    # ------------------------------------------------------------ lexing
    def lex(self, text: str) -> tuple[list[Lexeme], list[int], list[dict], dict]:
        lexemes: list[Lexeme] = []
        trace: list[int] = []
        steps: list[dict] = []
        n = len(text)
        pos = 0
        mode = START
        transitions = backtracked = errors = 0
        while pos < n:
            mt = self.modes[mode]
            table, class_of, accept, dead = mt.table, mt.class_of, mt.accept, mt.dead
            state = mt.start
            i = pos
            last_acc = -1
            last_type = None
            path: list[int] = []
            path_len_at_acc = 0
            while i < n:
                cp = ord(text[i])
                nxt = table[state][class_of[cp if cp < 128 else 128]]
                transitions += 1
                if nxt == dead:
                    break
                state = nxt
                path.append(state)
                i += 1
                tag = accept.get(state)
                if tag is not None:
                    last_acc, last_type, path_len_at_acc = i, tag, len(path)
            if last_acc < 0:
                if mode in FALLTHROUGH:
                    mode = FALLTHROUGH[mode]
                    continue
                # panic-mode recovery: one-character ERROR lexeme
                errors += 1
                lexemes.append(Lexeme("ERROR", text[pos], pos, pos + 1, mode))
                trace.append(-1)
                steps.append({"i": pos, "ch": text[pos], "mode": mode, "state": -1, "g": -1,
                              "accept": "ERROR", "lexeme": len(lexemes) - 1, "anomaly": False})
                pos += 1
                continue
            backtracked += len(path) - path_len_at_acc
            lx = Lexeme(last_type, text[pos:last_acc], pos, last_acc, mode)
            lexemes.append(lx)
            for j, q in enumerate(path[:path_len_at_acc]):
                trace.append(mt.offset + q)
                tag = accept.get(q)
                steps.append({"i": pos + j, "ch": text[pos + j], "mode": mode, "state": q, "g": mt.offset + q,
                              "accept": tag, "lexeme": len(lexemes) - 1,
                              "anomaly": bool(tag is not None and flag_of(tag) is not None)})
            mode = MODE_SWITCH.get((mode, last_type), mode)
            pos = last_acc
        return lexemes, trace, steps, {"transitions": transitions, "backtracked": backtracked, "errors": errors}

    # ------------------------------------------------------------ full scan
    def scan(self, text: str) -> ScanResult:
        lexemes, trace, steps, stats = self.lex(text)
        flags: list[Flag] = []
        for lx in lexemes:  # hook: DFA anomaly states (Prakhar)
            f = anomaly.dfa_flag(lx)
            if f:
                flags.append(f)
        tokens, ctx, host, reg = assemble(lexemes)
        flags.extend(anomaly.attribute_flags(ctx))  # hook: attribute checks (Prakhar)
        flags.sort(key=lambda f: (f.start, f.code))
        symtab = build_symtab(tokens, ctx, flags)
        return ScanResult(tokens=tokens, flags=flags, trace=trace, symtab=symtab.to_dict(), lexemes=lexemes,
                          steps=steps, host=host, registered_domain=reg, stats=stats)


# ---------------------------------------------------------------- assembly


def _component(lx: Lexeme) -> str:
    m, t = lx.mode, lx.type
    if m == "START":
        return "scheme"
    if m == "AUTHORITY":
        if t in ("SLASH", "DSLASH"):
            return "path"
        if t in ("QMARK", "HASH"):
            return "delim"
        return "authority"
    if m == "PATH":
        return "delim" if t in ("QMARK", "HASH") else "path"
    if m == "QUERY":
        return "delim" if t == "HASH" else "query"
    return "fragment"


def _span_token(kind: str, lxs: list[Lexeme]) -> Token:
    return Token(kind, "".join(x.value for x in lxs), lxs[0].start, lxs[-1].end)


def assemble(lexemes: list[Lexeme]) -> tuple[list[Token], anomaly.HostContext, str, str]:
    tokens: list[Token] = []
    ctx = anomaly.HostContext()
    groups: dict[str, list[Lexeme]] = {"scheme": [], "authority": [], "path": [], "query": [], "fragment": []}
    for lx in lexemes:
        comp = _component(lx)
        if lx.type == "ERROR":
            tokens.append(Token("ERROR", lx.value, lx.start, lx.end))
        if comp in groups:
            groups[comp].append(lx)

    for lx in groups["scheme"]:
        if lx.type == "SCHEME":
            ctx.scheme = lx.value[:-3].lower()
            tokens.append(Token("SCHEME", lx.value[:-3], lx.start, lx.end - 3))
        elif lx.type == "SCHEME_OPAQUE":
            ctx.scheme = lx.value[:-1].lower()
            tokens.append(Token("SCHEME", lx.value[:-1], lx.start, lx.end - 1))

    host, reg = "", ""
    auth = groups["authority"]
    if auth:
        at_idx = max((i for i, x in enumerate(auth) if x.type == "AT"), default=-1)
        if at_idx > 0:
            tokens.append(_span_token("USERINFO", auth[:at_idx]))
        rest = auth[at_idx + 1:]
        ports = [x for x in rest if x.type == "PORT"]
        if ports:
            p = ports[-1]
            tokens.append(Token("PORT", p.value[1:], p.start + 1, p.end))
            ctx.port = (p.value[1:], p.start, p.end)
        host_lx = [x for x in rest if x.type in HOST_PARTS]
        if host_lx:
            host, reg = _assemble_host(host_lx, tokens, ctx)

    if groups["path"]:
        tokens.append(_span_token("PATH", groups["path"]))

    if groups["query"]:
        cur: list[Lexeme] = []
        for lx in groups["query"] + [None]:  # type: ignore[list-item]
            if lx is None or lx.type == "AMP":
                if cur:
                    tok = _span_token("QUERY_PARAM", cur)
                    tokens.append(tok)
                    eq = next((i for i, x in enumerate(cur) if x.type == "EQ"), None)
                    key = "".join(x.value for x in cur[:eq]) if eq is not None else tok.value
                    val = "".join(x.value for x in cur[eq + 1:]) if eq is not None else ""
                    ctx.params.append((key, val, tok.start, tok.end))
                cur = []
            else:
                cur.append(lx)

    if groups["fragment"]:
        tokens.append(_span_token("FRAGMENT", groups["fragment"]))

    tokens.sort(key=lambda t: (t.start, t.type == "ERROR"))
    return tokens, ctx, host, reg


def _assemble_host(host_lx: list[Lexeme], tokens: list[Token], ctx: anomaly.HostContext) -> tuple[str, str]:
    host = "".join(x.value for x in host_lx)
    start, end = host_lx[0].start, host_lx[-1].end
    ctx.host, ctx.host_start = host, start
    single = len(host_lx) == 1 and host_lx[0].type in ("IPV4", "IPV6")
    ip = parse_ipv4(host)
    if single or ip is not None:
        ctx.ip = ip
        ctx.ip_lexed_by_dfa = single
        if single and host_lx[0].type == "IPV6":
            ctx.ip = None
        tokens.append(Token("IP_HOST", host, start, end))
        return host, host

    labels = _split_labels(host_lx)
    if not labels:
        return host, ""
    names = [x.value.lower() for x in labels]
    psl = public_suffixes()
    k = 1 if len(labels) >= 2 else 0
    for j in range(len(labels) - 1, 1, -1):  # longest multi-label suffix first
        if ".".join(names[-j:]) in psl:
            k = j
            break
    if k and k == len(labels):  # host is itself a public suffix
        k = len(labels) - 1
    suffix = labels[len(labels) - k:] if k else []
    base = labels[len(labels) - k - 1]
    subs = labels[:len(labels) - k - 1]
    for s in subs:
        tokens.append(Token("SUBDOMAIN", s.value, s.start, s.end))
    tokens.append(Token("BASE_DOMAIN", base.value, base.start, base.end))
    if suffix:
        tokens.append(Token("TLD", ".".join(x.value for x in suffix), suffix[0].start, suffix[-1].end))
    ctx.labels = [(x.value, x.start, x.end) for x in subs + [base]]
    ctx.n_subdomains = len(subs)
    reg = ".".join([base.value] + [x.value for x in suffix]).lower()
    return host, reg


def _split_labels(host_lx: list[Lexeme]) -> list[Token]:
    """Domain labels = maximal runs of host lexemes between DOT lexemes.

    An IPV4 lexeme inside a longer host (1.2.3.4.evil.example) is split back
    into its numeric labels."""
    labels: list[Token] = []
    cur: list[Lexeme] = []

    def flush() -> None:
        if cur:
            labels.append(_span_token("LABEL", cur))
            cur.clear()

    for x in host_lx:
        if x.type == "DOT":
            flush()
        elif x.type == "IPV4":
            flush()
            pos = x.start
            for part in x.value.split("."):
                labels.append(Token("LABEL", part, pos, pos + len(part)))
                pos += len(part) + 1
        else:
            cur.append(x)
    flush()
    return labels


def build_symtab(tokens: list[Token], ctx: anomaly.HostContext, flags: list[Flag]) -> SymbolTable:
    st = SymbolTable()
    kind_of = {"SCHEME": "scheme", "SUBDOMAIN": "label", "BASE_DOMAIN": "label", "TLD": "tld",
               "IP_HOST": "ip", "PORT": "port", "USERINFO": "userinfo", "FRAGMENT": "fragment"}
    for t in tokens:
        if t.type in kind_of:
            st.insert(t.value.lower() if t.type != "PORT" else t.value, kind_of[t.type], t.type, t.start)
        elif t.type == "PATH":
            pos = t.start
            for seg in t.value.split("/"):
                if seg:
                    st.insert(seg, "path_seg", "PATH", pos)
                pos += len(seg) + 1
        elif t.type == "QUERY_PARAM":
            key = t.value.split("=", 1)[0]
            st.insert(key.lower(), "param", "QUERY_PARAM", t.start)
    if ctx.host:
        st.insert(ctx.host.lower(), "host", "HOST", ctx.host_start)
    for f in flags:
        for sym in st:
            if sym.first <= f.start < sym.first + max(len(sym.lexeme), 1) or \
                    f.start <= sym.first < max(f.end, f.start + 1):
                sym.flags.add(f.code)
    return st


@lru_cache(maxsize=1)
def get_scanner() -> Scanner:
    return Scanner.load()


def scan(text: str) -> ScanResult:
    return get_scanner().scan(text)
