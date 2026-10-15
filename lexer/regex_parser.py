"""Regular-expression parser: lexical specification -> syntax trees.

Author: Prakhar Tandon (24BCI0222)

Pipeline (classic compiler front end, applied to regexes themselves):

    pattern string
      -> tokenize          (literals, escapes, [classes], operators, {NAME} expansion)
      -> insert CONCAT     (make the implicit concatenation operator explicit)
      -> shunting-yard     (infix -> postfix, respecting precedence)
      -> build tree        (postfix -> AST)

Supported syntax
    a            literal              \\. \\\\ \\- \\xHH  escapes  (\\t \\n \\r too)
    [a-z_]       character class      [^...] negated class
    .            any symbol           \\u   any non-ASCII code point (symbol 128)
    a|b  ab      alternation, concatenation
    a* a+ a?     Kleene star, plus, optional
    a{m,n} a{m}  counted repetition (expanded during Thompson construction)
    (a)          grouping             {NAME} named definition (lex "definitions" section)

Syntax errors raise RegexSyntaxError with the column where they were detected.

The module never imports Python's ``re``: the engine is built from first
principles. ``to_python_regex`` only *emits* a pattern string so that the test
suite can use ``re`` as an independent oracle.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Union

from core.types import ALPHABET_SIZE, NONASCII

# --------------------------------------------------------------------------- AST


@dataclass(frozen=True)
class Lit:
    chars: frozenset  # set of alphabet symbols


@dataclass(frozen=True)
class Eps:
    pass


@dataclass(frozen=True)
class Cat:
    left: "Node"
    right: "Node"


@dataclass(frozen=True)
class Alt:
    left: "Node"
    right: "Node"


@dataclass(frozen=True)
class Star:
    child: "Node"


@dataclass(frozen=True)
class Plus:
    child: "Node"


@dataclass(frozen=True)
class Opt:
    child: "Node"


@dataclass(frozen=True)
class Rep:
    child: "Node"
    lo: int
    hi: int


Node = Union[Lit, Eps, Cat, Alt, Star, Plus, Opt, Rep]

ANY = frozenset(range(ALPHABET_SIZE))


class RegexSyntaxError(ValueError):
    def __init__(self, msg: str, pattern: str, pos: int):
        self.pattern = pattern
        self.pos = pos
        caret = " " * pos + "^"
        super().__init__(f"{msg} at column {pos}\n  {pattern}\n  {caret}")


# ---------------------------------------------------------------------- tokens

CHARSET, LPAREN, RPAREN, ALT, STAR, PLUS, QMARK, REP, CONCAT, EPS = (
    "CHARSET", "LPAREN", "RPAREN", "ALT", "STAR", "PLUS", "QMARK", "REP", "CONCAT", "EPS",
)
POSTFIX_UNARY = {STAR, PLUS, QMARK, REP}
PRECEDENCE = {ALT: 1, CONCAT: 2}


@dataclass
class RTok:
    kind: str
    pos: int
    chars: frozenset = frozenset()
    lo: int = 0
    hi: int = 0


_SIMPLE_ESCAPES = {"t": 9, "n": 10, "r": 13, "f": 12, "v": 11, "0": 0}


def _read_escape(p: str, i: int) -> tuple[frozenset, int]:
    """Read an escape starting at p[i] == '\\'. Return (charset, next index)."""
    if i + 1 >= len(p):
        raise RegexSyntaxError("dangling backslash", p, i)
    c = p[i + 1]
    if c == "u":
        return frozenset({NONASCII}), i + 2
    if c == "x":
        hx = p[i + 2:i + 4]
        if len(hx) != 2 or any(h not in "0123456789abcdefABCDEF" for h in hx):
            raise RegexSyntaxError("\\x needs two hex digits", p, i)
        return frozenset({int(hx, 16)}), i + 4
    if c in _SIMPLE_ESCAPES:
        return frozenset({_SIMPLE_ESCAPES[c]}), i + 2
    if ord(c) >= 128:
        return frozenset({NONASCII}), i + 2
    return frozenset({ord(c)}), i + 2


def _read_class(p: str, i: int) -> tuple[frozenset, int]:
    """Read a bracket expression starting at p[i] == '['."""
    start = i
    i += 1
    negate = False
    if i < len(p) and p[i] == "^":
        negate = True
        i += 1
    members: set[int] = set()
    first = True
    while True:
        if i >= len(p):
            raise RegexSyntaxError("unterminated character class", p, start)
        c = p[i]
        if c == "]" and not first:
            i += 1
            break
        first = False
        if c == "\\":
            cs, i = _read_escape(p, i)
            lo_sym = next(iter(cs)) if len(cs) == 1 else None
        else:
            cs = frozenset({ord(c) if ord(c) < 128 else NONASCII})
            lo_sym = ord(c) if ord(c) < 128 else None
            i += 1
        # range a-z ?
        if lo_sym is not None and i + 1 < len(p) and p[i] == "-" and p[i + 1] != "]":
            if p[i + 1] == "\\":
                hi_cs, j = _read_escape(p, i + 1)
                hi_sym = next(iter(hi_cs))
            else:
                hi_sym, j = ord(p[i + 1]), i + 2
            if hi_sym < lo_sym or hi_sym >= 128:
                raise RegexSyntaxError("invalid range in character class", p, i)
            members.update(range(lo_sym, hi_sym + 1))
            i = j
        else:
            members |= cs
    if negate:
        members = set(range(ALPHABET_SIZE)) - members
    if not members:
        raise RegexSyntaxError("empty character class", p, start)
    return frozenset(members), i


def tokenize(pattern: str, defs: dict[str, str] | None = None, _depth: int = 0,
             _base: int = 0) -> list[RTok]:
    """Tokenize a pattern, expanding {NAME} references from ``defs``.

    Tokens produced by an expanded definition report the position of the
    ``{NAME}`` reference so that errors still point into the user's pattern.
    """
    if _depth > 20:
        raise RegexSyntaxError("definition nesting too deep (recursive definition?)", pattern, 0)
    defs = defs or {}
    out: list[RTok] = []
    i = 0
    p = pattern
    while i < len(p):
        c = p[i]
        pos = _base + i if _depth == 0 else _base
        if c == "\\":
            cs, i = _read_escape(p, i)
            out.append(RTok(CHARSET, pos, cs))
        elif c == "[":
            cs, i = _read_class(p, i)
            out.append(RTok(CHARSET, pos, cs))
        elif c == ".":
            out.append(RTok(CHARSET, pos, ANY))
            i += 1
        elif c == "(":
            out.append(RTok(LPAREN, pos))
            i += 1
        elif c == ")":
            out.append(RTok(RPAREN, pos))
            i += 1
        elif c == "|":
            out.append(RTok(ALT, pos))
            i += 1
        elif c == "*":
            out.append(RTok(STAR, pos))
            i += 1
        elif c == "+":
            out.append(RTok(PLUS, pos))
            i += 1
        elif c == "?":
            out.append(RTok(QMARK, pos))
            i += 1
        elif c == "{":
            close = p.find("}", i)
            if close < 0:
                raise RegexSyntaxError("unterminated '{'", p, i)
            body = p[i + 1:close]
            if body and (body[0].isdigit()):
                parts = body.split(",")
                try:
                    if len(parts) == 1:
                        lo = hi = int(parts[0])
                    elif len(parts) == 2:
                        lo = int(parts[0])
                        hi = int(parts[1]) if parts[1] else -1
                    else:
                        raise ValueError
                except ValueError:
                    raise RegexSyntaxError("bad counted repetition {m,n}", p, i) from None
                if hi != -1 and hi < lo:
                    raise RegexSyntaxError("repetition upper bound below lower bound", p, i)
                out.append(RTok(REP, pos, lo=lo, hi=hi))
            else:
                if body not in defs:
                    raise RegexSyntaxError(f"undefined name {{{body}}}", p, i)
                sub = tokenize(defs[body], defs, _depth + 1, pos)
                out.append(RTok(LPAREN, pos))
                out.extend(sub)
                out.append(RTok(RPAREN, pos))
            i = close + 1
        else:
            out.append(RTok(CHARSET, pos, frozenset({ord(c) if ord(c) < 128 else NONASCII})))
            i += 1
    return out


def insert_concat(tokens: list[RTok], pattern: str = "") -> list[RTok]:
    """Make concatenation explicit and fill empty alternatives with EPS."""
    out: list[RTok] = []
    prev: RTok | None = None
    for t in tokens:
        if t.kind in POSTFIX_UNARY and (prev is None or prev.kind in (ALT, LPAREN)):
            raise RegexSyntaxError(f"'{_op_char(t)}' has nothing to repeat", pattern, t.pos)
        # empty operand: "(|a)", "(a|)", "()", leading "|"
        if t.kind in (ALT, RPAREN) and (prev is None or prev.kind in (ALT, LPAREN)):
            out.append(RTok(EPS, t.pos))
            prev = out[-1]
        if prev is not None and prev.kind in {CHARSET, RPAREN, EPS} | POSTFIX_UNARY \
                and t.kind in (CHARSET, LPAREN):
            out.append(RTok(CONCAT, t.pos))
        out.append(t)
        prev = t
    if prev is None or prev.kind == ALT:
        out.append(RTok(EPS, prev.pos if prev else 0))
    return out


def to_postfix(tokens: list[RTok], pattern: str) -> list[RTok]:
    """Dijkstra's shunting-yard algorithm."""
    output: list[RTok] = []
    ops: list[RTok] = []
    for t in tokens:
        if t.kind in (CHARSET, EPS):
            output.append(t)
        elif t.kind in POSTFIX_UNARY:
            output.append(t)  # postfix unary binds tightest: apply immediately
        elif t.kind == LPAREN:
            ops.append(t)
        elif t.kind == RPAREN:
            while ops and ops[-1].kind != LPAREN:
                output.append(ops.pop())
            if not ops:
                raise RegexSyntaxError("unmatched ')'", pattern, t.pos)
            ops.pop()
        else:  # binary operator
            while ops and ops[-1].kind != LPAREN and PRECEDENCE[ops[-1].kind] >= PRECEDENCE[t.kind]:
                output.append(ops.pop())
            ops.append(t)
    while ops:
        t = ops.pop()
        if t.kind == LPAREN:
            raise RegexSyntaxError("unmatched '('", pattern, t.pos)
        output.append(t)
    return output


def build_tree(postfix: list[RTok], pattern: str) -> Node:
    stack: list[Node] = []
    for t in postfix:
        if t.kind == CHARSET:
            stack.append(Lit(t.chars))
        elif t.kind == EPS:
            stack.append(Eps())
        elif t.kind in POSTFIX_UNARY:
            if not stack:
                raise RegexSyntaxError(f"'{_op_char(t)}' has nothing to repeat", pattern, t.pos)
            a = stack.pop()
            if t.kind == STAR:
                stack.append(Star(a))
            elif t.kind == PLUS:
                stack.append(Plus(a))
            elif t.kind == QMARK:
                stack.append(Opt(a))
            else:
                stack.append(Rep(a, t.lo, t.hi))
        else:
            if len(stack) < 2:
                raise RegexSyntaxError("operator is missing an operand", pattern, t.pos)
            b, a = stack.pop(), stack.pop()
            stack.append(Cat(a, b) if t.kind == CONCAT else Alt(a, b))
    if len(stack) != 1:
        raise RegexSyntaxError("malformed expression", pattern, 0)
    return stack[0]


def _op_char(t: RTok) -> str:
    return {STAR: "*", PLUS: "+", QMARK: "?", REP: "{m,n}"}.get(t.kind, t.kind)


def parse(pattern: str, defs: dict[str, str] | None = None) -> Node:
    """Parse a pattern into an AST (the full front-end pipeline)."""
    toks = tokenize(pattern, defs)
    toks = insert_concat(toks, pattern)
    post = to_postfix(toks, pattern)
    return build_tree(post, pattern)


def postfix_string(pattern: str, defs: dict[str, str] | None = None) -> str:
    """Human-readable postfix form, shown in the report and the Automata Lab."""
    toks = to_postfix(insert_concat(tokenize(pattern, defs), pattern), pattern)
    parts = []
    for t in toks:
        if t.kind == CHARSET:
            parts.append(charset_label(t.chars))
        elif t.kind == REP:
            parts.append("{%d,%s}" % (t.lo, "" if t.hi < 0 else t.hi))
        else:
            parts.append({CONCAT: "·", ALT: "|", STAR: "*", PLUS: "+", QMARK: "?", EPS: "ε"}[t.kind])
    return " ".join(parts)


# ------------------------------------------------------------------- utilities


def charset_label(cs: frozenset) -> str:
    """Compact label for a set of symbols, e.g. 'a-z0-9' or '¬[/]'."""
    if cs == ANY:
        return "ANY"
    if len(cs) > ALPHABET_SIZE // 2:
        rest = frozenset(range(ALPHABET_SIZE)) - cs
        return "¬[" + _ranges(rest) + "]"
    s = _ranges(cs)
    return s if len(cs) == 1 else "[" + s + "]"


def _show(sym: int) -> str:
    if sym == NONASCII:
        return "\\u"
    if sym < 33 or sym == 127:
        return "\\x%02x" % sym
    return chr(sym)


def _ranges(cs) -> str:
    syms = sorted(cs)
    out = []
    i = 0
    while i < len(syms):
        j = i
        while j + 1 < len(syms) and syms[j + 1] == syms[j] + 1 and syms[j + 1] < 128:
            j += 1
        if j - i >= 2:
            out.append(_show(syms[i]) + "-" + _show(syms[j]))
        else:
            out.extend(_show(s) for s in syms[i:j + 1])
        i = j + 1
    return "".join(out)


def to_python_regex(node: Node) -> str:
    """Emit an equivalent Python ``re`` pattern. Used ONLY by the test oracle."""
    if isinstance(node, Lit):
        return _py_class(node.chars)
    if isinstance(node, Eps):
        return "(?:)"
    if isinstance(node, Cat):
        return to_python_regex(node.left) + to_python_regex(node.right)
    if isinstance(node, Alt):
        return "(?:" + to_python_regex(node.left) + "|" + to_python_regex(node.right) + ")"
    if isinstance(node, Star):
        return "(?:" + to_python_regex(node.child) + ")*"
    if isinstance(node, Plus):
        return "(?:" + to_python_regex(node.child) + ")+"
    if isinstance(node, Opt):
        return "(?:" + to_python_regex(node.child) + ")?"
    if isinstance(node, Rep):
        hi = "" if node.hi < 0 else str(node.hi)
        return "(?:" + to_python_regex(node.child) + "){%d,%s}" % (node.lo, hi)
    raise TypeError(node)


def _py_class(cs: frozenset) -> str:
    parts = []
    for s in sorted(cs):
        if s == NONASCII:
            parts.append("\\u0080-\\U0010ffff")
        else:
            parts.append("\\x%02x" % s)
    return "[" + "".join(parts) + "]"


def ast_size(node: Node) -> int:
    if isinstance(node, (Lit, Eps)):
        return 1
    if isinstance(node, (Cat, Alt)):
        return 1 + ast_size(node.left) + ast_size(node.right)
    return 1 + ast_size(node.child)


def ast_to_dict(node: Node) -> dict:
    """JSON form of the syntax tree for the Automata Lab."""
    if isinstance(node, Lit):
        return {"op": "lit", "label": charset_label(node.chars)}
    if isinstance(node, Eps):
        return {"op": "eps", "label": "ε"}
    if isinstance(node, (Cat, Alt)):
        return {"op": "cat" if isinstance(node, Cat) else "alt",
                "label": "·" if isinstance(node, Cat) else "|",
                "children": [ast_to_dict(node.left), ast_to_dict(node.right)]}
    label = {Star: "*", Plus: "+", Opt: "?"}.get(type(node))
    if isinstance(node, Rep):
        label = "{%d,%s}" % (node.lo, "" if node.hi < 0 else node.hi)
    return {"op": type(node).__name__.lower(), "label": label, "children": [ast_to_dict(node.child)]}
