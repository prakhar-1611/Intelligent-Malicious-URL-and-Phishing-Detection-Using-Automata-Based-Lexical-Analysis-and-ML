"""Shared interfaces between the three compiler stages and the downstream layers.

Owned jointly by Prakhar Tandon, Ishitwo Khanra and Amrita Bhatia.
Changes to this file need all three to agree (Review 2 plan, section 3).

Alphabet convention used by every automaton in the project
----------------------------------------------------------
Input characters are mapped to integer *symbols* before they reach an
automaton:

* code points 0..127 map to themselves (plain ASCII),
* every code point >= 128 maps to the single symbol ``NONASCII`` (128).

Non-ASCII characters are therefore *kept* (they matter for IDN / homoglyph
analysis) but the alphabet stays finite and small: |Sigma| = 129.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import FrozenSet

NONASCII = 128
ALPHABET_SIZE = 129
ALPHABET = range(ALPHABET_SIZE)

CharSet = FrozenSet[int]


def symbol_of(ch: str) -> int:
    """Map one input character to its alphabet symbol."""
    cp = ord(ch)
    return cp if cp < 128 else NONASCII


@dataclass
class NFA:  # Prakhar -> Ishitwo
    n_states: int
    start: int
    trans: dict[tuple[int, CharSet], set[int]]
    eps: dict[int, set[int]]
    accept: dict[int, tuple[str, int]]  # state -> (TOKEN_TYPE or S_FLAG, priority)

    def accepts(self, text: str) -> bool:
        """Direct NFA simulation (set of states), used as a test oracle."""
        current = self.eps_closure({self.start})
        for ch in text:
            sym = symbol_of(ch)
            nxt: set[int] = set()
            for (src, cs), dsts in self.trans.items():
                if src in current and sym in cs:
                    nxt |= dsts
            current = self.eps_closure(nxt)
            if not current:
                return False
        return any(s in self.accept for s in current)

    def eps_closure(self, states: set[int]) -> set[int]:
        stack = list(states)
        seen = set(states)
        while stack:
            s = stack.pop()
            for t in self.eps.get(s, ()):
                if t not in seen:
                    seen.add(t)
                    stack.append(t)
        return seen


@dataclass
class DFA:  # Ishitwo -> Amrita
    n_states: int
    start: int
    trans: list[dict[int, int]]  # state -> {symbol: next_state}
    accept: dict[int, str]  # state -> token type / anomaly tag
    dead: int = -1  # explicit dead (trap) state, -1 if none

    def step(self, state: int, sym: int) -> int:
        return self.trans[state].get(sym, self.dead)

    def accepts(self, text: str) -> bool:
        s = self.start
        for ch in text:
            s = self.step(s, symbol_of(ch))
            if s < 0 or s == self.dead:
                return False
        return s in self.accept


@dataclass
class Token:
    type: str
    value: str
    start: int
    end: int


@dataclass
class Flag:
    code: str
    start: int
    end: int
    evidence: str
    severity: int
    source: str = "dfa"  # "dfa" (anomaly state) or "attr" (post-lexing attribute check)


@dataclass
class Lexeme:
    """A raw maximal-munch match produced by one lexer mode's minimal DFA."""

    type: str
    value: str
    start: int
    end: int
    mode: str


@dataclass
class ScanResult:  # Amrita + Prakhar -> Ishitwo
    tokens: list[Token]
    flags: list[Flag]
    trace: list[int]  # global min-DFA state visited after each character (-1 = dead / error)
    symtab: dict
    lexemes: list[Lexeme] = field(default_factory=list)
    steps: list[dict] = field(default_factory=list)  # per-character detail for the Live Trace UI
    host: str = ""
    registered_domain: str = ""
    stats: dict = field(default_factory=dict)  # transitions, backtracked chars, errors

    def to_dict(self) -> dict:
        return asdict(self)
