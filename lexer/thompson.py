"""Thompson's construction: syntax tree -> epsilon-NFA.

Author: Prakhar Tandon (24BCI0222)

Every operator becomes a fragment with exactly one entry and one exit state
(Thompson, CACM 1968):

    literal / class   s --[C]--> f            (a character class is ONE transition on a set)
    concatenation     frag(a).exit --ε--> frag(b).entry
    alternation       s --ε--> a, s --ε--> b, a.exit --ε--> f, b.exit --ε--> f
    Kleene star       s --ε--> a, s --ε--> f, a.exit --ε--> a.entry, a.exit --ε--> f

Derived operators are rewritten into the three primitives, which is why ``+``
is *not* a basic operator:

    a+      ->  a a*
    a?      ->  a | ε
    a{m,n}  ->  a^m (a?)^(n-m)        a{m,} -> a^m a*

Each token rule gets its own NFA. ``combine`` joins several rule NFAs under a
fresh start state with ε-edges, and tags each accept state with
(token_type, priority) so that subset construction can resolve conflicts.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from core.types import NFA
from lexer.regex_parser import Alt, Cat, Eps, Lit, Node, Opt, Plus, Rep, Star, parse


@dataclass
class Fragment:
    entry: int
    exit: int


class NFABuilder:
    def __init__(self) -> None:
        self.n = 0
        self.trans: dict[tuple[int, frozenset], set[int]] = defaultdict(set)
        self.eps: dict[int, set[int]] = defaultdict(set)

    def new_state(self) -> int:
        self.n += 1
        return self.n - 1

    def edge(self, a: int, chars: frozenset, b: int) -> None:
        self.trans[(a, chars)].add(b)

    def eps_edge(self, a: int, b: int) -> None:
        self.eps[a].add(b)

    # -- the construction ----------------------------------------------------
    def build(self, node: Node) -> Fragment:
        if isinstance(node, Lit):
            s, f = self.new_state(), self.new_state()
            self.edge(s, node.chars, f)
            return Fragment(s, f)
        if isinstance(node, Eps):
            s, f = self.new_state(), self.new_state()
            self.eps_edge(s, f)
            return Fragment(s, f)
        if isinstance(node, Cat):
            a = self.build(node.left)
            b = self.build(node.right)
            self.eps_edge(a.exit, b.entry)
            return Fragment(a.entry, b.exit)
        if isinstance(node, Alt):
            s = self.new_state()
            a = self.build(node.left)
            b = self.build(node.right)
            f = self.new_state()
            self.eps_edge(s, a.entry)
            self.eps_edge(s, b.entry)
            self.eps_edge(a.exit, f)
            self.eps_edge(b.exit, f)
            return Fragment(s, f)
        if isinstance(node, Star):
            s = self.new_state()
            a = self.build(node.child)
            f = self.new_state()
            self.eps_edge(s, a.entry)
            self.eps_edge(s, f)
            self.eps_edge(a.exit, a.entry)
            self.eps_edge(a.exit, f)
            return Fragment(s, f)
        if isinstance(node, Plus):  # a+ == a a*
            return self.build(Cat(node.child, Star(node.child)))
        if isinstance(node, Opt):  # a? == a | eps
            return self.build(Alt(node.child, Eps()))
        if isinstance(node, Rep):
            return self.build(expand_rep(node))
        raise TypeError(f"unknown node {node!r}")

    def to_nfa(self, frag: Fragment, accept_tag: tuple[str, int]) -> NFA:
        return NFA(
            n_states=self.n,
            start=frag.entry,
            trans={k: set(v) for k, v in self.trans.items()},
            eps={k: set(v) for k, v in self.eps.items()},
            accept={frag.exit: accept_tag},
        )


def expand_rep(node: Rep) -> Node:
    parts: list[Node] = [node.child] * node.lo
    if node.hi < 0:
        parts.append(Star(node.child))
    else:
        parts.extend([Opt(node.child)] * (node.hi - node.lo))
    if not parts:
        return Eps()
    out = parts[0]
    for p in parts[1:]:
        out = Cat(out, p)
    return out


def thompson(node: Node, token_type: str = "ACCEPT", priority: int = 0) -> NFA:
    b = NFABuilder()
    frag = b.build(node)
    return b.to_nfa(frag, (token_type, priority))


def nfa_for_pattern(pattern: str, defs: dict[str, str] | None = None,
                    token_type: str = "ACCEPT", priority: int = 0) -> NFA:
    return thompson(parse(pattern, defs), token_type, priority)


def combine(nfas: list[NFA]) -> NFA:
    """Union of rule NFAs under a new start state (lex-style combined automaton)."""
    trans: dict[tuple[int, frozenset], set[int]] = defaultdict(set)
    eps: dict[int, set[int]] = defaultdict(set)
    accept: dict[int, tuple[str, int]] = {}
    start = 0
    offset = 1
    for nfa in nfas:
        for (s, cs), dsts in nfa.trans.items():
            trans[(s + offset, cs)] |= {d + offset for d in dsts}
        for s, dsts in nfa.eps.items():
            eps[s + offset] |= {d + offset for d in dsts}
        for s, tag in nfa.accept.items():
            accept[s + offset] = tag
        eps[start].add(nfa.start + offset)
        offset += nfa.n_states
    return NFA(n_states=offset, start=start, trans=dict(trans), eps=dict(eps), accept=accept)


def nfa_stats(nfa: NFA) -> dict:
    n_trans = sum(len(v) for v in nfa.trans.values())
    n_eps = sum(len(v) for v in nfa.eps.values())
    return {"states": nfa.n_states, "transitions": n_trans, "epsilon": n_eps}
