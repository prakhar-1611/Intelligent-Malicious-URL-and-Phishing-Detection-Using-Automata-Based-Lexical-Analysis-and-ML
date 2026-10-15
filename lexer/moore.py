"""Moore's DFA minimisation, used as an independent cross-check of Hopcroft.

Author: Amrita Bhatia (24BCI0215)

Moore refines the partition in rounds: two states stay together only if they
are in the same block now AND every symbol sends them to the same block. The
loop stops when a round creates no new block. Worst case O(k * n^2), versus
Hopcroft's O(k * n log n), but it is short and obviously correct, which makes
it a good oracle: both algorithms must yield the same number of states (and,
up to renumbering, the same automaton) for every rule.
"""
from __future__ import annotations

from core.types import DFA
from lexer.hopcroft import build_quotient, initial_partition


def moore_partition(dfa: DFA, symbols: list[int]) -> tuple[list[set[int]], int]:
    block_of = [0] * dfa.n_states
    for i, b in enumerate(initial_partition(dfa)):
        for q in b:
            block_of[q] = i
    n_blocks = len(set(block_of))
    rounds = 0
    while True:
        rounds += 1
        sig_ids: dict[tuple, int] = {}
        new_block_of = [0] * dfa.n_states
        for q in range(dfa.n_states):
            sig = (block_of[q],) + tuple(block_of[dfa.trans[q][c]] for c in symbols)
            new_block_of[q] = sig_ids.setdefault(sig, len(sig_ids))
        if len(sig_ids) == n_blocks:
            break
        block_of, n_blocks = new_block_of, len(sig_ids)
    blocks: dict[int, set[int]] = {}
    for q, b in enumerate(block_of):
        blocks.setdefault(b, set()).add(q)
    return list(blocks.values()), rounds


def moore_minimize(dfa: DFA, symbols: list[int] | None = None) -> DFA:
    syms = symbols if symbols is not None else sorted(dfa.trans[0].keys())
    blocks, _ = moore_partition(dfa, syms)
    return build_quotient(dfa, blocks)[0]


def isomorphic(a: DFA, b: DFA, n_syms: int) -> bool:
    """True if two complete DFAs are identical up to state renaming."""
    if a.n_states != b.n_states:
        return False
    m = {a.start: b.start}
    stack = [a.start]
    while stack:
        p = stack.pop()
        q = m[p]
        if a.accept.get(p) != b.accept.get(q):
            return False
        for c in range(n_syms):
            p2, q2 = a.trans[p][c], b.trans[q][c]
            if p2 in m:
                if m[p2] != q2:
                    return False
            else:
                m[p2] = q2
                stack.append(p2)
    return True
