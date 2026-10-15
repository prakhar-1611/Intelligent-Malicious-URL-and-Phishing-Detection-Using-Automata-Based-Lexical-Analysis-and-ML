"""Hopcroft DFA minimisation (partition refinement with a worklist of splitters).

Author: Amrita Bhatia (24BCI0215)

Initial partition
    States are grouped by their *accept tag* (token type or anomaly tag), not
    just accepting vs non-accepting. A lexer DFA must never merge a state that
    accepts PCT_ENC with one that accepts LABEL, even though both "accept":
    the scanner would then emit the wrong token type.

Refinement (Hopcroft 1971, O(k * n log n))
    W <- all initial blocks except the largest
    while W not empty:
        A <- pop(W)
        for each symbol c:
            X <- { q : delta(q, c) in A }            (via inverse transitions)
            for each block Y split by X into Y∩X and Y\\X (both non-empty):
                replace Y by the two halves; push the smaller half onto W
                (if Y itself was waiting in W, both halves end up in W)

The input DFA must be complete (subset.py adds the explicit dead state).
"""
from __future__ import annotations

from collections import defaultdict

from core.types import DFA


def initial_partition(dfa: DFA) -> list[set[int]]:
    groups: dict[str | None, set[int]] = defaultdict(set)
    for q in range(dfa.n_states):
        groups[dfa.accept.get(q)].add(q)
    # deterministic order: non-accepting first, then by tag name
    keys = sorted(groups, key=lambda k: (k is not None, k or ""))
    return [groups[k] for k in keys]


def hopcroft_partition(dfa: DFA, symbols: list[int]) -> list[set[int]]:
    inv: dict[int, dict[int, list[int]]] = {c: defaultdict(list) for c in symbols}
    for q in range(dfa.n_states):
        row = dfa.trans[q]
        for c in symbols:
            inv[c][row[c]].append(q)

    blocks: list[set[int]] = [b for b in initial_partition(dfa) if b]
    block_of = [0] * dfa.n_states
    for i, b in enumerate(blocks):
        for q in b:
            block_of[q] = i

    largest = max(range(len(blocks)), key=lambda i: len(blocks[i]))
    waiting: set[int] = {i for i in range(len(blocks)) if i != largest}
    worklist = sorted(waiting)

    while worklist:
        a = worklist.pop()
        waiting.discard(a)
        splitter = list(blocks[a])
        for c in symbols:
            x: set[int] = set()
            inv_c = inv[c]
            for q in splitter:
                x.update(inv_c.get(q, ()))
            if not x:
                continue
            touched: dict[int, set[int]] = defaultdict(set)
            for q in x:
                touched[block_of[q]].add(q)
            for b, inter in touched.items():
                y = blocks[b]
                if len(inter) == len(y):
                    continue  # not split
                rest = y - inter
                small, big = (inter, rest) if len(inter) <= len(rest) else (rest, inter)
                blocks[b] = big
                new_id = len(blocks)
                blocks.append(small)
                for q in small:
                    block_of[q] = new_id
                # whether or not b was waiting, adding the smaller half is enough:
                # if b was waiting it still is (now = big half), plus the new half.
                waiting.add(new_id)
                worklist.append(new_id)
        # blocks[a] may have been split while we iterated over the snapshot; that is
        # fine: refining by the old A and by one half implies refining by the other.
    return blocks


def build_quotient(dfa: DFA, blocks: list[set[int]], symbols_all: int | None = None) -> tuple[DFA, list[int]]:
    """Construct the quotient DFA; states renumbered in BFS order from the start."""
    block_of = [0] * dfa.n_states
    for i, b in enumerate(blocks):
        for q in b:
            block_of[q] = i
    n_syms = len(dfa.trans[0]) if symbols_all is None else symbols_all

    order: dict[int, int] = {}
    queue = [block_of[dfa.start]]
    order[queue[0]] = 0
    head = 0
    while head < len(queue):
        b = queue[head]
        head += 1
        rep = next(iter(blocks[b]))
        for c in range(n_syms):
            nb = block_of[dfa.trans[rep][c]]
            if nb not in order:
                order[nb] = len(order)
                queue.append(nb)

    trans: list[dict[int, int]] = [dict() for _ in order]
    accept: dict[int, str] = {}
    for b, new in order.items():
        rep = next(iter(blocks[b]))
        trans[new] = {c: order[block_of[dfa.trans[rep][c]]] for c in range(n_syms)}
        if rep in dfa.accept:
            accept[new] = dfa.accept[rep]
    dead = order.get(block_of[dfa.dead], -1) if dfa.dead >= 0 else -1
    if dead < 0:
        # a non-accepting state that only loops to itself is a dead state too
        for q in range(len(trans)):
            if q not in accept and all(t == q for t in trans[q].values()):
                dead = q
                break
    mapping = [order.get(block_of[q], -1) for q in range(dfa.n_states)]
    return DFA(n_states=len(order), start=0, trans=trans, accept=accept, dead=dead), mapping


def hopcroft_minimize(dfa: DFA, symbols: list[int] | None = None) -> DFA:
    """Minimise a complete DFA. ``symbols`` may be one representative per
    alphabet equivalence class (see alphabet.py) to make k small."""
    syms = symbols if symbols is not None else sorted(dfa.trans[0].keys())
    blocks = hopcroft_partition(dfa, syms)
    return build_quotient(dfa, blocks)[0]
