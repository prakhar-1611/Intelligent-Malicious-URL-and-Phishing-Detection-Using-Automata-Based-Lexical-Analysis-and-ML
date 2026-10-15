"""Alphabet compression (equivalence classes of input symbols), as flex does.

Author: Amrita Bhatia (24BCI0215)

Two symbols are equivalent when their columns in the transition table are
identical: no state can tell them apart. Every class is then represented by
one column, so the table shrinks from |Sigma| = 129 columns to k columns and the
k in Hopcroft's O(k * n log n) becomes a concrete, much smaller number.
"""
from __future__ import annotations

from core.types import ALPHABET_SIZE, DFA


def symbol_classes(dfas: list[DFA], alphabet_size: int = ALPHABET_SIZE) -> list[int]:
    """Return class_of[symbol] valid for *all* given DFAs simultaneously."""
    col_ids: dict[tuple, int] = {}
    class_of = [0] * alphabet_size
    for sym in range(alphabet_size):
        col = tuple(tuple(d.trans[q][sym] for q in range(d.n_states)) for d in dfas)
        class_of[sym] = col_ids.setdefault(col, len(col_ids))
    return class_of


def representatives(class_of: list[int]) -> list[int]:
    reps: dict[int, int] = {}
    for sym, c in enumerate(class_of):
        reps.setdefault(c, sym)
    return [reps[c] for c in sorted(reps)]


def compress(dfa: DFA, class_of: list[int]) -> list[list[int]]:
    """Dense transition table indexed [state][class]."""
    k = max(class_of) + 1
    reps = representatives(class_of)
    return [[dfa.trans[q][reps[c]] for c in range(k)] for q in range(dfa.n_states)]


def describe_classes(class_of: list[int]) -> list[str]:
    from lexer.regex_parser import charset_label

    groups: dict[int, set[int]] = {}
    for sym, c in enumerate(class_of):
        groups.setdefault(c, set()).add(sym)
    return [charset_label(frozenset(groups[c])) for c in sorted(groups)]
