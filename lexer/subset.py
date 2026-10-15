"""Subset construction: epsilon-NFA -> complete DFA.

Author: Ishitwo Khanra (24BCE2975)

* NFA state sets are canonicalised as Python ``int`` bitmasks (bit i = NFA state i),
  so equal sets are equal keys in the state table with no sorting.
* epsilon-closure uses an explicit stack (no recursion) and is memoised per state.
* A worklist drives the search: each newly discovered set becomes a DFA state.
* The dead (trap) state is explicit: the empty set gets its own DFA state with
  self-loops on every symbol, so the DFA is *complete*, as Hopcroft requires.
* Priority resolution: when one DFA state contains accept states of several
  rules, the rule with the highest priority wins. This is how lex decides
  "keyword vs identifier"; every resolved conflict is recorded for the report.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from core.types import ALPHABET_SIZE, DFA, NFA


def _bits(mask: int):
    while mask:
        low = mask & -mask
        yield low.bit_length() - 1
        mask ^= low


@dataclass
class SubsetInfo:
    state_sets: list[list[int]] = field(default_factory=list)  # DFA state -> NFA states
    conflicts: list[dict] = field(default_factory=list)


class _Closure:
    def __init__(self, nfa: NFA):
        self.nfa = nfa
        self.cache: dict[int, int] = {}

    def of_state(self, s: int) -> int:
        hit = self.cache.get(s)
        if hit is not None:
            return hit
        mask = 1 << s
        stack = [s]
        while stack:
            u = stack.pop()
            for v in self.nfa.eps.get(u, ()):
                if not mask >> v & 1:
                    mask |= 1 << v
                    stack.append(v)
        self.cache[s] = mask
        return mask

    def of_mask(self, mask: int) -> int:
        out = 0
        for s in _bits(mask):
            out |= self.of_state(s)
        return out


class StateExplosion(RuntimeError):
    """Raised when subset construction exceeds ``max_states`` (exponential blow-up guard)."""


def subset_construct_with_info(nfa: NFA, alphabet_size: int = ALPHABET_SIZE,
                               max_states: int | None = None) -> tuple[DFA, SubsetInfo]:
    # outgoing labelled edges per NFA state: [(charset, target_mask)]
    out: dict[int, list[tuple[frozenset, int]]] = {}
    for (s, cs), dsts in nfa.trans.items():
        m = 0
        for d in dsts:
            m |= 1 << d
        out.setdefault(s, []).append((cs, m))

    closure = _Closure(nfa)
    start_mask = closure.of_state(nfa.start)

    ids: dict[int, int] = {start_mask: 0}
    masks: list[int] = [start_mask]
    trans: list[dict[int, int]] = [{}]
    worklist = [0]

    def get_id(mask: int) -> int:
        if mask not in ids:
            if max_states is not None and len(masks) >= max_states:
                raise StateExplosion(f"DFA exceeded {max_states} states")
            ids[mask] = len(masks)
            masks.append(mask)
            trans.append({})
            worklist.append(ids[mask])
        return ids[mask]

    while worklist:
        d = worklist.pop()
        mask = masks[d]
        move = [0] * alphabet_size
        for s in _bits(mask):
            for cs, tmask in out.get(s, ()):
                for sym in cs:
                    move[sym] |= tmask
        row = trans[d]
        # memoise closures of identical move sets within this row
        local: dict[int, int] = {}
        for sym in range(alphabet_size):
            m = move[sym]
            if m not in local:
                local[m] = get_id(closure.of_mask(m)) if m else get_id(0)
            row[sym] = local[m]

    dead = ids.get(0, -1)

    info = SubsetInfo()
    accept: dict[int, str] = {}
    for d, mask in enumerate(masks):
        info.state_sets.append(list(_bits(mask)))
        tags = [nfa.accept[s] for s in _bits(mask) if s in nfa.accept]
        if not tags:
            continue
        # highest priority wins; ties broken by token name for determinism
        best = max(tags, key=lambda t: (t[1], t[0]))
        accept[d] = best[0]
        distinct = sorted({t[0] for t in tags})
        if len(distinct) > 1:
            info.conflicts.append({"dfa_state": d, "candidates": distinct, "winner": best[0]})

    dfa = DFA(n_states=len(masks), start=0, trans=trans, accept=accept, dead=dead)
    return dfa, info


def subset_construct(nfa: NFA, alphabet_size: int = ALPHABET_SIZE, max_states: int | None = None) -> DFA:
    return subset_construct_with_info(nfa, alphabet_size, max_states)[0]


def reachable_live_states(dfa: DFA) -> int:
    """Number of states excluding the dead state (what textbooks usually count)."""
    return dfa.n_states - (1 if dfa.dead >= 0 else 0)
