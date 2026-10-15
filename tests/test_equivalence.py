"""Automata equivalence: the promise of Review 1 section 3.5, tested on every rule.

Owner: Ishitwo Khanra (24BCE2975). Failures are routed to the owner of the stage:
NFA -> Prakhar, subset DFA -> Ishitwo, minimal DFA / Moore -> Amrita.

For every rule R and many generated strings w:

    NFA.accepts(w) == DFA.accepts(w) == MinDFA.accepts(w) == Moore.accepts(w) == re.fullmatch(R, w)

Python's ``re`` appears here ONLY as an independent oracle.
"""
import re

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from lexer.build_automata import mode_pipeline, pipeline
from lexer.moore import isomorphic
from lexer.regex_parser import to_python_regex
from lexer.rules import DEFS, EXAMPLE_PATTERNS, MODES, RULES, rules_for_mode

CASES = [(r.name, r.pattern, DEFS) for r in RULES] + [(k, v, {}) for k, v in EXAMPLE_PATTERNS.items()]
BUILT = {name: pipeline(pat, name, defs=defs) for name, pat, defs in CASES}
PYRE = {name: re.compile(to_python_regex(BUILT[name]["ast"]), re.DOTALL) for name, _, _ in CASES}

URLISH = st.text(alphabet=st.sampled_from(list("aAxn-._~:/?#[]@!$&'()*+,;=%25fF09 \x00\x7féа")), max_size=24)
SETTINGS = settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])


def _check(name: str, w: str) -> None:
    b = BUILT[name]
    expected = PYRE[name].fullmatch(w) is not None
    got = {"nfa": b["nfa"].accepts(w), "dfa": b["dfa"].accepts(w), "min": b["min"].accepts(w),
           "moore": b["moore"].accepts(w)}
    assert all(v == expected for v in got.values()), f"{name}: {w!r} re={expected} {got}"


@pytest.mark.parametrize("name", [c[0] for c in CASES])
@SETTINGS
@given(data=st.data())
def test_generated_members(name, data):
    """Strings generated FROM the regex must be accepted by every automaton."""
    w = data.draw(st.from_regex(PYRE[name], fullmatch=True))
    _check(name, w)


@pytest.mark.parametrize("name", [c[0] for c in CASES])
@SETTINGS
@given(w=URLISH)
def test_random_strings(name, w):
    """Random URL-ish strings: all automata must agree with the oracle (mostly rejections)."""
    _check(name, w)


@pytest.mark.parametrize("name", [c[0] for c in CASES])
def test_hopcroft_equals_moore(name):
    b = BUILT[name]
    assert b["min"].n_states == b["moore"].n_states
    assert isomorphic(b["min"], b["moore"], 129)


def test_minimal_never_larger_than_dfa():
    for name, b in BUILT.items():
        assert b["min"].n_states <= b["dfa"].n_states, name


# ---------------------------------------------------------------- whole modes
MODE_BUILT = {m: mode_pipeline(m) for m in MODES}
MODE_RE = {m: [(r.name, r.priority, re.compile(to_python_regex(pipeline(r.pattern, r.name)["ast"]), re.DOTALL))
               for r in rules_for_mode(m)] for m in MODES}


def _oracle_longest(mode: str, text: str):
    """Brute force: longest prefix matched by any rule; ties -> highest priority."""
    for n in range(len(text), 0, -1):
        hits = [(p, name) for name, p, rx in MODE_RE[mode] if rx.fullmatch(text[:n])]
        if hits:
            return n, max(hits)[1]
    return 0, None


def _dfa_longest(mode: str, text: str):
    d = MODE_BUILT[mode]["min"]
    s, best = d.start, (0, None)
    for i, ch in enumerate(text):
        cp = ord(ch)
        s = d.trans[s][cp if cp < 128 else 128]
        if s == d.dead:
            break
        if s in d.accept:
            best = (i + 1, d.accept[s])
    return best


@pytest.mark.parametrize("mode", MODES)
@SETTINGS
@given(w=URLISH)
def test_mode_longest_match_and_priority(mode, w):
    assert _dfa_longest(mode, w) == _oracle_longest(mode, w)


@pytest.mark.parametrize("mode", MODES)
def test_mode_hopcroft_equals_moore(mode):
    b = MODE_BUILT[mode]
    assert isomorphic(b["min"], b["moore"], 129)
