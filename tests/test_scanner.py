"""Scanner, minimisation and alphabet-compression tests.

Owner: Amrita Bhatia (24BCI0215)
"""
import time

import pytest

from core.types import ALPHABET_SIZE
from lexer.alphabet import compress, representatives, symbol_classes
from lexer.build_automata import mode_pipeline, pipeline
from lexer.hopcroft import hopcroft_minimize, initial_partition
from lexer.moore import isomorphic, moore_minimize
from lexer.rules import MODES
from lexer.scanner import get_scanner, scan


def test_review1_figure_3_2c():
    """LABEL over {a,-}: subset construction gives 5 states, Hopcroft merges D1 and D3 -> 4."""
    b = pipeline("a(a|\\-)*a|a", defs={})
    assert b["dfa"].n_states == 5
    assert b["min"].n_states == 4
    assert b["moore"].n_states == 4


def test_strict_thompson_xn_prefix():
    """Strict Thompson construction for xn-- has 8 states (4 literal fragments x 2 states)."""
    b = pipeline("xn\\-\\-", defs={})
    assert b["nfa"].n_states == 8
    assert b["min"].n_states == 6  # 5 live states + dead state


def test_initial_partition_split_by_token_type():
    """States accepting different token types must start in different blocks."""
    mp = mode_pipeline("AUTHORITY")
    d = mp["dfa"]
    for block in initial_partition(d):
        assert len({d.accept.get(q) for q in block}) == 1


def test_minimisation_preserves_token_types():
    mp = mode_pipeline("AUTHORITY")
    assert set(mp["dfa"].accept.values()) == set(mp["min"].accept.values())


@pytest.mark.parametrize("mode", MODES)
def test_alphabet_compression_is_lossless(mode):
    d = mode_pipeline(mode)["min"]
    class_of = symbol_classes([d])
    table = compress(d, class_of)
    for q in range(d.n_states):
        for sym in range(ALPHABET_SIZE):
            assert table[q][class_of[sym]] == d.trans[q][sym]
    assert len(representatives(class_of)) < ALPHABET_SIZE


@pytest.mark.parametrize("mode", MODES)
def test_hopcroft_over_classes_equals_full_alphabet(mode):
    dfa = mode_pipeline(mode)["dfa"]
    reps = representatives(symbol_classes([dfa]))
    assert isomorphic(hopcroft_minimize(dfa, reps), hopcroft_minimize(dfa), ALPHABET_SIZE)
    assert isomorphic(moore_minimize(dfa, reps), hopcroft_minimize(dfa), ALPHABET_SIZE)


def test_maximal_munch_prefers_longest():
    lx = scan("http://a.com/%2541").lexemes
    assert [x.type for x in lx if x.mode == "PATH"] == ["DOUBLE_ENC"]  # not PCT_ENC "%25" + "41"


def test_priority_breaks_ties():
    lx = scan("http://xn--abc.com").lexemes
    assert lx[1].type == "PUNY_LABEL"  # HOST_LABEL matches the same length, lower priority


def test_mode_switching():
    modes = [(x.mode, x.type) for x in scan("https://a.b/c?d=e#f").lexemes]
    assert modes[0] == ("START", "SCHEME")
    assert ("AUTHORITY", "SLASH") in modes and ("PATH", "QMARK") in modes and ("QUERY", "HASH") in modes
    assert modes[-1] == ("FRAGMENT", "FTEXT")


def test_start_mode_fallthrough_without_scheme():
    r = scan("example.com/x")
    assert r.lexemes[0].mode == "AUTHORITY"


def test_panic_mode_recovery_keeps_text():
    r = scan("http://a.com/x y\\z")
    errors = [t for t in r.tokens if t.type == "ERROR"]
    assert [e.value for e in errors] == [" ", "\\"]
    assert "".join(x.value for x in r.lexemes) == "http://a.com/x y\\z"  # nothing deleted


def test_trace_covers_every_character():
    for url in ["https://www.example.com/a?b=c#d", "http://a b.com/", "x", "http://[::1]:80/"]:
        r = scan(url)
        assert len(r.trace) == len(url)
        assert len(r.steps) == len(url)


def test_trace_states_are_valid_global_ids():
    sc = get_scanner()
    r = scan("https://login.paypal.com.evil.example:8443/%252e?next=http://x#y")
    assert all(-1 <= g < sc.total_states for g in r.trace)


def test_symbol_table_contents():
    r = scan("https://login.example.com/a/b?id=1&id=2")
    syms = {(s["lexeme"], s["kind"]): s for s in r.symtab["symbols"]}
    assert ("login", "label") in syms and ("example", "label") in syms
    assert syms[("id", "param")]["freq"] == 2
    assert ("a", "path_seg") in syms


def test_linear_time_on_long_input():
    sc = get_scanner()
    t = {}
    for n in (10_000, 100_000):
        s = "https://example.com/" + "a" * n
        t0 = time.perf_counter()
        sc.lex(s)
        t[n] = time.perf_counter() - t0
    assert t[100_000] < 25 * t[10_000] + 0.05  # ~10x for 10x input, generous slack for CI noise
