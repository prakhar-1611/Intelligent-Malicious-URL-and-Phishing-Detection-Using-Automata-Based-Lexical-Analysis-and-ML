"""Regex front end: tokenizer, shunting-yard, syntax errors, Thompson construction.

Owner: Prakhar Tandon (24BCI0222)
"""
import pytest

from lexer.regex_parser import Alt, Cat, Lit, Plus, RegexSyntaxError, Star, parse, postfix_string
from lexer.rules import DEFS
from lexer.thompson import nfa_for_pattern


def test_explicit_concatenation_and_precedence():
    assert postfix_string("ab|c") == "a b · c |"
    assert postfix_string("a(b|c)*") == "a b c | * ·"


def test_tree_shapes():
    assert isinstance(parse("ab"), Cat)
    assert isinstance(parse("a|b"), Alt)
    assert isinstance(parse("a*"), Star)
    assert isinstance(parse("a+"), Plus)


def test_character_classes():
    node = parse("[a-c_]")
    assert isinstance(node, Lit) and node.chars == frozenset(map(ord, "abc_"))
    neg = parse("[^a]")
    assert ord("a") not in neg.chars and ord("b") in neg.chars and 128 in neg.chars


def test_named_definitions_expand():
    nfa = nfa_for_pattern("{LABEL}", DEFS)
    assert nfa.accepts("login-secure") and not nfa.accepts("-bad")


def test_counted_repetition():
    nfa = nfa_for_pattern("a{2,3}", {})
    assert [nfa.accepts("a" * k) for k in range(5)] == [False, False, True, True, False]


@pytest.mark.parametrize("pattern,col", [("(ab", 0), ("ab)", 2), ("*a", 0), ("[abc", 0), ("a{x}", 1), ("a|*", 2)])
def test_syntax_errors_report_position(pattern, col):
    with pytest.raises(RegexSyntaxError) as e:
        parse(pattern, {})
    assert e.value.pos == col


def test_plus_is_rewritten_not_primitive():
    """a+ becomes a a*: the NFA has two copies of the 'a' fragment."""
    nfa = nfa_for_pattern("a+", {})
    labelled = [k for k in nfa.trans if k[1] == frozenset({ord("a")})]
    assert len(labelled) == 2


def test_empty_alternative_is_epsilon():
    nfa = nfa_for_pattern("a(b|)", {})
    assert nfa.accepts("a") and nfa.accepts("ab")
