"""Offline build: lexical specification -> minimal, alphabet-compressed DFA tables.

Author: Amrita Bhatia (24BCI0215)

Review 1 claimed "expensive construction offline, cheap deterministic scanning
at runtime". This script is that offline step:

    for each lexer mode:
        rule NFAs (Thompson)  -> combined NFA
        subset construction   -> DFA (priority-resolved, explicit dead state)
        alphabet compression  -> k equivalence classes
        Hopcroft (over k)     -> minimal DFA, cross-checked against Moore
        compress              -> dense table [state][class]

Outputs
    artifacts/lexer_tables.json   loaded by lexer/scanner.py at runtime
    artifacts/automata_stats.json per-rule and per-mode state counts (report table 5.1)

Run:  python -m lexer.build_automata
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from core.types import ALPHABET_SIZE
from lexer.alphabet import compress, describe_classes, representatives, symbol_classes
from lexer.hopcroft import hopcroft_minimize
from lexer.moore import isomorphic, moore_minimize, moore_partition
from lexer.regex_parser import parse
from lexer.rules import DEFS, EXAMPLE_PATTERNS, MODES, RULES, Rule, rules_for_mode
from lexer.subset import subset_construct_with_info
from lexer.thompson import combine, nfa_stats, thompson

ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS = ROOT / "artifacts"
TABLES_PATH = ARTIFACTS / "lexer_tables.json"
STATS_PATH = ARTIFACTS / "automata_stats.json"


def pipeline(pattern: str, name: str = "ACCEPT", priority: int = 0, defs: dict | None = None,
             max_states: int | None = None) -> dict:
    """Run one regex through every stage; return all intermediate automata + stats."""
    t0 = time.perf_counter()
    ast = parse(pattern, DEFS if defs is None else defs)
    nfa = thompson(ast, name, priority)
    t1 = time.perf_counter()
    dfa, info = subset_construct_with_info(nfa, max_states=max_states)
    t2 = time.perf_counter()
    class_of = symbol_classes([dfa])
    reps = representatives(class_of)
    mdfa = hopcroft_minimize(dfa, reps)
    t3 = time.perf_counter()
    moore_dfa = moore_minimize(dfa, reps)
    _, moore_rounds = moore_partition(dfa, reps)
    return {
        "ast": ast, "nfa": nfa, "dfa": dfa, "min": mdfa, "moore": moore_dfa, "info": info,
        "class_of": class_of,
        "stats": {
            "nfa": nfa_stats(nfa)["states"],
            "nfa_transitions": nfa_stats(nfa)["transitions"],
            "nfa_epsilon": nfa_stats(nfa)["epsilon"],
            "dfa": dfa.n_states,
            "min": mdfa.n_states,
            "moore": moore_dfa.n_states,
            "moore_rounds": moore_rounds,
            "hopcroft_eq_moore": isomorphic(mdfa, moore_dfa, ALPHABET_SIZE),
            "k_before": ALPHABET_SIZE,
            "k_after": len(reps),
            "ms_thompson": round((t1 - t0) * 1000, 3),
            "ms_subset": round((t2 - t1) * 1000, 3),
            "ms_hopcroft": round((t3 - t2) * 1000, 3),
        },
    }


def rule_pipeline(rule: Rule) -> dict:
    return pipeline(rule.pattern, rule.name, rule.priority)


def mode_pipeline(mode: str) -> dict:
    rules = rules_for_mode(mode)
    nfas = [thompson(parse(r.pattern, DEFS), r.name, r.priority) for r in rules]
    nfa = combine(nfas)
    t1 = time.perf_counter()
    dfa, info = subset_construct_with_info(nfa)
    t2 = time.perf_counter()
    class_of_dfa = symbol_classes([dfa])
    reps = representatives(class_of_dfa)
    mdfa = hopcroft_minimize(dfa, reps)
    t3 = time.perf_counter()
    moore_dfa = moore_minimize(dfa, reps)
    class_of = symbol_classes([mdfa])
    return {
        "rules": rules, "nfa": nfa, "dfa": dfa, "min": mdfa, "moore": moore_dfa, "info": info,
        "class_of": class_of,
        "stats": {
            "mode": mode,
            "rules": [r.name for r in rules],
            "nfa": nfa.n_states,
            "dfa": dfa.n_states,
            "min": mdfa.n_states,
            "moore": moore_dfa.n_states,
            "hopcroft_eq_moore": isomorphic(mdfa, moore_dfa, ALPHABET_SIZE),
            "conflicts_resolved": len(info.conflicts),
            "conflicts": info.conflicts[:20],
            "k_before": ALPHABET_SIZE,
            "k_after": max(class_of) + 1,
            "classes": describe_classes(class_of),
            "ms_subset": round((t2 - t1) * 1000, 3),
            "ms_hopcroft": round((t3 - t2) * 1000, 3),
        },
    }


def build_all() -> tuple[dict, dict]:
    tables: dict = {"version": 1, "alphabet_size": ALPHABET_SIZE, "mode_order": MODES, "modes": {}}
    stats: dict = {"rules": [], "modes": [], "examples": []}
    offset = 0
    for mode in MODES:
        mp = mode_pipeline(mode)
        mdfa = mp["min"]
        tables["modes"][mode] = {
            "start": mdfa.start,
            "dead": mdfa.dead,
            "offset": offset,
            "n_states": mdfa.n_states,
            "class_of": mp["class_of"],
            "table": compress(mdfa, mp["class_of"]),
            "accept": {str(q): t for q, t in mdfa.accept.items()},
        }
        offset += mdfa.n_states
        stats["modes"].append(mp["stats"])
    tables["total_states"] = offset
    for rule in RULES:
        rp = rule_pipeline(rule)
        stats["rules"].append({"rule": rule.name, "flag": rule.flag, "priority": rule.priority,
                               "modes": list(rule.modes), **rp["stats"]})
    for name, pat in EXAMPLE_PATTERNS.items():
        ep = pipeline(pat, name, defs={})
        stats["examples"].append({"rule": name, "pattern": pat, **ep["stats"]})
    return tables, stats


def main() -> None:
    ARTIFACTS.mkdir(exist_ok=True)
    t0 = time.perf_counter()
    tables, stats = build_all()
    TABLES_PATH.write_text(json.dumps(tables), encoding="utf-8")
    STATS_PATH.write_text(json.dumps(stats, indent=2), encoding="utf-8")
    print(f"built lexer tables in {time.perf_counter() - t0:.2f}s -> {TABLES_PATH}")
    print(f"{'mode':<10}{'NFA':>6}{'DFA':>6}{'min':>6}{'Moore':>7}{'k':>9}  H=M")
    for m in stats["modes"]:
        print(f"{m['mode']:<10}{m['nfa']:>6}{m['dfa']:>6}{m['min']:>6}{m['moore']:>7}"
              f"{m['k_before']:>5}->{m['k_after']:<3} {m['hopcroft_eq_moore']}")
    print(f"\n{'rule':<15}{'NFA':>6}{'DFA':>6}{'min':>6}{'Moore':>7}  H=M")
    for r in stats["rules"] + stats["examples"]:
        print(f"{r['rule']:<15}{r['nfa']:>6}{r['dfa']:>6}{r['min']:>6}{r['moore']:>7}  {r['hopcroft_eq_moore']}")


if __name__ == "__main__":
    main()
