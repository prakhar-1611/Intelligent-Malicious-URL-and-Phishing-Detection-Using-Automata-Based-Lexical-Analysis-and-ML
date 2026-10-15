"""Export automata as graph JSON (for Cytoscape.js in the Automata Lab) and DOT.

Author: Amrita Bhatia (24BCI0215)

Run:  python -m lexer.export            -> artifacts/dot/<rule>_{nfa,dfa,min}.dot
"""
from __future__ import annotations

from collections import defaultdict
from functools import lru_cache
from pathlib import Path

from core.types import DFA, NFA
from lexer.regex_parser import ast_to_dict, charset_label, postfix_string
from lexer.rules import DEFS, EXAMPLE_PATTERNS, MODES, RULES_BY_NAME

ROOT = Path(__file__).resolve().parent.parent


def nfa_graph(nfa: NFA) -> dict:
    nodes = [{"id": f"n{q}", "label": f"q{q}", "start": q == nfa.start,
              "accept": q in nfa.accept, "tag": nfa.accept.get(q, (None,))[0]} for q in range(nfa.n_states)]
    edges = []
    for (s, cs), dsts in nfa.trans.items():
        for d in dsts:
            edges.append({"source": f"n{s}", "target": f"n{d}", "label": charset_label(cs)})
    for s, dsts in nfa.eps.items():
        for d in dsts:
            edges.append({"source": f"n{s}", "target": f"n{d}", "label": "ε", "eps": True})
    return {"nodes": nodes, "edges": edges}


def dfa_graph(dfa: DFA, prefix: str = "D", show_dead: bool = False, state_sets=None,
              anomaly_tags: set[str] | None = None) -> dict:
    anomaly_tags = anomaly_tags or set()
    nodes = []
    for q in range(dfa.n_states):
        if q == dfa.dead and not show_dead:
            continue
        tag = dfa.accept.get(q)
        node = {"id": f"s{q}", "label": f"{prefix}{q}", "start": q == dfa.start, "accept": tag is not None,
                "tag": tag, "dead": q == dfa.dead, "anomaly": tag in anomaly_tags}
        if state_sets is not None:
            node["nfa_states"] = state_sets[q]
        nodes.append(node)
    grouped: dict[tuple[int, int], set[int]] = defaultdict(set)
    for q in range(dfa.n_states):
        if q == dfa.dead and not show_dead:
            continue
        for sym, d in dfa.trans[q].items():
            if d == dfa.dead and not show_dead:
                continue
            grouped[(q, d)].add(sym)
    edges = [{"source": f"s{a}", "target": f"s{b}", "label": charset_label(frozenset(syms))}
             for (a, b), syms in grouped.items()]
    return {"nodes": nodes, "edges": edges}


def to_dot(graph: dict, name: str = "A") -> str:
    lines = [f'digraph "{name}" {{', "  rankdir=LR;", '  node [shape=circle, fontname="Helvetica"];',
             '  __start [shape=point];']
    for n in graph["nodes"]:
        shape = "doublecircle" if n["accept"] else "circle"
        color = ', color="red"' if n.get("anomaly") else ""
        lines.append(f'  {n["id"]} [label="{n["label"]}", shape={shape}{color}];')
        if n["start"]:
            lines.append(f"  __start -> {n['id']};")
    for e in graph["edges"]:
        lab = e["label"].replace("\\", "\\\\").replace('"', '\\"')
        style = ", style=dashed" if e.get("eps") else ""
        lines.append(f'  {e["source"]} -> {e["target"]} [label="{lab}"{style}];')
    lines.append("}")
    return "\n".join(lines)


def list_automata() -> dict:
    return {"rules": sorted(RULES_BY_NAME), "examples": sorted(EXAMPLE_PATTERNS),
            "modes": [f"mode:{m}" for m in MODES]}


@lru_cache(maxsize=64)
def _built(name: str):
    from lexer.build_automata import mode_pipeline, pipeline, rule_pipeline

    if name.startswith("mode:"):
        return "mode", mode_pipeline(name[5:])
    if name in RULES_BY_NAME:
        return "rule", rule_pipeline(RULES_BY_NAME[name])
    if name in EXAMPLE_PATTERNS:
        return "example", pipeline(EXAMPLE_PATTERNS[name], name, defs={})
    raise KeyError(name)


def automaton_view(name: str, stage: str) -> dict:
    """Graph + metadata for one automaton at one stage: regex | nfa | dfa | min."""
    from lexer.rules import DFA_FLAGS, RULES

    kind, built = _built(name)
    anomaly_tags = {r.name for r in RULES if r.flag in DFA_FLAGS}
    out: dict = {"name": name, "kind": kind, "stage": stage, "stats": built["stats"]}
    if kind != "mode":
        pattern = RULES_BY_NAME[name].pattern if kind == "rule" else EXAMPLE_PATTERNS[name]
        defs = DEFS if kind == "rule" else {}
        out["pattern"] = pattern
        out["postfix"] = postfix_string(pattern, defs)
        out["ast"] = ast_to_dict(built["ast"])
    else:
        out["rules"] = [{"name": r.name, "pattern": r.pattern, "priority": r.priority, "flag": r.flag}
                        for r in built["rules"]]
    if stage == "nfa":
        out["graph"] = nfa_graph(built["nfa"])
    elif stage == "dfa":
        out["graph"] = dfa_graph(built["dfa"], "D", state_sets=built["info"].state_sets, anomaly_tags=anomaly_tags)
    elif stage in ("min", "regex"):
        out["graph"] = dfa_graph(built["min"], "M", anomaly_tags=anomaly_tags)
    else:
        raise ValueError("stage must be regex, nfa, dfa or min")
    return out


def custom_pattern_view(pattern: str, stage: str) -> dict:
    """Automaton for a user-typed pattern (Automata Lab). Guarded against blow-up."""
    from lexer.build_automata import pipeline

    if len(pattern) > 120:
        raise ValueError("pattern too long (max 120 characters)")
    built = pipeline(pattern, "ACCEPT", defs=DEFS, max_states=400)
    out = {"name": "custom", "kind": "custom", "stage": stage, "pattern": pattern,
           "postfix": postfix_string(pattern, DEFS), "ast": ast_to_dict(built["ast"]), "stats": built["stats"]}
    if built["nfa"].n_states > 600:
        raise ValueError("NFA too large to display")
    out["graph"] = {"nfa": nfa_graph(built["nfa"]),
                    "dfa": dfa_graph(built["dfa"], "D", state_sets=built["info"].state_sets),
                    "min": dfa_graph(built["min"], "M")}.get(stage, dfa_graph(built["min"], "M"))
    return out


def main() -> None:
    out_dir = ROOT / "artifacts" / "dot"
    out_dir.mkdir(parents=True, exist_ok=True)
    names = list(EXAMPLE_PATTERNS) + sorted(RULES_BY_NAME) + [f"mode:{m}" for m in MODES]
    for name in names:
        for stage in ("nfa", "dfa", "min"):
            view = automaton_view(name, stage)
            fname = name.replace(":", "_") + f"_{stage}.dot"
            (out_dir / fname).write_text(to_dot(view["graph"], f"{name} {stage}"), encoding="utf-8")
    print(f"wrote {len(names) * 3} DOT files to {out_dir}")
    print("render with:  dot -Tpng artifacts/dot/XN_PREFIX_nfa.dot -o xn_nfa.png")


if __name__ == "__main__":
    main()
