"""ReDoS benchmark: Python's backtracking ``re`` versus the project's DFA scanner.

Author: Prakhar Tandon (24BCI0222)

A backtracking matcher can take exponential time on patterns with nested
quantifiers when the input almost matches. A DFA does exactly one table lookup
per character, so it cannot be "ReDoS'd": time is linear in input length no
matter what the input is.

Patterns
    nested      ^(a+)+$                     input "a"*n + "!"
    url_regex   a widely copied URL validator with a nested quantifier
                ^(https?://)?([\\da-z.-]+)\\.([a-z.]{2,6})([/\\w .-]*)*/?$
                input "http://example.com/" + "a"*n + "!"

Each ``re`` run happens in a child process with a timeout, so a catastrophic
case is recorded as ">= timeout" instead of hanging the benchmark. ``re`` is
used here ONLY as the thing being attacked; the engine itself never imports it.

    python -m bench.redos            -> artifacts/results/redos.json + figures/redos.png
"""
from __future__ import annotations

import json
import multiprocessing as mp
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "artifacts" / "results"

PATTERNS = {
    "nested": (r"^(a+)+$", lambda n: "a" * n + "!"),
    "url_regex": (r"^(https?://)?([\da-z.-]+)\.([a-z.]{2,6})([/\w .-]*)*/?$",
                  lambda n: "http://example.com/" + "a" * n + "!"),
}
RE_LENGTHS = [10, 14, 16, 18, 20, 22, 24, 26, 28, 30]
DFA_LENGTHS = [10, 100, 1_000, 10_000, 100_000]


def _re_worker(pattern: str, text: str, q) -> None:
    import re  # the backtracking engine under test (never used by the lexer)

    t0 = time.perf_counter()
    re.match(pattern, text)
    q.put(time.perf_counter() - t0)


def time_re(pattern: str, text: str, timeout: float) -> float | None:
    q = mp.Queue()
    p = mp.Process(target=_re_worker, args=(pattern, text, q))
    p.start()
    p.join(timeout)
    if p.is_alive():
        p.terminate()
        p.join()
        return None
    return q.get()


def time_fn(fn, reps: int = 3) -> float:
    best = float("inf")
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - t0)
    return best


def main(timeout: float = 5.0) -> dict:
    from lexer.build_automata import pipeline
    from lexer.scanner import get_scanner

    nested_dfa = pipeline("(a+)+", "ACCEPT", defs={})["min"]
    scanner = get_scanner()
    out: dict = {"timeout_s": timeout, "re": {}, "dfa": {}}

    for name, (pat, make) in PATTERNS.items():
        rows = []
        for n in RE_LENGTHS:
            t = time_re(pat, make(n), timeout)
            rows.append({"n": n, "seconds": t, "timed_out": t is None})
            print(f"  re   {name:<10} n={n:<6} {'TIMEOUT' if t is None else f'{t:.4f}s'}")
            if t is None:
                break
        out["re"][name] = rows

    out["dfa"]["nested"] = []
    out["dfa"]["url_scanner"] = []
    for n in DFA_LENGTHS:
        text = "a" * n + "!"
        t = time_fn(lambda: nested_dfa.accepts(text))
        out["dfa"]["nested"].append({"n": n, "seconds": t})
        url = PATTERNS["url_regex"][1](n)
        t2 = time_fn(lambda: scanner.lex(url))
        out["dfa"]["url_scanner"].append({"n": n, "seconds": t2})
        print(f"  dfa  n={n:<7} nested {t:.6f}s   url scanner {t2:.6f}s ({t2 / len(url) * 1e6:.2f} µs/char)")

    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "redos.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    plot(out)
    return out


def plot(out: dict) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(8, 5))
    for name, rows in out["re"].items():
        xs = [r["n"] for r in rows if not r["timed_out"]]
        ys = [r["seconds"] for r in rows if not r["timed_out"]]
        ax.plot(xs, ys, "o-", label=f"Python re: {name}")
        to = [r["n"] for r in rows if r["timed_out"]]
        if to:
            ax.plot(to, [out["timeout_s"]] * len(to), "x", color="red", markersize=10,
                    label=f"re {name}: timeout ≥{out['timeout_s']:.0f}s")
    for name, rows in out["dfa"].items():
        ax.plot([r["n"] for r in rows], [r["seconds"] for r in rows], "s--", label=f"DFA: {name}")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("input length (characters)")
    ax.set_ylabel("time (s)")
    ax.set_title("Backtracking regex vs DFA scanning (ReDoS)")
    ax.grid(True, which="both", alpha=0.3)
    ax.legend(fontsize=8)
    fig.tight_layout()
    (RESULTS / "figures").mkdir(parents=True, exist_ok=True)
    fig.savefig(RESULTS / "figures" / "redos.png", dpi=150)
    print(f"  wrote {RESULTS / 'figures' / 'redos.png'}")


if __name__ == "__main__":
    main()
