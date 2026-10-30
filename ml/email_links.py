"""Benign full URLs taken from legitimate email corpora, for data_pipeline --benign-urls.

Author: Ishitwo Khanra (24BCE2975)

Why: Tranco gives bare domains and Hacker News gives short article links, so the model learned
"unfamiliar domain + real path = phishing". On 251 legitimate SpamAssassin hard_ham emails, 72% of
the unflagged links scored Malicious, and Google Play's c.gle tracking links scored 0.99.
Links in legitimate mail (newsletters, receipts, notifications) are the missing benign examples.

Sources (place them under data/raw/email_ham/, they are not redistributed)
    enron/emails.csv              Kaggle "Enron Email Dataset" (columns file, message)
    spamassassin/spam_assassin.csv Kaggle "SpamAssassin public corpus" (columns text, target; 0 = ham)

Rules
    * SpamAssassin: ham only (target 0). Enron: skip junk / spam / deleted folders.
    * a link is kept only if the URL scanner raises no security flag on it
    * at most --per-domain links per registered domain, so one site cannot dominate
Nothing is ever fetched: links are only lexed.

Run:  python -m ml.email_links --enron-sample 100000   ->  data/raw/email_ham_urls.txt
"""
from __future__ import annotations

import argparse
import random
from collections import defaultdict
from pathlib import Path

import pandas as pd

from lexer.email_lexer import find_urls, scan_email
from lexer.scanner import scan

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "data" / "raw" / "email_ham"
OUT = ROOT / "data" / "raw" / "email_ham_urls.txt"
SKIP_FOLDERS = ("junk", "spam", "deleted_items", "discussion_threads")


def enron_links(sample: int, seed: int) -> list[str]:
    path = SRC / "enron" / "emails.csv"
    if not path.exists():
        return []
    df = pd.read_csv(path, usecols=["file", "message"], dtype=str)
    df = df[~df["file"].str.lower().str.contains("|".join(SKIP_FOLDERS), regex=True)]
    if sample and len(df) > sample:
        df = df.sample(sample, random_state=seed)
    out: list[str] = []
    for n, msg in enumerate(df["message"], 1):
        res = scan_email(msg[:200_000])
        # many Enron messages are quoted-printable without saying so: "=3D" is an encoded "="
        out += [u["url"].replace("=3D", "=") for u in res.urls if not u["flags"]]
        if n % 10_000 == 0:
            print(f"  enron {n}/{len(df)} emails, {len(out)} links", flush=True)
    return out


def spamassassin_links() -> list[str]:
    path = SRC / "spamassassin" / "spam_assassin.csv"
    if not path.exists():
        return []
    df = pd.read_csv(path, dtype={"text": str, "target": int})
    out: list[str] = []
    for text in df.loc[df["target"] == 0, "text"].fillna(""):
        for u in find_urls(text):
            if not scan(u[:2048]).flags:
                out.append(u)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--enron-sample", type=int, default=100_000, help="emails to sample from Enron (0 = all)")
    ap.add_argument("--per-domain", type=int, default=50)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()

    links = spamassassin_links()
    print(f"spamassassin ham: {len(links)} clean links", flush=True)
    links += enron_links(a.enron_sample, a.seed)
    by_domain: dict[str, list[str]] = defaultdict(list)
    for u in dict.fromkeys(x for x in links if x.lower().startswith(("http://", "https://"))):
        d = scan(u[:2048]).registered_domain.lower()
        if d:
            by_domain[d].append(u)
    rng = random.Random(a.seed)
    kept: list[str] = []
    for d in sorted(by_domain):
        urls = by_domain[d]
        rng.shuffle(urls)
        kept += urls[:a.per_domain]
    OUT.write_text("\n".join(kept) + "\n", encoding="utf-8")
    print(f"{len(kept)} benign links from {len(by_domain)} domains -> {OUT}")


if __name__ == "__main__":
    main()
