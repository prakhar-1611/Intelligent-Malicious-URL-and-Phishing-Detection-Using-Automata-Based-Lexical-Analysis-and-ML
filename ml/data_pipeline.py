"""Dataset pipeline: download, clean, de-duplicate, and split by domain and time.

Author: Ishitwo Khanra (24BCE2975)

Sources
    malicious  PhishTank (verified phishing, has submission_time)
               URLhaus   (malware distribution, has dateadded)
               OpenPhish community feed (optional, no timestamps)
    benign     Tranco top sites (bare domains)
               Hacker News story links via the public Algolia API (real full URLs with
               paths; skewed towards tech/news sites, reported as a limitation)
               optional extra full benign URLs (--benign-urls FILE, e.g. a Common Crawl sample)

Safety: only the *lists* are downloaded. No listed URL is ever resolved or fetched.

Leakage control
    * exact duplicates and malformed records are removed
    * registered domain (computed by our own lexer + public suffix list) is the
      group key: a domain never appears in more than one split
    * the final test set is time-based: a malicious domain goes to test when it was
      *first seen* after the 80th percentile of first-seen times, so the model is
      tested on campaigns that started after everything it was trained on

Known bias, measured and reported (dataset_stats.json -> "path_rate")
    Tranco gives bare domains while phishing feeds give full URLs, so a model can
    learn "has a path = malicious". Mitigations: (1) real full benign URLs (Hacker
    News links, optional Common Crawl sample), (2) train.py --domain-only re-runs
    the whole evaluation on scheme+host only, where that shortcut is impossible.

Run:  python -m ml.data_pipeline --download --tranco-top 60000
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import random
import urllib.request
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"
PROCESSED = ROOT / "data" / "processed"
DATASET = PROCESSED / "dataset.csv"
STATS = PROCESSED / "dataset_stats.json"

SOURCES = {
    "urlhaus": "https://urlhaus.abuse.ch/downloads/csv_recent/",
    "urlhaus_full": "https://urlhaus.abuse.ch/downloads/csv/",
    "phishtank": "http://data.phishtank.com/data/{key}online-valid.csv",
    "openphish": "https://openphish.com/feed.txt",
    "tranco": "https://tranco-list.eu/top-1m.csv.zip",
    "hn": "https://hn.algolia.com/api/v1/search_by_date?tags=story&hitsPerPage=1000&numericFilters=created_at_i<{t}",
}
UA = {"User-Agent": "VIT-BCSE307P-research-dataset-builder/1.0 (+lists only, no URL visits)"}


def _download(url: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"  downloading {url}")
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=180) as r, open(dest, "wb") as f:
        f.write(r.read())
    return dest


def download_hn(pages: int = 45, before: int | None = None) -> Path:
    """Story links submitted to Hacker News, newest first, 1000 per page."""
    import time

    t = before or int(time.time())
    urls: list[str] = []
    for i in range(pages):
        req = urllib.request.Request(SOURCES["hn"].format(t=t), headers=UA)
        with urllib.request.urlopen(req, timeout=60) as r:
            hits = json.loads(r.read().decode("utf-8"))["hits"]
        if not hits:
            break
        urls += [h["url"] for h in hits if h.get("url")]
        t = min(h["created_at_i"] for h in hits)
        if i % 10 == 9:
            print(f"    hn: {len(urls)} urls")
        time.sleep(0.4)  # stay well under the API rate limit
    out = RAW / "hn_urls.txt"
    out.write_text("\n".join(urls), encoding="utf-8")
    return out


def download_all(full_urlhaus: bool = False, hn_pages: int = 45) -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    if full_urlhaus:
        _download(SOURCES["urlhaus_full"], RAW / "urlhaus_full.zip")
    else:
        _download(SOURCES["urlhaus"], RAW / "urlhaus.csv")
    key = os.environ.get("PHISHTANK_APP_KEY", "")
    try:
        _download(SOURCES["phishtank"].format(key=f"{key}/" if key else ""), RAW / "phishtank.csv")
    except Exception as e:  # PhishTank rate-limits anonymous downloads
        print(f"  ! PhishTank download failed ({e}); set PHISHTANK_APP_KEY or place phishtank.csv in data/raw")
    try:
        _download(SOURCES["openphish"], RAW / "openphish.txt")
    except Exception as e:
        print(f"  ! OpenPhish download failed ({e})")
    _download(SOURCES["tranco"], RAW / "tranco.zip")
    print("  downloading Hacker News story links (benign full URLs)")
    download_hn(hn_pages)


# ------------------------------------------------------------------ loaders


def _read_urlhaus() -> pd.DataFrame:
    frames = []
    if (RAW / "urlhaus_full.zip").exists():
        with zipfile.ZipFile(RAW / "urlhaus_full.zip") as z:
            text = z.read(z.namelist()[0]).decode("utf-8", errors="replace")
        frames.append(text)
    if (RAW / "urlhaus.csv").exists():
        frames.append((RAW / "urlhaus.csv").read_text(encoding="utf-8", errors="replace"))
    rows = []
    for text in frames:
        lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
        for rec in csv.reader(lines):
            if len(rec) >= 3:
                rows.append({"url": rec[2], "timestamp": rec[1], "source": "urlhaus"})
    return pd.DataFrame(rows)


def _read_phishtank() -> pd.DataFrame:
    p = RAW / "phishtank.csv"
    if not p.exists():
        return pd.DataFrame(columns=["url", "timestamp", "source"])
    df = pd.read_csv(p, dtype=str, on_bad_lines="skip")
    return pd.DataFrame({"url": df["url"], "timestamp": df.get("submission_time"), "source": "phishtank"})


def _read_openphish() -> pd.DataFrame:
    p = RAW / "openphish.txt"
    if not p.exists():
        return pd.DataFrame(columns=["url", "timestamp", "source"])
    urls = [u.strip() for u in p.read_text(encoding="utf-8", errors="replace").splitlines() if u.strip()]
    return pd.DataFrame({"url": urls, "timestamp": None, "source": "openphish"})


def _read_tranco(top: int, seed: int) -> pd.DataFrame:
    p = RAW / "tranco.zip"
    if not p.exists():
        return pd.DataFrame(columns=["url", "timestamp", "source"])
    with zipfile.ZipFile(p) as z:
        text = z.read(z.namelist()[0]).decode("utf-8")
    domains = [ln.split(",", 1)[1].strip() for ln in text.splitlines()[:top] if "," in ln]
    rng = random.Random(seed)
    urls = []
    for d in domains:
        # vary the surface form a little so "scheme/www/trailing slash" is not a class signal
        scheme = "https://" if rng.random() < 0.85 else "http://"
        www = "www." if rng.random() < 0.3 and not d.startswith("www.") else ""
        slash = "/" if rng.random() < 0.5 else ""
        urls.append(scheme + www + d + slash)
    return pd.DataFrame({"url": urls, "timestamp": None, "source": "tranco"})


def _read_hn() -> pd.DataFrame:
    p = RAW / "hn_urls.txt"
    if not p.exists():
        return pd.DataFrame(columns=["url", "timestamp", "source"])
    urls = [u.strip() for u in p.read_text(encoding="utf-8").splitlines() if u.strip()]
    return pd.DataFrame({"url": urls, "timestamp": None, "source": "hackernews"})


def _read_benign_urls(path: Path | None) -> pd.DataFrame:
    if not path or not Path(path).exists():
        return pd.DataFrame(columns=["url", "timestamp", "source"])
    urls = [u.strip() for u in Path(path).read_text(encoding="utf-8", errors="replace").splitlines() if u.strip()]
    return pd.DataFrame({"url": urls, "timestamp": None, "source": "benign_full"})


# ------------------------------------------------------------------ cleaning


def clean(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    from lexer.scanner import scan

    report = {"raw": int(len(df))}
    df = df.dropna(subset=["url"]).copy()
    df["url"] = df["url"].astype(str).str.strip()
    df = df[(df["url"].str.len() > 3) & (df["url"].str.len() <= 2048)]
    report["after_length_filter"] = int(len(df))
    # a URL listed as both benign and malicious is ambiguous: drop all copies
    conflicted = set(df.groupby("url")["label"].nunique().loc[lambda s: s > 1].index)
    df = df[~df["url"].isin(conflicted)]
    report["label_conflicts_removed"] = len(conflicted)
    df = df.drop_duplicates(subset=["url"])
    report["after_dedup"] = int(len(df))
    # malformed = our lexer cannot find a host / registered domain in it
    df["domain"] = [scan(u).registered_domain.lower() for u in df["url"]]
    df = df[[bool(d) for d in df["domain"]]]
    report["after_malformed_filter"] = int(len(df))
    return df.reset_index(drop=True), report


def split(df: pd.DataFrame, seed: int = 42, test_quantile: float = 0.8, val_frac: float = 0.15) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    df = df.copy()
    df["ts"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df["split"] = ""
    # first time each malicious domain was reported
    first_seen = df.loc[(df["label"] == 1) & df["ts"].notna()].groupby("domain")["ts"].min()
    test_domains: set[str] = set()
    cutoff = None
    if len(first_seen) > 50:
        cutoff = first_seen.quantile(test_quantile)
        test_domains |= set(first_seen[first_seen >= cutoff].index)
    # benign domains and malicious domains without timestamps: random 20% to test.
    # timestamped malicious domains first seen before the cutoff stay in train/val.
    other = sorted(set(df["domain"]) - test_domains - set(first_seen.index))
    n_extra = int(round(0.2 * len(other)))
    test_domains |= set(rng.choice(other, size=n_extra, replace=False)) if other and n_extra else set()
    df.loc[df["domain"].isin(test_domains), "split"] = "test"
    rest = sorted(set(df.loc[df["split"] == "", "domain"]))
    val_domains = set(rng.choice(rest, size=int(round(val_frac * len(rest))), replace=False)) if rest else set()
    df.loc[(df["split"] == "") & df["domain"].isin(val_domains), "split"] = "val"
    df.loc[df["split"] == "", "split"] = "train"
    df.attrs["time_cutoff"] = str(cutoff) if cutoff is not None else None
    return df.drop(columns=["ts"])


def dataset_stats(df: pd.DataFrame, clean_report: dict) -> dict:
    def has_path(u: str) -> bool:
        rest = u.split("://", 1)[-1]
        i = rest.find("/")
        return i >= 0 and len(rest) > i + 1

    stats: dict = {"cleaning": clean_report, "time_cutoff": df.attrs.get("time_cutoff")}
    stats["by_split_label"] = {f"{s}/{lab}": int(n) for (s, lab), n in df.groupby(["split", "label"]).size().items()}
    stats["by_source"] = {k: int(v) for k, v in df["source"].value_counts().items()}
    stats["domains_per_split"] = {s: int(g["domain"].nunique()) for s, g in df.groupby("split")}
    overlap = set(df.loc[df.split == "train", "domain"]) & set(df.loc[df.split == "test", "domain"])
    stats["train_test_domain_overlap"] = len(overlap)
    stats["path_rate"] = {str(lab): round(float(g["url"].map(has_path).mean()), 4) for lab, g in df.groupby("label")}
    stats["mean_length"] = {str(lab): round(float(g["url"].str.len().mean()), 1) for lab, g in df.groupby("label")}
    return stats


def build(tranco_top: int, benign_urls: Path | None, seed: int, max_per_source: int | None) -> pd.DataFrame:
    mal = pd.concat([_read_phishtank(), _read_urlhaus(), _read_openphish()], ignore_index=True)
    ben = pd.concat([_read_tranco(tranco_top, seed), _read_hn(), _read_benign_urls(benign_urls)],
                    ignore_index=True)
    if max_per_source:
        mal = mal.groupby("source", group_keys=False).apply(
            lambda g: g.sample(min(len(g), max_per_source), random_state=seed))
        ben = ben.groupby("source", group_keys=False).apply(
            lambda g: g.sample(min(len(g), max_per_source), random_state=seed))
    mal["label"], ben["label"] = 1, 0
    df = pd.concat([mal, ben], ignore_index=True)
    if df.empty:
        raise SystemExit("no raw data found: run with --download first (or place files in data/raw)")
    df, report = clean(df)
    df = split(df, seed)
    PROCESSED.mkdir(parents=True, exist_ok=True)
    df.to_csv(DATASET, index=False)
    stats = dataset_stats(df, report)
    STATS.write_text(json.dumps(stats, indent=2), encoding="utf-8")
    print(json.dumps(stats, indent=2))
    return df


def load_dataset(path: Path = DATASET) -> pd.DataFrame:
    return pd.read_csv(path, dtype={"url": str, "domain": str, "split": str, "source": str}, low_memory=False)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--download", action="store_true", help="download the raw lists first")
    ap.add_argument("--full-urlhaus", action="store_true", help="use the full URLhaus archive, not the last 30 days")
    ap.add_argument("--tranco-top", type=int, default=60000)
    ap.add_argument("--benign-urls", type=Path, default=None, help="file with full benign URLs, one per line")
    ap.add_argument("--max-per-source", type=int, default=None)
    ap.add_argument("--hn-pages", type=int, default=45, help="pages of 1000 Hacker News links")
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    if a.download:
        download_all(a.full_urlhaus, a.hn_pages)
    build(a.tranco_top, a.benign_urls, a.seed, a.max_per_source)


if __name__ == "__main__":
    main()

