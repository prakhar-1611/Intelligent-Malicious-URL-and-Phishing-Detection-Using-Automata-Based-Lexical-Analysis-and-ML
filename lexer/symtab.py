"""Symbol tables: one per scanned URL and one for the whole corpus.

Author: Ishitwo Khanra (24BCE2975)

``SymbolTable`` is a separate-chaining hash table keyed by (lexeme, kind),
written out explicitly (FNV-1a hash, load-factor-driven rehashing) as the
classic compiler data structure, rather than hidden behind ``dict``.

Per symbol we keep: the token types it appeared as, frequency, first and last
position, and the anomaly flags whose span overlaps it.

``CorpusSymbolTable`` aggregates many URLs: how common each domain label is
(label rarity), and how often a brand name shows up as a *subdomain* label
(paypal.com.verify-account.example). Both feed the feature extractor.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path

FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3
MASK64 = (1 << 64) - 1


def fnv1a(text: str) -> int:
    h = FNV_OFFSET
    for b in text.encode("utf-8", errors="surrogatepass"):
        h ^= b
        h = (h * FNV_PRIME) & MASK64
    return h


@dataclass
class Symbol:
    lexeme: str
    kind: str  # label, host, domain, ip, param, port, scheme, path_seg, header_key, address
    token_types: set[str] = field(default_factory=set)
    freq: int = 0
    first: int = -1
    last: int = -1
    flags: set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {"lexeme": self.lexeme, "kind": self.kind, "token_types": sorted(self.token_types),
                "freq": self.freq, "first": self.first, "last": self.last, "flags": sorted(self.flags)}


class SymbolTable:
    def __init__(self, capacity: int = 16) -> None:
        self._buckets: list[list[Symbol]] = [[] for _ in range(capacity)]
        self._size = 0

    def _index(self, lexeme: str, kind: str, n: int) -> int:
        return fnv1a(kind + "\x00" + lexeme) % n

    def _rehash(self) -> None:
        old = [s for b in self._buckets for s in b]
        self._buckets = [[] for _ in range(len(self._buckets) * 2)]
        for s in old:
            self._buckets[self._index(s.lexeme, s.kind, len(self._buckets))].append(s)

    def lookup(self, lexeme: str, kind: str) -> Symbol | None:
        for s in self._buckets[self._index(lexeme, kind, len(self._buckets))]:
            if s.lexeme == lexeme and s.kind == kind:
                return s
        return None

    def insert(self, lexeme: str, kind: str, token_type: str, pos: int) -> Symbol:
        sym = self.lookup(lexeme, kind)
        if sym is None:
            if (self._size + 1) / len(self._buckets) > 0.75:
                self._rehash()
            sym = Symbol(lexeme, kind, first=pos)
            self._buckets[self._index(lexeme, kind, len(self._buckets))].append(sym)
            self._size += 1
        sym.token_types.add(token_type)
        sym.freq += 1
        sym.last = pos
        return sym

    def link_flag(self, lexeme: str, kind: str, code: str) -> None:
        sym = self.lookup(lexeme, kind)
        if sym:
            sym.flags.add(code)

    def __len__(self) -> int:
        return self._size

    def __iter__(self):
        for b in self._buckets:
            yield from b

    def by_kind(self, kind: str) -> list[Symbol]:
        return [s for s in self if s.kind == kind]

    def max_chain(self) -> int:
        return max((len(b) for b in self._buckets), default=0)

    def to_dict(self) -> dict:
        return {
            "size": self._size,
            "buckets": len(self._buckets),
            "max_chain": self.max_chain(),
            "symbols": sorted((s.to_dict() for s in self), key=lambda d: (d["first"], d["kind"])),
        }


class CorpusSymbolTable:
    """Corpus-wide statistics, built from the *training* split only."""

    def __init__(self) -> None:
        self.label_counts: dict[str, int] = {}
        self.brand_subdomain_counts: dict[str, int] = {}
        self.n_urls = 0

    def add(self, labels: list[str], subdomains: list[str], brands: set[str]) -> None:
        self.n_urls += 1
        for lab in set(labels):
            self.label_counts[lab] = self.label_counts.get(lab, 0) + 1
        for sub in set(subdomains):
            if sub in brands:
                self.brand_subdomain_counts[sub] = self.brand_subdomain_counts.get(sub, 0) + 1

    def label_rarity(self, label: str) -> float:
        """-log P(label) with add-one smoothing; unseen labels are maximally rare."""
        c = self.label_counts.get(label, 0)
        v = len(self.label_counts) + 1
        return -math.log((c + 1) / (self.n_urls + v))

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps({
            "n_urls": self.n_urls, "label_counts": self.label_counts,
            "brand_subdomain_counts": self.brand_subdomain_counts}), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "CorpusSymbolTable":
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        t = cls()
        t.n_urls = d["n_urls"]
        t.label_counts = d["label_counts"]
        t.brand_subdomain_counts = d.get("brand_subdomain_counts", {})
        return t
