"""RAG retrieval over the ingested reference corpus.

Indexes the markdown/text from the cloned references (PayloadsAllTheThings, bug-bounty
writeups, etc.) in data/kb_corpus and answers `search(query)` with the most relevant
chunks. Stdlib-only TF-IDF (no heavy deps). This is how the AI "loads" the external
sources: during analysis it retrieves real payloads/techniques and uses them — rather
than anyone memorizing hundreds of files.
"""
from __future__ import annotations

import math
import re
from functools import lru_cache
from pathlib import Path

from ..config import DATA_DIR

CORPUS = DATA_DIR / "kb_corpus"
# md-heavy sources worth indexing as prose/payloads
_SOURCES = ["payloads", "bb-writeups", "fuzzyai", "hacktricks"]
_TOKEN = re.compile(r"[a-zA-Z0-9_]{3,}")

_INDEX: dict | None = None


def _tokenize(text: str) -> list[str]:
    return [t.lower() for t in _TOKEN.findall(text)]


def _iter_files():
    for src in _SOURCES:
        base = CORPUS / src
        if not base.exists():
            continue
        for p in base.rglob("*.md"):
            yield src, p
        for p in base.rglob("*.txt"):
            if p.stat().st_size < 200_000:  # skip giant wordlists here
                yield src, p


def _chunks(text: str):
    # split on markdown headers; keep sections digestible
    parts = re.split(r"\n(?=#{1,4}\s)", text)
    for part in parts:
        s = part.strip()
        if len(s) < 50:
            continue
        heading = s.splitlines()[0].lstrip("# ").strip()[:120]
        yield heading, s[:1600]


def build() -> dict:
    global _INDEX
    if _INDEX is not None:
        return _INDEX
    chunks: list[dict] = []
    postings: dict[str, list[int]] = {}
    for src, path in _iter_files():
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(CORPUS))
        for heading, body in _chunks(text):
            cid = len(chunks)
            chunks.append({"src": src, "path": rel, "heading": heading, "text": body})
            for term in set(_tokenize(heading + " " + body)):
                postings.setdefault(term, []).append(cid)
            if len(chunks) >= 40000:  # safety cap
                break
    n = max(1, len(chunks))
    idf = {t: math.log(1 + n / len(ids)) for t, ids in postings.items()}
    _INDEX = {"chunks": chunks, "postings": postings, "idf": idf, "n": n}
    return _INDEX


def available() -> bool:
    return CORPUS.exists() and any((CORPUS / s).exists() for s in _SOURCES)


def stats() -> dict:
    if not available():
        return {"indexed": False, "sources": [], "chunks": 0}
    idx = build()
    srcs = sorted({c["src"] for c in idx["chunks"]})
    return {"indexed": True, "sources": srcs, "chunks": idx["n"]}


def search(query: str, k: int = 5) -> list[dict]:
    if not available():
        return []
    idx = build()
    terms = _tokenize(query)
    scores: dict[int, float] = {}
    for t in terms:
        w = idx["idf"].get(t, 0.0)
        for cid in idx["postings"].get(t, ()):
            scores[cid] = scores.get(cid, 0.0) + w
    top = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:k]
    return [idx["chunks"][cid] for cid, _ in top]


def brief(query: str, k: int = 4, max_chars: int = 2400) -> str:
    """Compact injectable block of retrieved payloads/techniques for the AI."""
    hits = search(query, k)
    if not hits:
        return ""
    out = ["Retrieved references (payloads/techniques from the knowledge corpus):"]
    for h in hits:
        out.append(f"\n## {h['heading']}  [{h['path']}]\n{h['text'][:600]}")
    return "\n".join(out)[:max_chars]
