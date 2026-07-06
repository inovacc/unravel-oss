"""Vendored smoke-corpus fixture (D-03 / SC3).

Small, self-contained, license-clean Python module: simple text statistics.
No third-party imports, no build system. See test_scenarios/smoke/SOURCES.md
for provenance and pinning.
"""

from collections import Counter


def word_count(text: str) -> int:
    return len(text.split())


def char_frequency(text: str) -> dict:
    counts = Counter()
    for ch in text:
        if ch.isalpha():
            counts[ch.lower()] += 1
    return dict(counts)


def longest_word(text: str) -> str:
    words = text.split()
    if not words:
        return ""
    best = words[0]
    for w in words[1:]:
        if len(w) > len(best):
            best = w
    return best


def average_word_length(text: str) -> float:
    words = text.split()
    if not words:
        return 0.0
    total = sum(len(w) for w in words)
    return total / len(words)


def is_palindrome(s: str) -> bool:
    cleaned = [c.lower() for c in s if c.isalnum()]
    return cleaned == cleaned[::-1]


class LineBuffer:
    def __init__(self):
        self._lines = []

    def add(self, line: str) -> None:
        self._lines.append(line.rstrip("\n"))

    def non_empty(self) -> list:
        return [ln for ln in self._lines if ln.strip()]

    def total(self) -> int:
        return len(self._lines)
