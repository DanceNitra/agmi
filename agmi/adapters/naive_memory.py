# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""A deliberately naive semantic memory store, as a reference target.

This models the common denominator of tools like Mem0/Letta at their core:
store text with a user_id, retrieve by simple lexical/semantic similarity,
scope by user. It applies NO integrity, provenance, or injection defences,
so it shows the baseline "unprotected" scorecard the memory attacks produce.

It is intentionally honest about being naive: when real Mem0/Letta adapters
are added, differences in their scores against THIS baseline are the finding.
"""

from __future__ import annotations

import re

from agmi.adapters.semantic_base import (
    SemanticMemoryAdapter, MemoryItem, Retrieved,
)


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


class NaiveMemoryAdapter(SemanticMemoryAdapter):
    """No defences. Retrieves by token overlap. Optionally leaks across users
    to model a tool that forgets to scope retrieval (a real bug class)."""

    def __init__(self, enforce_user_scope: bool = True):
        self.name = "naive-memory"
        self.enforce_user_scope = enforce_user_scope
        self._items: list[MemoryItem] = []

    def reset(self) -> None:
        self._items = []

    def add_memory(self, item: MemoryItem) -> None:
        self._items.append(item)

    def retrieve(self, query: str, user_id: str, k: int = 5) -> list[Retrieved]:
        q = _tokens(query)
        scored: list[tuple[float, MemoryItem]] = []
        for item in self._items:
            if self.enforce_user_scope and item.user_id != user_id:
                continue
            overlap = len(q & _tokens(item.text))
            if overlap == 0:
                continue
            score = overlap / (len(q) or 1)
            scored.append((score, item))
        scored.sort(key=lambda s: s[0], reverse=True)
        return [Retrieved(text=i.text, user_id=i.user_id, score=s)
                for s, i in scored[:k]]

    def retrieve_where(self, query: str, user_id: str, where: dict,
                       k: int = 5) -> list[Retrieved]:
        q = _tokens(query)
        scored = []
        for i in self._items:
            if self.enforce_user_scope and i.user_id != user_id:
                continue
            if any(i.metadata.get(key) != val for key, val in where.items()):
                continue
            overlap = len(q & _tokens(i.text))
            if overlap:
                scored.append((overlap / (len(q) or 1), i))
        scored.sort(key=lambda s: -s[0])
        return [Retrieved(text=i.text, user_id=i.user_id, score=s)
                for s, i in scored[:k]]

    def measured_on(self) -> str:
        return "reference store, token-overlap ranking, no defences"
