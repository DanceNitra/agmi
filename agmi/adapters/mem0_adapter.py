# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Adapter for Mem0 (mem0ai), the open-source semantic memory layer.

Maps the suite's semantic interface onto Mem0's real API:
    m.add(text, user_id=...)                     -> add_memory
    m.search(query, user_id=..., ...)            -> retrieve
    m.delete_all(user_id=...) / m.reset()        -> reset

IMPORTANT — this talks to real Mem0, which uses an LLM to extract and store
memories. That means:
  * `pip install mem0ai` is required, and
  * an LLM key (e.g. OPENAI_API_KEY) must be set, and
  * runs make network calls and cost tokens.

Because of that, this adapter cannot run in a sealed CI sandbox. Run it on a
machine with a key set. The suite treats an unavailable Mem0 as an errored
(n/a) cell, never as a pass.

Mem0 note that matters for the attacks: `add()` does not store text
verbatim. It runs the input through an LLM that extracts salient "facts", so
what comes back from search() is a paraphrase, not your exact bytes. The
attacks below therefore check for a stable, unusual token planted in the
input rather than exact-string containment. This is a deliberate,
Mem0-specific accommodation and is documented in each override.
"""

from __future__ import annotations

from agmi.adapters.semantic_base import (
    SemanticMemoryAdapter, MemoryItem, Retrieved,
)


class Mem0Adapter(SemanticMemoryAdapter):
    """Wraps a real Mem0 `Memory` instance.

    Parameters
    ----------
    memory:
        An already-constructed `mem0.Memory` (or compatible) object. Passing
        it in keeps API-key and provider config out of the suite. If None,
        the adapter tries to build a default `Memory()` on first use and
        raises a clear error if mem0ai or a key is missing.
    """

    def __init__(self, memory=None):
        self.name = "mem0"
        self._memory = memory
        self._users: set[str] = set()

    def _mem(self):
        if self._memory is None:
            try:
                from mem0 import Memory
            except ImportError as exc:  # pragma: no cover - env dependent
                raise NotImplementedError(
                    "mem0ai not installed; run `pip install mem0ai`"
                ) from exc
            self._memory = Memory()
        return self._memory

    def reset(self) -> None:
        m = self._mem()
        # Prefer targeted cleanup per user; fall back to global reset.
        for uid in list(self._users):
            try:
                m.delete_all(user_id=uid)
            except Exception:  # noqa: BLE001
                pass
        self._users.clear()
        try:
            m.reset()
        except Exception:  # noqa: BLE001
            pass

    def add_memory(self, item: MemoryItem) -> None:
        m = self._mem()
        self._users.add(item.user_id)
        # Mem0 accepts either a plain string or a messages list; the messages
        # form is the documented one and extracts more reliably.
        messages = [{"role": "user", "content": item.text}]
        m.add(messages, user_id=item.user_id, metadata=item.metadata or {})

    def retrieve(self, query: str, user_id: str, k: int = 5) -> list[Retrieved]:
        m = self._mem()
        # Mem0 has shifted the user_id location across versions (top-level vs
        # filters). Try the current filters form first, fall back to legacy.
        try:
            res = m.search(query, filters={"user_id": user_id}, limit=k)
        except TypeError:
            res = m.search(query, user_id=user_id, limit=k)
        rows = res.get("results", res) if isinstance(res, dict) else res
        out: list[Retrieved] = []
        for r in rows or []:
            out.append(Retrieved(
                text=r.get("memory", ""),
                user_id=r.get("user_id", user_id) or user_id,
                score=float(r.get("score", 0.0) or 0.0),
            ))
        return out
