# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Extended adapter surface for semantic-memory attacks.

The at-rest attacks only needed raw-store access. The memory-specific
attacks (injection, cross-session bleed, retrieval hijack, indirect prompt
injection) need to exercise the tool the way an agent does: write a memory
scoped to a user, then retrieve by semantic query scoped to a user.

A tool that has no notion of users, queries, or retrieval simply does not
implement this interface, and these attacks report "n/a" for it (correctly:
an audit log like OpenFang cannot be memory-injected because nothing ever
retrieves it as context). That n/a is a real signal, not a gap in the suite.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class MemoryItem:
    """One semantic memory as an agent tool stores it.

    ``source`` names the channel the memory arrived on: "user" for
    something the user said, "external" for content the agent read (a web
    page, an email, a tool result). Adapters pass it to the tool as
    metadata where the tool accepts any; a tool that keeps provenance can
    act on it, and most do not, which is the finding.
    """

    text: str
    user_id: str
    metadata: dict = field(default_factory=dict)
    source: str = "user"
    #: Signature over (user_id, source, text) by the writer's key, or None.
    #: Adapters pass it to the tool as metadata; see ``agmi.signing``.
    signature: str | None = None


@dataclass
class Retrieved:
    """One result returned by a semantic query, with its source scope."""

    text: str
    user_id: str
    score: float = 0.0


class SemanticMemoryAdapter(ABC):
    """Implemented only by tools that do user-scoped semantic memory.

    Attacks use this to answer behavioural questions:
      - after injecting a memory, does a later retrieval surface it as the
        agent's own fact? (injection)
      - can a query as user B surface user A's memory? (cross-session bleed)
      - can a crafted entry be retrieved for an unrelated query? (hijack)
      - does retrieved memory carry instruction-shaped content into context?
        (indirect prompt injection)
    """

    name: str

    @abstractmethod
    def reset(self) -> None:
        """Clear all memory for a fresh test."""

    @abstractmethod
    def add_memory(self, item: MemoryItem) -> None:
        """Store a memory through the tool's normal write path."""

    @abstractmethod
    def retrieve(self, query: str, user_id: str, k: int = 5) -> list[Retrieved]:
        """Return the top-k memories the tool considers relevant to `query`
        for `user_id`, exactly as an agent would fetch context."""

    def supports_users(self) -> bool:
        """Whether the tool scopes memory per user. Tools that don't cannot
        be tested for cross-session bleed."""
        return True

    def close(self) -> None:
        """Release anything the adapter holds. The runner calls this after
        the last attack. Default: nothing to release."""

    def measured_on(self) -> str:
        """One line naming what a row was produced with: library version,
        embedder, which of the tool's optional features were on. Printed
        next to the row. Default says the adapter did not record it."""
        return "not recorded by this adapter"
