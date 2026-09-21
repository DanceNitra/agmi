# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Adapter for LangGraph's long-term memory store, memory-specific surface.

LangGraph has two persistence components. The checkpointer (``SqliteSaver``,
measured at rest in ``langgraph_sqlite``) saves and resumes a graph's state;
it does not search. The store (``SqliteStore`` here, from the same
``langgraph-checkpoint-sqlite`` package) is the long-term memory an agent
writes facts into and searches by meaning. The memory-specific attacks
apply to the store, so this is a separate row from the checkpointer.

Write path
    ``SqliteStore.put(("memories", user_id), key, {"text": ...})`` with the
    store's vector index configured to embed the ``text`` field. The text
    is stored as given.

Read path
    ``SqliteStore.search(("memories", user_id), query=..., limit=k)``, the
    call an agent makes to fetch context, with every other parameter at
    its default. Results are passed to the attack exactly as the store
    returns them: no client-side filtering and no floor of this suite's
    own. The ``user_id`` on each hit is the second element of the hit's
    namespace.

    Two facts about langgraph-checkpoint-sqlite 3.1.1's store decide the
    row. First, ``search`` applies no relevance floor: with a query that
    shares nothing with a stored memory, that memory still comes back at
    score 0.0. Second, user isolation is the namespace the caller passes,
    not a filter the store applies over a shared pool: a search for the
    parent prefix ``("memories",)`` returns every user's memories. An agent
    that searches its own user's namespace cannot see another user's, so
    the bleed cell holds; the guarantee sits in the caller's code, not the
    store's.

Embedder
    Passed in. The store ranks by cosine similarity over whatever embedder
    its index is given, so the cells that depend on ranking are published
    only when measured with a real sentence embedder. See
    ``agmi.embedders``.

Store
    A fresh SQLite file under a temporary directory for every ``reset()``,
    opened in autocommit mode as ``SqliteStore.from_conn_string`` does.
"""

from __future__ import annotations

import importlib.metadata as md
import platform
import sqlite3
import sys
import tempfile
import uuid
from pathlib import Path

from agmi.adapters.semantic_base import (
    MemoryItem, Retrieved, SemanticMemoryAdapter,
)
from agmi.embedders import Embedder, HashEmbedder

#: Row label as it appears on the scorecard. The runner may override it.
LABEL = "langgraph-sqlite-store"
NAMESPACE_ROOT = "memories"


def langgraph_store_version() -> str:
    try:
        return md.version("langgraph-checkpoint-sqlite")
    except md.PackageNotFoundError:
        return "not installed"


class LangGraphSqliteStoreAdapter(SemanticMemoryAdapter):
    """Real LangGraph ``SqliteStore`` with a vector index, for the
    memory-specific attacks.

    Parameters
    ----------
    embedder:
        The embedder the store's index vectorises with. Defaults to the
        offline hashing embedder, which is enough to exercise storage and
        scoping but not ranking. Pass ``SentenceTransformerEmbedder()`` for
        a measurement that can be published for every cell.
    label:
        Scorecard row name. Defaults to ``LABEL``.
    """

    def __init__(self, embedder: Embedder | None = None,
                 label: str | None = None):
        self.embedder: Embedder = embedder or HashEmbedder()
        self.name = label or LABEL
        self._dir: tempfile.TemporaryDirectory | None = None
        self._conn: sqlite3.Connection | None = None
        self._store = None

    # --- lifecycle -----------------------------------------------------
    def reset(self) -> None:
        """Throw the store away and start from an empty one."""
        try:
            from langgraph.store.sqlite import SqliteStore
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise NotImplementedError(
                "langgraph-checkpoint-sqlite is not installed; run "
                "pip install 'agent-memory-integrity[langgraph]'") from exc
        self.close()
        self._dir = tempfile.TemporaryDirectory(prefix="agmi-langgraph-store-")
        path = Path(self._dir.name) / "store.sqlite"
        self._conn = sqlite3.connect(str(path), check_same_thread=False,
                                     isolation_level=None)
        embed = self.embedder

        def embed_batch(texts: list[str]) -> list[list[float]]:
            return [embed.embed(t, "add") for t in texts]

        self._store = SqliteStore(self._conn, index={
            "dims": embed.dims, "embed": embed_batch, "fields": ["text"],
        })
        self._store.setup()

    def close(self) -> None:
        """Close the connection and delete the store. Idempotent."""
        self._store = None
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:  # noqa: BLE001 - best effort on teardown
                pass
            self._conn = None
        if self._dir is not None:
            self._dir.cleanup()
            self._dir = None

    def _memory(self):
        if self._store is None:
            self.reset()
        return self._store

    def __enter__(self) -> "LangGraphSqliteStoreAdapter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __del__(self) -> None:  # pragma: no cover - interpreter teardown
        try:
            self.close()
        except Exception:  # noqa: BLE001
            pass

    # --- the tool's own write and read paths ---------------------------
    def add_memory(self, item: MemoryItem) -> None:
        value = {"text": item.text}
        if item.metadata:
            value.update({k: v for k, v in item.metadata.items() if k != "text"})
        self._memory().put((NAMESPACE_ROOT, item.user_id), str(uuid.uuid4()),
                           value)

    def retrieve(self, query: str, user_id: str, k: int = 5) -> list[Retrieved]:
        items = self._memory().search((NAMESPACE_ROOT, user_id), query=query,
                                      limit=k)
        out: list[Retrieved] = []
        for it in items:
            owner = it.namespace[1] if len(it.namespace) > 1 else ""
            out.append(Retrieved(
                text=str((it.value or {}).get("text", "")),
                user_id=str(owner),
                score=float(it.score or 0.0),
            ))
        return out

    def supports_users(self) -> bool:
        return True

    # --- provenance for reports ----------------------------------------
    def measured_on(self) -> str:
        """One line stating what this row was produced with."""
        return (f"langgraph-checkpoint-sqlite {langgraph_store_version()} "
                f"SqliteStore with a vector index, search defaults (no "
                f"relevance floor), {self.embedder.describe()}, "
                f"{platform.system()} {platform.machine()}, "
                f"Python {sys.version_info.major}.{sys.version_info.minor}")
