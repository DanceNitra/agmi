# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""What the two Mem0 adapters share: opening a real ``mem0.Memory`` on a
private local Qdrant store, closing it cleanly, and locating its files.

Both adapters build Mem0 the same way so that a reader comparing the at-rest
row with the memory-specific row is comparing the same product configured
the same way, with only the embedder differing where the measurement needs
it to.

Layout under ``root``::

    root/qdrant/collection/agmi/storage.sqlite   points(id TEXT, point BLOB)
    root/history.db                              Mem0's ADD/UPDATE/DELETE log
"""

from __future__ import annotations

import importlib.metadata as md
import os
from pathlib import Path

from agmi.embedders import Embedder

#: Qdrant collection name every Mem0 row uses.
COLLECTION = "agmi"

#: Mem0 constructs an OpenAI client at start-up even when no call is ever
#: made. A dummy key satisfies the constructor; nothing goes over the wire.
DUMMY_OPENAI_KEY = "sk-agmi-offline-dummy"


def open_local_memory(root: Path, embedder: Embedder, live: bool = False):
    """Construct a real ``mem0.Memory`` whose stores live under ``root``.

    ``embedder`` replaces Mem0's default (OpenAI) embedder after
    construction, so no network is needed and the Qdrant collection is
    created with ``embedder.dims`` as its vector width.

    ``live=True`` is for the ``infer=True`` tier: Mem0's own LLM (its
    default OpenAI configuration) is left in place and a real
    ``OPENAI_API_KEY`` must already be in the environment. Nothing is
    substituted, so the row measures Mem0 as shipped.

    Raises ``NotImplementedError`` if mem0ai is not installed, or if the
    live tier is asked for without a key; the attacks score both ``n/a``.
    """
    os.environ.setdefault("MEM0_TELEMETRY", "false")
    if live:
        key = os.environ.get("OPENAI_API_KEY", "")
        if not key or key == DUMMY_OPENAI_KEY:
            raise NotImplementedError(
                "the infer=True tier needs a real OPENAI_API_KEY in the "
                "environment; it is never measured with a stand-in")
    else:
        os.environ.setdefault("OPENAI_API_KEY", DUMMY_OPENAI_KEY)
    try:
        from mem0 import Memory
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise NotImplementedError(
            "mem0ai is not installed; run "
            "pip install 'agent-memory-integrity[mem0]'") from exc
    cfg = {
        "vector_store": {"provider": "qdrant", "config": {
            "path": str(root / "qdrant"),
            "collection_name": COLLECTION,
            "embedding_model_dims": embedder.dims,
            "on_disk": True,
        }},
        "history_db_path": str(history_db(root)),
    }
    mem = Memory.from_config(cfg)
    mem.embedding_model = embedder
    return mem


def close_local_memory(mem) -> None:
    """Release the Qdrant client and the history connection so the store's
    directory can be removed or reopened. Safe to call on ``None``."""
    if mem is None:
        return
    for closer in (lambda: mem.vector_store.client.close(),
                   lambda: mem.db.connection.close()):
        try:
            closer()
        except Exception:  # noqa: BLE001 - best effort on teardown
            pass


def history_db(root: Path) -> Path:
    return root / "history.db"


def points_db(root: Path) -> Path:
    return root / "qdrant" / "collection" / COLLECTION / "storage.sqlite"


def mem0_version() -> str:
    """Installed mem0ai version, for MEASURED_ON lines and reports."""
    try:
        return md.version("mem0ai")
    except md.PackageNotFoundError:
        return "not installed"
