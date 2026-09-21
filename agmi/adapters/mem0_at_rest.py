# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Adapter for Mem0 (mem0ai), the real library, at-rest attack surface.

Mem0 keeps each memory as a point in a vector store and writes an ADD/UPDATE/
DELETE event for every change into a SQLite history table. With the default
local Qdrant backend the points live on disk in
    <path>/collection/<name>/storage.sqlite   points(id TEXT, point BLOB)
where `point` is a pickled qdrant PointStruct whose payload carries the
memory text (`data`), an md5 `hash` of that text, and timestamps.

This adapter drives real Mem0 through its own add()/get_all()/search()/
history() and edits the on-disk store directly for the attacks. To keep it
offline and deterministic it opens Memory through mem0_common with the
hashing embedder from agmi.embedders (bag-of-words into 64 dims). Every
add() uses infer=False so no LLM is called. Nothing about Mem0's storage or
integrity behaviour depends on which embedder produced the vectors.

What "verify" means here: Mem0 has no integrity check on its stores. The
payload `hash` is used for de-duplication, not verification, and the history
table is never reconciled against the vector store. verify() runs get_all(),
search() and history() for the seeded user and returns True if Mem0 raised
nothing. That is the tool's honest answer.
"""

from __future__ import annotations

import base64
import pickle
import sqlite3
import tempfile
import uuid
from pathlib import Path

from agmi.adapters.base import MemoryAdapter, Record
from agmi.adapters.mem0_common import (
    close_local_memory, history_db, open_local_memory, points_db,
)
from agmi.embedders import HashEmbedder

USER = "victim"
SEED_TOKEN = "agmi-seed-"


class Mem0AtRestAdapter(MemoryAdapter):
    name = "mem0-qdrant-local"

    def __init__(self):
        self._dir: tempfile.TemporaryDirectory | None = None
        self._root: Path | None = None
        self._mem = None

    # --- lifecycle -----------------------------------------------------
    def _open(self):
        return open_local_memory(self._root, HashEmbedder())

    def _close(self) -> None:
        close_local_memory(self._mem)
        self._mem = None

    def setup(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self._root = Path(self._dir.name)
        self._mem = self._open()

    def teardown(self) -> None:
        self._close()
        if self._dir is not None:
            self._dir.cleanup()
            self._dir = None

    # --- normal tool API (used to seed legitimately) -------------------
    def seed(self, n: int) -> None:
        for i in range(n):
            self._mem.add(f"{SEED_TOKEN}{i} note about topic {i}",
                          user_id=USER, infer=False)

    # --- raw store access (used by attacks) ----------------------------
    @property
    def _points_db(self) -> Path:
        return points_db(self._root)

    def _order(self) -> list[str]:
        """Memory ids in insertion order, from Mem0's own history log."""
        conn = sqlite3.connect(history_db(self._root))
        ids = [r[0] for r in conn.execute(
            "SELECT memory_id FROM history WHERE event = 'ADD' "
            "ORDER BY created_at ASC, rowid ASC")]
        conn.close()
        return ids

    @staticmethod
    def _key(pid: str) -> str:
        """qdrant-local keys the points table by base64(pickle(id))."""
        return base64.b64encode(pickle.dumps(pid)).decode()

    def read_all_raw(self) -> list[Record]:
        conn = sqlite3.connect(self._points_db)
        rows = dict(conn.execute("SELECT id, point FROM points"))
        conn.close()
        out = []
        for pid in self._order():
            key = self._key(pid)
            if key not in rows:
                continue
            point = pickle.loads(rows[key])
            out.append(Record(seq=len(out), fields={
                "id": pid, "text": point.payload.get("data", ""),
                "point": point,
            }))
        return out

    def write_raw(self, record: Record) -> None:
        f = record.fields
        point = f["point"]
        point.payload["data"] = f["text"]
        point.payload["text_lemmatized"] = f["text"]
        conn = sqlite3.connect(self._points_db)
        conn.execute("INSERT INTO points (id, point) VALUES (?, ?) "
                     "ON CONFLICT(id) DO UPDATE SET point = excluded.point",
                     (self._key(f["id"]), pickle.dumps(point)))
        conn.commit()
        conn.close()

    def delete_raw(self, seq: int) -> None:
        recs = self.read_all_raw()
        if seq >= len(recs):
            return
        pid = recs[seq].fields["id"]
        conn = sqlite3.connect(self._points_db)
        conn.execute("DELETE FROM points WHERE id = ?", (self._key(pid),))
        conn.commit()
        conn.close()

    # --- payload hooks -------------------------------------------------
    def mutate_payload(self, record: Record) -> Record:
        record.fields["text"] = record.fields["text"].replace(
            SEED_TOKEN, "agmi-TAMP-", 1)
        return record

    def forge_record(self, template: Record) -> Record:
        import copy
        point = copy.deepcopy(template.fields["point"])
        point.id = str(uuid.uuid4())
        forged = Record(seq=template.seq + 1, fields={
            "id": point.id, "text": template.fields["text"], "point": point})
        forged = self.mutate_payload(forged)
        # Register the forged id in the history log too, as an attacker with
        # store access would, so Mem0's own history() knows the memory.
        conn = sqlite3.connect(history_db(self._root))
        conn.execute(
            "INSERT INTO history (id, memory_id, old_memory, new_memory, "
            "event, created_at, updated_at, is_deleted, actor_id, role) "
            "VALUES (?,?,?,?,?,?,?,0,NULL,'user')",
            (str(uuid.uuid4()), point.id, None, forged.fields["text"], "ADD",
             point.payload["created_at"], point.payload["updated_at"]))
        conn.commit()
        conn.close()
        return forged

    # --- reload + verify (the tool's own integrity answer) -------------
    def reload(self) -> None:
        self._close()
        self._mem = self._open()

    def verify(self) -> bool:
        try:
            res = self._mem.get_all(filters={"user_id": USER})
            items = res["results"] if isinstance(res, dict) else res
            if not items:
                return False
            self._mem.search("note about topic", filters={"user_id": USER},
                             limit=5)
            for it in items:
                self._mem.history(it["id"])
            return True
        except Exception:  # noqa: BLE001
            return False
