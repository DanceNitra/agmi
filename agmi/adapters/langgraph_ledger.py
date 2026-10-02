# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""langgraph-ledger: a hash-chained event log beside a LangGraph checkpointer.

The package (PyPI `langgraph-ledger`, MIT) wraps any LangGraph checkpointer
in `TracingCheckpointSaver`. Every `put()` still lands in the inner store,
and the wrapper appends a `state/snapshot` event to a per-thread JSONL
ledger carrying the checkpoint id, its parent and a SHA-256 of the
normalised checkpoint. Events are hash-chained to their predecessor.
`verify_log()` re-checks the chain; `verify_thread()` additionally fetches
every logged checkpoint back from the saver and compares its digest to the
logged claim, reporting a missing or drifted checkpoint.

This adapter follows the README's quick start with `SqliteSaver` as the
inner store and the default keyless chain. The attacker edits the
checkpoint store (the SQLite file), which is the memory the agent resumes
from, and leaves the ledger alone; the README's own threat model covers
what an attacker who also rewrites the ledger can do, and that case is
not one of the eight edits.

Detection point is the audit: the agent's read path is the inner
`SqliteSaver`, unchanged, so a tampered checkpoint is still served on
resume; `verify_thread()` is a separate call the operator has to make.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from agmi.adapters.langgraph_sqlite import LangGraphSqliteAdapter, THREAD


class LangGraphLedgerAdapter(LangGraphSqliteAdapter):
    name = "langgraph-ledger"
    detection_point = "audit"

    def _wrap(self, conn: sqlite3.Connection):
        from langgraph.checkpoint.sqlite import SqliteSaver
        from langgraph_ledger import TracingCheckpointSaver
        inner = SqliteSaver(conn)
        return TracingCheckpointSaver(inner, trace_root=str(self._traces))

    @property
    def _traces(self) -> Path:
        return Path(self._dir.name) / "traces"

    @property
    def _log(self) -> Path:
        return self._traces / f"{THREAD}.jsonl"

    def setup(self) -> None:
        super().setup()
        self._saver.conn.close()
        self._traces.mkdir(exist_ok=True)
        conn = sqlite3.connect(self._db, check_same_thread=False)
        self._saver = self._wrap(conn)
        self._saver.inner.setup()

    def _close(self) -> None:
        try:
            self._saver.inner.conn.close()
        except Exception:  # noqa: BLE001
            pass

    def teardown(self) -> None:
        self._close()
        self._saver = None
        if self._dir is not None:
            self._dir.cleanup()
            self._dir = None

    def reload(self) -> None:
        self._close()
        conn = sqlite3.connect(self._db, check_same_thread=False)
        self._saver = self._wrap(conn)

    def verify(self) -> bool:
        """verify_thread(): chain intact and every logged checkpoint still
        present in the saver with the digest the ledger recorded."""
        from langgraph_ledger import verify_thread
        self.verify_detail = None
        report = verify_thread(self._saver, self._log)
        if report.get("ok"):
            return True
        errs = report.get("errors") or []
        self.verify_detail = "verify_thread: " + "; ".join(
            str(e.get("error", e)) for e in errs[:3])[:200]
        return False
