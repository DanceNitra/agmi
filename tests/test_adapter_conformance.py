# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""The contract every semantic adapter has to meet before its cells can
mean anything. A wrong adapter gives a wrong cell, so these run against
every adapter available in the environment, the reference stores included.

Write, read back, honour k, start empty after reset, scope by user, report
provenance, close cleanly. An adapter that fails here is a bug in the
adapter, never a finding about the tool."""

import pytest

from agmi.adapters.defended_memory import DefendedMemoryAdapter
from agmi.adapters.naive_memory import NaiveMemoryAdapter
from agmi.adapters.semantic_base import MemoryItem


def _available():
    yield "naive", NaiveMemoryAdapter
    yield "defended", DefendedMemoryAdapter
    try:
        import mem0  # noqa: F401
        import qdrant_client  # noqa: F401
        from agmi.adapters.mem0_semantic import Mem0SemanticAdapter
        yield "mem0", Mem0SemanticAdapter
    except ImportError:
        pass
    try:
        import langgraph.store.sqlite  # noqa: F401
        from agmi.adapters.langgraph_store import LangGraphSqliteStoreAdapter
        yield "langgraph-store", LangGraphSqliteStoreAdapter
    except ImportError:
        pass
    try:
        import inspeximus  # noqa: F401
        from agmi.adapters.inspeximus_recall import InspeximusRecallAdapter
        yield "inspeximus", InspeximusRecallAdapter
    except ImportError:
        pass


ADAPTERS = list(_available())


@pytest.fixture(params=ADAPTERS, ids=[a[0] for a in ADAPTERS])
def adapter(request):
    a = request.param[1]()
    a.reset()
    yield a
    a.close()


def test_write_then_read_back_verbatim(adapter):
    adapter.add_memory(MemoryItem("The user prefers metric units.", user_id="u1"))
    hits = adapter.retrieve("what units does the user prefer?", user_id="u1", k=5)
    assert [h.text for h in hits] == ["The user prefers metric units."]


def test_k_is_honoured(adapter):
    for i in range(6):
        adapter.add_memory(MemoryItem(f"note about topic {i}", user_id="u1"))
    assert len(adapter.retrieve("note about topic", user_id="u1", k=3)) == 3


def test_reset_starts_empty(adapter):
    adapter.add_memory(MemoryItem("note about topic 1", user_id="u1"))
    adapter.reset()
    assert adapter.retrieve("note about topic", user_id="u1", k=5) == []


def test_scoped_by_user(adapter):
    adapter.add_memory(MemoryItem("note about topic 1", user_id="u1"))
    assert adapter.retrieve("note about topic", user_id="u2", k=5) == []


def test_reports_provenance(adapter):
    line = adapter.measured_on()
    assert isinstance(line, str) and len(line) > 10
    assert line != "not recorded by this adapter"


def test_close_is_idempotent(adapter):
    adapter.close()
    adapter.close()
